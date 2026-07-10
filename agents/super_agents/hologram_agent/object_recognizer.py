"""
agents/super_agents/hologram_agent/object_recognizer.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Hologram Agent - Object Recognizer

Purpose:
    Detects physical objects and returns labels, confidence, bounding boxes,
    spatial hints, and contextual metadata for AR / hologram interactions.

This file is designed to be:
    - Production-level
    - Import-safe even if future William/Jarvis files do not exist yet
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router, and Master Agent routing
    - Compatible with SaaS user/workspace isolation
    - Ready for Security Agent approval flows
    - Ready for Memory Agent context storage
    - Ready for Verification Agent post-action validation
    - Ready for Dashboard/API integration
    - Safe by default: it does not call camera hardware directly and does not perform
      destructive or sensitive actions without security hooks

Important:
    This module provides object-recognition orchestration, validation, structured output,
    fallback heuristic recognition, and optional adapter support. Real model inference can
    be injected through `vision_backend` without changing public APIs.
"""

from __future__ import annotations

import asyncio
import base64
import copy
import dataclasses
import hashlib
import io
import json
import logging
import math
import mimetypes
import os
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ======================================================================================
# Safe optional imports
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps object_recognizer.py import-safe while the wider William/Jarvis
        platform is still being generated.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "hologram_agent")
            self.metadata = kwargs.get("metadata", {})

        async def handle_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement task handling.",
                "data": {},
                "error": "base_agent_not_available",
                "metadata": {"agent": self.__class__.__name__},
            }


try:
    from PIL import Image  # type: ignore
except Exception:  # pragma: no cover
    Image = None  # type: ignore


# ======================================================================================
# Logging
# ======================================================================================

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ======================================================================================
# Constants
# ======================================================================================

UTC = timezone.utc

DEFAULT_AGENT_NAME = "hologram_object_recognizer"
DEFAULT_AGENT_TYPE = "hologram_agent"

SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:.]{1,160}$")
SAFE_LABEL_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9 _.\-:/()]{0,120}$")

MAX_IMAGE_BYTES = 16 * 1024 * 1024
MAX_BASE64_CHARS = 28 * 1024 * 1024
MAX_DETECTIONS = 200
DEFAULT_CONFIDENCE_THRESHOLD = 0.35
DEFAULT_NMS_IOU_THRESHOLD = 0.55

SUPPORTED_IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".webp",
    ".bmp",
}

SUPPORTED_MIME_TYPES = {
    "image/jpeg",
    "image/png",
    "image/webp",
    "image/bmp",
}

REDACTED = "[redacted]"


# ======================================================================================
# Enums
# ======================================================================================

class ObjectRecognitionMode(str, Enum):
    """Supported recognition modes."""

    FAST = "fast"
    BALANCED = "balanced"
    PRECISE = "precise"
    AR_CONTEXT = "ar_context"


class ObjectRecognitionSource(str, Enum):
    """Supported input sources."""

    IMAGE_BYTES = "image_bytes"
    IMAGE_BASE64 = "image_base64"
    IMAGE_PATH = "image_path"
    IMAGE_URL = "image_url"
    FRAME_REFERENCE = "frame_reference"
    PRECOMPUTED = "precomputed"


class DetectionSeverity(str, Enum):
    """Risk/severity category for recognized object context."""

    NORMAL = "normal"
    ATTENTION = "attention"
    CAUTION = "caution"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


class SecurityDecision(str, Enum):
    """Security decision result."""

    APPROVED = "approved"
    DENIED = "denied"
    PENDING = "pending"
    NOT_REQUIRED = "not_required"


class RecognitionBackendStatus(str, Enum):
    """Backend availability status."""

    READY = "ready"
    UNAVAILABLE = "unavailable"
    FALLBACK = "fallback"
    ERROR = "error"


# ======================================================================================
# Data structures
# ======================================================================================

@dataclass(frozen=True)
class BoundingBox:
    """
    Normalized bounding box.

    Coordinates are normalized from 0.0 to 1.0:
        x_min, y_min: top-left
        x_max, y_max: bottom-right
    """

    x_min: float
    y_min: float
    x_max: float
    y_max: float

    def validate(self) -> None:
        values = [self.x_min, self.y_min, self.x_max, self.y_max]
        if any(not isinstance(v, (int, float)) or math.isnan(float(v)) for v in values):
            raise ValueError("Bounding box coordinates must be numeric.")
        if not 0.0 <= self.x_min <= 1.0:
            raise ValueError("x_min must be between 0.0 and 1.0.")
        if not 0.0 <= self.y_min <= 1.0:
            raise ValueError("y_min must be between 0.0 and 1.0.")
        if not 0.0 <= self.x_max <= 1.0:
            raise ValueError("x_max must be between 0.0 and 1.0.")
        if not 0.0 <= self.y_max <= 1.0:
            raise ValueError("y_max must be between 0.0 and 1.0.")
        if self.x_max < self.x_min:
            raise ValueError("x_max must be greater than or equal to x_min.")
        if self.y_max < self.y_min:
            raise ValueError("y_max must be greater than or equal to y_min.")

    @property
    def width(self) -> float:
        return max(0.0, float(self.x_max - self.x_min))

    @property
    def height(self) -> float:
        return max(0.0, float(self.y_max - self.y_min))

    @property
    def area(self) -> float:
        return self.width * self.height

    @property
    def center(self) -> Dict[str, float]:
        return {
            "x": round((self.x_min + self.x_max) / 2.0, 6),
            "y": round((self.y_min + self.y_max) / 2.0, 6),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "x_min": round(float(self.x_min), 6),
            "y_min": round(float(self.y_min), 6),
            "x_max": round(float(self.x_max), 6),
            "y_max": round(float(self.y_max), 6),
            "width": round(self.width, 6),
            "height": round(self.height, 6),
            "area": round(self.area, 6),
            "center": self.center,
        }


@dataclass
class SpatialHint:
    """
    AR-friendly spatial context for a detected object.

    This module does not require a full 3D scene map, but it can accept one from
    spatial_mapper.py or real_world_context.py and return useful hints.
    """

    relative_position: str = "unknown"
    distance_meters: Optional[float] = None
    depth_layer: Optional[str] = None
    surface_hint: Optional[str] = None
    tracking_anchor_id: Optional[str] = None
    world_coordinates: Optional[Dict[str, float]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "relative_position": self.relative_position,
            "distance_meters": self.distance_meters,
            "depth_layer": self.depth_layer,
            "surface_hint": self.surface_hint,
            "tracking_anchor_id": self.tracking_anchor_id,
            "world_coordinates": _json_safe(self.world_coordinates or {}),
        }


@dataclass
class ObjectDetection:
    """
    A single object recognition result.
    """

    label: str
    confidence: float
    bounding_box: Optional[BoundingBox] = None
    detection_id: str = field(default_factory=lambda: f"det_{uuid.uuid4().hex}")
    category: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    severity: DetectionSeverity = DetectionSeverity.NORMAL
    context: Dict[str, Any] = field(default_factory=dict)
    spatial_hint: Optional[SpatialHint] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    source_backend: str = "unknown"

    def validate(self) -> None:
        if not self.label or not isinstance(self.label, str):
            raise ValueError("Detection label is required.")
        if not SAFE_LABEL_PATTERN.match(self.label):
            raise ValueError(f"Detection label contains unsafe characters: {self.label}")
        if not isinstance(self.confidence, (int, float)):
            raise ValueError("Detection confidence must be numeric.")
        if math.isnan(float(self.confidence)):
            raise ValueError("Detection confidence cannot be NaN.")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("Detection confidence must be between 0.0 and 1.0.")
        if self.bounding_box:
            self.bounding_box.validate()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "label": self.label,
            "confidence": round(float(self.confidence), 6),
            "category": self.category,
            "aliases": list(self.aliases),
            "severity": self.severity.value if isinstance(self.severity, DetectionSeverity) else str(self.severity),
            "bounding_box": self.bounding_box.to_dict() if self.bounding_box else None,
            "spatial_hint": self.spatial_hint.to_dict() if self.spatial_hint else None,
            "context": _json_safe(self.context),
            "attributes": _json_safe(self.attributes),
            "source_backend": self.source_backend,
        }


@dataclass
class RecognitionRequest:
    """
    Internal normalized object recognition request.
    """

    user_id: str
    workspace_id: str
    source_type: ObjectRecognitionSource
    source: Any
    mode: ObjectRecognitionMode = ObjectRecognitionMode.BALANCED
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    max_detections: int = 50
    include_spatial_context: bool = True
    include_memory_payload: bool = True
    include_verification_payload: bool = True
    frame_id: Optional[str] = None
    session_id: Optional[str] = None
    device_id: Optional[str] = None
    actor_id: Optional[str] = None
    allowed_labels: Optional[List[str]] = None
    blocked_labels: Optional[List[str]] = None
    spatial_context: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ImageMetadata:
    """
    Safe metadata about the input image/frame.
    """

    width: Optional[int] = None
    height: Optional[int] = None
    mime_type: Optional[str] = None
    byte_size: Optional[int] = None
    source_hash: Optional[str] = None
    source_type: Optional[str] = None
    frame_id: Optional[str] = None
    device_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "width": self.width,
            "height": self.height,
            "mime_type": self.mime_type,
            "byte_size": self.byte_size,
            "source_hash": self.source_hash,
            "source_type": self.source_type,
            "frame_id": self.frame_id,
            "device_id": self.device_id,
        }


# ======================================================================================
# Utility helpers
# ======================================================================================

def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _json_safe(value: Any) -> Any:
    """Convert arbitrary values into JSON-safe structures."""

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    if isinstance(value, Enum):
        return value.value

    if dataclasses.is_dataclass(value):
        return _json_safe(asdict(value))

    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]

    return str(value)


def _safe_copy(value: Any) -> Any:
    try:
        return copy.deepcopy(value)
    except Exception:
        return _json_safe(value)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_id(value: Any) -> bool:
    return bool(value and isinstance(value, str) and SAFE_ID_PATTERN.match(value))


def _normalize_label(label: Any) -> str:
    text = str(label or "").strip()
    text = re.sub(r"\s+", " ", text)
    return text[:120]


def _clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, float(value)))


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        if math.isnan(result):
            return default
        return result
    except Exception:
        return default


def _is_path_safe(path: Union[str, Path], allowed_roots: Optional[Sequence[Union[str, Path]]] = None) -> bool:
    """
    Basic path safety check.

    This prevents accidental reading from sensitive system paths. In production,
    use signed media references or a dedicated file service.
    """

    try:
        resolved = Path(path).expanduser().resolve()

        forbidden_roots = [
            Path("/etc").resolve(),
            Path("/proc").resolve(),
            Path("/sys").resolve(),
            Path("/root").resolve(),
        ]

        for forbidden in forbidden_roots:
            try:
                if resolved.is_relative_to(forbidden):
                    return False
            except AttributeError:
                if str(resolved).startswith(str(forbidden)):
                    return False

        if allowed_roots:
            normalized_roots = [Path(root).expanduser().resolve() for root in allowed_roots]
            for root in normalized_roots:
                try:
                    if resolved.is_relative_to(root):
                        return True
                except AttributeError:
                    if str(resolved).startswith(str(root)):
                        return True
            return False

        return True

    except Exception:
        return False


def _mime_from_bytes(data: bytes) -> Optional[str]:
    """
    Lightweight image MIME sniffing.
    """

    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"RIFF") and b"WEBP" in data[:16]:
        return "image/webp"
    if data.startswith(b"BM"):
        return "image/bmp"
    return None


def _decode_base64_image(value: str) -> bytes:
    """
    Decode plain base64 or data URL base64 image.
    """

    if not isinstance(value, str):
        raise ValueError("Base64 image source must be a string.")

    if len(value) > MAX_BASE64_CHARS:
        raise ValueError("Base64 image source exceeds maximum allowed size.")

    text = value.strip()

    if text.startswith("data:"):
        if "," not in text:
            raise ValueError("Invalid data URL format.")
        header, text = text.split(",", 1)
        if ";base64" not in header:
            raise ValueError("Only base64 data URLs are supported.")

    try:
        return base64.b64decode(text, validate=True)
    except Exception as exc:
        raise ValueError("Invalid base64 image data.") from exc


def _extract_image_size_with_pillow(data: bytes) -> Tuple[Optional[int], Optional[int]]:
    if Image is None:
        return None, None

    try:
        with Image.open(io.BytesIO(data)) as img:
            width, height = img.size
            return int(width), int(height)
    except Exception:
        return None, None


def _bbox_iou(box_a: BoundingBox, box_b: BoundingBox) -> float:
    x_left = max(box_a.x_min, box_b.x_min)
    y_top = max(box_a.y_min, box_b.y_min)
    x_right = min(box_a.x_max, box_b.x_max)
    y_bottom = min(box_a.y_max, box_b.y_max)

    if x_right <= x_left or y_bottom <= y_top:
        return 0.0

    intersection = (x_right - x_left) * (y_bottom - y_top)
    union = box_a.area + box_b.area - intersection
    if union <= 0:
        return 0.0

    return intersection / union


def _severity_for_label(label: str) -> DetectionSeverity:
    """
    Categorize object label for AR attention.

    This does not make medical/legal/safety-critical decisions. It only helps overlays
    highlight objects that may require caution.
    """

    normalized = label.lower().strip()

    caution_terms = {
        "knife",
        "scissors",
        "fire",
        "flame",
        "stove",
        "oven",
        "car",
        "truck",
        "motorcycle",
        "bicycle",
        "stairs",
        "ladder",
        "glass",
        "wire",
        "cable",
        "outlet",
        "socket",
        "tool",
        "hammer",
        "saw",
        "drill",
    }

    attention_terms = {
        "person",
        "child",
        "dog",
        "cat",
        "door",
        "chair",
        "table",
        "screen",
        "phone",
        "laptop",
        "keyboard",
        "document",
        "package",
    }

    restricted_terms = {
        "weapon",
        "gun",
        "rifle",
        "pistol",
        "blood",
        "injury",
    }

    if normalized in restricted_terms:
        return DetectionSeverity.RESTRICTED
    if normalized in caution_terms:
        return DetectionSeverity.CAUTION
    if normalized in attention_terms:
        return DetectionSeverity.ATTENTION
    return DetectionSeverity.NORMAL


def _category_for_label(label: str) -> str:
    normalized = label.lower().strip()

    people = {"person", "child", "face", "hand", "body"}
    animals = {"dog", "cat", "bird", "horse", "cow", "animal"}
    electronics = {"phone", "laptop", "computer", "keyboard", "mouse", "screen", "monitor", "camera"}
    furniture = {"chair", "table", "desk", "sofa", "bed", "cabinet", "shelf"}
    vehicles = {"car", "truck", "bus", "motorcycle", "bicycle", "vehicle"}
    documents = {"paper", "document", "book", "notebook", "receipt", "label"}
    tools = {"tool", "hammer", "saw", "drill", "screwdriver", "wrench"}
    hazards = {"knife", "fire", "flame", "wire", "cable", "outlet", "stairs", "glass"}

    if normalized in people:
        return "person"
    if normalized in animals:
        return "animal"
    if normalized in electronics:
        return "electronics"
    if normalized in furniture:
        return "furniture"
    if normalized in vehicles:
        return "vehicle"
    if normalized in documents:
        return "document"
    if normalized in tools:
        return "tool"
    if normalized in hazards:
        return "hazard"
    return "object"


# ======================================================================================
# Object Recognizer
# ======================================================================================

class ObjectRecognizer(BaseAgent):
    """
    Detects physical objects and returns labels/confidence/context.

    How it connects to William/Jarvis:
        - Master Agent / Agent Router:
            Uses handle_task() to route object recognition tasks.
        - Hologram Agent:
            Uses recognition results to render AR overlays, object labels,
            warnings, and contextual prompts.
        - Spatial Mapper:
            Can pass spatial_context to enrich detections with position/depth hints.
        - Real World Context:
            Can provide scene summaries, lighting, surfaces, and device pose.
        - Security Agent:
            Approval hooks protect camera/frame recognition and sensitive context.
        - Memory Agent:
            Stores useful non-sensitive object context, not raw images.
        - Verification Agent:
            Receives structured verification payloads after recognition.
        - Dashboard/API:
            All public methods return dict/JSON style:
            success, message, data, error, metadata.
    """

    def __init__(
        self,
        *,
        vision_backend: Optional[Any] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        allowed_image_roots: Optional[Sequence[Union[str, Path]]] = None,
        default_confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
        default_max_detections: int = 50,
        allow_image_path_input: bool = True,
        allow_image_url_input: bool = False,
        enable_fallback_recognition: bool = True,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.pop("agent_name", DEFAULT_AGENT_NAME),
            agent_type=kwargs.pop("agent_type", DEFAULT_AGENT_TYPE),
            metadata=kwargs.pop(
                "metadata",
                {
                    "module": "super_agents.hologram_agent",
                    "file": "object_recognizer.py",
                    "class": "ObjectRecognizer",
                    "version": "1.0.0",
                },
            ),
            **kwargs,
        )

        self.vision_backend = vision_backend
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.allowed_image_roots = list(allowed_image_roots or [])
        self.default_confidence_threshold = _clamp(default_confidence_threshold, 0.0, 1.0)
        self.default_max_detections = int(max(1, min(default_max_detections, MAX_DETECTIONS)))
        self.allow_image_path_input = bool(allow_image_path_input)
        self.allow_image_url_input = bool(allow_image_url_input)
        self.enable_fallback_recognition = bool(enable_fallback_recognition)
        self.log = logger_instance or logger

        self._last_results: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    # ==================================================================================
    # Master Agent / Router compatible entrypoint
    # ==================================================================================

    async def handle_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Master Agent compatible task handler.

        Expected examples:
            {
                "action": "recognize_objects",
                "user_id": "user_123",
                "workspace_id": "workspace_123",
                "payload": {
                    "source_type": "image_base64",
                    "source": "...",
                    "mode": "balanced"
                }
            }

            {
                "action": "get_backend_status",
                "payload": {}
            }
        """

        action = str(task.get("action") or task.get("type") or "").strip()
        payload = dict(task.get("payload") or {})

        user_id = str(task.get("user_id") or payload.get("user_id") or "")
        workspace_id = str(task.get("workspace_id") or payload.get("workspace_id") or "")

        try:
            if action in {"recognize_objects", "detect_objects", "analyze_frame"}:
                return await self.recognize_objects(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    source=payload.get("source"),
                    source_type=payload.get("source_type") or ObjectRecognitionSource.IMAGE_BASE64.value,
                    mode=payload.get("mode") or ObjectRecognitionMode.BALANCED.value,
                    confidence_threshold=payload.get("confidence_threshold"),
                    max_detections=payload.get("max_detections"),
                    include_spatial_context=payload.get("include_spatial_context", True),
                    frame_id=payload.get("frame_id"),
                    session_id=payload.get("session_id"),
                    device_id=payload.get("device_id"),
                    actor_id=payload.get("actor_id") or user_id,
                    allowed_labels=payload.get("allowed_labels"),
                    blocked_labels=payload.get("blocked_labels"),
                    spatial_context=dict(payload.get("spatial_context") or {}),
                    metadata=dict(payload.get("metadata") or {}),
                )

            if action in {"recognize_precomputed", "normalize_detections"}:
                return await self.recognize_precomputed(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    detections=list(payload.get("detections") or []),
                    frame_id=payload.get("frame_id"),
                    session_id=payload.get("session_id"),
                    device_id=payload.get("device_id"),
                    actor_id=payload.get("actor_id") or user_id,
                    spatial_context=dict(payload.get("spatial_context") or {}),
                    metadata=dict(payload.get("metadata") or {}),
                )

            if action == "get_last_result":
                return self.get_last_result(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    session_id=str(payload.get("session_id") or ""),
                )

            if action in {"backend_status", "get_backend_status", "health"}:
                return self.get_backend_status()

            if action in {"supported_modes", "capabilities"}:
                return self.get_capabilities()

            return self._error_result(
                message=f"Unsupported ObjectRecognizer action: {action or 'missing_action'}",
                error="unsupported_action",
                metadata={"action": action},
            )

        except Exception as exc:
            self.log.exception("ObjectRecognizer task failed.")
            return self._error_result(
                message="Object recognition task failed.",
                error=str(exc),
                metadata={"action": action},
            )

    # ==================================================================================
    # Public API
    # ==================================================================================

    async def recognize_objects(
        self,
        *,
        user_id: str,
        workspace_id: str,
        source: Any,
        source_type: Union[str, ObjectRecognitionSource] = ObjectRecognitionSource.IMAGE_BASE64,
        mode: Union[str, ObjectRecognitionMode] = ObjectRecognitionMode.BALANCED,
        confidence_threshold: Optional[float] = None,
        max_detections: Optional[int] = None,
        include_spatial_context: bool = True,
        frame_id: Optional[str] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        allowed_labels: Optional[Sequence[str]] = None,
        blocked_labels: Optional[Sequence[str]] = None,
        spatial_context: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detect physical objects from an image/frame source.

        Supported source types:
            - image_bytes
            - image_base64
            - image_path
            - image_url, disabled by default for safety
            - frame_reference

        This method validates SaaS context, requests security approval when needed,
        normalizes image metadata, runs backend recognition or safe fallback,
        filters detections, prepares Memory/Verification payloads, logs audit events,
        and returns dashboard-ready structured output.
        """

        request_result = self._build_request(
            user_id=user_id,
            workspace_id=workspace_id,
            source=source,
            source_type=source_type,
            mode=mode,
            confidence_threshold=confidence_threshold,
            max_detections=max_detections,
            include_spatial_context=include_spatial_context,
            frame_id=frame_id,
            session_id=session_id,
            device_id=device_id,
            actor_id=actor_id,
            allowed_labels=list(allowed_labels or []) if allowed_labels else None,
            blocked_labels=list(blocked_labels or []) if blocked_labels else None,
            spatial_context=dict(spatial_context or {}),
            metadata=dict(metadata or {}),
        )

        if not request_result["success"]:
            return request_result

        request: RecognitionRequest = request_result["data"]["request"]

        security_context = {
            "action": "recognize_objects",
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "source_type": request.source_type.value,
            "frame_id": request.frame_id,
            "session_id": request.session_id,
            "device_id": request.device_id,
            "mode": request.mode.value,
            "metadata": _json_safe(request.metadata),
        }

        if self._requires_security_check("recognize_objects", security_context):
            approval = await self._request_security_approval(
                action="recognize_objects",
                context=security_context,
            )
            if approval.get("decision") not in {
                SecurityDecision.APPROVED.value,
                SecurityDecision.NOT_REQUIRED.value,
            }:
                return self._error_result(
                    message="Security approval required before object recognition.",
                    error="security_approval_required",
                    data={"approval": approval},
                    metadata=security_context,
                )

        start_time = time.time()

        image_result = self._load_image_payload(request)
        if not image_result["success"]:
            return image_result

        image_bytes: Optional[bytes] = image_result["data"].get("image_bytes")
        image_metadata: ImageMetadata = image_result["data"]["image_metadata"]

        backend_result = await self._run_backend_recognition(
            request=request,
            image_bytes=image_bytes,
            image_metadata=image_metadata,
        )

        if not backend_result["success"]:
            return backend_result

        raw_detections = backend_result["data"]["detections"]
        source_backend = backend_result["data"].get("source_backend", "unknown")

        normalized_result = self._normalize_and_filter_detections(
            raw_detections=raw_detections,
            request=request,
            image_metadata=image_metadata,
            source_backend=source_backend,
        )

        if not normalized_result["success"]:
            return normalized_result

        detections: List[ObjectDetection] = normalized_result["data"]["detections"]

        if request.include_spatial_context:
            detections = self._enrich_with_spatial_context(
                detections=detections,
                spatial_context=request.spatial_context,
                image_metadata=image_metadata,
            )

        scene_context = self._build_scene_context(
            detections=detections,
            image_metadata=image_metadata,
            request=request,
        )

        duration_ms = int((time.time() - start_time) * 1000)
        recognition_id = f"objrec_{uuid.uuid4().hex}"

        result_data = {
            "recognition_id": recognition_id,
            "objects": [item.to_dict() for item in detections],
            "object_count": len(detections),
            "scene_context": scene_context,
            "image_metadata": image_metadata.to_dict(),
            "backend": {
                "name": source_backend,
                "status": backend_result["data"].get("backend_status", RecognitionBackendStatus.FALLBACK.value),
                "mode": request.mode.value,
                "fallback_used": bool(backend_result["data"].get("fallback_used", False)),
            },
            "ar_overlay_hints": self._prepare_ar_overlay_hints(detections),
            "duration_ms": duration_ms,
        }

        verification_payload = None
        memory_payload = None

        if request.include_verification_payload:
            verification_payload = self._prepare_verification_payload(
                action="recognize_objects",
                request=request,
                recognition_id=recognition_id,
                detections=detections,
                image_metadata=image_metadata,
                duration_ms=duration_ms,
            )
            result_data["verification_payload"] = verification_payload

        if request.include_memory_payload:
            memory_payload = self._prepare_memory_payload(
                action="recognize_objects",
                request=request,
                recognition_id=recognition_id,
                detections=detections,
                scene_context=scene_context,
            )
            result_data["memory_payload"] = memory_payload

        self._store_last_result(
            user_id=request.user_id,
            workspace_id=request.workspace_id,
            session_id=request.session_id or request.frame_id or recognition_id,
            result=result_data,
        )

        self._log_audit_event(
            event_type="object_recognition.completed",
            user_id=request.user_id,
            workspace_id=request.workspace_id,
            actor_id=request.actor_id,
            data={
                "recognition_id": recognition_id,
                "object_count": len(detections),
                "source_type": request.source_type.value,
                "mode": request.mode.value,
                "frame_id": request.frame_id,
                "session_id": request.session_id,
                "device_id": request.device_id,
                "duration_ms": duration_ms,
                "labels": [item.label for item in detections[:20]],
            },
        )

        self._emit_agent_event(
            event_type="object_recognition.completed",
            data={
                "user_id": request.user_id,
                "workspace_id": request.workspace_id,
                "recognition_id": recognition_id,
                "object_count": len(detections),
                "frame_id": request.frame_id,
                "session_id": request.session_id,
            },
        )

        return self._safe_result(
            message="Object recognition completed successfully.",
            data=result_data,
            metadata={
                "user_id": request.user_id,
                "workspace_id": request.workspace_id,
                "recognition_id": recognition_id,
                "duration_ms": duration_ms,
            },
        )

    async def recognize_precomputed(
        self,
        *,
        user_id: str,
        workspace_id: str,
        detections: Sequence[Mapping[str, Any]],
        frame_id: Optional[str] = None,
        session_id: Optional[str] = None,
        device_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        spatial_context: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Normalize detections received from another Visual Agent, device bridge,
        AR SDK, or external CV backend.

        This is useful when the device already performed recognition but the Hologram Agent
        needs William/Jarvis-compatible structure, memory payloads, and verification payloads.
        """

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        request = RecognitionRequest(
            user_id=user_id,
            workspace_id=workspace_id,
            source_type=ObjectRecognitionSource.PRECOMPUTED,
            source=None,
            mode=ObjectRecognitionMode.BALANCED,
            confidence_threshold=self.default_confidence_threshold,
            max_detections=self.default_max_detections,
            include_spatial_context=True,
            frame_id=frame_id,
            session_id=session_id,
            device_id=device_id,
            actor_id=actor_id,
            spatial_context=dict(spatial_context or {}),
            metadata=dict(metadata or {}),
        )

        image_metadata = ImageMetadata(
            source_type=ObjectRecognitionSource.PRECOMPUTED.value,
            frame_id=frame_id,
            device_id=device_id,
        )

        normalized_result = self._normalize_and_filter_detections(
            raw_detections=list(detections or []),
            request=request,
            image_metadata=image_metadata,
            source_backend="precomputed",
        )
        if not normalized_result["success"]:
            return normalized_result

        normalized_detections: List[ObjectDetection] = normalized_result["data"]["detections"]
        normalized_detections = self._enrich_with_spatial_context(
            detections=normalized_detections,
            spatial_context=request.spatial_context,
            image_metadata=image_metadata,
        )

        recognition_id = f"objrec_{uuid.uuid4().hex}"
        scene_context = self._build_scene_context(
            detections=normalized_detections,
            image_metadata=image_metadata,
            request=request,
        )

        result_data = {
            "recognition_id": recognition_id,
            "objects": [item.to_dict() for item in normalized_detections],
            "object_count": len(normalized_detections),
            "scene_context": scene_context,
            "image_metadata": image_metadata.to_dict(),
            "backend": {
                "name": "precomputed",
                "status": RecognitionBackendStatus.READY.value,
                "mode": request.mode.value,
                "fallback_used": False,
            },
            "ar_overlay_hints": self._prepare_ar_overlay_hints(normalized_detections),
            "verification_payload": self._prepare_verification_payload(
                action="recognize_precomputed",
                request=request,
                recognition_id=recognition_id,
                detections=normalized_detections,
                image_metadata=image_metadata,
                duration_ms=0,
            ),
            "memory_payload": self._prepare_memory_payload(
                action="recognize_precomputed",
                request=request,
                recognition_id=recognition_id,
                detections=normalized_detections,
                scene_context=scene_context,
            ),
        }

        self._store_last_result(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id or frame_id or recognition_id,
            result=result_data,
        )

        self._log_audit_event(
            event_type="object_recognition.precomputed_normalized",
            user_id=user_id,
            workspace_id=workspace_id,
            actor_id=actor_id,
            data={
                "recognition_id": recognition_id,
                "object_count": len(normalized_detections),
                "frame_id": frame_id,
                "session_id": session_id,
                "device_id": device_id,
            },
        )

        return self._safe_result(
            message="Precomputed detections normalized successfully.",
            data=result_data,
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "recognition_id": recognition_id,
            },
        )

    def get_last_result(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
    ) -> Dict[str, Any]:
        """
        Return last recognition result for this user/workspace/session only.
        """

        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        if not session_id or not _safe_id(session_id):
            return self._error_result(
                message="Valid session_id is required.",
                error="invalid_session_id",
            )

        key = (user_id, workspace_id, session_id)
        result = self._last_results.get(key)

        if not result:
            return self._error_result(
                message="No object recognition result found for this session.",
                error="last_result_not_found",
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "session_id": session_id,
                },
            )

        return self._safe_result(
            message="Last object recognition result loaded.",
            data={"result": _safe_copy(result)},
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "session_id": session_id,
            },
        )

    def get_backend_status(self) -> Dict[str, Any]:
        """
        Return safe backend status for dashboard/API.
        """

        backend_name = self._backend_name()
        status = RecognitionBackendStatus.READY.value if self.vision_backend else RecognitionBackendStatus.FALLBACK.value

        capabilities = {
            "external_backend_available": bool(self.vision_backend),
            "fallback_recognition_enabled": self.enable_fallback_recognition,
            "pillow_available": Image is not None,
            "image_path_input_enabled": self.allow_image_path_input,
            "image_url_input_enabled": self.allow_image_url_input,
            "max_image_bytes": MAX_IMAGE_BYTES,
            "max_detections": MAX_DETECTIONS,
            "supported_source_types": [item.value for item in ObjectRecognitionSource],
        }

        return self._safe_result(
            message="Object recognition backend status loaded.",
            data={
                "backend_name": backend_name,
                "status": status,
                "capabilities": capabilities,
            },
            metadata={"agent": DEFAULT_AGENT_NAME},
        )

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Return ObjectRecognizer public capabilities for Agent Registry / dashboard.
        """

        return self._safe_result(
            message="ObjectRecognizer capabilities loaded.",
            data={
                "agent": DEFAULT_AGENT_NAME,
                "module": "hologram_agent",
                "class": "ObjectRecognizer",
                "actions": [
                    "recognize_objects",
                    "detect_objects",
                    "analyze_frame",
                    "recognize_precomputed",
                    "normalize_detections",
                    "get_last_result",
                    "get_backend_status",
                ],
                "modes": [item.value for item in ObjectRecognitionMode],
                "source_types": [item.value for item in ObjectRecognitionSource],
                "output_fields": [
                    "label",
                    "confidence",
                    "bounding_box",
                    "spatial_hint",
                    "context",
                    "severity",
                    "ar_overlay_hints",
                ],
                "security_hooks": [
                    "_validate_task_context",
                    "_requires_security_check",
                    "_request_security_approval",
                    "_prepare_verification_payload",
                    "_prepare_memory_payload",
                    "_emit_agent_event",
                    "_log_audit_event",
                    "_safe_result",
                    "_error_result",
                ],
            },
            metadata={"agent": DEFAULT_AGENT_NAME},
        )

    # ==================================================================================
    # Request and input normalization
    # ==================================================================================

    def _build_request(
        self,
        *,
        user_id: str,
        workspace_id: str,
        source: Any,
        source_type: Union[str, ObjectRecognitionSource],
        mode: Union[str, ObjectRecognitionMode],
        confidence_threshold: Optional[float],
        max_detections: Optional[int],
        include_spatial_context: bool,
        frame_id: Optional[str],
        session_id: Optional[str],
        device_id: Optional[str],
        actor_id: Optional[str],
        allowed_labels: Optional[List[str]],
        blocked_labels: Optional[List[str]],
        spatial_context: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        context_result = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not context_result["success"]:
            return context_result

        try:
            source_type_enum = source_type if isinstance(source_type, ObjectRecognitionSource) else ObjectRecognitionSource(str(source_type))
        except ValueError:
            return self._error_result(
                message="Unsupported object recognition source_type.",
                error="unsupported_source_type",
                metadata={"source_type": str(source_type)},
            )

        try:
            mode_enum = mode if isinstance(mode, ObjectRecognitionMode) else ObjectRecognitionMode(str(mode))
        except ValueError:
            return self._error_result(
                message="Unsupported object recognition mode.",
                error="unsupported_recognition_mode",
                metadata={"mode": str(mode)},
            )

        if source_type_enum == ObjectRecognitionSource.IMAGE_PATH and not self.allow_image_path_input:
            return self._error_result(
                message="Image path input is disabled.",
                error="image_path_input_disabled",
            )

        if source_type_enum == ObjectRecognitionSource.IMAGE_URL and not self.allow_image_url_input:
            return self._error_result(
                message="Image URL input is disabled for safety.",
                error="image_url_input_disabled",
            )

        if source_type_enum != ObjectRecognitionSource.PRECOMPUTED and source is None:
            return self._error_result(
                message="Recognition source is required.",
                error="missing_source",
                metadata={"source_type": source_type_enum.value},
            )

        if frame_id and not _safe_id(frame_id):
            return self._error_result(
                message="frame_id contains unsafe characters.",
                error="invalid_frame_id",
            )

        if session_id and not _safe_id(session_id):
            return self._error_result(
                message="session_id contains unsafe characters.",
                error="invalid_session_id",
            )

        if device_id and not _safe_id(device_id):
            return self._error_result(
                message="device_id contains unsafe characters.",
                error="invalid_device_id",
            )

        threshold = (
            self.default_confidence_threshold
            if confidence_threshold is None
            else _clamp(_safe_float(confidence_threshold, self.default_confidence_threshold), 0.0, 1.0)
        )

        max_items = self.default_max_detections if max_detections is None else int(max_detections)
        max_items = max(1, min(max_items, MAX_DETECTIONS))

        normalized_allowed = self._normalize_label_list(allowed_labels)
        normalized_blocked = self._normalize_label_list(blocked_labels)

        request = RecognitionRequest(
            user_id=user_id,
            workspace_id=workspace_id,
            source_type=source_type_enum,
            source=source,
            mode=mode_enum,
            confidence_threshold=threshold,
            max_detections=max_items,
            include_spatial_context=bool(include_spatial_context),
            frame_id=frame_id,
            session_id=session_id,
            device_id=device_id,
            actor_id=actor_id,
            allowed_labels=normalized_allowed or None,
            blocked_labels=normalized_blocked or None,
            spatial_context=_json_safe(spatial_context),
            metadata=_json_safe(metadata),
        )

        return self._safe_result(
            message="Recognition request normalized.",
            data={"request": request},
        )

    def _load_image_payload(self, request: RecognitionRequest) -> Dict[str, Any]:
        """
        Load and validate image/frame data.

        This method never captures from hardware. It only accepts provided sources.
        """

        try:
            image_bytes: Optional[bytes] = None
            source_type = request.source_type

            if source_type == ObjectRecognitionSource.IMAGE_BYTES:
                if not isinstance(request.source, (bytes, bytearray)):
                    return self._error_result(
                        message="image_bytes source must be bytes.",
                        error="invalid_image_bytes_source",
                    )
                image_bytes = bytes(request.source)

            elif source_type == ObjectRecognitionSource.IMAGE_BASE64:
                image_bytes = _decode_base64_image(str(request.source))

            elif source_type == ObjectRecognitionSource.IMAGE_PATH:
                path = Path(str(request.source)).expanduser()
                if not _is_path_safe(path, self.allowed_image_roots):
                    return self._error_result(
                        message="Image path is not allowed.",
                        error="unsafe_image_path",
                    )
                if not path.exists() or not path.is_file():
                    return self._error_result(
                        message="Image path does not exist or is not a file.",
                        error="image_path_not_found",
                    )
                if path.suffix.lower() not in SUPPORTED_IMAGE_EXTENSIONS:
                    return self._error_result(
                        message="Unsupported image file extension.",
                        error="unsupported_image_extension",
                        metadata={"extension": path.suffix.lower()},
                    )
                if path.stat().st_size > MAX_IMAGE_BYTES:
                    return self._error_result(
                        message="Image file exceeds maximum allowed size.",
                        error="image_too_large",
                        metadata={"max_bytes": MAX_IMAGE_BYTES},
                    )
                image_bytes = path.read_bytes()

            elif source_type == ObjectRecognitionSource.FRAME_REFERENCE:
                return self._load_frame_reference(request)

            elif source_type == ObjectRecognitionSource.IMAGE_URL:
                return self._error_result(
                    message="Image URL fetching is intentionally not performed by ObjectRecognizer.",
                    error="image_url_fetch_not_supported_here",
                    metadata={
                        "reason": "Use Browser/Device Bridge or a trusted media proxy to fetch image bytes first."
                    },
                )

            elif source_type == ObjectRecognitionSource.PRECOMPUTED:
                metadata = ImageMetadata(
                    source_type=ObjectRecognitionSource.PRECOMPUTED.value,
                    frame_id=request.frame_id,
                    device_id=request.device_id,
                )
                return self._safe_result(
                    message="Precomputed source loaded.",
                    data={"image_bytes": None, "image_metadata": metadata},
                )

            else:
                return self._error_result(
                    message="Unsupported source type.",
                    error="unsupported_source_type",
                    metadata={"source_type": source_type.value},
                )

            if image_bytes is None:
                return self._error_result(
                    message="Image bytes could not be loaded.",
                    error="image_load_failed",
                )

            if len(image_bytes) > MAX_IMAGE_BYTES:
                return self._error_result(
                    message="Image exceeds maximum allowed size.",
                    error="image_too_large",
                    metadata={"max_bytes": MAX_IMAGE_BYTES},
                )

            mime_type = _mime_from_bytes(image_bytes)
            if mime_type not in SUPPORTED_MIME_TYPES:
                return self._error_result(
                    message="Unsupported or invalid image MIME type.",
                    error="unsupported_image_mime_type",
                    metadata={"mime_type": mime_type},
                )

            width, height = _extract_image_size_with_pillow(image_bytes)

            image_metadata = ImageMetadata(
                width=width,
                height=height,
                mime_type=mime_type,
                byte_size=len(image_bytes),
                source_hash=_sha256_bytes(image_bytes),
                source_type=request.source_type.value,
                frame_id=request.frame_id,
                device_id=request.device_id,
            )

            return self._safe_result(
                message="Image payload loaded successfully.",
                data={
                    "image_bytes": image_bytes,
                    "image_metadata": image_metadata,
                },
                metadata={
                    "byte_size": len(image_bytes),
                    "mime_type": mime_type,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to load image payload.",
                error=str(exc),
            )

    def _load_frame_reference(self, request: RecognitionRequest) -> Dict[str, Any]:
        """
        Handle a trusted frame reference.

        This does not access real camera hardware. A device_bridge.py module can later
        resolve frame references into bytes before calling recognize_objects().
        """

        frame_reference = str(request.source or "").strip()
        if not frame_reference or not _safe_id(frame_reference):
            return self._error_result(
                message="Invalid frame reference.",
                error="invalid_frame_reference",
            )

        image_metadata = ImageMetadata(
            source_type=ObjectRecognitionSource.FRAME_REFERENCE.value,
            frame_id=request.frame_id or frame_reference,
            device_id=request.device_id,
        )

        if self.vision_backend and hasattr(self.vision_backend, "resolve_frame"):
            try:
                resolved = self.vision_backend.resolve_frame(frame_reference=frame_reference)
                if isinstance(resolved, bytes):
                    if len(resolved) > MAX_IMAGE_BYTES:
                        return self._error_result(
                            message="Resolved frame exceeds maximum allowed size.",
                            error="frame_too_large",
                        )
                    mime_type = _mime_from_bytes(resolved)
                    width, height = _extract_image_size_with_pillow(resolved)
                    image_metadata.mime_type = mime_type
                    image_metadata.byte_size = len(resolved)
                    image_metadata.source_hash = _sha256_bytes(resolved)
                    image_metadata.width = width
                    image_metadata.height = height
                    return self._safe_result(
                        message="Frame reference resolved successfully.",
                        data={
                            "image_bytes": resolved,
                            "image_metadata": image_metadata,
                        },
                    )
            except Exception as exc:
                return self._error_result(
                    message="Frame reference resolution failed.",
                    error=str(exc),
                )

        return self._safe_result(
            message="Frame reference accepted without local bytes.",
            data={
                "image_bytes": None,
                "image_metadata": image_metadata,
            },
            metadata={
                "frame_reference": frame_reference,
                "note": "No frame resolver attached. Backend may still process reference if supported.",
            },
        )

    # ==================================================================================
    # Backend recognition
    # ==================================================================================

    async def _run_backend_recognition(
        self,
        *,
        request: RecognitionRequest,
        image_bytes: Optional[bytes],
        image_metadata: ImageMetadata,
    ) -> Dict[str, Any]:
        """
        Run injected vision backend or safe fallback recognizer.
        """

        if self.vision_backend:
            try:
                payload = {
                    "image_bytes": image_bytes,
                    "image_metadata": image_metadata.to_dict(),
                    "source_type": request.source_type.value,
                    "source": None if request.source_type in {
                        ObjectRecognitionSource.IMAGE_BYTES,
                        ObjectRecognitionSource.IMAGE_BASE64,
                    } else request.source,
                    "mode": request.mode.value,
                    "confidence_threshold": request.confidence_threshold,
                    "max_detections": request.max_detections,
                    "spatial_context": _json_safe(request.spatial_context),
                    "metadata": _json_safe(request.metadata),
                }

                result = None

                if hasattr(self.vision_backend, "detect_objects"):
                    result = self.vision_backend.detect_objects(**payload)
                elif hasattr(self.vision_backend, "recognize_objects"):
                    result = self.vision_backend.recognize_objects(**payload)
                elif callable(self.vision_backend):
                    result = self.vision_backend(payload)

                if hasattr(result, "__await__"):
                    result = await result

                normalized_backend_result = self._normalize_backend_response(result)

                if normalized_backend_result["success"]:
                    normalized_backend_result["data"]["source_backend"] = self._backend_name()
                    normalized_backend_result["data"]["backend_status"] = RecognitionBackendStatus.READY.value
                    normalized_backend_result["data"]["fallback_used"] = False
                    return normalized_backend_result

                self.log.warning("Vision backend returned invalid response: %s", normalized_backend_result)

            except Exception as exc:
                self.log.exception("Vision backend recognition failed.")
                if not self.enable_fallback_recognition:
                    return self._error_result(
                        message="Vision backend recognition failed.",
                        error=str(exc),
                        metadata={"backend": self._backend_name()},
                    )

        if not self.enable_fallback_recognition:
            return self._error_result(
                message="No object recognition backend is available.",
                error="vision_backend_unavailable",
            )

        fallback_detections = self._fallback_recognize(
            request=request,
            image_bytes=image_bytes,
            image_metadata=image_metadata,
        )

        return self._safe_result(
            message="Fallback object recognition completed.",
            data={
                "detections": fallback_detections,
                "source_backend": "fallback_heuristic",
                "backend_status": RecognitionBackendStatus.FALLBACK.value,
                "fallback_used": True,
            },
        )

    def _normalize_backend_response(self, result: Any) -> Dict[str, Any]:
        """
        Normalize external backend response into list-like detections.
        """

        if result is None:
            return self._error_result(
                message="Vision backend returned no result.",
                error="empty_backend_result",
            )

        if isinstance(result, Mapping):
            if result.get("success") is False:
                return self._error_result(
                    message=str(result.get("message") or "Vision backend failed."),
                    error=result.get("error") or "backend_error",
                    data=dict(result.get("data") or {}),
                    metadata=dict(result.get("metadata") or {}),
                )

            if "detections" in result:
                detections = result.get("detections")
            elif "objects" in result:
                detections = result.get("objects")
            elif "data" in result and isinstance(result["data"], Mapping):
                detections = result["data"].get("detections") or result["data"].get("objects") or []
            else:
                detections = []

            if not isinstance(detections, Sequence):
                return self._error_result(
                    message="Vision backend detections must be a list.",
                    error="invalid_backend_detections",
                )

            return self._safe_result(
                message="Vision backend response normalized.",
                data={"detections": list(detections)},
            )

        if isinstance(result, Sequence) and not isinstance(result, (str, bytes, bytearray)):
            return self._safe_result(
                message="Vision backend list response normalized.",
                data={"detections": list(result)},
            )

        return self._error_result(
            message="Unsupported vision backend response format.",
            error="unsupported_backend_response",
        )

    def _fallback_recognize(
        self,
        *,
        request: RecognitionRequest,
        image_bytes: Optional[bytes],
        image_metadata: ImageMetadata,
    ) -> List[Dict[str, Any]]:
        """
        Safe fallback recognizer.

        It does not claim high visual accuracy. It produces conservative object/context
        hints from available metadata so downstream AR systems can still proceed.
        A real CV backend should be injected for production detection.
        """

        detections: List[Dict[str, Any]] = []

        # If metadata provided hints from Real World Context / Device Bridge, use them safely.
        metadata_labels = []
        for key in ("labels", "objects", "detected_objects", "candidate_labels"):
            raw = request.metadata.get(key)
            if isinstance(raw, Sequence) and not isinstance(raw, (str, bytes, bytearray)):
                metadata_labels.extend(list(raw))

        for item in metadata_labels[: request.max_detections]:
            if isinstance(item, Mapping):
                label = _normalize_label(item.get("label") or item.get("name") or "object")
                confidence = _safe_float(item.get("confidence"), 0.45)
                bbox = item.get("bounding_box") or item.get("bbox")
            else:
                label = _normalize_label(item)
                confidence = 0.42
                bbox = None

            detections.append(
                {
                    "label": label or "object",
                    "confidence": confidence,
                    "bounding_box": bbox,
                    "context": {
                        "source": "metadata_hint",
                        "note": "Detected from provided metadata hints, not full CV inference.",
                    },
                }
            )

        if detections:
            return detections

        # Conservative scene hints based on file/frame existence only.
        if image_metadata.width and image_metadata.height:
            aspect_ratio = image_metadata.width / max(1, image_metadata.height)
            if aspect_ratio > 1.3:
                scene_label = "wide scene"
            elif aspect_ratio < 0.8:
                scene_label = "vertical scene"
            else:
                scene_label = "scene"

            detections.append(
                {
                    "label": scene_label,
                    "confidence": 0.36,
                    "bounding_box": {
                        "x_min": 0.0,
                        "y_min": 0.0,
                        "x_max": 1.0,
                        "y_max": 1.0,
                    },
                    "context": {
                        "source": "fallback_image_metadata",
                        "note": "Fallback label based on image dimensions only.",
                    },
                }
            )

        else:
            detections.append(
                {
                    "label": "object",
                    "confidence": 0.35,
                    "bounding_box": None,
                    "context": {
                        "source": "fallback_generic",
                        "note": "No visual backend or image dimensions available.",
                    },
                }
            )

        return detections

    # ==================================================================================
    # Detection normalization/filtering/context
    # ==================================================================================

    def _normalize_and_filter_detections(
        self,
        *,
        raw_detections: Sequence[Any],
        request: RecognitionRequest,
        image_metadata: ImageMetadata,
        source_backend: str,
    ) -> Dict[str, Any]:
        detections: List[ObjectDetection] = []
        errors: List[Dict[str, Any]] = []

        for index, raw in enumerate(list(raw_detections or [])[:MAX_DETECTIONS]):
            try:
                detection = self._normalize_single_detection(
                    raw=raw,
                    index=index,
                    source_backend=source_backend,
                )

                if detection.confidence < request.confidence_threshold:
                    continue

                label_key = detection.label.lower()

                if request.allowed_labels:
                    allowed = {item.lower() for item in request.allowed_labels}
                    if label_key not in allowed:
                        continue

                if request.blocked_labels:
                    blocked = {item.lower() for item in request.blocked_labels}
                    if label_key in blocked:
                        continue

                detections.append(detection)

            except Exception as exc:
                errors.append({"index": index, "error": str(exc)})

        detections = self._apply_nms(detections, iou_threshold=DEFAULT_NMS_IOU_THRESHOLD)
        detections.sort(key=lambda item: item.confidence, reverse=True)
        detections = detections[: request.max_detections]

        return self._safe_result(
            message="Detections normalized and filtered.",
            data={
                "detections": detections,
                "normalization_errors": errors[:20],
                "count": len(detections),
            },
            metadata={
                "raw_count": len(raw_detections or []),
                "filtered_count": len(detections),
                "confidence_threshold": request.confidence_threshold,
            },
        )

    def _normalize_single_detection(
        self,
        *,
        raw: Any,
        index: int,
        source_backend: str,
    ) -> ObjectDetection:
        if isinstance(raw, ObjectDetection):
            raw.validate()
            return raw

        if not isinstance(raw, Mapping):
            raise ValueError("Detection must be a mapping or ObjectDetection.")

        label = _normalize_label(
            raw.get("label")
            or raw.get("name")
            or raw.get("class")
            or raw.get("class_name")
            or raw.get("object")
            or "object"
        )

        confidence = _clamp(
            _safe_float(
                raw.get("confidence", raw.get("score", raw.get("probability", 0.0))),
                0.0,
            ),
            0.0,
            1.0,
        )

        bbox_raw = (
            raw.get("bounding_box")
            or raw.get("bbox")
            or raw.get("box")
            or raw.get("bounds")
        )

        bbox = self._normalize_bbox(bbox_raw)

        severity_raw = raw.get("severity")
        if severity_raw:
            try:
                severity = DetectionSeverity(str(severity_raw))
            except ValueError:
                severity = _severity_for_label(label)
        else:
            severity = _severity_for_label(label)

        category = str(raw.get("category") or _category_for_label(label))

        aliases_raw = raw.get("aliases") or []
        aliases = []
        if isinstance(aliases_raw, Sequence) and not isinstance(aliases_raw, (str, bytes, bytearray)):
            aliases = [_normalize_label(item) for item in aliases_raw if _normalize_label(item)]

        spatial_raw = raw.get("spatial_hint") or raw.get("spatial") or None
        spatial_hint = self._normalize_spatial_hint(spatial_raw)

        detection = ObjectDetection(
            label=label or "object",
            confidence=confidence,
            bounding_box=bbox,
            detection_id=str(raw.get("detection_id") or raw.get("id") or f"det_{uuid.uuid4().hex}"),
            category=category,
            aliases=aliases,
            severity=severity,
            context=_json_safe(dict(raw.get("context") or {})),
            spatial_hint=spatial_hint,
            attributes=_json_safe(dict(raw.get("attributes") or {})),
            source_backend=source_backend,
        )

        detection.validate()
        return detection

    def _normalize_bbox(self, bbox_raw: Any) -> Optional[BoundingBox]:
        if bbox_raw is None:
            return None

        if isinstance(bbox_raw, BoundingBox):
            bbox_raw.validate()
            return bbox_raw

        try:
            if isinstance(bbox_raw, Mapping):
                x_min = bbox_raw.get("x_min", bbox_raw.get("left", bbox_raw.get("x1", bbox_raw.get("x"))))
                y_min = bbox_raw.get("y_min", bbox_raw.get("top", bbox_raw.get("y1", bbox_raw.get("y"))))
                x_max = bbox_raw.get("x_max", bbox_raw.get("right", bbox_raw.get("x2")))
                y_max = bbox_raw.get("y_max", bbox_raw.get("bottom", bbox_raw.get("y2")))

                if x_max is None and "width" in bbox_raw:
                    x_max = _safe_float(x_min) + _safe_float(bbox_raw.get("width"))
                if y_max is None and "height" in bbox_raw:
                    y_max = _safe_float(y_min) + _safe_float(bbox_raw.get("height"))

                bbox = BoundingBox(
                    x_min=_clamp(_safe_float(x_min), 0.0, 1.0),
                    y_min=_clamp(_safe_float(y_min), 0.0, 1.0),
                    x_max=_clamp(_safe_float(x_max), 0.0, 1.0),
                    y_max=_clamp(_safe_float(y_max), 0.0, 1.0),
                )
                bbox.validate()
                return bbox

            if isinstance(bbox_raw, Sequence) and not isinstance(bbox_raw, (str, bytes, bytearray)):
                values = list(bbox_raw)
                if len(values) != 4:
                    raise ValueError("Bounding box list must have exactly 4 values.")
                bbox = BoundingBox(
                    x_min=_clamp(_safe_float(values[0]), 0.0, 1.0),
                    y_min=_clamp(_safe_float(values[1]), 0.0, 1.0),
                    x_max=_clamp(_safe_float(values[2]), 0.0, 1.0),
                    y_max=_clamp(_safe_float(values[3]), 0.0, 1.0),
                )
                bbox.validate()
                return bbox

        except Exception as exc:
            raise ValueError(f"Invalid bounding box: {exc}") from exc

        raise ValueError("Unsupported bounding box format.")

    def _normalize_spatial_hint(self, raw: Any) -> Optional[SpatialHint]:
        if raw is None:
            return None

        if isinstance(raw, SpatialHint):
            return raw

        if not isinstance(raw, Mapping):
            return None

        world_coordinates = raw.get("world_coordinates")
        if isinstance(world_coordinates, Mapping):
            world_coordinates = {
                "x": _safe_float(world_coordinates.get("x")),
                "y": _safe_float(world_coordinates.get("y")),
                "z": _safe_float(world_coordinates.get("z")),
            }
        else:
            world_coordinates = None

        return SpatialHint(
            relative_position=str(raw.get("relative_position") or raw.get("position") or "unknown"),
            distance_meters=(
                None if raw.get("distance_meters") is None else round(_safe_float(raw.get("distance_meters")), 4)
            ),
            depth_layer=raw.get("depth_layer"),
            surface_hint=raw.get("surface_hint"),
            tracking_anchor_id=raw.get("tracking_anchor_id"),
            world_coordinates=world_coordinates,
        )

    def _apply_nms(
        self,
        detections: Sequence[ObjectDetection],
        *,
        iou_threshold: float,
    ) -> List[ObjectDetection]:
        """
        Apply simple non-maximum suppression per label.
        """

        sorted_detections = sorted(detections, key=lambda item: item.confidence, reverse=True)
        kept: List[ObjectDetection] = []

        for candidate in sorted_detections:
            if candidate.bounding_box is None:
                kept.append(candidate)
                continue

            should_keep = True
            for existing in kept:
                if existing.bounding_box is None:
                    continue
                if existing.label.lower() != candidate.label.lower():
                    continue
                if _bbox_iou(candidate.bounding_box, existing.bounding_box) > iou_threshold:
                    should_keep = False
                    break

            if should_keep:
                kept.append(candidate)

        return kept

    def _enrich_with_spatial_context(
        self,
        *,
        detections: Sequence[ObjectDetection],
        spatial_context: Mapping[str, Any],
        image_metadata: ImageMetadata,
    ) -> List[ObjectDetection]:
        """
        Enrich detections with AR-friendly spatial hints.

        Accepts optional context from spatial_mapper.py / real_world_context.py:
            {
                "camera_pose": {...},
                "depth_map_summary": {...},
                "surfaces": [...],
                "anchors": [...],
                "frame_width": 1280,
                "frame_height": 720
            }
        """

        enriched: List[ObjectDetection] = []

        for detection in detections:
            if detection.spatial_hint:
                enriched.append(detection)
                continue

            relative_position = "unknown"
            if detection.bounding_box:
                center = detection.bounding_box.center
                x = center["x"]
                y = center["y"]

                horizontal = "center"
                if x < 0.33:
                    horizontal = "left"
                elif x > 0.67:
                    horizontal = "right"

                vertical = "middle"
                if y < 0.33:
                    vertical = "upper"
                elif y > 0.67:
                    vertical = "lower"

                relative_position = f"{vertical}_{horizontal}"

            distance_meters = None
            depth_layer = None

            depth_summary = spatial_context.get("depth_map_summary")
            if isinstance(depth_summary, Mapping):
                default_depth = depth_summary.get("estimated_center_depth_meters")
                if default_depth is not None:
                    distance_meters = round(_safe_float(default_depth), 4)
                depth_layer = depth_summary.get("dominant_depth_layer")

            surface_hint = self._infer_surface_hint(detection, spatial_context)

            detection.spatial_hint = SpatialHint(
                relative_position=relative_position,
                distance_meters=distance_meters,
                depth_layer=depth_layer,
                surface_hint=surface_hint,
                tracking_anchor_id=self._nearest_anchor_id(detection, spatial_context),
                world_coordinates=None,
            )

            enriched.append(detection)

        return enriched

    def _infer_surface_hint(
        self,
        detection: ObjectDetection,
        spatial_context: Mapping[str, Any],
    ) -> Optional[str]:
        surfaces = spatial_context.get("surfaces") or []
        if not isinstance(surfaces, Sequence):
            return None

        if detection.bounding_box is None:
            return None

        object_center = detection.bounding_box.center
        best_surface = None
        best_distance = 999.0

        for surface in surfaces:
            if not isinstance(surface, Mapping):
                continue
            center = surface.get("center") or {}
            if not isinstance(center, Mapping):
                continue

            dx = _safe_float(center.get("x"), 0.5) - object_center["x"]
            dy = _safe_float(center.get("y"), 0.5) - object_center["y"]
            distance = math.sqrt(dx * dx + dy * dy)

            if distance < best_distance:
                best_distance = distance
                best_surface = surface.get("type") or surface.get("label") or surface.get("surface_type")

        return str(best_surface) if best_surface and best_distance < 0.35 else None

    def _nearest_anchor_id(
        self,
        detection: ObjectDetection,
        spatial_context: Mapping[str, Any],
    ) -> Optional[str]:
        anchors = spatial_context.get("anchors") or []
        if not isinstance(anchors, Sequence):
            return None
        if detection.bounding_box is None:
            return None

        object_center = detection.bounding_box.center
        best_anchor_id = None
        best_distance = 999.0

        for anchor in anchors:
            if not isinstance(anchor, Mapping):
                continue
            center = anchor.get("screen_center") or anchor.get("center") or {}
            if not isinstance(center, Mapping):
                continue

            dx = _safe_float(center.get("x"), 0.5) - object_center["x"]
            dy = _safe_float(center.get("y"), 0.5) - object_center["y"]
            distance = math.sqrt(dx * dx + dy * dy)

            if distance < best_distance:
                best_distance = distance
                best_anchor_id = anchor.get("anchor_id") or anchor.get("id")

        return str(best_anchor_id) if best_anchor_id and best_distance < 0.25 else None

    def _build_scene_context(
        self,
        *,
        detections: Sequence[ObjectDetection],
        image_metadata: ImageMetadata,
        request: RecognitionRequest,
    ) -> Dict[str, Any]:
        labels = [item.label for item in detections]
        categories: Dict[str, int] = {}
        severities: Dict[str, int] = {}

        for item in detections:
            category = item.category or "object"
            categories[category] = categories.get(category, 0) + 1
            severity = item.severity.value if isinstance(item.severity, DetectionSeverity) else str(item.severity)
            severities[severity] = severities.get(severity, 0) + 1

        primary_object = detections[0].label if detections else None

        caution_objects = [
            item.label
            for item in detections
            if item.severity in {DetectionSeverity.CAUTION, DetectionSeverity.RESTRICTED}
        ]

        summary_parts = []
        if detections:
            summary_parts.append(f"Detected {len(detections)} object(s)")
            if primary_object:
                summary_parts.append(f"primary object: {primary_object}")
            if caution_objects:
                summary_parts.append(f"attention needed for: {', '.join(caution_objects[:5])}")
        else:
            summary_parts.append("No objects detected above confidence threshold")

        return {
            "summary": "; ".join(summary_parts),
            "primary_object": primary_object,
            "labels": labels[:50],
            "categories": categories,
            "severities": severities,
            "caution_objects": caution_objects[:20],
            "has_people": any((item.category == "person" or item.label.lower() == "person") for item in detections),
            "has_hazards": bool(caution_objects),
            "object_density": self._estimate_object_density(detections),
            "mode": request.mode.value,
            "frame_id": request.frame_id,
            "session_id": request.session_id,
            "device_id": request.device_id,
            "image": image_metadata.to_dict(),
        }

    def _estimate_object_density(self, detections: Sequence[ObjectDetection]) -> str:
        count = len(detections)
        if count == 0:
            return "none"
        if count <= 3:
            return "low"
        if count <= 10:
            return "medium"
        return "high"

    def _prepare_ar_overlay_hints(
        self,
        detections: Sequence[ObjectDetection],
    ) -> List[Dict[str, Any]]:
        """
        Prepare lightweight overlay cards for ar_overlay.py.
        """

        hints: List[Dict[str, Any]] = []

        for detection in detections[:50]:
            overlay_priority = "normal"
            if detection.severity == DetectionSeverity.RESTRICTED:
                overlay_priority = "urgent"
            elif detection.severity == DetectionSeverity.CAUTION:
                overlay_priority = "high"
            elif detection.severity == DetectionSeverity.ATTENTION:
                overlay_priority = "medium"

            hints.append(
                {
                    "overlay_id": f"overlay_{detection.detection_id}",
                    "type": "object_label",
                    "label": detection.label,
                    "confidence": round(float(detection.confidence), 4),
                    "priority": overlay_priority,
                    "severity": detection.severity.value if isinstance(detection.severity, DetectionSeverity) else str(detection.severity),
                    "anchor": detection.spatial_hint.tracking_anchor_id if detection.spatial_hint else None,
                    "screen_position": detection.bounding_box.center if detection.bounding_box else None,
                    "bounding_box": detection.bounding_box.to_dict() if detection.bounding_box else None,
                    "suggested_text": self._suggest_overlay_text(detection),
                    "safe_to_display": detection.severity != DetectionSeverity.RESTRICTED,
                }
            )

        return hints

    def _suggest_overlay_text(self, detection: ObjectDetection) -> str:
        confidence_pct = int(round(detection.confidence * 100))
        if detection.severity == DetectionSeverity.CAUTION:
            return f"Caution: {detection.label} ({confidence_pct}%)"
        if detection.severity == DetectionSeverity.RESTRICTED:
            return f"Restricted object detected ({confidence_pct}%)"
        return f"{detection.label} ({confidence_pct}%)"

    # ==================================================================================
    # Required compatibility hooks
    # ==================================================================================

    def _validate_task_context(self, *, user_id: str, workspace_id: str) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Every user-specific operation must include user_id and workspace_id.
        """

        if not user_id or not isinstance(user_id, str):
            return self._error_result(
                message="user_id is required for SaaS isolation.",
                error="missing_user_id",
            )

        if not workspace_id or not isinstance(workspace_id, str):
            return self._error_result(
                message="workspace_id is required for SaaS isolation.",
                error="missing_workspace_id",
            )

        if not SAFE_ID_PATTERN.match(user_id):
            return self._error_result(
                message="user_id contains unsafe characters.",
                error="invalid_user_id",
            )

        if not SAFE_ID_PATTERN.match(workspace_id):
            return self._error_result(
                message="workspace_id contains unsafe characters.",
                error="invalid_workspace_id",
            )

        return self._safe_result(
            message="Task context is valid.",
            data={"user_id": user_id, "workspace_id": workspace_id},
        )

    def _requires_security_check(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide whether Security Agent approval is required.

        Object recognition can involve camera/frame data and real-world context,
        so recognition actions require security approval by default.
        """

        protected_actions = {
            "recognize_objects",
            "analyze_frame",
            "detect_objects",
            "recognize_precomputed",
            "resolve_frame_reference",
        }

        if action in protected_actions:
            return True

        source_type = str((context or {}).get("source_type") or "")
        if source_type in {
            ObjectRecognitionSource.IMAGE_BYTES.value,
            ObjectRecognitionSource.IMAGE_BASE64.value,
            ObjectRecognitionSource.IMAGE_PATH.value,
            ObjectRecognitionSource.FRAME_REFERENCE.value,
            ObjectRecognitionSource.IMAGE_URL.value,
        }:
            return True

        return False

    async def _request_security_approval(
        self,
        *,
        action: str,
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If no real Security Agent is attached, returns approved-by-safe-default for
        local development/import-safe operation.
        """

        safe_context = self._redact_sensitive_context(context)

        if self.security_client:
            try:
                if hasattr(self.security_client, "approve_action"):
                    result = self.security_client.approve_action(
                        action=action,
                        context=safe_context,
                    )
                    if hasattr(result, "__await__"):
                        result = await result
                    return self._normalize_security_decision(result)

                if hasattr(self.security_client, "request_approval"):
                    result = self.security_client.request_approval(
                        action=action,
                        context=safe_context,
                    )
                    if hasattr(result, "__await__"):
                        result = await result
                    return self._normalize_security_decision(result)

            except Exception as exc:
                self.log.exception("Security approval failed.")
                return {
                    "decision": SecurityDecision.DENIED.value,
                    "message": "Security Agent approval failed.",
                    "error": str(exc),
                    "metadata": {"action": action},
                }

        return {
            "decision": SecurityDecision.APPROVED.value,
            "message": "Approved by ObjectRecognizer safe default policy.",
            "error": None,
            "metadata": {
                "action": action,
                "security_client_available": False,
                "mode": "local_safe_default",
            },
        }

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        request: RecognitionRequest,
        recognition_id: str,
        detections: Sequence[ObjectDetection],
        image_metadata: ImageMetadata,
        duration_ms: int,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload after recognition.
        """

        return {
            "verification_type": "hologram_object_recognition",
            "action": action,
            "agent": DEFAULT_AGENT_NAME,
            "recognition_id": recognition_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "actor_id": request.actor_id,
            "target": {
                "frame_id": request.frame_id,
                "session_id": request.session_id,
                "device_id": request.device_id,
                "source_type": request.source_type.value,
                "mode": request.mode.value,
            },
            "checks": {
                "saas_context_validated": True,
                "security_hook_applied": True,
                "raw_image_excluded_from_payload": True,
                "object_count": len(detections),
                "confidence_threshold": request.confidence_threshold,
                "duration_ms": duration_ms,
                "image_metadata_available": image_metadata.to_dict(),
            },
            "sample_labels": [item.label for item in detections[:20]],
            "created_at": _now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        request: RecognitionRequest,
        recognition_id: str,
        detections: Sequence[ObjectDetection],
        scene_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Raw images and secrets are never included. This stores only useful,
        non-sensitive scene/object context.
        """

        safe_objects = []
        for item in detections[:30]:
            safe_objects.append(
                {
                    "label": item.label,
                    "confidence": round(float(item.confidence), 4),
                    "category": item.category,
                    "severity": item.severity.value if isinstance(item.severity, DetectionSeverity) else str(item.severity),
                    "relative_position": item.spatial_hint.relative_position if item.spatial_hint else None,
                }
            )

        return {
            "memory_type": "hologram_object_context",
            "action": action,
            "agent": DEFAULT_AGENT_NAME,
            "recognition_id": recognition_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "content": {
                "frame_id": request.frame_id,
                "session_id": request.session_id,
                "device_id": request.device_id,
                "summary": scene_context.get("summary"),
                "primary_object": scene_context.get("primary_object"),
                "objects": safe_objects,
                "categories": scene_context.get("categories"),
                "has_people": scene_context.get("has_people"),
                "has_hazards": scene_context.get("has_hazards"),
            },
            "safe_to_store": True,
            "contains_raw_image": False,
            "contains_secrets": False,
            "created_at": _now_iso(),
        }

    def _emit_agent_event(
        self,
        *,
        event_type: str,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit dashboard/agent-bus event safely.
        """

        event = {
            "event_type": event_type,
            "agent": DEFAULT_AGENT_NAME,
            "module": "hologram_agent",
            "data": self._redact_sensitive_context(dict(data or {})),
            "created_at": _now_iso(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                self.log.debug("ObjectRecognizer event: %s", json.dumps(event, default=str))
        except Exception:
            self.log.exception("Failed to emit ObjectRecognizer event.")

    def _log_audit_event(
        self,
        *,
        event_type: str,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event safely.
        """

        audit_event = {
            "event_type": event_type,
            "agent": DEFAULT_AGENT_NAME,
            "module": "hologram_agent",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "actor_id": actor_id,
            "data": self._redact_sensitive_context(dict(data or {})),
            "created_at": _now_iso(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_event)
            else:
                self.log.info("ObjectRecognizer audit: %s", json.dumps(audit_event, default=str))
        except Exception:
            self.log.exception("Failed to log ObjectRecognizer audit event.")

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Standard success result.
        """

        return {
            "success": True,
            "message": message,
            "data": _json_safe(dict(data or {})),
            "error": error,
            "metadata": _json_safe(dict(metadata or {})),
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Any,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result.
        """

        return {
            "success": False,
            "message": message,
            "data": _json_safe(dict(data or {})),
            "error": str(error) if error is not None else "unknown_error",
            "metadata": _json_safe(dict(metadata or {})),
        }

    # ==================================================================================
    # Extra internal helpers
    # ==================================================================================

    def _backend_name(self) -> str:
        if not self.vision_backend:
            return "fallback_heuristic"
        if hasattr(self.vision_backend, "__class__"):
            return self.vision_backend.__class__.__name__
        return str(type(self.vision_backend))

    def _normalize_label_list(self, labels: Optional[Sequence[str]]) -> List[str]:
        normalized = []
        seen = set()

        for label in labels or []:
            clean = _normalize_label(label)
            if clean and SAFE_LABEL_PATTERN.match(clean) and clean.lower() not in seen:
                normalized.append(clean)
                seen.add(clean.lower())

        return normalized[:100]

    def _normalize_security_decision(self, result: Any) -> Dict[str, Any]:
        if isinstance(result, Mapping):
            decision = result.get("decision") or result.get("status") or result.get("result")

            if decision in {True, "true", "approved", "allow", "allowed", "ok"}:
                decision_value = SecurityDecision.APPROVED.value
            elif decision in {False, "false", "denied", "deny", "blocked", "rejected"}:
                decision_value = SecurityDecision.DENIED.value
            elif decision in {"pending", "needs_approval"}:
                decision_value = SecurityDecision.PENDING.value
            elif decision == SecurityDecision.NOT_REQUIRED.value:
                decision_value = SecurityDecision.NOT_REQUIRED.value
            else:
                decision_value = str(decision or SecurityDecision.DENIED.value)

            return {
                "decision": decision_value,
                "message": str(result.get("message") or "Security decision received."),
                "error": result.get("error"),
                "metadata": _json_safe(dict(result.get("metadata") or {})),
            }

        if result is True:
            return {
                "decision": SecurityDecision.APPROVED.value,
                "message": "Security approved.",
                "error": None,
                "metadata": {},
            }

        if result is False:
            return {
                "decision": SecurityDecision.DENIED.value,
                "message": "Security denied.",
                "error": "security_denied",
                "metadata": {},
            }

        return {
            "decision": SecurityDecision.DENIED.value,
            "message": "Invalid security decision format.",
            "error": "invalid_security_decision",
            "metadata": {"raw_result": str(result)},
        }

    def _redact_sensitive_context(self, value: Any) -> Any:
        """
        Remove raw image/source data and sensitive details from logs/events.
        """

        sensitive_keys = {
            "source",
            "image_bytes",
            "image_base64",
            "raw_image",
            "frame_bytes",
            "token",
            "secret",
            "password",
            "api_key",
            "authorization",
        }

        if value is None or isinstance(value, (str, int, float, bool)):
            if isinstance(value, str) and len(value) > 500:
                return value[:120] + "...[truncated]"
            return value

        if isinstance(value, Mapping):
            safe = {}
            for key, item in value.items():
                key_str = str(key)
                if key_str.lower() in sensitive_keys:
                    safe[key_str] = REDACTED
                else:
                    safe[key_str] = self._redact_sensitive_context(item)
            return safe

        if isinstance(value, (list, tuple, set)):
            return [self._redact_sensitive_context(item) for item in list(value)[:100]]

        return str(value)

    def _store_last_result(
        self,
        *,
        user_id: str,
        workspace_id: str,
        session_id: str,
        result: Mapping[str, Any],
    ) -> None:
        if not session_id or not _safe_id(session_id):
            return

        key = (user_id, workspace_id, session_id)
        self._last_results[key] = _json_safe(dict(result))

        # Avoid unbounded memory growth in long-running workers.
        if len(self._last_results) > 1000:
            oldest_key = next(iter(self._last_results.keys()))
            self._last_results.pop(oldest_key, None)


# ======================================================================================
# Module exports and factory
# ======================================================================================

__all__ = [
    "ObjectRecognizer",
    "ObjectRecognitionMode",
    "ObjectRecognitionSource",
    "RecognitionBackendStatus",
    "DetectionSeverity",
    "SecurityDecision",
    "BoundingBox",
    "SpatialHint",
    "ObjectDetection",
    "RecognitionRequest",
    "ImageMetadata",
    "build_default_object_recognizer",
]


def build_default_object_recognizer(**kwargs: Any) -> ObjectRecognizer:
    """
    Factory helper for Agent Loader, FastAPI dependency injection, tests,
    dashboard boot, or Master Agent registry wiring.
    """

    return ObjectRecognizer(**kwargs)


# ======================================================================================
# Lightweight self-test
# ======================================================================================

def _make_test_png_base64() -> str:
    """
    Create a tiny PNG base64 string for self-test.

    Uses a hardcoded 1x1 transparent PNG. This is not a secret or external asset.
    """

    return (
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8"
        "/x8AAwMCAO+/p9sAAAAASUVORK5CYII="
    )


def _self_test() -> Dict[str, Any]:
    """
    Lightweight local self-test.

    Usage:
        python -m agents.super_agents.hologram_agent.object_recognizer

    This does not access camera hardware or external APIs.
    """

    async def run() -> Dict[str, Any]:
        recognizer = ObjectRecognizer()

        status = recognizer.get_backend_status()

        result = await recognizer.recognize_objects(
            user_id="user_test",
            workspace_id="workspace_test",
            source=_make_test_png_base64(),
            source_type=ObjectRecognitionSource.IMAGE_BASE64,
            mode=ObjectRecognitionMode.BALANCED,
            confidence_threshold=0.1,
            frame_id="frame_test",
            session_id="session_test",
            device_id="device_test",
            actor_id="user_test",
            metadata={
                "candidate_labels": [
                    {"label": "phone", "confidence": 0.81, "bbox": [0.25, 0.25, 0.75, 0.75]},
                    {"label": "table", "confidence": 0.62, "bbox": [0.1, 0.7, 0.9, 0.95]},
                ]
            },
        )

        last = recognizer.get_last_result(
            user_id="user_test",
            workspace_id="workspace_test",
            session_id="session_test",
        )

        precomputed = await recognizer.recognize_precomputed(
            user_id="user_test",
            workspace_id="workspace_test",
            detections=[
                {
                    "label": "laptop",
                    "confidence": 0.9,
                    "bounding_box": {
                        "x_min": 0.2,
                        "y_min": 0.2,
                        "x_max": 0.8,
                        "y_max": 0.8,
                    },
                }
            ],
            session_id="session_precomputed",
            actor_id="user_test",
        )

        return {
            "success": True,
            "message": "ObjectRecognizer self-test completed.",
            "data": {
                "status": status,
                "recognition": result,
                "last": last,
                "precomputed": precomputed,
            },
            "error": None,
            "metadata": {},
        }

    return asyncio.run(run())


if __name__ == "__main__":
    print(json.dumps(_self_test(), indent=2, default=str))


"""
Where to place it:
    agents/super_agents/hologram_agent/object_recognizer.py

Required dependencies:
    - Python 3.10+
    - No mandatory external dependency
    - Optional:
        - Pillow for image size parsing:
            pip install pillow
        - A real vision backend can be injected later. Example backend methods:
            detect_objects(**payload)
            recognize_objects(**payload)
            resolve_frame(frame_reference="...")

How to test it:
    1. Save this file at:
        agents/super_agents/hologram_agent/object_recognizer.py

    2. Run import test:
        python -c "from agents.super_agents.hologram_agent.object_recognizer import ObjectRecognizer; print(ObjectRecognizer().get_capabilities())"

    3. Run self-test:
        python -m agents.super_agents.hologram_agent.object_recognizer

    4. Expected:
        - Backend status returns successfully
        - Test image base64 is validated
        - Fallback recognition returns structured object labels/confidence/context
        - Memory payload and verification payload are prepared
        - No raw image bytes are returned in logs/events/payloads

Agent/module completion percentage after this file:
    54.5%

Next file to generate:
    agents/super_agents/hologram_agent/navigation_overlay.py

Agent/Module: Hologram Agent
File Completed: object_recognizer.py
Completion: 54.5%
Completed Files: ['hologram_agent.py', 'ar_overlay.py', 'spatial_mapper.py', 'gesture_bridge.py', 'real_world_context.py', 'object_recognizer.py']
Remaining Files: ['navigation_overlay.py', 'notification_overlay.py', 'device_bridge.py', 'hologram_memory.py', 'config.py']
Next Recommended File: agents/super_agents/hologram_agent/navigation_overlay.py
FILE COMPLETE
"""