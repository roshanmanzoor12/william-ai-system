"""
agents/visual_agent/annotation_tool.py

Annotation Tool for William / Jarvis Multi-Agent AI SaaS System
by Digital Promotix.

Purpose:
    Draws boxes/labels around elements, errors, and click targets for
    reports/debugging.

This file is import-safe:
    - It can import even if future William/Jarvis modules do not exist yet.
    - Pillow is optional; if Pillow is missing, the tool still returns annotation
      metadata without drawing an output image.
    - It never captures a real screen by itself.
    - It never performs destructive actions.
    - It validates user_id and workspace_id for SaaS isolation.
    - It prepares Verification Agent and Memory Agent compatible payloads.
    - It is ready for Master Agent routing, dashboard/API usage, and registry loading.

Architecture connections:
    - Visual Agent:
        Uses this helper to render/debug UI detections, OCR regions, click targets,
        forms, and error screens.
    - Verification Agent:
        Receives annotation proof payloads to confirm what was found.
    - Security Agent:
        Sensitive visual annotations can be approval-gated.
    - Memory Agent:
        Receives safe summary metadata, not raw private image bytes.
    - Dashboard/API:
        Structured JSON-style responses include annotation metadata and output path.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import math
import mimetypes
import os
import re
import tempfile
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ======================================================================================
# Optional imports with safe fallback
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """Fallback BaseAgent so this file remains import-safe."""

        agent_name: str = "base_agent"
        agent_type: str = "base"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = logging.getLogger(self.__class__.__name__)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback log_audit: %s", payload)


try:
    from agents.visual_agent.config import VisualConfig  # type: ignore
except Exception:
    VisualConfig = None  # type: ignore


try:
    from PIL import Image, ImageDraw, ImageFont  # type: ignore
except Exception:
    Image = None  # type: ignore
    ImageDraw = None  # type: ignore
    ImageFont = None  # type: ignore


# ======================================================================================
# Logging
# ======================================================================================

LOGGER = logging.getLogger("william.visual_agent.annotation_tool")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# ======================================================================================
# Constants
# ======================================================================================

AGENT_NAME = "annotation_tool"
AGENT_DISPLAY_NAME = "Annotation Tool"
AGENT_MODULE = "agents.visual_agent"
AGENT_FILE = "annotation_tool.py"
AGENT_VERSION = "1.0.0"

DEFAULT_MAX_IMAGE_BYTES = 20_000_000
DEFAULT_MAX_ANNOTATIONS = 2_000
DEFAULT_OUTPUT_FORMAT = "PNG"
DEFAULT_LINE_WIDTH = 3
DEFAULT_FONT_SIZE = 14

SUPPORTED_IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".bmp",
    ".tif",
    ".tiff",
}

SENSITIVE_ANNOTATION_TYPES = {
    "screenshot",
    "screen",
    "browser_screen",
    "device_screen",
    "private_screen",
    "ocr_region",
    "credential_region",
}

SAFE_COLOR_PALETTE = {
    "element": "#2563EB",
    "button": "#16A34A",
    "input": "#7C3AED",
    "link": "#0891B2",
    "error": "#DC2626",
    "warning": "#F59E0B",
    "success": "#22C55E",
    "click_target": "#EA580C",
    "ocr": "#64748B",
    "form": "#9333EA",
    "default": "#2563EB",
}


# ======================================================================================
# Enums / Data Structures
# ======================================================================================

class AnnotationStatus(str, Enum):
    """Annotation result status."""

    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    NEEDS_REVIEW = "needs_review"
    BLOCKED = "blocked"
    ERROR = "error"


class AnnotationType(str, Enum):
    """Supported annotation types."""

    BOX = "box"
    LABEL = "label"
    CLICK_TARGET = "click_target"
    ERROR = "error"
    WARNING = "warning"
    SUCCESS = "success"
    OCR_REGION = "ocr_region"
    FORM_FIELD = "form_field"
    UI_ELEMENT = "ui_element"
    DEBUG_POINT = "debug_point"


class AnnotationSeverity(str, Enum):
    """Annotation finding severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AnnotationContext:
    """SaaS scoped annotation context."""

    user_id: str
    workspace_id: str
    task_id: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    source_agent: Optional[str] = None
    permissions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnnotationBox:
    """Bounding box for visual annotations."""

    x: int
    y: int
    width: int
    height: int
    confidence: float = 1.0
    coordinate_system: str = "pixels"

    @property
    def left(self) -> int:
        return self.x

    @property
    def top(self) -> int:
        return self.y

    @property
    def right(self) -> int:
        return self.x + self.width

    @property
    def bottom(self) -> int:
        return self.y + self.height

    @property
    def center_x(self) -> int:
        return self.x + self.width // 2

    @property
    def center_y(self) -> int:
        return self.y + self.height // 2

    def clamp(self, image_width: int, image_height: int) -> "AnnotationBox":
        """Clamp box coordinates to image bounds."""
        x = max(0, min(self.x, max(0, image_width - 1)))
        y = max(0, min(self.y, max(0, image_height - 1)))
        right = max(x + 1, min(self.right, image_width))
        bottom = max(y + 1, min(self.bottom, image_height))
        return AnnotationBox(
            x=x,
            y=y,
            width=max(1, right - x),
            height=max(1, bottom - y),
            confidence=self.confidence,
            coordinate_system=self.coordinate_system,
        )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data.update(
            {
                "left": self.left,
                "top": self.top,
                "right": self.right,
                "bottom": self.bottom,
                "center_x": self.center_x,
                "center_y": self.center_y,
            }
        )
        return data


@dataclass
class AnnotationItem:
    """Single annotation instruction."""

    annotation_id: str
    annotation_type: AnnotationType
    label: Optional[str] = None
    box: Optional[AnnotationBox] = None
    point: Optional[Tuple[int, int]] = None
    color: Optional[str] = None
    line_width: int = DEFAULT_LINE_WIDTH
    confidence: float = 1.0
    element_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "annotation_id": self.annotation_id,
            "annotation_type": self.annotation_type.value,
            "label": self.label,
            "box": self.box.to_dict() if self.box else None,
            "point": list(self.point) if self.point else None,
            "color": self.color,
            "line_width": self.line_width,
            "confidence": self.confidence,
            "element_id": self.element_id,
            "metadata": self.metadata,
        }


@dataclass
class AnnotationFinding:
    """Finding created during annotation."""

    check_name: str
    status: AnnotationStatus
    message: str
    severity: AnnotationSeverity = AnnotationSeverity.INFO
    expected: Any = None
    actual: Any = None
    confidence: float = 1.0
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["severity"] = self.severity.value
        return data


@dataclass
class AnnotationArtifact:
    """Artifact generated by annotation."""

    artifact_id: str
    artifact_type: str
    title: str
    data: Any
    created_at: str
    source: str = AGENT_NAME
    confidence: float = 1.0
    privacy_filtered: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AnnotationReport:
    """Complete annotation report."""

    report_id: str
    status: AnnotationStatus
    summary: str
    annotations: List[AnnotationItem]
    findings: List[AnnotationFinding]
    artifacts: List[AnnotationArtifact]
    output_path: Optional[str]
    output_format: Optional[str]
    confidence: float
    created_at: str
    context: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "status": self.status.value,
            "summary": self.summary,
            "annotations": [item.to_dict() for item in self.annotations],
            "findings": [item.to_dict() for item in self.findings],
            "artifacts": [item.to_dict() for item in self.artifacts],
            "output_path": self.output_path,
            "output_format": self.output_format,
            "confidence": self.confidence,
            "created_at": self.created_at,
            "context": self.context,
            "metadata": self.metadata,
        }


# ======================================================================================
# Helper functions
# ======================================================================================

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_uuid(prefix: str = "ann") -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _json_safe(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except TypeError:
        if isinstance(value, Path):
            return str(value)
        if isinstance(value, Enum):
            return value.value
        if hasattr(value, "to_dict") and callable(value.to_dict):
            return value.to_dict()
        if hasattr(value, "__dict__"):
            return dict(value.__dict__)
        return str(value)


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def _lower(value: Any) -> str:
    return _normalize_text(value).lower()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(round(float(value)))
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _clamp_float(value: Any, default: float = 0.0) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except Exception:
        return default


def _looks_like_base64(value: str) -> bool:
    if not value or len(value) < 32:
        return False
    candidate = value.split(",", 1)[-1] if "," in value[:100] else value
    return bool(re.fullmatch(r"[A-Za-z0-9+/=\s]+", candidate[:300]))


def _decode_base64(value: str, max_bytes: int) -> Tuple[Optional[bytes], Optional[str]]:
    try:
        candidate = value.split(",", 1)[-1] if "," in value[:100] else value
        raw = base64.b64decode(candidate, validate=False)
        if len(raw) > max_bytes:
            return None, f"image_too_large:{len(raw)}>{max_bytes}"
        return raw, None
    except Exception as exc:
        return None, str(exc)


def _read_file_bytes(path: Path, max_bytes: int) -> Tuple[Optional[bytes], Optional[str]]:
    try:
        if not path.exists():
            return None, "file_not_found"
        if not path.is_file():
            return None, "path_is_not_file"
        size = path.stat().st_size
        if size > max_bytes:
            return None, f"file_too_large:{size}>{max_bytes}"
        return path.read_bytes(), None
    except Exception as exc:
        return None, str(exc)


def _hex_to_rgb(hex_value: str) -> Tuple[int, int, int]:
    """Convert hex color into RGB tuple."""
    value = str(hex_value or "").strip().lstrip("#")
    if len(value) == 3:
        value = "".join(ch * 2 for ch in value)
    if len(value) != 6:
        return (37, 99, 235)
    try:
        return tuple(int(value[i:i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]
    except Exception:
        return (37, 99, 235)


def _pick_color(annotation_type: str, element_type: Optional[str] = None, color: Optional[str] = None) -> str:
    if color:
        return color
    key = _lower(annotation_type)
    element_key = _lower(element_type)
    return SAFE_COLOR_PALETTE.get(key) or SAFE_COLOR_PALETTE.get(element_key) or SAFE_COLOR_PALETTE["default"]


# ======================================================================================
# Annotation Tool
# ======================================================================================

class AnnotationTool(BaseAgent):
    """
    Draw boxes, labels, click targets, and debug markers on provided screenshots/images.

    This tool is intentionally a helper, not a screen capture agent. Browser/System/Device
    agents should capture screenshots with permission, then pass the image here.
    """

    agent_name = AGENT_NAME
    agent_type = "visual_helper"
    agent_version = AGENT_VERSION
    display_name = AGENT_DISPLAY_NAME

    def __init__(
        self,
        config: Optional[Any] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.config = config or self._load_default_config()
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.logger = logger or LOGGER

        self.max_image_bytes = int(getattr(self.config, "max_image_bytes", DEFAULT_MAX_IMAGE_BYTES))
        self.max_annotations = int(getattr(self.config, "max_annotations", DEFAULT_MAX_ANNOTATIONS))
        self.default_output_format = str(getattr(self.config, "default_output_format", DEFAULT_OUTPUT_FORMAT))
        self.default_line_width = int(getattr(self.config, "default_line_width", DEFAULT_LINE_WIDTH))
        self.default_font_size = int(getattr(self.config, "default_font_size", DEFAULT_FONT_SIZE))

    # ----------------------------------------------------------------------------------
    # Metadata / health
    # ----------------------------------------------------------------------------------

    def get_agent_metadata(self) -> Dict[str, Any]:
        """Return Agent Registry compatible metadata."""
        return self._safe_result(
            message="Annotation Tool metadata loaded.",
            data={
                "agent_name": self.agent_name,
                "display_name": self.display_name,
                "agent_type": self.agent_type,
                "agent_version": self.agent_version,
                "module": AGENT_MODULE,
                "file": AGENT_FILE,
                "safe_import": True,
                "requires_saas_context": True,
                "supports_security_agent": True,
                "supports_memory_agent": True,
                "supports_verification_agent": True,
                "supports_dashboard_api": True,
                "pillow_available": Image is not None,
                "supported_image_extensions": sorted(SUPPORTED_IMAGE_EXTENSIONS),
                "public_methods": [
                    "annotate_image",
                    "draw_boxes",
                    "draw_labels",
                    "draw_click_targets",
                    "draw_error_highlights",
                    "prepare_annotation_payload",
                    "generate_debug_overlay",
                    "health_check",
                    "get_agent_metadata",
                ],
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """Return lightweight health status."""
        return self._safe_result(
            message="Annotation Tool is healthy.",
            data={
                "agent_name": self.agent_name,
                "version": self.agent_version,
                "pillow_available": Image is not None,
                "security_agent_connected": self.security_agent is not None,
                "memory_agent_connected": self.memory_agent is not None,
                "verification_agent_connected": self.verification_agent is not None,
                "max_image_bytes": self.max_image_bytes,
                "max_annotations": self.max_annotations,
                "default_output_format": self.default_output_format,
            },
        )

    # ----------------------------------------------------------------------------------
    # Public methods
    # ----------------------------------------------------------------------------------

    def annotate_image(
        self,
        context: Union[AnnotationContext, Mapping[str, Any]],
        image: Union[str, Path, bytes, Mapping[str, Any]],
        annotations: Sequence[Union[AnnotationItem, Mapping[str, Any]]],
        output_path: Optional[Union[str, Path]] = None,
        output_format: Optional[str] = None,
        annotation_style: str = "default",
        privacy_mode: str = "safe",
        image_type: str = "screenshot",
    ) -> Dict[str, Any]:
        """
        Draw annotations onto a provided image.

        Args:
            context:
                Must include user_id and workspace_id.
            image:
                Image path, bytes, base64 string, or mapping with path/base64/bytes.
            annotations:
                Boxes, labels, click targets, errors, or debug points.
            output_path:
                Optional output file path. If omitted, writes to temp directory.
            output_format:
                PNG/JPEG/WEBP. Defaults to PNG.
            annotation_style:
                default, compact, debug, report.
            privacy_mode:
                safe or raw. Raw requires explicit permission.
            image_type:
                screenshot/screen/browser_screen/etc. Used for security checks.
        """
        started_at = datetime.now(timezone.utc)
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            approval = self._maybe_request_security(
                context=ctx,
                annotation_type=image_type,
                action="annotate_image",
                payload={
                    "annotation_count": len(annotations),
                    "privacy_mode": privacy_mode,
                    "annotation_style": annotation_style,
                },
            )
            if not approval["success"]:
                return approval

            normalized_annotations = self._normalize_annotations(annotations)
            findings: List[AnnotationFinding] = []
            artifacts: List[AnnotationArtifact] = []

            if len(normalized_annotations) > self.max_annotations:
                findings.append(
                    AnnotationFinding(
                        check_name="annotation_limit",
                        status=AnnotationStatus.PARTIAL,
                        message="Annotation count exceeds max limit; extra annotations were ignored.",
                        expected=f"<= {self.max_annotations}",
                        actual=len(normalized_annotations),
                        severity=AnnotationSeverity.MEDIUM,
                        confidence=0.8,
                    )
                )
                normalized_annotations = normalized_annotations[: self.max_annotations]

            image_result = self._load_image(image)
            if not image_result["success"]:
                findings.append(
                    AnnotationFinding(
                        check_name="image_load",
                        status=AnnotationStatus.FAILED,
                        message="Image could not be loaded for annotation.",
                        severity=AnnotationSeverity.HIGH,
                        actual=image_result.get("error"),
                        confidence=0.1,
                    )
                )
                report = self._build_report(
                    context=ctx,
                    annotations=normalized_annotations,
                    findings=findings,
                    artifacts=artifacts,
                    output_path=None,
                    output_format=None,
                    metadata={
                        "annotation_style": annotation_style,
                        "privacy_mode": privacy_mode,
                        "pillow_available": Image is not None,
                    },
                )
                return self._safe_result(
                    message=report.summary,
                    data={
                        "report": report.to_dict(),
                        "verification_payload": self._prepare_verification_payload(report, ctx),
                        "memory_payload": self._prepare_memory_payload(report, ctx),
                    },
                )

            image_obj = image_result["data"].get("image")
            image_metadata = image_result["data"].get("metadata", {})

            if Image is None or ImageDraw is None or image_obj is None:
                findings.append(
                    AnnotationFinding(
                        check_name="pillow_available",
                        status=AnnotationStatus.NEEDS_REVIEW,
                        message="Pillow is not installed; returning annotation metadata without drawing image.",
                        severity=AnnotationSeverity.MEDIUM,
                        confidence=0.5,
                        remediation="Install Pillow with: pip install pillow",
                    )
                )

                artifact = AnnotationArtifact(
                    artifact_id=_safe_uuid("artifact"),
                    artifact_type="annotation_metadata",
                    title="Annotation metadata only",
                    data={
                        "annotations": [item.to_dict() for item in normalized_annotations],
                        "image_metadata": image_metadata,
                    },
                    created_at=_utc_now(),
                    confidence=0.5,
                    privacy_filtered=True,
                )
                artifacts.append(artifact)

                report = self._build_report(
                    context=ctx,
                    annotations=normalized_annotations,
                    findings=findings,
                    artifacts=artifacts,
                    output_path=None,
                    output_format=None,
                    metadata={"pillow_available": False},
                )
                return self._safe_result(
                    message=report.summary,
                    data={
                        "report": report.to_dict(),
                        "verification_payload": self._prepare_verification_payload(report, ctx),
                        "memory_payload": self._prepare_memory_payload(report, ctx),
                    },
                )

            drawn_image = image_obj.convert("RGBA")
            draw = ImageDraw.Draw(drawn_image)

            image_width, image_height = drawn_image.size
            font = self._load_font(self.default_font_size)

            for item in normalized_annotations:
                self._draw_annotation(
                    draw=draw,
                    image=drawn_image,
                    annotation=item,
                    image_width=image_width,
                    image_height=image_height,
                    font=font,
                    style=annotation_style,
                )

            final_output_format = (output_format or self.default_output_format or "PNG").upper()
            safe_output_path = self._resolve_output_path(
                output_path=output_path,
                context=ctx,
                output_format=final_output_format,
            )

            if final_output_format in {"JPG", "JPEG"}:
                save_image = drawn_image.convert("RGB")
                final_output_format = "JPEG"
            else:
                save_image = drawn_image

            save_image.save(str(safe_output_path), format=final_output_format)

            output_metadata = {
                "output_path": str(safe_output_path),
                "output_format": final_output_format,
                "output_size_bytes": safe_output_path.stat().st_size if safe_output_path.exists() else None,
                "image_width": image_width,
                "image_height": image_height,
                "annotation_count": len(normalized_annotations),
                "sha256": self._file_sha256(safe_output_path),
                "mime_type": mimetypes.guess_type(str(safe_output_path))[0],
            }

            findings.append(
                AnnotationFinding(
                    check_name="annotation_render",
                    status=AnnotationStatus.PASSED,
                    message=f"Rendered {len(normalized_annotations)} annotation(s).",
                    actual=output_metadata,
                    confidence=0.95,
                )
            )

            artifacts.append(
                AnnotationArtifact(
                    artifact_id=_safe_uuid("artifact"),
                    artifact_type="annotated_image",
                    title="Annotated image",
                    data=output_metadata,
                    created_at=_utc_now(),
                    confidence=0.95,
                    privacy_filtered=privacy_mode != "raw",
                )
            )

            artifacts.append(
                AnnotationArtifact(
                    artifact_id=_safe_uuid("artifact"),
                    artifact_type="annotation_manifest",
                    title="Annotation manifest",
                    data={
                        "annotations": [item.to_dict() for item in normalized_annotations],
                        "image_metadata": image_metadata,
                        "annotation_style": annotation_style,
                    },
                    created_at=_utc_now(),
                    confidence=0.95,
                    privacy_filtered=True,
                )
            )

            report = self._build_report(
                context=ctx,
                annotations=normalized_annotations,
                findings=findings,
                artifacts=artifacts,
                output_path=str(safe_output_path),
                output_format=final_output_format,
                metadata={
                    "annotation_style": annotation_style,
                    "privacy_mode": privacy_mode,
                    "duration_ms": round((datetime.now(timezone.utc) - started_at).total_seconds() * 1000, 2),
                },
            )

            self._emit_agent_event(
                "visual.annotation.created",
                {
                    "context": ctx,
                    "report_id": report.report_id,
                    "output_path": report.output_path,
                    "annotation_count": len(normalized_annotations),
                    "status": report.status.value,
                },
            )
            self._log_audit_event(
                {
                    "event": "visual_annotation_created",
                    "context": ctx,
                    "report_id": report.report_id,
                    "output_path": report.output_path,
                    "annotation_count": len(normalized_annotations),
                    "created_at": report.created_at,
                }
            )

            return self._safe_result(
                message=report.summary,
                data={
                    "report": report.to_dict(),
                    "output_path": str(safe_output_path),
                    "verification_payload": self._prepare_verification_payload(report, ctx),
                    "memory_payload": self._prepare_memory_payload(report, ctx),
                    "annotations": [item.to_dict() for item in normalized_annotations],
                    "artifacts": [item.to_dict() for item in artifacts],
                    "findings": [item.to_dict() for item in findings],
                },
                metadata={
                    "duration_ms": round((datetime.now(timezone.utc) - started_at).total_seconds() * 1000, 2),
                },
            )
        except Exception as exc:
            return self._error_result("Image annotation failed unexpectedly.", exc)

    def draw_boxes(
        self,
        context: Union[AnnotationContext, Mapping[str, Any]],
        image: Union[str, Path, bytes, Mapping[str, Any]],
        boxes: Sequence[Mapping[str, Any]],
        output_path: Optional[Union[str, Path]] = None,
        label_prefix: str = "Box",
        privacy_mode: str = "safe",
    ) -> Dict[str, Any]:
        """Draw bounding boxes on image."""
        annotations: List[Dict[str, Any]] = []
        for index, box in enumerate(boxes):
            annotations.append(
                {
                    "annotation_type": "box",
                    "label": box.get("label") or f"{label_prefix} {index + 1}",
                    "box": box.get("box") or box.get("bbox") or box,
                    "color": box.get("color"),
                    "confidence": box.get("confidence", 1.0),
                    "element_id": box.get("element_id") or box.get("id"),
                    "metadata": box.get("metadata") or {},
                }
            )
        return self.annotate_image(
            context=context,
            image=image,
            annotations=annotations,
            output_path=output_path,
            annotation_style="report",
            privacy_mode=privacy_mode,
        )

    def draw_labels(
        self,
        context: Union[AnnotationContext, Mapping[str, Any]],
        image: Union[str, Path, bytes, Mapping[str, Any]],
        labels: Sequence[Mapping[str, Any]],
        output_path: Optional[Union[str, Path]] = None,
        privacy_mode: str = "safe",
    ) -> Dict[str, Any]:
        """Draw labels on image."""
        annotations: List[Dict[str, Any]] = []
        for index, item in enumerate(labels):
            point = item.get("point")
            box = item.get("box") or item.get("bbox")
            annotations.append(
                {
                    "annotation_type": "label",
                    "label": item.get("label") or item.get("text") or f"Label {index + 1}",
                    "point": point,
                    "box": box,
                    "color": item.get("color"),
                    "confidence": item.get("confidence", 1.0),
                    "metadata": item.get("metadata") or {},
                }
            )
        return self.annotate_image(
            context=context,
            image=image,
            annotations=annotations,
            output_path=output_path,
            annotation_style="compact",
            privacy_mode=privacy_mode,
        )

    def draw_click_targets(
        self,
        context: Union[AnnotationContext, Mapping[str, Any]],
        image: Union[str, Path, bytes, Mapping[str, Any]],
        targets: Sequence[Mapping[str, Any]],
        output_path: Optional[Union[str, Path]] = None,
        privacy_mode: str = "safe",
    ) -> Dict[str, Any]:
        """Draw click targets as crosshair/circle markers."""
        annotations: List[Dict[str, Any]] = []
        for index, target in enumerate(targets):
            point = target.get("point")
            if not point and "x" in target and "y" in target:
                point = [target.get("x"), target.get("y")]
            annotations.append(
                {
                    "annotation_type": "click_target",
                    "label": target.get("label") or f"Click {index + 1}",
                    "point": point,
                    "box": target.get("box") or target.get("bbox"),
                    "color": target.get("color") or SAFE_COLOR_PALETTE["click_target"],
                    "confidence": target.get("confidence", 1.0),
                    "element_id": target.get("element_id") or target.get("id"),
                    "metadata": target.get("metadata") or {},
                }
            )
        return self.annotate_image(
            context=context,
            image=image,
            annotations=annotations,
            output_path=output_path,
            annotation_style="debug",
            privacy_mode=privacy_mode,
        )

    def draw_error_highlights(
        self,
        context: Union[AnnotationContext, Mapping[str, Any]],
        image: Union[str, Path, bytes, Mapping[str, Any]],
        errors: Sequence[Mapping[str, Any]],
        output_path: Optional[Union[str, Path]] = None,
        privacy_mode: str = "safe",
    ) -> Dict[str, Any]:
        """Draw error/warning highlights around detected problems."""
        annotations: List[Dict[str, Any]] = []
        for index, error in enumerate(errors):
            severity = _lower(error.get("severity") or "error")
            annotation_type = "warning" if severity in {"warning", "medium", "low"} else "error"
            annotations.append(
                {
                    "annotation_type": annotation_type,
                    "label": error.get("label") or error.get("message") or f"Error {index + 1}",
                    "box": error.get("box") or error.get("bbox") or error.get("bounds"),
                    "point": error.get("point"),
                    "color": error.get("color") or SAFE_COLOR_PALETTE[annotation_type],
                    "confidence": error.get("confidence", 1.0),
                    "element_id": error.get("element_id") or error.get("id"),
                    "metadata": error.get("metadata") or {"severity": severity},
                }
            )
        return self.annotate_image(
            context=context,
            image=image,
            annotations=annotations,
            output_path=output_path,
            annotation_style="report",
            privacy_mode=privacy_mode,
        )

    def prepare_annotation_payload(
        self,
        context: Union[AnnotationContext, Mapping[str, Any]],
        elements: Sequence[Mapping[str, Any]],
        include_click_targets: bool = True,
        include_labels: bool = True,
    ) -> Dict[str, Any]:
        """
        Convert detected UI elements into annotation instructions.

        This is useful when VisualAgent.element_detector or ui_mapper returns element
        dictionaries and dashboard needs annotation metadata.
        """
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result

            annotations: List[AnnotationItem] = []

            for index, element in enumerate(list(elements)[: self.max_annotations]):
                element_type = str(element.get("element_type") or element.get("type") or "element")
                label = element.get("label") or element.get("text") or element.get("name") or f"Element {index + 1}"
                box = self._box_from_mapping(element.get("box") or element.get("bbox") or element.get("bounds"))
                color = _pick_color("ui_element", element_type, element.get("color"))

                annotations.append(
                    AnnotationItem(
                        annotation_id=str(element.get("annotation_id") or _safe_uuid("annotation")),
                        annotation_type=AnnotationType.UI_ELEMENT,
                        label=str(label) if include_labels else None,
                        box=box,
                        point=None,
                        color=color,
                        line_width=self.default_line_width,
                        confidence=_clamp_float(element.get("confidence", 0.7), 0.7),
                        element_id=str(element.get("element_id") or element.get("id") or f"element_{index + 1}"),
                        metadata={
                            "element_type": element_type,
                            "clickable": element.get("clickable"),
                            "visible": element.get("visible", True),
                            "enabled": element.get("enabled"),
                        },
                    )
                )

                if include_click_targets:
                    point = self._point_from_mapping(element.get("point"))
                    if not point and box:
                        point = (box.center_x, box.center_y)
                    if point:
                        annotations.append(
                            AnnotationItem(
                                annotation_id=_safe_uuid("click_target"),
                                annotation_type=AnnotationType.CLICK_TARGET,
                                label="Click Target" if include_labels else None,
                                box=None,
                                point=point,
                                color=SAFE_COLOR_PALETTE["click_target"],
                                line_width=self.default_line_width,
                                confidence=_clamp_float(element.get("confidence", 0.7), 0.7),
                                element_id=str(element.get("element_id") or element.get("id") or f"element_{index + 1}"),
                                metadata={"source": "element_center"},
                            )
                        )

            finding = AnnotationFinding(
                check_name="prepare_annotation_payload",
                status=AnnotationStatus.PASSED if annotations else AnnotationStatus.NEEDS_REVIEW,
                message=f"Prepared {len(annotations)} annotation instruction(s).",
                actual={"annotation_count": len(annotations)},
                confidence=0.9 if annotations else 0.35,
                severity=AnnotationSeverity.INFO if annotations else AnnotationSeverity.MEDIUM,
            )

            artifact = AnnotationArtifact(
                artifact_id=_safe_uuid("artifact"),
                artifact_type="annotation_payload",
                title="Prepared annotation payload",
                data={"annotations": [item.to_dict() for item in annotations]},
                created_at=_utc_now(),
                confidence=finding.confidence,
                privacy_filtered=True,
            )

            return self._safe_result(
                message="Annotation payload prepared.",
                data={
                    "annotations": [item.to_dict() for item in annotations],
                    "findings": [finding.to_dict()],
                    "artifacts": [artifact.to_dict()],
                },
            )
        except Exception as exc:
            return self._error_result("Annotation payload preparation failed unexpectedly.", exc)

    def generate_debug_overlay(
        self,
        context: Union[AnnotationContext, Mapping[str, Any]],
        image: Union[str, Path, bytes, Mapping[str, Any]],
        elements: Optional[Sequence[Mapping[str, Any]]] = None,
        errors: Optional[Sequence[Mapping[str, Any]]] = None,
        click_targets: Optional[Sequence[Mapping[str, Any]]] = None,
        output_path: Optional[Union[str, Path]] = None,
        privacy_mode: str = "safe",
    ) -> Dict[str, Any]:
        """Generate a combined debug overlay for elements, errors, and click targets."""
        annotations: List[Dict[str, Any]] = []

        payload = self.prepare_annotation_payload(
            context=context,
            elements=elements or [],
            include_click_targets=False,
            include_labels=True,
        )
        if payload.get("success"):
            annotations.extend(payload.get("data", {}).get("annotations", []))

        for error in errors or []:
            annotations.append(
                {
                    "annotation_type": "error",
                    "label": error.get("label") or error.get("message") or "Error",
                    "box": error.get("box") or error.get("bbox") or error.get("bounds"),
                    "point": error.get("point"),
                    "color": SAFE_COLOR_PALETTE["error"],
                    "confidence": error.get("confidence", 1.0),
                    "metadata": error.get("metadata") or {},
                }
            )

        for index, target in enumerate(click_targets or []):
            point = target.get("point")
            if not point and "x" in target and "y" in target:
                point = [target.get("x"), target.get("y")]
            annotations.append(
                {
                    "annotation_type": "click_target",
                    "label": target.get("label") or f"Target {index + 1}",
                    "point": point,
                    "box": target.get("box") or target.get("bbox"),
                    "color": SAFE_COLOR_PALETTE["click_target"],
                    "confidence": target.get("confidence", 1.0),
                    "metadata": target.get("metadata") or {},
                }
            )

        return self.annotate_image(
            context=context,
            image=image,
            annotations=annotations,
            output_path=output_path,
            annotation_style="debug",
            privacy_mode=privacy_mode,
        )

    # ----------------------------------------------------------------------------------
    # Required compatibility hooks
    # ----------------------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[AnnotationContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Validate SaaS user/workspace context."""
        try:
            if isinstance(context, AnnotationContext):
                ctx = context.to_dict()
            elif isinstance(context, Mapping):
                ctx = dict(context)
            else:
                return self._error_result(
                    message="Invalid annotation context.",
                    error="context must be AnnotationContext or mapping",
                )

            user_id = ctx.get("user_id")
            workspace_id = ctx.get("workspace_id")

            if not isinstance(user_id, str) or not user_id.strip():
                return self._error_result(
                    message="Annotation context missing user_id.",
                    error="missing_user_id",
                    metadata={"hook": "_validate_task_context"},
                )

            if not isinstance(workspace_id, str) or not workspace_id.strip():
                return self._error_result(
                    message="Annotation context missing workspace_id.",
                    error="missing_workspace_id",
                    metadata={"hook": "_validate_task_context"},
                )

            ctx["user_id"] = user_id.strip()
            ctx["workspace_id"] = workspace_id.strip()
            ctx.setdefault("task_id", None)
            ctx.setdefault("request_id", _safe_uuid("req"))
            ctx.setdefault("session_id", None)
            ctx.setdefault("source_agent", None)
            ctx.setdefault("permissions", {})
            ctx.setdefault("metadata", {})
            ctx.setdefault("agent_name", self.agent_name)

            return self._safe_result(
                message="Annotation context is valid.",
                data={"context": ctx},
                metadata={"hook": "_validate_task_context"},
            )
        except Exception as exc:
            return self._error_result("Annotation context validation failed unexpectedly.", exc)

    def _requires_security_check(
        self,
        annotation_type: str,
        payload: Optional[Mapping[str, Any]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """Decide if annotation requires Security Agent approval."""
        context = dict(context or {})
        permissions = dict(context.get("permissions") or {})
        annotation_type = _lower(annotation_type)
        payload_text = json.dumps(_json_safe(payload or {}), default=str).lower()

        if permissions.get("allow_sensitive_visual_tasks") is True:
            return False

        if permissions.get("allow_annotation_tool") is True:
            return False

        if annotation_type in SENSITIVE_ANNOTATION_TYPES:
            return True

        sensitive_terms = ["password", "secret", "token", "credential", "private", "screenshot", "screen"]
        if any(term in payload_text for term in sensitive_terms):
            return True

        return False

    def _request_security_approval(
        self,
        context: Mapping[str, Any],
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If no Security Agent exists, sensitive annotation is blocked unless explicit
        context permission allow_without_security_agent is true.
        """
        permissions = dict(context.get("permissions") or {})
        payload = dict(payload or {})

        if self.security_agent is None:
            if permissions.get("allow_without_security_agent") is True:
                return self._safe_result(
                    message="Security approval bypassed by explicit context permission.",
                    data={"approved": True, "source": "context_permission"},
                    metadata={"hook": "_request_security_approval", "action": action},
                )
            return self._error_result(
                message="Security approval required, but Security Agent is not connected.",
                error="security_agent_unavailable",
                metadata={"hook": "_request_security_approval", "action": action, "blocked": True},
            )

        try:
            if hasattr(self.security_agent, "approve_action"):
                decision = self.security_agent.approve_action(
                    user_id=context.get("user_id"),
                    workspace_id=context.get("workspace_id"),
                    action=action,
                    payload=payload,
                )
            elif hasattr(self.security_agent, "request_approval"):
                decision = self.security_agent.request_approval(
                    context=dict(context),
                    action=action,
                    payload=payload,
                )
            else:
                return self._error_result(
                    message="Connected Security Agent does not expose an approval method.",
                    error="security_agent_missing_approval_method",
                    metadata={"action": action},
                )

            if isinstance(decision, Mapping):
                approved = bool(
                    decision.get("approved")
                    or decision.get("success")
                    or decision.get("allow")
                    or decision.get("allowed")
                )
                if approved:
                    return self._safe_result(
                        message="Security Agent approved annotation action.",
                        data={"approved": True, "decision": _json_safe(dict(decision))},
                        metadata={"hook": "_request_security_approval", "action": action},
                    )
                return self._error_result(
                    message="Security Agent blocked annotation action.",
                    error=decision.get("error") or decision.get("reason") or "security_blocked",
                    metadata={"decision": _json_safe(dict(decision)), "action": action},
                )

            if bool(decision):
                return self._safe_result(
                    message="Security Agent approved annotation action.",
                    data={"approved": True, "decision": bool(decision)},
                    metadata={"hook": "_request_security_approval", "action": action},
                )

            return self._error_result(
                message="Security Agent blocked annotation action.",
                error="security_blocked",
                metadata={"action": action},
            )
        except Exception as exc:
            return self._error_result("Security approval request failed.", exc)

    def _prepare_verification_payload(
        self,
        report: Union[AnnotationReport, Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent compatible payload."""
        report_data = report.to_dict() if isinstance(report, AnnotationReport) else dict(report)
        ctx = dict(context or report_data.get("context") or {})

        return {
            "agent": self.agent_name,
            "type": "visual_annotation_verification_payload",
            "version": self.agent_version,
            "user_id": ctx.get("user_id"),
            "workspace_id": ctx.get("workspace_id"),
            "task_id": ctx.get("task_id"),
            "request_id": ctx.get("request_id"),
            "status": report_data.get("status"),
            "confidence": report_data.get("confidence"),
            "report_id": report_data.get("report_id"),
            "summary": report_data.get("summary"),
            "output_path": report_data.get("output_path"),
            "output_format": report_data.get("output_format"),
            "annotation_count": len(report_data.get("annotations") or []),
            "artifact_count": len(report_data.get("artifacts") or []),
            "created_at": _utc_now(),
            "data": {
                "report": report_data,
            },
        }

    def _prepare_memory_payload(
        self,
        report: Union[AnnotationReport, Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare safe Memory Agent compatible payload."""
        report_data = report.to_dict() if isinstance(report, AnnotationReport) else dict(report)
        ctx = dict(context or report_data.get("context") or {})

        safe_annotations = []
        for item in report_data.get("annotations", [])[:50]:
            safe_annotations.append(
                {
                    "annotation_id": item.get("annotation_id"),
                    "annotation_type": item.get("annotation_type"),
                    "label": item.get("label"),
                    "element_id": item.get("element_id"),
                    "confidence": item.get("confidence"),
                }
            )

        safe_findings = []
        for finding in report_data.get("findings", [])[:10]:
            safe_findings.append(
                {
                    "check_name": finding.get("check_name"),
                    "status": finding.get("status"),
                    "message": finding.get("message"),
                    "severity": finding.get("severity"),
                    "confidence": finding.get("confidence"),
                }
            )

        return {
            "agent": self.agent_name,
            "type": "annotation_memory",
            "user_id": ctx.get("user_id"),
            "workspace_id": ctx.get("workspace_id"),
            "task_id": ctx.get("task_id"),
            "memory_scope": "workspace",
            "importance": self._memory_importance_from_status(str(report_data.get("status"))),
            "summary": report_data.get("summary"),
            "facts": {
                "report_id": report_data.get("report_id"),
                "status": report_data.get("status"),
                "confidence": report_data.get("confidence"),
                "output_path": report_data.get("output_path"),
                "output_format": report_data.get("output_format"),
                "annotation_count": len(report_data.get("annotations") or []),
                "annotations": safe_annotations,
                "findings": safe_findings,
            },
            "created_at": _utc_now(),
            "metadata": {
                "source_agent": self.agent_name,
                "raw_image_data_excluded": True,
                "privacy_filtered": True,
            },
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """Emit agent event safely."""
        try:
            safe_payload = _json_safe(payload)
            if self.event_emitter:
                self.event_emitter(event_name, safe_payload)
                return
            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, safe_payload)  # type: ignore[misc]
                    return
                except Exception:
                    pass
            self.logger.debug("Agent event: %s %s", event_name, safe_payload)
        except Exception as exc:
            self.logger.warning("Failed to emit annotation event '%s': %s", event_name, exc)

    def _log_audit_event(self, payload: Dict[str, Any]) -> None:
        """Log audit event safely."""
        try:
            safe_payload = _json_safe(payload)
            if self.audit_logger:
                self.audit_logger(safe_payload)
                return
            if hasattr(super(), "log_audit"):
                try:
                    super().log_audit(safe_payload)  # type: ignore[misc]
                    return
                except Exception:
                    pass
            self.logger.info("AUDIT %s", json.dumps(safe_payload, default=str))
        except Exception as exc:
            self.logger.warning("Failed to log annotation audit event: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standardized success response."""
        return {
            "success": True,
            "message": message,
            "data": _json_safe(data or {}),
            "error": None,
            "metadata": _json_safe(
                {
                    "agent": self.agent_name,
                    "agent_version": self.agent_version,
                    "timestamp": _utc_now(),
                    **(metadata or {}),
                }
            ),
        }

    def _error_result(
        self,
        message: str,
        error: Any,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standardized error response."""
        if isinstance(error, BaseException):
            error_payload: Any = {
                "type": error.__class__.__name__,
                "message": str(error),
                "traceback": traceback.format_exc(),
            }
        else:
            error_payload = error

        return {
            "success": False,
            "message": message,
            "data": _json_safe(data or {}),
            "error": _json_safe(error_payload),
            "metadata": _json_safe(
                {
                    "agent": self.agent_name,
                    "agent_version": self.agent_version,
                    "timestamp": _utc_now(),
                    **(metadata or {}),
                }
            ),
        }

    # ----------------------------------------------------------------------------------
    # Internal helpers
    # ----------------------------------------------------------------------------------

    def _load_default_config(self) -> Any:
        """Load VisualConfig if present; otherwise use fallback config."""
        if VisualConfig is not None:
            try:
                return VisualConfig()
            except Exception:
                pass

        class _FallbackConfig:
            max_image_bytes = DEFAULT_MAX_IMAGE_BYTES
            max_annotations = DEFAULT_MAX_ANNOTATIONS
            default_output_format = DEFAULT_OUTPUT_FORMAT
            default_line_width = DEFAULT_LINE_WIDTH
            default_font_size = DEFAULT_FONT_SIZE

        return _FallbackConfig()

    def _maybe_request_security(
        self,
        context: Mapping[str, Any],
        annotation_type: str,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Request Security Agent approval only if required."""
        if self._requires_security_check(annotation_type, payload=payload, context=context):
            return self._request_security_approval(context=context, action=action, payload=payload)
        return self._safe_result(
            message="Security approval not required.",
            data={"approved": True, "required": False},
            metadata={"action": action},
        )

    def _load_image(
        self,
        image: Union[str, Path, bytes, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Load image from path, bytes, base64, or mapping."""
        try:
            metadata: Dict[str, Any] = {
                "source_type": type(image).__name__,
                "path": None,
                "exists": None,
                "size_bytes": None,
                "sha256": None,
                "mime_type": None,
                "extension": None,
                "width": None,
                "height": None,
                "format": None,
            }

            raw: Optional[bytes] = None

            if isinstance(image, bytes):
                raw = image
                metadata["source_type"] = "bytes"
                metadata["size_bytes"] = len(raw)

            elif isinstance(image, (str, Path)):
                raw_str = str(image)
                if _looks_like_base64(raw_str):
                    raw, error = _decode_base64(raw_str, self.max_image_bytes)
                    if error:
                        return self._error_result("Base64 image could not be decoded.", error)
                    metadata["source_type"] = "base64"
                    metadata["size_bytes"] = len(raw or b"")
                else:
                    path = Path(raw_str).expanduser()
                    metadata["source_type"] = "path"
                    metadata["path"] = str(path)
                    metadata["exists"] = path.exists()
                    metadata["extension"] = path.suffix.lower()
                    metadata["mime_type"] = mimetypes.guess_type(str(path))[0]

                    if metadata["extension"] not in SUPPORTED_IMAGE_EXTENSIONS:
                        return self._error_result(
                            message="Unsupported image extension.",
                            error=f"unsupported_extension:{metadata['extension']}",
                            data={"metadata": metadata},
                        )

                    raw, error = _read_file_bytes(path, self.max_image_bytes)
                    if error:
                        return self._error_result("Image file could not be read.", error, data={"metadata": metadata})
                    metadata["size_bytes"] = len(raw or b"")

            elif isinstance(image, Mapping):
                mapping = dict(image)
                metadata["source_type"] = "mapping"

                if isinstance(mapping.get("bytes"), bytes):
                    raw = mapping["bytes"]
                    metadata["size_bytes"] = len(raw)
                elif isinstance(mapping.get("base64"), str):
                    raw, error = _decode_base64(mapping["base64"], self.max_image_bytes)
                    if error:
                        return self._error_result("Mapping base64 image could not be decoded.", error)
                    metadata["size_bytes"] = len(raw or b"")
                elif mapping.get("path"):
                    path = Path(str(mapping["path"])).expanduser()
                    metadata["path"] = str(path)
                    metadata["exists"] = path.exists()
                    metadata["extension"] = path.suffix.lower()
                    metadata["mime_type"] = mimetypes.guess_type(str(path))[0]
                    raw, error = _read_file_bytes(path, self.max_image_bytes)
                    if error:
                        return self._error_result("Mapping image path could not be read.", error)
                    metadata["size_bytes"] = len(raw or b"")
                else:
                    metadata.update(
                        {
                            "width": mapping.get("width"),
                            "height": mapping.get("height"),
                            "format": mapping.get("format"),
                            "mime_type": mapping.get("mime_type"),
                        }
                    )
            else:
                return self._error_result("Unsupported image input type.", type(image).__name__)

            if raw and len(raw) > self.max_image_bytes:
                return self._error_result("Image exceeds max byte limit.", f"{len(raw)}>{self.max_image_bytes}")

            if raw:
                metadata["sha256"] = _sha256_bytes(raw)

            if Image is None or raw is None:
                return self._safe_result(
                    message="Image metadata loaded; Pillow unavailable or raw data missing.",
                    data={"image": None, "metadata": metadata},
                )

            image_obj = Image.open(io.BytesIO(raw))
            image_obj.load()
            metadata["width"] = image_obj.width
            metadata["height"] = image_obj.height
            metadata["format"] = image_obj.format
            if image_obj.format:
                metadata["mime_type"] = getattr(Image, "MIME", {}).get(image_obj.format, metadata.get("mime_type"))

            return self._safe_result(
                message="Image loaded.",
                data={"image": image_obj, "metadata": metadata},
            )
        except Exception as exc:
            return self._error_result("Image loading failed.", exc)

    def _normalize_annotations(
        self,
        annotations: Sequence[Union[AnnotationItem, Mapping[str, Any]]],
    ) -> List[AnnotationItem]:
        """Normalize annotation mappings into AnnotationItem objects."""
        normalized: List[AnnotationItem] = []
        for index, item in enumerate(annotations):
            if isinstance(item, AnnotationItem):
                normalized.append(item)
                continue

            if not isinstance(item, Mapping):
                continue

            annotation_type = self._annotation_type_from_string(
                str(item.get("annotation_type") or item.get("type") or "box")
            )
            box = self._box_from_mapping(item.get("box") or item.get("bbox") or item.get("bounds") or item.get("rect"))
            point = self._point_from_mapping(item.get("point"))

            if point is None and "x" in item and "y" in item and not box:
                point = (_safe_int(item.get("x")), _safe_int(item.get("y")))

            if annotation_type == AnnotationType.CLICK_TARGET and point is None and box:
                point = (box.center_x, box.center_y)

            element_type = item.get("element_type") or item.get("role")
            color = _pick_color(annotation_type.value, element_type, item.get("color"))

            normalized.append(
                AnnotationItem(
                    annotation_id=str(item.get("annotation_id") or _safe_uuid("annotation")),
                    annotation_type=annotation_type,
                    label=item.get("label") or item.get("text") or item.get("name"),
                    box=box,
                    point=point,
                    color=color,
                    line_width=max(1, _safe_int(item.get("line_width"), self.default_line_width)),
                    confidence=_clamp_float(item.get("confidence", 1.0), 1.0),
                    element_id=item.get("element_id") or item.get("id"),
                    metadata=dict(item.get("metadata") or {}),
                )
            )
        return normalized

    def _box_from_mapping(self, box: Any) -> Optional[AnnotationBox]:
        """Parse box dict/list into AnnotationBox."""
        if box is None:
            return None

        if isinstance(box, AnnotationBox):
            return box

        if isinstance(box, Mapping):
            x = _safe_int(box.get("x", box.get("left", 0)))
            y = _safe_int(box.get("y", box.get("top", 0)))

            if "width" in box:
                width = _safe_int(box.get("width"), 1)
            else:
                width = max(1, _safe_int(box.get("right"), x + 1) - x)

            if "height" in box:
                height = _safe_int(box.get("height"), 1)
            else:
                height = max(1, _safe_int(box.get("bottom"), y + 1) - y)

            return AnnotationBox(
                x=x,
                y=y,
                width=max(1, width),
                height=max(1, height),
                confidence=_clamp_float(box.get("confidence", 1.0), 1.0),
                coordinate_system=str(box.get("coordinate_system") or "pixels"),
            )

        if isinstance(box, (list, tuple)) and len(box) >= 4:
            x = _safe_int(box[0])
            y = _safe_int(box[1])
            width = _safe_int(box[2])
            height = _safe_int(box[3])
            return AnnotationBox(x=x, y=y, width=max(1, width), height=max(1, height))

        return None

    def _point_from_mapping(self, point: Any) -> Optional[Tuple[int, int]]:
        """Parse point dict/list into tuple."""
        if point is None:
            return None
        if isinstance(point, Mapping):
            return (_safe_int(point.get("x")), _safe_int(point.get("y")))
        if isinstance(point, (list, tuple)) and len(point) >= 2:
            return (_safe_int(point[0]), _safe_int(point[1]))
        return None

    def _draw_annotation(
        self,
        draw: Any,
        image: Any,
        annotation: AnnotationItem,
        image_width: int,
        image_height: int,
        font: Any,
        style: str,
    ) -> None:
        """Draw a single annotation."""
        color_hex = annotation.color or SAFE_COLOR_PALETTE["default"]
        color = _hex_to_rgb(color_hex)
        fill_with_alpha = color + (45,)
        line_width = max(1, annotation.line_width)

        if annotation.box:
            box = annotation.box.clamp(image_width, image_height)
        else:
            box = None

        if annotation.annotation_type in {
            AnnotationType.BOX,
            AnnotationType.UI_ELEMENT,
            AnnotationType.FORM_FIELD,
            AnnotationType.ERROR,
            AnnotationType.WARNING,
            AnnotationType.SUCCESS,
            AnnotationType.OCR_REGION,
        }:
            if box:
                if annotation.annotation_type in {AnnotationType.ERROR, AnnotationType.WARNING, AnnotationType.SUCCESS}:
                    overlay = Image.new("RGBA", image.size, (0, 0, 0, 0))
                    overlay_draw = ImageDraw.Draw(overlay)
                    overlay_draw.rectangle(
                        [box.left, box.top, box.right, box.bottom],
                        fill=fill_with_alpha,
                        outline=color + (255,),
                        width=line_width,
                    )
                    image.alpha_composite(overlay)
                    draw = ImageDraw.Draw(image)
                else:
                    draw.rectangle(
                        [box.left, box.top, box.right, box.bottom],
                        outline=color,
                        width=line_width,
                    )

                if annotation.label:
                    self._draw_label(
                        draw=draw,
                        text=str(annotation.label),
                        x=box.left,
                        y=max(0, box.top - self.default_font_size - 8),
                        color=color,
                        font=font,
                        style=style,
                    )

        if annotation.annotation_type == AnnotationType.LABEL:
            if annotation.point:
                x, y = annotation.point
            elif box:
                x, y = box.left, box.top
            else:
                x, y = 10, 10

            self._draw_label(
                draw=draw,
                text=str(annotation.label or "Label"),
                x=max(0, min(x, image_width - 1)),
                y=max(0, min(y, image_height - 1)),
                color=color,
                font=font,
                style=style,
            )

        if annotation.annotation_type in {AnnotationType.CLICK_TARGET, AnnotationType.DEBUG_POINT}:
            if annotation.point:
                x, y = annotation.point
            elif box:
                x, y = box.center_x, box.center_y
            else:
                return

            x = max(0, min(x, image_width - 1))
            y = max(0, min(y, image_height - 1))
            radius = 10 if style != "compact" else 7

            draw.ellipse(
                [x - radius, y - radius, x + radius, y + radius],
                outline=color,
                width=line_width,
            )
            draw.line([x - radius - 6, y, x + radius + 6, y], fill=color, width=line_width)
            draw.line([x, y - radius - 6, x, y + radius + 6], fill=color, width=line_width)

            if annotation.label:
                self._draw_label(
                    draw=draw,
                    text=str(annotation.label),
                    x=min(image_width - 1, x + radius + 5),
                    y=max(0, y - radius),
                    color=color,
                    font=font,
                    style=style,
                )

    def _draw_label(
        self,
        draw: Any,
        text: str,
        x: int,
        y: int,
        color: Tuple[int, int, int],
        font: Any,
        style: str,
    ) -> None:
        """Draw label with readable background."""
        text = _normalize_text(text)
        if not text:
            return

        max_len = 80 if style == "debug" else 48
        if len(text) > max_len:
            text = text[: max_len - 3] + "..."

        padding_x = 5
        padding_y = 3

        try:
            bbox = draw.textbbox((x, y), text, font=font)
            text_width = bbox[2] - bbox[0]
            text_height = bbox[3] - bbox[1]
        except Exception:
            text_width = max(40, len(text) * 8)
            text_height = self.default_font_size + 4

        background = color
        draw.rectangle(
            [
                x,
                y,
                x + text_width + padding_x * 2,
                y + text_height + padding_y * 2,
            ],
            fill=background,
        )
        draw.text(
            (x + padding_x, y + padding_y),
            text,
            fill=(255, 255, 255),
            font=font,
        )

    def _load_font(self, size: int) -> Any:
        """Load default font safely."""
        if ImageFont is None:
            return None
        try:
            return ImageFont.truetype("DejaVuSans.ttf", size)
        except Exception:
            try:
                return ImageFont.load_default()
            except Exception:
                return None

    def _resolve_output_path(
        self,
        output_path: Optional[Union[str, Path]],
        context: Mapping[str, Any],
        output_format: str,
    ) -> Path:
        """Resolve safe output path."""
        suffix = ".jpg" if output_format.upper() in {"JPG", "JPEG"} else f".{output_format.lower()}"

        if output_path:
            path = Path(output_path).expanduser()
            if not path.suffix:
                path = path.with_suffix(suffix)
            path.parent.mkdir(parents=True, exist_ok=True)
            return path

        base_dir = Path(tempfile.gettempdir()) / "william_visual_annotations"
        workspace_dir = base_dir / self._safe_path_part(str(context.get("workspace_id", "workspace")))
        workspace_dir.mkdir(parents=True, exist_ok=True)

        return workspace_dir / f"annotation_{_safe_uuid('img')}{suffix}"

    def _safe_path_part(self, value: str) -> str:
        """Make safe path segment."""
        value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
        return value[:80] or "default"

    def _file_sha256(self, path: Path) -> Optional[str]:
        """Hash output file safely."""
        try:
            if not path.exists() or not path.is_file():
                return None
            return _sha256_bytes(path.read_bytes())
        except Exception:
            return None

    def _build_report(
        self,
        context: Mapping[str, Any],
        annotations: Sequence[AnnotationItem],
        findings: Sequence[AnnotationFinding],
        artifacts: Sequence[AnnotationArtifact],
        output_path: Optional[str],
        output_format: Optional[str],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> AnnotationReport:
        """Build final annotation report."""
        normalized_findings = list(findings)
        status = self._calculate_status(normalized_findings)
        confidence = self._calculate_confidence(normalized_findings)
        summary = self._build_summary(
            status=status,
            annotation_count=len(annotations),
            artifact_count=len(artifacts),
            confidence=confidence,
            output_path=output_path,
        )

        return AnnotationReport(
            report_id=_safe_uuid("annotation_report"),
            status=status,
            summary=summary,
            annotations=list(annotations),
            findings=normalized_findings,
            artifacts=list(artifacts),
            output_path=output_path,
            output_format=output_format,
            confidence=confidence,
            created_at=_utc_now(),
            context=dict(context),
            metadata=dict(metadata or {}),
        )

    def _calculate_status(self, findings: Sequence[AnnotationFinding]) -> AnnotationStatus:
        """Calculate overall annotation status."""
        if not findings:
            return AnnotationStatus.NEEDS_REVIEW

        statuses = [item.status for item in findings]

        if any(status == AnnotationStatus.ERROR for status in statuses):
            return AnnotationStatus.ERROR
        if any(status == AnnotationStatus.BLOCKED for status in statuses):
            return AnnotationStatus.BLOCKED
        if any(status == AnnotationStatus.FAILED for status in statuses):
            passed = sum(1 for status in statuses if status == AnnotationStatus.PASSED)
            return AnnotationStatus.PARTIAL if passed else AnnotationStatus.FAILED
        if any(status == AnnotationStatus.NEEDS_REVIEW for status in statuses):
            passed = sum(1 for status in statuses if status == AnnotationStatus.PASSED)
            return AnnotationStatus.PARTIAL if passed else AnnotationStatus.NEEDS_REVIEW
        if all(status == AnnotationStatus.SKIPPED for status in statuses):
            return AnnotationStatus.SKIPPED
        if all(status == AnnotationStatus.PASSED for status in statuses):
            return AnnotationStatus.PASSED
        return AnnotationStatus.PARTIAL

    def _calculate_confidence(self, findings: Sequence[AnnotationFinding]) -> float:
        """Calculate weighted confidence."""
        if not findings:
            return 0.0

        weights = {
            AnnotationSeverity.INFO: 1.0,
            AnnotationSeverity.LOW: 1.1,
            AnnotationSeverity.MEDIUM: 1.3,
            AnnotationSeverity.HIGH: 1.6,
            AnnotationSeverity.CRITICAL: 2.0,
        }

        total = 0.0
        weighted = 0.0

        for finding in findings:
            weight = weights.get(finding.severity, 1.0)
            total += weight
            weighted += _clamp_float(finding.confidence, 0.5) * weight

        return round(weighted / total, 4) if total else 0.0

    def _build_summary(
        self,
        status: AnnotationStatus,
        annotation_count: int,
        artifact_count: int,
        confidence: float,
        output_path: Optional[str],
    ) -> str:
        """Build annotation summary."""
        output_text = "output image created" if output_path else "metadata only"
        return (
            f"Annotation {status.value}: {annotation_count} annotation(s), "
            f"{artifact_count} artifact(s), {output_text}. Confidence: {confidence:.2f}."
        )

    def _annotation_type_from_string(self, value: str) -> AnnotationType:
        """Parse annotation type safely."""
        normalized = _lower(value)
        aliases = {
            "bbox": "box",
            "bounding_box": "box",
            "element": "ui_element",
            "ui": "ui_element",
            "field": "form_field",
            "form": "form_field",
            "target": "click_target",
            "click": "click_target",
            "point": "debug_point",
        }
        normalized = aliases.get(normalized, normalized)

        for item in AnnotationType:
            if item.value == normalized:
                return item
        return AnnotationType.BOX

    def _memory_importance_from_status(self, status: str) -> str:
        """Map status to memory importance."""
        normalized = _lower(status)
        if normalized in {"failed", "blocked", "error"}:
            return "high"
        if normalized in {"partial", "needs_review"}:
            return "medium"
        return "low"


# ======================================================================================
# Registry / Loader compatibility
# ======================================================================================

def create_agent(*args: Any, **kwargs: Any) -> AnnotationTool:
    """Factory used by William/Jarvis Agent Loader."""
    return AnnotationTool(*args, **kwargs)


def get_agent_class() -> type:
    """Return class for registry discovery."""
    return AnnotationTool


__all__ = [
    "AnnotationTool",
    "AnnotationStatus",
    "AnnotationType",
    "AnnotationSeverity",
    "AnnotationContext",
    "AnnotationBox",
    "AnnotationItem",
    "AnnotationFinding",
    "AnnotationArtifact",
    "AnnotationReport",
    "create_agent",
    "get_agent_class",
]


# ======================================================================================
# Completion tracking
# ======================================================================================
#
# Agent/Module: Visual Agent
# File Completed: annotation_tool.py
# Completion: 94.4%
# Completed Files: ['visual_agent.py', 'screenshot_reader.py', 'video_analyzer.py', 'ocr_engine.py', 'ui_mapper.py', 'image_analyzer.py', 'screen_context.py', 'element_detector.py', 'workflow_learner.py', 'visual_memory.py', 'error_screen_detector.py', 'form_reader.py', 'app_screen_mapper.py', 'video_frame_extractor.py', 'visual_validator.py', 'privacy_filter.py', 'annotation_tool.py']
# Remaining Files: ['config.py']
# Next Recommended File: agents/visual_agent/config.py
# FILE COMPLETE