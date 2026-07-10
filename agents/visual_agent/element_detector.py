"""
agents/visual_agent/element_detector.py

William / Jarvis Multi-Agent AI SaaS System
Visual Agent - Element Detector

Purpose:
    Finds buttons, inputs, cards, icons, labels, bounds, confidence.

This module is intentionally import-safe:
    - It does not require the rest of William/Jarvis to exist.
    - It uses optional Pillow/OpenCV/Numpy only when installed.
    - It provides fallback BaseAgent behavior if core modules are unavailable.
    - It does not execute destructive, browser, system, call, message, or financial actions.
    - It supports SaaS user/workspace isolation through required task context.

Responsibilities:
    - Detect UI-like elements from screenshots/images.
    - Detect and classify elements from OCR boxes.
    - Merge OCR, visual, and layout-hint detections.
    - Return structured bounds, labels, element types, confidence, and evidence.
    - Prepare Verification Agent payloads.
    - Prepare Memory Agent payloads.
    - Emit agent events and audit logs where integrations are available.

Connections:
    - Master Agent:
        Can call detect_elements() after screenshots, visual tasks, or UI automation tasks.
    - Visual Agent:
        This helper powers UI element detection for screen analysis, workflow learning,
        form reading, UI mapping, and visual validation.
    - Security Agent:
        Included hooks for compatibility. This file performs safe read-only analysis only.
    - Verification Agent:
        Produces verification-compatible payloads after completed detection.
    - Memory Agent:
        Can prepare memory-compatible summaries of reusable UI patterns.
    - Dashboard/API:
        All public methods return dict/JSON-style results.
    - Agent Registry / Agent Loader:
        Exposes stable class name ElementDetector and metadata helpers.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import math
import os
import re
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------

try:
    from PIL import Image, ImageEnhance, ImageFilter, ImageOps  # type: ignore
except Exception:  # pragma: no cover
    Image = None  # type: ignore
    ImageEnhance = None  # type: ignore
    ImageFilter = None  # type: ignore
    ImageOps = None  # type: ignore

try:
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover
    np = None  # type: ignore

try:
    import cv2  # type: ignore
except Exception:  # pragma: no cover
    cv2 = None  # type: ignore


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    try:
        from core.base_agent import BaseAgent  # type: ignore
    except Exception:

        class BaseAgent:  # type: ignore
            """
            Import-safe fallback BaseAgent.

            Real William/Jarvis deployments should provide their own BaseAgent.
            This fallback allows this file to be imported and tested before the
            full project is available.
            """

            def __init__(self, *args: Any, **kwargs: Any) -> None:
                self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
                self.logger = logging.getLogger(self.agent_name)

            def emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
                self.logger.debug("Fallback emit_event: %s %s", event_type, payload)

            def log_audit(self, payload: Dict[str, Any]) -> None:
                self.logger.info("Fallback audit_log: %s", payload)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("William.VisualAgent.ElementDetector")
if not LOGGER.handlers:
    logging.basicConfig(
        level=os.getenv("WILLIAM_LOG_LEVEL", "INFO"),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ELEMENT_BUTTON = "button"
ELEMENT_INPUT = "input"
ELEMENT_CARD = "card"
ELEMENT_ICON = "icon"
ELEMENT_LABEL = "label"
ELEMENT_LINK = "link"
ELEMENT_CHECKBOX = "checkbox"
ELEMENT_TOGGLE = "toggle"
ELEMENT_IMAGE = "image"
ELEMENT_CONTAINER = "container"
ELEMENT_UNKNOWN = "unknown"

SUPPORTED_ELEMENT_TYPES = {
    ELEMENT_BUTTON,
    ELEMENT_INPUT,
    ELEMENT_CARD,
    ELEMENT_ICON,
    ELEMENT_LABEL,
    ELEMENT_LINK,
    ELEMENT_CHECKBOX,
    ELEMENT_TOGGLE,
    ELEMENT_IMAGE,
    ELEMENT_CONTAINER,
    ELEMENT_UNKNOWN,
}

BUTTON_WORDS = {
    "submit",
    "send",
    "save",
    "next",
    "continue",
    "login",
    "log in",
    "sign in",
    "sign up",
    "register",
    "start",
    "stop",
    "cancel",
    "apply",
    "search",
    "buy",
    "order",
    "call",
    "quote",
    "get quote",
    "learn more",
    "download",
    "upload",
    "confirm",
    "done",
    "ok",
    "yes",
    "no",
    "retry",
    "refresh",
    "add",
    "remove",
    "delete",
    "edit",
    "update",
}

INPUT_HINT_WORDS = {
    "name",
    "email",
    "phone",
    "password",
    "username",
    "address",
    "city",
    "state",
    "zip",
    "postal",
    "search",
    "message",
    "comment",
    "amount",
    "price",
    "date",
    "time",
    "domain",
    "url",
    "website",
}

ICON_HINT_WORDS = {
    "menu",
    "close",
    "x",
    "back",
    "home",
    "settings",
    "profile",
    "user",
    "cart",
    "search",
    "bell",
    "notification",
    "calendar",
    "phone",
    "mail",
    "trash",
    "edit",
    "plus",
    "minus",
    "arrow",
}

LABEL_HINT_WORDS = {
    "label",
    "title",
    "heading",
    "description",
    "note",
    "status",
    "error",
    "warning",
    "success",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BoundingBox:
    """
    Pixel-space rectangle used for UI element detection.

    Coordinates:
        x1, y1: top-left
        x2, y2: bottom-right
    """

    x1: int
    y1: int
    x2: int
    y2: int

    def normalize(self) -> "BoundingBox":
        x1 = int(min(self.x1, self.x2))
        y1 = int(min(self.y1, self.y2))
        x2 = int(max(self.x1, self.x2))
        y2 = int(max(self.y1, self.y2))
        return BoundingBox(x1=x1, y1=y1, x2=x2, y2=y2)

    @property
    def width(self) -> int:
        box = self.normalize()
        return max(0, box.x2 - box.x1)

    @property
    def height(self) -> int:
        box = self.normalize()
        return max(0, box.y2 - box.y1)

    @property
    def area(self) -> int:
        return self.width * self.height

    @property
    def center(self) -> Dict[str, int]:
        box = self.normalize()
        return {
            "x": int((box.x1 + box.x2) / 2),
            "y": int((box.y1 + box.y2) / 2),
        }

    def clamp(self, image_width: int, image_height: int) -> "BoundingBox":
        box = self.normalize()
        return BoundingBox(
            x1=max(0, min(box.x1, image_width)),
            y1=max(0, min(box.y1, image_height)),
            x2=max(0, min(box.x2, image_width)),
            y2=max(0, min(box.y2, image_height)),
        )

    def expand(self, px: int, image_width: Optional[int] = None, image_height: Optional[int] = None) -> "BoundingBox":
        box = BoundingBox(
            x1=self.x1 - px,
            y1=self.y1 - px,
            x2=self.x2 + px,
            y2=self.y2 + px,
        ).normalize()

        if image_width is not None and image_height is not None:
            return box.clamp(image_width, image_height)

        return box

    def iou(self, other: "BoundingBox") -> float:
        a = self.normalize()
        b = other.normalize()

        inter_x1 = max(a.x1, b.x1)
        inter_y1 = max(a.y1, b.y1)
        inter_x2 = min(a.x2, b.x2)
        inter_y2 = min(a.y2, b.y2)

        inter_w = max(0, inter_x2 - inter_x1)
        inter_h = max(0, inter_y2 - inter_y1)
        inter_area = inter_w * inter_h

        union_area = a.area + b.area - inter_area
        if union_area <= 0:
            return 0.0

        return inter_area / union_area

    def contains_center_of(self, other: "BoundingBox") -> bool:
        center = other.center
        box = self.normalize()
        return box.x1 <= center["x"] <= box.x2 and box.y1 <= center["y"] <= box.y2

    def to_dict(self) -> Dict[str, Any]:
        box = self.normalize()
        return {
            "x1": box.x1,
            "y1": box.y1,
            "x2": box.x2,
            "y2": box.y2,
            "width": box.width,
            "height": box.height,
            "area": box.area,
            "center": box.center,
        }


@dataclass
class OCRItem:
    """
    OCR item consumed by ElementDetector.

    Supports OCR output from future ocr_engine.py, screenshot_reader.py,
    external OCR APIs, or dashboard-provided OCR.
    """

    text: str
    bounds: BoundingBox
    confidence: float = 0.75
    source: str = "ocr"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VisualCandidate:
    """
    Candidate rectangle detected by image processing or layout hints.
    """

    bounds: BoundingBox
    source: str
    confidence: float
    visual_features: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectedElement:
    """
    Final UI element detection result.
    """

    element_id: str
    element_type: str
    bounds: BoundingBox
    confidence: float
    label: Optional[str] = None
    text: Optional[str] = None
    role: Optional[str] = None
    source: str = "element_detector"
    evidence: Dict[str, Any] = field(default_factory=dict)
    children: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "element_id": self.element_id,
            "element_type": self.element_type,
            "bounds": self.bounds.to_dict(),
            "confidence": round(float(self.confidence), 4),
            "label": self.label,
            "text": self.text,
            "role": self.role,
            "source": self.source,
            "evidence": self.evidence,
            "children": self.children,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ElementDetectorConfig:
    """
    Configuration for read-only UI element detection.

    Safe defaults are intentionally conservative:
        - No external OCR/network calls.
        - No destructive action.
        - Maximum image size and candidate counts are capped.
    """

    max_image_bytes: int = 15 * 1024 * 1024
    max_image_pixels: int = 16_000_000
    min_candidate_area: int = 80
    max_candidate_area_ratio: float = 0.92
    min_confidence: float = 0.20
    merge_iou_threshold: float = 0.45
    nested_iou_threshold: float = 0.85
    text_merge_distance_px: int = 18
    max_elements: int = 300
    max_ocr_items: int = 1000
    button_aspect_min: float = 1.2
    button_aspect_max: float = 12.0
    input_aspect_min: float = 2.0
    input_aspect_max: float = 25.0
    icon_max_size_px: int = 64
    card_min_width_px: int = 120
    card_min_height_px: int = 80
    card_area_min_ratio: float = 0.015
    enable_cv2_detection: bool = True
    enable_pillow_detection: bool = True
    enable_ocr_classification: bool = True
    enable_layout_hint_detection: bool = True


# ---------------------------------------------------------------------------
# Main detector
# ---------------------------------------------------------------------------

class ElementDetector(BaseAgent):
    """
    Visual Agent helper for UI element detection.

    Public methods return structured dictionaries:
        success, message, data, error, metadata

    Typical usage:
        detector = ElementDetector()
        result = detector.detect_elements(
            user_id="u_123",
            workspace_id="w_123",
            image_path="screenshot.png",
            ocr_items=[
                {"text": "Submit", "bounds": {"x1": 100, "y1": 200, "x2": 180, "y2": 235}}
            ],
        )
    """

    agent_type = "visual_agent.helper"
    detector_name = "element_detector"
    file_path = "agents/visual_agent/element_detector.py"
    version = "1.0.0"

    def __init__(
        self,
        config: Optional[ElementDetectorConfig] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="ElementDetector", **kwargs)
        self.config = config or ElementDetectorConfig()
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self.logger = logger or LOGGER

    # -----------------------------------------------------------------------
    # Registry / loader metadata
    # -----------------------------------------------------------------------

    def get_agent_metadata(self) -> Dict[str, Any]:
        """
        Metadata used by Agent Registry, Agent Loader, Agent Router, and Dashboard.
        """

        return {
            "name": self.__class__.__name__,
            "detector_name": self.detector_name,
            "agent_type": self.agent_type,
            "module": "visual_agent",
            "file_path": self.file_path,
            "version": self.version,
            "capabilities": [
                "button_detection",
                "input_detection",
                "card_detection",
                "icon_detection",
                "label_detection",
                "bounds_detection",
                "confidence_scoring",
                "ocr_box_classification",
                "layout_hint_merging",
                "visual_candidate_detection",
                "verification_payload_generation",
                "memory_payload_generation",
            ],
            "optional_dependencies": {
                "Pillow": Image is not None,
                "numpy": np is not None,
                "opencv_python": cv2 is not None,
            },
            "requires_user_context": True,
            "requires_workspace_context": True,
            "safe_to_import": True,
            "read_only": True,
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Lightweight readiness check.
        """

        return self._safe_result(
            success=True,
            message="ElementDetector is ready.",
            data={
                "metadata": self.get_agent_metadata(),
                "config": asdict(self.config),
            },
        )

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str] = None,
        extra: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Enforces SaaS user/workspace isolation.
        """

        errors: List[str] = []

        if not user_id or not str(user_id).strip():
            errors.append("Missing required user_id.")
        if not workspace_id or not str(workspace_id).strip():
            errors.append("Missing required workspace_id.")

        context = {
            "user_id": str(user_id).strip() if user_id else None,
            "workspace_id": str(workspace_id).strip() if workspace_id else None,
            "task_id": str(task_id).strip() if task_id else None,
            "extra": dict(extra or {}),
        }

        if errors:
            return self._error_result(
                message="Invalid task context.",
                error={
                    "code": "INVALID_TASK_CONTEXT",
                    "details": errors,
                },
                metadata={"context": context},
            )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={"context": context},
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Element detection is read-only, so it normally does not require Security Agent.

        This hook exists for architecture compatibility. Future versions may gate
        sensitive screenshots, external URLs, or restricted workspaces.
        """

        action = (action or "").lower().strip()
        payload_dict = dict(payload or {})

        if action in {"external_image_fetch", "restricted_screenshot_analysis"}:
            return True

        if payload_dict.get("sensitive") is True:
            return True

        return False

    def _request_security_approval(
        self,
        user_id: str,
        workspace_id: str,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Requests Security Agent approval if connected.

        Fallback behavior approves only safe local read-only analysis.
        """

        request_payload = {
            "agent": self.__class__.__name__,
            "module": "visual_agent",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "payload": self._sanitize_for_memory(dict(payload or {})),
            "timestamp": self._utc_timestamp(),
        }

        if self.security_agent is not None:
            for method_name in (
                "approve_action",
                "request_approval",
                "validate_action",
                "check_permission",
            ):
                method = getattr(self.security_agent, method_name, None)
                if callable(method):
                    try:
                        approval = method(request_payload)
                        if isinstance(approval, dict):
                            approved = bool(
                                approval.get("approved")
                                or approval.get("success")
                                or approval.get("allowed")
                            )
                            return self._safe_result(
                                success=approved,
                                message=approval.get(
                                    "message",
                                    "Security approval returned.",
                                ),
                                data={"approval": approval},
                                error=None if approved else approval.get("error"),
                            )
                    except Exception as exc:
                        return self._error_result(
                            message="Security approval request failed.",
                            error={
                                "code": "SECURITY_AGENT_ERROR",
                                "exception": str(exc),
                            },
                            metadata={"request": request_payload},
                        )

        if action in {"external_image_fetch"}:
            return self._error_result(
                message="External image fetch is denied by fallback security.",
                error={"code": "EXTERNAL_FETCH_DENIED"},
                metadata={"request": request_payload},
            )

        return self._safe_result(
            success=True,
            message="Fallback security approved read-only visual analysis.",
            data={"request": request_payload},
        )

    def _prepare_verification_payload(
        self,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str],
        check_type: str,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Creates a Verification Agent-compatible payload.
        """

        return {
            "agent": "VerificationAgent",
            "source_agent": "VisualAgent",
            "checker": self.__class__.__name__,
            "check_type": check_type,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "data": result.get("data", {}),
            "error": result.get("error"),
            "metadata": {
                **dict(result.get("metadata") or {}),
                "generated_by": self.__class__.__name__,
                "generated_at": self._utc_timestamp(),
            },
        }

    def _prepare_memory_payload(
        self,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str],
        summary: str,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Creates a Memory Agent-compatible payload.

        Keeps useful visual layout context without storing raw image bytes.
        """

        sanitized = self._sanitize_for_memory(dict(result))
        return {
            "type": "visual_element_detection",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "summary": summary,
            "source_agent": self.__class__.__name__,
            "timestamp": self._utc_timestamp(),
            "data": sanitized,
        }

    def _emit_agent_event(
        self,
        event_type: str,
        payload: Mapping[str, Any],
    ) -> None:
        """
        Emits Visual Agent events to event bus or BaseAgent fallback.
        """

        safe_payload = dict(payload)

        try:
            if self.event_bus is not None:
                if hasattr(self.event_bus, "emit") and callable(self.event_bus.emit):
                    self.event_bus.emit(event_type, safe_payload)
                    return
                if hasattr(self.event_bus, "publish") and callable(self.event_bus.publish):
                    self.event_bus.publish(event_type, safe_payload)
                    return

            emit_event = getattr(super(), "emit_event", None)
            if callable(emit_event):
                emit_event(event_type, safe_payload)
        except Exception as exc:
            self.logger.debug("Unable to emit event %s: %s", event_type, exc)

    def _log_audit_event(
        self,
        user_id: str,
        workspace_id: str,
        action: str,
        result: Mapping[str, Any],
        task_id: Optional[str] = None,
    ) -> None:
        """
        Writes audit metadata without storing raw images or secrets.
        """

        audit_payload = {
            "agent": self.__class__.__name__,
            "module": "visual_agent",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "timestamp": self._utc_timestamp(),
            "metadata": self._sanitize_for_memory(dict(result.get("metadata") or {})),
        }

        try:
            if self.audit_logger is not None:
                if hasattr(self.audit_logger, "log") and callable(self.audit_logger.log):
                    self.audit_logger.log(audit_payload)
                    return
                if hasattr(self.audit_logger, "write") and callable(self.audit_logger.write):
                    self.audit_logger.write(audit_payload)
                    return

            log_audit = getattr(super(), "log_audit", None)
            if callable(log_audit):
                log_audit(audit_payload)
                return

            self.logger.info("Audit event: %s", json.dumps(audit_payload, default=str))
        except Exception as exc:
            self.logger.debug("Unable to log audit event: %s", exc)

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured result wrapper.
        """

        return {
            "success": bool(success),
            "message": str(message),
            "data": dict(data or {}),
            "error": error,
            "metadata": {
                "detector": self.__class__.__name__,
                "timestamp": self._utc_timestamp(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured error wrapper.
        """

        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error or {"code": "UNKNOWN_ERROR"},
            metadata=metadata or {},
        )

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def detect_elements(
        self,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        image_path: Optional[Union[str, Path]] = None,
        image_bytes: Optional[bytes] = None,
        image_base64: Optional[str] = None,
        ocr_items: Optional[Sequence[Union[OCRItem, Mapping[str, Any]]]] = None,
        layout_hints: Optional[Sequence[Mapping[str, Any]]] = None,
        image_size: Optional[Tuple[int, int]] = None,
        target_types: Optional[Sequence[str]] = None,
        min_confidence: Optional[float] = None,
        emit_events: bool = True,
        save_memory: bool = False,
    ) -> Dict[str, Any]:
        """
        Main element detection entrypoint.

        Inputs can be:
            - image_path
            - image_bytes
            - image_base64
            - ocr_items
            - layout_hints
            - image_size when no image is provided

        Returns:
            Structured dict with detected elements, counts, summary, and
            verification payload.
        """

        context_result = self._validate_task_context(user_id, workspace_id, task_id)
        if not context_result["success"]:
            return context_result

        started_at = time.time()

        try:
            if self._requires_security_check(
                "visual_element_detection",
                {
                    "image_path": str(image_path) if image_path else None,
                    "has_image_bytes": image_bytes is not None,
                    "has_image_base64": image_base64 is not None,
                    "sensitive": False,
                },
            ):
                approval = self._request_security_approval(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    action="visual_element_detection",
                    payload={
                        "image_path": str(image_path) if image_path else None,
                        "has_image_bytes": image_bytes is not None,
                        "has_image_base64": image_base64 is not None,
                    },
                )
                if not approval["success"]:
                    return approval

            normalized_target_types = self._normalize_target_types(target_types)
            threshold = float(min_confidence if min_confidence is not None else self.config.min_confidence)

            image = self._load_image(
                image_path=image_path,
                image_bytes=image_bytes,
                image_base64=image_base64,
            )

            resolved_image_size = self._resolve_image_size(image=image, image_size=image_size)
            normalized_ocr = self._coerce_ocr_items(ocr_items or [], resolved_image_size)
            normalized_hints = self._coerce_layout_hints(layout_hints or [], resolved_image_size)

            visual_candidates: List[VisualCandidate] = []

            if image is not None:
                visual_candidates.extend(self._detect_visual_candidates(image))

            if self.config.enable_layout_hint_detection:
                visual_candidates.extend(normalized_hints)

            elements = self._build_elements(
                image_size=resolved_image_size,
                visual_candidates=visual_candidates,
                ocr_items=normalized_ocr,
            )

            elements = self._merge_duplicate_elements(elements)
            elements = self._attach_child_labels(elements)
            elements = self._filter_elements(
                elements=elements,
                target_types=normalized_target_types,
                min_confidence=threshold,
            )
            elements = self._sort_elements(elements)
            elements = elements[: self.config.max_elements]

            counts = self._count_by_type(elements)
            result = self._safe_result(
                success=True,
                message=f"Detected {len(elements)} UI element(s).",
                data={
                    "elements": [element.to_dict() for element in elements],
                    "counts": counts,
                    "image_size": {
                        "width": resolved_image_size[0],
                        "height": resolved_image_size[1],
                    } if resolved_image_size else None,
                    "ocr_items_used": len(normalized_ocr),
                    "visual_candidates_used": len(visual_candidates),
                    "target_types": sorted(normalized_target_types) if normalized_target_types else None,
                    "summary": self._build_summary(elements),
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                    "duration_seconds": round(time.time() - started_at, 4),
                    "check_type": "visual_element_detection",
                    "optional_dependencies": {
                        "Pillow": Image is not None,
                        "numpy": np is not None,
                        "opencv_python": cv2 is not None,
                    },
                },
            )

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                check_type="visual_element_detection",
                result=result,
            )
            result["data"]["verification_payload"] = verification_payload

            if emit_events:
                self._emit_agent_event(
                    "visual.element_detection.completed",
                    verification_payload,
                )

            self._log_audit_event(
                user_id=user_id,
                workspace_id=workspace_id,
                action="detect_elements",
                result=result,
                task_id=task_id,
            )

            if save_memory:
                memory_payload = self._prepare_memory_payload(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=task_id,
                    summary=result["message"],
                    result=result,
                )
                result["data"]["memory_payload"] = memory_payload
                self._send_memory_payload(memory_payload)

            return result

        except Exception as exc:
            result = self._exception_result(
                message="Element detection failed unexpectedly.",
                exc=exc,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
            )
            self._log_audit_event(
                user_id=user_id,
                workspace_id=workspace_id,
                action="detect_elements_exception",
                result=result,
                task_id=task_id,
            )
            return result

    def detect_buttons(
        self,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Convenience method for detecting buttons only.
        """

        kwargs["target_types"] = [ELEMENT_BUTTON]
        return self.detect_elements(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            **kwargs,
        )

    def detect_inputs(
        self,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Convenience method for detecting inputs only.
        """

        kwargs["target_types"] = [ELEMENT_INPUT]
        return self.detect_elements(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            **kwargs,
        )

    def detect_cards(
        self,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Convenience method for detecting cards only.
        """

        kwargs["target_types"] = [ELEMENT_CARD]
        return self.detect_elements(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            **kwargs,
        )

    def classify_ocr_elements(
        self,
        user_id: str,
        workspace_id: str,
        ocr_items: Sequence[Union[OCRItem, Mapping[str, Any]]],
        task_id: Optional[str] = None,
        image_size: Optional[Tuple[int, int]] = None,
    ) -> Dict[str, Any]:
        """
        Classifies UI elements from OCR boxes only.

        Useful when OCR is already produced by ocr_engine.py or screenshot_reader.py.
        """

        return self.detect_elements(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            ocr_items=ocr_items,
            image_size=image_size,
        )

    # -----------------------------------------------------------------------
    # Image loading
    # -----------------------------------------------------------------------

    def _load_image(
        self,
        image_path: Optional[Union[str, Path]] = None,
        image_bytes: Optional[bytes] = None,
        image_base64: Optional[str] = None,
    ) -> Optional[Any]:
        """
        Loads image using Pillow if available.

        Returns None when no image is provided. Raises structured-safe exceptions
        for invalid image payloads.
        """

        if image_path is None and image_bytes is None and image_base64 is None:
            return None

        if Image is None:
            raise RuntimeError(
                "Pillow is not installed. Install pillow or provide OCR/layout hints only."
            )

        raw_bytes: Optional[bytes] = None

        if image_path is not None:
            path = Path(image_path).expanduser().resolve()
            if not path.exists():
                raise FileNotFoundError(f"Image path does not exist: {path}")
            if not path.is_file():
                raise ValueError(f"Image path is not a file: {path}")
            if path.stat().st_size > self.config.max_image_bytes:
                raise ValueError(
                    f"Image exceeds max size of {self.config.max_image_bytes} bytes."
                )
            raw_bytes = path.read_bytes()

        elif image_bytes is not None:
            if len(image_bytes) > self.config.max_image_bytes:
                raise ValueError(
                    f"Image bytes exceed max size of {self.config.max_image_bytes} bytes."
                )
            raw_bytes = image_bytes

        elif image_base64 is not None:
            clean_b64 = self._strip_data_uri_prefix(image_base64)
            raw_bytes = base64.b64decode(clean_b64)
            if len(raw_bytes) > self.config.max_image_bytes:
                raise ValueError(
                    f"Decoded image exceeds max size of {self.config.max_image_bytes} bytes."
                )

        if raw_bytes is None:
            return None

        image = Image.open(io.BytesIO(raw_bytes)).convert("RGB")
        width, height = image.size

        if width * height > self.config.max_image_pixels:
            raise ValueError(
                f"Image exceeds max pixel count of {self.config.max_image_pixels}."
            )

        return image

    def _resolve_image_size(
        self,
        image: Optional[Any],
        image_size: Optional[Tuple[int, int]],
    ) -> Optional[Tuple[int, int]]:
        if image is not None:
            width, height = image.size
            return int(width), int(height)

        if image_size is None:
            return None

        width, height = image_size
        if width <= 0 or height <= 0:
            raise ValueError("image_size must contain positive width and height.")

        return int(width), int(height)

    # -----------------------------------------------------------------------
    # Visual candidate detection
    # -----------------------------------------------------------------------

    def _detect_visual_candidates(self, image: Any) -> List[VisualCandidate]:
        """
        Detects UI-like rectangles from screenshot.

        Uses OpenCV if available; otherwise uses a Pillow-based fallback.
        """

        candidates: List[VisualCandidate] = []

        if self.config.enable_cv2_detection and cv2 is not None and np is not None:
            candidates.extend(self._detect_candidates_cv2(image))

        if self.config.enable_pillow_detection:
            candidates.extend(self._detect_candidates_pillow(image))

        return self._dedupe_candidates(candidates)

    def _detect_candidates_cv2(self, image: Any) -> List[VisualCandidate]:
        """
        OpenCV rectangle/contour based candidate detection.

        This is not ML-based object detection. It detects UI layout components
        from edges, contours, and geometry.
        """

        candidates: List[VisualCandidate] = []

        try:
            arr = np.array(image)
            gray = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)

            blurred = cv2.GaussianBlur(gray, (3, 3), 0)
            edges = cv2.Canny(blurred, 40, 120)

            kernel = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
            closed = cv2.morphologyEx(edges, cv2.MORPH_CLOSE, kernel, iterations=2)

            contours, _ = cv2.findContours(
                closed,
                cv2.RETR_EXTERNAL,
                cv2.CHAIN_APPROX_SIMPLE,
            )

            width, height = image.size
            image_area = width * height

            for contour in contours:
                x, y, w, h = cv2.boundingRect(contour)
                box = BoundingBox(x, y, x + w, y + h).clamp(width, height)
                area = box.area

                if not self._candidate_area_ok(area, image_area):
                    continue

                aspect = self._aspect_ratio(box)
                extent = float(area) / float(max(cv2.contourArea(contour), 1.0))
                edge_density = self._estimate_edge_density(edges, box)

                confidence = self._score_visual_candidate(
                    box=box,
                    image_size=(width, height),
                    features={
                        "aspect_ratio": aspect,
                        "edge_density": edge_density,
                        "extent": extent,
                        "detector": "cv2_contour",
                    },
                )

                if confidence < self.config.min_confidence:
                    continue

                candidates.append(
                    VisualCandidate(
                        bounds=box,
                        source="cv2_contour",
                        confidence=confidence,
                        visual_features={
                            "aspect_ratio": aspect,
                            "edge_density": edge_density,
                            "extent": extent,
                        },
                    )
                )

        except Exception as exc:
            self.logger.debug("CV2 candidate detection failed: %s", exc)

        return candidates

    def _detect_candidates_pillow(self, image: Any) -> List[VisualCandidate]:
        """
        Pillow fallback candidate detection.

        Uses thresholded edge differences and connected-component style grouping.
        """

        candidates: List[VisualCandidate] = []

        if ImageFilter is None or ImageOps is None:
            return candidates

        try:
            width, height = image.size
            image_area = width * height

            gray = ImageOps.grayscale(image)
            edges = gray.filter(ImageFilter.FIND_EDGES)
            thresholded = edges.point(lambda p: 255 if p > 35 else 0)

            if np is None:
                return candidates

            arr = np.array(thresholded)
            visited = np.zeros(arr.shape, dtype=bool)

            step = 2
            max_components = 600
            components_found = 0

            for y in range(0, height, step):
                if components_found >= max_components:
                    break

                for x in range(0, width, step):
                    if visited[y, x] or arr[y, x] == 0:
                        continue

                    component = self._flood_fill_binary(arr, visited, x, y, step=step)
                    if component is None:
                        continue

                    x1, y1, x2, y2, count = component
                    box = BoundingBox(x1, y1, x2, y2).clamp(width, height)
                    area = box.area

                    if not self._candidate_area_ok(area, image_area):
                        continue

                    if box.width < 8 or box.height < 8:
                        continue

                    confidence = self._score_visual_candidate(
                        box=box,
                        image_size=(width, height),
                        features={
                            "edge_pixels": int(count),
                            "detector": "pillow_edges",
                        },
                    )

                    if confidence < self.config.min_confidence:
                        continue

                    candidates.append(
                        VisualCandidate(
                            bounds=box,
                            source="pillow_edges",
                            confidence=confidence,
                            visual_features={
                                "edge_pixels": int(count),
                                "aspect_ratio": self._aspect_ratio(box),
                            },
                        )
                    )
                    components_found += 1

        except Exception as exc:
            self.logger.debug("Pillow candidate detection failed: %s", exc)

        return candidates

    def _flood_fill_binary(
        self,
        arr: Any,
        visited: Any,
        start_x: int,
        start_y: int,
        step: int = 2,
    ) -> Optional[Tuple[int, int, int, int, int]]:
        """
        Small flood-fill helper for Pillow fallback.
        """

        if np is None:
            return None

        height, width = arr.shape[:2]
        stack = [(start_x, start_y)]

        x1 = start_x
        y1 = start_y
        x2 = start_x
        y2 = start_y
        count = 0
        max_pixels = 8000

        while stack and count < max_pixels:
            x, y = stack.pop()

            if x < 0 or y < 0 or x >= width or y >= height:
                continue

            if visited[y, x] or arr[y, x] == 0:
                continue

            visited[y, x] = True
            count += 1

            x1 = min(x1, x)
            y1 = min(y1, y)
            x2 = max(x2, x)
            y2 = max(y2, y)

            stack.append((x + step, y))
            stack.append((x - step, y))
            stack.append((x, y + step))
            stack.append((x, y - step))

        if count <= 0:
            return None

        return x1, y1, x2 + 1, y2 + 1, count

    # -----------------------------------------------------------------------
    # OCR and layout coercion
    # -----------------------------------------------------------------------

    def _coerce_ocr_items(
        self,
        raw_items: Sequence[Union[OCRItem, Mapping[str, Any]]],
        image_size: Optional[Tuple[int, int]],
    ) -> List[OCRItem]:
        items: List[OCRItem] = []

        for raw in list(raw_items)[: self.config.max_ocr_items]:
            try:
                if isinstance(raw, OCRItem):
                    item = raw
                else:
                    item = self._ocr_item_from_mapping(raw)

                item.bounds = self._clamp_box_if_possible(item.bounds, image_size)

                if item.text is None:
                    continue

                text = str(item.text).strip()
                if not text:
                    continue

                item.text = text
                item.confidence = self._clamp_confidence(item.confidence)
                items.append(item)

            except Exception as exc:
                self.logger.debug("Skipping invalid OCR item: %s", exc)

        return items

    def _ocr_item_from_mapping(self, raw: Mapping[str, Any]) -> OCRItem:
        data = dict(raw)
        bounds_raw = data.get("bounds") or data.get("box") or data.get("bbox")

        if bounds_raw is None:
            x = data.get("x")
            y = data.get("y")
            w = data.get("width") or data.get("w")
            h = data.get("height") or data.get("h")
            if x is None or y is None or w is None or h is None:
                raise ValueError("OCR item missing bounds.")
            bounds = BoundingBox(int(x), int(y), int(x) + int(w), int(y) + int(h))
        else:
            bounds = self._coerce_bounds(bounds_raw)

        return OCRItem(
            text=str(data.get("text") or data.get("label") or ""),
            bounds=bounds,
            confidence=float(data.get("confidence", data.get("score", 0.75))),
            source=str(data.get("source") or "ocr"),
            metadata=dict(data.get("metadata") or {}),
        )

    def _coerce_layout_hints(
        self,
        raw_hints: Sequence[Mapping[str, Any]],
        image_size: Optional[Tuple[int, int]],
    ) -> List[VisualCandidate]:
        hints: List[VisualCandidate] = []

        for raw in raw_hints:
            try:
                data = dict(raw)
                bounds_raw = data.get("bounds") or data.get("box") or data.get("bbox")
                if bounds_raw is None:
                    continue

                bounds = self._coerce_bounds(bounds_raw)
                bounds = self._clamp_box_if_possible(bounds, image_size)

                confidence = self._clamp_confidence(float(data.get("confidence", 0.7)))

                hints.append(
                    VisualCandidate(
                        bounds=bounds,
                        source=str(data.get("source") or "layout_hint"),
                        confidence=confidence,
                        visual_features=dict(data.get("visual_features") or {}),
                        metadata={
                            key: value
                            for key, value in data.items()
                            if key not in {"bounds", "box", "bbox", "confidence", "visual_features"}
                        },
                    )
                )
            except Exception as exc:
                self.logger.debug("Skipping invalid layout hint: %s", exc)

        return hints

    def _coerce_bounds(self, raw: Any) -> BoundingBox:
        if isinstance(raw, BoundingBox):
            return raw.normalize()

        if isinstance(raw, Mapping):
            data = dict(raw)

            if all(key in data for key in ("x1", "y1", "x2", "y2")):
                return BoundingBox(
                    int(data["x1"]),
                    int(data["y1"]),
                    int(data["x2"]),
                    int(data["y2"]),
                ).normalize()

            if all(key in data for key in ("left", "top", "right", "bottom")):
                return BoundingBox(
                    int(data["left"]),
                    int(data["top"]),
                    int(data["right"]),
                    int(data["bottom"]),
                ).normalize()

            if all(key in data for key in ("x", "y", "width", "height")):
                x = int(data["x"])
                y = int(data["y"])
                return BoundingBox(
                    x,
                    y,
                    x + int(data["width"]),
                    y + int(data["height"]),
                ).normalize()

            if all(key in data for key in ("x", "y", "w", "h")):
                x = int(data["x"])
                y = int(data["y"])
                return BoundingBox(
                    x,
                    y,
                    x + int(data["w"]),
                    y + int(data["h"]),
                ).normalize()

        if isinstance(raw, (list, tuple)) and len(raw) == 4:
            x1, y1, x2, y2 = raw
            return BoundingBox(int(x1), int(y1), int(x2), int(y2)).normalize()

        raise ValueError(f"Unsupported bounds format: {raw}")

    # -----------------------------------------------------------------------
    # Element construction and classification
    # -----------------------------------------------------------------------

    def _build_elements(
        self,
        image_size: Optional[Tuple[int, int]],
        visual_candidates: Sequence[VisualCandidate],
        ocr_items: Sequence[OCRItem],
    ) -> List[DetectedElement]:
        elements: List[DetectedElement] = []

        for candidate in visual_candidates:
            linked_texts = self._find_ocr_inside_or_near(candidate.bounds, ocr_items)
            text = self._combine_ocr_text(linked_texts)
            element_type, type_confidence, role = self._classify_candidate(
                bounds=candidate.bounds,
                text=text,
                candidate=candidate,
                image_size=image_size,
            )

            confidence = self._combine_confidence(
                candidate.confidence,
                type_confidence,
                self._ocr_confidence(linked_texts),
            )

            elements.append(
                DetectedElement(
                    element_id=self._new_element_id(element_type),
                    element_type=element_type,
                    bounds=candidate.bounds,
                    confidence=confidence,
                    label=self._label_from_text(text, element_type),
                    text=text or None,
                    role=role,
                    source=candidate.source,
                    evidence={
                        "visual_features": candidate.visual_features,
                        "ocr_text_count": len(linked_texts),
                        "classification": "visual_candidate_with_ocr",
                    },
                    children=[self._ocr_to_child(item) for item in linked_texts],
                    metadata=candidate.metadata,
                )
            )

        if self.config.enable_ocr_classification:
            for item in ocr_items:
                if self._ocr_already_covered(item, elements):
                    continue

                element_type, confidence, role = self._classify_ocr_item(item, image_size)
                elements.append(
                    DetectedElement(
                        element_id=self._new_element_id(element_type),
                        element_type=element_type,
                        bounds=item.bounds,
                        confidence=confidence,
                        label=self._label_from_text(item.text, element_type),
                        text=item.text,
                        role=role,
                        source=item.source,
                        evidence={
                            "classification": "ocr_only",
                            "ocr_confidence": item.confidence,
                        },
                        children=[],
                        metadata=item.metadata,
                    )
                )

        return elements

    def _classify_candidate(
        self,
        bounds: BoundingBox,
        text: str,
        candidate: VisualCandidate,
        image_size: Optional[Tuple[int, int]],
    ) -> Tuple[str, float, str]:
        text_lower = self._clean_text(text).lower()
        aspect = self._aspect_ratio(bounds)
        width = bounds.width
        height = bounds.height
        area = bounds.area

        hinted_type = str(candidate.metadata.get("element_type") or candidate.metadata.get("type") or "").lower()
        if hinted_type in SUPPORTED_ELEMENT_TYPES:
            return hinted_type, min(0.95, candidate.confidence + 0.15), self._role_for_type(hinted_type)

        if self._looks_like_checkbox(bounds):
            return ELEMENT_CHECKBOX, 0.72, "checkbox"

        if self._looks_like_toggle(bounds):
            return ELEMENT_TOGGLE, 0.72, "switch"

        if self._looks_like_icon(bounds, text_lower):
            return ELEMENT_ICON, 0.65, "img"

        if self._text_suggests_button(text_lower) and self._shape_suggests_button(bounds):
            return ELEMENT_BUTTON, 0.88, "button"

        if self._shape_suggests_input(bounds) and self._text_suggests_input(text_lower):
            return ELEMENT_INPUT, 0.83, "textbox"

        if self._shape_suggests_input(bounds) and not text_lower:
            return ELEMENT_INPUT, 0.68, "textbox"

        if self._text_suggests_link(text_lower):
            return ELEMENT_LINK, 0.72, "link"

        if image_size is not None and self._shape_suggests_card(bounds, image_size):
            return ELEMENT_CARD, 0.70, "group"

        if text_lower:
            if self._text_suggests_button(text_lower):
                return ELEMENT_BUTTON, 0.68, "button"
            return ELEMENT_LABEL, 0.62, "text"

        if area > 0 and aspect > 0:
            return ELEMENT_CONTAINER, 0.45, "group"

        return ELEMENT_UNKNOWN, 0.25, "unknown"

    def _classify_ocr_item(
        self,
        item: OCRItem,
        image_size: Optional[Tuple[int, int]],
    ) -> Tuple[str, float, str]:
        text = self._clean_text(item.text).lower()
        bounds = item.bounds

        if self._text_suggests_button(text):
            confidence = self._weighted_average(
                [(item.confidence, 0.55), (0.78 if self._shape_suggests_button(bounds) else 0.55, 0.45)]
            )
            return ELEMENT_BUTTON, confidence, "button"

        if self._text_suggests_input(text):
            confidence = self._weighted_average(
                [(item.confidence, 0.45), (0.70, 0.55)]
            )
            return ELEMENT_LABEL, confidence, "label"

        if self._text_suggests_link(text):
            return ELEMENT_LINK, self._weighted_average([(item.confidence, 0.6), (0.68, 0.4)]), "link"

        if self._looks_like_icon(bounds, text):
            return ELEMENT_ICON, self._weighted_average([(item.confidence, 0.5), (0.58, 0.5)]), "img"

        return ELEMENT_LABEL, self._weighted_average([(item.confidence, 0.7), (0.60, 0.3)]), "text"

    def _attach_child_labels(self, elements: List[DetectedElement]) -> List[DetectedElement]:
        """
        Associates nearby labels with inputs/cards/containers.
        """

        labels = [element for element in elements if element.element_type == ELEMENT_LABEL]
        attachable = {
            ELEMENT_INPUT,
            ELEMENT_BUTTON,
            ELEMENT_CARD,
            ELEMENT_CONTAINER,
            ELEMENT_CHECKBOX,
            ELEMENT_TOGGLE,
        }

        for element in elements:
            if element.element_type not in attachable:
                continue

            nearby = self._find_nearby_labels(element, labels)
            if not nearby:
                continue

            if not element.label:
                element.label = nearby[0].text or nearby[0].label

            existing_ids = {child.get("element_id") for child in element.children}
            for label_element in nearby:
                if label_element.element_id in existing_ids:
                    continue
                element.children.append(
                    {
                        "element_id": label_element.element_id,
                        "type": label_element.element_type,
                        "text": label_element.text,
                        "bounds": label_element.bounds.to_dict(),
                        "relationship": "nearby_label",
                    }
                )

            element.confidence = min(0.98, element.confidence + 0.05)

        return elements

    # -----------------------------------------------------------------------
    # Merge / filter / sorting
    # -----------------------------------------------------------------------

    def _merge_duplicate_elements(self, elements: List[DetectedElement]) -> List[DetectedElement]:
        """
        Merges overlapping duplicate detections.
        """

        if not elements:
            return []

        sorted_elements = sorted(
            elements,
            key=lambda item: (item.bounds.y1, item.bounds.x1, -item.confidence),
        )

        merged: List[DetectedElement] = []

        for element in sorted_elements:
            duplicate_index = self._find_duplicate_index(element, merged)

            if duplicate_index is None:
                merged.append(element)
                continue

            existing = merged[duplicate_index]
            merged[duplicate_index] = self._merge_two_elements(existing, element)

        return merged

    def _find_duplicate_index(
        self,
        element: DetectedElement,
        existing_elements: Sequence[DetectedElement],
    ) -> Optional[int]:
        for index, existing in enumerate(existing_elements):
            iou = element.bounds.iou(existing.bounds)

            if iou >= self.config.merge_iou_threshold:
                return index

            if existing.bounds.contains_center_of(element.bounds) and element.bounds.area < existing.bounds.area:
                if element.element_type == existing.element_type:
                    return index

            if element.bounds.contains_center_of(existing.bounds) and existing.bounds.area < element.bounds.area:
                if element.element_type == existing.element_type:
                    return index

        return None

    def _merge_two_elements(
        self,
        first: DetectedElement,
        second: DetectedElement,
    ) -> DetectedElement:
        primary = first if first.confidence >= second.confidence else second
        secondary = second if primary is first else first

        merged_text = self._merge_text_values(primary.text, secondary.text)
        merged_label = primary.label or secondary.label

        x1 = min(first.bounds.x1, second.bounds.x1)
        y1 = min(first.bounds.y1, second.bounds.y1)
        x2 = max(first.bounds.x2, second.bounds.x2)
        y2 = max(first.bounds.y2, second.bounds.y2)

        confidence = min(
            0.99,
            max(primary.confidence, secondary.confidence)
            + min(primary.confidence, secondary.confidence) * 0.08,
        )

        children = list(primary.children)
        known = {
            json.dumps(child, sort_keys=True, default=str)
            for child in children
        }

        for child in secondary.children:
            key = json.dumps(child, sort_keys=True, default=str)
            if key not in known:
                children.append(child)
                known.add(key)

        return DetectedElement(
            element_id=primary.element_id,
            element_type=primary.element_type,
            bounds=BoundingBox(x1, y1, x2, y2).normalize(),
            confidence=confidence,
            label=merged_label,
            text=merged_text,
            role=primary.role or secondary.role,
            source=f"{primary.source}+{secondary.source}",
            evidence={
                "merged": True,
                "primary_evidence": primary.evidence,
                "secondary_evidence": secondary.evidence,
            },
            children=children,
            metadata={**secondary.metadata, **primary.metadata},
        )

    def _filter_elements(
        self,
        elements: Sequence[DetectedElement],
        target_types: Optional[set],
        min_confidence: float,
    ) -> List[DetectedElement]:
        filtered: List[DetectedElement] = []

        for element in elements:
            if element.confidence < min_confidence:
                continue

            if target_types and element.element_type not in target_types:
                continue

            if element.bounds.area <= 0:
                continue

            filtered.append(element)

        return filtered

    def _sort_elements(self, elements: Sequence[DetectedElement]) -> List[DetectedElement]:
        """
        Sorts by screen reading order, then higher confidence.
        """

        return sorted(
            elements,
            key=lambda item: (
                item.bounds.y1,
                item.bounds.x1,
                -item.confidence,
                item.element_type,
            ),
        )

    # -----------------------------------------------------------------------
    # Feature scoring helpers
    # -----------------------------------------------------------------------

    def _score_visual_candidate(
        self,
        box: BoundingBox,
        image_size: Tuple[int, int],
        features: Mapping[str, Any],
    ) -> float:
        width, height = image_size
        image_area = max(1, width * height)
        area_ratio = box.area / image_area
        aspect = self._aspect_ratio(box)

        score = 0.30

        if 8 <= box.height <= 90 and 20 <= box.width <= width * 0.95:
            score += 0.18

        if self.config.button_aspect_min <= aspect <= self.config.button_aspect_max:
            score += 0.12

        if self._shape_suggests_input(box):
            score += 0.12

        if self._shape_suggests_card(box, image_size):
            score += 0.12

        if 0.0002 <= area_ratio <= 0.25:
            score += 0.10

        edge_density = float(features.get("edge_density", 0.0) or 0.0)
        if 0.02 <= edge_density <= 0.55:
            score += 0.10

        if self._looks_like_icon(box, ""):
            score += 0.08

        return self._clamp_confidence(score)

    def _combine_confidence(self, visual_confidence: float, type_confidence: float, ocr_confidence: float) -> float:
        values = [
            (visual_confidence, 0.40),
            (type_confidence, 0.40),
            (ocr_confidence, 0.20),
        ]
        return self._clamp_confidence(self._weighted_average(values))

    def _ocr_confidence(self, items: Sequence[OCRItem]) -> float:
        if not items:
            return 0.45
        return self._clamp_confidence(sum(item.confidence for item in items) / len(items))

    def _weighted_average(self, values: Sequence[Tuple[float, float]]) -> float:
        total_weight = sum(weight for _, weight in values)
        if total_weight <= 0:
            return 0.0
        return sum(value * weight for value, weight in values) / total_weight

    def _clamp_confidence(self, value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    # -----------------------------------------------------------------------
    # Shape and text classification helpers
    # -----------------------------------------------------------------------

    def _shape_suggests_button(self, box: BoundingBox) -> bool:
        aspect = self._aspect_ratio(box)
        return (
            self.config.button_aspect_min <= aspect <= self.config.button_aspect_max
            and 18 <= box.height <= 90
            and box.width >= 35
        )

    def _shape_suggests_input(self, box: BoundingBox) -> bool:
        aspect = self._aspect_ratio(box)
        return (
            self.config.input_aspect_min <= aspect <= self.config.input_aspect_max
            and 22 <= box.height <= 90
            and box.width >= 80
        )

    def _shape_suggests_card(self, box: BoundingBox, image_size: Tuple[int, int]) -> bool:
        width, height = image_size
        image_area = max(1, width * height)
        area_ratio = box.area / image_area

        return (
            box.width >= self.config.card_min_width_px
            and box.height >= self.config.card_min_height_px
            and area_ratio >= self.config.card_area_min_ratio
            and area_ratio <= self.config.max_candidate_area_ratio
        )

    def _looks_like_icon(self, box: BoundingBox, text_lower: str) -> bool:
        if box.width <= self.config.icon_max_size_px and box.height <= self.config.icon_max_size_px:
            aspect = self._aspect_ratio(box)
            if 0.55 <= aspect <= 1.8:
                return True

        cleaned = self._clean_text(text_lower).lower()
        if cleaned in ICON_HINT_WORDS:
            return True

        if len(cleaned) <= 2 and cleaned in {"x", "+", "-", "<", ">", "←", "→", "✓"}:
            return True

        return False

    def _looks_like_checkbox(self, box: BoundingBox) -> bool:
        aspect = self._aspect_ratio(box)
        return 10 <= box.width <= 34 and 10 <= box.height <= 34 and 0.75 <= aspect <= 1.35

    def _looks_like_toggle(self, box: BoundingBox) -> bool:
        aspect = self._aspect_ratio(box)
        return 28 <= box.width <= 90 and 14 <= box.height <= 48 and 1.6 <= aspect <= 3.4

    def _text_suggests_button(self, text_lower: str) -> bool:
        cleaned = self._clean_text(text_lower).lower()
        if not cleaned:
            return False

        if cleaned in BUTTON_WORDS:
            return True

        for word in BUTTON_WORDS:
            if word in cleaned and len(cleaned) <= max(28, len(word) + 12):
                return True

        return False

    def _text_suggests_input(self, text_lower: str) -> bool:
        cleaned = self._clean_text(text_lower).lower()
        if not cleaned:
            return False

        if cleaned.endswith(":"):
            cleaned = cleaned[:-1].strip()

        for word in INPUT_HINT_WORDS:
            if word == cleaned or word in cleaned:
                return True

        if "enter " in cleaned or "type " in cleaned:
            return True

        return False

    def _text_suggests_link(self, text_lower: str) -> bool:
        cleaned = self._clean_text(text_lower).lower()
        if not cleaned:
            return False

        if cleaned.startswith(("http://", "https://", "www.")):
            return True

        if "learn more" in cleaned or "read more" in cleaned:
            return True

        if re.search(r"\b[a-z0-9-]+\.(com|net|org|io|co|online|us|uk)\b", cleaned):
            return True

        return False

    def _label_from_text(self, text: str, element_type: str) -> Optional[str]:
        cleaned = self._clean_text(text)
        if not cleaned:
            return None

        if element_type == ELEMENT_INPUT:
            cleaned = cleaned.rstrip(":").strip()

        return cleaned[:120]

    def _role_for_type(self, element_type: str) -> str:
        mapping = {
            ELEMENT_BUTTON: "button",
            ELEMENT_INPUT: "textbox",
            ELEMENT_CARD: "group",
            ELEMENT_ICON: "img",
            ELEMENT_LABEL: "text",
            ELEMENT_LINK: "link",
            ELEMENT_CHECKBOX: "checkbox",
            ELEMENT_TOGGLE: "switch",
            ELEMENT_IMAGE: "img",
            ELEMENT_CONTAINER: "group",
            ELEMENT_UNKNOWN: "unknown",
        }
        return mapping.get(element_type, "unknown")

    # -----------------------------------------------------------------------
    # OCR relation helpers
    # -----------------------------------------------------------------------

    def _find_ocr_inside_or_near(
        self,
        bounds: BoundingBox,
        ocr_items: Sequence[OCRItem],
    ) -> List[OCRItem]:
        linked: List[OCRItem] = []
        expanded = bounds.expand(self.config.text_merge_distance_px)

        for item in ocr_items:
            if bounds.contains_center_of(item.bounds):
                linked.append(item)
                continue

            if expanded.contains_center_of(item.bounds):
                linked.append(item)
                continue

            if bounds.iou(item.bounds) > 0.10:
                linked.append(item)

        return sorted(linked, key=lambda item: (item.bounds.y1, item.bounds.x1))

    def _combine_ocr_text(self, items: Sequence[OCRItem]) -> str:
        if not items:
            return ""

        sorted_items = sorted(items, key=lambda item: (item.bounds.y1, item.bounds.x1))
        words: List[str] = []

        for item in sorted_items:
            text = self._clean_text(item.text)
            if text:
                words.append(text)

        return " ".join(words).strip()

    def _ocr_already_covered(
        self,
        item: OCRItem,
        elements: Sequence[DetectedElement],
    ) -> bool:
        for element in elements:
            if element.bounds.contains_center_of(item.bounds):
                return True
            if element.bounds.iou(item.bounds) >= 0.45:
                return True
        return False

    def _find_nearby_labels(
        self,
        element: DetectedElement,
        labels: Sequence[DetectedElement],
    ) -> List[DetectedElement]:
        nearby: List[Tuple[float, DetectedElement]] = []

        for label in labels:
            if label.element_id == element.element_id:
                continue

            distance = self._box_distance(element.bounds, label.bounds)

            same_row = abs(element.bounds.center["y"] - label.bounds.center["y"]) <= max(
                element.bounds.height,
                label.bounds.height,
                20,
            )

            above = (
                label.bounds.y2 <= element.bounds.y1
                and abs(label.bounds.x1 - element.bounds.x1) <= max(80, element.bounds.width)
            )

            left_of = (
                label.bounds.x2 <= element.bounds.x1
                and same_row
            )

            if distance <= 90 and (same_row or above or left_of):
                nearby.append((distance, label))

        nearby.sort(key=lambda pair: pair[0])
        return [item for _, item in nearby[:3]]

    def _ocr_to_child(self, item: OCRItem) -> Dict[str, Any]:
        return {
            "type": "ocr_text",
            "text": item.text,
            "confidence": round(item.confidence, 4),
            "bounds": item.bounds.to_dict(),
            "source": item.source,
        }

    # -----------------------------------------------------------------------
    # Candidate cleanup helpers
    # -----------------------------------------------------------------------

    def _dedupe_candidates(self, candidates: Sequence[VisualCandidate]) -> List[VisualCandidate]:
        sorted_candidates = sorted(
            candidates,
            key=lambda item: (-item.confidence, item.bounds.y1, item.bounds.x1),
        )

        kept: List[VisualCandidate] = []

        for candidate in sorted_candidates:
            duplicate = False

            for existing in kept:
                if candidate.bounds.iou(existing.bounds) >= self.config.merge_iou_threshold:
                    duplicate = True
                    break

                if existing.bounds.contains_center_of(candidate.bounds):
                    if candidate.bounds.area <= existing.bounds.area * 0.20:
                        continue
                    duplicate = True
                    break

            if not duplicate:
                kept.append(candidate)

        return kept

    def _candidate_area_ok(self, area: int, image_area: int) -> bool:
        if area < self.config.min_candidate_area:
            return False

        ratio = area / max(1, image_area)
        if ratio > self.config.max_candidate_area_ratio:
            return False

        return True

    def _estimate_edge_density(self, edge_array: Any, box: BoundingBox) -> float:
        if np is None:
            return 0.0

        try:
            region = edge_array[box.y1:box.y2, box.x1:box.x2]
            if region.size <= 0:
                return 0.0
            active = float(np.count_nonzero(region))
            return active / float(region.size)
        except Exception:
            return 0.0

    # -----------------------------------------------------------------------
    # Utility helpers
    # -----------------------------------------------------------------------

    def _normalize_target_types(self, target_types: Optional[Sequence[str]]) -> Optional[set]:
        if not target_types:
            return None

        normalized = {
            str(item).strip().lower()
            for item in target_types
            if str(item).strip().lower() in SUPPORTED_ELEMENT_TYPES
        }

        return normalized or None

    def _clamp_box_if_possible(
        self,
        box: BoundingBox,
        image_size: Optional[Tuple[int, int]],
    ) -> BoundingBox:
        normalized = box.normalize()

        if image_size is None:
            return normalized

        width, height = image_size
        return normalized.clamp(width, height)

    def _aspect_ratio(self, box: BoundingBox) -> float:
        if box.height <= 0:
            return 0.0
        return box.width / box.height

    def _box_distance(self, first: BoundingBox, second: BoundingBox) -> float:
        a = first.center
        b = second.center
        return math.sqrt((a["x"] - b["x"]) ** 2 + (a["y"] - b["y"]) ** 2)

    def _clean_text(self, text: Optional[str]) -> str:
        if not text:
            return ""

        cleaned = re.sub(r"\s+", " ", str(text)).strip()
        return cleaned

    def _merge_text_values(self, first: Optional[str], second: Optional[str]) -> Optional[str]:
        first_clean = self._clean_text(first)
        second_clean = self._clean_text(second)

        if not first_clean:
            return second_clean or None

        if not second_clean:
            return first_clean or None

        if first_clean.lower() == second_clean.lower():
            return first_clean

        if second_clean.lower() in first_clean.lower():
            return first_clean

        if first_clean.lower() in second_clean.lower():
            return second_clean

        return f"{first_clean} {second_clean}".strip()

    def _new_element_id(self, element_type: str) -> str:
        return f"{element_type}_{uuid.uuid4().hex[:12]}"

    def _count_by_type(self, elements: Sequence[DetectedElement]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for element in elements:
            counts[element.element_type] = counts.get(element.element_type, 0) + 1
        return counts

    def _build_summary(self, elements: Sequence[DetectedElement]) -> Dict[str, Any]:
        counts = self._count_by_type(elements)
        high_confidence = [element for element in elements if element.confidence >= 0.75]

        return {
            "total": len(elements),
            "by_type": counts,
            "high_confidence_count": len(high_confidence),
            "clickable_count": sum(
                counts.get(element_type, 0)
                for element_type in (
                    ELEMENT_BUTTON,
                    ELEMENT_LINK,
                    ELEMENT_ICON,
                    ELEMENT_CHECKBOX,
                    ELEMENT_TOGGLE,
                )
            ),
            "form_related_count": sum(
                counts.get(element_type, 0)
                for element_type in (
                    ELEMENT_INPUT,
                    ELEMENT_CHECKBOX,
                    ELEMENT_TOGGLE,
                )
            ),
        }

    def _strip_data_uri_prefix(self, value: str) -> str:
        text = value.strip()
        if "," in text and text.lower().startswith("data:"):
            return text.split(",", 1)[1]
        return text

    def _utc_timestamp(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _sanitize_for_memory(self, value: Any) -> Any:
        """
        Sanitizes nested payloads before audit/memory storage.

        Raw image bytes/base64 are removed.
        """

        if isinstance(value, Mapping):
            sanitized: Dict[str, Any] = {}
            for key, item in value.items():
                lower_key = str(key).lower()

                if lower_key in {"image_bytes", "image_base64", "raw_image", "screenshot_bytes"}:
                    sanitized[str(key)] = "<OMITTED_IMAGE_DATA>"
                elif any(
                    marker in lower_key
                    for marker in (
                        "token",
                        "secret",
                        "password",
                        "passwd",
                        "api_key",
                        "apikey",
                        "credential",
                        "authorization",
                    )
                ):
                    sanitized[str(key)] = "<REDACTED>"
                else:
                    sanitized[str(key)] = self._sanitize_for_memory(item)
            return sanitized

        if isinstance(value, list):
            return [self._sanitize_for_memory(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self._sanitize_for_memory(item) for item in value)

        if isinstance(value, bytes):
            return "<OMITTED_BYTES>"

        return value

    def _send_memory_payload(self, payload: Mapping[str, Any]) -> None:
        """
        Sends useful visual context to Memory Agent if connected.
        """

        if self.memory_agent is None:
            return

        for method_name in ("store", "remember", "save_memory", "add"):
            method = getattr(self.memory_agent, method_name, None)
            if callable(method):
                try:
                    method(dict(payload))
                    return
                except Exception as exc:
                    self.logger.debug("Unable to send memory payload: %s", exc)
                    return

    def _exception_result(
        self,
        message: str,
        exc: Exception,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return self._error_result(
            message=message,
            error={
                "code": "UNEXPECTED_EXCEPTION",
                "exception": str(exc),
                "traceback": traceback.format_exc(),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
            },
        )


# ---------------------------------------------------------------------------
# Convenience factory for Agent Loader / Registry
# ---------------------------------------------------------------------------

def create_element_detector(**kwargs: Any) -> ElementDetector:
    """
    Factory used by Agent Loader, Agent Registry, tests, or Dashboard/API.
    """

    return ElementDetector(**kwargs)


def get_module_metadata() -> Dict[str, Any]:
    """
    Module-level metadata for registry discovery.
    """

    return {
        "module": "agents.visual_agent.element_detector",
        "file_path": "agents/visual_agent/element_detector.py",
        "class_name": "ElementDetector",
        "factory": "create_element_detector",
        "version": ElementDetector.version,
        "safe_to_import": True,
        "purpose": "Finds buttons, inputs, cards, icons, labels, bounds, confidence.",
        "agent_module": "Visual Agent",
        "optional_dependencies": {
            "Pillow": Image is not None,
            "numpy": np is not None,
            "opencv_python": cv2 is not None,
        },
    }


__all__ = [
    "ElementDetector",
    "ElementDetectorConfig",
    "BoundingBox",
    "OCRItem",
    "VisualCandidate",
    "DetectedElement",
    "create_element_detector",
    "get_module_metadata",
    "ELEMENT_BUTTON",
    "ELEMENT_INPUT",
    "ELEMENT_CARD",
    "ELEMENT_ICON",
    "ELEMENT_LABEL",
    "ELEMENT_LINK",
    "ELEMENT_CHECKBOX",
    "ELEMENT_TOGGLE",
    "ELEMENT_IMAGE",
    "ELEMENT_CONTAINER",
    "ELEMENT_UNKNOWN",
]


if __name__ == "__main__":
    detector = ElementDetector()
    print(json.dumps(detector.health_check(), indent=2, default=str))