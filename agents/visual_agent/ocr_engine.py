"""
File: agents/visual_agent/ocr_engine.py
Project: William / Jarvis Multi-Agent AI SaaS System by Digital Promotix

Purpose:
    Extracts and cleans text from screenshots, images, and video frames.

Agent/Module:
    Visual Agent

Required Class:
    OCREngine

Architecture Compatibility:
    - BaseAgent compatible with fallback if BaseAgent does not exist yet.
    - MasterAgent / Agent Registry / Agent Loader / Agent Router compatible.
    - SaaS user/workspace isolation aware.
    - Security Agent hook compatible for sensitive OCR content.
    - Memory Agent payload compatible.
    - Verification Agent payload compatible.
    - Dashboard/API ready structured responses.

Import Safety:
    This file can be imported even when optional OCR/image dependencies are not
    installed yet. OCR execution gracefully falls back with a clear error/status.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import io
import json
import logging
import os
import re
import time
import traceback
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        Keeps this file import-safe before the real William/Jarvis BaseAgent is
        available. The real BaseAgent can later provide richer registry, routing,
        event, audit, memory, and security integrations.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "visual")
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)

        def log_audit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit_event: %s %s", event_name, payload)


try:
    from PIL import Image, ImageOps, ImageEnhance, ImageFilter  # type: ignore
    PIL_AVAILABLE = True
except Exception:  # pragma: no cover
    Image = None  # type: ignore
    ImageOps = None  # type: ignore
    ImageEnhance = None  # type: ignore
    ImageFilter = None  # type: ignore
    PIL_AVAILABLE = False


try:
    import pytesseract  # type: ignore
    PYTESSERACT_AVAILABLE = True
except Exception:  # pragma: no cover
    pytesseract = None  # type: ignore
    PYTESSERACT_AVAILABLE = False


try:
    import cv2  # type: ignore
    CV2_AVAILABLE = True
except Exception:  # pragma: no cover
    cv2 = None  # type: ignore
    CV2_AVAILABLE = False


try:
    import numpy as np  # type: ignore
    NUMPY_AVAILABLE = True
except Exception:  # pragma: no cover
    np = None  # type: ignore
    NUMPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("william.visual_agent.ocr_engine")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MIN_CONFIDENCE = 35.0
DEFAULT_HIGH_CONFIDENCE = 80.0
DEFAULT_MAX_IMAGE_BYTES = 25 * 1024 * 1024
DEFAULT_MAX_IMAGE_PIXELS = 40_000_000
DEFAULT_LANGUAGE = "eng"
DEFAULT_TESSERACT_CONFIG = "--oem 3 --psm 6"
MAX_TEXT_PREVIEW = 800
MAX_BLOCKS_RETURNED = 500
MAX_LINES_RETURNED = 500
MAX_WORDS_RETURNED = 2000


# ---------------------------------------------------------------------------
# Enums / Data structures
# ---------------------------------------------------------------------------

class OCRBackend(str, Enum):
    """Supported OCR backend names."""

    AUTO = "auto"
    TESSERACT = "tesseract"
    NONE = "none"


class OCRStatus(str, Enum):
    """High-level OCR extraction status."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    EMPTY = "empty"
    SKIPPED = "skipped"
    ERROR = "error"


class ImageInputType(str, Enum):
    """Input source type for OCR."""

    FILE_PATH = "file_path"
    BYTES = "bytes"
    BASE64 = "base64"
    PIL_IMAGE = "pil_image"
    CV2_IMAGE = "cv2_image"
    UNKNOWN = "unknown"


@dataclasses.dataclass
class OCRBox:
    """Single OCR text box/word item."""

    text: str
    confidence: float
    left: int
    top: int
    width: int
    height: int
    level: Optional[int] = None
    page_num: Optional[int] = None
    block_num: Optional[int] = None
    par_num: Optional[int] = None
    line_num: Optional[int] = None
    word_num: Optional[int] = None

    @property
    def right(self) -> int:
        return self.left + self.width

    @property
    def bottom(self) -> int:
        return self.top + self.height

    @property
    def center_x(self) -> float:
        return self.left + (self.width / 2)

    @property
    def center_y(self) -> float:
        return self.top + (self.height / 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "confidence": round(float(self.confidence), 4),
            "left": int(self.left),
            "top": int(self.top),
            "width": int(self.width),
            "height": int(self.height),
            "right": int(self.right),
            "bottom": int(self.bottom),
            "center_x": round(float(self.center_x), 3),
            "center_y": round(float(self.center_y), 3),
            "level": self.level,
            "page_num": self.page_num,
            "block_num": self.block_num,
            "par_num": self.par_num,
            "line_num": self.line_num,
            "word_num": self.word_num,
        }


@dataclasses.dataclass
class OCRLine:
    """Grouped OCR line derived from OCR boxes."""

    text: str
    confidence: float
    left: int
    top: int
    width: int
    height: int
    word_count: int
    words: List[Dict[str, Any]]

    @property
    def right(self) -> int:
        return self.left + self.width

    @property
    def bottom(self) -> int:
        return self.top + self.height

    @property
    def center_x(self) -> float:
        return self.left + (self.width / 2)

    @property
    def center_y(self) -> float:
        return self.top + (self.height / 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "confidence": round(float(self.confidence), 4),
            "left": int(self.left),
            "top": int(self.top),
            "width": int(self.width),
            "height": int(self.height),
            "right": int(self.right),
            "bottom": int(self.bottom),
            "center_x": round(float(self.center_x), 3),
            "center_y": round(float(self.center_y), 3),
            "word_count": int(self.word_count),
            "words": self.words,
        }


@dataclasses.dataclass
class OCREngineOptions:
    """OCR run configuration."""

    backend: OCRBackend = OCRBackend.AUTO
    language: str = DEFAULT_LANGUAGE
    tesseract_config: str = DEFAULT_TESSERACT_CONFIG
    min_confidence: float = DEFAULT_MIN_CONFIDENCE
    high_confidence: float = DEFAULT_HIGH_CONFIDENCE
    preprocess: bool = True
    grayscale: bool = True
    auto_contrast: bool = True
    sharpen: bool = False
    upscale: bool = False
    upscale_factor: float = 1.5
    normalize_text: bool = True
    remove_empty_lines: bool = True
    collapse_whitespace: bool = True
    redact_sensitive_text: bool = True
    include_boxes: bool = True
    include_lines: bool = True
    include_raw: bool = False
    max_image_bytes: int = DEFAULT_MAX_IMAGE_BYTES
    max_image_pixels: int = DEFAULT_MAX_IMAGE_PIXELS
    max_blocks_returned: int = MAX_BLOCKS_RETURNED
    max_lines_returned: int = MAX_LINES_RETURNED
    max_words_returned: int = MAX_WORDS_RETURNED
    allowed_file_extensions: Tuple[str, ...] = (
        ".png",
        ".jpg",
        ".jpeg",
        ".webp",
        ".bmp",
        ".tif",
        ".tiff",
    )
    sensitive_patterns: Tuple[str, ...] = (
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        r"\b(?:\+?\d[\d\s().-]{7,}\d)\b",
        r"\b(?:password|secret|token|api[_-]?key|authorization|bearer)\b\s*[:=]\s*\S+",
        r"\b\d{13,19}\b",
    )

    @classmethod
    def from_dict(cls, data: Optional[Mapping[str, Any]]) -> "OCREngineOptions":
        if not data:
            return cls()

        raw = dict(data)

        backend_raw = raw.get("backend", OCRBackend.AUTO.value)
        if isinstance(backend_raw, OCRBackend):
            backend = backend_raw
        else:
            try:
                backend = OCRBackend(str(backend_raw).strip().lower())
            except Exception:
                backend = OCRBackend.AUTO

        def as_bool(name: str, default: bool) -> bool:
            value = raw.get(name, default)
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "y", "on"}
            return bool(value)

        def as_float(name: str, default: float) -> float:
            try:
                return float(raw.get(name, default))
            except Exception:
                return default

        def as_int(name: str, default: int) -> int:
            try:
                return int(raw.get(name, default))
            except Exception:
                return default

        def as_tuple(name: str, default: Tuple[str, ...]) -> Tuple[str, ...]:
            value = raw.get(name, default)
            if value is None:
                return default
            if isinstance(value, str):
                return (value,)
            if isinstance(value, Iterable):
                return tuple(str(item) for item in value)
            return default

        return cls(
            backend=backend,
            language=str(raw.get("language", DEFAULT_LANGUAGE) or DEFAULT_LANGUAGE),
            tesseract_config=str(raw.get("tesseract_config", DEFAULT_TESSERACT_CONFIG) or ""),
            min_confidence=as_float("min_confidence", DEFAULT_MIN_CONFIDENCE),
            high_confidence=as_float("high_confidence", DEFAULT_HIGH_CONFIDENCE),
            preprocess=as_bool("preprocess", True),
            grayscale=as_bool("grayscale", True),
            auto_contrast=as_bool("auto_contrast", True),
            sharpen=as_bool("sharpen", False),
            upscale=as_bool("upscale", False),
            upscale_factor=max(1.0, as_float("upscale_factor", 1.5)),
            normalize_text=as_bool("normalize_text", True),
            remove_empty_lines=as_bool("remove_empty_lines", True),
            collapse_whitespace=as_bool("collapse_whitespace", True),
            redact_sensitive_text=as_bool("redact_sensitive_text", True),
            include_boxes=as_bool("include_boxes", True),
            include_lines=as_bool("include_lines", True),
            include_raw=as_bool("include_raw", False),
            max_image_bytes=max(1, as_int("max_image_bytes", DEFAULT_MAX_IMAGE_BYTES)),
            max_image_pixels=max(1, as_int("max_image_pixels", DEFAULT_MAX_IMAGE_PIXELS)),
            max_blocks_returned=max(1, as_int("max_blocks_returned", MAX_BLOCKS_RETURNED)),
            max_lines_returned=max(1, as_int("max_lines_returned", MAX_LINES_RETURNED)),
            max_words_returned=max(1, as_int("max_words_returned", MAX_WORDS_RETURNED)),
            allowed_file_extensions=as_tuple(
                "allowed_file_extensions",
                (
                    ".png",
                    ".jpg",
                    ".jpeg",
                    ".webp",
                    ".bmp",
                    ".tif",
                    ".tiff",
                ),
            ),
            sensitive_patterns=as_tuple(
                "sensitive_patterns",
                (
                    r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
                    r"\b(?:\+?\d[\d\s().-]{7,}\d)\b",
                    r"\b(?:password|secret|token|api[_-]?key|authorization|bearer)\b\s*[:=]\s*\S+",
                    r"\b\d{13,19}\b",
                ),
            ),
        )


# ---------------------------------------------------------------------------
# OCREngine
# ---------------------------------------------------------------------------

class OCREngine(BaseAgent):
    """
    Visual Agent OCR engine.

    Responsibilities:
        - Accept screenshot/image/frame input.
        - Validate SaaS user/workspace context.
        - Safely load image input.
        - Preprocess image for OCR.
        - Extract text using optional OCR backend.
        - Clean and normalize extracted text.
        - Build word boxes and grouped text lines.
        - Redact sensitive OCR output when configured.
        - Return structured William/Jarvis result dict.
        - Prepare Verification Agent and Memory Agent compatible payloads.

    Connections:
        - Master Agent can call extract_text_from_image() after screenshots.
        - Visual Agent can call this from screenshot_reader.py and video_analyzer.py.
        - Verification Agent can use OCR text as proof.
        - Memory Agent can store safe text summaries.
        - Security Agent can approve sensitive OCR extraction/reporting.
        - Dashboard/API can display text, lines, boxes, confidence, and metadata.
    """

    agent_name = "visual_ocr_engine"
    agent_type = "visual"
    module_name = "visual_agent"
    file_name = "ocr_engine.py"

    def __init__(
        self,
        *,
        default_options: Optional[Union[OCREngineOptions, Mapping[str, Any]]] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(
                agent_name=self.agent_name,
                agent_type=self.agent_type,
                **kwargs,
            )
        except TypeError:
            super().__init__()

        self.logger = logger or getattr(self, "logger", LOGGER)
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger

        if isinstance(default_options, OCREngineOptions):
            self.default_options = default_options
        else:
            self.default_options = OCREngineOptions.from_dict(default_options)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_text_from_image(
        self,
        image: Any,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        task_id: Optional[str] = None,
        source_id: Optional[str] = None,
        source_type: str = "image",
        options: Optional[Union[OCREngineOptions, Mapping[str, Any]]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract and clean text from an image-like input.

        Supported image inputs:
            - str / Path file path
            - bytes image data
            - base64 string
            - PIL.Image object
            - OpenCV / numpy image array when cv2/numpy are installed

        Returns:
            {
                success,
                message,
                data: {
                    status,
                    text,
                    clean_text,
                    redacted_text,
                    confidence,
                    boxes,
                    lines,
                    word_count,
                    line_count,
                    image_metadata,
                    verification_payload,
                    memory_payload
                },
                error,
                metadata
            }
        """

        started_at = time.time()
        ctx = dict(context or {})
        run_options = self._merge_options(options)

        validation_context = {
            "user_id": str(user_id) if user_id is not None else None,
            "workspace_id": str(workspace_id) if workspace_id is not None else None,
            "task_id": task_id,
            "source_id": source_id,
            "source_type": source_type,
            "context": ctx,
        }

        try:
            context_result = self._validate_task_context(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                context=ctx,
            )
            if not context_result["success"]:
                return context_result

            image_obj, input_type, image_metadata = self._load_image(
                image=image,
                options=run_options,
            )

            if self._requires_security_check(
                image_metadata=image_metadata,
                context=ctx,
                options=run_options,
            ):
                approval = self._request_security_approval(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=task_id,
                    action="extract_ocr_text",
                    metadata={
                        "source_id": source_id,
                        "source_type": source_type,
                        "input_type": input_type.value,
                        "reason": "ocr_may_contain_sensitive_text",
                    },
                )
                if not approval.get("approved", False):
                    return self._safe_result(
                        success=False,
                        message="OCR extraction requires security approval and was not approved.",
                        data={
                            "status": OCRStatus.SKIPPED.value,
                            "text": "",
                            "confidence": 0.0,
                            "approved": False,
                        },
                        metadata=self._metadata(
                            started_at=started_at,
                            validation_context=validation_context,
                            options=run_options,
                        ),
                    )

            processed_image = self._preprocess_image(image_obj, run_options)
            backend = self._resolve_backend(run_options.backend)

            if backend == OCRBackend.NONE:
                return self._safe_result(
                    success=False,
                    message="No OCR backend is available. Install pytesseract and Tesseract OCR to enable extraction.",
                    data={
                        "status": OCRStatus.ERROR.value,
                        "text": "",
                        "clean_text": "",
                        "redacted_text": "",
                        "confidence": 0.0,
                        "boxes": [],
                        "lines": [],
                        "image_metadata": image_metadata,
                    },
                    error={
                        "code": "OCR_BACKEND_UNAVAILABLE",
                        "details": self._backend_help_message(),
                    },
                    metadata=self._metadata(
                        started_at=started_at,
                        validation_context=validation_context,
                        options=run_options,
                    ),
                )

            raw_result = self._run_ocr(
                image=processed_image,
                backend=backend,
                options=run_options,
            )

            text = raw_result.get("text", "")
            clean_text = self.clean_text(text, options=run_options)
            redacted_text = self.redact_sensitive_text(clean_text, options=run_options) if run_options.redact_sensitive_text else clean_text

            boxes = raw_result.get("boxes", [])
            filtered_boxes = self._filter_boxes(boxes, run_options)
            lines = self._group_boxes_into_lines(filtered_boxes, run_options)

            confidence = self._calculate_overall_confidence(filtered_boxes, text=clean_text)
            status = self._status_from_ocr(clean_text, confidence, filtered_boxes, run_options)

            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                source_id=source_id,
                source_type=source_type,
                status=status,
                confidence=confidence,
                clean_text=redacted_text,
                image_metadata=image_metadata,
                context=ctx,
            )

            memory_payload = self._prepare_memory_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                source_id=source_id,
                source_type=source_type,
                status=status,
                confidence=confidence,
                clean_text=redacted_text,
                context=ctx,
            )

            self._emit_agent_event(
                event_name="visual.ocr_extracted",
                payload={
                    "user_id": str(user_id) if user_id is not None else None,
                    "workspace_id": str(workspace_id) if workspace_id is not None else None,
                    "task_id": task_id,
                    "source_id": source_id,
                    "source_type": source_type,
                    "status": status.value,
                    "confidence": confidence,
                    "word_count": len(filtered_boxes),
                    "line_count": len(lines),
                },
            )

            self._log_audit_event(
                event_name="visual_ocr_extraction_completed",
                payload={
                    "user_id": str(user_id) if user_id is not None else None,
                    "workspace_id": str(workspace_id) if workspace_id is not None else None,
                    "task_id": task_id,
                    "source_id": source_id,
                    "source_type": source_type,
                    "status": status.value,
                    "confidence": confidence,
                    "duration_ms": round((time.time() - started_at) * 1000, 3),
                },
            )

            data = {
                "status": status.value,
                "text": redacted_text,
                "clean_text": redacted_text,
                "raw_text": text if run_options.include_raw else None,
                "unredacted_clean_text": clean_text if not run_options.redact_sensitive_text else None,
                "confidence": confidence,
                "backend": backend.value,
                "input_type": input_type.value,
                "word_count": len(filtered_boxes),
                "line_count": len(lines),
                "char_count": len(redacted_text),
                "has_text": bool(redacted_text.strip()),
                "boxes": [box.to_dict() for box in filtered_boxes[: run_options.max_words_returned]] if run_options.include_boxes else [],
                "lines": [line.to_dict() for line in lines[: run_options.max_lines_returned]] if run_options.include_lines else [],
                "image_metadata": image_metadata,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            }

            return self._safe_result(
                success=status in {OCRStatus.COMPLETED, OCRStatus.PARTIAL},
                message=self._message_for_status(status, confidence, len(filtered_boxes)),
                data=data,
                metadata=self._metadata(
                    started_at=started_at,
                    validation_context=validation_context,
                    options=run_options,
                ),
            )

        except Exception as exc:
            self.logger.exception("OCR extraction failed unexpectedly.")
            self._log_audit_event(
                event_name="visual_ocr_extraction_error",
                payload={
                    "user_id": str(user_id) if user_id is not None else None,
                    "workspace_id": str(workspace_id) if workspace_id is not None else None,
                    "task_id": task_id,
                    "source_id": source_id,
                    "source_type": source_type,
                    "error": str(exc),
                },
            )
            return self._error_result(
                message="OCR extraction failed due to an internal error.",
                error=exc,
                metadata=self._metadata(
                    started_at=started_at,
                    validation_context=validation_context,
                    options=run_options,
                ),
            )

    def extract_text_from_frame(
        self,
        frame: Any,
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        task_id: Optional[str] = None,
        video_id: Optional[str] = None,
        frame_index: Optional[int] = None,
        timestamp_seconds: Optional[float] = None,
        options: Optional[Union[OCREngineOptions, Mapping[str, Any]]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract OCR text from a video frame.

        This wraps extract_text_from_image() and adds video/frame metadata so
        video_analyzer.py can reuse OCR output safely.
        """

        ctx = dict(context or {})
        ctx.update(
            {
                "video_id": video_id,
                "frame_index": frame_index,
                "timestamp_seconds": timestamp_seconds,
            }
        )

        source_id = video_id
        if video_id is not None and frame_index is not None:
            source_id = f"{video_id}:frame:{frame_index}"

        return self.extract_text_from_image(
            frame,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            source_id=source_id,
            source_type="video_frame",
            options=options,
            context=ctx,
        )

    def extract_text_batch(
        self,
        images: Sequence[Any],
        *,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        task_id: Optional[str] = None,
        source_type: str = "image_batch",
        options: Optional[Union[OCREngineOptions, Mapping[str, Any]]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract OCR text from multiple images/frames.

        Each item is processed independently with the same SaaS isolation context.
        """

        started_at = time.time()
        results: List[Dict[str, Any]] = []
        combined_text_parts: List[str] = []
        success_count = 0
        error_count = 0

        for index, item in enumerate(images or []):
            result = self.extract_text_from_image(
                item,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                source_id=f"{task_id or 'batch'}:{index}",
                source_type=source_type,
                options=options,
                context={
                    **dict(context or {}),
                    "batch_index": index,
                    "batch_size": len(images or []),
                },
            )
            results.append(result)

            if result.get("success"):
                success_count += 1
                text = str(result.get("data", {}).get("clean_text", "") or "")
                if text.strip():
                    combined_text_parts.append(text.strip())
            else:
                error_count += 1

        combined_text = "\n\n".join(combined_text_parts)
        status = OCRStatus.COMPLETED if success_count and not error_count else OCRStatus.PARTIAL if success_count else OCRStatus.ERROR

        return self._safe_result(
            success=success_count > 0,
            message=f"Batch OCR completed: {success_count} succeeded, {error_count} failed.",
            data={
                "status": status.value,
                "success_count": success_count,
                "error_count": error_count,
                "total_count": len(images or []),
                "combined_text": combined_text,
                "results": results,
            },
            metadata={
                "agent": self.agent_name,
                "module": self.module_name,
                "file": self.file_name,
                "duration_ms": round((time.time() - started_at) * 1000, 3),
                "created_at": self._utc_now_iso(),
            },
        )

    def clean_text(
        self,
        text: str,
        *,
        options: Optional[Union[OCREngineOptions, Mapping[str, Any]]] = None,
    ) -> str:
        """
        Clean and normalize OCR text.

        Handles common OCR artifacts while preserving enough formatting for UI
        mapping, screenshot reading, and verification proof.
        """

        run_options = self._merge_options(options)
        if text is None:
            return ""

        cleaned = str(text).replace("\r\n", "\n").replace("\r", "\n")
        cleaned = cleaned.replace("\x0c", "\n")
        cleaned = cleaned.replace("\u00a0", " ")

        cleaned = self._fix_common_ocr_artifacts(cleaned)

        if run_options.collapse_whitespace:
            lines = []
            for line in cleaned.split("\n"):
                line = re.sub(r"[ \t]+", " ", line)
                line = line.strip()
                if line or not run_options.remove_empty_lines:
                    lines.append(line)
            cleaned = "\n".join(lines)

        if run_options.remove_empty_lines:
            cleaned = "\n".join(line for line in cleaned.split("\n") if line.strip())

        if run_options.normalize_text:
            cleaned = cleaned.strip()

        return cleaned

    def redact_sensitive_text(
        self,
        text: str,
        *,
        options: Optional[Union[OCREngineOptions, Mapping[str, Any]]] = None,
    ) -> str:
        """
        Redact sensitive-looking OCR text.

        This protects Memory Agent, audit logs, Dashboard previews, and
        Verification payloads from leaking credentials or private data.
        """

        run_options = self._merge_options(options)
        redacted = str(text or "")

        for pattern in run_options.sensitive_patterns:
            try:
                redacted = re.sub(pattern, "[REDACTED]", redacted, flags=re.IGNORECASE)
            except re.error:
                continue

        return redacted

    def has_ocr_backend(self) -> bool:
        """Return True when an OCR backend is currently available."""

        return PYTESSERACT_AVAILABLE

    # ------------------------------------------------------------------
    # Image loading / preprocessing
    # ------------------------------------------------------------------

    def _load_image(
        self,
        *,
        image: Any,
        options: OCREngineOptions,
    ) -> Tuple[Any, ImageInputType, Dict[str, Any]]:
        if not PIL_AVAILABLE:
            raise RuntimeError("Pillow is required to load images for OCR. Install pillow.")

        input_type = self._detect_input_type(image)
        raw_bytes: Optional[bytes] = None
        image_hash: Optional[str] = None

        if input_type == ImageInputType.FILE_PATH:
            path = Path(str(image)).expanduser()
            if not path.exists():
                raise FileNotFoundError(f"Image file does not exist: {path}")
            if not path.is_file():
                raise ValueError(f"Image path is not a file: {path}")

            extension = path.suffix.lower()
            if extension not in {ext.lower() for ext in options.allowed_file_extensions}:
                raise ValueError(f"Unsupported image extension: {extension}")

            size_bytes = path.stat().st_size
            if size_bytes > options.max_image_bytes:
                raise ValueError(f"Image exceeds max size: {size_bytes} bytes")

            raw_bytes = path.read_bytes()
            pil_image = Image.open(io.BytesIO(raw_bytes))
            image_hash = self._sha256_bytes(raw_bytes)
            source_name = path.name

        elif input_type == ImageInputType.BYTES:
            raw_bytes = bytes(image)
            if len(raw_bytes) > options.max_image_bytes:
                raise ValueError(f"Image exceeds max size: {len(raw_bytes)} bytes")
            pil_image = Image.open(io.BytesIO(raw_bytes))
            image_hash = self._sha256_bytes(raw_bytes)
            source_name = None

        elif input_type == ImageInputType.BASE64:
            raw_bytes = self._decode_base64_image(str(image))
            if len(raw_bytes) > options.max_image_bytes:
                raise ValueError(f"Image exceeds max size: {len(raw_bytes)} bytes")
            pil_image = Image.open(io.BytesIO(raw_bytes))
            image_hash = self._sha256_bytes(raw_bytes)
            source_name = None

        elif input_type == ImageInputType.PIL_IMAGE:
            pil_image = image.copy()
            source_name = None

        elif input_type == ImageInputType.CV2_IMAGE:
            if not NUMPY_AVAILABLE:
                raise RuntimeError("numpy is required for cv2/numpy frame OCR input.")

            array = image
            if CV2_AVAILABLE:
                try:
                    if len(array.shape) == 3:
                        array = cv2.cvtColor(array, cv2.COLOR_BGR2RGB)
                except Exception:
                    pass
            pil_image = Image.fromarray(array)
            source_name = None

        else:
            raise TypeError("Unsupported image input type for OCR.")

        pil_image = pil_image.convert("RGB")
        width, height = pil_image.size
        pixels = width * height
        if pixels > options.max_image_pixels:
            raise ValueError(f"Image exceeds max pixel count: {pixels}")

        metadata = {
            "input_type": input_type.value,
            "source_name": source_name,
            "width": width,
            "height": height,
            "pixels": pixels,
            "mode": pil_image.mode,
            "format": getattr(pil_image, "format", None),
            "sha256": image_hash,
            "size_bytes": len(raw_bytes) if raw_bytes is not None else None,
        }

        return pil_image, input_type, metadata

    def _detect_input_type(self, image: Any) -> ImageInputType:
        if PIL_AVAILABLE and Image is not None:
            try:
                if isinstance(image, Image.Image):
                    return ImageInputType.PIL_IMAGE
            except Exception:
                pass

        if isinstance(image, (str, os.PathLike, Path)):
            text = str(image)
            if self._looks_like_base64(text):
                return ImageInputType.BASE64
            return ImageInputType.FILE_PATH

        if isinstance(image, (bytes, bytearray, memoryview)):
            return ImageInputType.BYTES

        if NUMPY_AVAILABLE:
            try:
                if isinstance(image, np.ndarray):  # type: ignore
                    return ImageInputType.CV2_IMAGE
            except Exception:
                pass

        return ImageInputType.UNKNOWN

    def _preprocess_image(
        self,
        image: Any,
        options: OCREngineOptions,
    ) -> Any:
        if not options.preprocess:
            return image

        processed = image

        if options.grayscale:
            processed = ImageOps.grayscale(processed)

        if options.auto_contrast:
            processed = ImageOps.autocontrast(processed)

        if options.upscale:
            width, height = processed.size
            new_size = (
                max(1, int(width * options.upscale_factor)),
                max(1, int(height * options.upscale_factor)),
            )
            processed = processed.resize(new_size)

        if options.sharpen:
            processed = processed.filter(ImageFilter.SHARPEN)

        return processed

    # ------------------------------------------------------------------
    # OCR backend
    # ------------------------------------------------------------------

    def _resolve_backend(self, backend: OCRBackend) -> OCRBackend:
        if backend == OCRBackend.TESSERACT:
            return OCRBackend.TESSERACT if PYTESSERACT_AVAILABLE else OCRBackend.NONE

        if backend == OCRBackend.AUTO:
            if PYTESSERACT_AVAILABLE:
                return OCRBackend.TESSERACT
            return OCRBackend.NONE

        return OCRBackend.NONE

    def _run_ocr(
        self,
        *,
        image: Any,
        backend: OCRBackend,
        options: OCREngineOptions,
    ) -> Dict[str, Any]:
        if backend == OCRBackend.TESSERACT:
            return self._run_tesseract(image=image, options=options)

        return {
            "text": "",
            "boxes": [],
            "raw": None,
        }

    def _run_tesseract(
        self,
        *,
        image: Any,
        options: OCREngineOptions,
    ) -> Dict[str, Any]:
        if not PYTESSERACT_AVAILABLE or pytesseract is None:
            raise RuntimeError("pytesseract is not available.")

        text = pytesseract.image_to_string(
            image,
            lang=options.language,
            config=options.tesseract_config,
        )

        boxes: List[OCRBox] = []
        raw_data: Optional[Dict[str, Any]] = None

        try:
            data = pytesseract.image_to_data(
                image,
                lang=options.language,
                config=options.tesseract_config,
                output_type=pytesseract.Output.DICT,
            )
            raw_data = data if options.include_raw else None
            boxes = self._parse_tesseract_data(data)
        except Exception as exc:
            self.logger.debug("Tesseract image_to_data failed safely: %s", exc)

        return {
            "text": text or "",
            "boxes": boxes,
            "raw": raw_data,
        }

    def _parse_tesseract_data(self, data: Mapping[str, Sequence[Any]]) -> List[OCRBox]:
        boxes: List[OCRBox] = []

        texts = data.get("text", [])
        count = len(texts)

        for index in range(count):
            text = str(data.get("text", [""])[index] or "").strip()
            if not text:
                continue

            confidence = self._safe_float(data.get("conf", [0])[index], default=-1.0)
            left = self._safe_int(data.get("left", [0])[index])
            top = self._safe_int(data.get("top", [0])[index])
            width = self._safe_int(data.get("width", [0])[index])
            height = self._safe_int(data.get("height", [0])[index])

            box = OCRBox(
                text=text,
                confidence=confidence,
                left=left,
                top=top,
                width=width,
                height=height,
                level=self._safe_optional_int(data.get("level", [None])[index]),
                page_num=self._safe_optional_int(data.get("page_num", [None])[index]),
                block_num=self._safe_optional_int(data.get("block_num", [None])[index]),
                par_num=self._safe_optional_int(data.get("par_num", [None])[index]),
                line_num=self._safe_optional_int(data.get("line_num", [None])[index]),
                word_num=self._safe_optional_int(data.get("word_num", [None])[index]),
            )
            boxes.append(box)

        return boxes

    def _filter_boxes(
        self,
        boxes: Sequence[OCRBox],
        options: OCREngineOptions,
    ) -> List[OCRBox]:
        filtered: List[OCRBox] = []

        for box in boxes:
            if not box.text.strip():
                continue
            if box.confidence < 0:
                continue
            if box.confidence < options.min_confidence:
                continue
            filtered.append(box)

        return filtered[: options.max_words_returned]

    def _group_boxes_into_lines(
        self,
        boxes: Sequence[OCRBox],
        options: OCREngineOptions,
    ) -> List[OCRLine]:
        grouped: Dict[Tuple[int, int, int, int], List[OCRBox]] = {}

        for box in boxes:
            key = (
                box.page_num or 0,
                box.block_num or 0,
                box.par_num or 0,
                box.line_num or 0,
            )
            grouped.setdefault(key, []).append(box)

        lines: List[OCRLine] = []

        for _key, line_boxes in grouped.items():
            sorted_boxes = sorted(line_boxes, key=lambda item: (item.left, item.top))
            text = " ".join(box.text for box in sorted_boxes).strip()
            if not text:
                continue

            left = min(box.left for box in sorted_boxes)
            top = min(box.top for box in sorted_boxes)
            right = max(box.right for box in sorted_boxes)
            bottom = max(box.bottom for box in sorted_boxes)
            confidence = sum(box.confidence for box in sorted_boxes) / max(1, len(sorted_boxes))

            line = OCRLine(
                text=self.clean_text(text, options=options),
                confidence=confidence,
                left=left,
                top=top,
                width=max(0, right - left),
                height=max(0, bottom - top),
                word_count=len(sorted_boxes),
                words=[box.to_dict() for box in sorted_boxes],
            )
            lines.append(line)

        lines = sorted(lines, key=lambda item: (item.top, item.left))
        return lines[: options.max_lines_returned]

    # ------------------------------------------------------------------
    # Context / Security / Verification / Memory hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        task_id: Optional[str] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        William/Jarvis rule:
            Every user-specific execution must carry user_id and workspace_id.

        For system tests or local non-user usage, pass:
            context={"non_user_context": True}
        """

        ctx = dict(context or {})
        non_user_context = bool(ctx.get("non_user_context", False) or ctx.get("system_context", False))

        if non_user_context:
            return self._safe_result(
                success=True,
                message="OCR context validated for non-user/system context.",
                data={"context_valid": True},
            )

        missing = []
        if user_id is None or str(user_id).strip() == "":
            missing.append("user_id")
        if workspace_id is None or str(workspace_id).strip() == "":
            missing.append("workspace_id")

        if missing:
            return self._safe_result(
                success=False,
                message=f"Missing required SaaS isolation context: {', '.join(missing)}.",
                data={
                    "status": OCRStatus.SKIPPED.value,
                    "context_valid": False,
                    "missing": missing,
                    "task_id": task_id,
                },
                error={
                    "code": "MISSING_TASK_CONTEXT",
                    "details": f"Missing required context fields: {', '.join(missing)}",
                },
            )

        return self._safe_result(
            success=True,
            message="OCR context validated.",
            data={
                "context_valid": True,
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "task_id": task_id,
            },
        )

    def _requires_security_check(
        self,
        *,
        image_metadata: Optional[Mapping[str, Any]] = None,
        context: Optional[Mapping[str, Any]] = None,
        options: Optional[OCREngineOptions] = None,
    ) -> bool:
        """
        Decide whether Security Agent approval is required.

        OCR is read-only, but screenshots can contain private credentials, PII,
        customer data, or client dashboards. This hook lets Master/Security Agent
        enforce policies before extracting/reporting text.
        """

        ctx = dict(context or {})
        if bool(ctx.get("force_security_check", False)):
            return True
        if bool(ctx.get("contains_sensitive_screen", False)):
            return True
        if bool(ctx.get("privacy_mode", False)):
            return True

        return False

    def _request_security_approval(
        self,
        *,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        task_id: Optional[str],
        action: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Safe default:
            If no security client is configured, allow read-only OCR but rely on
            redaction before audit/memory/report output.
        """

        payload = {
            "user_id": str(user_id) if user_id is not None else None,
            "workspace_id": str(workspace_id) if workspace_id is not None else None,
            "task_id": task_id,
            "requesting_agent": self.agent_name,
            "action": action,
            "metadata": dict(metadata or {}),
            "read_only": True,
            "destructive": False,
        }

        if self.security_client is None:
            return {
                "approved": True,
                "source": "safe_default_no_security_client",
                "payload": payload,
            }

        try:
            if hasattr(self.security_client, "approve"):
                response = self.security_client.approve(payload)
            elif hasattr(self.security_client, "request_approval"):
                response = self.security_client.request_approval(payload)
            else:
                response = {"approved": True, "source": "security_client_no_approval_method"}

            if isinstance(response, Mapping):
                return {
                    "approved": bool(response.get("approved", response.get("success", False))),
                    "source": response.get("source", "security_client"),
                    "payload": payload,
                    "raw": dict(response),
                }

            return {
                "approved": bool(response),
                "source": "security_client_bool",
                "payload": payload,
            }

        except Exception as exc:
            self.logger.warning("Security approval failed safely: %s", exc)
            return {
                "approved": False,
                "source": "security_client_error",
                "error": str(exc),
                "payload": payload,
            }

    def _prepare_verification_payload(
        self,
        *,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        task_id: Optional[str],
        source_id: Optional[str],
        source_type: str,
        status: OCRStatus,
        confidence: float,
        clean_text: str,
        image_metadata: Mapping[str, Any],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible OCR proof payload.
        """

        return {
            "verification_type": "visual_ocr_text",
            "agent": self.agent_name,
            "user_id": str(user_id) if user_id is not None else None,
            "workspace_id": str(workspace_id) if workspace_id is not None else None,
            "task_id": task_id,
            "source_id": source_id,
            "source_type": source_type,
            "status": status.value,
            "confidence": confidence,
            "has_text": bool(clean_text.strip()),
            "text_preview": self._text_preview(clean_text),
            "image_metadata": dict(image_metadata),
            "context": dict(context or {}),
            "created_at": self._utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        task_id: Optional[str],
        source_id: Optional[str],
        source_type: str,
        status: OCRStatus,
        confidence: float,
        clean_text: str,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible OCR summary payload.

        Stores a safe preview only, not full unredacted screenshot text.
        """

        payload = {
            "memory_type": "visual_ocr_summary",
            "importance": "medium" if status in {OCRStatus.PARTIAL, OCRStatus.ERROR} else "low",
            "user_id": str(user_id) if user_id is not None else None,
            "workspace_id": str(workspace_id) if workspace_id is not None else None,
            "task_id": task_id,
            "source_id": source_id,
            "source_type": source_type,
            "status": status.value,
            "confidence": confidence,
            "text_preview": self._text_preview(clean_text),
            "char_count": len(clean_text or ""),
            "created_at": self._utc_now_iso(),
            "context": dict(context or {}),
        }

        if self.memory_client is not None:
            try:
                if hasattr(self.memory_client, "prepare_payload"):
                    prepared = self.memory_client.prepare_payload(payload)
                    if isinstance(prepared, Mapping):
                        return dict(prepared)
            except Exception as exc:
                self.logger.debug("Memory client prepare_payload failed safely: %s", exc)

        return payload

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit Visual Agent event for MasterAgent, Dashboard, analytics, or registry.
        """

        safe_payload = self._redact_mapping(payload)

        try:
            if self.event_emitter:
                self.event_emitter(event_name, safe_payload)
                return

            try:
                super().emit_event(event_name, safe_payload)  # type: ignore[misc]
                return
            except Exception:
                pass

            self.logger.debug("Agent event: %s %s", event_name, safe_payload)

        except Exception as exc:
            self.logger.debug("Event emit failed safely: %s", exc)

    def _log_audit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Write audit event without leaking sensitive OCR content.
        """

        safe_payload = self._redact_mapping(payload)

        try:
            if self.audit_logger:
                self.audit_logger(event_name, safe_payload)
                return

            try:
                super().log_audit_event(event_name, safe_payload)  # type: ignore[misc]
                return
            except Exception:
                pass

            self.logger.info("Audit event: %s %s", event_name, safe_payload)

        except Exception as exc:
            self.logger.debug("Audit logging failed safely: %s", exc)

    # ------------------------------------------------------------------
    # Structured results
    # ------------------------------------------------------------------

    def _safe_result(
        self,
        *,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Union[Mapping[str, Any], str, Exception]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": bool(success),
            "message": str(message),
            "data": dict(data or {}),
            "error": self._format_error(error),
            "metadata": dict(metadata or {}),
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Union[Exception, str, Mapping[str, Any]],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": False,
            "message": str(message),
            "data": {
                "status": OCRStatus.ERROR.value,
                "text": "",
                "clean_text": "",
                "redacted_text": "",
                "confidence": 0.0,
            },
            "error": self._format_error(error),
            "metadata": dict(metadata or {}),
        }

    def _format_error(self, error: Optional[Union[Mapping[str, Any], str, Exception]]) -> Optional[Dict[str, Any]]:
        if error is None:
            return None

        if isinstance(error, Mapping):
            return dict(error)

        if isinstance(error, Exception):
            return {
                "code": error.__class__.__name__,
                "message": str(error),
                "traceback": traceback.format_exc(limit=5),
            }

        return {
            "code": "ERROR",
            "message": str(error),
        }

    def _metadata(
        self,
        *,
        started_at: float,
        validation_context: Optional[Mapping[str, Any]],
        options: OCREngineOptions,
    ) -> Dict[str, Any]:
        return {
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "module": self.module_name,
            "file": self.file_name,
            "duration_ms": round((time.time() - started_at) * 1000, 3),
            "created_at": self._utc_now_iso(),
            "context": dict(validation_context or {}),
            "options": {
                "backend": options.backend.value,
                "language": options.language,
                "min_confidence": options.min_confidence,
                "preprocess": options.preprocess,
                "grayscale": options.grayscale,
                "auto_contrast": options.auto_contrast,
                "sharpen": options.sharpen,
                "upscale": options.upscale,
                "redact_sensitive_text": options.redact_sensitive_text,
                "include_boxes": options.include_boxes,
                "include_lines": options.include_lines,
                "include_raw": options.include_raw,
            },
            "dependencies": {
                "pillow_available": PIL_AVAILABLE,
                "pytesseract_available": PYTESSERACT_AVAILABLE,
                "cv2_available": CV2_AVAILABLE,
                "numpy_available": NUMPY_AVAILABLE,
            },
        }

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    def _merge_options(
        self,
        options: Optional[Union[OCREngineOptions, Mapping[str, Any]]],
    ) -> OCREngineOptions:
        if isinstance(options, OCREngineOptions):
            return dataclasses.replace(options)

        if isinstance(options, Mapping):
            base = dataclasses.asdict(self.default_options)
            base.update(dict(options))
            return OCREngineOptions.from_dict(base)

        return dataclasses.replace(self.default_options)

    def _status_from_ocr(
        self,
        clean_text: str,
        confidence: float,
        boxes: Sequence[OCRBox],
        options: OCREngineOptions,
    ) -> OCRStatus:
        if not clean_text.strip() and not boxes:
            return OCRStatus.EMPTY

        if confidence >= options.high_confidence:
            return OCRStatus.COMPLETED

        if confidence >= options.min_confidence:
            return OCRStatus.PARTIAL

        if clean_text.strip():
            return OCRStatus.PARTIAL

        return OCRStatus.EMPTY

    def _message_for_status(
        self,
        status: OCRStatus,
        confidence: float,
        word_count: int,
    ) -> str:
        if status == OCRStatus.COMPLETED:
            return f"OCR extraction completed with confidence {confidence:.2f}% and {word_count} word(s)."
        if status == OCRStatus.PARTIAL:
            return f"OCR extraction partially completed with confidence {confidence:.2f}% and {word_count} word(s)."
        if status == OCRStatus.EMPTY:
            return "OCR completed but no readable text was found."
        if status == OCRStatus.SKIPPED:
            return "OCR extraction was skipped."
        return "OCR extraction failed."

    def _calculate_overall_confidence(
        self,
        boxes: Sequence[OCRBox],
        *,
        text: str,
    ) -> float:
        valid_conf = [float(box.confidence) for box in boxes if box.confidence >= 0]
        if valid_conf:
            return round(sum(valid_conf) / len(valid_conf), 4)

        if text.strip():
            return 50.0

        return 0.0

    def _fix_common_ocr_artifacts(self, text: str) -> str:
        replacements = {
            "“": '"',
            "”": '"',
            "‘": "'",
            "’": "'",
            "—": "-",
            "–": "-",
            "|": "I",
        }

        fixed = text
        for old, new in replacements.items():
            fixed = fixed.replace(old, new)

        fixed = re.sub(r"[ \t]+\n", "\n", fixed)
        fixed = re.sub(r"\n{3,}", "\n\n", fixed)
        return fixed

    def _looks_like_base64(self, value: str) -> bool:
        text = value.strip()
        if text.startswith("data:image/") and ";base64," in text:
            return True

        if len(text) < 100:
            return False

        if re.fullmatch(r"[A-Za-z0-9+/=\s]+", text) is None:
            return False

        return len(text) % 4 == 0 or text.endswith("=")

    def _decode_base64_image(self, value: str) -> bytes:
        text = value.strip()

        if text.startswith("data:image/") and ";base64," in text:
            text = text.split(";base64,", 1)[1]

        text = re.sub(r"\s+", "", text)
        try:
            return base64.b64decode(text, validate=True)
        except Exception:
            return base64.b64decode(text)

    def _sha256_bytes(self, value: bytes) -> str:
        return hashlib.sha256(value).hexdigest()

    def _text_preview(self, text: str, limit: int = MAX_TEXT_PREVIEW) -> str:
        safe = str(text or "").strip()
        if len(safe) <= limit:
            return safe
        return safe[:limit] + "...[TRUNCATED]"

    def _safe_float(self, value: Any, default: float = 0.0) -> float:
        try:
            return float(value)
        except Exception:
            return default

    def _safe_int(self, value: Any, default: int = 0) -> int:
        try:
            return int(float(value))
        except Exception:
            return default

    def _safe_optional_int(self, value: Any) -> Optional[int]:
        try:
            if value is None:
                return None
            return int(float(value))
        except Exception:
            return None

    def _redact_mapping(self, data: Any) -> Any:
        sensitive_keys = (
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "private_key",
            "authorization",
            "cookie",
            "session",
            "raw_text",
            "unredacted_clean_text",
        )

        def redact(value: Any, depth: int = 0) -> Any:
            if depth > 20:
                return "[MAX_DEPTH]"

            if isinstance(value, Mapping):
                result: Dict[str, Any] = {}
                for key, child in value.items():
                    key_text = str(key).lower()
                    if any(sensitive in key_text for sensitive in sensitive_keys):
                        result[str(key)] = "[REDACTED]"
                    else:
                        result[str(key)] = redact(child, depth + 1)
                return result

            if isinstance(value, list):
                return [redact(item, depth + 1) for item in value]

            if isinstance(value, tuple):
                return tuple(redact(item, depth + 1) for item in value)

            return value

        return redact(data)

    def _backend_help_message(self) -> str:
        return (
            "Install dependencies with: pip install pillow pytesseract. "
            "Also install the Tesseract OCR system binary and ensure it is available in PATH."
        )

    def _utc_now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Registry / Loader compatibility
    # ------------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Agent Registry / Agent Loader compatible manifest.
        """

        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "module": self.module_name,
            "file": self.file_name,
            "class": self.__class__.__name__,
            "public_methods": [
                "extract_text_from_image",
                "extract_text_from_frame",
                "extract_text_batch",
                "clean_text",
                "redact_sensitive_text",
                "has_ocr_backend",
                "get_agent_manifest",
                "health_check",
            ],
            "requires_user_context": True,
            "requires_workspace_context": True,
            "performs_destructive_actions": False,
            "requires_security_for_sensitive_screens": True,
            "compatible_with": [
                "BaseAgent",
                "MasterAgent",
                "AgentRegistry",
                "AgentLoader",
                "AgentRouter",
                "VisualAgent",
                "VerificationAgent",
                "MemoryAgent",
                "SecurityAgent",
                "DashboardAPI",
            ],
            "optional_dependencies": {
                "pillow": PIL_AVAILABLE,
                "pytesseract": PYTESSERACT_AVAILABLE,
                "opencv-python": CV2_AVAILABLE,
                "numpy": NUMPY_AVAILABLE,
            },
            "version": "1.0.0",
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Lightweight health check for Dashboard/API and Agent Registry.
        """

        return self._safe_result(
            success=True,
            message="OCREngine is healthy.",
            data={
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "module": self.module_name,
                "file": self.file_name,
                "ocr_backend_available": self.has_ocr_backend(),
                "resolved_backend": self._resolve_backend(self.default_options.backend).value,
                "dependencies": {
                    "pillow_available": PIL_AVAILABLE,
                    "pytesseract_available": PYTESSERACT_AVAILABLE,
                    "cv2_available": CV2_AVAILABLE,
                    "numpy_available": NUMPY_AVAILABLE,
                },
                "backend_help": None if self.has_ocr_backend() else self._backend_help_message(),
            },
            metadata={
                "checked_at": self._utc_now_iso(),
            },
        )


# ---------------------------------------------------------------------------
# Convenience module-level functions
# ---------------------------------------------------------------------------

def extract_text_from_image(
    image: Any,
    *,
    user_id: Optional[Union[str, int]] = None,
    workspace_id: Optional[Union[str, int]] = None,
    task_id: Optional[str] = None,
    source_id: Optional[str] = None,
    source_type: str = "image",
    options: Optional[Union[OCREngineOptions, Mapping[str, Any]]] = None,
    context: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Convenience wrapper for OCR extraction without manually instantiating OCREngine.
    """

    engine = OCREngine()
    return engine.extract_text_from_image(
        image,
        user_id=user_id,
        workspace_id=workspace_id,
        task_id=task_id,
        source_id=source_id,
        source_type=source_type,
        options=options,
        context=context,
    )


def clean_ocr_text(
    text: str,
    *,
    options: Optional[Union[OCREngineOptions, Mapping[str, Any]]] = None,
) -> str:
    """
    Convenience wrapper for OCR text cleaning.
    """

    engine = OCREngine()
    return engine.clean_text(text, options=options)


__all__ = [
    "OCREngine",
    "OCREngineOptions",
    "OCRBackend",
    "OCRStatus",
    "ImageInputType",
    "OCRBox",
    "OCRLine",
    "extract_text_from_image",
    "clean_ocr_text",
]


"""
Where to place it:
    agents/visual_agent/ocr_engine.py

Required dependencies:
    Required for image loading:
        pip install pillow

    Optional OCR backend:
        pip install pytesseract

    Optional video-frame / OpenCV array support:
        pip install opencv-python numpy

    System dependency for OCR:
        Install Tesseract OCR binary and make sure it is available in PATH.

How to test it:
    1. Import and health check:
        python -c "from agents.visual_agent.ocr_engine import OCREngine; print(OCREngine().health_check())"

    2. Clean text only:
        python - <<'PY'
        from agents.visual_agent.ocr_engine import OCREngine
        engine = OCREngine()
        print(engine.clean_text("  Hello   world\\n\\n\\x0c Test  "))
        PY

    3. OCR image file:
        python - <<'PY'
        from agents.visual_agent.ocr_engine import OCREngine
        engine = OCREngine()
        result = engine.extract_text_from_image(
            "sample.png",
            user_id="user_1",
            workspace_id="workspace_1",
            task_id="task_ocr_1",
        )
        print(result["success"])
        print(result["data"].get("clean_text"))
        PY

    4. Non-user local test mode:
        python - <<'PY'
        from agents.visual_agent.ocr_engine import OCREngine
        engine = OCREngine()
        print(engine.extract_text_from_image(
            "sample.png",
            context={"non_user_context": True},
        ))
        PY

Agent/Module: Visual Agent
File Completed: ocr_engine.py
Completion: 22.2%
Completed Files: ['visual_agent.py', 'screenshot_reader.py', 'video_analyzer.py', 'ocr_engine.py']
Remaining Files: ['ui_mapper.py', 'image_analyzer.py', 'screen_context.py', 'element_detector.py', 'workflow_learner.py', 'visual_memory.py', 'error_screen_detector.py', 'form_reader.py', 'app_screen_mapper.py', 'video_frame_extractor.py', 'visual_validator.py', 'privacy_filter.py', 'annotation_tool.py', 'config.py']
Next Recommended File: agents/visual_agent/ui_mapper.py
FILE COMPLETE
"""