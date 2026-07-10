"""
agents/visual_agent/video_frame_extractor.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Extracts important frames, removes duplicates, detects screen changes.

This module belongs to the Visual Agent. It converts video/screen recordings into
important frame artifacts that downstream Visual Agent modules can use:
    - video_analyzer.py
    - screenshot_reader.py
    - screen_context.py
    - ui_mapper.py
    - element_detector.py
    - workflow_learner.py
    - proof_collector.py / Verification Agent

Architecture compatibility:
    - Safe to import even if future William modules do not exist yet.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent routing, Dashboard/API, Memory Agent, Security Agent, and
      Verification Agent payloads.
    - Enforces user_id/workspace_id/task_id SaaS isolation for user-specific work.
    - Does not execute destructive/system/browser/financial/message/call actions.
    - Uses optional dependencies safely:
        * cv2 / opencv-python for actual frame extraction
        * PIL / Pillow for image fallback/hash support
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import math
import os
import shutil
import traceback
import uuid
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------

try:
    import cv2  # type: ignore
except Exception:  # pragma: no cover
    cv2 = None  # type: ignore

try:
    from PIL import Image, ImageChops, ImageStat  # type: ignore
except Exception:  # pragma: no cover
    Image = None  # type: ignore
    ImageChops = None  # type: ignore
    ImageStat = None  # type: ignore


# ---------------------------------------------------------------------------
# Optional BaseAgent import with fallback
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        Keeps this file import-safe before the full William/Jarvis framework is
        generated.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() is not implemented.",
                "data": None,
                "error": "BASE_AGENT_FALLBACK_RUN_NOT_IMPLEMENTED",
                "metadata": {},
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("VideoFrameExtractor")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "video_frame_extractor"
DEFAULT_MODULE = "visual_agent"
SCHEMA_VERSION = "1.0.0"

DEFAULT_OUTPUT_DIR = "runtime/visual_agent/video_frames"
DEFAULT_MAX_FRAMES = 80
DEFAULT_SAMPLE_EVERY_SECONDS = 1.0
DEFAULT_MIN_CHANGE_SCORE = 0.08
DEFAULT_DUPLICATE_THRESHOLD = 0.035
DEFAULT_SCENE_CHANGE_THRESHOLD = 0.18
DEFAULT_MIN_SECONDS_BETWEEN_IMPORTANT_FRAMES = 0.40
DEFAULT_JPEG_QUALITY = 90
DEFAULT_RESIZE_WIDTH = 960
MAX_SAFE_VIDEO_BYTES = 1024 * 1024 * 1024 * 2  # 2GB
MAX_METADATA_DEPTH = 6
MAX_STRING_FIELD_LENGTH = 10_000
MAX_ERROR_TRACE_LENGTH = 8_000
MAX_EVENT_FRAMES = 500
SAFE_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
SAFE_VIDEO_EXTENSIONS = {
    ".mp4",
    ".mov",
    ".m4v",
    ".avi",
    ".mkv",
    ".webm",
    ".wmv",
    ".mpeg",
    ".mpg",
}


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FrameImportanceReason(str, Enum):
    """Reasons why a frame is considered important."""

    FIRST_FRAME = "first_frame"
    LAST_FRAME = "last_frame"
    SCREEN_CHANGE = "screen_change"
    MOTION_SPIKE = "motion_spike"
    ERROR_LIKE_CHANGE = "error_like_change"
    UI_LAYOUT_CHANGE = "ui_layout_change"
    PERIODIC_SAMPLE = "periodic_sample"
    MANUAL_SELECTED = "manual_selected"
    UNKNOWN = "unknown"


class FrameOutputFormat(str, Enum):
    """Supported frame output formats."""

    JPG = "jpg"
    PNG = "png"


class ExtractionMode(str, Enum):
    """Frame extraction modes."""

    BALANCED = "balanced"
    FAST = "fast"
    DETAILED = "detailed"
    SCREEN_RECORDING = "screen_recording"


class ChangeSeverity(str, Enum):
    """Human-readable screen change severity."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class VisualTaskContext:
    """
    SaaS-safe task context.

    user_id, workspace_id, and task_id are required for user-specific processing.
    """

    user_id: str
    workspace_id: str
    task_id: str
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    actor_id: Optional[str] = None
    source_agent: Optional[str] = None
    route: Optional[str] = None
    correlation_id: Optional[str] = None


@dataclass
class FrameExtractionConfig:
    """
    Configuration for video frame extraction.

    The defaults are optimized for screen recordings and browser/app workflow
    captures where the goal is to keep meaningful UI changes and remove duplicate
    frames.
    """

    mode: str = ExtractionMode.SCREEN_RECORDING.value
    output_dir: str = DEFAULT_OUTPUT_DIR
    output_format: str = FrameOutputFormat.JPG.value
    max_frames: int = DEFAULT_MAX_FRAMES
    sample_every_seconds: float = DEFAULT_SAMPLE_EVERY_SECONDS
    min_change_score: float = DEFAULT_MIN_CHANGE_SCORE
    duplicate_threshold: float = DEFAULT_DUPLICATE_THRESHOLD
    scene_change_threshold: float = DEFAULT_SCENE_CHANGE_THRESHOLD
    min_seconds_between_important_frames: float = DEFAULT_MIN_SECONDS_BETWEEN_IMPORTANT_FRAMES
    include_first_frame: bool = True
    include_last_frame: bool = True
    save_frames: bool = True
    return_frame_bytes: bool = False
    resize_width: Optional[int] = DEFAULT_RESIZE_WIDTH
    jpeg_quality: int = DEFAULT_JPEG_QUALITY
    generate_perceptual_hash: bool = True
    overwrite_output_dir: bool = False
    keep_duplicate_metadata: bool = True


@dataclass
class VideoMetadata:
    """Video file metadata used by dashboard/API and Verification Agent."""

    video_path: str
    file_name: str
    file_size_bytes: Optional[int]
    extension: str
    fps: Optional[float]
    frame_count: Optional[int]
    duration_seconds: Optional[float]
    width: Optional[int]
    height: Optional[int]
    readable: bool
    backend: str = "opencv"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExtractedFrame:
    """
    Important frame artifact.

    This record is safe to return in API/Dashboard responses.
    """

    frame_id: str
    index: int
    timestamp_seconds: float
    output_path: Optional[str]
    file_name: Optional[str]
    width: Optional[int]
    height: Optional[int]
    change_score: float
    duplicate_score: float
    scene_change_score: float
    importance_score: float
    importance_reasons: List[str]
    change_severity: str
    perceptual_hash: Optional[str] = None
    sha256: Optional[str] = None
    is_duplicate: bool = False
    duplicate_of_frame_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScreenChangeEvent:
    """Detected screen change event between two kept/observed frames."""

    event_id: str
    previous_frame_index: Optional[int]
    current_frame_index: int
    previous_timestamp_seconds: Optional[float]
    current_timestamp_seconds: float
    change_score: float
    severity: str
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class VideoFrameExtractor(BaseAgent):
    """
    Visual Agent helper for video frame extraction.

    Responsibilities:
        - Read video metadata safely.
        - Sample frames from screen recordings/videos.
        - Detect screen changes using lightweight visual difference scoring.
        - Remove duplicate frames using difference/hash comparison.
        - Save important frames to a user/workspace/task-scoped output directory.
        - Return structured dict/JSON-style results.
        - Prepare Verification Agent and Memory Agent payloads.

    Public methods:
        - extract_important_frames()
        - extract_from_payload()
        - get_video_metadata()
        - detect_screen_changes()
        - remove_duplicate_frames()
        - compare_images()
    """

    agent_type = DEFAULT_MODULE
    agent_name = DEFAULT_AGENT_NAME

    public_methods = (
        "extract_important_frames",
        "extract_from_payload",
        "get_video_metadata",
        "detect_screen_changes",
        "remove_duplicate_frames",
        "compare_images",
    )

    def __init__(
        self,
        *,
        agent_name: str = DEFAULT_AGENT_NAME,
        logger: Optional[logging.Logger] = None,
        strict_context: bool = True,
        default_config: Optional[Union[FrameExtractionConfig, Mapping[str, Any]]] = None,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(agent_name=agent_name, **kwargs)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.logger = logger or logging.getLogger(agent_name)
        self.strict_context = strict_context
        self.default_config = self._coerce_config(default_config or {})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract_important_frames(
        self,
        *,
        context: Union[VisualTaskContext, Mapping[str, Any]],
        video_path: Union[str, os.PathLike[str]],
        config: Optional[Union[FrameExtractionConfig, Mapping[str, Any]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        emit_events: bool = True,
    ) -> Dict[str, Any]:
        """
        Extract important frames from a video.

        Args:
            context:
                SaaS context with user_id, workspace_id, task_id.
            video_path:
                Local video path. This method does not download remote files.
            config:
                Optional extraction configuration.
            metadata:
                Extra safe metadata for dashboard/API.
            emit_events:
                Whether to emit agent/audit events.

        Returns:
            Structured result:
                {
                    success,
                    message,
                    data: {
                        video_metadata,
                        frames,
                        duplicate_frames,
                        screen_changes,
                        output_dir,
                        verification_payload,
                        memory_payload
                    },
                    error,
                    metadata
                }
        """

        try:
            parsed_context = self._coerce_context(context)
            context_result = self._validate_task_context(parsed_context)
            if not context_result["success"]:
                return context_result

            safe_config = self._merge_config(config)
            safe_metadata = self._sanitize_mapping(metadata or {})

            video_path_obj = self._validate_video_path(video_path)
            if isinstance(video_path_obj, dict):
                return video_path_obj

            security_required = self._requires_security_check(
                {
                    "operation": "extract_important_frames",
                    "video_path": str(video_path_obj),
                    "config": asdict(safe_config),
                    "metadata": safe_metadata,
                }
            )
            if security_required:
                security_result = self._request_security_approval(
                    context=parsed_context,
                    action="extract_important_frames",
                    payload={
                        "video_path": str(video_path_obj),
                        "config": asdict(safe_config),
                    },
                )
                return security_result

            video_metadata_result = self.get_video_metadata(
                context=parsed_context,
                video_path=video_path_obj,
                emit_events=False,
            )
            if not video_metadata_result["success"]:
                return video_metadata_result

            video_metadata = VideoMetadata(**video_metadata_result["data"]["video_metadata"])

            if cv2 is None:
                return self._error_result(
                    message="OpenCV is required to extract video frames but is not installed.",
                    error={
                        "code": "OPENCV_NOT_AVAILABLE",
                        "message": "Install opencv-python to enable video frame extraction.",
                    },
                    metadata={
                        "required_dependency": "opencv-python",
                        "video_path": str(video_path_obj),
                    },
                )

            output_dir = self._prepare_output_dir(
                context=parsed_context,
                base_output_dir=safe_config.output_dir,
                overwrite=safe_config.overwrite_output_dir,
            )

            extraction_result = self._extract_with_opencv(
                context=parsed_context,
                video_path=video_path_obj,
                video_metadata=video_metadata,
                config=safe_config,
                output_dir=output_dir,
            )

            if not extraction_result["success"]:
                return extraction_result

            frames: List[ExtractedFrame] = extraction_result["data"]["frames"]
            duplicate_frames: List[ExtractedFrame] = extraction_result["data"]["duplicate_frames"]
            screen_changes: List[ScreenChangeEvent] = extraction_result["data"]["screen_changes"]

            frame_dicts = [asdict(frame) for frame in frames]
            duplicate_dicts = [asdict(frame) for frame in duplicate_frames]
            change_dicts = [asdict(change) for change in screen_changes[:MAX_EVENT_FRAMES]]

            verification_payload = self._prepare_verification_payload(
                {
                    "context": asdict(parsed_context),
                    "video_metadata": asdict(video_metadata),
                    "frames": frame_dicts,
                    "duplicate_frames": duplicate_dicts,
                    "screen_changes": change_dicts,
                    "output_dir": str(output_dir),
                    "config": asdict(safe_config),
                }
            )

            memory_payload = self._prepare_memory_payload(
                context=parsed_context,
                video_metadata=video_metadata,
                frames=frames,
                duplicate_frames=duplicate_frames,
                screen_changes=screen_changes,
                output_dir=output_dir,
                metadata=safe_metadata,
            )

            if emit_events:
                self._emit_agent_event(
                    event_name="visual.video_frames.extracted",
                    payload={
                        "video_path": str(video_path_obj),
                        "output_dir": str(output_dir),
                        "kept_frame_count": len(frames),
                        "duplicate_frame_count": len(duplicate_frames),
                        "screen_change_count": len(screen_changes),
                    },
                    context=parsed_context,
                )
                self._log_audit_event(
                    action="video_frame_extraction_completed",
                    payload={
                        "video_path_hash": self._hash_text(str(video_path_obj)),
                        "output_dir": str(output_dir),
                        "kept_frame_count": len(frames),
                        "duplicate_frame_count": len(duplicate_frames),
                        "screen_change_count": len(screen_changes),
                    },
                    context=parsed_context,
                )

            return self._safe_result(
                success=True,
                message=(
                    f"Extracted {len(frames)} important frame(s), removed "
                    f"{len(duplicate_frames)} duplicate frame(s), and detected "
                    f"{len(screen_changes)} screen change event(s)."
                ),
                data={
                    "video_metadata": asdict(video_metadata),
                    "frames": frame_dicts,
                    "duplicate_frames": duplicate_dicts,
                    "screen_changes": change_dicts,
                    "output_dir": str(output_dir),
                    "config": asdict(safe_config),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "agent_name": self.agent_name,
                    "module": DEFAULT_MODULE,
                    "schema_version": SCHEMA_VERSION,
                    "kept_frame_count": len(frames),
                    "duplicate_frame_count": len(duplicate_frames),
                    "screen_change_count": len(screen_changes),
                    "opencv_available": cv2 is not None,
                    "pillow_available": Image is not None,
                    **safe_metadata,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to extract important video frames.",
                error=exc,
                metadata={
                    "operation": "extract_important_frames",
                    "agent_name": self.agent_name,
                },
            )

    def extract_from_payload(
        self,
        payload: Mapping[str, Any],
        *,
        emit_events: bool = True,
    ) -> Dict[str, Any]:
        """
        Extract frames using a single payload dict.

        Useful for Master Agent, Agent Router, API routes, queue workers, and
        dashboard jobs.
        """

        try:
            safe_payload = self._sanitize_mapping(payload)
            context = safe_payload.get("context") or {
                "user_id": safe_payload.get("user_id"),
                "workspace_id": safe_payload.get("workspace_id"),
                "task_id": safe_payload.get("task_id"),
                "request_id": safe_payload.get("request_id"),
                "session_id": safe_payload.get("session_id"),
                "source_agent": safe_payload.get("source_agent"),
            }

            video_path = safe_payload.get("video_path") or safe_payload.get("path")
            if not video_path:
                return self._safe_result(
                    success=False,
                    message="video_path is required.",
                    data=None,
                    error={
                        "code": "MISSING_VIDEO_PATH",
                        "message": "Payload must include video_path or path.",
                    },
                    metadata={"operation": "extract_from_payload"},
                )

            return self.extract_important_frames(
                context=context,
                video_path=str(video_path),
                config=safe_payload.get("config") or {},
                metadata=safe_payload.get("metadata") or {},
                emit_events=emit_events,
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to extract frames from payload.",
                error=exc,
                metadata={"operation": "extract_from_payload"},
            )

    def get_video_metadata(
        self,
        *,
        context: Union[VisualTaskContext, Mapping[str, Any]],
        video_path: Union[str, os.PathLike[str]],
        emit_events: bool = True,
    ) -> Dict[str, Any]:
        """
        Read safe video metadata.

        Does not extract frames.
        """

        try:
            parsed_context = self._coerce_context(context)
            context_result = self._validate_task_context(parsed_context)
            if not context_result["success"]:
                return context_result

            video_path_obj = self._validate_video_path(video_path)
            if isinstance(video_path_obj, dict):
                return video_path_obj

            file_size = video_path_obj.stat().st_size
            extension = video_path_obj.suffix.lower()

            metadata = VideoMetadata(
                video_path=str(video_path_obj),
                file_name=video_path_obj.name,
                file_size_bytes=file_size,
                extension=extension,
                fps=None,
                frame_count=None,
                duration_seconds=None,
                width=None,
                height=None,
                readable=False,
                backend="opencv" if cv2 is not None else "none",
                metadata={},
            )

            if cv2 is not None:
                capture = cv2.VideoCapture(str(video_path_obj))
                try:
                    readable = bool(capture.isOpened())
                    fps = float(capture.get(cv2.CAP_PROP_FPS) or 0.0)
                    frame_count = int(capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
                    width = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
                    height = int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)

                    duration = None
                    if fps and fps > 0 and frame_count > 0:
                        duration = frame_count / fps

                    metadata = VideoMetadata(
                        video_path=str(video_path_obj),
                        file_name=video_path_obj.name,
                        file_size_bytes=file_size,
                        extension=extension,
                        fps=fps if fps > 0 else None,
                        frame_count=frame_count if frame_count > 0 else None,
                        duration_seconds=duration,
                        width=width if width > 0 else None,
                        height=height if height > 0 else None,
                        readable=readable,
                        backend="opencv",
                        metadata={
                            "is_opened": readable,
                            "fourcc": int(capture.get(cv2.CAP_PROP_FOURCC) or 0),
                        },
                    )
                finally:
                    capture.release()

            if emit_events:
                self._emit_agent_event(
                    event_name="visual.video_metadata.read",
                    payload={
                        "video_path_hash": self._hash_text(str(video_path_obj)),
                        "file_name": video_path_obj.name,
                        "readable": metadata.readable,
                        "duration_seconds": metadata.duration_seconds,
                        "frame_count": metadata.frame_count,
                    },
                    context=parsed_context,
                )

            return self._safe_result(
                success=True,
                message="Video metadata read successfully.",
                data={"video_metadata": asdict(metadata)},
                metadata={
                    "agent_name": self.agent_name,
                    "module": DEFAULT_MODULE,
                    "opencv_available": cv2 is not None,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to read video metadata.",
                error=exc,
                metadata={"operation": "get_video_metadata"},
            )

    def detect_screen_changes(
        self,
        *,
        frames: Sequence[Union[ExtractedFrame, Mapping[str, Any]]],
        threshold: float = DEFAULT_SCENE_CHANGE_THRESHOLD,
    ) -> Dict[str, Any]:
        """
        Detect screen changes from already-extracted frame metadata.

        This method works on frame records, not raw video.
        """

        try:
            normalized_frames = [
                self._coerce_frame_record(frame)
                for frame in frames
            ]
            normalized_frames = [
                frame for frame in normalized_frames
                if frame is not None
            ]

            changes: List[ScreenChangeEvent] = []
            previous: Optional[ExtractedFrame] = None

            for frame in normalized_frames:
                if previous is None:
                    previous = frame
                    continue

                score = max(frame.change_score, frame.scene_change_score)
                if score >= threshold:
                    changes.append(
                        ScreenChangeEvent(
                            event_id=f"change_{uuid.uuid4().hex[:12]}",
                            previous_frame_index=previous.index,
                            current_frame_index=frame.index,
                            previous_timestamp_seconds=previous.timestamp_seconds,
                            current_timestamp_seconds=frame.timestamp_seconds,
                            change_score=self._clamp_float(score),
                            severity=self._change_severity(score),
                            reason=self._primary_reason(frame.importance_reasons),
                            metadata={
                                "previous_frame_id": previous.frame_id,
                                "current_frame_id": frame.frame_id,
                            },
                        )
                    )

                previous = frame

            return self._safe_result(
                success=True,
                message=f"Detected {len(changes)} screen change event(s).",
                data={
                    "screen_changes": [asdict(change) for change in changes],
                    "threshold": threshold,
                },
                metadata={"frame_count": len(normalized_frames)},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to detect screen changes.",
                error=exc,
                metadata={"operation": "detect_screen_changes"},
            )

    def remove_duplicate_frames(
        self,
        *,
        frames: Sequence[Union[ExtractedFrame, Mapping[str, Any]]],
        duplicate_threshold: float = DEFAULT_DUPLICATE_THRESHOLD,
    ) -> Dict[str, Any]:
        """
        Remove duplicate frames from extracted frame records using duplicate_score
        and perceptual_hash metadata when available.
        """

        try:
            normalized_frames = [
                self._coerce_frame_record(frame)
                for frame in frames
            ]
            normalized_frames = [
                frame for frame in normalized_frames
                if frame is not None
            ]

            kept: List[ExtractedFrame] = []
            duplicates: List[ExtractedFrame] = []
            seen_hashes: Dict[str, ExtractedFrame] = {}

            for frame in normalized_frames:
                duplicate_of: Optional[ExtractedFrame] = None

                if frame.perceptual_hash and frame.perceptual_hash in seen_hashes:
                    duplicate_of = seen_hashes[frame.perceptual_hash]
                elif frame.duplicate_score <= duplicate_threshold and kept:
                    duplicate_of = kept[-1]

                if duplicate_of:
                    dup = copy.deepcopy(frame)
                    dup.is_duplicate = True
                    dup.duplicate_of_frame_id = duplicate_of.frame_id
                    duplicates.append(dup)
                    continue

                kept.append(frame)
                if frame.perceptual_hash:
                    seen_hashes[frame.perceptual_hash] = frame

            return self._safe_result(
                success=True,
                message=f"Kept {len(kept)} frame(s) and removed {len(duplicates)} duplicate frame(s).",
                data={
                    "frames": [asdict(frame) for frame in kept],
                    "duplicate_frames": [asdict(frame) for frame in duplicates],
                },
                metadata={
                    "input_frame_count": len(normalized_frames),
                    "duplicate_threshold": duplicate_threshold,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to remove duplicate frames.",
                error=exc,
                metadata={"operation": "remove_duplicate_frames"},
            )

    def compare_images(
        self,
        image_a_path: Union[str, os.PathLike[str]],
        image_b_path: Union[str, os.PathLike[str]],
    ) -> Dict[str, Any]:
        """
        Compare two image files and return a normalized visual difference score.

        Score range:
            0.0 = nearly identical
            1.0 = very different
        """

        try:
            path_a = Path(image_a_path).expanduser().resolve()
            path_b = Path(image_b_path).expanduser().resolve()

            if not path_a.exists() or not path_b.exists():
                return self._safe_result(
                    success=False,
                    message="Both image paths must exist.",
                    data=None,
                    error={
                        "code": "IMAGE_PATH_NOT_FOUND",
                        "image_a_exists": path_a.exists(),
                        "image_b_exists": path_b.exists(),
                    },
                    metadata={},
                )

            if Image is None:
                return self._safe_result(
                    success=False,
                    message="Pillow is required for image comparison.",
                    data=None,
                    error={
                        "code": "PILLOW_NOT_AVAILABLE",
                        "message": "Install Pillow to enable image comparison.",
                    },
                    metadata={},
                )

            score = self._compare_image_files_with_pillow(path_a, path_b)

            return self._safe_result(
                success=True,
                message="Images compared successfully.",
                data={
                    "difference_score": score,
                    "severity": self._change_severity(score),
                    "image_a": str(path_a),
                    "image_b": str(path_b),
                },
                metadata={},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to compare images.",
                error=exc,
                metadata={"operation": "compare_images"},
            )

    async def run(self, payload: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        """
        Async-compatible BaseAgent entry point for Master Agent / Router.
        """

        final_payload: Dict[str, Any] = {}
        if payload:
            final_payload.update(dict(payload))
        if kwargs:
            final_payload.update(kwargs)

        return self.extract_from_payload(final_payload)

    # ------------------------------------------------------------------
    # Core extraction implementation
    # ------------------------------------------------------------------

    def _extract_with_opencv(
        self,
        *,
        context: VisualTaskContext,
        video_path: Path,
        video_metadata: VideoMetadata,
        config: FrameExtractionConfig,
        output_dir: Path,
    ) -> Dict[str, Any]:
        """
        Actual OpenCV-based extraction.
        """

        if cv2 is None:
            return self._error_result(
                message="OpenCV is not available.",
                error={"code": "OPENCV_NOT_AVAILABLE"},
                metadata={},
            )

        capture = cv2.VideoCapture(str(video_path))
        if not capture.isOpened():
            return self._safe_result(
                success=False,
                message="Video could not be opened.",
                data=None,
                error={
                    "code": "VIDEO_NOT_READABLE",
                    "message": "OpenCV could not open this video file.",
                    "video_path": str(video_path),
                },
                metadata={},
            )

        try:
            fps = video_metadata.fps or float(capture.get(cv2.CAP_PROP_FPS) or 0.0)
            if not fps or fps <= 0:
                fps = 25.0

            frame_count = video_metadata.frame_count or int(capture.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
            duration = video_metadata.duration_seconds
            if duration is None and frame_count > 0:
                duration = frame_count / fps

            sampling_interval_frames = max(1, int(round(fps * max(0.05, config.sample_every_seconds))))

            if config.mode == ExtractionMode.FAST.value:
                sampling_interval_frames = max(sampling_interval_frames, int(round(fps * 2.0)))
            elif config.mode == ExtractionMode.DETAILED.value:
                sampling_interval_frames = max(1, int(round(fps * 0.5)))
            elif config.mode == ExtractionMode.SCREEN_RECORDING.value:
                sampling_interval_frames = max(1, int(round(fps * config.sample_every_seconds)))

            kept_frames: List[ExtractedFrame] = []
            duplicate_frames: List[ExtractedFrame] = []
            screen_changes: List[ScreenChangeEvent] = []

            previous_sample_gray: Optional[Any] = None
            previous_kept_gray: Optional[Any] = None
            previous_kept_frame: Optional[ExtractedFrame] = None
            last_kept_timestamp = -999999.0

            sample_indices = self._build_sample_indices(
                frame_count=frame_count,
                interval=sampling_interval_frames,
                include_first=config.include_first_frame,
                include_last=config.include_last_frame,
            )

            for frame_index in sample_indices:
                if len(kept_frames) >= config.max_frames:
                    break

                capture.set(cv2.CAP_PROP_POS_FRAMES, frame_index)
                ok, frame = capture.read()
                if not ok or frame is None:
                    continue

                timestamp_seconds = float(frame_index / fps)

                processed_frame = self._resize_frame_if_needed(
                    frame=frame,
                    resize_width=config.resize_width,
                )

                gray = cv2.cvtColor(processed_frame, cv2.COLOR_BGR2GRAY)

                change_score = (
                    self._frame_difference_score(previous_sample_gray, gray)
                    if previous_sample_gray is not None
                    else 1.0
                )
                duplicate_score = (
                    self._frame_difference_score(previous_kept_gray, gray)
                    if previous_kept_gray is not None
                    else 1.0
                )
                scene_change_score = change_score

                reasons: List[str] = []

                if frame_index == 0 and config.include_first_frame:
                    reasons.append(FrameImportanceReason.FIRST_FRAME.value)

                if frame_count and frame_index >= max(0, frame_count - 2) and config.include_last_frame:
                    reasons.append(FrameImportanceReason.LAST_FRAME.value)

                if change_score >= config.scene_change_threshold:
                    reasons.append(FrameImportanceReason.SCREEN_CHANGE.value)

                if change_score >= max(config.scene_change_threshold * 1.5, 0.28):
                    reasons.append(FrameImportanceReason.MOTION_SPIKE.value)

                if self._looks_like_ui_layout_change(change_score, duplicate_score):
                    reasons.append(FrameImportanceReason.UI_LAYOUT_CHANGE.value)

                if not reasons and change_score >= config.min_change_score:
                    reasons.append(FrameImportanceReason.PERIODIC_SAMPLE.value)

                enough_time_since_last = (
                    timestamp_seconds - last_kept_timestamp
                    >= config.min_seconds_between_important_frames
                )

                is_duplicate = duplicate_score <= config.duplicate_threshold

                should_keep = bool(reasons) and enough_time_since_last and not is_duplicate

                if not kept_frames and config.include_first_frame:
                    should_keep = True
                    is_duplicate = False
                    if FrameImportanceReason.FIRST_FRAME.value not in reasons:
                        reasons.insert(0, FrameImportanceReason.FIRST_FRAME.value)

                if should_keep:
                    frame_record = self._create_frame_record(
                        context=context,
                        frame=processed_frame,
                        frame_index=frame_index,
                        timestamp_seconds=timestamp_seconds,
                        output_dir=output_dir,
                        config=config,
                        change_score=change_score,
                        duplicate_score=duplicate_score,
                        scene_change_score=scene_change_score,
                        reasons=reasons,
                        is_duplicate=False,
                        duplicate_of_frame_id=None,
                    )

                    if previous_kept_frame and scene_change_score >= config.scene_change_threshold:
                        screen_changes.append(
                            ScreenChangeEvent(
                                event_id=f"change_{uuid.uuid4().hex[:12]}",
                                previous_frame_index=previous_kept_frame.index,
                                current_frame_index=frame_record.index,
                                previous_timestamp_seconds=previous_kept_frame.timestamp_seconds,
                                current_timestamp_seconds=frame_record.timestamp_seconds,
                                change_score=self._clamp_float(scene_change_score),
                                severity=self._change_severity(scene_change_score),
                                reason=self._primary_reason(reasons),
                                metadata={
                                    "previous_frame_id": previous_kept_frame.frame_id,
                                    "current_frame_id": frame_record.frame_id,
                                },
                            )
                        )

                    kept_frames.append(frame_record)
                    previous_kept_gray = gray
                    previous_kept_frame = frame_record
                    last_kept_timestamp = timestamp_seconds

                elif is_duplicate and previous_kept_frame and config.keep_duplicate_metadata:
                    duplicate_record = ExtractedFrame(
                        frame_id=f"frame_{uuid.uuid4().hex[:12]}",
                        index=frame_index,
                        timestamp_seconds=timestamp_seconds,
                        output_path=None,
                        file_name=None,
                        width=int(processed_frame.shape[1]),
                        height=int(processed_frame.shape[0]),
                        change_score=self._clamp_float(change_score),
                        duplicate_score=self._clamp_float(duplicate_score),
                        scene_change_score=self._clamp_float(scene_change_score),
                        importance_score=self._importance_score(
                            change_score=change_score,
                            duplicate_score=duplicate_score,
                            reasons=[FrameImportanceReason.UNKNOWN.value],
                        ),
                        importance_reasons=[FrameImportanceReason.UNKNOWN.value],
                        change_severity=self._change_severity(scene_change_score),
                        perceptual_hash=None,
                        sha256=None,
                        is_duplicate=True,
                        duplicate_of_frame_id=previous_kept_frame.frame_id,
                        metadata={
                            "duplicate_reason": "visual_difference_below_threshold",
                            "threshold": config.duplicate_threshold,
                        },
                    )
                    duplicate_frames.append(duplicate_record)

                previous_sample_gray = gray

            return self._safe_result(
                success=True,
                message="OpenCV extraction completed.",
                data={
                    "frames": kept_frames,
                    "duplicate_frames": duplicate_frames,
                    "screen_changes": screen_changes,
                },
                metadata={
                    "sampled_frame_count": len(sample_indices),
                    "fps": fps,
                    "sampling_interval_frames": sampling_interval_frames,
                    "max_frames": config.max_frames,
                },
            )

        finally:
            capture.release()

    def _create_frame_record(
        self,
        *,
        context: VisualTaskContext,
        frame: Any,
        frame_index: int,
        timestamp_seconds: float,
        output_dir: Path,
        config: FrameExtractionConfig,
        change_score: float,
        duplicate_score: float,
        scene_change_score: float,
        reasons: List[str],
        is_duplicate: bool,
        duplicate_of_frame_id: Optional[str],
    ) -> ExtractedFrame:
        """
        Save a frame if configured and build an ExtractedFrame record.
        """

        frame_id = f"frame_{uuid.uuid4().hex[:12]}"
        extension = ".jpg" if config.output_format == FrameOutputFormat.JPG.value else ".png"
        file_name = f"{context.task_id}_{frame_index:08d}_{int(timestamp_seconds * 1000):012d}ms{extension}"
        output_path = output_dir / file_name

        saved_path: Optional[str] = None
        sha256_value: Optional[str] = None
        phash_value: Optional[str] = None

        if config.save_frames:
            self._write_frame(output_path=output_path, frame=frame, config=config)
            saved_path = str(output_path)
            sha256_value = self._sha256_file(output_path)

            if config.generate_perceptual_hash:
                phash_value = self._perceptual_hash(output_path)

        importance = self._importance_score(
            change_score=change_score,
            duplicate_score=duplicate_score,
            reasons=reasons,
        )

        return ExtractedFrame(
            frame_id=frame_id,
            index=int(frame_index),
            timestamp_seconds=float(timestamp_seconds),
            output_path=saved_path,
            file_name=file_name if saved_path else None,
            width=int(frame.shape[1]) if hasattr(frame, "shape") else None,
            height=int(frame.shape[0]) if hasattr(frame, "shape") else None,
            change_score=self._clamp_float(change_score),
            duplicate_score=self._clamp_float(duplicate_score),
            scene_change_score=self._clamp_float(scene_change_score),
            importance_score=importance,
            importance_reasons=list(dict.fromkeys(reasons or [FrameImportanceReason.UNKNOWN.value])),
            change_severity=self._change_severity(scene_change_score),
            perceptual_hash=phash_value,
            sha256=sha256_value,
            is_duplicate=is_duplicate,
            duplicate_of_frame_id=duplicate_of_frame_id,
            metadata={
                "saved": bool(saved_path),
                "output_format": config.output_format,
                "source": self.agent_name,
            },
        )

    # ------------------------------------------------------------------
    # Frame and image helpers
    # ------------------------------------------------------------------

    def _build_sample_indices(
        self,
        *,
        frame_count: int,
        interval: int,
        include_first: bool,
        include_last: bool,
    ) -> List[int]:
        if frame_count <= 0:
            return [0]

        indices = set(range(0, frame_count, max(1, interval)))

        if include_first:
            indices.add(0)

        if include_last:
            indices.add(max(0, frame_count - 1))

        return sorted(index for index in indices if 0 <= index < frame_count)

    def _resize_frame_if_needed(self, *, frame: Any, resize_width: Optional[int]) -> Any:
        if cv2 is None or resize_width is None or resize_width <= 0:
            return frame

        height, width = frame.shape[:2]
        if width <= resize_width:
            return frame

        ratio = resize_width / float(width)
        new_height = max(1, int(height * ratio))
        return cv2.resize(frame, (resize_width, new_height), interpolation=cv2.INTER_AREA)

    def _frame_difference_score(self, previous_gray: Any, current_gray: Any) -> float:
        """
        Return normalized visual difference between two grayscale frames.

        0.0 = identical
        1.0 = very different
        """

        if cv2 is None:
            return 1.0

        if previous_gray is None or current_gray is None:
            return 1.0

        if previous_gray.shape != current_gray.shape:
            current_gray = cv2.resize(
                current_gray,
                (previous_gray.shape[1], previous_gray.shape[0]),
                interpolation=cv2.INTER_AREA,
            )

        diff = cv2.absdiff(previous_gray, current_gray)
        mean_diff = float(diff.mean()) / 255.0

        # Add edge/structure sensitivity for UI changes.
        prev_edges = cv2.Canny(previous_gray, 80, 160)
        curr_edges = cv2.Canny(current_gray, 80, 160)
        edge_diff = float(cv2.absdiff(prev_edges, curr_edges).mean()) / 255.0

        score = (mean_diff * 0.70) + (edge_diff * 0.30)
        return self._clamp_float(score)

    def _looks_like_ui_layout_change(self, change_score: float, duplicate_score: float) -> bool:
        return change_score >= 0.10 and duplicate_score >= 0.08

    def _importance_score(
        self,
        *,
        change_score: float,
        duplicate_score: float,
        reasons: Sequence[str],
    ) -> float:
        reason_bonus = min(0.30, len(set(reasons)) * 0.06)
        duplicate_bonus = min(0.20, duplicate_score * 0.25)
        score = (change_score * 0.65) + duplicate_bonus + reason_bonus

        if FrameImportanceReason.FIRST_FRAME.value in reasons:
            score = max(score, 0.80)
        if FrameImportanceReason.LAST_FRAME.value in reasons:
            score = max(score, 0.70)
        if FrameImportanceReason.SCREEN_CHANGE.value in reasons:
            score = max(score, 0.75)

        return self._clamp_float(score)

    def _write_frame(
        self,
        *,
        output_path: Path,
        frame: Any,
        config: FrameExtractionConfig,
    ) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if cv2 is None:
            raise RuntimeError("OpenCV is required to write extracted video frames.")

        if config.output_format == FrameOutputFormat.PNG.value:
            cv2.imwrite(str(output_path), frame, [cv2.IMWRITE_PNG_COMPRESSION, 3])
        else:
            quality = max(40, min(100, int(config.jpeg_quality)))
            cv2.imwrite(str(output_path), frame, [cv2.IMWRITE_JPEG_QUALITY, quality])

    def _compare_image_files_with_pillow(self, path_a: Path, path_b: Path) -> float:
        if Image is None or ImageChops is None or ImageStat is None:
            return 1.0

        with Image.open(path_a) as img_a_raw, Image.open(path_b) as img_b_raw:
            img_a = img_a_raw.convert("RGB").resize((256, 256))
            img_b = img_b_raw.convert("RGB").resize((256, 256))

            diff = ImageChops.difference(img_a, img_b)
            stat = ImageStat.Stat(diff)
            rms = math.sqrt(sum(value ** 2 for value in stat.rms) / len(stat.rms))
            return self._clamp_float(rms / 255.0)

    def _perceptual_hash(self, image_path: Path) -> Optional[str]:
        """
        Lightweight average hash.

        This avoids requiring imagehash while still giving duplicate detection a
        stable image fingerprint.
        """

        if Image is None:
            return None

        try:
            with Image.open(image_path) as image:
                image = image.convert("L").resize((8, 8))
                pixels = list(image.getdata())
                avg = sum(pixels) / len(pixels)
                bits = "".join("1" if pixel >= avg else "0" for pixel in pixels)
                return f"{int(bits, 2):016x}"
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Validation and config
    # ------------------------------------------------------------------

    def _validate_video_path(
        self,
        video_path: Union[str, os.PathLike[str]],
    ) -> Union[Path, Dict[str, Any]]:
        try:
            path = Path(video_path).expanduser().resolve()

            if not path.exists():
                return self._safe_result(
                    success=False,
                    message="Video file does not exist.",
                    data=None,
                    error={
                        "code": "VIDEO_NOT_FOUND",
                        "video_path": str(path),
                    },
                    metadata={},
                )

            if not path.is_file():
                return self._safe_result(
                    success=False,
                    message="Video path must be a file.",
                    data=None,
                    error={
                        "code": "VIDEO_PATH_NOT_FILE",
                        "video_path": str(path),
                    },
                    metadata={},
                )

            extension = path.suffix.lower()
            if extension not in SAFE_VIDEO_EXTENSIONS:
                return self._safe_result(
                    success=False,
                    message="Unsupported video file extension.",
                    data=None,
                    error={
                        "code": "UNSUPPORTED_VIDEO_EXTENSION",
                        "extension": extension,
                        "supported_extensions": sorted(SAFE_VIDEO_EXTENSIONS),
                    },
                    metadata={},
                )

            file_size = path.stat().st_size
            if file_size > MAX_SAFE_VIDEO_BYTES:
                return self._safe_result(
                    success=False,
                    message="Video file is larger than the configured safe limit.",
                    data=None,
                    error={
                        "code": "VIDEO_TOO_LARGE",
                        "file_size_bytes": file_size,
                        "max_safe_video_bytes": MAX_SAFE_VIDEO_BYTES,
                    },
                    metadata={},
                )

            return path

        except Exception as exc:
            return self._error_result(
                message="Failed to validate video path.",
                error=exc,
                metadata={"operation": "_validate_video_path"},
            )

    def _prepare_output_dir(
        self,
        *,
        context: VisualTaskContext,
        base_output_dir: str,
        overwrite: bool,
    ) -> Path:
        safe_user = self._safe_path_part(context.user_id)
        safe_workspace = self._safe_path_part(context.workspace_id)
        safe_task = self._safe_path_part(context.task_id)

        output_dir = (
            Path(base_output_dir)
            .expanduser()
            .resolve()
            / safe_user
            / safe_workspace
            / safe_task
        )

        if overwrite and output_dir.exists():
            shutil.rmtree(output_dir)

        output_dir.mkdir(parents=True, exist_ok=True)
        return output_dir

    def _merge_config(
        self,
        config: Optional[Union[FrameExtractionConfig, Mapping[str, Any]]],
    ) -> FrameExtractionConfig:
        base = asdict(self.default_config)
        incoming = asdict(config) if isinstance(config, FrameExtractionConfig) else dict(config or {})
        base.update(incoming)
        return self._coerce_config(base)

    def _coerce_config(
        self,
        config: Union[FrameExtractionConfig, Mapping[str, Any]],
    ) -> FrameExtractionConfig:
        if isinstance(config, FrameExtractionConfig):
            raw = asdict(config)
        else:
            raw = dict(config or {})

        mode = str(raw.get("mode") or ExtractionMode.SCREEN_RECORDING.value).lower()
        if mode not in {item.value for item in ExtractionMode}:
            mode = ExtractionMode.SCREEN_RECORDING.value

        output_format = str(raw.get("output_format") or FrameOutputFormat.JPG.value).lower().replace(".", "")
        if output_format not in {item.value for item in FrameOutputFormat}:
            output_format = FrameOutputFormat.JPG.value

        return FrameExtractionConfig(
            mode=mode,
            output_dir=str(raw.get("output_dir") or DEFAULT_OUTPUT_DIR),
            output_format=output_format,
            max_frames=max(1, min(500, int(raw.get("max_frames", DEFAULT_MAX_FRAMES)))),
            sample_every_seconds=max(0.05, float(raw.get("sample_every_seconds", DEFAULT_SAMPLE_EVERY_SECONDS))),
            min_change_score=self._clamp_float(raw.get("min_change_score", DEFAULT_MIN_CHANGE_SCORE)),
            duplicate_threshold=self._clamp_float(raw.get("duplicate_threshold", DEFAULT_DUPLICATE_THRESHOLD)),
            scene_change_threshold=self._clamp_float(raw.get("scene_change_threshold", DEFAULT_SCENE_CHANGE_THRESHOLD)),
            min_seconds_between_important_frames=max(
                0.0,
                float(
                    raw.get(
                        "min_seconds_between_important_frames",
                        DEFAULT_MIN_SECONDS_BETWEEN_IMPORTANT_FRAMES,
                    )
                ),
            ),
            include_first_frame=bool(raw.get("include_first_frame", True)),
            include_last_frame=bool(raw.get("include_last_frame", True)),
            save_frames=bool(raw.get("save_frames", True)),
            return_frame_bytes=bool(raw.get("return_frame_bytes", False)),
            resize_width=(
                None
                if raw.get("resize_width") in (None, "", 0, "0")
                else max(240, min(3840, int(raw.get("resize_width", DEFAULT_RESIZE_WIDTH))))
            ),
            jpeg_quality=max(40, min(100, int(raw.get("jpeg_quality", DEFAULT_JPEG_QUALITY)))),
            generate_perceptual_hash=bool(raw.get("generate_perceptual_hash", True)),
            overwrite_output_dir=bool(raw.get("overwrite_output_dir", False)),
            keep_duplicate_metadata=bool(raw.get("keep_duplicate_metadata", True)),
        )

    def _coerce_context(
        self,
        context: Union[VisualTaskContext, Mapping[str, Any]],
    ) -> VisualTaskContext:
        if isinstance(context, VisualTaskContext):
            return context

        if not isinstance(context, Mapping):
            raise ValueError("context must be VisualTaskContext or mapping.")

        return VisualTaskContext(
            user_id=str(context.get("user_id") or "").strip(),
            workspace_id=str(context.get("workspace_id") or "").strip(),
            task_id=str(context.get("task_id") or context.get("id") or "").strip(),
            request_id=self._optional_str(context.get("request_id")),
            session_id=self._optional_str(context.get("session_id")),
            actor_id=self._optional_str(context.get("actor_id")),
            source_agent=self._optional_str(context.get("source_agent")),
            route=self._optional_str(context.get("route")),
            correlation_id=self._optional_str(context.get("correlation_id")),
        )

    def _coerce_frame_record(
        self,
        frame: Union[ExtractedFrame, Mapping[str, Any]],
    ) -> Optional[ExtractedFrame]:
        try:
            if isinstance(frame, ExtractedFrame):
                return frame

            if not isinstance(frame, Mapping):
                return None

            return ExtractedFrame(
                frame_id=str(frame.get("frame_id") or frame.get("id") or f"frame_{uuid.uuid4().hex[:12]}"),
                index=int(frame.get("index") or 0),
                timestamp_seconds=float(frame.get("timestamp_seconds") or 0.0),
                output_path=self._optional_str(frame.get("output_path")),
                file_name=self._optional_str(frame.get("file_name")),
                width=self._optional_int(frame.get("width")),
                height=self._optional_int(frame.get("height")),
                change_score=self._clamp_float(frame.get("change_score", 0.0)),
                duplicate_score=self._clamp_float(frame.get("duplicate_score", 1.0)),
                scene_change_score=self._clamp_float(frame.get("scene_change_score", frame.get("change_score", 0.0))),
                importance_score=self._clamp_float(frame.get("importance_score", 0.0)),
                importance_reasons=[
                    str(reason)
                    for reason in frame.get("importance_reasons", [])
                    if reason is not None
                ] or [FrameImportanceReason.UNKNOWN.value],
                change_severity=str(frame.get("change_severity") or ChangeSeverity.NONE.value),
                perceptual_hash=self._optional_str(frame.get("perceptual_hash")),
                sha256=self._optional_str(frame.get("sha256")),
                is_duplicate=bool(frame.get("is_duplicate", False)),
                duplicate_of_frame_id=self._optional_str(frame.get("duplicate_of_frame_id")),
                metadata=self._sanitize_mapping(frame.get("metadata") or {}),
            )
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[VisualTaskContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace/task isolation.

        Every user-specific visual processing task must keep records scoped by:
            - user_id
            - workspace_id
            - task_id
        """

        try:
            parsed = self._coerce_context(context)

            missing: List[str] = []
            for field_name in ("user_id", "workspace_id", "task_id"):
                value = getattr(parsed, field_name)
                if not isinstance(value, str) or not value.strip():
                    missing.append(field_name)

            if missing:
                return self._safe_result(
                    success=False,
                    message="Visual task context is missing required SaaS isolation fields.",
                    data=None,
                    error={
                        "code": "INVALID_TASK_CONTEXT",
                        "missing_fields": missing,
                    },
                    metadata={
                        "required_fields": ["user_id", "workspace_id", "task_id"],
                        "strict_context": self.strict_context,
                    },
                )

            unsafe_fields = []
            for field_name in ("user_id", "workspace_id", "task_id"):
                if not self._is_safe_identifier(getattr(parsed, field_name)):
                    unsafe_fields.append(field_name)

            if unsafe_fields:
                return self._safe_result(
                    success=False,
                    message="Visual task context contains unsafe identifier values.",
                    data=None,
                    error={
                        "code": "UNSAFE_CONTEXT_IDENTIFIER",
                        "fields": unsafe_fields,
                    },
                    metadata={},
                )

            return self._safe_result(
                success=True,
                message="Visual task context is valid.",
                data={"context": asdict(parsed)},
                metadata={},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to validate visual task context.",
                error=exc,
                metadata={"operation": "_validate_task_context"},
            )

    def _requires_security_check(self, payload: Mapping[str, Any]) -> bool:
        """
        Determine whether Security Agent approval is required.

        Frame extraction from a local video is normally non-destructive. Approval
        is required only if caller explicitly marks the operation sensitive or
        attempts unsafe paths.
        """

        try:
            safe_payload = self._sanitize_mapping(payload)

            if bool(safe_payload.get("requires_security_check")):
                return True

            metadata = safe_payload.get("metadata") or {}
            if isinstance(metadata, Mapping):
                if bool(metadata.get("requires_security_check")):
                    return True
                if bool(metadata.get("sensitive_action_detected")):
                    return True

            path_text = str(safe_payload.get("video_path") or "").lower()
            unsafe_path_fragments = [
                "/etc/",
                "\\windows\\system32",
                "/root/",
                "/var/lib/",
                ".ssh",
                "id_rsa",
                "credentials",
                "secrets",
                "tokens",
            ]

            if any(fragment in path_text for fragment in unsafe_path_fragments):
                return True

            return False

        except Exception:
            return True

    def _request_security_approval(
        self,
        *,
        context: Union[VisualTaskContext, Mapping[str, Any]],
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Security Agent approval hook.

        This file does not directly call the Security Agent because it must remain
        import-safe. The returned payload can be routed to Security Agent later.
        """

        try:
            parsed_context = self._coerce_context(context)
            request_id = str(uuid.uuid4())

            approval_payload = {
                "request_id": request_id,
                "action": action,
                "context": asdict(parsed_context),
                "payload": self._sanitize_mapping(payload or {}),
                "requested_by": self.agent_name,
                "status": "approval_required",
                "created_at": self.utcnow_iso(),
                "security_agent_route": "security_agent.approval.request",
            }

            return self._safe_result(
                success=False,
                message="Security approval is required before this visual extraction can continue.",
                data=approval_payload,
                error={
                    "code": "SECURITY_APPROVAL_REQUIRED",
                    "request_id": request_id,
                },
                metadata={
                    "agent_name": self.agent_name,
                    "module": DEFAULT_MODULE,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to prepare security approval request.",
                error=exc,
                metadata={"operation": "_request_security_approval"},
            )

    def _prepare_verification_payload(self, extraction_data: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Prepare Verification Agent-compatible payload.

        Verification Agent can use this to prove that a screen recording was
        processed and important evidence frames were produced.
        """

        safe_data = self._sanitize_mapping(extraction_data)

        frames = safe_data.get("frames") or []
        duplicates = safe_data.get("duplicate_frames") or []
        changes = safe_data.get("screen_changes") or []
        video_metadata = safe_data.get("video_metadata") or {}

        success = bool(frames)

        return {
            "type": "visual_video_frame_extraction",
            "schema_version": SCHEMA_VERSION,
            "success": success,
            "status": "passed" if success else "review",
            "message": (
                f"Extracted {len(frames)} important frame(s), removed "
                f"{len(duplicates)} duplicate(s), detected {len(changes)} change event(s)."
            ),
            "confidence": self._calculate_extraction_confidence(
                frame_count=len(frames),
                duplicate_count=len(duplicates),
                screen_change_count=len(changes),
                video_metadata=video_metadata,
            ),
            "proof": [
                {
                    "proof_type": "video_frame",
                    "title": frame.get("file_name") or frame.get("frame_id"),
                    "path": frame.get("output_path"),
                    "timestamp_seconds": frame.get("timestamp_seconds"),
                    "sha256": frame.get("sha256"),
                    "confidence": frame.get("importance_score"),
                    "metadata": {
                        "change_score": frame.get("change_score"),
                        "importance_reasons": frame.get("importance_reasons"),
                        "change_severity": frame.get("change_severity"),
                    },
                }
                for frame in frames
            ],
            "data": {
                "video_metadata": video_metadata,
                "output_dir": safe_data.get("output_dir"),
                "frame_count": len(frames),
                "duplicate_frame_count": len(duplicates),
                "screen_change_count": len(changes),
            },
            "metadata": {
                "agent_name": self.agent_name,
                "module": DEFAULT_MODULE,
                "created_at": self.utcnow_iso(),
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        context: VisualTaskContext,
        video_metadata: VideoMetadata,
        frames: Sequence[ExtractedFrame],
        duplicate_frames: Sequence[ExtractedFrame],
        screen_changes: Sequence[ScreenChangeEvent],
        output_dir: Path,
        metadata: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Keeps user/workspace/task isolation explicit so future Memory Agent code
        does not mix data between SaaS users/workspaces.
        """

        return {
            "memory_type": "visual_video_frame_extraction",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "source_agent": self.agent_name,
            "summary": (
                f"Video frame extraction produced {len(frames)} important frame(s), "
                f"{len(duplicate_frames)} duplicate record(s), and "
                f"{len(screen_changes)} screen change event(s)."
            ),
            "video": {
                "file_name": video_metadata.file_name,
                "extension": video_metadata.extension,
                "duration_seconds": video_metadata.duration_seconds,
                "frame_count": video_metadata.frame_count,
                "width": video_metadata.width,
                "height": video_metadata.height,
            },
            "frame_artifacts": [
                {
                    "frame_id": frame.frame_id,
                    "timestamp_seconds": frame.timestamp_seconds,
                    "output_path": frame.output_path,
                    "importance_score": frame.importance_score,
                    "importance_reasons": frame.importance_reasons,
                    "sha256": frame.sha256,
                }
                for frame in frames
            ],
            "screen_changes": [
                {
                    "event_id": event.event_id,
                    "timestamp_seconds": event.current_timestamp_seconds,
                    "severity": event.severity,
                    "change_score": event.change_score,
                    "reason": event.reason,
                }
                for event in screen_changes[:MAX_EVENT_FRAMES]
            ],
            "output_dir": str(output_dir),
            "metadata": self._sanitize_mapping(metadata),
            "created_at": self.utcnow_iso(),
            "privacy_scope": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "isolation_required": True,
            },
        }

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        payload: Mapping[str, Any],
        context: Union[VisualTaskContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Event hook for Agent Registry, Dashboard streams, task history, or
        workflow engine. It does not require external services.
        """

        try:
            parsed_context = self._coerce_context(context)
            event = {
                "event_id": str(uuid.uuid4()),
                "event_name": event_name,
                "agent_name": self.agent_name,
                "module": DEFAULT_MODULE,
                "context": asdict(parsed_context),
                "payload": self._sanitize_mapping(payload),
                "created_at": self.utcnow_iso(),
            }

            self.logger.info(
                "Agent event emitted: %s user=%s workspace=%s task=%s",
                event_name,
                parsed_context.user_id,
                parsed_context.workspace_id,
                parsed_context.task_id,
            )

            return self._safe_result(
                success=True,
                message="Agent event emitted.",
                data=event,
                metadata={},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to emit agent event.",
                error=exc,
                metadata={"operation": "_emit_agent_event"},
            )

    def _log_audit_event(
        self,
        *,
        action: str,
        payload: Mapping[str, Any],
        context: Union[VisualTaskContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Audit hook for SaaS task history and compliance logs.
        """

        try:
            parsed_context = self._coerce_context(context)

            audit_event = {
                "audit_id": str(uuid.uuid4()),
                "action": action,
                "agent_name": self.agent_name,
                "module": DEFAULT_MODULE,
                "user_id": parsed_context.user_id,
                "workspace_id": parsed_context.workspace_id,
                "task_id": parsed_context.task_id,
                "request_id": parsed_context.request_id,
                "correlation_id": parsed_context.correlation_id,
                "payload": self._sanitize_mapping(payload),
                "created_at": self.utcnow_iso(),
                "category": "visual_processing",
            }

            self.logger.info(
                "Audit event prepared: %s user=%s workspace=%s task=%s",
                action,
                parsed_context.user_id,
                parsed_context.workspace_id,
                parsed_context.task_id,
            )

            return self._safe_result(
                success=True,
                message="Audit event prepared.",
                data=audit_event,
                metadata={},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to log audit event.",
                error=exc,
                metadata={"operation": "_log_audit_event"},
            )

    def _safe_result(
        self,
        *,
        success: bool,
        message: str,
        data: Any = None,
        error: Any = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis result envelope.
        """

        return {
            "success": bool(success),
            "message": str(message),
            "data": data,
            "error": self._sanitize_any(error),
            "metadata": self._sanitize_mapping(metadata or {}),
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Union[BaseException, Mapping[str, Any], str, None] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis error envelope.
        """

        if isinstance(error, BaseException):
            error_payload = {
                "code": error.__class__.__name__,
                "message": str(error),
                "trace": traceback.format_exc()[-MAX_ERROR_TRACE_LENGTH:],
            }
        elif isinstance(error, Mapping):
            error_payload = self._sanitize_mapping(error)
        elif error is None:
            error_payload = {
                "code": "UNKNOWN_ERROR",
                "message": "Unknown error.",
            }
        else:
            error_payload = {
                "code": "ERROR",
                "message": str(error),
            }

        self.logger.error("%s | %s", message, error_payload.get("message"))

        return {
            "success": False,
            "message": str(message),
            "data": None,
            "error": error_payload,
            "metadata": self._sanitize_mapping(metadata or {}),
        }

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    @staticmethod
    def utcnow_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _calculate_extraction_confidence(
        self,
        *,
        frame_count: int,
        duplicate_count: int,
        screen_change_count: int,
        video_metadata: Mapping[str, Any],
    ) -> Dict[str, Any]:
        score = 0.35
        reasons: List[str] = []

        if video_metadata.get("readable"):
            score += 0.20
            reasons.append("Video was readable.")

        if frame_count > 0:
            score += 0.25
            reasons.append("Important frames were extracted.")

        if screen_change_count > 0:
            score += 0.12
            reasons.append("Screen change events were detected.")

        if duplicate_count >= 0:
            score += 0.05
            reasons.append("Duplicate filtering completed.")

        if video_metadata.get("duration_seconds"):
            score += 0.03
            reasons.append("Video duration metadata was available.")

        score = self._clamp_float(score)

        return {
            "score": score,
            "label": self._confidence_label(score),
            "reasons": reasons,
            "components": {
                "video_readable": 1.0 if video_metadata.get("readable") else 0.0,
                "frame_extraction": min(1.0, frame_count / 5.0),
                "screen_change_detection": min(1.0, screen_change_count / 3.0),
                "duplicate_filtering": 1.0,
            },
        }

    def _confidence_label(self, score: float) -> str:
        score = self._clamp_float(score)

        if score >= 0.90:
            return "very_high"
        if score >= 0.75:
            return "high"
        if score >= 0.55:
            return "medium"
        if score >= 0.35:
            return "low"
        return "very_low"

    def _change_severity(self, score: float) -> str:
        score = self._clamp_float(score)

        if score >= 0.55:
            return ChangeSeverity.CRITICAL.value
        if score >= 0.35:
            return ChangeSeverity.HIGH.value
        if score >= 0.18:
            return ChangeSeverity.MEDIUM.value
        if score >= 0.06:
            return ChangeSeverity.LOW.value
        return ChangeSeverity.NONE.value

    def _primary_reason(self, reasons: Sequence[str]) -> str:
        if not reasons:
            return FrameImportanceReason.UNKNOWN.value

        priority = [
            FrameImportanceReason.FIRST_FRAME.value,
            FrameImportanceReason.LAST_FRAME.value,
            FrameImportanceReason.SCREEN_CHANGE.value,
            FrameImportanceReason.UI_LAYOUT_CHANGE.value,
            FrameImportanceReason.MOTION_SPIKE.value,
            FrameImportanceReason.ERROR_LIKE_CHANGE.value,
            FrameImportanceReason.PERIODIC_SAMPLE.value,
            FrameImportanceReason.MANUAL_SELECTED.value,
        ]

        reason_set = set(reasons)
        for item in priority:
            if item in reason_set:
                return item

        return str(reasons[0])

    def _sha256_file(self, path: Path) -> Optional[str]:
        try:
            digest = hashlib.sha256()
            with path.open("rb") as file:
                for chunk in iter(lambda: file.read(1024 * 1024), b""):
                    digest.update(chunk)
            return digest.hexdigest()
        except Exception:
            return None

    def _hash_text(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def _clamp_float(self, value: Any, minimum: float = 0.0, maximum: float = 1.0) -> float:
        try:
            number = float(value)
        except Exception:
            number = minimum

        if math.isnan(number) or math.isinf(number):
            number = minimum

        return max(minimum, min(maximum, number))

    def _optional_str(self, value: Any) -> Optional[str]:
        if value is None:
            return None

        text = str(value).strip()
        if not text:
            return None

        return self._truncate(text, 1_000)

    def _optional_int(self, value: Any) -> Optional[int]:
        if value is None:
            return None

        try:
            return int(value)
        except Exception:
            return None

    def _truncate(self, value: str, max_length: int) -> str:
        text = str(value)
        if len(text) <= max_length:
            return text
        return text[: max(0, max_length - 15)] + "...[TRUNCATED]"

    def _sanitize_mapping(
        self,
        value: Mapping[str, Any],
        *,
        depth: int = 0,
    ) -> Dict[str, Any]:
        if not isinstance(value, Mapping):
            return {}

        if depth > MAX_METADATA_DEPTH:
            return {"_truncated": "maximum_depth_reached"}

        sanitized: Dict[str, Any] = {}

        for key, raw_value in value.items():
            safe_key = str(key)

            if self._is_sensitive_key(safe_key):
                sanitized[safe_key] = "[REDACTED]"
                continue

            sanitized[safe_key] = self._sanitize_any(raw_value, depth=depth + 1)

        return sanitized

    def _sanitize_any(self, value: Any, *, depth: int = 0) -> Any:
        if depth > MAX_METADATA_DEPTH:
            return "[TRUNCATED_MAX_DEPTH]"

        if value is None:
            return None

        if isinstance(value, (bool, int)):
            return value

        if isinstance(value, float):
            if math.isnan(value) or math.isinf(value):
                return None
            return value

        if isinstance(value, Enum):
            return value.value

        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).isoformat()

        if is_dataclass(value):
            return self._sanitize_mapping(asdict(value), depth=depth + 1)

        if isinstance(value, Mapping):
            return self._sanitize_mapping(value, depth=depth + 1)

        if isinstance(value, (list, tuple, set)):
            return [self._sanitize_any(item, depth=depth + 1) for item in list(value)[:1000]]

        if isinstance(value, bytes):
            return {
                "type": "bytes",
                "length": len(value),
                "sha256": hashlib.sha256(value).hexdigest(),
            }

        return self._truncate(str(value), MAX_STRING_FIELD_LENGTH)

    def _is_sensitive_key(self, key: str) -> bool:
        lowered = key.lower()
        sensitive_fragments = {
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "auth_header",
            "cookie",
            "session_cookie",
            "private_key",
            "credential",
            "access_key",
            "refresh_token",
            "client_secret",
        }
        return any(fragment in lowered for fragment in sensitive_fragments)

    def _is_safe_identifier(self, value: str) -> bool:
        if not isinstance(value, str):
            return False

        text = value.strip()
        if not text or len(text) > 180:
            return False

        unsafe_fragments = {"..", "/", "\\", "\x00", "\n", "\r", "\t"}
        return not any(fragment in text for fragment in unsafe_fragments)

    def _safe_path_part(self, value: str) -> str:
        text = str(value or "").strip()
        cleaned = []
        for char in text:
            if char.isalnum() or char in {"_", "-", "."}:
                cleaned.append(char)
            else:
                cleaned.append("_")

        result = "".join(cleaned).strip("._")
        return result or f"id_{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Convenience factory for Agent Loader / Registry
# ---------------------------------------------------------------------------

def create_video_frame_extractor(**kwargs: Any) -> VideoFrameExtractor:
    """
    Factory used by Agent Loader / Agent Registry.
    """

    return VideoFrameExtractor(**kwargs)


# ---------------------------------------------------------------------------
# Module metadata for Agent Registry / Agent Loader
# ---------------------------------------------------------------------------

AGENT_MODULE_INFO: Dict[str, Any] = {
    "module": DEFAULT_MODULE,
    "file": "video_frame_extractor.py",
    "class": "VideoFrameExtractor",
    "agent_name": DEFAULT_AGENT_NAME,
    "schema_version": SCHEMA_VERSION,
    "purpose": "Extracts important frames, removes duplicates, detects screen changes.",
    "safe_to_import": True,
    "requires_user_context": True,
    "requires_workspace_context": True,
    "optional_dependencies": [
        "opencv-python",
        "Pillow",
    ],
    "public_methods": list(VideoFrameExtractor.public_methods),
    "compatible_with": [
        "BaseAgent",
        "AgentRegistry",
        "AgentLoader",
        "AgentRouter",
        "MasterAgent",
        "VisualAgent",
        "SecurityAgent",
        "MemoryAgent",
        "VerificationAgent",
        "DashboardAPI",
        "AuditLog",
        "TaskHistory",
    ],
}


__all__ = [
    "VideoFrameExtractor",
    "VisualTaskContext",
    "FrameExtractionConfig",
    "VideoMetadata",
    "ExtractedFrame",
    "ScreenChangeEvent",
    "FrameImportanceReason",
    "FrameOutputFormat",
    "ExtractionMode",
    "ChangeSeverity",
    "create_video_frame_extractor",
    "AGENT_MODULE_INFO",
]