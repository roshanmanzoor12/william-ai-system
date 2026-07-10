"""
agents/visual_agent/video_analyzer.py

Purpose:
    Analyzes videos/screen recordings, extracts key frames and workflow steps
    for the William / Jarvis Multi-Agent AI SaaS System.

Agent/Module:
    Visual Agent

Required class:
    VideoAnalyzer

Architecture Fit:
    - Master Agent / Agent Router:
        Exposes clear public methods with structured dict results.
    - Visual Agent:
        Performs video metadata extraction, key-frame extraction, scene/change
        analysis, optional OCR, and workflow-step inference.
    - Verification Agent:
        Prepares verification payloads with evidence references.
    - Memory Agent:
        Prepares safe memory payloads with summaries and artifact paths.
    - Security Agent:
        Video/screen recording analysis can expose private data, so analysis
        uses security hooks where relevant.
    - Dashboard/API:
        Returns JSON-style responses ready for FastAPI or dashboard integration.
    - SaaS Isolation:
        Every operation requires user_id and workspace_id and stores artifacts in
        user/workspace scoped folders.

Important:
    - Import-safe even if OpenCV/Pillow/pytesseract or other William modules are
      not installed yet.
    - Does not hardcode secrets.
    - Does not execute destructive/system/browser/call/message/financial actions.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import logging
import math
import os
import re
import shutil
import tempfile
import threading
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional third-party imports
# ---------------------------------------------------------------------------

try:
    import cv2  # type: ignore
except Exception:  # pragma: no cover
    cv2 = None

try:
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover
    np = None

try:
    from PIL import Image, ImageEnhance, ImageFilter, ImageOps, ImageStat
except Exception:  # pragma: no cover
    Image = None
    ImageEnhance = None
    ImageFilter = None
    ImageOps = None
    ImageStat = None

try:
    import pytesseract  # type: ignore
except Exception:  # pragma: no cover
    pytesseract = None


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallback
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover

    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent so this file remains import-safe before the real
        William/Jarvis BaseAgent exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)

        def log_audit_event(self, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit event: %s", payload)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("william.visual_agent.video_analyzer")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_OUTPUT_ROOT = Path(os.getenv("WILLIAM_VIDEO_ANALYZER_ROOT", "runtime/visual/videos"))
DEFAULT_MAX_VIDEO_BYTES = int(os.getenv("WILLIAM_VIDEO_ANALYZER_MAX_BYTES", str(1024 * 1024 * 1024)))
DEFAULT_FRAME_FORMAT = "jpg"

SUPPORTED_VIDEO_EXTENSIONS = {
    ".mp4",
    ".mov",
    ".mkv",
    ".avi",
    ".webm",
    ".m4v",
    ".wmv",
}

COMMON_ERROR_TERMS = [
    "error",
    "failed",
    "failure",
    "exception",
    "timeout",
    "access denied",
    "permission denied",
    "not responding",
    "crashed",
    "invalid",
    "unauthorized",
    "forbidden",
    "server error",
    "fatal",
    "traceback",
]

COMMON_ACTION_TERMS = [
    "login",
    "sign in",
    "submit",
    "save",
    "continue",
    "next",
    "back",
    "cancel",
    "confirm",
    "allow",
    "deny",
    "search",
    "upload",
    "download",
    "open",
    "close",
    "settings",
    "dashboard",
    "create",
    "delete",
    "edit",
    "update",
]

SENSITIVE_TEXT_PATTERNS = [
    re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),
    re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
    re.compile(r"\b(?:password|passcode|secret|api[_-]?key|token|private[_-]?key)\b", re.I),
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class VideoTaskContext:
    """
    SaaS-safe context for video analysis.

    user_id and workspace_id are mandatory to prevent cross-tenant data mixing.
    """

    user_id: str
    workspace_id: str
    task_id: Optional[str] = None
    action_id: Optional[str] = None
    session_id: Optional[str] = None
    source_agent: Optional[str] = None
    requested_by: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclasses.dataclass(frozen=True)
class VideoAnalysisOptions:
    """
    Options for analyzing videos/screen recordings.
    """

    extract_key_frames: bool = True
    frame_interval_seconds: float = 2.0
    max_key_frames: int = 30
    scene_change_threshold: float = 0.18
    include_scene_changes: bool = True
    include_static_samples: bool = True
    enable_ocr: bool = False
    ocr_every_n_keyframes: int = 1
    infer_workflow_steps: bool = True
    detect_errors: bool = True
    redact_ocr_text: bool = True
    save_frames: bool = True
    frame_format: str = DEFAULT_FRAME_FORMAT
    resize_width: Optional[int] = 1280
    max_video_bytes: int = DEFAULT_MAX_VIDEO_BYTES


@dataclasses.dataclass(frozen=True)
class FrameRecord:
    """
    A key frame extracted from a video.
    """

    frame_index: int
    timestamp_seconds: float
    reason: str
    path: Optional[str]
    sha256: Optional[str]
    width: Optional[int]
    height: Optional[int]
    change_score: Optional[float]
    brightness: Optional[float]
    blur_score: Optional[float]
    ocr_text: Optional[str] = None
    ocr_available: bool = False


@dataclasses.dataclass(frozen=True)
class WorkflowStep:
    """
    Inferred workflow step from a key frame or video segment.
    """

    step_number: int
    timestamp_seconds: float
    title: str
    description: str
    confidence: float
    evidence_frame_path: Optional[str]
    signals: Dict[str, Any]


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class VideoAnalyzer(BaseAgent):
    """
    Video/screen-recording analyzer for the William/Jarvis Visual Agent.

    Public methods:
        - analyze_video()
        - extract_key_frames()
        - infer_workflow_steps()
        - read_video_metadata()
        - compare_frames()
        - clean_old_artifacts()

    All public methods return:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": dict | None,
            "metadata": dict
        }
    """

    def __init__(
        self,
        output_root: Union[str, Path] = DEFAULT_OUTPUT_ROOT,
        agent_name: str = "VideoAnalyzer",
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=agent_name, **kwargs)
        self.agent_name = agent_name
        self.agent_id = "visual.video_analyzer"
        self.output_root = Path(output_root)
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self.logger = logger or LOGGER
        self._lock = threading.RLock()

        try:
            self.output_root.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            self.logger.warning("Could not create video analyzer output root %s: %s", self.output_root, exc)

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: Union[VideoTaskContext, Mapping[str, Any]]) -> VideoTaskContext:
        """
        Validate and normalize SaaS task context.
        """
        if isinstance(context, VideoTaskContext):
            ctx = context
        elif isinstance(context, Mapping):
            ctx = VideoTaskContext(
                user_id=str(context.get("user_id", "")).strip(),
                workspace_id=str(context.get("workspace_id", "")).strip(),
                task_id=self._optional_str(context.get("task_id")),
                action_id=self._optional_str(context.get("action_id")),
                session_id=self._optional_str(context.get("session_id")),
                source_agent=self._optional_str(context.get("source_agent")),
                requested_by=self._optional_str(context.get("requested_by")),
                metadata=dict(context.get("metadata") or {}),
            )
        else:
            raise ValueError("context must be VideoTaskContext or mapping")

        if not ctx.user_id:
            raise ValueError("user_id is required for video analysis")
        if not ctx.workspace_id:
            raise ValueError("workspace_id is required for video analysis")
        if not self._is_safe_identifier(ctx.user_id):
            raise ValueError("user_id contains unsafe characters")
        if not self._is_safe_identifier(ctx.workspace_id):
            raise ValueError("workspace_id contains unsafe characters")

        return ctx

    def _requires_security_check(self, operation: str, options: Optional[Any] = None) -> bool:
        """
        Video/screen recordings may contain private data, so analysis and frame
        extraction can require security approval in production.
        """
        operation = (operation or "").lower().strip()

        if operation in {"analyze_video", "extract_key_frames", "ocr_video", "workflow_inference"}:
            return True

        if isinstance(options, Mapping):
            return bool(options.get("require_security_approval", False))

        return False

    def _request_security_approval(
        self,
        operation: str,
        context: VideoTaskContext,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval when available.

        Fallback:
            If no Security Agent is attached, local analysis is allowed only when:
                WILLIAM_ALLOW_VIDEO_ANALYSIS_WITHOUT_SECURITY=true

            This keeps production safe while still allowing local development tests.
        """
        payload = {
            "operation": operation,
            "agent": self.agent_id,
            "reason": reason,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "action_id": context.action_id,
            "metadata": metadata or {},
            "requested_at": self._utc_now_iso(),
        }

        if self.security_agent is not None:
            for method_name in ("approve_action", "request_approval", "authorize", "check_permission"):
                method = getattr(self.security_agent, method_name, None)
                if callable(method):
                    try:
                        response = method(payload)
                        normalized = self._normalize_security_response(response)
                        self._log_audit_event(
                            context,
                            "security_approval_checked",
                            {
                                "operation": operation,
                                "approved": normalized.get("approved"),
                                "reason": normalized.get("reason"),
                            },
                        )
                        return normalized
                    except Exception as exc:
                        self.logger.exception("Security approval failed: %s", exc)
                        return {
                            "approved": False,
                            "reason": "security_agent_error",
                            "details": {"exception": str(exc)},
                        }

        fallback_allowed = os.getenv("WILLIAM_ALLOW_VIDEO_ANALYSIS_WITHOUT_SECURITY", "false").lower() == "true"
        if not fallback_allowed:
            return {
                "approved": False,
                "reason": "security_agent_required_for_video_analysis",
                "details": {
                    "message": "Video/screen recording analysis requires Security Agent approval."
                },
            }

        return {
            "approved": True,
            "reason": "local_development_fallback_allowed",
            "details": {},
        }

    def _prepare_verification_payload(
        self,
        context: VideoTaskContext,
        verification_type: str,
        evidence: Dict[str, Any],
        status: str,
        confidence: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.
        """
        return {
            "type": "verification_payload",
            "verification_type": verification_type,
            "status": status,
            "confidence": self._clamp_confidence(confidence),
            "agent": self.agent_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "action_id": context.action_id,
            "session_id": context.session_id,
            "evidence": evidence,
            "metadata": metadata or {},
            "created_at": self._utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        context: VideoTaskContext,
        event_type: str,
        summary: str,
        data: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Stores summaries and artifact references, not raw video bytes.
        """
        return {
            "type": "memory_payload",
            "memory_scope": "workspace",
            "event_type": event_type,
            "summary": summary,
            "agent": self.agent_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "action_id": context.action_id,
            "session_id": context.session_id,
            "data": data,
            "metadata": metadata or {},
            "created_at": self._utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        context: VideoTaskContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit event for Master Agent, dashboard, workflow logs, or event bus.
        """
        event_payload = {
            "event_name": event_name,
            "agent": self.agent_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "action_id": context.action_id,
            "payload": payload or {},
            "timestamp": self._utc_now_iso(),
        }

        try:
            if self.event_bus is not None:
                for method_name in ("publish", "emit", "send"):
                    method = getattr(self.event_bus, method_name, None)
                    if callable(method):
                        method(event_name, event_payload)
                        return

            emit_method = getattr(super(), "emit_event", None)
            if callable(emit_method):
                emit_method(event_name, event_payload)
        except Exception as exc:
            self.logger.debug("Could not emit event %s: %s", event_name, exc)

    def _log_audit_event(
        self,
        context: VideoTaskContext,
        event_type: str,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "info",
    ) -> None:
        """
        Log audit event without leaking video/frame raw content.
        """
        audit_payload = {
            "event_type": event_type,
            "severity": severity,
            "agent": self.agent_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "task_id": context.task_id,
            "action_id": context.action_id,
            "details": details or {},
            "timestamp": self._utc_now_iso(),
        }

        try:
            if self.audit_logger is not None:
                for method_name in ("log", "write", "record"):
                    method = getattr(self.audit_logger, method_name, None)
                    if callable(method):
                        method(audit_payload)
                        return

            base_audit = getattr(super(), "log_audit_event", None)
            if callable(base_audit):
                base_audit(audit_payload)
                return

            self.logger.info("Audit event: %s", json.dumps(audit_payload, default=str))
        except Exception as exc:
            self.logger.debug("Could not write audit event: %s", exc)

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured result.
        """
        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        code: str = "video_analyzer_error",
        exception: Optional[BaseException] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured error result.
        """
        error = {
            "code": code,
            "message": message,
        }
        if exception is not None:
            error["exception_type"] = exception.__class__.__name__
            error["exception"] = str(exception)

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze_video(
        self,
        context: Union[VideoTaskContext, Mapping[str, Any]],
        video_path: Union[str, Path],
        options: Optional[Union[VideoAnalysisOptions, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Full video analysis:
            1. Validate SaaS context and video file.
            2. Read video metadata.
            3. Extract key frames.
            4. Optionally OCR key frames.
            5. Detect scene changes and errors.
            6. Infer workflow steps.
            7. Prepare verification and memory payloads.
        """
        try:
            ctx = self._validate_task_context(context)
            opts = self._normalize_options(options)
            safe_video_path = self._validate_video_path(video_path, opts.max_video_bytes)

            approval = self._request_security_approval(
                operation="analyze_video",
                context=ctx,
                reason="Analyze user/workspace video or screen recording for visual workflow evidence.",
                metadata={
                    "video_path": str(safe_video_path),
                    "enable_ocr": opts.enable_ocr,
                    "extract_key_frames": opts.extract_key_frames,
                    "infer_workflow_steps": opts.infer_workflow_steps,
                },
            )
            if self._requires_security_check("analyze_video", opts) and not approval.get("approved"):
                return self._error_result(
                    message="Video analysis denied by security policy.",
                    code="security_approval_denied",
                    data={"approval": approval},
                    metadata={"agent": self.agent_id},
                )

            metadata_result = self.read_video_metadata(ctx, safe_video_path)
            if not metadata_result.get("success"):
                return metadata_result

            video_metadata = metadata_result["data"]["video_metadata"]

            key_frames: List[Dict[str, Any]] = []
            if opts.extract_key_frames:
                frame_result = self.extract_key_frames(ctx, safe_video_path, opts)
                if not frame_result.get("success"):
                    return frame_result
                key_frames = frame_result["data"].get("key_frames", [])

            workflow_steps: List[Dict[str, Any]] = []
            if opts.infer_workflow_steps:
                workflow_result = self.infer_workflow_steps(ctx, key_frames, opts)
                if workflow_result.get("success"):
                    workflow_steps = workflow_result["data"].get("workflow_steps", [])

            error_signals = self._collect_error_signals(key_frames) if opts.detect_errors else []
            timeline_summary = self._build_timeline_summary(key_frames, workflow_steps, video_metadata)

            status = "analyzed"
            if error_signals:
                status = "errors_detected"
            elif workflow_steps:
                status = "workflow_inferred"
            elif key_frames:
                status = "frames_extracted"

            confidence = self._calculate_video_analysis_confidence(
                metadata=video_metadata,
                key_frames=key_frames,
                workflow_steps=workflow_steps,
                error_signals=error_signals,
                options=opts,
            )

            evidence = {
                "video_path": str(safe_video_path),
                "video_sha256": self._sha256_file(safe_video_path),
                "video_metadata": video_metadata,
                "key_frames": key_frames,
                "workflow_steps": workflow_steps,
                "error_signals": error_signals,
                "timeline_summary": timeline_summary,
                "options": dataclasses.asdict(opts),
            }

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                verification_type="video_analysis",
                evidence=evidence,
                status=status,
                confidence=confidence,
                metadata={"video_path": str(safe_video_path)},
            )

            memory_payload = self._prepare_memory_payload(
                context=ctx,
                event_type="video_analyzed",
                summary=f"Video analyzed with status {status}. Extracted {len(key_frames)} key frames and inferred {len(workflow_steps)} workflow steps.",
                data={
                    "video_path": str(safe_video_path),
                    "status": status,
                    "confidence": confidence,
                    "key_frame_count": len(key_frames),
                    "workflow_step_count": len(workflow_steps),
                    "error_signal_count": len(error_signals),
                    "duration_seconds": video_metadata.get("duration_seconds"),
                },
            )

            self._emit_agent_event(
                "visual.video.analyzed",
                ctx,
                {
                    "video_path": str(safe_video_path),
                    "status": status,
                    "confidence": confidence,
                    "key_frame_count": len(key_frames),
                    "workflow_step_count": len(workflow_steps),
                },
            )

            self._log_audit_event(
                ctx,
                "video_analyzed",
                {
                    "video_path": str(safe_video_path),
                    "status": status,
                    "key_frame_count": len(key_frames),
                    "workflow_step_count": len(workflow_steps),
                    "error_signal_count": len(error_signals),
                },
            )

            return self._safe_result(
                True,
                "Video analyzed successfully.",
                data={
                    "status": status,
                    "confidence": confidence,
                    "video_metadata": video_metadata,
                    "key_frames": key_frames,
                    "workflow_steps": workflow_steps,
                    "error_signals": error_signals,
                    "timeline_summary": timeline_summary,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={"agent": self.agent_id},
            )

        except Exception as exc:
            self.logger.exception("analyze_video failed")
            return self._error_result(
                message="Video analysis failed.",
                code="analyze_video_failed",
                exception=exc,
                metadata={"agent": self.agent_id},
            )

    def read_video_metadata(
        self,
        context: Union[VideoTaskContext, Mapping[str, Any]],
        video_path: Union[str, Path],
    ) -> Dict[str, Any]:
        """
        Read video metadata using OpenCV when available.
        """
        try:
            ctx = self._validate_task_context(context)
            safe_video_path = self._validate_video_path(video_path, DEFAULT_MAX_VIDEO_BYTES)

            if cv2 is None:
                basic_metadata = {
                    "path": str(safe_video_path),
                    "filename": safe_video_path.name,
                    "size_bytes": safe_video_path.stat().st_size,
                    "sha256": self._sha256_file(safe_video_path),
                    "backend": "filesystem_only",
                    "opencv_available": False,
                    "duration_seconds": None,
                    "fps": None,
                    "frame_count": None,
                    "width": None,
                    "height": None,
                }
                return self._safe_result(
                    True,
                    "Basic video metadata read. OpenCV is unavailable for duration/frame metadata.",
                    data={"video_metadata": basic_metadata},
                    metadata=self._dependency_metadata(),
                )

            cap = cv2.VideoCapture(str(safe_video_path))
            if not cap.isOpened():
                return self._error_result(
                    message="Could not open video file with OpenCV.",
                    code="video_open_failed",
                    data={"path": str(safe_video_path)},
                    metadata=self._dependency_metadata(),
                )

            try:
                fps = float(cap.get(cv2.CAP_PROP_FPS) or 0.0)
                frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
                width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
                height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
                duration = frame_count / fps if fps > 0 and frame_count > 0 else None

                metadata = {
                    "path": str(safe_video_path),
                    "filename": safe_video_path.name,
                    "size_bytes": safe_video_path.stat().st_size,
                    "sha256": self._sha256_file(safe_video_path),
                    "backend": "opencv",
                    "opencv_available": True,
                    "duration_seconds": round(duration, 4) if duration is not None else None,
                    "fps": round(fps, 4),
                    "frame_count": frame_count,
                    "width": width,
                    "height": height,
                    "extension": safe_video_path.suffix.lower(),
                }
            finally:
                cap.release()

            self._emit_agent_event(
                "visual.video.metadata_read",
                ctx,
                {"video_path": str(safe_video_path), "duration_seconds": metadata.get("duration_seconds")},
            )

            return self._safe_result(
                True,
                "Video metadata read successfully.",
                data={"video_metadata": metadata},
                metadata={"agent": self.agent_id},
            )

        except Exception as exc:
            self.logger.exception("read_video_metadata failed")
            return self._error_result(
                message="Video metadata read failed.",
                code="read_video_metadata_failed",
                exception=exc,
                metadata={"agent": self.agent_id},
            )

    def extract_key_frames(
        self,
        context: Union[VideoTaskContext, Mapping[str, Any]],
        video_path: Union[str, Path],
        options: Optional[Union[VideoAnalysisOptions, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Extract key frames using interval sampling and scene-change detection.
        """
        try:
            if cv2 is None or np is None:
                return self._error_result(
                    message="OpenCV and numpy are required for key-frame extraction.",
                    code="opencv_numpy_required",
                    metadata=self._dependency_metadata(),
                )

            ctx = self._validate_task_context(context)
            opts = self._normalize_options(options)
            safe_video_path = self._validate_video_path(video_path, opts.max_video_bytes)

            approval = self._request_security_approval(
                operation="extract_key_frames",
                context=ctx,
                reason="Extract key frames from a user/workspace video for visual analysis.",
                metadata={
                    "video_path": str(safe_video_path),
                    "max_key_frames": opts.max_key_frames,
                    "enable_ocr": opts.enable_ocr,
                },
            )
            if self._requires_security_check("extract_key_frames", opts) and not approval.get("approved"):
                return self._error_result(
                    message="Key-frame extraction denied by security policy.",
                    code="security_approval_denied",
                    data={"approval": approval},
                    metadata={"agent": self.agent_id},
                )

            output_dir = self._artifact_dir(ctx, safe_video_path)
            output_dir.mkdir(parents=True, exist_ok=True)

            cap = cv2.VideoCapture(str(safe_video_path))
            if not cap.isOpened():
                return self._error_result(
                    message="Could not open video for key-frame extraction.",
                    code="video_open_failed",
                    data={"path": str(safe_video_path)},
                    metadata=self._dependency_metadata(),
                )

            key_frames: List[FrameRecord] = []
            previous_small_gray = None
            last_saved_timestamp = -9999.0
            frame_index = 0

            fps = float(cap.get(cv2.CAP_PROP_FPS) or 0.0)
            frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
            interval_frames = max(1, int(round((opts.frame_interval_seconds or 1.0) * fps))) if fps > 0 else 30

            try:
                while True:
                    ok, frame = cap.read()
                    if not ok:
                        break

                    timestamp_seconds = frame_index / fps if fps > 0 else float(frame_index)

                    resized_frame = self._resize_frame(frame, opts.resize_width)
                    gray_small = self._frame_to_small_gray(resized_frame)
                    change_score = self._frame_change_score(previous_small_gray, gray_small)
                    previous_small_gray = gray_small

                    should_save = False
                    reason = ""

                    if frame_index == 0:
                        should_save = True
                        reason = "first_frame"
                    elif opts.include_static_samples and frame_index % interval_frames == 0:
                        should_save = True
                        reason = "interval_sample"
                    elif opts.include_scene_changes and change_score is not None and change_score >= opts.scene_change_threshold:
                        should_save = True
                        reason = "scene_change"

                    if should_save and len(key_frames) < opts.max_key_frames:
                        minimum_gap = max(0.25, min(opts.frame_interval_seconds * 0.5, 2.0))
                        if timestamp_seconds - last_saved_timestamp >= minimum_gap or reason == "first_frame":
                            record = self._save_frame_record(
                                context=ctx,
                                frame=resized_frame,
                                output_dir=output_dir,
                                frame_index=frame_index,
                                timestamp_seconds=timestamp_seconds,
                                reason=reason,
                                change_score=change_score,
                                options=opts,
                                key_frame_position=len(key_frames),
                            )
                            key_frames.append(record)
                            last_saved_timestamp = timestamp_seconds

                    frame_index += 1

                    if len(key_frames) >= opts.max_key_frames:
                        break

            finally:
                cap.release()

            key_frames_dict = [dataclasses.asdict(record) for record in key_frames]

            self._emit_agent_event(
                "visual.video.key_frames_extracted",
                ctx,
                {
                    "video_path": str(safe_video_path),
                    "key_frame_count": len(key_frames_dict),
                    "frame_count_seen": frame_index,
                },
            )

            self._log_audit_event(
                ctx,
                "video_key_frames_extracted",
                {
                    "video_path": str(safe_video_path),
                    "key_frame_count": len(key_frames_dict),
                    "output_dir": str(output_dir),
                },
            )

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                verification_type="video_key_frame_extraction",
                evidence={
                    "video_path": str(safe_video_path),
                    "output_dir": str(output_dir),
                    "key_frames": key_frames_dict,
                    "fps": fps,
                    "frame_count": frame_count,
                },
                status="frames_extracted",
                confidence=0.90 if key_frames_dict else 0.30,
            )

            return self._safe_result(
                True,
                "Key frames extracted successfully.",
                data={
                    "video_path": str(safe_video_path),
                    "output_dir": str(output_dir),
                    "key_frames": key_frames_dict,
                    "key_frame_count": len(key_frames_dict),
                    "verification_payload": verification_payload,
                },
                metadata={"agent": self.agent_id},
            )

        except Exception as exc:
            self.logger.exception("extract_key_frames failed")
            return self._error_result(
                message="Key-frame extraction failed.",
                code="extract_key_frames_failed",
                exception=exc,
                metadata={"agent": self.agent_id},
            )

    def infer_workflow_steps(
        self,
        context: Union[VideoTaskContext, Mapping[str, Any]],
        key_frames: Sequence[Mapping[str, Any]],
        options: Optional[Union[VideoAnalysisOptions, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Infer workflow steps from key frames.

        This method uses safe deterministic heuristics:
            - OCR action words
            - error terms
            - frame reason / timestamp
            - scene-change score
            - brightness/blur quality
        """
        try:
            ctx = self._validate_task_context(context)
            opts = self._normalize_options(options)

            workflow_steps: List[WorkflowStep] = []
            last_title = ""

            for index, frame in enumerate(key_frames):
                timestamp = float(frame.get("timestamp_seconds") or 0.0)
                ocr_text = str(frame.get("ocr_text") or "")
                redacted_text = self._redact_text(ocr_text) if opts.redact_ocr_text else ocr_text

                action_terms = self._find_terms(redacted_text, COMMON_ACTION_TERMS)
                error_terms = self._find_terms(redacted_text, COMMON_ERROR_TERMS)
                reason = str(frame.get("reason") or "key_frame")
                change_score = frame.get("change_score")
                path = self._optional_str(frame.get("path"))

                if error_terms:
                    title = "Error or failure screen detected"
                    description = f"At {self._format_timestamp(timestamp)}, the recording shows possible error evidence: {', '.join(error_terms[:5])}."
                    confidence = 0.86
                elif action_terms:
                    primary_action = action_terms[0]
                    title = f"User reaches {primary_action.title()} step"
                    description = f"At {self._format_timestamp(timestamp)}, visible text suggests a workflow step related to '{primary_action}'."
                    confidence = 0.76
                elif reason == "first_frame":
                    title = "Workflow starts"
                    description = f"The recording starts at {self._format_timestamp(timestamp)} with the first captured screen."
                    confidence = 0.70
                elif reason == "scene_change":
                    title = "Screen changes"
                    description = f"At {self._format_timestamp(timestamp)}, a visual scene change indicates a possible workflow transition."
                    confidence = 0.68
                elif reason == "interval_sample":
                    title = "Screen state sample"
                    description = f"At {self._format_timestamp(timestamp)}, this sampled frame represents the current screen state."
                    confidence = 0.55
                else:
                    title = "Visual workflow checkpoint"
                    description = f"At {self._format_timestamp(timestamp)}, a key frame was captured for workflow review."
                    confidence = 0.52

                if title == last_title and workflow_steps:
                    previous = workflow_steps[-1]
                    merged_signals = dict(previous.signals)
                    merged_signals.setdefault("merged_frame_paths", [])
                    if path:
                        merged_signals["merged_frame_paths"].append(path)
                    merged_signals["last_timestamp_seconds"] = timestamp

                    workflow_steps[-1] = WorkflowStep(
                        step_number=previous.step_number,
                        timestamp_seconds=previous.timestamp_seconds,
                        title=previous.title,
                        description=previous.description + f" Additional evidence appears near {self._format_timestamp(timestamp)}.",
                        confidence=max(previous.confidence, confidence),
                        evidence_frame_path=previous.evidence_frame_path,
                        signals=merged_signals,
                    )
                    continue

                step = WorkflowStep(
                    step_number=len(workflow_steps) + 1,
                    timestamp_seconds=timestamp,
                    title=title,
                    description=description,
                    confidence=self._clamp_confidence(confidence),
                    evidence_frame_path=path,
                    signals={
                        "reason": reason,
                        "change_score": change_score,
                        "action_terms": action_terms,
                        "error_terms": error_terms,
                        "ocr_text_excerpt": self._excerpt(redacted_text, 280),
                        "frame_index": frame.get("frame_index"),
                        "brightness": frame.get("brightness"),
                        "blur_score": frame.get("blur_score"),
                    },
                )
                workflow_steps.append(step)
                last_title = title

            workflow_steps_dict = [dataclasses.asdict(step) for step in workflow_steps]

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                verification_type="video_workflow_inference",
                evidence={"workflow_steps": workflow_steps_dict},
                status="workflow_steps_inferred" if workflow_steps_dict else "no_workflow_steps_found",
                confidence=0.82 if workflow_steps_dict else 0.35,
            )

            self._emit_agent_event(
                "visual.video.workflow_inferred",
                ctx,
                {"workflow_step_count": len(workflow_steps_dict)},
            )

            return self._safe_result(
                True,
                "Workflow steps inferred successfully.",
                data={
                    "workflow_steps": workflow_steps_dict,
                    "workflow_step_count": len(workflow_steps_dict),
                    "verification_payload": verification_payload,
                },
                metadata={"agent": self.agent_id},
            )

        except Exception as exc:
            self.logger.exception("infer_workflow_steps failed")
            return self._error_result(
                message="Workflow step inference failed.",
                code="infer_workflow_steps_failed",
                exception=exc,
                metadata={"agent": self.agent_id},
            )

    def compare_frames(
        self,
        context: Union[VideoTaskContext, Mapping[str, Any]],
        frame_a_path: Union[str, Path],
        frame_b_path: Union[str, Path],
    ) -> Dict[str, Any]:
        """
        Compare two saved frame images and return a normalized difference score.
        """
        try:
            if cv2 is None or np is None:
                return self._error_result(
                    message="OpenCV and numpy are required for frame comparison.",
                    code="opencv_numpy_required",
                    metadata=self._dependency_metadata(),
                )

            ctx = self._validate_task_context(context)
            a_path = self._validate_image_path(frame_a_path)
            b_path = self._validate_image_path(frame_b_path)

            img_a = cv2.imread(str(a_path))
            img_b = cv2.imread(str(b_path))

            if img_a is None or img_b is None:
                return self._error_result(
                    message="Could not read one or both frame images.",
                    code="frame_read_failed",
                    data={"frame_a_path": str(a_path), "frame_b_path": str(b_path)},
                )

            if img_a.shape[:2] != img_b.shape[:2]:
                img_b = cv2.resize(img_b, (img_a.shape[1], img_a.shape[0]))

            gray_a = cv2.cvtColor(img_a, cv2.COLOR_BGR2GRAY)
            gray_b = cv2.cvtColor(img_b, cv2.COLOR_BGR2GRAY)

            score = self._frame_change_score(gray_a, gray_b)
            changed = bool(score is not None and score >= 0.18)

            payload = self._prepare_verification_payload(
                context=ctx,
                verification_type="frame_comparison",
                evidence={
                    "frame_a_path": str(a_path),
                    "frame_b_path": str(b_path),
                    "change_score": score,
                    "changed": changed,
                },
                status="changed" if changed else "similar",
                confidence=0.88,
            )

            return self._safe_result(
                True,
                "Frames compared successfully.",
                data={
                    "frame_a_path": str(a_path),
                    "frame_b_path": str(b_path),
                    "change_score": score,
                    "changed": changed,
                    "verification_payload": payload,
                },
                metadata={"agent": self.agent_id},
            )

        except Exception as exc:
            self.logger.exception("compare_frames failed")
            return self._error_result(
                message="Frame comparison failed.",
                code="compare_frames_failed",
                exception=exc,
                metadata={"agent": self.agent_id},
            )

    def clean_old_artifacts(
        self,
        context: Union[VideoTaskContext, Mapping[str, Any]],
        older_than_days: int = 30,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Clean old visual video artifacts for a single user/workspace only.
        """
        try:
            ctx = self._validate_task_context(context)
            if older_than_days < 1:
                return self._error_result(
                    message="older_than_days must be at least 1.",
                    code="invalid_retention_days",
                )

            scoped_dir = self._workspace_dir(ctx)
            if not scoped_dir.exists():
                return self._safe_result(
                    True,
                    "No video artifact directory exists for this user/workspace.",
                    data={"dry_run": dry_run, "candidates": [], "deleted": []},
                    metadata={"agent": self.agent_id},
                )

            cutoff = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=older_than_days)
            candidates: List[str] = []

            for path in scoped_dir.rglob("*"):
                if not path.is_file():
                    continue
                try:
                    modified = _dt.datetime.fromtimestamp(path.stat().st_mtime, tz=_dt.timezone.utc)
                    if modified < cutoff:
                        candidates.append(str(path))
                except Exception:
                    continue

            deleted: List[str] = []
            if not dry_run:
                for item in candidates:
                    p = Path(item)
                    if self._is_path_inside(p, scoped_dir):
                        try:
                            p.unlink()
                            deleted.append(item)
                        except Exception as exc:
                            self.logger.warning("Could not delete old artifact %s: %s", item, exc)

            self._log_audit_event(
                ctx,
                "video_artifacts_cleanup",
                {
                    "older_than_days": older_than_days,
                    "dry_run": dry_run,
                    "candidate_count": len(candidates),
                    "deleted_count": len(deleted),
                },
            )

            return self._safe_result(
                True,
                "Video artifact cleanup completed." if not dry_run else "Video artifact cleanup dry run completed.",
                data={
                    "dry_run": dry_run,
                    "candidates": candidates,
                    "deleted": deleted,
                    "candidate_count": len(candidates),
                    "deleted_count": len(deleted),
                },
                metadata={"agent": self.agent_id},
            )

        except Exception as exc:
            self.logger.exception("clean_old_artifacts failed")
            return self._error_result(
                message="Video artifact cleanup failed.",
                code="clean_old_artifacts_failed",
                exception=exc,
                metadata={"agent": self.agent_id},
            )

    # ------------------------------------------------------------------
    # Frame extraction internals
    # ------------------------------------------------------------------

    def _save_frame_record(
        self,
        context: VideoTaskContext,
        frame: Any,
        output_dir: Path,
        frame_index: int,
        timestamp_seconds: float,
        reason: str,
        change_score: Optional[float],
        options: VideoAnalysisOptions,
        key_frame_position: int,
    ) -> FrameRecord:
        """
        Save one frame and return its metadata record.
        """
        path: Optional[Path] = None
        sha256: Optional[str] = None

        frame_to_save = frame
        height, width = frame_to_save.shape[:2]

        if options.save_frames:
            extension = self._safe_frame_extension(options.frame_format)
            filename = (
                f"frame_{key_frame_position + 1:04d}_"
                f"idx_{frame_index}_"
                f"t_{timestamp_seconds:.2f}_"
                f"{self._safe_slug(reason)}.{extension}"
            )
            path = output_dir / filename
            self._write_frame(path, frame_to_save, extension)
            sha256 = self._sha256_file(path)

        brightness = self._frame_brightness(frame_to_save)
        blur_score = self._frame_blur_score(frame_to_save)

        ocr_text = None
        ocr_available = bool(pytesseract is not None and Image is not None)
        should_ocr = (
            options.enable_ocr
            and ocr_available
            and options.ocr_every_n_keyframes > 0
            and key_frame_position % options.ocr_every_n_keyframes == 0
        )

        if should_ocr:
            ocr_text = self._ocr_frame(frame_to_save)
            if options.redact_ocr_text:
                ocr_text = self._redact_text(ocr_text)

        return FrameRecord(
            frame_index=frame_index,
            timestamp_seconds=round(timestamp_seconds, 4),
            reason=reason,
            path=str(path) if path else None,
            sha256=sha256,
            width=int(width),
            height=int(height),
            change_score=round(change_score, 6) if change_score is not None else None,
            brightness=round(brightness, 4) if brightness is not None else None,
            blur_score=round(blur_score, 4) if blur_score is not None else None,
            ocr_text=ocr_text,
            ocr_available=ocr_available,
        )

    def _resize_frame(self, frame: Any, resize_width: Optional[int]) -> Any:
        if cv2 is None or resize_width is None or resize_width <= 0:
            return frame

        height, width = frame.shape[:2]
        if width <= resize_width:
            return frame

        ratio = resize_width / float(width)
        new_height = max(1, int(height * ratio))
        return cv2.resize(frame, (resize_width, new_height), interpolation=cv2.INTER_AREA)

    def _frame_to_small_gray(self, frame: Any) -> Any:
        if cv2 is None:
            return frame

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        return cv2.resize(gray, (160, 90), interpolation=cv2.INTER_AREA)

    def _frame_change_score(self, previous_gray: Any, current_gray: Any) -> Optional[float]:
        if previous_gray is None or current_gray is None or cv2 is None or np is None:
            return None

        if previous_gray.shape != current_gray.shape:
            current_gray = cv2.resize(current_gray, (previous_gray.shape[1], previous_gray.shape[0]))

        diff = cv2.absdiff(previous_gray, current_gray)
        score = float(np.mean(diff) / 255.0)
        return max(0.0, min(1.0, score))

    def _frame_brightness(self, frame: Any) -> Optional[float]:
        if cv2 is None or np is None:
            return None
        try:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            return float(np.mean(gray))
        except Exception:
            return None

    def _frame_blur_score(self, frame: Any) -> Optional[float]:
        if cv2 is None:
            return None
        try:
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            return float(cv2.Laplacian(gray, cv2.CV_64F).var())
        except Exception:
            return None

    def _write_frame(self, path: Path, frame: Any, extension: str) -> None:
        if cv2 is None:
            raise RuntimeError("OpenCV is required to save video frames.")

        path.parent.mkdir(parents=True, exist_ok=True)

        params: List[int] = []
        if extension in {"jpg", "jpeg"}:
            params = [int(cv2.IMWRITE_JPEG_QUALITY), 88]
        elif extension == "png":
            params = [int(cv2.IMWRITE_PNG_COMPRESSION), 3]

        ok = cv2.imwrite(str(path), frame, params)
        if not ok:
            raise RuntimeError(f"Could not write frame to {path}")

    def _ocr_frame(self, frame: Any) -> str:
        if pytesseract is None or Image is None or cv2 is None:
            return ""

        try:
            rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            pil_image = Image.fromarray(rgb)

            if ImageOps is not None and ImageEnhance is not None:
                pil_image = ImageOps.grayscale(pil_image)
                pil_image = ImageEnhance.Contrast(pil_image).enhance(1.4)

            text = pytesseract.image_to_string(pil_image) or ""
            return text.strip()
        except Exception as exc:
            self.logger.debug("Frame OCR failed: %s", exc)
            return ""

    # ------------------------------------------------------------------
    # Analysis helpers
    # ------------------------------------------------------------------

    def _collect_error_signals(self, key_frames: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        signals: List[Dict[str, Any]] = []

        for frame in key_frames:
            text = str(frame.get("ocr_text") or "")
            terms = self._find_terms(text, COMMON_ERROR_TERMS)
            if not terms:
                continue

            signals.append(
                {
                    "type": "video_frame_error_text",
                    "timestamp_seconds": frame.get("timestamp_seconds"),
                    "frame_index": frame.get("frame_index"),
                    "frame_path": frame.get("path"),
                    "terms": terms,
                    "confidence": 0.84,
                }
            )

        return signals

    def _build_timeline_summary(
        self,
        key_frames: Sequence[Mapping[str, Any]],
        workflow_steps: Sequence[Mapping[str, Any]],
        video_metadata: Mapping[str, Any],
    ) -> Dict[str, Any]:
        duration = video_metadata.get("duration_seconds")
        first_frame = key_frames[0] if key_frames else None
        last_frame = key_frames[-1] if key_frames else None

        return {
            "duration_seconds": duration,
            "key_frame_count": len(key_frames),
            "workflow_step_count": len(workflow_steps),
            "first_key_frame_at": first_frame.get("timestamp_seconds") if first_frame else None,
            "last_key_frame_at": last_frame.get("timestamp_seconds") if last_frame else None,
            "high_change_frames": [
                {
                    "timestamp_seconds": frame.get("timestamp_seconds"),
                    "path": frame.get("path"),
                    "change_score": frame.get("change_score"),
                }
                for frame in key_frames
                if isinstance(frame.get("change_score"), (int, float)) and float(frame.get("change_score")) >= 0.18
            ],
        }

    def _calculate_video_analysis_confidence(
        self,
        metadata: Mapping[str, Any],
        key_frames: Sequence[Mapping[str, Any]],
        workflow_steps: Sequence[Mapping[str, Any]],
        error_signals: Sequence[Mapping[str, Any]],
        options: VideoAnalysisOptions,
    ) -> float:
        score = 0.20

        if metadata.get("duration_seconds") is not None:
            score += 0.15
        if metadata.get("frame_count"):
            score += 0.10
        if key_frames:
            score += min(0.25, len(key_frames) * 0.015 + 0.10)
        if workflow_steps:
            score += min(0.20, len(workflow_steps) * 0.025 + 0.08)
        if options.enable_ocr:
            ocr_frames = [f for f in key_frames if f.get("ocr_text")]
            score += min(0.15, len(ocr_frames) * 0.025)
        else:
            score += 0.05
        if error_signals:
            score += 0.05

        return self._clamp_confidence(score)

    # ------------------------------------------------------------------
    # Path and artifact helpers
    # ------------------------------------------------------------------

    def _validate_video_path(self, video_path: Union[str, Path], max_video_bytes: int) -> Path:
        path = Path(video_path).expanduser().resolve()

        if not path.exists():
            raise FileNotFoundError(f"Video file does not exist: {path}")
        if not path.is_file():
            raise ValueError(f"Video path is not a file: {path}")

        suffix = path.suffix.lower()
        if suffix not in SUPPORTED_VIDEO_EXTENSIONS:
            raise ValueError(f"Unsupported video extension: {suffix}")

        size = path.stat().st_size
        if size <= 0:
            raise ValueError("Video file is empty")
        if size > max_video_bytes:
            raise ValueError(f"Video file exceeds max allowed size: {size} > {max_video_bytes}")

        return path

    def _validate_image_path(self, image_path: Union[str, Path]) -> Path:
        path = Path(image_path).expanduser().resolve()

        if not path.exists():
            raise FileNotFoundError(f"Frame image does not exist: {path}")
        if not path.is_file():
            raise ValueError(f"Frame image path is not a file: {path}")
        if path.suffix.lower() not in {".jpg", ".jpeg", ".png", ".webp", ".bmp"}:
            raise ValueError(f"Unsupported frame image extension: {path.suffix}")

        return path

    def _workspace_dir(self, context: VideoTaskContext) -> Path:
        return self.output_root / self._safe_slug(context.workspace_id) / self._safe_slug(context.user_id)

    def _artifact_dir(self, context: VideoTaskContext, video_path: Path) -> Path:
        video_slug = self._safe_slug(video_path.stem)
        date_slug = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
        run_id = uuid.uuid4().hex[:10]
        return self._workspace_dir(context) / date_slug / f"{video_slug}_{run_id}"

    def _sha256_file(self, path: Union[str, Path]) -> str:
        digest = hashlib.sha256()
        with Path(path).open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _is_path_inside(self, child: Path, parent: Path) -> bool:
        try:
            child_resolved = child.resolve()
            parent_resolved = parent.resolve()
            return str(child_resolved).startswith(str(parent_resolved))
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Normalization helpers
    # ------------------------------------------------------------------

    def _normalize_options(
        self,
        options: Optional[Union[VideoAnalysisOptions, Mapping[str, Any]]],
    ) -> VideoAnalysisOptions:
        if options is None:
            return VideoAnalysisOptions()
        if isinstance(options, VideoAnalysisOptions):
            return options
        if not isinstance(options, Mapping):
            raise ValueError("options must be VideoAnalysisOptions or mapping")

        return VideoAnalysisOptions(
            extract_key_frames=bool(options.get("extract_key_frames", True)),
            frame_interval_seconds=float(options.get("frame_interval_seconds", 2.0)),
            max_key_frames=int(options.get("max_key_frames", 30)),
            scene_change_threshold=float(options.get("scene_change_threshold", 0.18)),
            include_scene_changes=bool(options.get("include_scene_changes", True)),
            include_static_samples=bool(options.get("include_static_samples", True)),
            enable_ocr=bool(options.get("enable_ocr", False)),
            ocr_every_n_keyframes=max(1, int(options.get("ocr_every_n_keyframes", 1))),
            infer_workflow_steps=bool(options.get("infer_workflow_steps", True)),
            detect_errors=bool(options.get("detect_errors", True)),
            redact_ocr_text=bool(options.get("redact_ocr_text", True)),
            save_frames=bool(options.get("save_frames", True)),
            frame_format=str(options.get("frame_format", DEFAULT_FRAME_FORMAT)),
            resize_width=self._optional_int(options.get("resize_width", 1280)),
            max_video_bytes=int(options.get("max_video_bytes", DEFAULT_MAX_VIDEO_BYTES)),
        )

    def _normalize_security_response(self, response: Any) -> Dict[str, Any]:
        if isinstance(response, Mapping):
            approved = bool(
                response.get("approved")
                or response.get("allowed")
                or response.get("success")
                or response.get("authorized")
            )
            return {
                "approved": approved,
                "reason": str(response.get("reason") or response.get("message") or ""),
                "details": dict(response),
            }

        if isinstance(response, bool):
            return {
                "approved": response,
                "reason": "boolean_security_response",
                "details": {},
            }

        return {
            "approved": False,
            "reason": "unrecognized_security_response",
            "details": {"response_type": type(response).__name__},
        }

    # ------------------------------------------------------------------
    # Text and utility helpers
    # ------------------------------------------------------------------

    def _find_terms(self, text: str, terms: Sequence[str]) -> List[str]:
        normalized = self._normalize_text(text)
        found: List[str] = []

        for term in terms:
            clean = self._normalize_text(term)
            if clean and clean in normalized:
                found.append(term)

        return found

    def _redact_text(self, text: str) -> str:
        redacted = text or ""
        for pattern in SENSITIVE_TEXT_PATTERNS:
            redacted = pattern.sub("[REDACTED]", redacted)
        return redacted

    def _normalize_text(self, text: str) -> str:
        value = str(text or "").lower()
        value = re.sub(r"\s+", " ", value)
        value = re.sub(r"[^a-z0-9\s._:@/\-]+", "", value)
        return value.strip()

    def _excerpt(self, text: str, max_chars: int) -> str:
        value = str(text or "").strip()
        if len(value) <= max_chars:
            return value
        return value[: max_chars - 3].rstrip() + "..."

    def _format_timestamp(self, seconds: float) -> str:
        seconds = max(0.0, float(seconds))
        minutes = int(seconds // 60)
        remaining = seconds - (minutes * 60)
        return f"{minutes:02d}:{remaining:05.2f}"

    def _safe_frame_extension(self, frame_format: str) -> str:
        value = str(frame_format or DEFAULT_FRAME_FORMAT).lower().strip().lstrip(".")
        if value in {"jpg", "jpeg"}:
            return "jpg"
        if value in {"png", "webp", "bmp"}:
            return value
        return DEFAULT_FRAME_FORMAT

    def _safe_slug(self, value: str) -> str:
        text = str(value or "unknown").strip()
        text = re.sub(r"[^A-Za-z0-9_.:@\-]+", "_", text)
        text = text.strip("._-")
        return text[:120] or "unknown"

    def _is_safe_identifier(self, value: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z0-9_.:@\-]{1,128}", value or ""))

    def _optional_str(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _optional_int(self, value: Any) -> Optional[int]:
        if value is None:
            return None
        try:
            number = int(value)
            return number if number > 0 else None
        except Exception:
            return None

    def _clamp_confidence(self, value: float) -> float:
        try:
            value = float(value)
        except Exception:
            value = 0.0
        return max(0.0, min(1.0, round(value, 4)))

    def _utc_now_iso(self) -> str:
        return _dt.datetime.now(_dt.timezone.utc).isoformat()

    def _dependency_metadata(self) -> Dict[str, Any]:
        return {
            "agent": self.agent_id,
            "dependencies": {
                "opencv": cv2 is not None,
                "numpy": np is not None,
                "pillow": Image is not None,
                "pytesseract": pytesseract is not None,
            },
        }


# ---------------------------------------------------------------------------
# Registry / Loader helper
# ---------------------------------------------------------------------------

def get_video_analyzer(**kwargs: Any) -> VideoAnalyzer:
    """
    Factory helper for Agent Loader / Agent Registry integration.
    """
    return VideoAnalyzer(**kwargs)


__all__ = [
    "VideoAnalyzer",
    "VideoTaskContext",
    "VideoAnalysisOptions",
    "FrameRecord",
    "WorkflowStep",
    "get_video_analyzer",
]


# ---------------------------------------------------------------------------
# Lightweight self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    analyzer = VideoAnalyzer(output_root=Path(tempfile.gettempdir()) / "william_video_analyzer_test")

    print("Dependency metadata:")
    print(json.dumps(analyzer._dependency_metadata(), indent=2))

    context = {
        "user_id": "test_user",
        "workspace_id": "test_workspace",
        "task_id": "test_task",
        "action_id": "test_action",
        "source_agent": "visual_agent",
    }

    print("Context validation self-test:")
    print(analyzer._validate_task_context(context))

    print("VideoAnalyzer import/self-test completed.")
    print("FILE COMPLETE")