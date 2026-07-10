"""
agents/verification_agent/screenshot_checker.py

Purpose:
    Captures and analyzes screenshots for app/page/UI/popup/error confirmation
    inside the William / Jarvis Multi-Agent AI SaaS System.

Agent/Module:
    Verification Agent

Required class:
    ScreenshotChecker

Architecture Fit:
    - Master Agent / Router:
        Exposes clear public methods that can be called by MasterAgent, AgentRouter,
        API routes, dashboard actions, or workflow tasks.
    - Security Agent:
        Screenshot capture can expose private data, so real screen capture requires
        a security check/approval hook unless explicitly disabled for test mode.
    - Memory Agent:
        Produces safe memory payloads with metadata and evidence references.
    - Verification Agent:
        Produces structured verification payloads for proof, UI confirmation,
        error confirmation, popup confirmation, and screenshot comparison.
    - SaaS Isolation:
        Every user/workspace operation validates user_id and workspace_id and writes
        outputs into isolated workspace/user scoped folders.
    - Registry / Loader:
        Import-safe. Uses optional imports and fallback BaseAgent stubs.

Important:
    This file does not hardcode secrets.
    This file does not perform destructive actions.
    Real system screen capture is gated by safety/security hooks.
"""

from __future__ import annotations

import base64
import dataclasses
import datetime as _dt
import difflib
import hashlib
import io
import json
import logging
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
    from PIL import Image, ImageChops, ImageEnhance, ImageFilter, ImageOps, ImageStat
except Exception:  # pragma: no cover - optional dependency
    Image = None
    ImageChops = None
    ImageEnhance = None
    ImageFilter = None
    ImageOps = None
    ImageStat = None

try:
    import pyautogui  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    pyautogui = None

try:
    import mss  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    mss = None

try:
    import pytesseract  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    pytesseract = None

try:
    import cv2  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    cv2 = None

try:
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    np = None


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety

    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent so this file remains import-safe before the
        real William/Jarvis BaseAgent exists.
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

LOGGER = logging.getLogger("william.verification_agent.screenshot_checker")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants and safe defaults
# ---------------------------------------------------------------------------

DEFAULT_OUTPUT_ROOT = Path(os.getenv("WILLIAM_SCREENSHOT_ROOT", "runtime/verification/screenshots"))
DEFAULT_MAX_IMAGE_BYTES = int(os.getenv("WILLIAM_SCREENSHOT_MAX_BYTES", str(15 * 1024 * 1024)))
DEFAULT_IMAGE_FORMAT = "PNG"
DEFAULT_CONFIDENCE_FLOOR = 0.05

SENSITIVE_TEXT_PATTERNS = [
    re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),  # card-like number
    re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),  # SSN-like pattern
    re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),  # email
    re.compile(r"\b(?:password|passcode|secret|api[_-]?key|token|private[_-]?key)\b", re.I),
]

ERROR_KEYWORDS = [
    "error",
    "failed",
    "failure",
    "exception",
    "unauthorized",
    "forbidden",
    "invalid",
    "timeout",
    "crashed",
    "not responding",
    "access denied",
    "permission denied",
    "server error",
    "client error",
    "fatal",
    "traceback",
    "cannot",
    "unable",
    "blocked",
]

POPUP_KEYWORDS = [
    "ok",
    "cancel",
    "confirm",
    "continue",
    "allow",
    "deny",
    "yes",
    "no",
    "save",
    "discard",
    "close",
    "dismiss",
    "retry",
    "update",
    "install",
    "permission",
    "notification",
    "modal",
]

UI_KEYWORDS = [
    "button",
    "menu",
    "input",
    "search",
    "submit",
    "login",
    "logout",
    "dashboard",
    "settings",
    "profile",
    "home",
    "next",
    "back",
    "done",
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class ScreenshotContext:
    """
    SaaS-safe context for screenshot operations.

    user_id and workspace_id are required to prevent cross-user or cross-workspace
    data mixing. task_id/action_id are optional but recommended for traceability.
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
class CaptureOptions:
    """
    Options for safe screenshot capture.

    allow_system_capture:
        Must be True for real local screen capture. Even then, security approval
        can still deny the action.

    monitor_index:
        Used by mss when available. 1 is usually the primary monitor.
    """

    allow_system_capture: bool = False
    require_security_approval: bool = True
    capture_method: str = "auto"  # auto | pyautogui | mss
    region: Optional[Tuple[int, int, int, int]] = None  # left, top, width, height
    monitor_index: int = 1
    output_format: str = DEFAULT_IMAGE_FORMAT
    redact_sensitive: bool = False
    include_base64_preview: bool = False
    preview_max_bytes: int = 250_000
    max_image_bytes: int = DEFAULT_MAX_IMAGE_BYTES


@dataclasses.dataclass(frozen=True)
class AnalysisOptions:
    """
    Options for screenshot analysis.

    OCR is optional and only used when pytesseract is installed and enabled.
    Visual heuristics work without OCR.
    """

    enable_ocr: bool = False
    detect_errors: bool = True
    detect_popups: bool = True
    detect_ui_elements: bool = True
    redact_extracted_text: bool = True
    include_histogram: bool = False
    include_dimensions: bool = True
    include_image_hash: bool = True
    expected_text: Optional[Sequence[str]] = None
    unexpected_text: Optional[Sequence[str]] = None
    expected_ui_keywords: Optional[Sequence[str]] = None
    min_text_match_ratio: float = 0.75


@dataclasses.dataclass(frozen=True)
class CompareOptions:
    """
    Options for comparing two screenshots.
    """

    pixel_threshold: float = 0.02
    perceptual_threshold: float = 0.08
    resize_to_smallest: bool = True
    include_diff_image: bool = False
    diff_output_format: str = DEFAULT_IMAGE_FORMAT


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class ScreenshotChecker(BaseAgent):
    """
    Screenshot capture and analysis helper for the Verification Agent.

    Public methods:
        - capture_screen()
        - analyze_screenshot()
        - confirm_error()
        - confirm_popup()
        - confirm_ui_state()
        - compare_screenshots()
        - verify_from_file()
        - verify_from_capture()
        - clean_old_artifacts()

    Every public operation returns a structured dict:
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
        agent_name: str = "ScreenshotChecker",
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
        self.agent_id = "verification.screenshot_checker"
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
            self.logger.warning("Could not create screenshot output root %s: %s", self.output_root, exc)

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: Union[ScreenshotContext, Mapping[str, Any]]) -> ScreenshotContext:
        """
        Validate and normalize task context.

        Raises:
            ValueError: when user_id or workspace_id is missing/invalid.
        """
        if isinstance(context, ScreenshotContext):
            ctx = context
        elif isinstance(context, Mapping):
            ctx = ScreenshotContext(
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
            raise ValueError("context must be ScreenshotContext or mapping")

        if not ctx.user_id:
            raise ValueError("user_id is required for screenshot verification")
        if not ctx.workspace_id:
            raise ValueError("workspace_id is required for screenshot verification")
        if not self._is_safe_identifier(ctx.user_id):
            raise ValueError("user_id contains unsafe characters")
        if not self._is_safe_identifier(ctx.workspace_id):
            raise ValueError("workspace_id contains unsafe characters")

        return ctx

    def _requires_security_check(self, operation: str, options: Optional[Any] = None) -> bool:
        """
        Decide whether an operation requires Security Agent approval.
        """
        operation = (operation or "").lower().strip()
        if operation in {"capture_screen", "verify_from_capture", "system_capture"}:
            return True

        if isinstance(options, CaptureOptions):
            return bool(options.require_security_approval)

        if isinstance(options, Mapping):
            return bool(options.get("require_security_approval", False))

        return False

    def _request_security_approval(
        self,
        operation: str,
        context: ScreenshotContext,
        reason: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Ask Security Agent for approval if available.

        Fallback behavior:
            If no security_agent is attached, allow only non-system operations.
            System screenshot capture remains denied unless explicit local fallback
            approval is allowed by environment variable:
                WILLIAM_ALLOW_SCREENSHOT_WITHOUT_SECURITY=true
        """
        approval_payload = {
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
                        response = method(approval_payload)
                        normalized = self._normalize_security_response(response)
                        self._log_audit_event(
                            context=context,
                            event_type="security_approval_checked",
                            details={
                                "operation": operation,
                                "approved": normalized.get("approved"),
                                "reason": normalized.get("reason"),
                            },
                        )
                        return normalized
                    except Exception as exc:
                        self.logger.exception("Security approval call failed: %s", exc)
                        return {
                            "approved": False,
                            "reason": "security_agent_error",
                            "details": {"exception": str(exc)},
                        }

        fallback_allowed = os.getenv("WILLIAM_ALLOW_SCREENSHOT_WITHOUT_SECURITY", "false").lower() == "true"
        if operation in {"capture_screen", "verify_from_capture", "system_capture"} and not fallback_allowed:
            return {
                "approved": False,
                "reason": "security_agent_required_for_screen_capture",
                "details": {
                    "message": "Real screen capture is denied because no Security Agent approval is available."
                },
            }

        return {
            "approved": True,
            "reason": "fallback_non_sensitive_operation_allowed",
            "details": {},
        }

    def _prepare_verification_payload(
        self,
        context: ScreenshotContext,
        verification_type: str,
        evidence: Dict[str, Any],
        status: str,
        confidence: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Verification Agent compatible payload.
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
        context: ScreenshotContext,
        event_type: str,
        summary: str,
        data: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Memory Agent compatible payload.

        Only stores evidence references and safe summaries by default, not raw
        screenshot bytes.
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
        context: ScreenshotContext,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit an agent event to the configured event bus or fallback BaseAgent.
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
            self.logger.debug("Event emit failed for %s: %s", event_name, exc)

    def _log_audit_event(
        self,
        context: ScreenshotContext,
        event_type: str,
        details: Optional[Dict[str, Any]] = None,
        severity: str = "info",
    ) -> None:
        """
        Log audit event without leaking raw screenshots.
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
            self.logger.debug("Audit logging failed: %s", exc)

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard successful/neutral result structure.
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
        code: str = "screenshot_checker_error",
        exception: Optional[BaseException] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result structure.
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

    def capture_screen(
        self,
        context: Union[ScreenshotContext, Mapping[str, Any]],
        options: Optional[Union[CaptureOptions, Mapping[str, Any]]] = None,
        label: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Capture the current screen to an isolated screenshot artifact.

        Security:
            Requires allow_system_capture=True and security approval unless
            explicitly configured otherwise.

        Returns:
            Structured result with screenshot path, hash, dimensions, and
            verification/memory payloads.
        """
        try:
            ctx = self._validate_task_context(context)
            opts = self._normalize_capture_options(options)
            capture_label = self._safe_slug(label or "screen_capture")

            if not opts.allow_system_capture:
                return self._error_result(
                    message="System screenshot capture is disabled. Set allow_system_capture=True after permission approval.",
                    code="system_capture_disabled",
                    metadata={"agent": self.agent_id},
                )

            if self._requires_security_check("capture_screen", opts):
                approval = self._request_security_approval(
                    operation="capture_screen",
                    context=ctx,
                    reason="Capture screenshot for verification evidence.",
                    metadata={
                        "capture_method": opts.capture_method,
                        "region": opts.region,
                        "redact_sensitive": opts.redact_sensitive,
                    },
                )
                if not approval.get("approved"):
                    return self._error_result(
                        message="Screenshot capture denied by security policy.",
                        code="security_approval_denied",
                        data={"approval": approval},
                        metadata={"agent": self.agent_id},
                    )

            with self._lock:
                image_obj = self._capture_image(opts)
                if image_obj is None:
                    return self._error_result(
                        message="No screenshot backend is available. Install pillow plus pyautogui or mss.",
                        code="screenshot_backend_unavailable",
                        metadata=self._dependency_metadata(),
                    )

                if opts.redact_sensitive:
                    image_obj = self._redact_image_basic(image_obj)

                output_path = self._build_output_path(ctx, capture_label, opts.output_format)
                self._save_image(image_obj, output_path, opts.output_format, opts.max_image_bytes)

                image_info = self._image_info(output_path)
                if opts.include_base64_preview:
                    image_info["base64_preview"] = self._base64_preview(output_path, opts.preview_max_bytes)

                evidence = {
                    "artifact_type": "screenshot",
                    "path": str(output_path),
                    "sha256": image_info.get("sha256"),
                    "dimensions": image_info.get("dimensions"),
                    "format": image_info.get("format"),
                    "capture_method": opts.capture_method,
                    "region": opts.region,
                }

                verification_payload = self._prepare_verification_payload(
                    context=ctx,
                    verification_type="screenshot_capture",
                    evidence=evidence,
                    status="captured",
                    confidence=0.95,
                    metadata={"label": capture_label},
                )

                memory_payload = self._prepare_memory_payload(
                    context=ctx,
                    event_type="screenshot_captured",
                    summary=f"Screenshot captured for {capture_label}.",
                    data={
                        "path": str(output_path),
                        "sha256": image_info.get("sha256"),
                        "dimensions": image_info.get("dimensions"),
                    },
                    metadata={"label": capture_label},
                )

                self._emit_agent_event(
                    "verification.screenshot.captured",
                    ctx,
                    {"path": str(output_path), "sha256": image_info.get("sha256")},
                )
                self._log_audit_event(
                    ctx,
                    "screenshot_captured",
                    {
                        "path": str(output_path),
                        "sha256": image_info.get("sha256"),
                        "capture_method": opts.capture_method,
                        "redacted": opts.redact_sensitive,
                    },
                )

                return self._safe_result(
                    True,
                    "Screenshot captured successfully.",
                    data={
                        "screenshot": image_info,
                        "verification_payload": verification_payload,
                        "memory_payload": memory_payload,
                    },
                    metadata={"agent": self.agent_id},
                )

        except Exception as exc:
            self.logger.exception("capture_screen failed")
            return self._error_result(
                message="Screenshot capture failed.",
                code="capture_screen_failed",
                exception=exc,
                metadata={"agent": self.agent_id},
            )

    def analyze_screenshot(
        self,
        context: Union[ScreenshotContext, Mapping[str, Any]],
        image_path: Union[str, Path],
        options: Optional[Union[AnalysisOptions, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze an existing screenshot.

        Detects:
            - Dimensions and image hash
            - Brightness/contrast
            - OCR text when enabled and available
            - Error text signals
            - Popup/modal visual signals
            - UI keyword signals
            - Sensitive text signals, with optional redaction
        """
        try:
            ctx = self._validate_task_context(context)
            opts = self._normalize_analysis_options(options)
            safe_path = self._validate_readable_image_path(image_path)

            image_info = self._image_info(safe_path)
            image_obj = self._open_image(safe_path)

            extracted_text = ""
            ocr_available = pytesseract is not None and Image is not None
            if opts.enable_ocr and ocr_available:
                extracted_text = self._extract_text_ocr(image_obj)
            elif opts.enable_ocr and not ocr_available:
                self.logger.debug("OCR requested but pytesseract/PIL is unavailable.")

            raw_text_for_detection = extracted_text or ""
            redacted_text = self._redact_text(raw_text_for_detection) if opts.redact_extracted_text else raw_text_for_detection

            sensitive_hits = self._detect_sensitive_text(raw_text_for_detection)
            error_signals = self._detect_error_signals(raw_text_for_detection) if opts.detect_errors else []
            popup_signals = self._detect_popup_signals(image_obj, raw_text_for_detection) if opts.detect_popups else []
            ui_signals = self._detect_ui_signals(raw_text_for_detection, opts.expected_ui_keywords) if opts.detect_ui_elements else []

            expected_text_result = self._match_expected_text(
                raw_text_for_detection,
                opts.expected_text or [],
                opts.min_text_match_ratio,
            )
            unexpected_text_result = self._match_unexpected_text(
                raw_text_for_detection,
                opts.unexpected_text or [],
                opts.min_text_match_ratio,
            )

            visual_metrics = self._visual_metrics(image_obj, include_histogram=opts.include_histogram)

            confidence = self._calculate_analysis_confidence(
                has_image=True,
                ocr_enabled=opts.enable_ocr,
                ocr_text=raw_text_for_detection,
                expected_text_result=expected_text_result,
                unexpected_text_result=unexpected_text_result,
                error_signals=error_signals,
                popup_signals=popup_signals,
                ui_signals=ui_signals,
            )

            status = "analyzed"
            if unexpected_text_result.get("matched"):
                status = "unexpected_text_detected"
            elif expected_text_result.get("total", 0) > 0 and not expected_text_result.get("all_matched"):
                status = "expected_text_missing"
            elif error_signals:
                status = "error_evidence_detected"
            elif popup_signals:
                status = "popup_evidence_detected"

            evidence = {
                "artifact_type": "screenshot_analysis",
                "path": str(safe_path),
                "image": image_info,
                "text": {
                    "ocr_enabled": opts.enable_ocr,
                    "ocr_available": ocr_available,
                    "extracted_text": redacted_text,
                    "sensitive_hits": sensitive_hits,
                },
                "signals": {
                    "errors": error_signals,
                    "popups": popup_signals,
                    "ui": ui_signals,
                    "expected_text": expected_text_result,
                    "unexpected_text": unexpected_text_result,
                },
                "visual_metrics": visual_metrics,
            }

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                verification_type="screenshot_analysis",
                evidence=evidence,
                status=status,
                confidence=confidence,
                metadata={"image_path": str(safe_path)},
            )

            memory_payload = self._prepare_memory_payload(
                context=ctx,
                event_type="screenshot_analyzed",
                summary=f"Screenshot analyzed with status: {status}.",
                data={
                    "path": str(safe_path),
                    "status": status,
                    "confidence": confidence,
                    "error_signal_count": len(error_signals),
                    "popup_signal_count": len(popup_signals),
                    "ui_signal_count": len(ui_signals),
                },
            )

            self._emit_agent_event(
                "verification.screenshot.analyzed",
                ctx,
                {"path": str(safe_path), "status": status, "confidence": confidence},
            )
            self._log_audit_event(
                ctx,
                "screenshot_analyzed",
                {
                    "path": str(safe_path),
                    "status": status,
                    "confidence": confidence,
                    "ocr_enabled": opts.enable_ocr,
                },
            )

            return self._safe_result(
                True,
                "Screenshot analyzed successfully.",
                data={
                    "status": status,
                    "confidence": confidence,
                    "analysis": evidence,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={"agent": self.agent_id},
            )

        except Exception as exc:
            self.logger.exception("analyze_screenshot failed")
            return self._error_result(
                message="Screenshot analysis failed.",
                code="analyze_screenshot_failed",
                exception=exc,
                metadata={"agent": self.agent_id},
            )

    def confirm_error(
        self,
        context: Union[ScreenshotContext, Mapping[str, Any]],
        image_path: Union[str, Path],
        expected_error_terms: Optional[Sequence[str]] = None,
        enable_ocr: bool = True,
    ) -> Dict[str, Any]:
        """
        Confirm whether a screenshot contains error evidence.
        """
        expected_terms = list(expected_error_terms or ERROR_KEYWORDS)
        result = self.analyze_screenshot(
            context=context,
            image_path=image_path,
            options=AnalysisOptions(
                enable_ocr=enable_ocr,
                detect_errors=True,
                detect_popups=False,
                detect_ui_elements=False,
                expected_text=expected_terms,
                redact_extracted_text=True,
                min_text_match_ratio=0.70,
            ),
        )

        if not result.get("success"):
            return result

        analysis = result["data"].get("analysis", {})
        error_signals = analysis.get("signals", {}).get("errors", [])
        expected_text = analysis.get("signals", {}).get("expected_text", {})

        confirmed = bool(error_signals or expected_text.get("matched"))
        confidence = 0.90 if confirmed else 0.35
        ctx = self._validate_task_context(context)

        payload = self._prepare_verification_payload(
            context=ctx,
            verification_type="error_confirmation",
            evidence={
                "path": str(image_path),
                "confirmed": confirmed,
                "error_signals": error_signals,
                "expected_text": expected_text,
            },
            status="confirmed" if confirmed else "not_confirmed",
            confidence=confidence,
        )

        return self._safe_result(
            True,
            "Error evidence confirmed." if confirmed else "No clear error evidence found.",
            data={
                "confirmed": confirmed,
                "confidence": confidence,
                "error_signals": error_signals,
                "verification_payload": payload,
            },
            metadata={"agent": self.agent_id},
        )

    def confirm_popup(
        self,
        context: Union[ScreenshotContext, Mapping[str, Any]],
        image_path: Union[str, Path],
        expected_popup_terms: Optional[Sequence[str]] = None,
        enable_ocr: bool = True,
    ) -> Dict[str, Any]:
        """
        Confirm whether a screenshot likely contains a popup/modal/dialog.
        """
        expected_terms = list(expected_popup_terms or POPUP_KEYWORDS)
        result = self.analyze_screenshot(
            context=context,
            image_path=image_path,
            options=AnalysisOptions(
                enable_ocr=enable_ocr,
                detect_errors=False,
                detect_popups=True,
                detect_ui_elements=True,
                expected_text=expected_terms,
                redact_extracted_text=True,
                min_text_match_ratio=0.70,
            ),
        )

        if not result.get("success"):
            return result

        analysis = result["data"].get("analysis", {})
        popup_signals = analysis.get("signals", {}).get("popups", [])
        expected_text = analysis.get("signals", {}).get("expected_text", {})

        confirmed = bool(popup_signals or expected_text.get("matched"))
        confidence = 0.88 if confirmed else 0.40
        ctx = self._validate_task_context(context)

        payload = self._prepare_verification_payload(
            context=ctx,
            verification_type="popup_confirmation",
            evidence={
                "path": str(image_path),
                "confirmed": confirmed,
                "popup_signals": popup_signals,
                "expected_text": expected_text,
            },
            status="confirmed" if confirmed else "not_confirmed",
            confidence=confidence,
        )

        return self._safe_result(
            True,
            "Popup evidence confirmed." if confirmed else "No clear popup evidence found.",
            data={
                "confirmed": confirmed,
                "confidence": confidence,
                "popup_signals": popup_signals,
                "verification_payload": payload,
            },
            metadata={"agent": self.agent_id},
        )

    def confirm_ui_state(
        self,
        context: Union[ScreenshotContext, Mapping[str, Any]],
        image_path: Union[str, Path],
        expected_text: Optional[Sequence[str]] = None,
        expected_ui_keywords: Optional[Sequence[str]] = None,
        unexpected_text: Optional[Sequence[str]] = None,
        enable_ocr: bool = True,
    ) -> Dict[str, Any]:
        """
        Confirm expected UI state from a screenshot using OCR and visual signals.
        """
        result = self.analyze_screenshot(
            context=context,
            image_path=image_path,
            options=AnalysisOptions(
                enable_ocr=enable_ocr,
                detect_errors=True,
                detect_popups=True,
                detect_ui_elements=True,
                expected_text=expected_text or [],
                unexpected_text=unexpected_text or [],
                expected_ui_keywords=expected_ui_keywords or [],
                redact_extracted_text=True,
                min_text_match_ratio=0.74,
            ),
        )

        if not result.get("success"):
            return result

        analysis = result["data"].get("analysis", {})
        signals = analysis.get("signals", {})
        expected_result = signals.get("expected_text", {})
        unexpected_result = signals.get("unexpected_text", {})
        ui_signals = signals.get("ui", [])
        error_signals = signals.get("errors", [])

        expected_total = int(expected_result.get("total", 0))
        expected_ok = expected_total == 0 or bool(expected_result.get("all_matched"))
        unexpected_ok = not bool(unexpected_result.get("matched"))
        ui_ok = True if not expected_ui_keywords else bool(ui_signals)
        error_ok = not bool(error_signals)

        confirmed = bool(expected_ok and unexpected_ok and ui_ok and error_ok)

        confidence = self._clamp_confidence(
            0.30
            + (0.25 if expected_ok else 0.0)
            + (0.20 if unexpected_ok else 0.0)
            + (0.15 if ui_ok else 0.0)
            + (0.10 if error_ok else 0.0)
        )

        ctx = self._validate_task_context(context)
        payload = self._prepare_verification_payload(
            context=ctx,
            verification_type="ui_state_confirmation",
            evidence={
                "path": str(image_path),
                "confirmed": confirmed,
                "expected_text": expected_result,
                "unexpected_text": unexpected_result,
                "ui_signals": ui_signals,
                "error_signals": error_signals,
            },
            status="confirmed" if confirmed else "not_confirmed",
            confidence=confidence,
        )

        return self._safe_result(
            True,
            "UI state confirmed." if confirmed else "UI state could not be fully confirmed.",
            data={
                "confirmed": confirmed,
                "confidence": confidence,
                "expected_ok": expected_ok,
                "unexpected_ok": unexpected_ok,
                "ui_ok": ui_ok,
                "error_ok": error_ok,
                "verification_payload": payload,
            },
            metadata={"agent": self.agent_id},
        )

    def compare_screenshots(
        self,
        context: Union[ScreenshotContext, Mapping[str, Any]],
        before_image_path: Union[str, Path],
        after_image_path: Union[str, Path],
        options: Optional[Union[CompareOptions, Mapping[str, Any]]] = None,
        label: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Compare two screenshots and report visual change.

        Useful for action confirmation:
            - before click vs after click
            - page loaded vs previous page
            - popup appeared/disappeared
            - error appeared/disappeared
        """
        try:
            if Image is None or ImageChops is None or ImageStat is None:
                return self._error_result(
                    message="Pillow is required for screenshot comparison.",
                    code="pillow_required",
                    metadata=self._dependency_metadata(),
                )

            ctx = self._validate_task_context(context)
            opts = self._normalize_compare_options(options)
            before_path = self._validate_readable_image_path(before_image_path)
            after_path = self._validate_readable_image_path(after_image_path)

            before = self._open_image(before_path).convert("RGB")
            after = self._open_image(after_path).convert("RGB")

            if opts.resize_to_smallest and before.size != after.size:
                smallest = (min(before.width, after.width), min(before.height, after.height))
                before = before.resize(smallest)
                after = after.resize(smallest)

            if before.size != after.size:
                return self._error_result(
                    message="Screenshots have different dimensions and resize_to_smallest is disabled.",
                    code="dimension_mismatch",
                    data={"before_size": before.size, "after_size": after.size},
                )

            diff = ImageChops.difference(before, after)
            stat = ImageStat.Stat(diff)

            rms = sum(value ** 2 for value in stat.rms) ** 0.5
            normalized_rms = rms / (255.0 * (len(stat.rms) ** 0.5))
            bbox = diff.getbbox()
            changed = bbox is not None and normalized_rms >= opts.pixel_threshold

            diff_path = None
            if opts.include_diff_image:
                diff_label = self._safe_slug(label or "screenshot_diff")
                diff_path = self._build_output_path(ctx, diff_label, opts.diff_output_format)
                self._save_image(diff, diff_path, opts.diff_output_format, DEFAULT_MAX_IMAGE_BYTES)

            confidence = self._clamp_confidence(0.95 if changed else 0.75)
            evidence = {
                "artifact_type": "screenshot_comparison",
                "before_path": str(before_path),
                "after_path": str(after_path),
                "before_sha256": self._sha256_file(before_path),
                "after_sha256": self._sha256_file(after_path),
                "changed": changed,
                "normalized_rms": normalized_rms,
                "pixel_threshold": opts.pixel_threshold,
                "difference_bbox": bbox,
                "diff_path": str(diff_path) if diff_path else None,
                "dimensions": {"width": before.width, "height": before.height},
            }

            payload = self._prepare_verification_payload(
                context=ctx,
                verification_type="screenshot_comparison",
                evidence=evidence,
                status="changed" if changed else "unchanged",
                confidence=confidence,
            )

            self._emit_agent_event(
                "verification.screenshot.compared",
                ctx,
                {"changed": changed, "normalized_rms": normalized_rms},
            )
            self._log_audit_event(
                ctx,
                "screenshot_compared",
                {"changed": changed, "normalized_rms": normalized_rms},
            )

            return self._safe_result(
                True,
                "Screenshots compared successfully.",
                data={
                    "changed": changed,
                    "confidence": confidence,
                    "comparison": evidence,
                    "verification_payload": payload,
                },
                metadata={"agent": self.agent_id},
            )

        except Exception as exc:
            self.logger.exception("compare_screenshots failed")
            return self._error_result(
                message="Screenshot comparison failed.",
                code="compare_screenshots_failed",
                exception=exc,
                metadata={"agent": self.agent_id},
            )

    def verify_from_file(
        self,
        context: Union[ScreenshotContext, Mapping[str, Any]],
        image_path: Union[str, Path],
        expected_text: Optional[Sequence[str]] = None,
        unexpected_text: Optional[Sequence[str]] = None,
        expected_ui_keywords: Optional[Sequence[str]] = None,
        enable_ocr: bool = True,
    ) -> Dict[str, Any]:
        """
        One-shot verification helper for an existing screenshot file.
        """
        return self.confirm_ui_state(
            context=context,
            image_path=image_path,
            expected_text=expected_text,
            unexpected_text=unexpected_text,
            expected_ui_keywords=expected_ui_keywords,
            enable_ocr=enable_ocr,
        )

    def verify_from_capture(
        self,
        context: Union[ScreenshotContext, Mapping[str, Any]],
        capture_options: Optional[Union[CaptureOptions, Mapping[str, Any]]] = None,
        analysis_options: Optional[Union[AnalysisOptions, Mapping[str, Any]]] = None,
        label: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Capture then analyze a screenshot in one call.
        """
        ctx = self._validate_task_context(context)

        capture_result = self.capture_screen(ctx, capture_options, label=label or "verify_capture")
        if not capture_result.get("success"):
            return capture_result

        screenshot_path = capture_result["data"]["screenshot"]["path"]
        analysis_result = self.analyze_screenshot(ctx, screenshot_path, analysis_options)
        if not analysis_result.get("success"):
            return analysis_result

        combined_payload = self._prepare_verification_payload(
            context=ctx,
            verification_type="capture_and_analysis",
            evidence={
                "capture": capture_result["data"],
                "analysis": analysis_result["data"],
            },
            status=analysis_result["data"].get("status", "analyzed"),
            confidence=analysis_result["data"].get("confidence", 0.70),
        )

        return self._safe_result(
            True,
            "Screenshot captured and analyzed successfully.",
            data={
                "capture": capture_result["data"],
                "analysis": analysis_result["data"],
                "verification_payload": combined_payload,
            },
            metadata={"agent": self.agent_id},
        )

    def clean_old_artifacts(
        self,
        context: Union[ScreenshotContext, Mapping[str, Any]],
        older_than_days: int = 30,
        dry_run: bool = True,
    ) -> Dict[str, Any]:
        """
        Clean old screenshot artifacts for a single user/workspace.

        Safe behavior:
            - Scoped to user_id/workspace_id only.
            - dry_run=True by default.
            - Does not delete outside the configured screenshot root.
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
                    "No screenshot artifact directory exists for this user/workspace.",
                    data={"deleted": [], "dry_run": dry_run},
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
                            self.logger.warning("Could not delete old screenshot artifact %s: %s", item, exc)

            self._log_audit_event(
                ctx,
                "screenshot_artifacts_cleanup",
                {
                    "older_than_days": older_than_days,
                    "dry_run": dry_run,
                    "candidate_count": len(candidates),
                    "deleted_count": len(deleted),
                },
            )

            return self._safe_result(
                True,
                "Screenshot artifact cleanup completed." if not dry_run else "Screenshot artifact cleanup dry run completed.",
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
                message="Screenshot artifact cleanup failed.",
                code="clean_old_artifacts_failed",
                exception=exc,
                metadata={"agent": self.agent_id},
            )

    # ------------------------------------------------------------------
    # Capture internals
    # ------------------------------------------------------------------

    def _capture_image(self, options: CaptureOptions) -> Any:
        """
        Capture screenshot using selected backend.
        """
        method = (options.capture_method or "auto").lower()

        if method in {"auto", "mss"} and mss is not None:
            image_obj = self._capture_with_mss(options)
            if image_obj is not None:
                return image_obj

        if method in {"auto", "pyautogui"} and pyautogui is not None:
            image_obj = self._capture_with_pyautogui(options)
            if image_obj is not None:
                return image_obj

        return None

    def _capture_with_pyautogui(self, options: CaptureOptions) -> Any:
        if pyautogui is None:
            return None

        if options.region:
            left, top, width, height = options.region
            return pyautogui.screenshot(region=(left, top, width, height))

        return pyautogui.screenshot()

    def _capture_with_mss(self, options: CaptureOptions) -> Any:
        if mss is None or Image is None:
            return None

        with mss.mss() as sct:
            if options.region:
                left, top, width, height = options.region
                monitor = {"left": left, "top": top, "width": width, "height": height}
            else:
                monitors = sct.monitors
                index = options.monitor_index
                if index < 0 or index >= len(monitors):
                    index = 1 if len(monitors) > 1 else 0
                monitor = monitors[index]

            raw = sct.grab(monitor)
            return Image.frombytes("RGB", raw.size, raw.rgb)

    # ------------------------------------------------------------------
    # Analysis internals
    # ------------------------------------------------------------------

    def _extract_text_ocr(self, image_obj: Any) -> str:
        if pytesseract is None:
            return ""

        try:
            processed = image_obj
            if ImageOps is not None and ImageEnhance is not None:
                processed = ImageOps.grayscale(image_obj)
                processed = ImageEnhance.Contrast(processed).enhance(1.5)
            text = pytesseract.image_to_string(processed) or ""
            return text.strip()
        except Exception as exc:
            self.logger.debug("OCR extraction failed: %s", exc)
            return ""

    def _detect_error_signals(self, text: str) -> List[Dict[str, Any]]:
        lowered = (text or "").lower()
        signals: List[Dict[str, Any]] = []

        for keyword in ERROR_KEYWORDS:
            if keyword in lowered:
                signals.append(
                    {
                        "type": "error_keyword",
                        "keyword": keyword,
                        "confidence": 0.82,
                    }
                )

        traceback_like = bool(re.search(r"\b(traceback|stack trace|exception|line \d+)\b", lowered, re.I))
        if traceback_like:
            signals.append(
                {
                    "type": "traceback_like_text",
                    "keyword": "traceback_or_stack_trace",
                    "confidence": 0.90,
                }
            )

        status_code_match = re.search(r"\b(?:4\d{2}|5\d{2})\b", lowered)
        if status_code_match:
            signals.append(
                {
                    "type": "http_error_code",
                    "keyword": status_code_match.group(0),
                    "confidence": 0.78,
                }
            )

        return signals

    def _detect_popup_signals(self, image_obj: Any, text: str) -> List[Dict[str, Any]]:
        signals: List[Dict[str, Any]] = []
        lowered = (text or "").lower()

        for keyword in POPUP_KEYWORDS:
            if keyword in lowered:
                signals.append(
                    {
                        "type": "popup_text_keyword",
                        "keyword": keyword,
                        "confidence": 0.70,
                    }
                )

        visual_popup_score = self._estimate_modal_visual_score(image_obj)
        if visual_popup_score >= 0.55:
            signals.append(
                {
                    "type": "center_modal_visual_pattern",
                    "score": visual_popup_score,
                    "confidence": min(0.92, visual_popup_score),
                }
            )

        return signals

    def _detect_ui_signals(
        self,
        text: str,
        expected_ui_keywords: Optional[Sequence[str]] = None,
    ) -> List[Dict[str, Any]]:
        lowered = (text or "").lower()
        keywords = list(expected_ui_keywords or UI_KEYWORDS)
        signals: List[Dict[str, Any]] = []

        for keyword in keywords:
            clean_keyword = str(keyword).lower().strip()
            if clean_keyword and clean_keyword in lowered:
                signals.append(
                    {
                        "type": "ui_text_keyword",
                        "keyword": clean_keyword,
                        "confidence": 0.72,
                    }
                )

        return signals

    def _detect_sensitive_text(self, text: str) -> List[Dict[str, Any]]:
        hits: List[Dict[str, Any]] = []
        for pattern in SENSITIVE_TEXT_PATTERNS:
            for match in pattern.finditer(text or ""):
                hits.append(
                    {
                        "type": "sensitive_text_pattern",
                        "pattern": pattern.pattern,
                        "start": match.start(),
                        "end": match.end(),
                    }
                )
        return hits

    def _match_expected_text(
        self,
        text: str,
        expected: Sequence[str],
        min_ratio: float,
    ) -> Dict[str, Any]:
        normalized_text = self._normalize_text(text)
        matches: List[Dict[str, Any]] = []

        for item in expected:
            term = str(item).strip()
            if not term:
                continue

            normalized_term = self._normalize_text(term)
            direct_match = normalized_term in normalized_text
            ratio = 1.0 if direct_match else self._best_similarity(normalized_term, normalized_text)
            matched = direct_match or ratio >= min_ratio

            matches.append(
                {
                    "term": term,
                    "matched": matched,
                    "ratio": ratio,
                    "match_type": "direct" if direct_match else "fuzzy",
                }
            )

        total = len(matches)
        matched_count = sum(1 for item in matches if item["matched"])

        return {
            "total": total,
            "matched_count": matched_count,
            "all_matched": total == matched_count if total else False,
            "matched": matched_count > 0,
            "matches": matches,
        }

    def _match_unexpected_text(
        self,
        text: str,
        unexpected: Sequence[str],
        min_ratio: float,
    ) -> Dict[str, Any]:
        result = self._match_expected_text(text, unexpected, min_ratio)
        result["matched_unexpected_count"] = result.get("matched_count", 0)
        return result

    def _estimate_modal_visual_score(self, image_obj: Any) -> float:
        """
        Estimate whether an image has a centered modal-like shape.

        Uses lightweight heuristics:
            - Center region brightness/contrast difference from edges
            - Rectangular edge/border likelihood
        """
        if Image is None or ImageStat is None:
            return DEFAULT_CONFIDENCE_FLOOR

        try:
            img = image_obj.convert("L")
            width, height = img.size
            if width < 120 or height < 120:
                return 0.10

            center_box = (
                int(width * 0.20),
                int(height * 0.20),
                int(width * 0.80),
                int(height * 0.80),
            )
            edge_top = img.crop((0, 0, width, int(height * 0.15)))
            edge_bottom = img.crop((0, int(height * 0.85), width, height))
            edge_left = img.crop((0, 0, int(width * 0.15), height))
            edge_right = img.crop((int(width * 0.85), 0, width, height))
            center = img.crop(center_box)

            center_stat = ImageStat.Stat(center)
            edge_values = []
            for part in (edge_top, edge_bottom, edge_left, edge_right):
                edge_values.append(ImageStat.Stat(part).mean[0])

            center_mean = center_stat.mean[0]
            edge_mean = sum(edge_values) / max(len(edge_values), 1)
            brightness_delta = abs(center_mean - edge_mean) / 255.0

            center_variance = center_stat.var[0] / (255.0 * 255.0)
            score = min(1.0, (brightness_delta * 1.8) + min(center_variance * 3.0, 0.35))

            return self._clamp_confidence(score)
        except Exception:
            return DEFAULT_CONFIDENCE_FLOOR

    def _visual_metrics(self, image_obj: Any, include_histogram: bool = False) -> Dict[str, Any]:
        metrics: Dict[str, Any] = {}

        if ImageStat is None:
            return metrics

        try:
            gray = image_obj.convert("L")
            stat = ImageStat.Stat(gray)
            metrics["brightness_mean"] = float(stat.mean[0])
            metrics["brightness_median"] = float(stat.median[0])
            metrics["brightness_stddev"] = float(stat.stddev[0])
            metrics["contrast_score"] = float(stat.stddev[0]) / 255.0
            metrics["modal_visual_score"] = self._estimate_modal_visual_score(image_obj)

            if include_histogram:
                hist = gray.histogram()
                bucket_size = 16
                buckets = [
                    sum(hist[i : i + bucket_size])
                    for i in range(0, len(hist), bucket_size)
                ]
                metrics["histogram_16_bucket"] = buckets

            return metrics
        except Exception as exc:
            self.logger.debug("visual metrics failed: %s", exc)
            return metrics

    def _calculate_analysis_confidence(
        self,
        has_image: bool,
        ocr_enabled: bool,
        ocr_text: str,
        expected_text_result: Dict[str, Any],
        unexpected_text_result: Dict[str, Any],
        error_signals: Sequence[Dict[str, Any]],
        popup_signals: Sequence[Dict[str, Any]],
        ui_signals: Sequence[Dict[str, Any]],
    ) -> float:
        score = 0.25 if has_image else 0.0

        if ocr_enabled:
            score += 0.15 if ocr_text else 0.03
        else:
            score += 0.08

        if expected_text_result.get("total", 0) > 0:
            total = max(int(expected_text_result.get("total", 0)), 1)
            matched = int(expected_text_result.get("matched_count", 0))
            score += 0.30 * (matched / total)
        else:
            score += 0.10

        if unexpected_text_result.get("matched"):
            score -= 0.20
        else:
            score += 0.08

        if error_signals:
            score += min(0.15, 0.04 * len(error_signals))

        if popup_signals:
            score += min(0.12, 0.04 * len(popup_signals))

        if ui_signals:
            score += min(0.10, 0.03 * len(ui_signals))

        return self._clamp_confidence(score)

    # ------------------------------------------------------------------
    # File/image helpers
    # ------------------------------------------------------------------

    def _workspace_dir(self, context: ScreenshotContext) -> Path:
        return self.output_root / self._safe_slug(context.workspace_id) / self._safe_slug(context.user_id)

    def _build_output_path(self, context: ScreenshotContext, label: str, output_format: str) -> Path:
        output_dir = self._workspace_dir(context) / self._date_slug()
        output_dir.mkdir(parents=True, exist_ok=True)

        extension = self._format_to_extension(output_format)
        stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%H%M%S_%f")
        task_part = self._safe_slug(context.task_id or "task")
        action_part = self._safe_slug(context.action_id or "action")
        name = f"{stamp}_{task_part}_{action_part}_{self._safe_slug(label)}_{uuid.uuid4().hex[:8]}.{extension}"
        return output_dir / name

    def _save_image(self, image_obj: Any, path: Path, output_format: str, max_bytes: int) -> None:
        if Image is None:
            raise RuntimeError("Pillow is required to save screenshot images.")

        path.parent.mkdir(parents=True, exist_ok=True)

        fmt = self._normalize_image_format(output_format)
        image_obj.save(path, format=fmt)

        size = path.stat().st_size
        if size > max_bytes:
            try:
                path.unlink(missing_ok=True)
            except TypeError:
                if path.exists():
                    path.unlink()
            raise ValueError(f"Screenshot exceeds max_image_bytes: {size} > {max_bytes}")

    def _open_image(self, path: Union[str, Path]) -> Any:
        if Image is None:
            raise RuntimeError("Pillow is required to open screenshot images.")
        return Image.open(path)

    def _image_info(self, path: Union[str, Path]) -> Dict[str, Any]:
        p = Path(path)
        info: Dict[str, Any] = {
            "path": str(p),
            "filename": p.name,
            "size_bytes": p.stat().st_size if p.exists() else None,
            "sha256": self._sha256_file(p) if p.exists() else None,
        }

        if Image is not None and p.exists():
            try:
                with Image.open(p) as img:
                    info["format"] = img.format
                    info["mode"] = img.mode
                    info["dimensions"] = {
                        "width": img.width,
                        "height": img.height,
                    }
            except Exception as exc:
                info["image_read_error"] = str(exc)

        return info

    def _validate_readable_image_path(self, path: Union[str, Path]) -> Path:
        p = Path(path).expanduser().resolve()
        if not p.exists():
            raise FileNotFoundError(f"Screenshot file does not exist: {p}")
        if not p.is_file():
            raise ValueError(f"Screenshot path is not a file: {p}")

        size = p.stat().st_size
        if size <= 0:
            raise ValueError(f"Screenshot file is empty: {p}")
        if size > DEFAULT_MAX_IMAGE_BYTES:
            raise ValueError(f"Screenshot file exceeds max allowed size: {size}")

        suffix = p.suffix.lower()
        if suffix not in {".png", ".jpg", ".jpeg", ".webp", ".bmp"}:
            raise ValueError(f"Unsupported screenshot image extension: {suffix}")

        return p

    def _base64_preview(self, path: Union[str, Path], max_bytes: int) -> Optional[str]:
        p = Path(path)
        if not p.exists() or p.stat().st_size > max_bytes:
            return None

        try:
            raw = p.read_bytes()
            return base64.b64encode(raw).decode("ascii")
        except Exception:
            return None

    def _sha256_file(self, path: Union[str, Path]) -> str:
        h = hashlib.sha256()
        with Path(path).open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def _redact_image_basic(self, image_obj: Any) -> Any:
        """
        Basic privacy blur.

        This intentionally does not claim perfect PII redaction. It creates a
        safer visual artifact by slightly blurring text-heavy screenshots.
        """
        if ImageFilter is None:
            return image_obj
        try:
            return image_obj.filter(ImageFilter.GaussianBlur(radius=1.2))
        except Exception:
            return image_obj

    # ------------------------------------------------------------------
    # Normalization helpers
    # ------------------------------------------------------------------

    def _normalize_capture_options(
        self,
        options: Optional[Union[CaptureOptions, Mapping[str, Any]]],
    ) -> CaptureOptions:
        if options is None:
            return CaptureOptions()
        if isinstance(options, CaptureOptions):
            return options
        if not isinstance(options, Mapping):
            raise ValueError("capture options must be CaptureOptions or mapping")

        region = options.get("region")
        normalized_region = None
        if region is not None:
            if not isinstance(region, (list, tuple)) or len(region) != 4:
                raise ValueError("region must be a 4-item list/tuple: left, top, width, height")
            normalized_region = tuple(int(x) for x in region)  # type: ignore[assignment]
            if normalized_region[2] <= 0 or normalized_region[3] <= 0:
                raise ValueError("region width and height must be positive")

        return CaptureOptions(
            allow_system_capture=bool(options.get("allow_system_capture", False)),
            require_security_approval=bool(options.get("require_security_approval", True)),
            capture_method=str(options.get("capture_method", "auto")),
            region=normalized_region,
            monitor_index=int(options.get("monitor_index", 1)),
            output_format=str(options.get("output_format", DEFAULT_IMAGE_FORMAT)),
            redact_sensitive=bool(options.get("redact_sensitive", False)),
            include_base64_preview=bool(options.get("include_base64_preview", False)),
            preview_max_bytes=int(options.get("preview_max_bytes", 250_000)),
            max_image_bytes=int(options.get("max_image_bytes", DEFAULT_MAX_IMAGE_BYTES)),
        )

    def _normalize_analysis_options(
        self,
        options: Optional[Union[AnalysisOptions, Mapping[str, Any]]],
    ) -> AnalysisOptions:
        if options is None:
            return AnalysisOptions()
        if isinstance(options, AnalysisOptions):
            return options
        if not isinstance(options, Mapping):
            raise ValueError("analysis options must be AnalysisOptions or mapping")

        return AnalysisOptions(
            enable_ocr=bool(options.get("enable_ocr", False)),
            detect_errors=bool(options.get("detect_errors", True)),
            detect_popups=bool(options.get("detect_popups", True)),
            detect_ui_elements=bool(options.get("detect_ui_elements", True)),
            redact_extracted_text=bool(options.get("redact_extracted_text", True)),
            include_histogram=bool(options.get("include_histogram", False)),
            include_dimensions=bool(options.get("include_dimensions", True)),
            include_image_hash=bool(options.get("include_image_hash", True)),
            expected_text=list(options.get("expected_text") or []),
            unexpected_text=list(options.get("unexpected_text") or []),
            expected_ui_keywords=list(options.get("expected_ui_keywords") or []),
            min_text_match_ratio=float(options.get("min_text_match_ratio", 0.75)),
        )

    def _normalize_compare_options(
        self,
        options: Optional[Union[CompareOptions, Mapping[str, Any]]],
    ) -> CompareOptions:
        if options is None:
            return CompareOptions()
        if isinstance(options, CompareOptions):
            return options
        if not isinstance(options, Mapping):
            raise ValueError("compare options must be CompareOptions or mapping")

        return CompareOptions(
            pixel_threshold=float(options.get("pixel_threshold", 0.02)),
            perceptual_threshold=float(options.get("perceptual_threshold", 0.08)),
            resize_to_smallest=bool(options.get("resize_to_smallest", True)),
            include_diff_image=bool(options.get("include_diff_image", False)),
            diff_output_format=str(options.get("diff_output_format", DEFAULT_IMAGE_FORMAT)),
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

    def _normalize_image_format(self, image_format: str) -> str:
        value = (image_format or DEFAULT_IMAGE_FORMAT).upper().strip()
        if value in {"JPG", "JPEG"}:
            return "JPEG"
        if value in {"PNG", "WEBP", "BMP"}:
            return value
        return DEFAULT_IMAGE_FORMAT

    def _format_to_extension(self, image_format: str) -> str:
        fmt = self._normalize_image_format(image_format)
        return "jpg" if fmt == "JPEG" else fmt.lower()

    # ------------------------------------------------------------------
    # Utility helpers
    # ------------------------------------------------------------------

    def _optional_str(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _is_safe_identifier(self, value: str) -> bool:
        return bool(re.fullmatch(r"[A-Za-z0-9_.:@\-]{1,128}", value or ""))

    def _safe_slug(self, value: str) -> str:
        text = str(value or "unknown").strip()
        text = re.sub(r"[^A-Za-z0-9_.:@\-]+", "_", text)
        text = text.strip("._-")
        return text[:120] or "unknown"

    def _date_slug(self) -> str:
        return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")

    def _utc_now_iso(self) -> str:
        return _dt.datetime.now(_dt.timezone.utc).isoformat()

    def _clamp_confidence(self, value: float) -> float:
        try:
            value = float(value)
        except Exception:
            value = DEFAULT_CONFIDENCE_FLOOR
        return max(0.0, min(1.0, round(value, 4)))

    def _normalize_text(self, text: str) -> str:
        text = text or ""
        text = text.lower()
        text = re.sub(r"\s+", " ", text)
        text = re.sub(r"[^a-z0-9\s._:@/\-]+", "", text)
        return text.strip()

    def _best_similarity(self, needle: str, haystack: str) -> float:
        if not needle or not haystack:
            return 0.0

        if needle in haystack:
            return 1.0

        words = haystack.split()
        needle_words = needle.split()
        window = max(len(needle_words), 1)

        best = difflib.SequenceMatcher(None, needle, haystack[: max(len(needle) * 2, 1)]).ratio()

        for i in range(0, max(len(words) - window + 1, 1)):
            candidate = " ".join(words[i : i + window + 2])
            ratio = difflib.SequenceMatcher(None, needle, candidate).ratio()
            if ratio > best:
                best = ratio

        return round(best, 4)

    def _redact_text(self, text: str) -> str:
        redacted = text or ""
        for pattern in SENSITIVE_TEXT_PATTERNS:
            redacted = pattern.sub("[REDACTED]", redacted)
        return redacted

    def _is_path_inside(self, child: Path, parent: Path) -> bool:
        try:
            child_resolved = child.resolve()
            parent_resolved = parent.resolve()
            return str(child_resolved).startswith(str(parent_resolved))
        except Exception:
            return False

    def _dependency_metadata(self) -> Dict[str, Any]:
        return {
            "agent": self.agent_id,
            "dependencies": {
                "pillow": Image is not None,
                "pyautogui": pyautogui is not None,
                "mss": mss is not None,
                "pytesseract": pytesseract is not None,
                "opencv": cv2 is not None,
                "numpy": np is not None,
            },
        }


# ---------------------------------------------------------------------------
# Module-level convenience function
# ---------------------------------------------------------------------------

def get_screenshot_checker(**kwargs: Any) -> ScreenshotChecker:
    """
    Factory helper for Agent Loader / Registry integration.
    """
    return ScreenshotChecker(**kwargs)


__all__ = [
    "ScreenshotChecker",
    "ScreenshotContext",
    "CaptureOptions",
    "AnalysisOptions",
    "CompareOptions",
    "get_screenshot_checker",
]


# ---------------------------------------------------------------------------
# Lightweight self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    checker = ScreenshotChecker(output_root=Path(tempfile.gettempdir()) / "william_screenshot_checker_test")
    test_context = {
        "user_id": "test_user",
        "workspace_id": "test_workspace",
        "task_id": "test_task",
        "action_id": "test_action",
        "source_agent": "verification_agent",
    }

    print("Dependency metadata:")
    print(json.dumps(checker._dependency_metadata(), indent=2))

    if Image is not None:
        test_dir = Path(tempfile.gettempdir()) / "william_screenshot_checker_test_input"
        test_dir.mkdir(parents=True, exist_ok=True)
        test_image_path = test_dir / "sample_error.png"

        img = Image.new("RGB", (800, 400), color=(255, 255, 255))
        img.save(test_image_path, format="PNG")

        analysis = checker.analyze_screenshot(
            test_context,
            test_image_path,
            options={"enable_ocr": False, "detect_errors": True, "detect_popups": True},
        )
        print("Analysis self-test:")
        print(json.dumps(analysis, indent=2, default=str))
    else:
        print("Pillow is not installed, skipping image self-test.")

    print("FILE COMPLETE")