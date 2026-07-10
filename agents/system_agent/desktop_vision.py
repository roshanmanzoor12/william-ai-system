"""
agents/system_agent/desktop_vision.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Screen OCR and UI detection bridge for errors, popups, windows, buttons.

This module is part of the System Agent and is designed to be safely routed by:
    - Master Agent
    - Agent Router
    - Agent Registry
    - Agent Loader
    - Security Agent
    - Verification Agent
    - Memory Agent
    - Dashboard/API layer

Key responsibilities:
    - Capture desktop screenshots safely.
    - Run OCR on screenshots if OCR dependencies are available.
    - Detect UI text, error messages, popups, buttons, and window-like regions.
    - Return structured dict responses.
    - Support SaaS context isolation with user_id and workspace_id.
    - Avoid destructive or sensitive actions.
    - Prepare verification, memory, audit, and event payloads.

Safety:
    This file does not click, type, move windows, close windows, execute commands,
    read private files, or perform destructive operations.
    It only observes visual/screenshot data after context validation and optional
    security approval.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import os
import platform
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional dependency imports
# ---------------------------------------------------------------------------

try:
    from PIL import Image, ImageEnhance, ImageFilter, ImageOps
except Exception:  # pragma: no cover - optional dependency fallback
    Image = None  # type: ignore
    ImageEnhance = None  # type: ignore
    ImageFilter = None  # type: ignore
    ImageOps = None  # type: ignore

try:
    import pyautogui
except Exception:  # pragma: no cover - optional dependency fallback
    pyautogui = None  # type: ignore

try:
    import pytesseract
except Exception:  # pragma: no cover - optional dependency fallback
    pytesseract = None  # type: ignore

try:
    import cv2
except Exception:  # pragma: no cover - optional dependency fallback
    cv2 = None  # type: ignore

try:
    import numpy as np
except Exception:  # pragma: no cover - optional dependency fallback
    np = None  # type: ignore


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:
        """
        Fallback BaseAgent stub.

        Real William/Jarvis installations should provide:
            agents/base_agent.py

        This fallback keeps the file import-safe while other system files are
        still being generated.
        """

        agent_name = "desktop_vision"
        agent_type = "system_agent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = logging.getLogger(self.__class__.__name__)

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent does not implement run().")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("william.system_agent.desktop_vision")
if not logger.handlers:
    logging.basicConfig(
        level=os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Enums and data structures
# ---------------------------------------------------------------------------

class VisionAction(str, Enum):
    """Supported public action names for DesktopVision."""

    HEALTH = "health"
    CAPTURE_SCREEN = "capture_screen"
    OCR_SCREEN = "ocr_screen"
    ANALYZE_SCREEN = "analyze_screen"
    DETECT_ERRORS = "detect_errors"
    DETECT_POPUPS = "detect_popups"
    DETECT_BUTTONS = "detect_buttons"
    DETECT_WINDOWS = "detect_windows"
    FIND_TEXT = "find_text"
    EXTRACT_UI_SUMMARY = "extract_ui_summary"


class DetectionType(str, Enum):
    """Types of UI detections produced by DesktopVision."""

    TEXT = "text"
    ERROR = "error"
    WARNING = "warning"
    POPUP = "popup"
    BUTTON = "button"
    WINDOW = "window"
    DIALOG = "dialog"
    UNKNOWN = "unknown"


@dataclass
class BoundingBox:
    """Simple screen-space bounding box."""

    x: int
    y: int
    width: int
    height: int

    @property
    def right(self) -> int:
        return self.x + self.width

    @property
    def bottom(self) -> int:
        return self.y + self.height

    @property
    def center(self) -> Dict[str, int]:
        return {
            "x": self.x + self.width // 2,
            "y": self.y + self.height // 2,
        }

    def to_dict(self) -> Dict[str, int]:
        return {
            "x": int(self.x),
            "y": int(self.y),
            "width": int(self.width),
            "height": int(self.height),
            "right": int(self.right),
            "bottom": int(self.bottom),
            "center": self.center,
        }


@dataclass
class OCRTextBlock:
    """OCR text block returned from screen analysis."""

    text: str
    confidence: float
    bbox: BoundingBox
    line_number: Optional[int] = None
    word_number: Optional[int] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "text": self.text,
            "confidence": float(self.confidence),
            "bbox": self.bbox.to_dict(),
            "line_number": self.line_number,
            "word_number": self.word_number,
            "raw": self.raw,
        }


@dataclass
class UIDetection:
    """Detected UI object such as error, popup, button, window, or text."""

    detection_id: str
    detection_type: DetectionType
    label: str
    text: str
    confidence: float
    bbox: Optional[BoundingBox] = None
    severity: str = "info"
    evidence: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "type": self.detection_type.value,
            "label": self.label,
            "text": self.text,
            "confidence": float(self.confidence),
            "bbox": self.bbox.to_dict() if self.bbox else None,
            "severity": self.severity,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }


@dataclass
class DesktopVisionConfig:
    """
    DesktopVision runtime configuration.

    This config is intentionally safe by default.
    """

    allow_screen_capture: bool = True
    require_security_for_capture: bool = True
    save_debug_screenshots: bool = False
    debug_screenshot_dir: str = "runtime/desktop_vision"
    max_image_width: int = 1920
    max_image_height: int = 1080
    ocr_language: str = "eng"
    ocr_min_confidence: float = 35.0
    tesseract_config: str = "--oem 3 --psm 6"
    include_image_base64_by_default: bool = False
    redact_sensitive_text: bool = True
    max_ocr_blocks: int = 500
    max_detections: int = 200
    popup_keywords: Tuple[str, ...] = (
        "ok",
        "cancel",
        "yes",
        "no",
        "confirm",
        "continue",
        "close",
        "retry",
        "allow",
        "deny",
        "permission",
        "are you sure",
        "do you want",
        "save changes",
    )
    error_keywords: Tuple[str, ...] = (
        "error",
        "failed",
        "failure",
        "exception",
        "warning",
        "crash",
        "not responding",
        "cannot",
        "can't",
        "unable",
        "denied",
        "invalid",
        "missing",
        "blocked",
        "timeout",
        "timed out",
        "fatal",
        "access denied",
        "permission denied",
        "authentication failed",
        "connection refused",
        "not found",
    )
    button_keywords: Tuple[str, ...] = (
        "ok",
        "cancel",
        "submit",
        "save",
        "send",
        "close",
        "next",
        "back",
        "continue",
        "retry",
        "allow",
        "deny",
        "start",
        "stop",
        "pause",
        "resume",
        "login",
        "sign in",
        "sign up",
        "download",
        "upload",
        "apply",
        "reset",
        "delete",
        "edit",
        "create",
        "open",
    )
    window_keywords: Tuple[str, ...] = (
        "file",
        "edit",
        "view",
        "window",
        "settings",
        "preferences",
        "dashboard",
        "browser",
        "terminal",
        "explorer",
        "finder",
        "chrome",
        "firefox",
        "edge",
    )

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["popup_keywords"] = list(self.popup_keywords)
        data["error_keywords"] = list(self.error_keywords)
        data["button_keywords"] = list(self.button_keywords)
        data["window_keywords"] = list(self.window_keywords)
        return data


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return a UTC ISO timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    """Create a compact unique id."""
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert value to float."""
    try:
        return float(value)
    except Exception:
        return default


def _normalize_text(text: Any) -> str:
    """Normalize OCR/UI text for matching."""
    if text is None:
        return ""
    cleaned = str(text).replace("\x00", " ")
    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()


def _contains_any(text: str, keywords: Sequence[str]) -> bool:
    """Check whether normalized text contains any keyword."""
    lower = text.lower()
    return any(keyword.lower() in lower for keyword in keywords)


def _redact_sensitive_text(text: str) -> str:
    """
    Redact common sensitive values from OCR output.

    This protects accidental display of emails, phone numbers, access tokens,
    long keys, and obvious secrets in dashboard/log/memory payloads.
    """
    if not text:
        return text

    redacted = text

    redacted = re.sub(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "[REDACTED_EMAIL]",
        redacted,
    )

    redacted = re.sub(
        r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)",
        "[REDACTED_PHONE]",
        redacted,
    )

    redacted = re.sub(
        r"\b(?:api[_-]?key|token|secret|password|passwd|pwd)\s*[:=]\s*[^\s,;]+",
        lambda m: m.group(0).split(":")[0].split("=")[0] + "=[REDACTED_SECRET]",
        redacted,
        flags=re.IGNORECASE,
    )

    redacted = re.sub(
        r"\b[A-Za-z0-9_\-]{32,}\b",
        "[REDACTED_LONG_TOKEN]",
        redacted,
    )

    return redacted


def _dependency_status() -> Dict[str, bool]:
    """Return optional dependency availability."""
    return {
        "pillow": Image is not None,
        "pyautogui": pyautogui is not None,
        "pytesseract": pytesseract is not None,
        "opencv": cv2 is not None,
        "numpy": np is not None,
    }


# ---------------------------------------------------------------------------
# DesktopVision
# ---------------------------------------------------------------------------

class DesktopVision(BaseAgent):
    """
    Screen OCR and UI detection bridge.

    Public methods are safe and return structured dict results:
        - health()
        - capture_screen()
        - ocr_screen()
        - analyze_screen()
        - detect_errors()
        - detect_popups()
        - detect_buttons()
        - detect_windows()
        - find_text()
        - extract_ui_summary()
        - run()

    Master Agent / Router compatibility:
        The async run(task) method accepts a task dict and routes to matching
        public actions.

    Security Agent compatibility:
        `_requires_security_check()` and `_request_security_approval()` are
        provided. A real Security Agent can be injected through `security_client`.

    Verification Agent compatibility:
        `_prepare_verification_payload()` returns verification-ready metadata.

    Memory Agent compatibility:
        `_prepare_memory_payload()` returns safe summaries with optional redaction.

    Dashboard/API compatibility:
        Every method returns JSON-serializable dicts with:
            success, message, data, error, metadata
    """

    agent_name = "desktop_vision"
    agent_type = "system_agent"
    version = "1.0.0"

    def __init__(
        self,
        config: Optional[Union[DesktopVisionConfig, Dict[str, Any]]] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], Any]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], Any]] = None,
        logger_instance: Optional[logging.Logger] = None,
    ) -> None:
        super().__init__()

        if isinstance(config, DesktopVisionConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = self._build_config_from_dict(config)
        else:
            self.config = DesktopVisionConfig()

        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.logger = logger_instance or logger

        self._last_screenshot = None
        self._last_screenshot_metadata: Dict[str, Any] = {}
        self._last_ocr_blocks: List[OCRTextBlock] = []
        self._last_detections: List[UIDetection] = []

    # -----------------------------------------------------------------------
    # Config
    # -----------------------------------------------------------------------

    def _build_config_from_dict(self, data: Dict[str, Any]) -> DesktopVisionConfig:
        """Build config safely from dict."""
        defaults = DesktopVisionConfig()
        merged = defaults.to_dict()
        merged.update(data or {})

        tuple_fields = {
            "popup_keywords",
            "error_keywords",
            "button_keywords",
            "window_keywords",
        }

        for field_name in tuple_fields:
            value = merged.get(field_name)
            if isinstance(value, list):
                merged[field_name] = tuple(str(item) for item in value)
            elif isinstance(value, tuple):
                merged[field_name] = value
            else:
                merged[field_name] = getattr(defaults, field_name)

        allowed_keys = set(DesktopVisionConfig.__dataclass_fields__.keys())
        clean = {key: value for key, value in merged.items() if key in allowed_keys}
        return DesktopVisionConfig(**clean)

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(self, task_context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Every user/workspace-specific execution must include:
            - user_id
            - workspace_id

        This prevents cross-user or cross-workspace mixing of memory, logs,
        files, tasks, screenshots, analytics, and audit records.
        """
        context = task_context or {}

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="Missing required user_id in task context.",
                error_code="MISSING_USER_ID",
                metadata={
                    "hook": "_validate_task_context",
                    "required": ["user_id", "workspace_id"],
                },
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="Missing required workspace_id in task context.",
                error_code="MISSING_WORKSPACE_ID",
                metadata={
                    "hook": "_validate_task_context",
                    "required": ["user_id", "workspace_id"],
                },
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "request_id": str(context.get("request_id") or _new_id("req")),
                "session_id": str(context.get("session_id") or ""),
                "role": str(context.get("role") or ""),
                "permissions": context.get("permissions") or [],
            },
            metadata={"hook": "_validate_task_context"},
        )

    def _requires_security_check(
        self,
        action: str,
        task_context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Decide whether this action requires Security Agent approval.

        Screenshot capture and OCR can expose sensitive visible data, so they are
        protected when config.require_security_for_capture is enabled.
        """
        protected_actions = {
            VisionAction.CAPTURE_SCREEN.value,
            VisionAction.OCR_SCREEN.value,
            VisionAction.ANALYZE_SCREEN.value,
            VisionAction.DETECT_ERRORS.value,
            VisionAction.DETECT_POPUPS.value,
            VisionAction.DETECT_BUTTONS.value,
            VisionAction.DETECT_WINDOWS.value,
            VisionAction.FIND_TEXT.value,
            VisionAction.EXTRACT_UI_SUMMARY.value,
        }

        return bool(
            self.config.require_security_for_capture
            and action in protected_actions
        )

    def _request_security_approval(
        self,
        action: str,
        task_context: Optional[Dict[str, Any]] = None,
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent if available.

        If no external Security Agent is injected, this method applies safe local
        checks using the context permissions.
        """
        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result

        context = context_result["data"]
        permissions = set(str(p).lower() for p in context.get("permissions", []))

        approval_payload = {
            "action": action,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "reason": reason or "Desktop vision screen observation requested.",
            "risk_level": "medium",
            "user_id": context["user_id"],
            "workspace_id": context["workspace_id"],
            "request_id": context["request_id"],
            "metadata": metadata or {},
            "timestamp": _utc_now_iso(),
        }

        if self.security_client is not None:
            try:
                if hasattr(self.security_client, "approve"):
                    approved = self.security_client.approve(approval_payload)
                    if isinstance(approved, dict):
                        if approved.get("approved") is True or approved.get("success") is True:
                            return self._safe_result(
                                message="Security approval granted.",
                                data={"approved": True, "source": "security_client"},
                                metadata=approval_payload,
                            )
                        return self._error_result(
                            message="Security approval denied.",
                            error_code="SECURITY_DENIED",
                            data={"approved": False, "source": "security_client"},
                            metadata={"security_response": approved},
                        )

                if hasattr(self.security_client, "request_approval"):
                    approved = self.security_client.request_approval(approval_payload)
                    if isinstance(approved, dict):
                        if approved.get("approved") is True or approved.get("success") is True:
                            return self._safe_result(
                                message="Security approval granted.",
                                data={"approved": True, "source": "security_client"},
                                metadata=approval_payload,
                            )
                        return self._error_result(
                            message="Security approval denied.",
                            error_code="SECURITY_DENIED",
                            data={"approved": False, "source": "security_client"},
                            metadata={"security_response": approved},
                        )

            except Exception as exc:
                return self._error_result(
                    message="Security approval request failed.",
                    error_code="SECURITY_CLIENT_ERROR",
                    error=str(exc),
                    metadata=approval_payload,
                )

        local_allowed = (
            "desktop_vision" in permissions
            or "screen_read" in permissions
            or "screen_capture" in permissions
            or "system_agent" in permissions
            or "admin" in permissions
            or "owner" in permissions
        )

        if local_allowed:
            return self._safe_result(
                message="Local security approval granted from context permissions.",
                data={"approved": True, "source": "local_permission_check"},
                metadata=approval_payload,
            )

        return self._error_result(
            message=(
                "Security approval required for screen observation. "
                "Add one permission: desktop_vision, screen_read, screen_capture, "
                "system_agent, admin, or owner."
            ),
            error_code="SECURITY_PERMISSION_REQUIRED",
            data={"approved": False, "source": "local_permission_check"},
            metadata=approval_payload,
        )

    def _prepare_verification_payload(
        self,
        action: str,
        result: Dict[str, Any],
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        This payload helps the Verification Agent confirm that the screen analysis
        was observational only and produced structured data.
        """
        context = task_context or {}
        data = result.get("data") if isinstance(result, dict) else {}

        return {
            "verification_id": _new_id("verify"),
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "success": bool(result.get("success")) if isinstance(result, dict) else False,
            "user_id": str(context.get("user_id", "")),
            "workspace_id": str(context.get("workspace_id", "")),
            "request_id": str(context.get("request_id", "")),
            "observational_only": True,
            "destructive_action_performed": False,
            "requires_human_review": self._verification_requires_review(result),
            "evidence_summary": {
                "ocr_blocks": len(data.get("ocr_blocks", []) or []) if isinstance(data, dict) else 0,
                "detections": len(data.get("detections", []) or []) if isinstance(data, dict) else 0,
                "screenshot_captured": bool(data.get("screenshot")) if isinstance(data, dict) else False,
            },
            "timestamp": _utc_now_iso(),
            "metadata": {
                "module": "agents/system_agent/desktop_vision.py",
                "version": self.version,
            },
        }

    def _prepare_memory_payload(
        self,
        action: str,
        result: Dict[str, Any],
        task_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare safe Memory Agent payload.

        The payload avoids saving raw screenshot data by default. OCR text is
        summarized and optionally redacted.
        """
        context = task_context or {}
        data = result.get("data") if isinstance(result, dict) else {}

        text_summary = ""
        detections_summary: List[Dict[str, Any]] = []

        if isinstance(data, dict):
            ocr_text = data.get("text") or data.get("ocr_text") or ""
            if isinstance(ocr_text, str):
                text_summary = ocr_text[:2000]
                if self.config.redact_sensitive_text:
                    text_summary = _redact_sensitive_text(text_summary)

            for item in data.get("detections", []) or []:
                if not isinstance(item, dict):
                    continue
                item_text = str(item.get("text", ""))[:300]
                if self.config.redact_sensitive_text:
                    item_text = _redact_sensitive_text(item_text)

                detections_summary.append(
                    {
                        "type": item.get("type"),
                        "label": item.get("label"),
                        "severity": item.get("severity"),
                        "text": item_text,
                        "confidence": item.get("confidence"),
                    }
                )

        return {
            "memory_id": _new_id("mem"),
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "user_id": str(context.get("user_id", "")),
            "workspace_id": str(context.get("workspace_id", "")),
            "request_id": str(context.get("request_id", "")),
            "summary": {
                "screen_text_excerpt": text_summary,
                "detections": detections_summary[:50],
                "success": bool(result.get("success")) if isinstance(result, dict) else False,
            },
            "store_policy": {
                "save_raw_screenshot": False,
                "save_redacted_text_only": self.config.redact_sensitive_text,
                "workspace_isolated": True,
            },
            "timestamp": _utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        event_type: str,
        task_context: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit an agent event for dashboard/task history/analytics.

        This is non-blocking and safe. Failures are logged only.
        """
        context = task_context or {}

        event = {
            "event_id": _new_id("evt"),
            "event_type": event_type,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": str(context.get("user_id", "")),
            "workspace_id": str(context.get("workspace_id", "")),
            "request_id": str(context.get("request_id", "")),
            "data": data or {},
            "timestamp": _utc_now_iso(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                self.logger.debug("Agent event: %s", json.dumps(event, default=str))
        except Exception as exc:
            self.logger.warning("Failed to emit DesktopVision event: %s", exc)

    def _log_audit_event(
        self,
        action: str,
        task_context: Optional[Dict[str, Any]] = None,
        status: str = "info",
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log an audit event.

        Used for SaaS isolation, compliance, and sensitive-observation tracking.
        """
        context = task_context or {}

        audit_event = {
            "audit_id": _new_id("audit"),
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "status": status,
            "user_id": str(context.get("user_id", "")),
            "workspace_id": str(context.get("workspace_id", "")),
            "request_id": str(context.get("request_id", "")),
            "details": details or {},
            "timestamp": _utc_now_iso(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_event)
            else:
                self.logger.info("Audit event: %s", json.dumps(audit_event, default=str))
        except Exception as exc:
            self.logger.warning("Failed to write DesktopVision audit event: %s", exc)

    def _safe_result(
        self,
        message: str = "OK",
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis standard success result."""
        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str = "Error",
        error_code: str = "DESKTOP_VISION_ERROR",
        error: Optional[str] = None,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis standard error result."""
        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": {
                "code": error_code,
                "detail": error or message,
            },
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    # -----------------------------------------------------------------------
    # Public agent health
    # -----------------------------------------------------------------------

    def health(self, task_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Return DesktopVision health and dependency status."""
        deps = _dependency_status()

        return self._safe_result(
            message="DesktopVision health check complete.",
            data={
                "agent": self.agent_name,
                "status": "ready",
                "platform": platform.platform(),
                "python_dependencies": deps,
                "screen_capture_available": bool(deps["pyautogui"] and deps["pillow"]),
                "ocr_available": bool(deps["pytesseract"] and deps["pillow"]),
                "opencv_available": bool(deps["opencv"] and deps["numpy"]),
                "config": {
                    "allow_screen_capture": self.config.allow_screen_capture,
                    "require_security_for_capture": self.config.require_security_for_capture,
                    "ocr_language": self.config.ocr_language,
                    "ocr_min_confidence": self.config.ocr_min_confidence,
                    "redact_sensitive_text": self.config.redact_sensitive_text,
                },
            },
            metadata={"action": VisionAction.HEALTH.value},
        )

    # -----------------------------------------------------------------------
    # Screenshot handling
    # -----------------------------------------------------------------------

    def capture_screen(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        include_image_base64: Optional[bool] = None,
        save_debug: Optional[bool] = None,
        region: Optional[Tuple[int, int, int, int]] = None,
    ) -> Dict[str, Any]:
        """
        Capture current desktop screen.

        Args:
            task_context:
                Must contain user_id and workspace_id.
            include_image_base64:
                Return PNG base64 in result. Default follows config.
            save_debug:
                Save screenshot to debug folder if enabled.
            region:
                Optional region tuple: (x, y, width, height).

        Returns:
            Structured result with screenshot metadata and optional base64.
        """
        action = VisionAction.CAPTURE_SCREEN.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result

        if not self.config.allow_screen_capture:
            return self._error_result(
                message="Screen capture is disabled by DesktopVision configuration.",
                error_code="SCREEN_CAPTURE_DISABLED",
                metadata={"action": action},
            )

        if self._requires_security_check(action, task_context):
            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                reason="Capture current desktop screen for visual analysis.",
                metadata={"region": region},
            )
            if not approval.get("success"):
                return approval

        if pyautogui is None or Image is None:
            return self._error_result(
                message="Screen capture requires pyautogui and Pillow.",
                error_code="MISSING_SCREENSHOT_DEPENDENCIES",
                data={"dependencies": _dependency_status()},
                metadata={"action": action},
            )

        try:
            self._emit_agent_event(
                event_type="desktop_vision.capture.started",
                task_context=task_context,
                data={"region": region},
            )

            if region is not None:
                self._validate_region(region)
                screenshot = pyautogui.screenshot(region=region)
            else:
                screenshot = pyautogui.screenshot()

            screenshot = self._normalize_image_size(screenshot)

            width, height = screenshot.size
            image_bytes = self._image_to_png_bytes(screenshot)

            screenshot_id = _new_id("screen")
            debug_path = None

            should_save = (
                self.config.save_debug_screenshots
                if save_debug is None
                else bool(save_debug)
            )

            if should_save:
                debug_path = self._save_debug_screenshot(
                    screenshot=screenshot,
                    screenshot_id=screenshot_id,
                    task_context=task_context,
                )

            self._last_screenshot = screenshot
            self._last_screenshot_metadata = {
                "screenshot_id": screenshot_id,
                "width": width,
                "height": height,
                "mode": getattr(screenshot, "mode", None),
                "region": region,
                "debug_path": debug_path,
                "captured_at": _utc_now_iso(),
            }

            include_b64 = (
                self.config.include_image_base64_by_default
                if include_image_base64 is None
                else bool(include_image_base64)
            )

            screenshot_data: Dict[str, Any] = {
                "screenshot_id": screenshot_id,
                "width": width,
                "height": height,
                "mode": getattr(screenshot, "mode", None),
                "region": region,
                "debug_path": debug_path,
                "byte_size": len(image_bytes),
                "captured_at": self._last_screenshot_metadata["captured_at"],
            }

            if include_b64:
                screenshot_data["image_base64_png"] = base64.b64encode(image_bytes).decode("utf-8")

            result = self._safe_result(
                message="Screen captured successfully.",
                data={"screenshot": screenshot_data},
                metadata={"action": action},
            )

            self._log_audit_event(
                action=action,
                task_context=task_context,
                status="success",
                details={
                    "screenshot_id": screenshot_id,
                    "width": width,
                    "height": height,
                    "include_image_base64": include_b64,
                    "saved_debug": bool(debug_path),
                },
            )

            self._emit_agent_event(
                event_type="desktop_vision.capture.completed",
                task_context=task_context,
                data={"screenshot_id": screenshot_id, "width": width, "height": height},
            )

            return result

        except Exception as exc:
            self.logger.exception("DesktopVision capture_screen failed")
            self._log_audit_event(
                action=action,
                task_context=task_context,
                status="failed",
                details={"error": str(exc)},
            )
            return self._error_result(
                message="Failed to capture screen.",
                error_code="SCREEN_CAPTURE_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def _validate_region(self, region: Tuple[int, int, int, int]) -> None:
        """Validate screenshot region."""
        if not isinstance(region, tuple) or len(region) != 4:
            raise ValueError("region must be a tuple of (x, y, width, height).")

        x, y, width, height = region
        if min(x, y, width, height) < 0:
            raise ValueError("region values must be non-negative.")
        if width <= 0 or height <= 0:
            raise ValueError("region width and height must be greater than zero.")

    def _normalize_image_size(self, image: Any) -> Any:
        """Resize image if it exceeds configured maximum dimensions."""
        if Image is None:
            return image

        width, height = image.size
        max_w = int(self.config.max_image_width)
        max_h = int(self.config.max_image_height)

        if width <= max_w and height <= max_h:
            return image

        ratio = min(max_w / float(width), max_h / float(height))
        new_size = (max(1, int(width * ratio)), max(1, int(height * ratio)))
        return image.resize(new_size)

    def _image_to_png_bytes(self, image: Any) -> bytes:
        """Convert PIL image to PNG bytes."""
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()

    def _save_debug_screenshot(
        self,
        screenshot: Any,
        screenshot_id: str,
        task_context: Optional[Dict[str, Any]],
    ) -> str:
        """
        Save screenshot in workspace-isolated debug folder.

        Path format:
            runtime/desktop_vision/user_<id>/workspace_<id>/<screenshot_id>.png
        """
        context = task_context or {}
        user_id = re.sub(r"[^A-Za-z0-9_.-]", "_", str(context.get("user_id", "unknown")))
        workspace_id = re.sub(r"[^A-Za-z0-9_.-]", "_", str(context.get("workspace_id", "unknown")))

        base_dir = Path(self.config.debug_screenshot_dir)
        safe_dir = base_dir / f"user_{user_id}" / f"workspace_{workspace_id}"
        safe_dir.mkdir(parents=True, exist_ok=True)

        path = safe_dir / f"{screenshot_id}.png"
        screenshot.save(str(path), format="PNG")
        return str(path)

    # -----------------------------------------------------------------------
    # OCR
    # -----------------------------------------------------------------------

    def ocr_screen(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        image: Optional[Any] = None,
        capture_if_missing: bool = True,
        include_blocks: bool = True,
        preprocess: bool = True,
    ) -> Dict[str, Any]:
        """
        Run OCR on current screen or provided image.

        Args:
            task_context:
                Must contain user_id and workspace_id.
            image:
                Optional PIL image. If not provided, last screenshot or fresh
                screenshot can be used.
            capture_if_missing:
                Capture a fresh screenshot if no image is provided.
            include_blocks:
                Include OCR blocks in response.
            preprocess:
                Apply light OCR preprocessing.

        Returns:
            Structured OCR result.
        """
        action = VisionAction.OCR_SCREEN.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result

        if self._requires_security_check(action, task_context):
            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                reason="Read visible text from desktop screen using OCR.",
            )
            if not approval.get("success"):
                return approval

        if pytesseract is None or Image is None:
            return self._error_result(
                message="OCR requires pytesseract and Pillow.",
                error_code="MISSING_OCR_DEPENDENCIES",
                data={
                    "dependencies": _dependency_status(),
                    "install_hint": "pip install pillow pytesseract",
                    "system_hint": "Install Tesseract OCR binary and make it available in PATH.",
                },
                metadata={"action": action},
            )

        try:
            source_image = self._resolve_image_for_analysis(
                image=image,
                task_context=task_context,
                capture_if_missing=capture_if_missing,
            )

            if source_image is None:
                return self._error_result(
                    message="No image available for OCR.",
                    error_code="NO_IMAGE_AVAILABLE",
                    metadata={"action": action},
                )

            working_image = self._preprocess_for_ocr(source_image) if preprocess else source_image

            self._emit_agent_event(
                event_type="desktop_vision.ocr.started",
                task_context=task_context,
                data={"preprocess": preprocess},
            )

            text = pytesseract.image_to_string(
                working_image,
                lang=self.config.ocr_language,
                config=self.config.tesseract_config,
            )

            blocks = self._extract_ocr_blocks(working_image)
            joined_text = _normalize_text(text)

            if self.config.redact_sensitive_text:
                safe_text = _redact_sensitive_text(joined_text)
            else:
                safe_text = joined_text

            self._last_ocr_blocks = blocks

            result_data: Dict[str, Any] = {
                "ocr_text": safe_text,
                "text": safe_text,
                "raw_text_length": len(joined_text),
                "redacted": self.config.redact_sensitive_text,
                "block_count": len(blocks),
                "language": self.config.ocr_language,
                "min_confidence": self.config.ocr_min_confidence,
            }

            if include_blocks:
                result_data["ocr_blocks"] = [
                    self._safe_ocr_block_dict(block) for block in blocks[: self.config.max_ocr_blocks]
                ]

            result = self._safe_result(
                message="OCR completed successfully.",
                data=result_data,
                metadata={"action": action},
            )

            result["metadata"]["verification_payload"] = self._prepare_verification_payload(
                action=action,
                result=result,
                task_context=task_context,
            )
            result["metadata"]["memory_payload"] = self._prepare_memory_payload(
                action=action,
                result=result,
                task_context=task_context,
            )

            self._log_audit_event(
                action=action,
                task_context=task_context,
                status="success",
                details={
                    "block_count": len(blocks),
                    "text_length": len(safe_text),
                    "redacted": self.config.redact_sensitive_text,
                },
            )

            self._emit_agent_event(
                event_type="desktop_vision.ocr.completed",
                task_context=task_context,
                data={"block_count": len(blocks), "text_length": len(safe_text)},
            )

            return result

        except Exception as exc:
            self.logger.exception("DesktopVision ocr_screen failed")
            self._log_audit_event(
                action=action,
                task_context=task_context,
                status="failed",
                details={"error": str(exc)},
            )
            return self._error_result(
                message="OCR failed.",
                error_code="OCR_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def _resolve_image_for_analysis(
        self,
        image: Optional[Any],
        task_context: Optional[Dict[str, Any]],
        capture_if_missing: bool,
    ) -> Optional[Any]:
        """Resolve the image to analyze."""
        if image is not None:
            return image

        if self._last_screenshot is not None:
            return self._last_screenshot

        if capture_if_missing:
            capture = self.capture_screen(
                task_context=task_context,
                include_image_base64=False,
                save_debug=False,
            )
            if capture.get("success"):
                return self._last_screenshot

        return None

    def _preprocess_for_ocr(self, image: Any) -> Any:
        """
        Apply safe preprocessing to improve OCR.

        Uses Pillow only, so this remains lightweight.
        """
        if Image is None or ImageOps is None or ImageEnhance is None:
            return image

        try:
            img = image.convert("RGB")
            img = ImageOps.grayscale(img)
            img = ImageEnhance.Contrast(img).enhance(1.5)
            img = ImageEnhance.Sharpness(img).enhance(1.3)
            return img
        except Exception:
            return image

    def _extract_ocr_blocks(self, image: Any) -> List[OCRTextBlock]:
        """Extract OCR text blocks with bounding boxes using pytesseract."""
        if pytesseract is None:
            return []

        try:
            data = pytesseract.image_to_data(
                image,
                lang=self.config.ocr_language,
                config=self.config.tesseract_config,
                output_type=pytesseract.Output.DICT,
            )
        except Exception:
            return []

        blocks: List[OCRTextBlock] = []

        count = len(data.get("text", []) or [])

        for index in range(count):
            text = _normalize_text(data["text"][index])
            if not text:
                continue

            conf = _safe_float(data.get("conf", [0])[index], default=0.0)
            if conf < self.config.ocr_min_confidence:
                continue

            bbox = BoundingBox(
                x=int(data.get("left", [0])[index] or 0),
                y=int(data.get("top", [0])[index] or 0),
                width=int(data.get("width", [0])[index] or 0),
                height=int(data.get("height", [0])[index] or 0),
            )

            if bbox.width <= 0 or bbox.height <= 0:
                continue

            blocks.append(
                OCRTextBlock(
                    text=text,
                    confidence=conf,
                    bbox=bbox,
                    line_number=int(data.get("line_num", [0])[index] or 0),
                    word_number=int(data.get("word_num", [0])[index] or 0),
                    raw={
                        "block_num": data.get("block_num", [None])[index],
                        "par_num": data.get("par_num", [None])[index],
                        "line_num": data.get("line_num", [None])[index],
                        "word_num": data.get("word_num", [None])[index],
                    },
                )
            )

            if len(blocks) >= self.config.max_ocr_blocks:
                break

        return blocks

    def _safe_ocr_block_dict(self, block: OCRTextBlock) -> Dict[str, Any]:
        """Convert OCR block to dict with optional redaction."""
        item = block.to_dict()

        if self.config.redact_sensitive_text:
            item["text"] = _redact_sensitive_text(item["text"])

        return item

    # -----------------------------------------------------------------------
    # Analysis / detection
    # -----------------------------------------------------------------------

    def analyze_screen(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        image: Optional[Any] = None,
        capture_if_missing: bool = True,
        include_ocr_blocks: bool = True,
        include_screenshot: bool = False,
    ) -> Dict[str, Any]:
        """
        Capture/OCR/analyze screen and return a combined UI summary.
        """
        action = VisionAction.ANALYZE_SCREEN.value

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result

        if self._requires_security_check(action, task_context):
            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                reason="Analyze current desktop UI for errors, popups, buttons, and windows.",
            )
            if not approval.get("success"):
                return approval

        ocr_result = self.ocr_screen(
            task_context=task_context,
            image=image,
            capture_if_missing=capture_if_missing,
            include_blocks=True,
            preprocess=True,
        )

        if not ocr_result.get("success"):
            return ocr_result

        blocks = list(self._last_ocr_blocks)
        detections = self._detect_all_from_blocks(blocks)

        self._last_detections = detections

        text = ocr_result.get("data", {}).get("ocr_text", "")

        data: Dict[str, Any] = {
            "summary": self._build_ui_summary(text=text, detections=detections, blocks=blocks),
            "ocr_text": text,
            "text": text,
            "detections": [item.to_dict() for item in detections[: self.config.max_detections]],
            "counts": self._count_detections(detections),
            "risk": self._calculate_screen_risk(detections),
        }

        if include_ocr_blocks:
            data["ocr_blocks"] = [
                self._safe_ocr_block_dict(block) for block in blocks[: self.config.max_ocr_blocks]
            ]

        if include_screenshot and self._last_screenshot is not None:
            image_bytes = self._image_to_png_bytes(self._last_screenshot)
            data["screenshot"] = {
                **self._last_screenshot_metadata,
                "image_base64_png": base64.b64encode(image_bytes).decode("utf-8"),
            }

        result = self._safe_result(
            message="Screen analysis completed successfully.",
            data=data,
            metadata={"action": action},
        )

        result["metadata"]["verification_payload"] = self._prepare_verification_payload(
            action=action,
            result=result,
            task_context=task_context,
        )
        result["metadata"]["memory_payload"] = self._prepare_memory_payload(
            action=action,
            result=result,
            task_context=task_context,
        )

        self._log_audit_event(
            action=action,
            task_context=task_context,
            status="success",
            details={
                "detections": len(detections),
                "counts": self._count_detections(detections),
                "risk": data["risk"],
            },
        )

        return result

    def detect_errors(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        image: Optional[Any] = None,
        capture_if_missing: bool = True,
    ) -> Dict[str, Any]:
        """Detect error/warning text on screen."""
        return self._detect_specific(
            action=VisionAction.DETECT_ERRORS.value,
            detection_types={DetectionType.ERROR, DetectionType.WARNING},
            task_context=task_context,
            image=image,
            capture_if_missing=capture_if_missing,
        )

    def detect_popups(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        image: Optional[Any] = None,
        capture_if_missing: bool = True,
    ) -> Dict[str, Any]:
        """Detect popup/dialog-like UI text on screen."""
        return self._detect_specific(
            action=VisionAction.DETECT_POPUPS.value,
            detection_types={DetectionType.POPUP, DetectionType.DIALOG},
            task_context=task_context,
            image=image,
            capture_if_missing=capture_if_missing,
        )

    def detect_buttons(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        image: Optional[Any] = None,
        capture_if_missing: bool = True,
    ) -> Dict[str, Any]:
        """Detect button-like text on screen."""
        return self._detect_specific(
            action=VisionAction.DETECT_BUTTONS.value,
            detection_types={DetectionType.BUTTON},
            task_context=task_context,
            image=image,
            capture_if_missing=capture_if_missing,
        )

    def detect_windows(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        image: Optional[Any] = None,
        capture_if_missing: bool = True,
    ) -> Dict[str, Any]:
        """Detect window-like regions/text on screen."""
        return self._detect_specific(
            action=VisionAction.DETECT_WINDOWS.value,
            detection_types={DetectionType.WINDOW},
            task_context=task_context,
            image=image,
            capture_if_missing=capture_if_missing,
        )

    def _detect_specific(
        self,
        action: str,
        detection_types: Iterable[DetectionType],
        task_context: Optional[Dict[str, Any]],
        image: Optional[Any],
        capture_if_missing: bool,
    ) -> Dict[str, Any]:
        """Shared implementation for specific detection methods."""
        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result

        if self._requires_security_check(action, task_context):
            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                reason=f"Detect UI elements for action: {action}.",
            )
            if not approval.get("success"):
                return approval

        ocr_result = self.ocr_screen(
            task_context=task_context,
            image=image,
            capture_if_missing=capture_if_missing,
            include_blocks=True,
            preprocess=True,
        )

        if not ocr_result.get("success"):
            return ocr_result

        requested = set(detection_types)
        detections = [
            detection
            for detection in self._detect_all_from_blocks(self._last_ocr_blocks)
            if detection.detection_type in requested
        ]

        self._last_detections = detections

        result = self._safe_result(
            message=f"{action} completed successfully.",
            data={
                "detections": [item.to_dict() for item in detections[: self.config.max_detections]],
                "count": len(detections),
                "counts": self._count_detections(detections),
                "risk": self._calculate_screen_risk(detections),
            },
            metadata={"action": action},
        )

        result["metadata"]["verification_payload"] = self._prepare_verification_payload(
            action=action,
            result=result,
            task_context=task_context,
        )
        result["metadata"]["memory_payload"] = self._prepare_memory_payload(
            action=action,
            result=result,
            task_context=task_context,
        )

        self._log_audit_event(
            action=action,
            task_context=task_context,
            status="success",
            details={"count": len(detections), "counts": self._count_detections(detections)},
        )

        return result

    def _detect_all_from_blocks(self, blocks: List[OCRTextBlock]) -> List[UIDetection]:
        """Detect errors, popups, buttons, and windows from OCR blocks."""
        detections: List[UIDetection] = []

        line_groups = self._group_blocks_into_lines(blocks)

        for block in blocks:
            detections.extend(self._detect_from_text_block(block))

        for line_text, line_blocks in line_groups:
            detections.extend(self._detect_from_line(line_text, line_blocks))

        detections = self._dedupe_detections(detections)
        detections = sorted(
            detections,
            key=lambda item: (
                self._severity_rank(item.severity),
                -item.confidence,
                item.bbox.y if item.bbox else 999999,
                item.bbox.x if item.bbox else 999999,
            ),
        )

        return detections[: self.config.max_detections]

    def _detect_from_text_block(self, block: OCRTextBlock) -> List[UIDetection]:
        """Detect UI labels from a single OCR block."""
        detections: List[UIDetection] = []
        text = _normalize_text(block.text)
        if not text:
            return detections

        safe_text = _redact_sensitive_text(text) if self.config.redact_sensitive_text else text

        if _contains_any(text, self.config.error_keywords):
            dtype, severity = self._classify_error_severity(text)
            detections.append(
                UIDetection(
                    detection_id=_new_id("det"),
                    detection_type=dtype,
                    label="Possible error/warning text",
                    text=safe_text,
                    confidence=min(99.0, block.confidence + 5.0),
                    bbox=block.bbox,
                    severity=severity,
                    evidence=[safe_text],
                    metadata={"source": "ocr_block"},
                )
            )

        if self._is_button_text(text):
            detections.append(
                UIDetection(
                    detection_id=_new_id("det"),
                    detection_type=DetectionType.BUTTON,
                    label="Possible button",
                    text=safe_text,
                    confidence=min(95.0, block.confidence),
                    bbox=block.bbox,
                    severity="info",
                    evidence=[safe_text],
                    metadata={"source": "ocr_block"},
                )
            )

        return detections

    def _detect_from_line(
        self,
        line_text: str,
        line_blocks: List[OCRTextBlock],
    ) -> List[UIDetection]:
        """Detect larger UI patterns from grouped OCR lines."""
        detections: List[UIDetection] = []
        text = _normalize_text(line_text)
        if not text:
            return detections

        bbox = self._merge_block_bboxes(line_blocks)
        avg_conf = self._average_confidence(line_blocks)
        safe_text = _redact_sensitive_text(text) if self.config.redact_sensitive_text else text

        if _contains_any(text, self.config.popup_keywords) and len(text) <= 180:
            popup_confidence = min(93.0, avg_conf + 8.0)
            popup_type = DetectionType.DIALOG if self._looks_like_dialog_text(text) else DetectionType.POPUP

            detections.append(
                UIDetection(
                    detection_id=_new_id("det"),
                    detection_type=popup_type,
                    label="Possible popup/dialog",
                    text=safe_text,
                    confidence=popup_confidence,
                    bbox=bbox,
                    severity="medium",
                    evidence=[safe_text],
                    metadata={"source": "ocr_line"},
                )
            )

        if _contains_any(text, self.config.window_keywords) and len(text) <= 220:
            detections.append(
                UIDetection(
                    detection_id=_new_id("det"),
                    detection_type=DetectionType.WINDOW,
                    label="Possible active window/menu area",
                    text=safe_text,
                    confidence=min(85.0, avg_conf),
                    bbox=bbox,
                    severity="info",
                    evidence=[safe_text],
                    metadata={"source": "ocr_line"},
                )
            )

        if _contains_any(text, self.config.error_keywords):
            dtype, severity = self._classify_error_severity(text)
            detections.append(
                UIDetection(
                    detection_id=_new_id("det"),
                    detection_type=dtype,
                    label="Possible error/warning line",
                    text=safe_text,
                    confidence=min(98.0, avg_conf + 7.0),
                    bbox=bbox,
                    severity=severity,
                    evidence=[safe_text],
                    metadata={"source": "ocr_line"},
                )
            )

        return detections

    def _group_blocks_into_lines(
        self,
        blocks: List[OCRTextBlock],
        y_tolerance: int = 10,
    ) -> List[Tuple[str, List[OCRTextBlock]]]:
        """Group OCR blocks into approximate visual lines."""
        if not blocks:
            return []

        sorted_blocks = sorted(blocks, key=lambda b: (b.bbox.y, b.bbox.x))
        lines: List[List[OCRTextBlock]] = []

        for block in sorted_blocks:
            placed = False

            for line in lines:
                line_y = sum(item.bbox.y for item in line) / max(1, len(line))
                if abs(block.bbox.y - line_y) <= y_tolerance:
                    line.append(block)
                    placed = True
                    break

            if not placed:
                lines.append([block])

        grouped: List[Tuple[str, List[OCRTextBlock]]] = []

        for line in lines:
            line_sorted = sorted(line, key=lambda b: b.bbox.x)
            text = " ".join(item.text for item in line_sorted)
            grouped.append((_normalize_text(text), line_sorted))

        return grouped

    def _merge_block_bboxes(self, blocks: List[OCRTextBlock]) -> Optional[BoundingBox]:
        """Merge OCR block boxes into one bounding box."""
        if not blocks:
            return None

        left = min(block.bbox.x for block in blocks)
        top = min(block.bbox.y for block in blocks)
        right = max(block.bbox.right for block in blocks)
        bottom = max(block.bbox.bottom for block in blocks)

        return BoundingBox(
            x=int(left),
            y=int(top),
            width=int(right - left),
            height=int(bottom - top),
        )

    def _average_confidence(self, blocks: List[OCRTextBlock]) -> float:
        """Average OCR confidence."""
        if not blocks:
            return 0.0
        return sum(block.confidence for block in blocks) / len(blocks)

    def _is_button_text(self, text: str) -> bool:
        """Heuristic for identifying button-like text."""
        normalized = _normalize_text(text).lower()
        if not normalized:
            return False

        exact_buttons = {item.lower() for item in self.config.button_keywords}
        if normalized in exact_buttons:
            return True

        if len(normalized) <= 32 and _contains_any(normalized, self.config.button_keywords):
            return True

        return False

    def _looks_like_dialog_text(self, text: str) -> bool:
        """Heuristic for dialog-like confirmation messages."""
        lower = text.lower()
        dialog_patterns = (
            "are you sure",
            "do you want",
            "would you like",
            "confirm",
            "permission",
            "allow",
            "deny",
            "save changes",
            "before closing",
        )
        return any(pattern in lower for pattern in dialog_patterns)

    def _classify_error_severity(self, text: str) -> Tuple[DetectionType, str]:
        """Classify error/warning severity."""
        lower = text.lower()

        high_terms = (
            "fatal",
            "crash",
            "access denied",
            "permission denied",
            "authentication failed",
            "not responding",
            "connection refused",
            "cannot",
            "can't",
            "unable",
        )
        medium_terms = (
            "error",
            "failed",
            "failure",
            "invalid",
            "missing",
            "blocked",
            "timeout",
            "timed out",
        )
        warning_terms = ("warning", "caution", "attention")

        if any(term in lower for term in high_terms):
            return DetectionType.ERROR, "high"

        if any(term in lower for term in medium_terms):
            return DetectionType.ERROR, "medium"

        if any(term in lower for term in warning_terms):
            return DetectionType.WARNING, "medium"

        return DetectionType.WARNING, "low"

    def _dedupe_detections(self, detections: List[UIDetection]) -> List[UIDetection]:
        """Remove near-duplicate detections."""
        seen = set()
        unique: List[UIDetection] = []

        for detection in detections:
            bbox_key = None
            if detection.bbox:
                bbox_key = (
                    detection.bbox.x // 10,
                    detection.bbox.y // 10,
                    detection.bbox.width // 10,
                    detection.bbox.height // 10,
                )

            key = (
                detection.detection_type.value,
                detection.text.lower()[:120],
                bbox_key,
            )

            if key in seen:
                continue

            seen.add(key)
            unique.append(detection)

        return unique

    def _severity_rank(self, severity: str) -> int:
        """Sort rank for severity."""
        ranks = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }
        return ranks.get(str(severity).lower(), 5)

    def _count_detections(self, detections: List[UIDetection]) -> Dict[str, int]:
        """Count detections by type."""
        counts: Dict[str, int] = {
            "total": len(detections),
            "error": 0,
            "warning": 0,
            "popup": 0,
            "dialog": 0,
            "button": 0,
            "window": 0,
            "text": 0,
            "unknown": 0,
        }

        for item in detections:
            key = item.detection_type.value
            counts[key] = counts.get(key, 0) + 1

        return counts

    def _calculate_screen_risk(self, detections: List[UIDetection]) -> Dict[str, Any]:
        """Calculate simple risk summary based on detections."""
        high = sum(1 for item in detections if item.severity == "high")
        medium = sum(1 for item in detections if item.severity == "medium")
        errors = sum(1 for item in detections if item.detection_type == DetectionType.ERROR)
        popups = sum(
            1
            for item in detections
            if item.detection_type in {DetectionType.POPUP, DetectionType.DIALOG}
        )

        score = min(100, high * 35 + medium * 15 + errors * 20 + popups * 8)

        if score >= 70:
            level = "high"
        elif score >= 35:
            level = "medium"
        elif score > 0:
            level = "low"
        else:
            level = "none"

        return {
            "level": level,
            "score": score,
            "requires_attention": score >= 35,
            "high_severity_count": high,
            "medium_severity_count": medium,
            "error_count": errors,
            "popup_count": popups,
        }

    def _verification_requires_review(self, result: Dict[str, Any]) -> bool:
        """Decide whether Verification Agent/human should review result."""
        if not result.get("success"):
            return True

        data = result.get("data", {}) or {}
        risk = data.get("risk", {}) if isinstance(data, dict) else {}
        return risk.get("level") in {"medium", "high"}

    def _build_ui_summary(
        self,
        text: str,
        detections: List[UIDetection],
        blocks: List[OCRTextBlock],
    ) -> Dict[str, Any]:
        """Build compact UI summary."""
        counts = self._count_detections(detections)
        risk = self._calculate_screen_risk(detections)

        top_items = []
        for item in detections[:10]:
            top_items.append(
                {
                    "type": item.detection_type.value,
                    "label": item.label,
                    "text": item.text[:250],
                    "severity": item.severity,
                    "confidence": item.confidence,
                }
            )

        return {
            "text_detected": bool(text),
            "text_length": len(text or ""),
            "ocr_block_count": len(blocks),
            "detection_counts": counts,
            "risk": risk,
            "top_detections": top_items,
            "recommendation": self._build_recommendation(counts, risk),
        }

    def _build_recommendation(self, counts: Dict[str, int], risk: Dict[str, Any]) -> str:
        """Build safe recommendation text."""
        if risk.get("level") == "high":
            return "High-risk UI issue detected. Route to Verification Agent and ask user before any action."
        if counts.get("error", 0) > 0:
            return "Error text detected. Summarize the error and ask user before remediation."
        if counts.get("popup", 0) > 0 or counts.get("dialog", 0) > 0:
            return "Popup or dialog detected. Do not click automatically; ask user or Security Agent for approval."
        if counts.get("button", 0) > 0:
            return "Buttons detected. Use this for observation only unless a separate approved action agent handles interaction."
        return "No urgent UI issue detected."

    # -----------------------------------------------------------------------
    # Search text / summary
    # -----------------------------------------------------------------------

    def find_text(
        self,
        query: str,
        task_context: Optional[Dict[str, Any]] = None,
        image: Optional[Any] = None,
        capture_if_missing: bool = True,
        case_sensitive: bool = False,
    ) -> Dict[str, Any]:
        """
        Find visible text on screen.

        Args:
            query:
                Text or regex-like phrase to search in OCR blocks.
            case_sensitive:
                If False, case-insensitive search is used.

        Returns:
            Matches with bounding boxes.
        """
        action = VisionAction.FIND_TEXT.value

        if not query or not str(query).strip():
            return self._error_result(
                message="find_text requires a non-empty query.",
                error_code="EMPTY_QUERY",
                metadata={"action": action},
            )

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result

        if self._requires_security_check(action, task_context):
            approval = self._request_security_approval(
                action=action,
                task_context=task_context,
                reason="Find visible text on desktop screen.",
                metadata={"query": _redact_sensitive_text(str(query))},
            )
            if not approval.get("success"):
                return approval

        ocr_result = self.ocr_screen(
            task_context=task_context,
            image=image,
            capture_if_missing=capture_if_missing,
            include_blocks=True,
            preprocess=True,
        )

        if not ocr_result.get("success"):
            return ocr_result

        query_text = str(query)
        matches: List[Dict[str, Any]] = []

        for block in self._last_ocr_blocks:
            block_text = block.text

            if case_sensitive:
                found = query_text in block_text
            else:
                found = query_text.lower() in block_text.lower()

            if not found:
                continue

            safe_text = _redact_sensitive_text(block_text) if self.config.redact_sensitive_text else block_text

            matches.append(
                {
                    "text": safe_text,
                    "confidence": block.confidence,
                    "bbox": block.bbox.to_dict(),
                    "line_number": block.line_number,
                    "word_number": block.word_number,
                }
            )

        result = self._safe_result(
            message="Visible text search completed.",
            data={
                "query": _redact_sensitive_text(query_text) if self.config.redact_sensitive_text else query_text,
                "match_count": len(matches),
                "matches": matches,
                "case_sensitive": case_sensitive,
            },
            metadata={"action": action},
        )

        result["metadata"]["verification_payload"] = self._prepare_verification_payload(
            action=action,
            result=result,
            task_context=task_context,
        )

        self._log_audit_event(
            action=action,
            task_context=task_context,
            status="success",
            details={
                "query": _redact_sensitive_text(query_text),
                "match_count": len(matches),
            },
        )

        return result

    def extract_ui_summary(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        image: Optional[Any] = None,
        capture_if_missing: bool = True,
    ) -> Dict[str, Any]:
        """
        Return a compact dashboard-friendly UI summary.
        """
        action = VisionAction.EXTRACT_UI_SUMMARY.value

        analysis = self.analyze_screen(
            task_context=task_context,
            image=image,
            capture_if_missing=capture_if_missing,
            include_ocr_blocks=False,
            include_screenshot=False,
        )

        if not analysis.get("success"):
            return analysis

        data = analysis.get("data", {}) or {}

        result = self._safe_result(
            message="UI summary extracted successfully.",
            data={
                "summary": data.get("summary", {}),
                "counts": data.get("counts", {}),
                "risk": data.get("risk", {}),
                "top_detections": data.get("summary", {}).get("top_detections", []),
            },
            metadata={"action": action},
        )

        result["metadata"]["verification_payload"] = self._prepare_verification_payload(
            action=action,
            result=result,
            task_context=task_context,
        )
        result["metadata"]["memory_payload"] = self._prepare_memory_payload(
            action=action,
            result=result,
            task_context=task_context,
        )

        return result

    # -----------------------------------------------------------------------
    # OpenCV optional visual helpers
    # -----------------------------------------------------------------------

    def detect_rectangular_regions(
        self,
        task_context: Optional[Dict[str, Any]] = None,
        image: Optional[Any] = None,
        capture_if_missing: bool = True,
        min_area: int = 5000,
        max_regions: int = 50,
    ) -> Dict[str, Any]:
        """
        Optional helper to detect rectangular regions using OpenCV.

        This can help future dashboard/API layers identify panel/window/button
        boundaries. It remains observational only.
        """
        action = "detect_rectangular_regions"

        context_result = self._validate_task_context(task_context)
        if not context_result.get("success"):
            return context_result

        if cv2 is None or np is None or Image is None:
            return self._error_result(
                message="Rectangular region detection requires opencv-python, numpy, and Pillow.",
                error_code="MISSING_OPENCV_DEPENDENCIES",
                data={"dependencies": _dependency_status()},
                metadata={"action": action},
            )

        try:
            source_image = self._resolve_image_for_analysis(
                image=image,
                task_context=task_context,
                capture_if_missing=capture_if_missing,
            )

            if source_image is None:
                return self._error_result(
                    message="No image available for rectangular region detection.",
                    error_code="NO_IMAGE_AVAILABLE",
                    metadata={"action": action},
                )

            rgb = source_image.convert("RGB")
            arr = np.array(rgb)
            gray = cv2.cvtColor(arr, cv2.COLOR_RGB2GRAY)
            edges = cv2.Canny(gray, 80, 180)
            contours, _ = cv2.findContours(edges, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

            regions: List[Dict[str, Any]] = []

            for contour in contours:
                x, y, w, h = cv2.boundingRect(contour)
                area = int(w * h)

                if area < min_area:
                    continue

                regions.append(
                    {
                        "bbox": BoundingBox(x=int(x), y=int(y), width=int(w), height=int(h)).to_dict(),
                        "area": area,
                    }
                )

            regions = sorted(regions, key=lambda item: item["area"], reverse=True)[:max_regions]

            return self._safe_result(
                message="Rectangular region detection completed.",
                data={
                    "regions": regions,
                    "count": len(regions),
                    "min_area": min_area,
                },
                metadata={"action": action},
            )

        except Exception as exc:
            return self._error_result(
                message="Rectangular region detection failed.",
                error_code="RECT_REGION_DETECTION_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    # -----------------------------------------------------------------------
    # Master Agent / Router entrypoint
    # -----------------------------------------------------------------------

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Async entrypoint for Master Agent / Agent Router.

        Expected task shape:
            {
                "action": "analyze_screen",
                "user_id": "1",
                "workspace_id": "main",
                "params": {
                    "include_ocr_blocks": true
                }
            }

        Supported actions are listed in VisionAction.
        """
        if not isinstance(task, dict):
            return self._error_result(
                message="DesktopVision task must be a dict.",
                error_code="INVALID_TASK",
            )

        action = str(task.get("action") or VisionAction.ANALYZE_SCREEN.value)
        params = task.get("params") or {}

        if not isinstance(params, dict):
            return self._error_result(
                message="DesktopVision task params must be a dict.",
                error_code="INVALID_TASK_PARAMS",
                metadata={"action": action},
            )

        task_context = self._extract_task_context(task)

        self._emit_agent_event(
            event_type="desktop_vision.task.received",
            task_context=task_context,
            data={"action": action},
        )

        try:
            if action == VisionAction.HEALTH.value:
                return self.health(task_context=task_context)

            if action == VisionAction.CAPTURE_SCREEN.value:
                return self.capture_screen(
                    task_context=task_context,
                    include_image_base64=params.get("include_image_base64"),
                    save_debug=params.get("save_debug"),
                    region=self._parse_region(params.get("region")),
                )

            if action == VisionAction.OCR_SCREEN.value:
                return self.ocr_screen(
                    task_context=task_context,
                    capture_if_missing=bool(params.get("capture_if_missing", True)),
                    include_blocks=bool(params.get("include_blocks", True)),
                    preprocess=bool(params.get("preprocess", True)),
                )

            if action == VisionAction.ANALYZE_SCREEN.value:
                return self.analyze_screen(
                    task_context=task_context,
                    capture_if_missing=bool(params.get("capture_if_missing", True)),
                    include_ocr_blocks=bool(params.get("include_ocr_blocks", True)),
                    include_screenshot=bool(params.get("include_screenshot", False)),
                )

            if action == VisionAction.DETECT_ERRORS.value:
                return self.detect_errors(
                    task_context=task_context,
                    capture_if_missing=bool(params.get("capture_if_missing", True)),
                )

            if action == VisionAction.DETECT_POPUPS.value:
                return self.detect_popups(
                    task_context=task_context,
                    capture_if_missing=bool(params.get("capture_if_missing", True)),
                )

            if action == VisionAction.DETECT_BUTTONS.value:
                return self.detect_buttons(
                    task_context=task_context,
                    capture_if_missing=bool(params.get("capture_if_missing", True)),
                )

            if action == VisionAction.DETECT_WINDOWS.value:
                return self.detect_windows(
                    task_context=task_context,
                    capture_if_missing=bool(params.get("capture_if_missing", True)),
                )

            if action == VisionAction.FIND_TEXT.value:
                return self.find_text(
                    query=str(params.get("query") or ""),
                    task_context=task_context,
                    capture_if_missing=bool(params.get("capture_if_missing", True)),
                    case_sensitive=bool(params.get("case_sensitive", False)),
                )

            if action == VisionAction.EXTRACT_UI_SUMMARY.value:
                return self.extract_ui_summary(
                    task_context=task_context,
                    capture_if_missing=bool(params.get("capture_if_missing", True)),
                )

            return self._error_result(
                message=f"Unsupported DesktopVision action: {action}",
                error_code="UNSUPPORTED_ACTION",
                data={
                    "supported_actions": [item.value for item in VisionAction],
                },
                metadata={"action": action},
            )

        except Exception as exc:
            self.logger.exception("DesktopVision run failed")
            return self._error_result(
                message="DesktopVision task failed.",
                error_code="RUN_FAILED",
                error=str(exc),
                metadata={"action": action},
            )

    def _extract_task_context(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Extract SaaS context from task."""
        context = dict(task.get("context") or {})

        for key in (
            "user_id",
            "workspace_id",
            "request_id",
            "session_id",
            "role",
            "permissions",
        ):
            if key in task and key not in context:
                context[key] = task.get(key)

        if "request_id" not in context or not context.get("request_id"):
            context["request_id"] = _new_id("req")

        return context

    def _parse_region(self, value: Any) -> Optional[Tuple[int, int, int, int]]:
        """Parse region from list/tuple/dict."""
        if value is None:
            return None

        if isinstance(value, tuple) and len(value) == 4:
            return (
                int(value[0]),
                int(value[1]),
                int(value[2]),
                int(value[3]),
            )

        if isinstance(value, list) and len(value) == 4:
            return (
                int(value[0]),
                int(value[1]),
                int(value[2]),
                int(value[3]),
            )

        if isinstance(value, dict):
            return (
                int(value.get("x", 0)),
                int(value.get("y", 0)),
                int(value.get("width", 0)),
                int(value.get("height", 0)),
            )

        raise ValueError("region must be tuple/list [x, y, width, height] or dict.")


# ---------------------------------------------------------------------------
# Standalone safe smoke test
# ---------------------------------------------------------------------------

def _standalone_smoke_test() -> Dict[str, Any]:
    """
    Safe smoke test that does not capture screen by default.

    Run:
        python agents/system_agent/desktop_vision.py

    For real capture/OCR, call DesktopVision methods from your app with a valid
    user_id/workspace_id and proper permissions.
    """
    vision = DesktopVision(
        config={
            "allow_screen_capture": False,
            "require_security_for_capture": True,
        }
    )

    return vision.health(
        task_context={
            "user_id": "local_test_user",
            "workspace_id": "local_test_workspace",
            "permissions": ["desktop_vision"],
        }
    )


if __name__ == "__main__":
    print(json.dumps(_standalone_smoke_test(), indent=2, default=str))


"""
Agent/Module: System Agent
File Completed: desktop_vision.py
Completion: 82.4%
Completed Files: ['system_agent.py', 'app_controller.py', 'file_manager.py', 'os_commands.py', 'device_controls.py', 'automation.py', 'notification_reader.py', 'message_controller.py', 'call_controller.py', 'permission_guard.py', 'app_profiles.py', 'device_sync.py', 'gesture_control.py', 'desktop_vision.py']
Remaining Files: ['task_recorder.py', 'system_memory.py', 'config.py']
Next Recommended File: agents/system_agent/task_recorder.py
FILE COMPLETE
"""