"""
agents/visual_agent/visual_agent.py

Visual Agent for William / Jarvis Multi-Agent AI SaaS System
by Digital Promotix.

Purpose:
    Screen and vision brain for screenshots, videos, OCR, UI mapping,
    element detection, and privacy filtering.

This file is production-oriented and import-safe:
    - It can import even if future William/Jarvis modules do not exist yet.
    - It uses optional imports and fallback stubs.
    - It does not capture the real screen, control browser/device, or perform
      destructive actions directly.
    - It validates SaaS user/workspace isolation.
    - It prepares Verification Agent and Memory Agent compatible payloads.
    - It is ready for FastAPI/dashboard integration.

Architecture connections:
    - Master Agent:
        Routes screenshot/image/video/UI inspection tasks to VisualAgent.
    - Security Agent:
        Sensitive visual actions, screenshots, OCR, and privacy-risk operations
        can be approval-gated.
    - Verification Agent:
        VisualAgent prepares verification payloads after analysis.
    - Memory Agent:
        VisualAgent prepares safe visual memory summaries without raw secrets.
    - Dashboard/API:
        Every public method returns structured dict/JSON style output.
    - Agent Registry / Agent Loader:
        Exposes create_agent(), get_agent_class(), and metadata methods.

Required compatibility hooks included:
    - _validate_task_context()
    - _requires_security_check()
    - _request_security_approval()
    - _prepare_verification_payload()
    - _prepare_memory_payload()
    - _emit_agent_event()
    - _log_audit_event()
    - _safe_result()
    - _error_result()
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import mimetypes
import os
import re
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ======================================================================================
# Optional imports
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        The real William/Jarvis BaseAgent can later provide richer event,
        registry, permissions, and telemetry functionality.
        """

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
    from PIL import Image  # type: ignore
except Exception:
    Image = None  # type: ignore


# ======================================================================================
# Logging
# ======================================================================================

LOGGER = logging.getLogger("william.visual_agent")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# ======================================================================================
# Constants
# ======================================================================================

AGENT_NAME = "visual_agent"
AGENT_DISPLAY_NAME = "Visual Agent"
AGENT_MODULE = "agents.visual_agent"
AGENT_FILE = "visual_agent.py"
AGENT_VERSION = "1.0.0"

DEFAULT_MAX_IMAGE_BYTES = 15_000_000
DEFAULT_MAX_OCR_CHARS = 100_000
DEFAULT_MAX_ELEMENTS = 2_000
DEFAULT_MAX_FRAMES = 500
DEFAULT_CONFIDENCE_THRESHOLD = 0.75

SUPPORTED_IMAGE_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".webp",
    ".bmp",
    ".gif",
    ".tiff",
    ".tif",
}

SUPPORTED_VIDEO_EXTENSIONS = {
    ".mp4",
    ".mov",
    ".mkv",
    ".webm",
    ".avi",
    ".m4v",
}

SENSITIVE_VISUAL_TYPES = {
    "screenshot",
    "screen",
    "screen_analysis",
    "ocr",
    "video",
    "video_analysis",
    "ui_mapping",
    "element_detection",
    "privacy_filtering",
    "image_with_text",
}

PRIVATE_TEXT_PATTERNS = {
    "email": r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
    "phone": r"(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}(?!\d)",
    "credit_card_like": r"\b(?:\d[ -]*?){13,19}\b",
    "api_key_like": r"\b(?:sk-|pk_|api[_-]?key|token|secret|bearer)[A-Za-z0-9_\-:.=]{8,}\b",
    "ipv4": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    "password_hint": r"(?i)\b(password|passwd|pwd|secret|token|api key|authorization|bearer)\b",
    "ssn_like": r"\b\d{3}-\d{2}-\d{4}\b",
}

COMMON_UI_KEYWORDS = {
    "button": ["button", "submit", "save", "cancel", "continue", "next", "back", "login", "sign in", "send"],
    "input": ["input", "field", "email", "password", "search", "name", "phone"],
    "link": ["link", "learn more", "click here", "open", "visit"],
    "error": ["error", "failed", "invalid", "denied", "not found", "warning", "blocked"],
    "success": ["success", "done", "completed", "saved", "verified"],
}


# ======================================================================================
# Enums and data structures
# ======================================================================================

class VisualStatus(str, Enum):
    """Visual processing status."""

    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    NEEDS_REVIEW = "needs_review"
    BLOCKED = "blocked"
    ERROR = "error"


class VisualTaskType(str, Enum):
    """Supported visual task domains."""

    SCREENSHOT = "screenshot"
    IMAGE = "image"
    VIDEO = "video"
    OCR = "ocr"
    UI_MAPPING = "ui_mapping"
    ELEMENT_DETECTION = "element_detection"
    PRIVACY_FILTERING = "privacy_filtering"
    SCREEN_CONTEXT = "screen_context"
    FORM_READING = "form_reading"
    ERROR_SCREEN_DETECTION = "error_screen_detection"
    ANNOTATION = "annotation"
    VALIDATION = "validation"


class VisualSeverity(str, Enum):
    """Visual finding severity."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class VisualContext:
    """
    SaaS-scoped Visual Agent context.

    user_id and workspace_id are mandatory for user-specific visual analysis.
    """

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
class BoundingBox:
    """Screen/image bounding box."""

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
class VisualElement:
    """Detected or mapped UI element."""

    element_id: str
    element_type: str
    label: Optional[str] = None
    text: Optional[str] = None
    bbox: Optional[BoundingBox] = None
    visible: bool = True
    enabled: Optional[bool] = None
    clickable: Optional[bool] = None
    confidence: float = 0.5
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["bbox"] = self.bbox.to_dict() if self.bbox else None
        return data


@dataclass
class VisualFinding:
    """A single visual analysis finding."""

    check_name: str
    status: VisualStatus
    message: str
    severity: VisualSeverity = VisualSeverity.INFO
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
class VisualArtifact:
    """Visual evidence artifact."""

    artifact_id: str
    artifact_type: str
    title: str
    data: Any
    created_at: str
    source: str = AGENT_NAME
    confidence: float = 1.0
    privacy_filtered: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VisualReport:
    """Complete visual analysis report."""

    report_id: str
    status: VisualStatus
    task_type: VisualTaskType
    summary: str
    findings: List[VisualFinding]
    elements: List[VisualElement]
    artifacts: List[VisualArtifact]
    confidence: float
    privacy_risk_score: float
    created_at: str
    context: Dict[str, Any]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "status": self.status.value,
            "task_type": self.task_type.value,
            "summary": self.summary,
            "findings": [item.to_dict() for item in self.findings],
            "elements": [item.to_dict() for item in self.elements],
            "artifacts": [item.to_dict() for item in self.artifacts],
            "confidence": self.confidence,
            "privacy_risk_score": self.privacy_risk_score,
            "created_at": self.created_at,
            "context": self.context,
            "metadata": self.metadata,
        }


# ======================================================================================
# Helper functions
# ======================================================================================

def _utc_now() -> str:
    """Return current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def _safe_uuid(prefix: str = "vis") -> str:
    """Create readable UUID."""
    return f"{prefix}_{uuid.uuid4().hex}"


def _json_safe(value: Any) -> Any:
    """Convert arbitrary values into JSON-safe values."""
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
    """Normalize text for search/comparison."""
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def _lower(value: Any) -> str:
    return _normalize_text(value).lower()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _safe_read_bytes(path: Path, max_bytes: int) -> Tuple[Optional[bytes], Optional[str]]:
    """Read file bytes with max-size safety."""
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


def _safe_read_text(path: Path, max_bytes: int) -> Tuple[Optional[str], Optional[str]]:
    """Read text file with max-size safety."""
    raw, error = _safe_read_bytes(path, max_bytes)
    if error:
        return None, error
    try:
        return (raw or b"").decode("utf-8"), None
    except UnicodeDecodeError:
        return (raw or b"").decode("utf-8", errors="replace"), None


def _redact_text(text: str, replacement: str = "[REDACTED]") -> Tuple[str, List[Dict[str, Any]]]:
    """Redact common sensitive strings from OCR/text output."""
    redacted = text
    matches: List[Dict[str, Any]] = []

    for name, pattern in PRIVATE_TEXT_PATTERNS.items():
        try:
            found = list(re.finditer(pattern, redacted, flags=re.IGNORECASE))
        except re.error:
            continue

        for match in found:
            raw = match.group(0)
            matches.append(
                {
                    "type": name,
                    "start": match.start(),
                    "end": match.end(),
                    "sample_hash": _sha256_text(raw)[:16],
                    "length": len(raw),
                }
            )

        redacted = re.sub(pattern, replacement, redacted, flags=re.IGNORECASE)

    return redacted, matches


def _clamp_float(value: Any, default: float = 0.0) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except Exception:
        return default


def _extension(path: Union[str, Path]) -> str:
    return Path(path).suffix.lower()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _looks_like_base64(value: str) -> bool:
    if not value or len(value) < 32:
        return False
    candidate = value.split(",", 1)[-1] if "," in value[:50] else value
    return bool(re.fullmatch(r"[A-Za-z0-9+/=\s]+", candidate[:200]))


def _decode_base64_image(value: str, max_bytes: int) -> Tuple[Optional[bytes], Optional[str]]:
    """Safely decode base64 image data."""
    try:
        candidate = value.split(",", 1)[-1] if "," in value[:80] else value
        raw = base64.b64decode(candidate, validate=False)
        if len(raw) > max_bytes:
            return None, f"base64_image_too_large:{len(raw)}>{max_bytes}"
        return raw, None
    except Exception as exc:
        return None, str(exc)


# ======================================================================================
# Main Visual Agent
# ======================================================================================

class VisualAgent(BaseAgent):
    """
    Central visual intelligence brain for William/Jarvis.

    VisualAgent coordinates screenshot/image/video analysis, OCR text handling,
    UI mapping, element detection, privacy filtering, and visual validation.

    It does not directly take screenshots or control devices. Capture/execution should
    be done by Browser/System/Device agents with proper permission checks, then passed
    into this agent as image paths, bytes, OCR text, frame metadata, or UI observations.
    """

    agent_name = AGENT_NAME
    agent_type = "visual"
    agent_version = AGENT_VERSION
    display_name = AGENT_DISPLAY_NAME

    def __init__(
        self,
        config: Optional[Any] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        screenshot_reader: Optional[Any] = None,
        video_analyzer: Optional[Any] = None,
        ocr_engine: Optional[Any] = None,
        ui_mapper: Optional[Any] = None,
        image_analyzer: Optional[Any] = None,
        element_detector: Optional[Any] = None,
        privacy_filter: Optional[Any] = None,
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

        self.screenshot_reader = screenshot_reader
        self.video_analyzer = video_analyzer
        self.ocr_engine = ocr_engine
        self.ui_mapper = ui_mapper
        self.image_analyzer = image_analyzer
        self.element_detector = element_detector
        self.privacy_filter = privacy_filter

        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.logger = logger or LOGGER

        self.max_image_bytes = int(getattr(self.config, "max_image_bytes", DEFAULT_MAX_IMAGE_BYTES))
        self.max_ocr_chars = int(getattr(self.config, "max_ocr_chars", DEFAULT_MAX_OCR_CHARS))
        self.max_elements = int(getattr(self.config, "max_elements", DEFAULT_MAX_ELEMENTS))
        self.max_frames = int(getattr(self.config, "max_frames", DEFAULT_MAX_FRAMES))
        self.default_confidence_threshold = float(
            getattr(self.config, "default_confidence_threshold", DEFAULT_CONFIDENCE_THRESHOLD)
        )
        self.enable_builtin_privacy_filter = bool(
            getattr(self.config, "enable_builtin_privacy_filter", True)
        )

    # ----------------------------------------------------------------------------------
    # Metadata and health
    # ----------------------------------------------------------------------------------

    def get_agent_metadata(self) -> Dict[str, Any]:
        """Return Agent Registry / Loader compatible metadata."""
        return self._safe_result(
            message="Visual Agent metadata loaded.",
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
                "supported_task_types": [item.value for item in VisualTaskType],
                "supported_image_extensions": sorted(SUPPORTED_IMAGE_EXTENSIONS),
                "supported_video_extensions": sorted(SUPPORTED_VIDEO_EXTENSIONS),
                "public_methods": [
                    "analyze_screenshot",
                    "analyze_image",
                    "analyze_video",
                    "extract_ocr",
                    "map_ui",
                    "detect_elements",
                    "filter_privacy",
                    "read_form",
                    "detect_error_screen",
                    "validate_visual_state",
                    "annotate_elements",
                    "build_screen_context",
                    "generate_visual_report",
                    "health_check",
                    "get_agent_metadata",
                ],
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """Return lightweight health check."""
        return self._safe_result(
            message="Visual Agent is healthy.",
            data={
                "agent_name": self.agent_name,
                "version": self.agent_version,
                "optional_pillow_available": Image is not None,
                "security_agent_connected": self.security_agent is not None,
                "memory_agent_connected": self.memory_agent is not None,
                "verification_agent_connected": self.verification_agent is not None,
                "screenshot_reader_connected": self.screenshot_reader is not None,
                "video_analyzer_connected": self.video_analyzer is not None,
                "ocr_engine_connected": self.ocr_engine is not None,
                "ui_mapper_connected": self.ui_mapper is not None,
                "image_analyzer_connected": self.image_analyzer is not None,
                "element_detector_connected": self.element_detector is not None,
                "privacy_filter_connected": self.privacy_filter is not None,
                "max_image_bytes": self.max_image_bytes,
                "max_ocr_chars": self.max_ocr_chars,
                "max_elements": self.max_elements,
                "max_frames": self.max_frames,
            },
            metadata={"checked_at": _utc_now()},
        )

    # ----------------------------------------------------------------------------------
    # Main public visual methods
    # ----------------------------------------------------------------------------------

    def analyze_screenshot(
        self,
        context: Union[VisualContext, Mapping[str, Any]],
        screenshot: Union[str, Path, bytes, Mapping[str, Any]],
        task_goal: Optional[str] = None,
        ocr_text: Optional[str] = None,
        observed_elements: Optional[Sequence[Mapping[str, Any]]] = None,
        privacy_mode: str = "safe",
        expected: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze a screenshot.

        screenshot can be:
            - path string
            - Path
            - bytes
            - mapping with path/base64/metadata/width/height

        This method does not capture a real screenshot. It analyzes provided data only.
        """
        started_at = time.time()
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            approval = self._maybe_request_security(
                context=ctx,
                visual_type="screenshot",
                action="analyze_screenshot",
                payload={"task_goal": task_goal, "privacy_mode": privacy_mode},
            )
            if not approval["success"]:
                return approval

            image_info = self._inspect_visual_input(screenshot, expected_kind="image")
            findings: List[VisualFinding] = []
            artifacts: List[VisualArtifact] = []
            elements: List[VisualElement] = []

            if not image_info["success"]:
                findings.append(
                    VisualFinding(
                        check_name="screenshot_input",
                        status=VisualStatus.FAILED,
                        message="Screenshot input could not be inspected.",
                        severity=VisualSeverity.HIGH,
                        actual=image_info.get("error"),
                        confidence=0.2,
                    )
                )
            else:
                findings.append(
                    VisualFinding(
                        check_name="screenshot_input",
                        status=VisualStatus.PASSED,
                        message="Screenshot input inspected successfully.",
                        actual=image_info["data"],
                        confidence=0.9,
                    )
                )
                artifacts.append(
                    VisualArtifact(
                        artifact_id=_safe_uuid("artifact"),
                        artifact_type="screenshot_metadata",
                        title="Screenshot metadata",
                        data=image_info["data"],
                        created_at=_utc_now(),
                        confidence=0.9,
                        privacy_filtered=True,
                    )
                )

            if self.screenshot_reader and hasattr(self.screenshot_reader, "read_screenshot"):
                reader_result = self._call_component_safe(
                    self.screenshot_reader.read_screenshot,
                    context=ctx,
                    screenshot=screenshot,
                    task_goal=task_goal,
                )
                self._merge_component_result(reader_result, findings, artifacts, elements, "screenshot_reader")

            text_result = self.extract_ocr(
                context=ctx,
                image=screenshot,
                provided_text=ocr_text,
                privacy_mode=privacy_mode,
            )
            if text_result["success"]:
                for item in text_result["data"].get("findings", []):
                    findings.append(self._finding_from_dict(item))
                for item in text_result["data"].get("artifacts", []):
                    artifacts.append(self._artifact_from_dict(item))

            if observed_elements:
                mapped = self.map_ui(
                    context=ctx,
                    elements=observed_elements,
                    screen_metadata=image_info.get("data", {}),
                    ocr_text=text_result["data"].get("text") if text_result["success"] else ocr_text,
                    privacy_mode=privacy_mode,
                )
                if mapped["success"]:
                    elements.extend(self._elements_from_data(mapped["data"].get("elements", [])))
                    for item in mapped["data"].get("findings", []):
                        findings.append(self._finding_from_dict(item))
                    for item in mapped["data"].get("artifacts", []):
                        artifacts.append(self._artifact_from_dict(item))

            detected = self.detect_elements(
                context=ctx,
                image=screenshot,
                ocr_text=text_result["data"].get("text") if text_result["success"] else ocr_text,
                existing_elements=[item.to_dict() for item in elements],
                privacy_mode=privacy_mode,
            )
            if detected["success"]:
                elements.extend(self._elements_from_data(detected["data"].get("elements", [])))
                for item in detected["data"].get("findings", []):
                    findings.append(self._finding_from_dict(item))
                for item in detected["data"].get("artifacts", []):
                    artifacts.append(self._artifact_from_dict(item))

            elements = self._deduplicate_elements(elements)

            if expected:
                validation = self.validate_visual_state(
                    context=ctx,
                    expected=expected,
                    actual={
                        "text": text_result["data"].get("text") if text_result["success"] else "",
                        "elements": [item.to_dict() for item in elements],
                        "image": image_info.get("data", {}),
                    },
                    privacy_mode=privacy_mode,
                )
                if validation["success"]:
                    for item in validation["data"].get("findings", []):
                        findings.append(self._finding_from_dict(item))
                    for item in validation["data"].get("artifacts", []):
                        artifacts.append(self._artifact_from_dict(item))

            report = self._build_report(
                context=ctx,
                task_type=VisualTaskType.SCREENSHOT,
                findings=findings,
                elements=elements,
                artifacts=artifacts,
                metadata={
                    "task_goal": task_goal,
                    "privacy_mode": privacy_mode,
                    "duration_ms": round((time.time() - started_at) * 1000, 2),
                },
            )

            self._emit_agent_event(
                "visual.screenshot.analyzed",
                {
                    "context": ctx,
                    "report_id": report.report_id,
                    "status": report.status.value,
                    "confidence": report.confidence,
                },
            )
            self._log_audit_event(
                {
                    "event": "visual_screenshot_analyzed",
                    "context": ctx,
                    "report_id": report.report_id,
                    "status": report.status.value,
                    "privacy_risk_score": report.privacy_risk_score,
                    "created_at": report.created_at,
                }
            )

            return self._safe_result(
                message=report.summary,
                data={
                    "report": report.to_dict(),
                    "verification_payload": self._prepare_verification_payload(report, ctx),
                    "memory_payload": self._prepare_memory_payload(report, ctx),
                    "text": self._extract_latest_text_artifact(artifacts),
                    "elements": [item.to_dict() for item in elements],
                    "findings": [item.to_dict() for item in findings],
                    "artifacts": [item.to_dict() for item in artifacts],
                },
                metadata={"duration_ms": round((time.time() - started_at) * 1000, 2)},
            )
        except Exception as exc:
            return self._error_result("Screenshot analysis failed unexpectedly.", exc)

    def analyze_image(
        self,
        context: Union[VisualContext, Mapping[str, Any]],
        image: Union[str, Path, bytes, Mapping[str, Any]],
        task_goal: Optional[str] = None,
        ocr_text: Optional[str] = None,
        privacy_mode: str = "safe",
    ) -> Dict[str, Any]:
        """Analyze a provided image with metadata, optional OCR, and privacy filtering."""
        started_at = time.time()
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            approval = self._maybe_request_security(
                context=ctx,
                visual_type="image_with_text" if ocr_text else "image",
                action="analyze_image",
                payload={"task_goal": task_goal, "privacy_mode": privacy_mode},
            )
            if not approval["success"]:
                return approval

            findings: List[VisualFinding] = []
            artifacts: List[VisualArtifact] = []
            elements: List[VisualElement] = []

            image_info = self._inspect_visual_input(image, expected_kind="image")
            if image_info["success"]:
                findings.append(
                    VisualFinding(
                        check_name="image_input",
                        status=VisualStatus.PASSED,
                        message="Image input inspected successfully.",
                        actual=image_info["data"],
                        confidence=0.9,
                    )
                )
                artifacts.append(
                    VisualArtifact(
                        artifact_id=_safe_uuid("artifact"),
                        artifact_type="image_metadata",
                        title="Image metadata",
                        data=image_info["data"],
                        created_at=_utc_now(),
                        confidence=0.9,
                        privacy_filtered=True,
                    )
                )
            else:
                findings.append(
                    VisualFinding(
                        check_name="image_input",
                        status=VisualStatus.FAILED,
                        message="Image input could not be inspected.",
                        severity=VisualSeverity.HIGH,
                        actual=image_info.get("error"),
                        confidence=0.2,
                    )
                )

            if self.image_analyzer and hasattr(self.image_analyzer, "analyze_image"):
                component_result = self._call_component_safe(
                    self.image_analyzer.analyze_image,
                    context=ctx,
                    image=image,
                    task_goal=task_goal,
                )
                self._merge_component_result(component_result, findings, artifacts, elements, "image_analyzer")

            ocr_result = self.extract_ocr(
                context=ctx,
                image=image,
                provided_text=ocr_text,
                privacy_mode=privacy_mode,
            )
            if ocr_result["success"]:
                for item in ocr_result["data"].get("findings", []):
                    findings.append(self._finding_from_dict(item))
                for item in ocr_result["data"].get("artifacts", []):
                    artifacts.append(self._artifact_from_dict(item))

            report = self._build_report(
                context=ctx,
                task_type=VisualTaskType.IMAGE,
                findings=findings,
                elements=elements,
                artifacts=artifacts,
                metadata={
                    "task_goal": task_goal,
                    "privacy_mode": privacy_mode,
                    "duration_ms": round((time.time() - started_at) * 1000, 2),
                },
            )

            return self._safe_result(
                message=report.summary,
                data={
                    "report": report.to_dict(),
                    "verification_payload": self._prepare_verification_payload(report, ctx),
                    "memory_payload": self._prepare_memory_payload(report, ctx),
                    "text": self._extract_latest_text_artifact(artifacts),
                    "findings": [item.to_dict() for item in findings],
                    "artifacts": [item.to_dict() for item in artifacts],
                },
                metadata={"duration_ms": round((time.time() - started_at) * 1000, 2)},
            )
        except Exception as exc:
            return self._error_result("Image analysis failed unexpectedly.", exc)

    def analyze_video(
        self,
        context: Union[VisualContext, Mapping[str, Any]],
        video: Union[str, Path, bytes, Mapping[str, Any]],
        frames: Optional[Sequence[Mapping[str, Any]]] = None,
        task_goal: Optional[str] = None,
        privacy_mode: str = "safe",
    ) -> Dict[str, Any]:
        """
        Analyze a video from metadata and optional frame observations.

        This method does not play, record, or capture a video. It can inspect file
        metadata and analyze caller-provided frames.
        """
        started_at = time.time()
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            approval = self._maybe_request_security(
                context=ctx,
                visual_type="video",
                action="analyze_video",
                payload={"task_goal": task_goal, "privacy_mode": privacy_mode},
            )
            if not approval["success"]:
                return approval

            findings: List[VisualFinding] = []
            artifacts: List[VisualArtifact] = []
            elements: List[VisualElement] = []

            video_info = self._inspect_visual_input(video, expected_kind="video")
            if video_info["success"]:
                findings.append(
                    VisualFinding(
                        check_name="video_input",
                        status=VisualStatus.PASSED,
                        message="Video input inspected successfully.",
                        actual=video_info["data"],
                        confidence=0.85,
                    )
                )
                artifacts.append(
                    VisualArtifact(
                        artifact_id=_safe_uuid("artifact"),
                        artifact_type="video_metadata",
                        title="Video metadata",
                        data=video_info["data"],
                        created_at=_utc_now(),
                        confidence=0.85,
                        privacy_filtered=True,
                    )
                )
            else:
                findings.append(
                    VisualFinding(
                        check_name="video_input",
                        status=VisualStatus.FAILED,
                        message="Video input could not be inspected.",
                        severity=VisualSeverity.HIGH,
                        actual=video_info.get("error"),
                        confidence=0.2,
                    )
                )

            if self.video_analyzer and hasattr(self.video_analyzer, "analyze_video"):
                component_result = self._call_component_safe(
                    self.video_analyzer.analyze_video,
                    context=ctx,
                    video=video,
                    frames=frames,
                    task_goal=task_goal,
                )
                self._merge_component_result(component_result, findings, artifacts, elements, "video_analyzer")

            frame_count = len(frames or [])
            if frame_count > self.max_frames:
                findings.append(
                    VisualFinding(
                        check_name="frame_limit",
                        status=VisualStatus.PARTIAL,
                        message="Frame list exceeds max frame limit; only summary was processed.",
                        expected=f"<= {self.max_frames}",
                        actual=frame_count,
                        severity=VisualSeverity.MEDIUM,
                        confidence=0.75,
                    )
                )

            frame_summary = self._summarize_frames(list(frames or [])[: self.max_frames], privacy_mode=privacy_mode)
            artifacts.append(
                VisualArtifact(
                    artifact_id=_safe_uuid("artifact"),
                    artifact_type="video_frame_summary",
                    title="Video frame summary",
                    data=frame_summary,
                    created_at=_utc_now(),
                    confidence=0.7 if frames else 0.4,
                    privacy_filtered=privacy_mode != "raw",
                )
            )

            if frames:
                findings.append(
                    VisualFinding(
                        check_name="frame_observations",
                        status=VisualStatus.PASSED,
                        message=f"Processed {min(frame_count, self.max_frames)} frame observation(s).",
                        actual={"frame_count": frame_count},
                        confidence=0.75,
                    )
                )
            else:
                findings.append(
                    VisualFinding(
                        check_name="frame_observations",
                        status=VisualStatus.NEEDS_REVIEW,
                        message="No frame observations were provided for deeper video analysis.",
                        severity=VisualSeverity.MEDIUM,
                        confidence=0.35,
                        remediation="Use video_frame_extractor.py later to provide frame observations.",
                    )
                )

            report = self._build_report(
                context=ctx,
                task_type=VisualTaskType.VIDEO,
                findings=findings,
                elements=elements,
                artifacts=artifacts,
                metadata={
                    "task_goal": task_goal,
                    "privacy_mode": privacy_mode,
                    "duration_ms": round((time.time() - started_at) * 1000, 2),
                },
            )

            return self._safe_result(
                message=report.summary,
                data={
                    "report": report.to_dict(),
                    "verification_payload": self._prepare_verification_payload(report, ctx),
                    "memory_payload": self._prepare_memory_payload(report, ctx),
                    "frame_summary": frame_summary,
                    "findings": [item.to_dict() for item in findings],
                    "artifacts": [item.to_dict() for item in artifacts],
                },
                metadata={"duration_ms": round((time.time() - started_at) * 1000, 2)},
            )
        except Exception as exc:
            return self._error_result("Video analysis failed unexpectedly.", exc)

    def extract_ocr(
        self,
        context: Union[VisualContext, Mapping[str, Any]],
        image: Optional[Union[str, Path, bytes, Mapping[str, Any]]] = None,
        provided_text: Optional[str] = None,
        privacy_mode: str = "safe",
    ) -> Dict[str, Any]:
        """
        Extract or normalize OCR text.

        If an external OCR engine is connected, it may be used. Otherwise, this method
        safely normalizes caller-provided OCR text and reports if OCR is unavailable.
        """
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            approval = self._maybe_request_security(
                context=ctx,
                visual_type="ocr",
                action="extract_ocr",
                payload={"privacy_mode": privacy_mode},
            )
            if not approval["success"]:
                return approval

            findings: List[VisualFinding] = []
            artifacts: List[VisualArtifact] = []
            raw_text = provided_text or ""

            if self.ocr_engine is not None and image is not None:
                method = None
                if hasattr(self.ocr_engine, "extract_text"):
                    method = self.ocr_engine.extract_text
                elif hasattr(self.ocr_engine, "extract_ocr"):
                    method = self.ocr_engine.extract_ocr

                if method:
                    component_result = self._call_component_safe(
                        method,
                        context=ctx,
                        image=image,
                    )
                    if component_result.get("success"):
                        raw_text = str(
                            component_result.get("data", {}).get("text")
                            or component_result.get("data", {}).get("ocr_text")
                            or raw_text
                        )
                        self._merge_component_result(component_result, findings, artifacts, [], "ocr_engine")
                    else:
                        findings.append(
                            VisualFinding(
                                check_name="ocr_engine",
                                status=VisualStatus.NEEDS_REVIEW,
                                message="Connected OCR engine did not return successful text.",
                                severity=VisualSeverity.MEDIUM,
                                actual=component_result.get("error"),
                                confidence=0.35,
                            )
                        )

            raw_text = raw_text[: self.max_ocr_chars]
            normalized_text = _normalize_text(raw_text)

            if normalized_text:
                findings.append(
                    VisualFinding(
                        check_name="ocr_text_available",
                        status=VisualStatus.PASSED,
                        message="OCR text is available.",
                        actual={"char_count": len(normalized_text)},
                        confidence=0.85 if provided_text else 0.7,
                    )
                )
            else:
                findings.append(
                    VisualFinding(
                        check_name="ocr_text_available",
                        status=VisualStatus.NEEDS_REVIEW,
                        message="No OCR text was available.",
                        severity=VisualSeverity.MEDIUM,
                        confidence=0.3,
                        remediation="Connect ocr_engine.py or pass provided_text from screenshot_reader.py.",
                    )
                )

            filtered_text = normalized_text
            privacy_matches: List[Dict[str, Any]] = []

            if privacy_mode != "raw":
                filter_result = self.filter_privacy(
                    context=ctx,
                    text=normalized_text,
                    artifacts=[],
                    mode=privacy_mode,
                )
                if filter_result["success"]:
                    filtered_text = filter_result["data"].get("text", normalized_text)
                    privacy_matches = filter_result["data"].get("privacy_matches", [])

            artifacts.append(
                VisualArtifact(
                    artifact_id=_safe_uuid("artifact"),
                    artifact_type="ocr_text",
                    title="OCR text",
                    data={
                        "text": filtered_text,
                        "char_count": len(filtered_text),
                        "raw_text_hash": _sha256_text(normalized_text) if normalized_text else None,
                        "privacy_matches": privacy_matches,
                        "privacy_mode": privacy_mode,
                    },
                    created_at=_utc_now(),
                    confidence=0.85 if normalized_text else 0.25,
                    privacy_filtered=privacy_mode != "raw",
                )
            )

            return self._safe_result(
                message="OCR extraction completed." if normalized_text else "OCR extraction needs review.",
                data={
                    "text": filtered_text,
                    "raw_text_hash": _sha256_text(normalized_text) if normalized_text else None,
                    "privacy_matches": privacy_matches,
                    "findings": [item.to_dict() for item in findings],
                    "artifacts": [item.to_dict() for item in artifacts],
                },
            )
        except Exception as exc:
            return self._error_result("OCR extraction failed unexpectedly.", exc)

    def map_ui(
        self,
        context: Union[VisualContext, Mapping[str, Any]],
        elements: Sequence[Mapping[str, Any]],
        screen_metadata: Optional[Mapping[str, Any]] = None,
        ocr_text: Optional[str] = None,
        privacy_mode: str = "safe",
    ) -> Dict[str, Any]:
        """Map caller-provided UI observations into standardized VisualElement objects."""
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            approval = self._maybe_request_security(
                context=ctx,
                visual_type="ui_mapping",
                action="map_ui",
                payload={"element_count": len(elements), "privacy_mode": privacy_mode},
            )
            if not approval["success"]:
                return approval

            findings: List[VisualFinding] = []
            artifacts: List[VisualArtifact] = []
            mapped_elements: List[VisualElement] = []

            if len(elements) > self.max_elements:
                findings.append(
                    VisualFinding(
                        check_name="ui_element_limit",
                        status=VisualStatus.PARTIAL,
                        message="UI element count exceeds max limit; extra elements were ignored.",
                        expected=f"<= {self.max_elements}",
                        actual=len(elements),
                        severity=VisualSeverity.MEDIUM,
                        confidence=0.75,
                    )
                )

            for index, item in enumerate(list(elements)[: self.max_elements]):
                mapped_elements.append(self._element_from_mapping(item, index=index))

            if self.ui_mapper and hasattr(self.ui_mapper, "map_ui"):
                component_result = self._call_component_safe(
                    self.ui_mapper.map_ui,
                    context=ctx,
                    elements=[item.to_dict() for item in mapped_elements],
                    screen_metadata=dict(screen_metadata or {}),
                    ocr_text=ocr_text,
                )
                self._merge_component_result(component_result, findings, artifacts, mapped_elements, "ui_mapper")

            mapped_elements = self._deduplicate_elements(mapped_elements)

            findings.append(
                VisualFinding(
                    check_name="ui_mapping",
                    status=VisualStatus.PASSED if mapped_elements else VisualStatus.NEEDS_REVIEW,
                    message=(
                        f"Mapped {len(mapped_elements)} UI element(s)."
                        if mapped_elements
                        else "No UI elements were available to map."
                    ),
                    actual={"element_count": len(mapped_elements)},
                    confidence=0.85 if mapped_elements else 0.35,
                    severity=VisualSeverity.INFO if mapped_elements else VisualSeverity.MEDIUM,
                )
            )

            artifacts.append(
                VisualArtifact(
                    artifact_id=_safe_uuid("artifact"),
                    artifact_type="ui_map",
                    title="UI map",
                    data={
                        "elements": [item.to_dict() for item in mapped_elements],
                        "screen_metadata": dict(screen_metadata or {}),
                        "ocr_text_hash": _sha256_text(ocr_text or "") if ocr_text else None,
                    },
                    created_at=_utc_now(),
                    confidence=0.8 if mapped_elements else 0.35,
                    privacy_filtered=privacy_mode != "raw",
                )
            )

            return self._safe_result(
                message="UI mapping completed.",
                data={
                    "elements": [item.to_dict() for item in mapped_elements],
                    "findings": [item.to_dict() for item in findings],
                    "artifacts": [item.to_dict() for item in artifacts],
                },
            )
        except Exception as exc:
            return self._error_result("UI mapping failed unexpectedly.", exc)

    def detect_elements(
        self,
        context: Union[VisualContext, Mapping[str, Any]],
        image: Optional[Union[str, Path, bytes, Mapping[str, Any]]] = None,
        ocr_text: Optional[str] = None,
        existing_elements: Optional[Sequence[Mapping[str, Any]]] = None,
        privacy_mode: str = "safe",
    ) -> Dict[str, Any]:
        """
        Detect likely UI elements.

        If an element_detector component exists, it is used. Otherwise, a safe text-based
        heuristic extracts likely UI controls from OCR text and existing observations.
        """
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            approval = self._maybe_request_security(
                context=ctx,
                visual_type="element_detection",
                action="detect_elements",
                payload={"privacy_mode": privacy_mode},
            )
            if not approval["success"]:
                return approval

            findings: List[VisualFinding] = []
            artifacts: List[VisualArtifact] = []
            elements: List[VisualElement] = []

            for index, item in enumerate(existing_elements or []):
                elements.append(self._element_from_mapping(item, index=index))

            if self.element_detector and hasattr(self.element_detector, "detect_elements"):
                component_result = self._call_component_safe(
                    self.element_detector.detect_elements,
                    context=ctx,
                    image=image,
                    ocr_text=ocr_text,
                    existing_elements=existing_elements or [],
                )
                self._merge_component_result(component_result, findings, artifacts, elements, "element_detector")

            heuristic_elements = self._detect_elements_from_text(ocr_text or "")
            elements.extend(heuristic_elements)
            elements = self._deduplicate_elements(elements)

            findings.append(
                VisualFinding(
                    check_name="element_detection",
                    status=VisualStatus.PASSED if elements else VisualStatus.NEEDS_REVIEW,
                    message=(
                        f"Detected or normalized {len(elements)} element(s)."
                        if elements
                        else "No UI elements detected."
                    ),
                    actual={"element_count": len(elements)},
                    confidence=0.7 if elements else 0.3,
                    severity=VisualSeverity.INFO if elements else VisualSeverity.MEDIUM,
                )
            )

            artifacts.append(
                VisualArtifact(
                    artifact_id=_safe_uuid("artifact"),
                    artifact_type="element_detection",
                    title="Detected visual elements",
                    data={
                        "elements": [item.to_dict() for item in elements],
                        "ocr_text_hash": _sha256_text(ocr_text or "") if ocr_text else None,
                    },
                    created_at=_utc_now(),
                    confidence=0.7 if elements else 0.3,
                    privacy_filtered=privacy_mode != "raw",
                )
            )

            return self._safe_result(
                message="Element detection completed.",
                data={
                    "elements": [item.to_dict() for item in elements],
                    "findings": [item.to_dict() for item in findings],
                    "artifacts": [item.to_dict() for item in artifacts],
                },
            )
        except Exception as exc:
            return self._error_result("Element detection failed unexpectedly.", exc)

    def filter_privacy(
        self,
        context: Union[VisualContext, Mapping[str, Any]],
        text: Optional[str] = None,
        artifacts: Optional[Sequence[Mapping[str, Any]]] = None,
        mode: str = "safe",
    ) -> Dict[str, Any]:
        """
        Filter sensitive text/artifact data.

        Modes:
            raw      - no redaction, requires explicit permission
            safe     - redact common sensitive text patterns
            strict   - redact and reduce artifact data more aggressively
        """
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            if mode == "raw" and not ctx.get("permissions", {}).get("allow_raw_visual_data"):
                return self._error_result(
                    message="Raw visual data mode requires explicit allow_raw_visual_data permission.",
                    error="raw_visual_data_blocked",
                    metadata={"mode": mode},
                )

            findings: List[VisualFinding] = []
            filtered_text = text or ""
            privacy_matches: List[Dict[str, Any]] = []

            if self.privacy_filter and hasattr(self.privacy_filter, "filter_privacy"):
                component_result = self._call_component_safe(
                    self.privacy_filter.filter_privacy,
                    context=ctx,
                    text=text or "",
                    artifacts=list(artifacts or []),
                    mode=mode,
                )
                if component_result.get("success"):
                    filtered_text = component_result.get("data", {}).get("text", filtered_text)
                    privacy_matches.extend(component_result.get("data", {}).get("privacy_matches", []))

            if self.enable_builtin_privacy_filter and mode != "raw":
                filtered_text, builtin_matches = _redact_text(filtered_text)
                privacy_matches.extend(builtin_matches)

            filtered_artifacts = []
            for item in artifacts or []:
                filtered_artifacts.append(self._privacy_filter_artifact(dict(item), mode=mode))

            risk_score = self._calculate_privacy_risk(privacy_matches)

            findings.append(
                VisualFinding(
                    check_name="privacy_filter",
                    status=VisualStatus.PASSED if risk_score < 0.8 else VisualStatus.NEEDS_REVIEW,
                    message=(
                        "Privacy filter completed."
                        if risk_score < 0.8
                        else "Privacy filter found high-risk sensitive visual text."
                    ),
                    severity=VisualSeverity.HIGH if risk_score >= 0.8 else VisualSeverity.INFO,
                    actual={"privacy_match_count": len(privacy_matches), "risk_score": risk_score},
                    confidence=0.85,
                )
            )

            return self._safe_result(
                message="Privacy filtering completed.",
                data={
                    "text": filtered_text,
                    "artifacts": filtered_artifacts,
                    "privacy_matches": privacy_matches,
                    "privacy_risk_score": risk_score,
                    "findings": [item.to_dict() for item in findings],
                },
            )
        except Exception as exc:
            return self._error_result("Privacy filtering failed unexpectedly.", exc)

    def read_form(
        self,
        context: Union[VisualContext, Mapping[str, Any]],
        elements: Sequence[Mapping[str, Any]],
        ocr_text: Optional[str] = None,
        privacy_mode: str = "safe",
    ) -> Dict[str, Any]:
        """Read likely form fields from UI elements and OCR text."""
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            mapped = [self._element_from_mapping(item, index=index) for index, item in enumerate(elements)]
            fields: List[Dict[str, Any]] = []

            for element in mapped:
                combined = _lower(f"{element.label or ''} {element.text or ''} {element.element_type}")
                if any(keyword in combined for keyword in ["input", "field", "email", "password", "name", "phone", "search"]):
                    field_type = "text"
                    if "email" in combined:
                        field_type = "email"
                    elif "password" in combined:
                        field_type = "password"
                    elif "phone" in combined:
                        field_type = "phone"
                    elif "search" in combined:
                        field_type = "search"

                    fields.append(
                        {
                            "field_id": element.element_id,
                            "field_type": field_type,
                            "label": element.label or element.text,
                            "bbox": element.bbox.to_dict() if element.bbox else None,
                            "visible": element.visible,
                            "enabled": element.enabled,
                            "confidence": element.confidence,
                        }
                    )

            text = ocr_text or ""
            if text and not fields:
                for keyword in ["email", "password", "name", "phone", "search", "message"]:
                    if keyword in _lower(text):
                        fields.append(
                            {
                                "field_id": f"field_{keyword}",
                                "field_type": keyword,
                                "label": keyword.title(),
                                "bbox": None,
                                "visible": True,
                                "enabled": None,
                                "confidence": 0.35,
                            }
                        )

            if privacy_mode != "raw":
                for field in fields:
                    if field.get("field_type") == "password":
                        field["label"] = "[REDACTED_PASSWORD_FIELD]"

            finding = VisualFinding(
                check_name="form_reader",
                status=VisualStatus.PASSED if fields else VisualStatus.NEEDS_REVIEW,
                message=f"Detected {len(fields)} form field(s)." if fields else "No form fields detected.",
                actual={"field_count": len(fields)},
                confidence=0.75 if fields else 0.3,
                severity=VisualSeverity.INFO if fields else VisualSeverity.MEDIUM,
            )

            artifact = VisualArtifact(
                artifact_id=_safe_uuid("artifact"),
                artifact_type="form_fields",
                title="Detected form fields",
                data={"fields": fields},
                created_at=_utc_now(),
                confidence=0.75 if fields else 0.3,
                privacy_filtered=privacy_mode != "raw",
            )

            return self._safe_result(
                message="Form reading completed.",
                data={
                    "fields": fields,
                    "findings": [finding.to_dict()],
                    "artifacts": [artifact.to_dict()],
                },
            )
        except Exception as exc:
            return self._error_result("Form reading failed unexpectedly.", exc)

    def detect_error_screen(
        self,
        context: Union[VisualContext, Mapping[str, Any]],
        ocr_text: Optional[str] = None,
        elements: Optional[Sequence[Mapping[str, Any]]] = None,
        signals: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Detect common error/warning/blocked screen states."""
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result

            text = _lower(ocr_text or "")
            signals = dict(signals or {})
            elements_text = " ".join(
                _lower(f"{item.get('text', '')} {item.get('label', '')} {item.get('element_type', '')}")
                for item in (elements or [])
            )
            combined = f"{text} {elements_text}"

            error_keywords = {
                "not_found": ["404", "not found", "page not found"],
                "server_error": ["500", "502", "503", "server error", "internal error"],
                "permission": ["permission denied", "access denied", "unauthorized", "forbidden", "blocked"],
                "network": ["network error", "connection failed", "timeout", "offline"],
                "validation": ["invalid", "required", "missing", "try again"],
                "crash": ["crash", "stopped working", "unexpected error"],
            }

            detected: List[Dict[str, Any]] = []
            for error_type, keywords in error_keywords.items():
                matched = [keyword for keyword in keywords if keyword in combined]
                if matched:
                    detected.append(
                        {
                            "error_type": error_type,
                            "matched_keywords": matched,
                            "confidence": min(0.95, 0.55 + 0.1 * len(matched)),
                        }
                    )

            if signals.get("http_status") and int(signals.get("http_status", 0)) >= 400:
                detected.append(
                    {
                        "error_type": "http_status",
                        "http_status": signals.get("http_status"),
                        "confidence": 0.9,
                    }
                )

            finding = VisualFinding(
                check_name="error_screen_detector",
                status=VisualStatus.PASSED if detected else VisualStatus.NEEDS_REVIEW,
                message=(
                    f"Detected {len(detected)} error screen signal(s)."
                    if detected
                    else "No clear error screen signal detected."
                ),
                severity=VisualSeverity.HIGH if detected else VisualSeverity.INFO,
                actual={"detected_errors": detected},
                confidence=max([item.get("confidence", 0.0) for item in detected], default=0.4),
            )

            artifact = VisualArtifact(
                artifact_id=_safe_uuid("artifact"),
                artifact_type="error_screen_detection",
                title="Error screen detection",
                data={"detected_errors": detected, "signals": signals},
                created_at=_utc_now(),
                confidence=finding.confidence,
                privacy_filtered=True,
            )

            return self._safe_result(
                message="Error screen detection completed.",
                data={
                    "detected_errors": detected,
                    "has_error_screen": bool(detected),
                    "findings": [finding.to_dict()],
                    "artifacts": [artifact.to_dict()],
                },
            )
        except Exception as exc:
            return self._error_result("Error screen detection failed unexpectedly.", exc)

    def validate_visual_state(
        self,
        context: Union[VisualContext, Mapping[str, Any]],
        expected: Mapping[str, Any],
        actual: Mapping[str, Any],
        privacy_mode: str = "safe",
    ) -> Dict[str, Any]:
        """
        Validate expected visual state against actual visual observations.

        Supported expected keys:
            - contains_text: list[str] or str
            - not_contains_text: list[str] or str
            - required_elements: list[str]
            - min_elements: int
            - image_exists: bool
        """
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result

            findings: List[VisualFinding] = []
            artifacts: List[VisualArtifact] = []

            actual_text = _lower(actual.get("text", ""))
            actual_elements = actual.get("elements", []) or []
            element_blob = _lower(json.dumps(actual_elements, default=str))

            for text in self._ensure_list(expected.get("contains_text")):
                passed = _lower(text) in actual_text
                findings.append(
                    VisualFinding(
                        check_name=f"contains_text:{str(text)[:40]}",
                        status=VisualStatus.PASSED if passed else VisualStatus.FAILED,
                        message="Expected text found." if passed else "Expected text missing.",
                        expected=text,
                        actual="[visual text checked]",
                        severity=VisualSeverity.HIGH if not passed else VisualSeverity.INFO,
                        confidence=0.85 if passed else 0.25,
                    )
                )

            for text in self._ensure_list(expected.get("not_contains_text")):
                passed = _lower(text) not in actual_text
                findings.append(
                    VisualFinding(
                        check_name=f"not_contains_text:{str(text)[:40]}",
                        status=VisualStatus.PASSED if passed else VisualStatus.FAILED,
                        message="Forbidden text absent." if passed else "Forbidden text was found.",
                        expected=f"not contains {text}",
                        actual="[visual text checked]",
                        severity=VisualSeverity.HIGH if not passed else VisualSeverity.INFO,
                        confidence=0.85 if passed else 0.25,
                    )
                )

            for label in self._ensure_list(expected.get("required_elements")):
                passed = _lower(label) in element_blob or _lower(label) in actual_text
                findings.append(
                    VisualFinding(
                        check_name=f"required_element:{str(label)[:40]}",
                        status=VisualStatus.PASSED if passed else VisualStatus.FAILED,
                        message="Required visual element found." if passed else "Required visual element missing.",
                        expected=label,
                        actual={"element_count": len(actual_elements)},
                        severity=VisualSeverity.HIGH if not passed else VisualSeverity.INFO,
                        confidence=0.75 if passed else 0.25,
                    )
                )

            if "min_elements" in expected:
                min_elements = _safe_int(expected.get("min_elements"), 0)
                passed = len(actual_elements) >= min_elements
                findings.append(
                    VisualFinding(
                        check_name="min_elements",
                        status=VisualStatus.PASSED if passed else VisualStatus.FAILED,
                        message=(
                            "Minimum element count met."
                            if passed
                            else "Minimum element count not met."
                        ),
                        expected=min_elements,
                        actual=len(actual_elements),
                        severity=VisualSeverity.MEDIUM if not passed else VisualSeverity.INFO,
                        confidence=0.8 if passed else 0.3,
                    )
                )

            if "image_exists" in expected:
                image_exists = bool(actual.get("image"))
                passed = image_exists == bool(expected["image_exists"])
                findings.append(
                    VisualFinding(
                        check_name="image_exists",
                        status=VisualStatus.PASSED if passed else VisualStatus.FAILED,
                        message="Image existence matched expectation." if passed else "Image existence mismatch.",
                        expected=expected["image_exists"],
                        actual=image_exists,
                        confidence=0.85,
                    )
                )

            if not findings:
                findings.append(
                    VisualFinding(
                        check_name="visual_validation_criteria",
                        status=VisualStatus.NEEDS_REVIEW,
                        message="No supported visual validation criteria were provided.",
                        severity=VisualSeverity.MEDIUM,
                        confidence=0.35,
                    )
                )

            artifacts.append(
                VisualArtifact(
                    artifact_id=_safe_uuid("artifact"),
                    artifact_type="visual_validation",
                    title="Visual state validation",
                    data={
                        "expected": dict(expected),
                        "actual_summary": {
                            "text_hash": _sha256_text(actual_text) if actual_text else None,
                            "text_char_count": len(actual_text),
                            "element_count": len(actual_elements),
                            "has_image": bool(actual.get("image")),
                        },
                    },
                    created_at=_utc_now(),
                    confidence=self._calculate_confidence(findings),
                    privacy_filtered=privacy_mode != "raw",
                )
            )

            return self._safe_result(
                message="Visual validation completed.",
                data={
                    "findings": [item.to_dict() for item in findings],
                    "artifacts": [item.to_dict() for item in artifacts],
                },
            )
        except Exception as exc:
            return self._error_result("Visual state validation failed unexpectedly.", exc)

    def annotate_elements(
        self,
        context: Union[VisualContext, Mapping[str, Any]],
        elements: Sequence[Mapping[str, Any]],
        annotation_style: str = "labels",
    ) -> Dict[str, Any]:
        """
        Prepare annotation metadata for UI overlays.

        This method does not edit images directly. annotation_tool.py can later use this
        payload to render boxes/labels on screenshots.
        """
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result

            normalized = [
                self._element_from_mapping(item, index=index).to_dict()
                for index, item in enumerate(elements[: self.max_elements] if isinstance(elements, list) else list(elements)[: self.max_elements])
            ]

            annotations = []
            for index, element in enumerate(normalized):
                bbox = element.get("bbox") or {}
                annotations.append(
                    {
                        "annotation_id": _safe_uuid("ann"),
                        "element_id": element.get("element_id"),
                        "label": element.get("label") or element.get("text") or f"Element {index + 1}",
                        "element_type": element.get("element_type"),
                        "bbox": bbox,
                        "style": annotation_style,
                        "confidence": element.get("confidence", 0.5),
                    }
                )

            finding = VisualFinding(
                check_name="annotation_payload",
                status=VisualStatus.PASSED if annotations else VisualStatus.NEEDS_REVIEW,
                message=f"Prepared {len(annotations)} annotation(s).",
                actual={"annotation_count": len(annotations)},
                confidence=0.8 if annotations else 0.3,
            )

            artifact = VisualArtifact(
                artifact_id=_safe_uuid("artifact"),
                artifact_type="annotation_payload",
                title="Element annotation payload",
                data={"annotations": annotations, "style": annotation_style},
                created_at=_utc_now(),
                confidence=finding.confidence,
                privacy_filtered=True,
            )

            return self._safe_result(
                message="Annotation payload prepared.",
                data={
                    "annotations": annotations,
                    "findings": [finding.to_dict()],
                    "artifacts": [artifact.to_dict()],
                },
            )
        except Exception as exc:
            return self._error_result("Annotation preparation failed unexpectedly.", exc)

    def build_screen_context(
        self,
        context: Union[VisualContext, Mapping[str, Any]],
        text: Optional[str] = None,
        elements: Optional[Sequence[Mapping[str, Any]]] = None,
        image_metadata: Optional[Mapping[str, Any]] = None,
        app_metadata: Optional[Mapping[str, Any]] = None,
        privacy_mode: str = "safe",
    ) -> Dict[str, Any]:
        """Build a dashboard/MasterAgent-friendly screen context summary."""
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result

            filtered_text = text or ""
            privacy_matches: List[Dict[str, Any]] = []

            if privacy_mode != "raw":
                filtered_text, privacy_matches = _redact_text(filtered_text)

            normalized_elements = [
                self._element_from_mapping(item, index=index).to_dict()
                for index, item in enumerate(list(elements or [])[: self.max_elements])
            ]

            context_summary = {
                "text": filtered_text[: self.max_ocr_chars],
                "text_hash": _sha256_text(text or "") if text else None,
                "text_char_count": len(text or ""),
                "element_count": len(normalized_elements),
                "elements": normalized_elements,
                "image_metadata": dict(image_metadata or {}),
                "app_metadata": dict(app_metadata or {}),
                "privacy_matches": privacy_matches,
                "privacy_risk_score": self._calculate_privacy_risk(privacy_matches),
                "privacy_mode": privacy_mode,
                "created_at": _utc_now(),
            }

            finding = VisualFinding(
                check_name="screen_context",
                status=VisualStatus.PASSED,
                message="Screen context summary prepared.",
                actual={
                    "text_char_count": context_summary["text_char_count"],
                    "element_count": context_summary["element_count"],
                    "privacy_risk_score": context_summary["privacy_risk_score"],
                },
                confidence=0.8,
            )

            artifact = VisualArtifact(
                artifact_id=_safe_uuid("artifact"),
                artifact_type="screen_context",
                title="Screen context summary",
                data=context_summary,
                created_at=_utc_now(),
                confidence=0.8,
                privacy_filtered=privacy_mode != "raw",
            )

            return self._safe_result(
                message="Screen context built.",
                data={
                    "screen_context": context_summary,
                    "findings": [finding.to_dict()],
                    "artifacts": [artifact.to_dict()],
                },
            )
        except Exception as exc:
            return self._error_result("Screen context build failed unexpectedly.", exc)

    def generate_visual_report(
        self,
        context: Union[VisualContext, Mapping[str, Any]],
        task_type: str,
        findings: Sequence[Union[VisualFinding, Mapping[str, Any]]],
        elements: Optional[Sequence[Union[VisualElement, Mapping[str, Any]]]] = None,
        artifacts: Optional[Sequence[Union[VisualArtifact, Mapping[str, Any]]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate a structured visual report from existing findings/elements/artifacts."""
        try:
            ctx_result = self._validate_task_context(context)
            if not ctx_result["success"]:
                return ctx_result
            ctx = ctx_result["data"]["context"]

            normalized_findings = [
                item if isinstance(item, VisualFinding) else self._finding_from_dict(item)
                for item in findings
            ]
            normalized_elements = [
                item if isinstance(item, VisualElement) else self._element_from_mapping(item, index=index)
                for index, item in enumerate(elements or [])
            ]
            normalized_artifacts = [
                item if isinstance(item, VisualArtifact) else self._artifact_from_dict(item)
                for item in (artifacts or [])
            ]

            report = self._build_report(
                context=ctx,
                task_type=self._task_type_from_string(task_type),
                findings=normalized_findings,
                elements=normalized_elements,
                artifacts=normalized_artifacts,
                metadata=dict(metadata or {}),
            )

            return self._safe_result(
                message=report.summary,
                data={
                    "report": report.to_dict(),
                    "verification_payload": self._prepare_verification_payload(report, ctx),
                    "memory_payload": self._prepare_memory_payload(report, ctx),
                },
            )
        except Exception as exc:
            return self._error_result("Visual report generation failed unexpectedly.", exc)

    # ----------------------------------------------------------------------------------
    # Required compatibility hooks
    # ----------------------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[VisualContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Validate SaaS user/workspace context."""
        try:
            if isinstance(context, VisualContext):
                ctx = context.to_dict()
            elif isinstance(context, Mapping):
                ctx = dict(context)
            else:
                return self._error_result(
                    message="Invalid visual context.",
                    error="context must be VisualContext or mapping",
                )

            user_id = ctx.get("user_id")
            workspace_id = ctx.get("workspace_id")

            if not isinstance(user_id, str) or not user_id.strip():
                return self._error_result(
                    message="Visual context missing user_id.",
                    error="missing_user_id",
                    metadata={"hook": "_validate_task_context"},
                )

            if not isinstance(workspace_id, str) or not workspace_id.strip():
                return self._error_result(
                    message="Visual context missing workspace_id.",
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
                message="Visual context is valid.",
                data={"context": ctx},
                metadata={"hook": "_validate_task_context"},
            )
        except Exception as exc:
            return self._error_result("Visual context validation failed unexpectedly.", exc)

    def _requires_security_check(
        self,
        visual_type: str,
        payload: Optional[Mapping[str, Any]] = None,
        context: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide if a visual operation requires Security Agent approval.

        Safe defaults:
            - Screenshot/screen/video/OCR/UI mapping tasks are sensitive.
            - Context can explicitly allow selected visual verification operations.
        """
        payload = dict(payload or {})
        context = dict(context or {})
        permissions = dict(context.get("permissions") or {})
        vt = _lower(visual_type)

        if permissions.get("allow_sensitive_visual_tasks") is True:
            return False

        specific_key = f"allow_{vt}_visual"
        if permissions.get(specific_key) is True:
            return False

        if vt in SENSITIVE_VISUAL_TYPES:
            return True

        raw = json.dumps(_json_safe(payload), default=str).lower()
        sensitive_words = ["password", "secret", "token", "credential", "private", "screenshot", "screen"]
        if any(word in raw for word in sensitive_words):
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

        If Security Agent is not connected, sensitive visual operations are blocked
        unless context permissions explicitly allow bypass.
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
                        message="Security Agent approved visual action.",
                        data={"approved": True, "decision": _json_safe(dict(decision))},
                        metadata={"hook": "_request_security_approval", "action": action},
                    )
                return self._error_result(
                    message="Security Agent blocked visual action.",
                    error=decision.get("error") or decision.get("reason") or "security_blocked",
                    metadata={"decision": _json_safe(dict(decision)), "action": action},
                )

            if bool(decision):
                return self._safe_result(
                    message="Security Agent approved visual action.",
                    data={"approved": True, "decision": bool(decision)},
                    metadata={"hook": "_request_security_approval", "action": action},
                )

            return self._error_result(
                message="Security Agent blocked visual action.",
                error="security_blocked",
                metadata={"action": action},
            )
        except Exception as exc:
            return self._error_result("Security approval request failed.", exc)

    def _prepare_verification_payload(
        self,
        report: Union[VisualReport, Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent compatible payload."""
        report_data = report.to_dict() if isinstance(report, VisualReport) else dict(report)
        ctx = dict(context or report_data.get("context") or {})

        return {
            "agent": self.agent_name,
            "type": "visual_verification_payload",
            "version": self.agent_version,
            "user_id": ctx.get("user_id"),
            "workspace_id": ctx.get("workspace_id"),
            "task_id": ctx.get("task_id"),
            "request_id": ctx.get("request_id"),
            "status": report_data.get("status"),
            "confidence": report_data.get("confidence"),
            "report_id": report_data.get("report_id"),
            "summary": report_data.get("summary"),
            "visual_task_type": report_data.get("task_type"),
            "privacy_risk_score": report_data.get("privacy_risk_score"),
            "findings_count": len(report_data.get("findings") or []),
            "elements_count": len(report_data.get("elements") or []),
            "artifacts_count": len(report_data.get("artifacts") or []),
            "created_at": _utc_now(),
            "data": {
                "report": report_data,
            },
        }

    def _prepare_memory_payload(
        self,
        report: Union[VisualReport, Mapping[str, Any]],
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Raw image bytes, full OCR secrets, and unfiltered screenshots are not included.
        """
        report_data = report.to_dict() if isinstance(report, VisualReport) else dict(report)
        ctx = dict(context or report_data.get("context") or {})

        safe_findings = []
        for item in report_data.get("findings", [])[:10]:
            safe_findings.append(
                {
                    "check_name": item.get("check_name"),
                    "status": item.get("status"),
                    "message": item.get("message"),
                    "severity": item.get("severity"),
                    "confidence": item.get("confidence"),
                }
            )

        safe_elements = []
        for item in report_data.get("elements", [])[:25]:
            safe_elements.append(
                {
                    "element_id": item.get("element_id"),
                    "element_type": item.get("element_type"),
                    "label": item.get("label"),
                    "visible": item.get("visible"),
                    "confidence": item.get("confidence"),
                }
            )

        return {
            "agent": self.agent_name,
            "type": "visual_memory",
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
                "task_type": report_data.get("task_type"),
                "privacy_risk_score": report_data.get("privacy_risk_score"),
                "findings": safe_findings,
                "elements": safe_elements,
            },
            "created_at": _utc_now(),
            "metadata": {
                "source_agent": self.agent_name,
                "raw_visual_data_excluded": True,
                "privacy_filtered": True,
            },
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """Emit event through configured event emitter or BaseAgent fallback."""
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
            self.logger.warning("Failed to emit visual event '%s': %s", event_name, exc)

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
            self.logger.warning("Failed to log visual audit event: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standardized success result."""
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
        """Return standardized error result."""
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
        """Load VisualConfig if available; otherwise use fallback config."""
        if VisualConfig is not None:
            try:
                return VisualConfig()
            except Exception:
                pass

        class _FallbackConfig:
            max_image_bytes = DEFAULT_MAX_IMAGE_BYTES
            max_ocr_chars = DEFAULT_MAX_OCR_CHARS
            max_elements = DEFAULT_MAX_ELEMENTS
            max_frames = DEFAULT_MAX_FRAMES
            default_confidence_threshold = DEFAULT_CONFIDENCE_THRESHOLD
            enable_builtin_privacy_filter = True

        return _FallbackConfig()

    def _maybe_request_security(
        self,
        context: Mapping[str, Any],
        visual_type: str,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Request Security Agent approval only when required."""
        if self._requires_security_check(visual_type, payload=payload, context=context):
            return self._request_security_approval(context=context, action=action, payload=payload)
        return self._safe_result(
            message="Security approval not required.",
            data={"approved": True, "required": False},
            metadata={"action": action},
        )

    def _inspect_visual_input(
        self,
        visual_input: Union[str, Path, bytes, Mapping[str, Any]],
        expected_kind: str,
    ) -> Dict[str, Any]:
        """Inspect image/video/screenshot input without exposing raw bytes."""
        try:
            metadata: Dict[str, Any] = {
                "input_kind": type(visual_input).__name__,
                "expected_kind": expected_kind,
                "source_type": None,
                "path": None,
                "exists": None,
                "size_bytes": None,
                "mime_type": None,
                "extension": None,
                "sha256": None,
                "width": None,
                "height": None,
                "format": None,
            }

            raw_bytes: Optional[bytes] = None

            if isinstance(visual_input, bytes):
                metadata["source_type"] = "bytes"
                metadata["size_bytes"] = len(visual_input)
                if len(visual_input) > self.max_image_bytes:
                    return self._error_result("Visual input bytes exceed max size.", "visual_input_too_large")
                raw_bytes = visual_input

            elif isinstance(visual_input, (str, Path)):
                raw_str = str(visual_input)
                if _looks_like_base64(raw_str):
                    metadata["source_type"] = "base64"
                    raw_bytes, error = _decode_base64_image(raw_str, self.max_image_bytes)
                    if error:
                        return self._error_result("Base64 visual input could not be decoded.", error)
                    metadata["size_bytes"] = len(raw_bytes or b"")
                else:
                    path = Path(raw_str).expanduser()
                    metadata["source_type"] = "path"
                    metadata["path"] = str(path)
                    metadata["exists"] = path.exists()
                    metadata["extension"] = path.suffix.lower()
                    metadata["mime_type"] = mimetypes.guess_type(str(path))[0]

                    if expected_kind == "image" and metadata["extension"] not in SUPPORTED_IMAGE_EXTENSIONS:
                        metadata["supported_extension"] = False
                    elif expected_kind == "video" and metadata["extension"] not in SUPPORTED_VIDEO_EXTENSIONS:
                        metadata["supported_extension"] = False
                    else:
                        metadata["supported_extension"] = True

                    raw_bytes, error = _safe_read_bytes(path, self.max_image_bytes)
                    if error:
                        metadata["read_error"] = error
                    else:
                        metadata["size_bytes"] = len(raw_bytes or b"")

            elif isinstance(visual_input, Mapping):
                metadata["source_type"] = "mapping"
                given = dict(visual_input)
                metadata.update(
                    {
                        "path": given.get("path"),
                        "width": given.get("width"),
                        "height": given.get("height"),
                        "format": given.get("format"),
                        "mime_type": given.get("mime_type"),
                        "extension": given.get("extension"),
                        "size_bytes": given.get("size_bytes"),
                    }
                )

                if given.get("bytes") and isinstance(given["bytes"], bytes):
                    raw_bytes = given["bytes"]
                    metadata["size_bytes"] = len(raw_bytes)
                elif given.get("base64") and isinstance(given["base64"], str):
                    raw_bytes, error = _decode_base64_image(given["base64"], self.max_image_bytes)
                    if error:
                        return self._error_result("Mapping base64 visual input could not be decoded.", error)
                    metadata["size_bytes"] = len(raw_bytes or b"")
                elif given.get("path"):
                    path = Path(str(given["path"])).expanduser()
                    metadata["path"] = str(path)
                    metadata["exists"] = path.exists()
                    metadata["extension"] = path.suffix.lower()
                    metadata["mime_type"] = mimetypes.guess_type(str(path))[0]
                    raw_bytes, error = _safe_read_bytes(path, self.max_image_bytes)
                    if error:
                        metadata["read_error"] = error
                    else:
                        metadata["size_bytes"] = len(raw_bytes or b"")
            else:
                return self._error_result("Unsupported visual input type.", type(visual_input).__name__)

            if raw_bytes:
                metadata["sha256"] = _sha256_bytes(raw_bytes)

                if Image is not None and expected_kind == "image":
                    try:
                        import io

                        with Image.open(io.BytesIO(raw_bytes)) as img:
                            metadata["width"] = img.width
                            metadata["height"] = img.height
                            metadata["format"] = img.format
                            metadata["mime_type"] = Image.MIME.get(img.format, metadata.get("mime_type"))
                    except Exception as exc:
                        metadata["image_parse_error"] = str(exc)

            metadata.pop("bytes", None)
            metadata.pop("base64", None)

            return self._safe_result(
                message="Visual input inspected.",
                data=metadata,
            )
        except Exception as exc:
            return self._error_result("Visual input inspection failed.", exc)

    def _call_component_safe(self, method: Callable[..., Any], **kwargs: Any) -> Dict[str, Any]:
        """Call optional component safely and normalize result."""
        try:
            result = method(**kwargs)
            if isinstance(result, Mapping):
                return dict(result)
            return self._safe_result(
                message="Component returned non-mapping result.",
                data={"result": _json_safe(result)},
            )
        except TypeError:
            try:
                result = method()
                if isinstance(result, Mapping):
                    return dict(result)
                return self._safe_result(
                    message="Component returned non-mapping result.",
                    data={"result": _json_safe(result)},
                )
            except Exception as exc:
                return self._error_result("Component call failed.", exc)
        except Exception as exc:
            return self._error_result("Component call failed.", exc)

    def _merge_component_result(
        self,
        component_result: Mapping[str, Any],
        findings: List[VisualFinding],
        artifacts: List[VisualArtifact],
        elements: List[VisualElement],
        component_name: str,
    ) -> None:
        """Merge optional component structured result into current lists."""
        try:
            if not component_result.get("success"):
                findings.append(
                    VisualFinding(
                        check_name=component_name,
                        status=VisualStatus.NEEDS_REVIEW,
                        message=f"{component_name} did not complete successfully.",
                        severity=VisualSeverity.MEDIUM,
                        actual=component_result.get("error"),
                        confidence=0.35,
                    )
                )
                return

            data = component_result.get("data", {}) or {}

            for item in data.get("findings", []):
                findings.append(self._finding_from_dict(item))

            for item in data.get("artifacts", []):
                artifacts.append(self._artifact_from_dict(item))

            for index, item in enumerate(data.get("elements", [])):
                elements.append(self._element_from_mapping(item, index=index))

            findings.append(
                VisualFinding(
                    check_name=component_name,
                    status=VisualStatus.PASSED,
                    message=f"{component_name} completed successfully.",
                    confidence=0.75,
                    evidence={"component_message": component_result.get("message")},
                )
            )
        except Exception as exc:
            findings.append(
                VisualFinding(
                    check_name=component_name,
                    status=VisualStatus.ERROR,
                    message=f"{component_name} merge failed.",
                    severity=VisualSeverity.MEDIUM,
                    actual=str(exc),
                    confidence=0.1,
                )
            )

    def _element_from_mapping(self, item: Mapping[str, Any], index: int = 0) -> VisualElement:
        """Normalize mapping into VisualElement."""
        bbox_raw = item.get("bbox") or item.get("bounds") or item.get("rect")
        bbox = None

        if isinstance(bbox_raw, Mapping):
            x = _safe_int(bbox_raw.get("x", bbox_raw.get("left", 0)))
            y = _safe_int(bbox_raw.get("y", bbox_raw.get("top", 0)))
            if "width" in bbox_raw:
                width = _safe_int(bbox_raw.get("width"))
            else:
                width = max(0, _safe_int(bbox_raw.get("right")) - x)
            if "height" in bbox_raw:
                height = _safe_int(bbox_raw.get("height"))
            else:
                height = max(0, _safe_int(bbox_raw.get("bottom")) - y)
            bbox = BoundingBox(
                x=x,
                y=y,
                width=width,
                height=height,
                confidence=_clamp_float(bbox_raw.get("confidence", 1.0), 1.0),
                coordinate_system=str(bbox_raw.get("coordinate_system") or "pixels"),
            )

        element_id = str(
            item.get("element_id")
            or item.get("id")
            or item.get("selector")
            or item.get("resource_id")
            or f"element_{index + 1}_{_safe_uuid('id')}"
        )

        return VisualElement(
            element_id=element_id,
            element_type=str(item.get("element_type") or item.get("type") or item.get("role") or "unknown"),
            label=item.get("label") or item.get("name") or item.get("content_description"),
            text=item.get("text"),
            bbox=bbox,
            visible=bool(item.get("visible", True)),
            enabled=item.get("enabled"),
            clickable=item.get("clickable"),
            confidence=_clamp_float(item.get("confidence", 0.5), 0.5),
            metadata=dict(item.get("metadata") or {}),
        )

    def _finding_from_dict(self, item: Mapping[str, Any]) -> VisualFinding:
        """Normalize mapping into VisualFinding."""
        return VisualFinding(
            check_name=str(item.get("check_name") or item.get("name") or "unnamed_visual_check"),
            status=self._status_from_string(str(item.get("status") or VisualStatus.NEEDS_REVIEW.value)),
            message=str(item.get("message") or ""),
            severity=self._severity_from_string(str(item.get("severity") or VisualSeverity.INFO.value)),
            expected=item.get("expected"),
            actual=item.get("actual"),
            confidence=_clamp_float(item.get("confidence", 0.5), 0.5),
            evidence=dict(item.get("evidence") or {}),
            remediation=item.get("remediation"),
        )

    def _artifact_from_dict(self, item: Mapping[str, Any]) -> VisualArtifact:
        """Normalize mapping into VisualArtifact."""
        return VisualArtifact(
            artifact_id=str(item.get("artifact_id") or _safe_uuid("artifact")),
            artifact_type=str(item.get("artifact_type") or item.get("type") or "visual_artifact"),
            title=str(item.get("title") or "Visual artifact"),
            data=_json_safe(item.get("data")),
            created_at=str(item.get("created_at") or _utc_now()),
            source=str(item.get("source") or self.agent_name),
            confidence=_clamp_float(item.get("confidence", 1.0), 1.0),
            privacy_filtered=bool(item.get("privacy_filtered", False)),
            metadata=dict(item.get("metadata") or {}),
        )

    def _elements_from_data(self, items: Sequence[Mapping[str, Any]]) -> List[VisualElement]:
        return [self._element_from_mapping(item, index=index) for index, item in enumerate(items)]

    def _deduplicate_elements(self, elements: Sequence[VisualElement]) -> List[VisualElement]:
        """Deduplicate visual elements by ID/type/text/bbox center."""
        seen = set()
        output: List[VisualElement] = []

        for item in elements:
            bbox_key = None
            if item.bbox:
                bbox_key = (item.bbox.center_x, item.bbox.center_y, item.bbox.width, item.bbox.height)

            key = (
                item.element_id,
                item.element_type,
                _lower(item.label or item.text or ""),
                bbox_key,
            )

            if key in seen:
                continue
            seen.add(key)
            output.append(item)

            if len(output) >= self.max_elements:
                break

        return output

    def _detect_elements_from_text(self, text: str) -> List[VisualElement]:
        """Heuristic text-based UI element detector."""
        clean = _normalize_text(text)
        if not clean:
            return []

        elements: List[VisualElement] = []
        lower_text = clean.lower()

        for element_type, keywords in COMMON_UI_KEYWORDS.items():
            for keyword in keywords:
                if keyword in lower_text:
                    elements.append(
                        VisualElement(
                            element_id=f"heuristic_{element_type}_{_sha256_text(keyword)[:8]}",
                            element_type=element_type,
                            label=keyword.title(),
                            text=keyword,
                            bbox=None,
                            visible=True,
                            enabled=None,
                            clickable=element_type in {"button", "link"},
                            confidence=0.35,
                            metadata={"source": "ocr_text_heuristic"},
                        )
                    )

        return elements

    def _summarize_frames(
        self,
        frames: Sequence[Mapping[str, Any]],
        privacy_mode: str = "safe",
    ) -> Dict[str, Any]:
        """Summarize provided video frame observations safely."""
        text_parts: List[str] = []
        element_count = 0
        timestamps: List[Any] = []

        for frame in frames:
            if frame.get("timestamp") is not None:
                timestamps.append(frame.get("timestamp"))
            if frame.get("text"):
                text_parts.append(str(frame.get("text")))
            element_count += len(frame.get("elements") or [])

        combined_text = _normalize_text(" ".join(text_parts))[: self.max_ocr_chars]
        privacy_matches: List[Dict[str, Any]] = []

        if privacy_mode != "raw":
            combined_text, privacy_matches = _redact_text(combined_text)

        return {
            "frame_count": len(frames),
            "timestamps_sample": timestamps[:20],
            "combined_text": combined_text,
            "combined_text_hash": _sha256_text(" ".join(text_parts)) if text_parts else None,
            "element_count": element_count,
            "privacy_matches": privacy_matches,
            "privacy_risk_score": self._calculate_privacy_risk(privacy_matches),
        }

    def _privacy_filter_artifact(self, artifact: Dict[str, Any], mode: str) -> Dict[str, Any]:
        """Filter artifact data safely."""
        filtered = dict(artifact)
        data = filtered.get("data")

        if mode == "raw":
            return filtered

        if isinstance(data, str):
            filtered_text, matches = _redact_text(data)
            filtered["data"] = filtered_text
            filtered["privacy_matches"] = matches
        elif isinstance(data, Mapping):
            filtered_data = {}
            for key, value in data.items():
                key_lower = _lower(key)
                if mode == "strict" and key_lower in {"text", "raw_text", "ocr_text", "image", "bytes", "base64"}:
                    filtered_data[key] = "[FILTERED]"
                elif isinstance(value, str):
                    filtered_data[key] = _redact_text(value)[0]
                else:
                    filtered_data[key] = value
            filtered["data"] = filtered_data
        elif mode == "strict":
            filtered["data"] = "[FILTERED_NON_TEXT_ARTIFACT_DATA]"

        filtered["privacy_filtered"] = True
        return filtered

    def _calculate_privacy_risk(self, privacy_matches: Sequence[Mapping[str, Any]]) -> float:
        """Calculate privacy risk score from detected sensitive matches."""
        if not privacy_matches:
            return 0.0

        weights = {
            "password_hint": 0.35,
            "api_key_like": 0.9,
            "credit_card_like": 0.9,
            "ssn_like": 0.95,
            "email": 0.25,
            "phone": 0.35,
            "ipv4": 0.15,
        }

        score = 0.0
        for match in privacy_matches:
            score += weights.get(str(match.get("type")), 0.25)

        return round(min(1.0, score), 4)

    def _build_report(
        self,
        context: Mapping[str, Any],
        task_type: VisualTaskType,
        findings: Sequence[VisualFinding],
        elements: Sequence[VisualElement],
        artifacts: Sequence[VisualArtifact],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> VisualReport:
        """Build final VisualReport."""
        normalized_findings = list(findings)
        normalized_elements = list(elements)
        normalized_artifacts = list(artifacts)

        status = self._calculate_status(normalized_findings)
        confidence = self._calculate_confidence(normalized_findings)
        privacy_risk_score = self._calculate_report_privacy_risk(normalized_artifacts)
        summary = self._build_summary(
            status=status,
            task_type=task_type,
            findings=normalized_findings,
            elements=normalized_elements,
            artifacts=normalized_artifacts,
            confidence=confidence,
            privacy_risk_score=privacy_risk_score,
        )

        return VisualReport(
            report_id=_safe_uuid("visual_report"),
            status=status,
            task_type=task_type,
            summary=summary,
            findings=normalized_findings,
            elements=normalized_elements,
            artifacts=normalized_artifacts,
            confidence=confidence,
            privacy_risk_score=privacy_risk_score,
            created_at=_utc_now(),
            context=dict(context),
            metadata=dict(metadata or {}),
        )

    def _calculate_status(self, findings: Sequence[VisualFinding]) -> VisualStatus:
        """Calculate overall status from findings."""
        if not findings:
            return VisualStatus.NEEDS_REVIEW

        statuses = [item.status for item in findings]

        if any(status == VisualStatus.ERROR for status in statuses):
            return VisualStatus.ERROR
        if any(status == VisualStatus.BLOCKED for status in statuses):
            return VisualStatus.BLOCKED
        if any(status == VisualStatus.FAILED for status in statuses):
            passed_count = sum(1 for status in statuses if status == VisualStatus.PASSED)
            return VisualStatus.PARTIAL if passed_count else VisualStatus.FAILED
        if any(status == VisualStatus.NEEDS_REVIEW for status in statuses):
            passed_count = sum(1 for status in statuses if status == VisualStatus.PASSED)
            return VisualStatus.PARTIAL if passed_count else VisualStatus.NEEDS_REVIEW
        if all(status == VisualStatus.SKIPPED for status in statuses):
            return VisualStatus.SKIPPED
        if all(status == VisualStatus.PASSED for status in statuses):
            return VisualStatus.PASSED
        return VisualStatus.PARTIAL

    def _calculate_confidence(self, findings: Sequence[VisualFinding]) -> float:
        """Calculate weighted confidence."""
        if not findings:
            return 0.0

        severity_weight = {
            VisualSeverity.INFO: 1.0,
            VisualSeverity.LOW: 1.1,
            VisualSeverity.MEDIUM: 1.3,
            VisualSeverity.HIGH: 1.6,
            VisualSeverity.CRITICAL: 2.0,
        }

        total = 0.0
        weighted = 0.0

        for finding in findings:
            weight = severity_weight.get(finding.severity, 1.0)
            total += weight
            weighted += _clamp_float(finding.confidence, 0.5) * weight

        return round(weighted / total, 4) if total else 0.0

    def _calculate_report_privacy_risk(self, artifacts: Sequence[VisualArtifact]) -> float:
        """Calculate report-level privacy risk from artifact data."""
        max_score = 0.0

        for artifact in artifacts:
            data = artifact.data
            if isinstance(data, Mapping):
                matches = data.get("privacy_matches") or []
                score = data.get("privacy_risk_score")
                if score is not None:
                    max_score = max(max_score, _clamp_float(score))
                if matches:
                    max_score = max(max_score, self._calculate_privacy_risk(matches))

        return round(max_score, 4)

    def _build_summary(
        self,
        status: VisualStatus,
        task_type: VisualTaskType,
        findings: Sequence[VisualFinding],
        elements: Sequence[VisualElement],
        artifacts: Sequence[VisualArtifact],
        confidence: float,
        privacy_risk_score: float,
    ) -> str:
        """Build report summary."""
        total = len(findings)
        passed = sum(1 for item in findings if item.status == VisualStatus.PASSED)
        failed = sum(1 for item in findings if item.status == VisualStatus.FAILED)
        review = sum(1 for item in findings if item.status == VisualStatus.NEEDS_REVIEW)
        blocked = sum(1 for item in findings if item.status == VisualStatus.BLOCKED)
        errors = sum(1 for item in findings if item.status == VisualStatus.ERROR)

        return (
            f"{task_type.value} visual analysis {status.value}. "
            f"Checks: {passed}/{total} passed, {failed} failed, "
            f"{review} need review, {blocked} blocked, {errors} errors. "
            f"Elements: {len(elements)}. Artifacts: {len(artifacts)}. "
            f"Confidence: {confidence:.2f}. Privacy risk: {privacy_risk_score:.2f}."
        )

    def _extract_latest_text_artifact(self, artifacts: Sequence[VisualArtifact]) -> str:
        """Return latest OCR text artifact text."""
        for artifact in reversed(list(artifacts)):
            if artifact.artifact_type == "ocr_text" and isinstance(artifact.data, Mapping):
                return str(artifact.data.get("text") or "")
        return ""

    def _status_from_string(self, value: str) -> VisualStatus:
        """Parse VisualStatus safely."""
        normalized = _lower(value)
        for item in VisualStatus:
            if item.value == normalized:
                return item
        return VisualStatus.NEEDS_REVIEW

    def _severity_from_string(self, value: str) -> VisualSeverity:
        """Parse VisualSeverity safely."""
        normalized = _lower(value)
        for item in VisualSeverity:
            if item.value == normalized:
                return item
        return VisualSeverity.INFO

    def _task_type_from_string(self, value: str) -> VisualTaskType:
        """Parse VisualTaskType safely."""
        normalized = _lower(value)
        for item in VisualTaskType:
            if item.value == normalized:
                return item
        return VisualTaskType.IMAGE

    def _memory_importance_from_status(self, status: str) -> str:
        """Map status to memory importance."""
        normalized = _lower(status)
        if normalized in {"failed", "blocked", "error"}:
            return "high"
        if normalized in {"partial", "needs_review"}:
            return "medium"
        return "low"

    def _ensure_list(self, value: Any) -> List[Any]:
        """Normalize scalar/list to list."""
        if value is None:
            return []
        if isinstance(value, list):
            return value
        if isinstance(value, tuple):
            return list(value)
        return [value]


# ======================================================================================
# Registry / Loader compatibility
# ======================================================================================

def create_agent(*args: Any, **kwargs: Any) -> VisualAgent:
    """Factory used by William/Jarvis Agent Loader."""
    return VisualAgent(*args, **kwargs)


def get_agent_class() -> type:
    """Return VisualAgent class for registry discovery."""
    return VisualAgent


__all__ = [
    "VisualAgent",
    "VisualStatus",
    "VisualTaskType",
    "VisualSeverity",
    "VisualContext",
    "BoundingBox",
    "VisualElement",
    "VisualFinding",
    "VisualArtifact",
    "VisualReport",
    "create_agent",
    "get_agent_class",
]


# ======================================================================================
# Completion tracking
# ======================================================================================
#
# Agent/Module: Visual Agent
# File Completed: visual_agent.py
# Completion: 5.6%
# Completed Files: ['visual_agent.py']
# Remaining Files: ['screenshot_reader.py', 'video_analyzer.py', 'ocr_engine.py', 'ui_mapper.py', 'image_analyzer.py', 'screen_context.py', 'element_detector.py', 'workflow_learner.py', 'visual_memory.py', 'error_screen_detector.py', 'form_reader.py', 'app_screen_mapper.py', 'video_frame_extractor.py', 'visual_validator.py', 'privacy_filter.py', 'annotation_tool.py', 'config.py']
# Next Recommended File: agents/visual_agent/screenshot_reader.py
# FILE COMPLETE