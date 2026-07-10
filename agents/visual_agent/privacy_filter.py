"""
agents/visual_agent/privacy_filter.py

PrivacyFilter for William / Jarvis Visual Agent.

Purpose:
    Redacts sensitive visual data and blocks hidden/private captures.

This module is production-oriented, import-safe, and designed for SaaS
multi-user/workspace isolation. It does not perform real browser, device,
message, financial, call, or destructive actions. It only evaluates capture
requests, blocks unsafe/private captures, redacts sensitive text/regions, and
returns structured results.

Architecture Integration:
    - Master Agent / Router:
        Can route visual privacy validation requests here before screenshots,
        OCR, video frames, UI maps, or visual proof are stored.

    - Security Agent:
        Hidden/private/secure captures require security approval. This file
        prepares approval payloads but does not bypass permissions.

    - Memory Agent:
        Can receive safe, non-sensitive privacy patterns and summaries through
        _prepare_memory_payload().

    - Verification Agent:
        Every completed privacy filtering action can prepare a verification
        payload proving that redaction/blocking rules were applied.

    - Dashboard/API:
        All public methods return structured dicts:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": Optional[dict],
            "metadata": dict
        }

Optional Dependency:
    Pillow is optional. If available, image bytes can be redacted directly.
    Without Pillow, the module still imports and can redact text/OCR metadata.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import logging
import mimetypes
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------

try:
    from PIL import Image, ImageDraw, ImageFilter  # type: ignore

    PIL_AVAILABLE = True
except Exception:  # pragma: no cover - import-safe fallback
    Image = None  # type: ignore
    ImageDraw = None  # type: ignore
    ImageFilter = None  # type: ignore
    PIL_AVAILABLE = False


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - safe fallback

    class BaseAgent:  # type: ignore
        """Minimal fallback BaseAgent for import safety."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None

        def log_audit(self, *args: Any, **kwargs: Any) -> None:
            return None


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODULE_NAME = "visual_agent"
FILE_NAME = "privacy_filter.py"
CLASS_NAME = "PrivacyFilter"
CONFIG_VERSION = "1.0.0"

DEFAULT_MAX_IMAGE_BYTES = 15 * 1024 * 1024
DEFAULT_MAX_OCR_ITEMS = 500
DEFAULT_REDACTION_FILL = "#111111"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class PrivacyDecision(str, Enum):
    """Capture privacy decision."""

    ALLOW = "allow"
    REDACT = "redact"
    BLOCK = "block"
    REQUIRE_SECURITY_APPROVAL = "require_security_approval"


class RedactionMode(str, Enum):
    """Image redaction strategy."""

    BOX = "box"
    BLUR = "blur"
    PIXELATE = "pixelate"
    TEXT_ONLY = "text_only"


class PrivacyRiskLevel(str, Enum):
    """Privacy risk level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SensitiveDataType(str, Enum):
    """Sensitive data categories detected in visual/text content."""

    PASSWORD = "password"
    SECRET = "secret"
    API_KEY = "api_key"
    TOKEN = "token"
    EMAIL = "email"
    PHONE = "phone"
    CREDIT_CARD = "credit_card"
    BANK_ACCOUNT = "bank_account"
    SSN = "ssn"
    ADDRESS = "address"
    PERSONAL_ID = "personal_id"
    PRIVATE_BROWSER = "private_browser"
    SECURE_WINDOW = "secure_window"
    HIDDEN_WINDOW = "hidden_window"
    PAYMENT_SCREEN = "payment_screen"
    BANKING_SCREEN = "banking_screen"
    AUTH_SCREEN = "auth_screen"
    HEALTH_DATA = "health_data"
    PRIVATE_MESSAGE = "private_message"
    UNKNOWN_SENSITIVE = "unknown_sensitive"


class CaptureSourceType(str, Enum):
    """Visual capture source type."""

    SCREENSHOT = "screenshot"
    VIDEO_FRAME = "video_frame"
    IMAGE_UPLOAD = "image_upload"
    OCR_TEXT = "ocr_text"
    UI_MAP = "ui_map"
    CAMERA = "camera"
    BROWSER = "browser"
    DEVICE = "device"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BoundingBox:
    """
    Rectangle coordinates used for visual redaction.

    Coordinates are pixel values:
        left, top, right, bottom
    """

    left: int
    top: int
    right: int
    bottom: int

    def validate(self) -> None:
        if self.left < 0 or self.top < 0:
            raise ValueError("BoundingBox left/top cannot be negative.")
        if self.right <= self.left:
            raise ValueError("BoundingBox right must be greater than left.")
        if self.bottom <= self.top:
            raise ValueError("BoundingBox bottom must be greater than top.")

    def clamp(self, width: int, height: int, padding: int = 0) -> "BoundingBox":
        """Clamp bounding box to image dimensions with optional padding."""
        left = max(0, self.left - padding)
        top = max(0, self.top - padding)
        right = min(width, self.right + padding)
        bottom = min(height, self.bottom + padding)

        if right <= left:
            right = min(width, left + 1)
        if bottom <= top:
            bottom = min(height, top + 1)

        return BoundingBox(left=left, top=top, right=right, bottom=bottom)

    def to_tuple(self) -> Tuple[int, int, int, int]:
        return (self.left, self.top, self.right, self.bottom)

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)


@dataclass(frozen=True)
class SensitiveFinding:
    """
    A sensitive item detected in OCR/text/visual context.
    """

    finding_id: str
    data_type: SensitiveDataType
    risk_level: PrivacyRiskLevel
    confidence: float
    reason: str
    text_preview: Optional[str] = None
    bounding_box: Optional[BoundingBox] = None
    source: str = "unknown"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if self.confidence < 0.0 or self.confidence > 1.0:
            raise ValueError("SensitiveFinding confidence must be between 0.0 and 1.0.")
        if self.bounding_box:
            self.bounding_box.validate()


@dataclass(frozen=True)
class PrivacyPolicy:
    """
    Privacy policy for visual capture safety.

    Safe defaults block hidden/private/secure windows and redact sensitive data.
    """

    enabled: bool = True
    block_hidden_captures: bool = True
    block_private_browser_captures: bool = True
    block_secure_window_captures: bool = True
    block_background_app_captures: bool = True
    block_camera_without_security: bool = True
    block_payment_screens: bool = False
    block_banking_screens: bool = True
    redact_sensitive_text: bool = True
    redact_sensitive_regions: bool = True
    redact_credentials: bool = True
    redact_payment_data: bool = True
    redact_personal_identifiers: bool = True
    redact_private_messages: bool = True
    allow_image_upload_redaction: bool = True
    allow_ocr_text_redaction: bool = True
    require_user_id: bool = True
    require_workspace_id: bool = True
    require_security_for_high_risk: bool = True
    require_security_for_camera: bool = True
    require_security_for_private_context: bool = True
    max_image_bytes: int = DEFAULT_MAX_IMAGE_BYTES
    max_ocr_items: int = DEFAULT_MAX_OCR_ITEMS
    redaction_mode: RedactionMode = RedactionMode.BOX
    redaction_fill: str = DEFAULT_REDACTION_FILL
    blur_radius: int = 18
    pixelate_factor: int = 12
    redaction_padding: int = 6
    min_redaction_confidence: float = 0.65
    audit_enabled: bool = True
    emit_events: bool = True

    def validate(self) -> None:
        if self.max_image_bytes < 1024:
            raise ValueError("max_image_bytes must be at least 1024.")
        if self.max_ocr_items < 0:
            raise ValueError("max_ocr_items cannot be negative.")
        if self.blur_radius < 1:
            raise ValueError("blur_radius must be at least 1.")
        if self.pixelate_factor < 2:
            raise ValueError("pixelate_factor must be at least 2.")
        if self.redaction_padding < 0:
            raise ValueError("redaction_padding cannot be negative.")
        if self.min_redaction_confidence < 0.0 or self.min_redaction_confidence > 1.0:
            raise ValueError("min_redaction_confidence must be between 0.0 and 1.0.")


@dataclass(frozen=True)
class CaptureContext:
    """
    Context describing a visual capture request.

    This supports screenshots, uploaded images, OCR text, video frames, UI maps,
    browser captures, camera captures, and device captures.
    """

    source_type: CaptureSourceType = CaptureSourceType.UNKNOWN
    app_name: Optional[str] = None
    window_title: Optional[str] = None
    url: Optional[str] = None
    is_visible: Optional[bool] = None
    is_foreground: Optional[bool] = None
    is_private_mode: Optional[bool] = None
    is_secure_window: Optional[bool] = None
    is_hidden: Optional[bool] = None
    capture_reason: Optional[str] = None
    user_visible_notice_shown: Optional[bool] = None
    security_approved: Optional[bool] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _now_epoch() -> float:
    return time.time()


def _safe_uuid() -> str:
    return str(uuid.uuid4())


def _stringify_identifier(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _is_safe_identifier(value: str) -> bool:
    if not value:
        return False
    blocked = ["..", "/", "\\", "\x00", "\n", "\r", "\t"]
    return not any(token in value for token in blocked)


def _enum_value(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    return value


def _json_safe(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "__dataclass_fields__"):
        return _json_safe(asdict(value))
    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if isinstance(value, bytes):
        return {
            "bytes_sha256": hashlib.sha256(value).hexdigest(),
            "bytes_length": len(value),
        }
    return value


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _redact_preview(text: str, keep: int = 2) -> str:
    cleaned = _normalize_text(text).strip()
    if not cleaned:
        return ""
    if len(cleaned) <= keep * 2:
        return "*" * len(cleaned)
    return f"{cleaned[:keep]}{'*' * max(4, len(cleaned) - keep * 2)}{cleaned[-keep:]}"


def _safe_lower(value: Any) -> str:
    return _normalize_text(value).strip().lower()


def _decode_base64_image(data: str) -> bytes:
    """
    Decode plain base64 or data URL image string.
    """
    cleaned = data.strip()
    if "," in cleaned and cleaned.lower().startswith("data:"):
        cleaned = cleaned.split(",", 1)[1]
    return base64.b64decode(cleaned, validate=False)


def _guess_mime_from_bytes(image_bytes: bytes) -> str:
    if image_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if image_bytes.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if image_bytes.startswith(b"RIFF") and b"WEBP" in image_bytes[:16]:
        return "image/webp"
    return "application/octet-stream"


def _safe_filename_mime(path: Union[str, Path]) -> str:
    guessed, _encoding = mimetypes.guess_type(str(path))
    return guessed or "application/octet-stream"


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class PrivacyFilter(BaseAgent):
    """
    Visual privacy filter for William/Jarvis Visual Agent.

    Main responsibilities:
        - Validate SaaS task context.
        - Block hidden/private captures.
        - Detect sensitive data in OCR/text/window context.
        - Redact OCR text and visual regions.
        - Return proof/verification/memory-compatible payloads.
        - Emit audit and agent events without requiring full system modules.
    """

    agent_name = "PrivacyFilter"
    module_name = MODULE_NAME
    file_name = FILE_NAME
    config_version = CONFIG_VERSION

    def __init__(
        self,
        policy: Optional[PrivacyPolicy] = None,
        event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        super().__init__(agent_name=self.agent_name)
        self.policy = policy or PrivacyPolicy()
        self.policy.validate()

        self.event_sink = event_sink
        self.audit_sink = audit_sink
        self.security_approval_callback = security_approval_callback
        self.metadata = metadata.copy() if metadata else {}

        self._compiled_patterns = self._compile_sensitive_patterns()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def assess_capture_request(
        self,
        context: Optional[Mapping[str, Any]],
        capture_context: Optional[Union[CaptureContext, Mapping[str, Any]]] = None,
        ocr_items: Optional[Sequence[Mapping[str, Any]]] = None,
        text: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Assess whether a visual capture is allowed, needs redaction, must be
        blocked, or requires Security Agent approval.

        This should be called before screenshot_reader, video_frame_extractor,
        ui_mapper, image_analyzer, or proof_collector stores visual data.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        ctx = validation["data"]["context"]
        cap = self._normalize_capture_context(capture_context)
        findings: List[SensitiveFinding] = []

        blocking_reasons = self._get_blocking_reasons(cap)
        approval_reasons = self._get_security_approval_reasons(cap)

        context_text = " ".join(
            filter(
                None,
                [
                    cap.app_name or "",
                    cap.window_title or "",
                    cap.url or "",
                    cap.capture_reason or "",
                    text or "",
                ],
            )
        )
        findings.extend(self._detect_sensitive_text_internal(context_text, source="capture_context"))

        if ocr_items:
            findings.extend(self._detect_sensitive_ocr_items_internal(ocr_items))

        high_risk = any(
            finding.risk_level in {PrivacyRiskLevel.HIGH, PrivacyRiskLevel.CRITICAL}
            for finding in findings
        )

        if high_risk and self.policy.require_security_for_high_risk:
            approval_reasons.append("high_risk_sensitive_visual_data")

        decision = PrivacyDecision.ALLOW

        if blocking_reasons:
            decision = PrivacyDecision.BLOCK
        elif approval_reasons and self.policy.require_security_for_private_context:
            if cap.security_approved is True:
                decision = PrivacyDecision.REDACT if findings else PrivacyDecision.ALLOW
            else:
                decision = PrivacyDecision.REQUIRE_SECURITY_APPROVAL
        elif findings:
            decision = PrivacyDecision.REDACT

        risk_level = self._highest_risk(findings)
        if blocking_reasons:
            risk_level = PrivacyRiskLevel.CRITICAL
        elif approval_reasons and risk_level == PrivacyRiskLevel.LOW:
            risk_level = PrivacyRiskLevel.HIGH

        data = {
            "decision": decision.value,
            "risk_level": risk_level.value,
            "blocking_reasons": sorted(set(blocking_reasons)),
            "security_approval_reasons": sorted(set(approval_reasons)),
            "requires_redaction": decision in {PrivacyDecision.REDACT, PrivacyDecision.REQUIRE_SECURITY_APPROVAL},
            "finding_count": len(findings),
            "findings": [self._finding_to_dict(finding) for finding in findings],
            "capture_context": _json_safe(cap),
            "pillow_available": PIL_AVAILABLE,
        }

        self._log_audit_event(
            event_type="visual.privacy.capture_assessed",
            context=ctx,
            data=data,
            risk_level=risk_level,
        )
        self._emit_agent_event(
            event_type="visual.privacy.capture_assessed",
            context=ctx,
            data={
                "decision": decision.value,
                "risk_level": risk_level.value,
                "finding_count": len(findings),
            },
            risk_level=risk_level,
        )

        return self._safe_result(
            message=f"Capture privacy decision: {decision.value}.",
            data=data,
            metadata=self._metadata(ctx),
        )

    def filter_capture(
        self,
        context: Optional[Mapping[str, Any]],
        capture_context: Optional[Union[CaptureContext, Mapping[str, Any]]] = None,
        image_bytes: Optional[bytes] = None,
        image_base64: Optional[str] = None,
        text: Optional[str] = None,
        ocr_items: Optional[Sequence[Mapping[str, Any]]] = None,
        explicit_regions: Optional[Sequence[Union[BoundingBox, Mapping[str, Any], Sequence[int]]]] = None,
        output_format: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Full privacy filtering pipeline.

        Steps:
            1. Validate context.
            2. Assess capture.
            3. Block hidden/private captures where policy requires.
            4. Redact text/OCR.
            5. Redact image regions if image bytes and Pillow are available.
            6. Prepare verification payload.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        ctx = validation["data"]["context"]

        raw_image_bytes = image_bytes
        if raw_image_bytes is None and image_base64:
            try:
                raw_image_bytes = _decode_base64_image(image_base64)
            except Exception as exc:
                return self._error_result(
                    message="Invalid base64 image data.",
                    code="INVALID_IMAGE_BASE64",
                    details={"exception": str(exc)},
                    metadata=self._metadata(ctx),
                )

        assessment = self.assess_capture_request(
            context=ctx,
            capture_context=capture_context,
            ocr_items=ocr_items,
            text=text,
        )
        if not assessment["success"]:
            return assessment

        decision = assessment["data"]["decision"]

        if decision == PrivacyDecision.BLOCK.value:
            verification_payload = self._prepare_verification_payload(
                context=ctx,
                action="privacy_filter_block",
                status="blocked",
                details=assessment["data"],
            )

            return self._safe_result(
                message="Capture blocked by privacy policy.",
                data={
                    "decision": decision,
                    "blocked": True,
                    "redacted": False,
                    "assessment": assessment["data"],
                    "verification_payload": verification_payload.get("data", {}).get("verification_payload"),
                },
                metadata=self._metadata(ctx),
            )

        if decision == PrivacyDecision.REQUIRE_SECURITY_APPROVAL.value:
            approval = self._request_security_approval(
                action="visual_capture_private_or_sensitive_context",
                context=ctx,
                risk_level=assessment["data"].get("risk_level", PrivacyRiskLevel.HIGH.value),
                reason="Visual capture requires security approval before proceeding.",
                metadata=assessment["data"],
            )

            return self._safe_result(
                message="Capture requires security approval before filtering can continue.",
                data={
                    "decision": decision,
                    "blocked": True,
                    "redacted": False,
                    "assessment": assessment["data"],
                    "security_approval": approval.get("data", {}),
                },
                metadata=self._metadata(ctx),
            )

        text_result = None
        ocr_result = None
        image_result = None

        if text is not None:
            text_result = self.redact_text(context=ctx, text=text)

        if ocr_items is not None:
            ocr_result = self.redact_ocr_items(context=ctx, ocr_items=ocr_items)

        regions: List[BoundingBox] = []

        if ocr_result and ocr_result.get("success"):
            for item in ocr_result["data"].get("redacted_items", []):
                bbox_data = item.get("bounding_box")
                if bbox_data and item.get("redacted"):
                    try:
                        regions.append(self._bbox_from_any(bbox_data))
                    except Exception:
                        continue

        for region in explicit_regions or []:
            try:
                regions.append(self._bbox_from_any(region))
            except Exception:
                continue

        if raw_image_bytes is not None:
            image_result = self.redact_image_bytes(
                context=ctx,
                image_bytes=raw_image_bytes,
                regions=regions,
                output_format=output_format,
            )

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action="privacy_filter_capture",
            status="completed",
            details={
                "decision": decision,
                "text_redacted": bool(text_result and text_result.get("data", {}).get("redacted")),
                "ocr_items_redacted": bool(ocr_result and ocr_result.get("data", {}).get("redacted_count", 0)),
                "image_redacted": bool(image_result and image_result.get("data", {}).get("redacted")),
                "region_count": len(regions),
            },
        )

        return self._safe_result(
            message="Capture privacy filtering completed.",
            data={
                "decision": decision,
                "blocked": False,
                "redacted": decision == PrivacyDecision.REDACT.value or bool(regions),
                "assessment": assessment["data"],
                "text_result": text_result,
                "ocr_result": ocr_result,
                "image_result": image_result,
                "verification_payload": verification_payload.get("data", {}).get("verification_payload"),
            },
            metadata=self._metadata(ctx),
        )

    def detect_sensitive_text(
        self,
        context: Optional[Mapping[str, Any]],
        text: str,
        source: str = "text",
    ) -> Dict[str, Any]:
        """Detect sensitive data in plain text."""
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        findings = self._detect_sensitive_text_internal(text, source=source)

        return self._safe_result(
            message="Sensitive text detection completed.",
            data={
                "finding_count": len(findings),
                "risk_level": self._highest_risk(findings).value,
                "findings": [self._finding_to_dict(finding) for finding in findings],
            },
            metadata=self._metadata(validation["data"]["context"]),
        )

    def redact_text(
        self,
        context: Optional[Mapping[str, Any]],
        text: str,
        replacement: str = "[REDACTED]",
    ) -> Dict[str, Any]:
        """
        Redact sensitive data in plain text.

        This is useful for OCR output, UI labels, screenshots metadata, report
        generator summaries, and dashboard logs.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        if not self.policy.redact_sensitive_text:
            return self._safe_result(
                message="Text redaction disabled by policy.",
                data={
                    "redacted": False,
                    "text": text,
                    "finding_count": 0,
                    "findings": [],
                },
                metadata=self._metadata(validation["data"]["context"]),
            )

        original = _normalize_text(text)
        redacted = original
        findings = self._detect_sensitive_text_internal(original, source="text_redaction")

        for name, pattern_info in self._compiled_patterns.items():
            if not pattern_info["redact"]:
                continue
            pattern = pattern_info["pattern"]
            redacted = pattern.sub(replacement, redacted)

        return self._safe_result(
            message="Text redaction completed.",
            data={
                "redacted": redacted != original,
                "text": redacted,
                "original_length": len(original),
                "redacted_length": len(redacted),
                "finding_count": len(findings),
                "findings": [self._finding_to_dict(finding) for finding in findings],
            },
            metadata=self._metadata(validation["data"]["context"]),
        )

    def redact_ocr_items(
        self,
        context: Optional[Mapping[str, Any]],
        ocr_items: Sequence[Mapping[str, Any]],
        replacement: str = "[REDACTED]",
    ) -> Dict[str, Any]:
        """
        Redact sensitive OCR items.

        Expected OCR item shapes are flexible:
            {
                "text": "...",
                "confidence": 0.93,
                "bbox": [left, top, right, bottom]
            }

        Supported bbox keys:
            bbox, bounding_box, bounds, box
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        if len(ocr_items) > self.policy.max_ocr_items:
            return self._error_result(
                message="OCR item count exceeds privacy policy limit.",
                code="OCR_ITEM_LIMIT_EXCEEDED",
                details={
                    "item_count": len(ocr_items),
                    "max_ocr_items": self.policy.max_ocr_items,
                },
                metadata=self._metadata(validation["data"]["context"]),
            )

        redacted_items: List[Dict[str, Any]] = []
        all_findings: List[SensitiveFinding] = []
        redacted_count = 0

        for index, item in enumerate(ocr_items):
            text = _normalize_text(item.get("text", ""))
            findings = self._detect_sensitive_text_internal(text, source=f"ocr_item:{index}")
            all_findings.extend(findings)

            item_copy = dict(item)
            if findings and self.policy.redact_sensitive_text:
                redacted_text_result = self.redact_text(
                    context=validation["data"]["context"],
                    text=text,
                    replacement=replacement,
                )
                if redacted_text_result["success"]:
                    item_copy["text"] = redacted_text_result["data"]["text"]
                else:
                    item_copy["text"] = replacement
                item_copy["redacted"] = True
                item_copy["sensitive_types"] = sorted(
                    {finding.data_type.value for finding in findings}
                )
                redacted_count += 1
            else:
                item_copy["redacted"] = False
                item_copy["sensitive_types"] = []

            bbox = self._extract_bbox_from_ocr_item(item)
            if bbox:
                item_copy["bounding_box"] = bbox.to_dict()

            redacted_items.append(_json_safe(item_copy))

        return self._safe_result(
            message="OCR privacy redaction completed.",
            data={
                "redacted_count": redacted_count,
                "total_items": len(ocr_items),
                "redacted_items": redacted_items,
                "finding_count": len(all_findings),
                "risk_level": self._highest_risk(all_findings).value,
                "findings": [self._finding_to_dict(finding) for finding in all_findings],
            },
            metadata=self._metadata(validation["data"]["context"]),
        )

    def redact_image_bytes(
        self,
        context: Optional[Mapping[str, Any]],
        image_bytes: bytes,
        regions: Sequence[Union[BoundingBox, Mapping[str, Any], Sequence[int]]],
        output_format: Optional[str] = None,
        redaction_mode: Optional[Union[str, RedactionMode]] = None,
    ) -> Dict[str, Any]:
        """
        Redact regions in image bytes.

        If Pillow is unavailable, returns a structured error with no raw image
        leakage. The caller can still use OCR text redaction.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        ctx = validation["data"]["context"]

        if not isinstance(image_bytes, (bytes, bytearray)):
            return self._error_result(
                message="image_bytes must be bytes.",
                code="INVALID_IMAGE_BYTES",
                details={"received_type": type(image_bytes).__name__},
                metadata=self._metadata(ctx),
            )

        if len(image_bytes) > self.policy.max_image_bytes:
            return self._error_result(
                message="Image exceeds privacy policy max size.",
                code="IMAGE_TOO_LARGE",
                details={
                    "image_bytes": len(image_bytes),
                    "max_image_bytes": self.policy.max_image_bytes,
                },
                metadata=self._metadata(ctx),
            )

        if not PIL_AVAILABLE:
            return self._error_result(
                message="Pillow is not installed, so image region redaction is unavailable.",
                code="PILLOW_NOT_AVAILABLE",
                details={
                    "install": "pip install pillow",
                    "can_still_redact_text": True,
                },
                metadata=self._metadata(ctx),
            )

        normalized_regions: List[BoundingBox] = []
        for region in regions:
            try:
                normalized_regions.append(self._bbox_from_any(region))
            except Exception as exc:
                logger.warning("Skipping invalid redaction region: %s", exc)

        if not normalized_regions:
            return self._safe_result(
                message="No image regions provided for redaction.",
                data={
                    "redacted": False,
                    "region_count": 0,
                    "image_sha256": hashlib.sha256(bytes(image_bytes)).hexdigest(),
                    "image_bytes": len(image_bytes),
                    "mime_type": _guess_mime_from_bytes(bytes(image_bytes)),
                },
                metadata=self._metadata(ctx),
            )

        mode = self._normalize_redaction_mode(redaction_mode or self.policy.redaction_mode)

        try:
            with Image.open(io.BytesIO(bytes(image_bytes))) as img:  # type: ignore[union-attr]
                original_format = img.format or "PNG"
                image = img.convert("RGBA")
                width, height = image.size

                for bbox in normalized_regions:
                    clamped = bbox.clamp(
                        width=width,
                        height=height,
                        padding=self.policy.redaction_padding,
                    )
                    self._apply_region_redaction(image, clamped, mode)

                final_format = (output_format or original_format or "PNG").upper()
                if final_format == "JPG":
                    final_format = "JPEG"

                output = io.BytesIO()

                if final_format == "JPEG":
                    image = image.convert("RGB")

                image.save(output, format=final_format)
                redacted_bytes = output.getvalue()

            return self._safe_result(
                message="Image region redaction completed.",
                data={
                    "redacted": True,
                    "redaction_mode": mode.value,
                    "region_count": len(normalized_regions),
                    "output_format": final_format.lower(),
                    "input_bytes": len(image_bytes),
                    "output_bytes": len(redacted_bytes),
                    "input_sha256": hashlib.sha256(bytes(image_bytes)).hexdigest(),
                    "output_sha256": hashlib.sha256(redacted_bytes).hexdigest(),
                    "image_base64": base64.b64encode(redacted_bytes).decode("ascii"),
                    "regions": [region.to_dict() for region in normalized_regions],
                },
                metadata=self._metadata(ctx),
            )

        except Exception as exc:
            logger.exception("Image redaction failed.")
            return self._error_result(
                message="Image redaction failed.",
                code="IMAGE_REDACTION_FAILED",
                details={"exception": str(exc)},
                metadata=self._metadata(ctx),
            )

    def redact_image_file(
        self,
        context: Optional[Mapping[str, Any]],
        input_path: Union[str, Path],
        output_path: Union[str, Path],
        regions: Sequence[Union[BoundingBox, Mapping[str, Any], Sequence[int]]],
        redaction_mode: Optional[Union[str, RedactionMode]] = None,
    ) -> Dict[str, Any]:
        """
        Redact an image file and write the redacted copy.

        This method never deletes or modifies the input file. It writes only to
        output_path.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        ctx = validation["data"]["context"]
        input_file = Path(input_path)
        output_file = Path(output_path)

        if not input_file.exists() or not input_file.is_file():
            return self._error_result(
                message="Input image file does not exist.",
                code="INPUT_IMAGE_NOT_FOUND",
                details={"input_path": str(input_file)},
                metadata=self._metadata(ctx),
            )

        try:
            image_bytes = input_file.read_bytes()
        except Exception as exc:
            return self._error_result(
                message="Failed to read input image file.",
                code="INPUT_IMAGE_READ_FAILED",
                details={"exception": str(exc), "input_path": str(input_file)},
                metadata=self._metadata(ctx),
            )

        output_format = output_file.suffix.replace(".", "").upper() or None
        redaction_result = self.redact_image_bytes(
            context=ctx,
            image_bytes=image_bytes,
            regions=regions,
            output_format=output_format,
            redaction_mode=redaction_mode,
        )

        if not redaction_result["success"]:
            return redaction_result

        try:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            redacted_base64 = redaction_result["data"].get("image_base64", "")
            output_file.write_bytes(base64.b64decode(redacted_base64))
        except Exception as exc:
            return self._error_result(
                message="Failed to write redacted image file.",
                code="OUTPUT_IMAGE_WRITE_FAILED",
                details={"exception": str(exc), "output_path": str(output_file)},
                metadata=self._metadata(ctx),
            )

        data = dict(redaction_result["data"])
        data.pop("image_base64", None)
        data["input_path"] = str(input_file)
        data["output_path"] = str(output_file)
        data["input_mime_type"] = _safe_filename_mime(input_file)

        return self._safe_result(
            message="Redacted image file written.",
            data=data,
            metadata=self._metadata(ctx),
        )

    def build_privacy_report(
        self,
        context: Optional[Mapping[str, Any]],
        findings: Optional[Sequence[Union[SensitiveFinding, Mapping[str, Any]]]] = None,
        decision: Union[str, PrivacyDecision] = PrivacyDecision.ALLOW,
        include_memory_payload: bool = True,
        include_verification_payload: bool = True,
    ) -> Dict[str, Any]:
        """Build dashboard/API-safe privacy report."""
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        ctx = validation["data"]["context"]
        normalized_decision = self._normalize_decision(decision)

        normalized_findings: List[Dict[str, Any]] = []
        for finding in findings or []:
            if isinstance(finding, SensitiveFinding):
                normalized_findings.append(self._finding_to_dict(finding))
            elif isinstance(finding, Mapping):
                normalized_findings.append(_json_safe(dict(finding)))

        report = {
            "report_id": _safe_uuid(),
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "class": CLASS_NAME,
            "decision": normalized_decision.value,
            "finding_count": len(normalized_findings),
            "findings": normalized_findings,
            "policy": _json_safe(self.policy),
            "generated_at_epoch": _now_epoch(),
            "context": {
                "user_id": ctx.get("user_id"),
                "workspace_id": ctx.get("workspace_id"),
                "request_id": ctx.get("request_id"),
                "task_id": ctx.get("task_id"),
            },
        }

        memory_payload = None
        verification_payload = None

        if include_memory_payload:
            memory_payload = self._prepare_memory_payload(
                context=ctx,
                memory_type="visual_privacy_report",
                content={
                    "decision": normalized_decision.value,
                    "finding_count": len(normalized_findings),
                    "risk_summary": self._risk_summary_from_finding_dicts(normalized_findings),
                },
            ).get("data", {}).get("memory_payload")

        if include_verification_payload:
            verification_payload = self._prepare_verification_payload(
                context=ctx,
                action="visual_privacy_report",
                status="completed",
                details={
                    "decision": normalized_decision.value,
                    "finding_count": len(normalized_findings),
                },
            ).get("data", {}).get("verification_payload")

        return self._safe_result(
            message="Privacy report generated.",
            data={
                "report": report,
                "memory_payload": memory_payload,
                "verification_payload": verification_payload,
            },
            metadata=self._metadata(ctx),
        )

    def health_check(self) -> Dict[str, Any]:
        """Registry/loader/dashboard startup health check."""
        try:
            self.policy.validate()
            return self._safe_result(
                message="PrivacyFilter health check passed.",
                data={
                    "healthy": True,
                    "module": MODULE_NAME,
                    "file": FILE_NAME,
                    "class": CLASS_NAME,
                    "version": CONFIG_VERSION,
                    "pillow_available": PIL_AVAILABLE,
                    "policy_enabled": self.policy.enabled,
                    "compiled_pattern_count": len(self._compiled_patterns),
                },
            )
        except Exception as exc:
            return self._error_result(
                message="PrivacyFilter health check failed.",
                code="HEALTH_CHECK_FAILED",
                details={"exception": str(exc)},
            )

    def describe(self) -> Dict[str, Any]:
        """Return registry-friendly module description."""
        return self._safe_result(
            message="PrivacyFilter description generated.",
            data={
                "agent_module": MODULE_NAME,
                "file": FILE_NAME,
                "class": CLASS_NAME,
                "purpose": "Redacts sensitive visual data and blocks hidden/private captures.",
                "version": CONFIG_VERSION,
                "safe_to_import": True,
                "optional_dependencies": ["Pillow"],
                "public_methods": [
                    "assess_capture_request",
                    "filter_capture",
                    "detect_sensitive_text",
                    "redact_text",
                    "redact_ocr_items",
                    "redact_image_bytes",
                    "redact_image_file",
                    "build_privacy_report",
                    "health_check",
                    "describe",
                ],
                "compatibility_hooks": [
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
        )

    # ------------------------------------------------------------------
    # Compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """
        Validate user_id/workspace_id for SaaS isolation.

        This prevents mixing privacy reports, image data, OCR output, or audit
        logs between tenants.
        """
        if context is None:
            context = {}

        if not isinstance(context, Mapping):
            return self._error_result(
                message="Invalid task context.",
                code="INVALID_CONTEXT_TYPE",
                details={"expected": "mapping/dict", "received": type(context).__name__},
            )

        user_id = _stringify_identifier(context.get("user_id"))
        workspace_id = _stringify_identifier(context.get("workspace_id"))

        errors: List[Dict[str, Any]] = []

        if self.policy.require_user_id and not user_id:
            errors.append({"field": "user_id", "message": "user_id is required."})
        elif user_id and not _is_safe_identifier(user_id):
            errors.append({"field": "user_id", "message": "user_id contains unsafe characters."})

        if self.policy.require_workspace_id and not workspace_id:
            errors.append({"field": "workspace_id", "message": "workspace_id is required."})
        elif workspace_id and not _is_safe_identifier(workspace_id):
            errors.append(
                {"field": "workspace_id", "message": "workspace_id contains unsafe characters."}
            )

        if errors:
            self._log_audit_event(
                event_type="visual.privacy.context_validation_failed",
                context=dict(context),
                data={"errors": errors},
                risk_level=PrivacyRiskLevel.MEDIUM,
            )
            return self._error_result(
                message="Task context validation failed.",
                code="CONTEXT_VALIDATION_FAILED",
                details={"errors": errors},
            )

        normalized = dict(context)
        normalized["user_id"] = user_id
        normalized["workspace_id"] = workspace_id
        normalized.setdefault("request_id", _safe_uuid())
        normalized.setdefault("source_agent", MODULE_NAME)

        return self._safe_result(
            message="Task context is valid.",
            data={"context": normalized},
            metadata=self._metadata(normalized),
        )

    def _requires_security_check(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        risk_level: Optional[Union[str, PrivacyRiskLevel]] = None,
        capture_context: Optional[Union[CaptureContext, Mapping[str, Any]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Determine whether Security Agent approval is required."""
        cap = self._normalize_capture_context(capture_context)
        risk = self._normalize_risk_level(risk_level)
        action_lower = _safe_lower(action)

        reasons: List[str] = []

        if risk in {PrivacyRiskLevel.HIGH, PrivacyRiskLevel.CRITICAL} and self.policy.require_security_for_high_risk:
            reasons.append("high_or_critical_privacy_risk")

        if cap.source_type == CaptureSourceType.CAMERA and self.policy.require_security_for_camera:
            reasons.append("camera_capture_requires_security")

        if cap.is_private_mode is True and self.policy.require_security_for_private_context:
            reasons.append("private_mode_requires_security")

        if cap.is_secure_window is True and self.policy.require_security_for_private_context:
            reasons.append("secure_window_requires_security")

        if cap.is_hidden is True and self.policy.require_security_for_private_context:
            reasons.append("hidden_window_requires_security")

        sensitive_action_terms = {
            "hidden_capture",
            "private_capture",
            "secure_window_capture",
            "camera_capture",
            "background_capture",
            "payment_capture",
            "banking_capture",
        }
        if any(term in action_lower for term in sensitive_action_terms):
            reasons.append("sensitive_visual_capture_action")

        return self._safe_result(
            message="Security requirement evaluated.",
            data={
                "requires_security_check": bool(reasons),
                "reasons": sorted(set(reasons)),
                "risk_level": risk.value,
                "action": action,
                "capture_context": _json_safe(cap),
                "metadata": dict(metadata or {}),
            },
            metadata=self._metadata(context),
        )

    def _request_security_approval(
        self,
        action: str,
        context: Optional[Mapping[str, Any]],
        risk_level: Optional[Union[str, PrivacyRiskLevel]] = None,
        reason: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare or send a Security Agent approval request."""
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        ctx = validation["data"]["context"]
        risk = self._normalize_risk_level(risk_level)

        approval_payload = {
            "approval_id": _safe_uuid(),
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "class": CLASS_NAME,
            "action": action,
            "risk_level": risk.value,
            "reason": reason or "Visual privacy action requires Security Agent approval.",
            "context": {
                "user_id": ctx.get("user_id"),
                "workspace_id": ctx.get("workspace_id"),
                "request_id": ctx.get("request_id"),
                "task_id": ctx.get("task_id"),
            },
            "metadata": dict(metadata or {}),
            "created_at_epoch": _now_epoch(),
        }

        self._log_audit_event(
            event_type="visual.privacy.security_approval_requested",
            context=ctx,
            data=approval_payload,
            risk_level=risk,
        )

        if self.security_approval_callback:
            try:
                response = self.security_approval_callback(copy.deepcopy(approval_payload))
                if not isinstance(response, Mapping):
                    return self._error_result(
                        message="Security approval callback returned invalid response.",
                        code="INVALID_SECURITY_CALLBACK_RESPONSE",
                        details={"received_type": type(response).__name__},
                        metadata=self._metadata(ctx),
                    )
                return self._safe_result(
                    message="Security approval callback completed.",
                    data={
                        "approval_payload": approval_payload,
                        "security_response": dict(response),
                    },
                    metadata=self._metadata(ctx),
                )
            except Exception as exc:
                logger.exception("Security approval callback failed.")
                return self._error_result(
                    message="Security approval callback failed.",
                    code="SECURITY_CALLBACK_FAILED",
                    details={"exception": str(exc)},
                    metadata=self._metadata(ctx),
                )

        return self._safe_result(
            message="Security approval request prepared.",
            data={
                "approval_payload": approval_payload,
                "status": "pending_external_security_agent",
            },
            metadata=self._metadata(ctx),
        )

    def _prepare_verification_payload(
        self,
        context: Optional[Mapping[str, Any]],
        action: str,
        status: str,
        details: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent compatible payload."""
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        ctx = validation["data"]["context"]

        payload = {
            "verification_id": _safe_uuid(),
            "source_module": MODULE_NAME,
            "source_file": FILE_NAME,
            "source_class": CLASS_NAME,
            "verification_type": "visual_privacy_filter",
            "action": action,
            "status": status,
            "details": dict(details or {}),
            "context": {
                "user_id": ctx.get("user_id"),
                "workspace_id": ctx.get("workspace_id"),
                "request_id": ctx.get("request_id"),
                "task_id": ctx.get("task_id"),
            },
            "created_at_epoch": _now_epoch(),
        }

        return self._safe_result(
            message="Verification payload prepared.",
            data={"verification_payload": payload},
            metadata=self._metadata(ctx),
        )

    def _prepare_memory_payload(
        self,
        context: Optional[Mapping[str, Any]],
        memory_type: str,
        content: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This does not store images or raw sensitive text. Only privacy-safe
        summary data should be sent.
        """
        validation = self._validate_task_context(context)
        if not validation["success"]:
            return validation

        ctx = validation["data"]["context"]

        payload = {
            "memory_id": _safe_uuid(),
            "memory_type": memory_type,
            "source_module": MODULE_NAME,
            "source_file": FILE_NAME,
            "scope": "workspace",
            "user_id": ctx.get("user_id"),
            "workspace_id": ctx.get("workspace_id"),
            "content": _json_safe(content or {}),
            "metadata": {
                **dict(metadata or {}),
                "privacy_safe_summary_only": True,
                "config_version": CONFIG_VERSION,
            },
            "created_at_epoch": _now_epoch(),
        }

        return self._safe_result(
            message="Memory payload prepared.",
            data={"memory_payload": payload},
            metadata=self._metadata(ctx),
        )

    def _emit_agent_event(
        self,
        event_type: str,
        context: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        risk_level: Union[str, PrivacyRiskLevel] = PrivacyRiskLevel.LOW,
    ) -> Dict[str, Any]:
        """Emit dashboard/registry-compatible Visual Agent event."""
        if not self.policy.emit_events:
            return self._safe_result(
                message="Agent event emission disabled.",
                data={"emitted": False, "reason": "disabled"},
                metadata=self._metadata(context),
            )

        event = {
            "event_id": _safe_uuid(),
            "event_type": event_type,
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "class": CLASS_NAME,
            "risk_level": self._normalize_risk_level(risk_level).value,
            "context": self._safe_context(context),
            "data": _json_safe(data or {}),
            "created_at_epoch": _now_epoch(),
        }

        try:
            if self.event_sink:
                self.event_sink(copy.deepcopy(event))
            elif hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event)  # type: ignore[misc]
                except Exception:
                    pass

            return self._safe_result(
                message="Agent event emitted.",
                data={"emitted": True, "event": event},
                metadata=self._metadata(context),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to emit agent event.",
                code="EVENT_EMIT_FAILED",
                details={"exception": str(exc)},
                metadata=self._metadata(context),
            )

    def _log_audit_event(
        self,
        event_type: str,
        context: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        risk_level: Union[str, PrivacyRiskLevel] = PrivacyRiskLevel.LOW,
    ) -> Dict[str, Any]:
        """Log audit event safely."""
        if not self.policy.audit_enabled:
            return self._safe_result(
                message="Audit logging disabled.",
                data={"logged": False, "reason": "disabled"},
                metadata=self._metadata(context),
            )

        audit_event = {
            "audit_id": _safe_uuid(),
            "event_type": event_type,
            "module": MODULE_NAME,
            "file": FILE_NAME,
            "class": CLASS_NAME,
            "risk_level": self._normalize_risk_level(risk_level).value,
            "context": self._safe_context(context),
            "data": _json_safe(data or {}),
            "created_at_epoch": _now_epoch(),
        }

        try:
            if self.audit_sink:
                self.audit_sink(copy.deepcopy(audit_event))
            elif hasattr(super(), "log_audit"):
                try:
                    super().log_audit(audit_event)  # type: ignore[misc]
                except Exception:
                    pass

            return self._safe_result(
                message="Audit event logged.",
                data={"logged": True, "audit_event": audit_event},
                metadata=self._metadata(context),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to log audit event.",
                code="AUDIT_LOG_FAILED",
                details={"exception": str(exc)},
                metadata=self._metadata(context),
            )

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis success result."""
        return {
            "success": True,
            "message": message,
            "data": _json_safe(dict(data or {})),
            "error": None,
            "metadata": _json_safe(
                {
                    "module": MODULE_NAME,
                    "file": FILE_NAME,
                    "class": CLASS_NAME,
                    "version": CONFIG_VERSION,
                    "timestamp_epoch": _now_epoch(),
                    **dict(metadata or {}),
                }
            ),
        }

    def _error_result(
        self,
        message: str,
        code: str = "PRIVACY_FILTER_ERROR",
        details: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis error result."""
        return {
            "success": False,
            "message": message,
            "data": {},
            "error": _json_safe(
                {
                    "code": code,
                    "details": dict(details or {}),
                }
            ),
            "metadata": _json_safe(
                {
                    "module": MODULE_NAME,
                    "file": FILE_NAME,
                    "class": CLASS_NAME,
                    "version": CONFIG_VERSION,
                    "timestamp_epoch": _now_epoch(),
                    **dict(metadata or {}),
                }
            ),
        }

    # ------------------------------------------------------------------
    # Internal detection logic
    # ------------------------------------------------------------------

    def _compile_sensitive_patterns(self) -> Dict[str, Dict[str, Any]]:
        """
        Compile sensitive data regex patterns.

        The patterns are intentionally conservative enough for production use
        but still avoid exposing raw matches in results.
        """
        return {
            "email": {
                "pattern": re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.I),
                "type": SensitiveDataType.EMAIL,
                "risk": PrivacyRiskLevel.MEDIUM,
                "confidence": 0.88,
                "redact": True,
            },
            "phone": {
                "pattern": re.compile(
                    r"(?<!\d)(?:\+?\d{1,3}[\s.\-()]*)?(?:\(?\d{3}\)?[\s.\-()]*)\d{3}[\s.\-]*\d{4}(?!\d)"
                ),
                "type": SensitiveDataType.PHONE,
                "risk": PrivacyRiskLevel.MEDIUM,
                "confidence": 0.74,
                "redact": self.policy.redact_personal_identifiers,
            },
            "credit_card": {
                "pattern": re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)"),
                "type": SensitiveDataType.CREDIT_CARD,
                "risk": PrivacyRiskLevel.CRITICAL,
                "confidence": 0.78,
                "redact": self.policy.redact_payment_data,
            },
            "ssn": {
                "pattern": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
                "type": SensitiveDataType.SSN,
                "risk": PrivacyRiskLevel.CRITICAL,
                "confidence": 0.92,
                "redact": self.policy.redact_personal_identifiers,
            },
            "password_assignment": {
                "pattern": re.compile(
                    r"\b(password|passcode|pin|secret)\s*[:=]\s*[^\s,;]{4,}",
                    re.I,
                ),
                "type": SensitiveDataType.PASSWORD,
                "risk": PrivacyRiskLevel.CRITICAL,
                "confidence": 0.92,
                "redact": self.policy.redact_credentials,
            },
            "api_key": {
                "pattern": re.compile(
                    r"\b(api[_\- ]?key|secret[_\- ]?key|access[_\- ]?key)\s*[:=]\s*[A-Za-z0-9_\-]{12,}",
                    re.I,
                ),
                "type": SensitiveDataType.API_KEY,
                "risk": PrivacyRiskLevel.CRITICAL,
                "confidence": 0.90,
                "redact": self.policy.redact_credentials,
            },
            "bearer_token": {
                "pattern": re.compile(r"\bBearer\s+[A-Za-z0-9._\-~+/]+=*", re.I),
                "type": SensitiveDataType.TOKEN,
                "risk": PrivacyRiskLevel.CRITICAL,
                "confidence": 0.95,
                "redact": self.policy.redact_credentials,
            },
            "jwt": {
                "pattern": re.compile(
                    r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"
                ),
                "type": SensitiveDataType.TOKEN,
                "risk": PrivacyRiskLevel.CRITICAL,
                "confidence": 0.92,
                "redact": self.policy.redact_credentials,
            },
            "bank_account": {
                "pattern": re.compile(
                    r"\b(account\s*(number|no\.?)|routing\s*(number|no\.?))\s*[:#]?\s*\d{6,17}\b",
                    re.I,
                ),
                "type": SensitiveDataType.BANK_ACCOUNT,
                "risk": PrivacyRiskLevel.CRITICAL,
                "confidence": 0.84,
                "redact": self.policy.redact_payment_data,
            },
            "address_hint": {
                "pattern": re.compile(
                    r"\b\d{1,6}\s+[A-Za-z0-9.\- ]+\s+(street|st\.|avenue|ave\.|road|rd\.|boulevard|blvd\.|lane|ln\.|drive|dr\.)\b",
                    re.I,
                ),
                "type": SensitiveDataType.ADDRESS,
                "risk": PrivacyRiskLevel.HIGH,
                "confidence": 0.72,
                "redact": self.policy.redact_personal_identifiers,
            },
        }

    def _detect_sensitive_text_internal(self, text: str, source: str) -> List[SensitiveFinding]:
        if not self.policy.enabled:
            return []

        findings: List[SensitiveFinding] = []
        source_text = _normalize_text(text)

        if not source_text.strip():
            return findings

        for name, info in self._compiled_patterns.items():
            pattern = info["pattern"]
            for match in pattern.finditer(source_text):
                matched_text = match.group(0)
                confidence = float(info["confidence"])

                if info["type"] == SensitiveDataType.CREDIT_CARD:
                    if not self._passes_luhn_check(re.sub(r"\D", "", matched_text)):
                        confidence = 0.45

                if confidence < self.policy.min_redaction_confidence:
                    continue

                findings.append(
                    SensitiveFinding(
                        finding_id=_safe_uuid(),
                        data_type=info["type"],
                        risk_level=info["risk"],
                        confidence=confidence,
                        reason=f"Matched sensitive pattern: {name}.",
                        text_preview=_redact_preview(matched_text),
                        source=source,
                        metadata={
                            "pattern_name": name,
                            "start": match.start(),
                            "end": match.end(),
                        },
                    )
                )

        lower = source_text.lower()
        contextual_findings = self._detect_contextual_sensitive_terms(lower, source)
        findings.extend(contextual_findings)

        return findings

    def _detect_contextual_sensitive_terms(self, lower_text: str, source: str) -> List[SensitiveFinding]:
        findings: List[SensitiveFinding] = []

        context_rules = [
            (
                SensitiveDataType.PRIVATE_BROWSER,
                PrivacyRiskLevel.HIGH,
                ["incognito", "private browsing", "private window", "inprivate"],
                "Private browser context detected.",
            ),
            (
                SensitiveDataType.PAYMENT_SCREEN,
                PrivacyRiskLevel.HIGH,
                ["payment method", "card number", "cvv", "billing address", "checkout"],
                "Payment screen context detected.",
            ),
            (
                SensitiveDataType.BANKING_SCREEN,
                PrivacyRiskLevel.CRITICAL,
                ["bank account", "routing number", "available balance", "transaction history"],
                "Banking screen context detected.",
            ),
            (
                SensitiveDataType.AUTH_SCREEN,
                PrivacyRiskLevel.HIGH,
                ["two-factor", "2fa", "verification code", "one-time password", "otp"],
                "Authentication screen context detected.",
            ),
            (
                SensitiveDataType.HEALTH_DATA,
                PrivacyRiskLevel.CRITICAL,
                ["patient", "diagnosis", "medical record", "prescription", "health insurance"],
                "Health data context detected.",
            ),
            (
                SensitiveDataType.PRIVATE_MESSAGE,
                PrivacyRiskLevel.HIGH,
                ["direct message", "private message", "whatsapp", "messenger", "inbox"],
                "Private message context detected.",
            ),
        ]

        for data_type, risk, terms, reason in context_rules:
            if any(term in lower_text for term in terms):
                findings.append(
                    SensitiveFinding(
                        finding_id=_safe_uuid(),
                        data_type=data_type,
                        risk_level=risk,
                        confidence=0.76,
                        reason=reason,
                        text_preview=None,
                        source=source,
                        metadata={"matched_terms": [term for term in terms if term in lower_text]},
                    )
                )

        return findings

    def _detect_sensitive_ocr_items_internal(
        self,
        ocr_items: Sequence[Mapping[str, Any]],
    ) -> List[SensitiveFinding]:
        findings: List[SensitiveFinding] = []
        limited_items = list(ocr_items)[: self.policy.max_ocr_items]

        for index, item in enumerate(limited_items):
            text = _normalize_text(item.get("text", ""))
            item_findings = self._detect_sensitive_text_internal(text, source=f"ocr_item:{index}")
            bbox = self._extract_bbox_from_ocr_item(item)

            if bbox:
                item_findings = [
                    SensitiveFinding(
                        finding_id=finding.finding_id,
                        data_type=finding.data_type,
                        risk_level=finding.risk_level,
                        confidence=finding.confidence,
                        reason=finding.reason,
                        text_preview=finding.text_preview,
                        bounding_box=bbox,
                        source=finding.source,
                        metadata=finding.metadata,
                    )
                    for finding in item_findings
                ]

            findings.extend(item_findings)

        return findings

    def _get_blocking_reasons(self, cap: CaptureContext) -> List[str]:
        reasons: List[str] = []

        if not self.policy.enabled:
            return reasons

        app_title_url = " ".join(
            [
                _safe_lower(cap.app_name),
                _safe_lower(cap.window_title),
                _safe_lower(cap.url),
            ]
        )

        inferred_private = any(
            token in app_title_url
            for token in ["incognito", "private browsing", "inprivate", "private window"]
        )
        inferred_banking = any(
            token in app_title_url
            for token in ["bank", "banking", "paypal", "stripe dashboard", "wallet"]
        )
        inferred_payment = any(
            token in app_title_url
            for token in ["checkout", "payment", "billing", "card details"]
        )

        if self.policy.block_hidden_captures and (cap.is_hidden is True or cap.is_visible is False):
            reasons.append("hidden_capture_blocked")

        if self.policy.block_background_app_captures and cap.is_foreground is False:
            reasons.append("background_app_capture_blocked")

        if self.policy.block_private_browser_captures and (cap.is_private_mode is True or inferred_private):
            reasons.append("private_browser_capture_blocked")

        if self.policy.block_secure_window_captures and cap.is_secure_window is True:
            reasons.append("secure_window_capture_blocked")

        if self.policy.block_banking_screens and inferred_banking:
            reasons.append("banking_screen_capture_blocked")

        if self.policy.block_payment_screens and inferred_payment:
            reasons.append("payment_screen_capture_blocked")

        if (
            self.policy.block_camera_without_security
            and cap.source_type == CaptureSourceType.CAMERA
            and cap.security_approved is not True
        ):
            reasons.append("camera_capture_without_security_blocked")

        return reasons

    def _get_security_approval_reasons(self, cap: CaptureContext) -> List[str]:
        reasons: List[str] = []

        if not self.policy.enabled:
            return reasons

        if cap.source_type == CaptureSourceType.CAMERA and self.policy.require_security_for_camera:
            reasons.append("camera_capture_requires_security")

        if cap.is_private_mode is True and self.policy.require_security_for_private_context:
            reasons.append("private_context_requires_security")

        if cap.is_secure_window is True and self.policy.require_security_for_private_context:
            reasons.append("secure_window_requires_security")

        if cap.is_hidden is True and self.policy.require_security_for_private_context:
            reasons.append("hidden_window_requires_security")

        return reasons

    # ------------------------------------------------------------------
    # Image redaction internals
    # ------------------------------------------------------------------

    def _apply_region_redaction(
        self,
        image: Any,
        bbox: BoundingBox,
        mode: RedactionMode,
    ) -> None:
        if not PIL_AVAILABLE:
            return

        box = bbox.to_tuple()

        if mode == RedactionMode.BLUR:
            crop = image.crop(box)
            blurred = crop.filter(ImageFilter.GaussianBlur(radius=self.policy.blur_radius))  # type: ignore[union-attr]
            image.paste(blurred, box)
            return

        if mode == RedactionMode.PIXELATE:
            crop = image.crop(box)
            width, height = crop.size
            small_width = max(1, width // self.policy.pixelate_factor)
            small_height = max(1, height // self.policy.pixelate_factor)
            small = crop.resize((small_width, small_height))
            pixelated = small.resize((width, height))
            image.paste(pixelated, box)
            return

        draw = ImageDraw.Draw(image)  # type: ignore[union-attr]
        draw.rectangle(box, fill=self.policy.redaction_fill)

    # ------------------------------------------------------------------
    # Normalizers
    # ------------------------------------------------------------------

    def _normalize_capture_context(
        self,
        capture_context: Optional[Union[CaptureContext, Mapping[str, Any]]],
    ) -> CaptureContext:
        if capture_context is None:
            return CaptureContext()

        if isinstance(capture_context, CaptureContext):
            return capture_context

        if not isinstance(capture_context, Mapping):
            return CaptureContext(metadata={"raw_type": type(capture_context).__name__})

        data = dict(capture_context)

        source_type = data.get("source_type", data.get("capture_source", CaptureSourceType.UNKNOWN))
        source_type_enum = self._normalize_source_type(source_type)

        return CaptureContext(
            source_type=source_type_enum,
            app_name=data.get("app_name") or data.get("application") or data.get("app"),
            window_title=data.get("window_title") or data.get("title"),
            url=data.get("url") or data.get("page_url"),
            is_visible=self._optional_bool(data.get("is_visible", data.get("visible"))),
            is_foreground=self._optional_bool(data.get("is_foreground", data.get("foreground"))),
            is_private_mode=self._optional_bool(
                data.get("is_private_mode", data.get("private_mode", data.get("incognito")))
            ),
            is_secure_window=self._optional_bool(
                data.get("is_secure_window", data.get("secure_window"))
            ),
            is_hidden=self._optional_bool(data.get("is_hidden", data.get("hidden"))),
            capture_reason=data.get("capture_reason") or data.get("reason"),
            user_visible_notice_shown=self._optional_bool(
                data.get("user_visible_notice_shown", data.get("notice_shown"))
            ),
            security_approved=self._optional_bool(
                data.get("security_approved", data.get("approved"))
            ),
            metadata=dict(data.get("metadata") or {}),
        )

    @staticmethod
    def _optional_bool(value: Any) -> Optional[bool]:
        if value is None:
            return None
        if isinstance(value, bool):
            return value
        cleaned = str(value).strip().lower()
        if cleaned in {"1", "true", "yes", "y", "on"}:
            return True
        if cleaned in {"0", "false", "no", "n", "off"}:
            return False
        return None

    @staticmethod
    def _normalize_source_type(value: Any) -> CaptureSourceType:
        if isinstance(value, CaptureSourceType):
            return value

        cleaned = _safe_lower(value)
        aliases = {
            "screenshot": CaptureSourceType.SCREENSHOT,
            "screen": CaptureSourceType.SCREENSHOT,
            "frame": CaptureSourceType.VIDEO_FRAME,
            "video": CaptureSourceType.VIDEO_FRAME,
            "video_frame": CaptureSourceType.VIDEO_FRAME,
            "image": CaptureSourceType.IMAGE_UPLOAD,
            "upload": CaptureSourceType.IMAGE_UPLOAD,
            "ocr": CaptureSourceType.OCR_TEXT,
            "text": CaptureSourceType.OCR_TEXT,
            "ui": CaptureSourceType.UI_MAP,
            "ui_map": CaptureSourceType.UI_MAP,
            "camera": CaptureSourceType.CAMERA,
            "browser": CaptureSourceType.BROWSER,
            "device": CaptureSourceType.DEVICE,
        }
        return aliases.get(cleaned, CaptureSourceType.UNKNOWN)

    @staticmethod
    def _normalize_risk_level(value: Optional[Union[str, PrivacyRiskLevel]]) -> PrivacyRiskLevel:
        if isinstance(value, PrivacyRiskLevel):
            return value
        if value is None:
            return PrivacyRiskLevel.LOW

        cleaned = _safe_lower(value)
        for item in PrivacyRiskLevel:
            if item.value == cleaned:
                return item
        return PrivacyRiskLevel.LOW

    @staticmethod
    def _normalize_decision(value: Union[str, PrivacyDecision]) -> PrivacyDecision:
        if isinstance(value, PrivacyDecision):
            return value

        cleaned = _safe_lower(value)
        for item in PrivacyDecision:
            if item.value == cleaned:
                return item
        return PrivacyDecision.ALLOW

    @staticmethod
    def _normalize_redaction_mode(value: Union[str, RedactionMode]) -> RedactionMode:
        if isinstance(value, RedactionMode):
            return value

        cleaned = _safe_lower(value)
        for item in RedactionMode:
            if item.value == cleaned:
                return item
        return RedactionMode.BOX

    def _bbox_from_any(
        self,
        value: Union[BoundingBox, Mapping[str, Any], Sequence[int]],
    ) -> BoundingBox:
        if isinstance(value, BoundingBox):
            value.validate()
            return value

        if isinstance(value, Mapping):
            if {"left", "top", "right", "bottom"}.issubset(value.keys()):
                bbox = BoundingBox(
                    left=int(value["left"]),
                    top=int(value["top"]),
                    right=int(value["right"]),
                    bottom=int(value["bottom"]),
                )
                bbox.validate()
                return bbox

            if {"x", "y", "width", "height"}.issubset(value.keys()):
                x = int(value["x"])
                y = int(value["y"])
                width = int(value["width"])
                height = int(value["height"])
                bbox = BoundingBox(left=x, top=y, right=x + width, bottom=y + height)
                bbox.validate()
                return bbox

            if "bbox" in value:
                return self._bbox_from_any(value["bbox"])  # type: ignore[arg-type]

            if "bounding_box" in value:
                return self._bbox_from_any(value["bounding_box"])  # type: ignore[arg-type]

        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            if len(value) != 4:
                raise ValueError("Bounding box sequence must contain exactly 4 numbers.")
            left, top, right, bottom = [int(v) for v in value]
            bbox = BoundingBox(left=left, top=top, right=right, bottom=bottom)
            bbox.validate()
            return bbox

        raise ValueError("Unsupported bounding box format.")

    def _extract_bbox_from_ocr_item(self, item: Mapping[str, Any]) -> Optional[BoundingBox]:
        for key in ("bbox", "bounding_box", "bounds", "box"):
            if key in item and item[key] is not None:
                try:
                    return self._bbox_from_any(item[key])  # type: ignore[arg-type]
                except Exception:
                    continue
        return None

    # ------------------------------------------------------------------
    # Risk helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _highest_risk(findings: Sequence[SensitiveFinding]) -> PrivacyRiskLevel:
        order = {
            PrivacyRiskLevel.LOW: 0,
            PrivacyRiskLevel.MEDIUM: 1,
            PrivacyRiskLevel.HIGH: 2,
            PrivacyRiskLevel.CRITICAL: 3,
        }
        highest = PrivacyRiskLevel.LOW
        for finding in findings:
            if order[finding.risk_level] > order[highest]:
                highest = finding.risk_level
        return highest

    @staticmethod
    def _finding_to_dict(finding: SensitiveFinding) -> Dict[str, Any]:
        finding.validate()
        data = {
            "finding_id": finding.finding_id,
            "data_type": finding.data_type.value,
            "risk_level": finding.risk_level.value,
            "confidence": finding.confidence,
            "reason": finding.reason,
            "text_preview": finding.text_preview,
            "bounding_box": finding.bounding_box.to_dict() if finding.bounding_box else None,
            "source": finding.source,
            "metadata": finding.metadata,
        }
        return _json_safe(data)

    @staticmethod
    def _risk_summary_from_finding_dicts(findings: Sequence[Mapping[str, Any]]) -> Dict[str, int]:
        summary = {
            PrivacyRiskLevel.LOW.value: 0,
            PrivacyRiskLevel.MEDIUM.value: 0,
            PrivacyRiskLevel.HIGH.value: 0,
            PrivacyRiskLevel.CRITICAL.value: 0,
        }
        for finding in findings:
            risk = str(finding.get("risk_level", PrivacyRiskLevel.LOW.value))
            if risk in summary:
                summary[risk] += 1
        return summary

    @staticmethod
    def _passes_luhn_check(number: str) -> bool:
        """
        Luhn check for credit card-like numbers.

        Returns False for too-short numbers.
        """
        digits = [int(ch) for ch in number if ch.isdigit()]
        if len(digits) < 13:
            return False

        checksum = 0
        parity = len(digits) % 2

        for index, digit in enumerate(digits):
            if index % 2 == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            checksum += digit

        return checksum % 10 == 0

    def _metadata(self, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        metadata = {
            "policy_enabled": self.policy.enabled,
            "pillow_available": PIL_AVAILABLE,
        }

        if isinstance(context, Mapping):
            metadata["user_id"] = context.get("user_id")
            metadata["workspace_id"] = context.get("workspace_id")
            metadata["request_id"] = context.get("request_id")
            metadata["task_id"] = context.get("task_id")

        return metadata

    @staticmethod
    def _safe_context(context: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        if not isinstance(context, Mapping):
            return {}

        safe = {}
        for key in ("user_id", "workspace_id", "request_id", "task_id", "source_agent"):
            if key in context:
                safe[key] = context.get(key)
        return safe


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def get_default_privacy_filter() -> PrivacyFilter:
    """Return a fresh PrivacyFilter instance with safe defaults."""
    return PrivacyFilter()


def build_privacy_filter_from_env() -> PrivacyFilter:
    """
    Build PrivacyFilter with environment-aware policy.

    Supported environment variables:
        WILLIAM_VISUAL_PRIVACY_ENABLED
        WILLIAM_VISUAL_PRIVACY_BLOCK_HIDDEN
        WILLIAM_VISUAL_PRIVACY_BLOCK_PRIVATE
        WILLIAM_VISUAL_PRIVACY_BLOCK_SECURE
        WILLIAM_VISUAL_PRIVACY_MAX_IMAGE_BYTES
        WILLIAM_VISUAL_PRIVACY_REDACTION_MODE
    """

    def env_bool(name: str, default: bool) -> bool:
        value = os.getenv(name)
        if value is None:
            return default
        cleaned = value.strip().lower()
        if cleaned in {"1", "true", "yes", "y", "on"}:
            return True
        if cleaned in {"0", "false", "no", "n", "off"}:
            return False
        return default

    def env_int(name: str, default: int) -> int:
        value = os.getenv(name)
        if value is None:
            return default
        try:
            return int(value)
        except Exception:
            return default

    mode_raw = os.getenv("WILLIAM_VISUAL_PRIVACY_REDACTION_MODE", RedactionMode.BOX.value)
    try:
        redaction_mode = RedactionMode(mode_raw.strip().lower())
    except Exception:
        redaction_mode = RedactionMode.BOX

    policy = PrivacyPolicy(
        enabled=env_bool("WILLIAM_VISUAL_PRIVACY_ENABLED", True),
        block_hidden_captures=env_bool("WILLIAM_VISUAL_PRIVACY_BLOCK_HIDDEN", True),
        block_private_browser_captures=env_bool("WILLIAM_VISUAL_PRIVACY_BLOCK_PRIVATE", True),
        block_secure_window_captures=env_bool("WILLIAM_VISUAL_PRIVACY_BLOCK_SECURE", True),
        max_image_bytes=env_int("WILLIAM_VISUAL_PRIVACY_MAX_IMAGE_BYTES", DEFAULT_MAX_IMAGE_BYTES),
        redaction_mode=redaction_mode,
    )

    return PrivacyFilter(policy=policy)


__all__ = [
    "BoundingBox",
    "CaptureContext",
    "CaptureSourceType",
    "CLASS_NAME",
    "CONFIG_VERSION",
    "DEFAULT_MAX_IMAGE_BYTES",
    "DEFAULT_MAX_OCR_ITEMS",
    "DEFAULT_REDACTION_FILL",
    "FILE_NAME",
    "MODULE_NAME",
    "PIL_AVAILABLE",
    "PrivacyDecision",
    "PrivacyFilter",
    "PrivacyPolicy",
    "PrivacyRiskLevel",
    "RedactionMode",
    "SensitiveDataType",
    "SensitiveFinding",
    "build_privacy_filter_from_env",
    "get_default_privacy_filter",
]