"""
agents/visual_agent/visual_validator.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Compares expected vs actual screens for visual task validation.

This module validates whether a visual task reached the expected screen/state by
comparing expected and actual screenshots or extracted visual screen data.

It is designed for:
    - Visual Agent screen validation
    - Verification Agent proof/validation payloads
    - Master Agent routed visual task checks
    - Dashboard/API integration
    - SaaS-safe user/workspace isolated validation

Supported comparison types:
    - Full screenshot similarity
    - Region-level similarity
    - Expected vs actual OCR/text
    - Expected vs actual UI elements
    - Expected vs actual screen/app/page context
    - Required and forbidden visual signals
    - Layout/bounds tolerance checks
    - Structured confidence scoring

Safety:
    - Does not click, type, browse, call, message, delete, or perform system actions.
    - Redacts sensitive fields.
    - Requires user_id and workspace_id for user-specific validation.
    - Uses optional imports safely.
"""

from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
import io
import json
import logging
import math
import os
import re
import statistics
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, ClassVar, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        The real William/Jarvis system should provide agents.base_agent.BaseAgent.
        This fallback keeps the file import-safe during isolated development.
        """

        agent_name: str = "base_agent_fallback"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.config = kwargs.get("config", {}) or {}

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            return None

        def log_audit(self, action: str, payload: Dict[str, Any]) -> None:
            return None


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover
    MemoryAgent = None  # type: ignore


try:
    from PIL import Image, ImageChops, ImageStat, ImageOps  # type: ignore
    PIL_AVAILABLE = True
except Exception:  # pragma: no cover
    Image = None  # type: ignore
    ImageChops = None  # type: ignore
    ImageStat = None  # type: ignore
    ImageOps = None  # type: ignore
    PIL_AVAILABLE = False


try:
    import numpy as np  # type: ignore
    NUMPY_AVAILABLE = True
except Exception:  # pragma: no cover
    np = None  # type: ignore
    NUMPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

UTC = timezone.utc
VISUAL_VALIDATOR_SCHEMA_VERSION = "1.0.0"

DEFAULT_IMAGE_SIMILARITY_THRESHOLD = 0.86
DEFAULT_TEXT_SIMILARITY_THRESHOLD = 0.78
DEFAULT_ELEMENT_MATCH_THRESHOLD = 0.75
DEFAULT_LAYOUT_MATCH_THRESHOLD = 0.75
DEFAULT_OVERALL_SUCCESS_THRESHOLD = 0.78
DEFAULT_REGION_SIMILARITY_THRESHOLD = 0.82
DEFAULT_BOUNDS_TOLERANCE_PX = 12
DEFAULT_BOUNDS_TOLERANCE_RATIO = 0.08
DEFAULT_MAX_IMAGE_DIMENSION = 1280
DEFAULT_MAX_TEXT_LENGTH = 12000
DEFAULT_MAX_ELEMENTS = 500
DEFAULT_MAX_REGIONS = 100

SENSITIVE_CONTEXT_KEYS = {
    "password",
    "token",
    "secret",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "session",
    "credential",
    "private_key",
    "access_key",
    "refresh_token",
    "bearer",
    "otp",
    "pin",
    "ssn",
    "card",
    "cvv",
}

SUPPORTED_IMAGE_INPUT_TYPES = {
    "path",
    "bytes",
    "base64",
    "pil",
    "none",
}

SAFE_VALIDATION_MODES = {
    "full",
    "image_only",
    "text_only",
    "elements_only",
    "layout_only",
    "regions_only",
    "signals_only",
    "context_only",
    "fast",
}

RISKY_OPERATION_NAMES = {
    "cross_workspace_validate",
    "cross_user_validate",
    "store_visual_memory",
    "export_visual_evidence",
    "admin_override",
}


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _safe_uuid(prefix: str = "vval") -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _normalize_str(value: Any, max_len: int = 1000) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    text = re.sub(r"\s+", " ", text)
    return text[:max_len]


def _normalize_lower(value: Any, max_len: int = 1000) -> str:
    return _normalize_str(value, max_len=max_len).lower()


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
        if math.isnan(number) or math.isinf(number):
            return default
        return number
    except Exception:
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _clamp(value: Any, minimum: float = 0.0, maximum: float = 1.0) -> float:
    number = _safe_float(value, minimum)
    return max(minimum, min(maximum, number))


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _stable_json_hash(payload: Mapping[str, Any]) -> str:
    try:
        raw = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    except Exception:
        raw = str(payload)
    return _sha256_text(raw)


def _redact_sensitive(value: Any) -> Any:
    """
    Recursively redact sensitive data.

    Visual validation should compare screens and signals, not store secrets.
    """
    if isinstance(value, Mapping):
        output: Dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key).lower()
            if any(sensitive in key_text for sensitive in SENSITIVE_CONTEXT_KEYS):
                output[str(key)] = "[REDACTED]"
            else:
                output[str(key)] = _redact_sensitive(item)
        return output

    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]

    if isinstance(value, tuple):
        return tuple(_redact_sensitive(item) for item in value)

    if isinstance(value, str):
        text = value
        text = re.sub(r"(?i)(bearer\s+)[a-z0-9._\-+/=]+", r"\1[REDACTED]", text)
        text = re.sub(r"(?i)(api[_-]?key\s*[:=]\s*)[a-z0-9._\-+/=]+", r"\1[REDACTED]", text)
        text = re.sub(r"(?i)(password\s*[:=]\s*)\S+", r"\1[REDACTED]", text)
        text = re.sub(r"(?i)(token\s*[:=]\s*)\S+", r"\1[REDACTED]", text)
        return text

    return value


def _deepcopy_json_safe(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return copy.deepcopy(value)


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _tokenize_text(text: str) -> List[str]:
    text = _normalize_lower(text, max_len=DEFAULT_MAX_TEXT_LENGTH)
    return re.findall(r"[a-z0-9]+", text)


def _jaccard_similarity(a: Iterable[str], b: Iterable[str]) -> float:
    set_a = set(a)
    set_b = set(b)
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    return len(set_a & set_b) / max(1, len(set_a | set_b))


def _sequence_similarity(a: str, b: str) -> float:
    """
    Lightweight text similarity without external dependencies.
    """
    a = _normalize_lower(a, max_len=DEFAULT_MAX_TEXT_LENGTH)
    b = _normalize_lower(b, max_len=DEFAULT_MAX_TEXT_LENGTH)
    if a == b:
        return 1.0
    if not a or not b:
        return 0.0

    tokens_score = _jaccard_similarity(_tokenize_text(a), _tokenize_text(b))

    common_chars = 0
    counter_b: Dict[str, int] = {}
    for char in b:
        counter_b[char] = counter_b.get(char, 0) + 1
    for char in a:
        if counter_b.get(char, 0) > 0:
            common_chars += 1
            counter_b[char] -= 1

    char_score = common_chars / max(len(a), len(b), 1)

    contains_boost = 0.0
    if a in b or b in a:
        contains_boost = 0.15

    return _clamp((tokens_score * 0.7) + (char_score * 0.3) + contains_boost, 0.0, 1.0)


def _safe_slug(value: Any, fallback: str = "item") -> str:
    text = _normalize_lower(value, max_len=160)
    text = re.sub(r"[^a-z0-9._-]+", "_", text)
    text = text.strip("._-")
    return text or fallback


def _bounds_to_tuple(bounds: Any) -> Optional[Tuple[float, float, float, float]]:
    """
    Convert bounds shape to (x, y, width, height).

    Accepts:
        {"x": 1, "y": 2, "width": 10, "height": 20}
        {"left": 1, "top": 2, "right": 11, "bottom": 22}
        [x, y, width, height]
    """
    if bounds is None:
        return None

    if isinstance(bounds, Mapping):
        if all(key in bounds for key in ("x", "y", "width", "height")):
            return (
                _safe_float(bounds.get("x")),
                _safe_float(bounds.get("y")),
                _safe_float(bounds.get("width")),
                _safe_float(bounds.get("height")),
            )

        if all(key in bounds for key in ("left", "top", "right", "bottom")):
            left = _safe_float(bounds.get("left"))
            top = _safe_float(bounds.get("top"))
            right = _safe_float(bounds.get("right"))
            bottom = _safe_float(bounds.get("bottom"))
            return (left, top, max(0.0, right - left), max(0.0, bottom - top))

    if isinstance(bounds, (list, tuple)) and len(bounds) >= 4:
        return (
            _safe_float(bounds[0]),
            _safe_float(bounds[1]),
            _safe_float(bounds[2]),
            _safe_float(bounds[3]),
        )

    return None


def _bounds_center(bounds: Tuple[float, float, float, float]) -> Tuple[float, float]:
    x, y, width, height = bounds
    return (x + width / 2.0, y + height / 2.0)


def _bounds_iou(a: Tuple[float, float, float, float], b: Tuple[float, float, float, float]) -> float:
    ax, ay, aw, ah = a
    bx, by, bw, bh = b

    a_left, a_top, a_right, a_bottom = ax, ay, ax + aw, ay + ah
    b_left, b_top, b_right, b_bottom = bx, by, bx + bw, by + bh

    inter_left = max(a_left, b_left)
    inter_top = max(a_top, b_top)
    inter_right = min(a_right, b_right)
    inter_bottom = min(a_bottom, b_bottom)

    inter_width = max(0.0, inter_right - inter_left)
    inter_height = max(0.0, inter_bottom - inter_top)
    intersection = inter_width * inter_height

    area_a = max(0.0, aw) * max(0.0, ah)
    area_b = max(0.0, bw) * max(0.0, bh)
    union = area_a + area_b - intersection

    if union <= 0:
        return 0.0
    return _clamp(intersection / union, 0.0, 1.0)


def _distance_score(
    expected: Tuple[float, float],
    actual: Tuple[float, float],
    screen_size: Optional[Tuple[int, int]] = None,
) -> float:
    ex, ey = expected
    ax, ay = actual
    distance = math.sqrt((ex - ax) ** 2 + (ey - ay) ** 2)

    if screen_size:
        max_distance = math.sqrt(screen_size[0] ** 2 + screen_size[1] ** 2)
    else:
        max_distance = max(1.0, distance + 100.0)

    return _clamp(1.0 - (distance / max(max_distance, 1.0)), 0.0, 1.0)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class VisualValidatorConfig:
    """
    Configuration for VisualValidator.

    All thresholds are safe defaults and can be overridden from FastAPI,
    dashboard, or agent config.
    """

    image_similarity_threshold: float = DEFAULT_IMAGE_SIMILARITY_THRESHOLD
    text_similarity_threshold: float = DEFAULT_TEXT_SIMILARITY_THRESHOLD
    element_match_threshold: float = DEFAULT_ELEMENT_MATCH_THRESHOLD
    layout_match_threshold: float = DEFAULT_LAYOUT_MATCH_THRESHOLD
    region_similarity_threshold: float = DEFAULT_REGION_SIMILARITY_THRESHOLD
    overall_success_threshold: float = DEFAULT_OVERALL_SUCCESS_THRESHOLD
    bounds_tolerance_px: int = DEFAULT_BOUNDS_TOLERANCE_PX
    bounds_tolerance_ratio: float = DEFAULT_BOUNDS_TOLERANCE_RATIO
    max_image_dimension: int = DEFAULT_MAX_IMAGE_DIMENSION
    max_text_length: int = DEFAULT_MAX_TEXT_LENGTH
    max_elements: int = DEFAULT_MAX_ELEMENTS
    max_regions: int = DEFAULT_MAX_REGIONS
    enable_image_comparison: bool = True
    enable_text_comparison: bool = True
    enable_element_comparison: bool = True
    enable_layout_comparison: bool = True
    enable_region_comparison: bool = True
    enable_signal_comparison: bool = True
    enable_agent_events: bool = True
    enable_audit_log: bool = True
    enable_memory_payloads: bool = True
    redact_sensitive_data: bool = True

    @classmethod
    def from_mapping(cls, config: Optional[Mapping[str, Any]]) -> "VisualValidatorConfig":
        config = config or {}
        return cls(
            image_similarity_threshold=_clamp(config.get("image_similarity_threshold", DEFAULT_IMAGE_SIMILARITY_THRESHOLD)),
            text_similarity_threshold=_clamp(config.get("text_similarity_threshold", DEFAULT_TEXT_SIMILARITY_THRESHOLD)),
            element_match_threshold=_clamp(config.get("element_match_threshold", DEFAULT_ELEMENT_MATCH_THRESHOLD)),
            layout_match_threshold=_clamp(config.get("layout_match_threshold", DEFAULT_LAYOUT_MATCH_THRESHOLD)),
            region_similarity_threshold=_clamp(config.get("region_similarity_threshold", DEFAULT_REGION_SIMILARITY_THRESHOLD)),
            overall_success_threshold=_clamp(config.get("overall_success_threshold", DEFAULT_OVERALL_SUCCESS_THRESHOLD)),
            bounds_tolerance_px=max(0, _safe_int(config.get("bounds_tolerance_px", DEFAULT_BOUNDS_TOLERANCE_PX))),
            bounds_tolerance_ratio=_clamp(config.get("bounds_tolerance_ratio", DEFAULT_BOUNDS_TOLERANCE_RATIO)),
            max_image_dimension=max(64, _safe_int(config.get("max_image_dimension", DEFAULT_MAX_IMAGE_DIMENSION))),
            max_text_length=max(100, _safe_int(config.get("max_text_length", DEFAULT_MAX_TEXT_LENGTH))),
            max_elements=max(1, _safe_int(config.get("max_elements", DEFAULT_MAX_ELEMENTS))),
            max_regions=max(1, _safe_int(config.get("max_regions", DEFAULT_MAX_REGIONS))),
            enable_image_comparison=bool(config.get("enable_image_comparison", True)),
            enable_text_comparison=bool(config.get("enable_text_comparison", True)),
            enable_element_comparison=bool(config.get("enable_element_comparison", True)),
            enable_layout_comparison=bool(config.get("enable_layout_comparison", True)),
            enable_region_comparison=bool(config.get("enable_region_comparison", True)),
            enable_signal_comparison=bool(config.get("enable_signal_comparison", True)),
            enable_agent_events=bool(config.get("enable_agent_events", True)),
            enable_audit_log=bool(config.get("enable_audit_log", True)),
            enable_memory_payloads=bool(config.get("enable_memory_payloads", True)),
            redact_sensitive_data=bool(config.get("redact_sensitive_data", True)),
        )


@dataclass
class VisualElement:
    """
    Normalized UI element.

    Used to compare expected vs actual buttons, inputs, links, cards, forms,
    icons, and detected UI regions.
    """

    element_id: str
    element_type: str = "unknown"
    text: str = ""
    label: str = ""
    role: str = ""
    bounds: Optional[Tuple[float, float, float, float]] = None
    confidence: float = 0.5
    visible: bool = True
    enabled: Optional[bool] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_any(cls, value: Any, index: int = 0) -> "VisualElement":
        if isinstance(value, VisualElement):
            return value

        payload = dict(value or {}) if isinstance(value, Mapping) else {"text": str(value)}
        bounds = _bounds_to_tuple(payload.get("bounds") or payload.get("box") or payload.get("rect"))

        element_id = _normalize_str(
            payload.get("element_id")
            or payload.get("id")
            or payload.get("key")
            or f"element_{index}",
            160,
        )

        return cls(
            element_id=element_id,
            element_type=_normalize_lower(payload.get("element_type") or payload.get("type") or "unknown", 100),
            text=_normalize_str(payload.get("text") or payload.get("value") or "", 500),
            label=_normalize_str(payload.get("label") or payload.get("name") or "", 500),
            role=_normalize_lower(payload.get("role") or payload.get("aria_role") or "", 100),
            bounds=bounds,
            confidence=_clamp(payload.get("confidence", 0.5)),
            visible=bool(payload.get("visible", True)),
            enabled=payload.get("enabled") if isinstance(payload.get("enabled"), bool) else None,
            metadata=_redact_sensitive(dict(payload.get("metadata") or {})),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "element_id": self.element_id,
            "element_type": self.element_type,
            "text": self.text,
            "label": self.label,
            "role": self.role,
            "bounds": self.bounds,
            "confidence": self.confidence,
            "visible": self.visible,
            "enabled": self.enabled,
            "metadata": _redact_sensitive(self.metadata),
        }

    def match_key(self) -> str:
        return " ".join(
            [
                self.element_type,
                self.role,
                self.text,
                self.label,
            ]
        ).strip().lower()


@dataclass
class VisualRegionSpec:
    """
    Expected region to compare.

    region may define bounds and optional expected image/text/signals.
    """

    region_id: str
    name: str
    bounds: Optional[Tuple[float, float, float, float]] = None
    expected_text: Optional[str] = None
    required: bool = True
    weight: float = 1.0
    threshold: float = DEFAULT_REGION_SIMILARITY_THRESHOLD
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_any(cls, value: Any, index: int = 0) -> "VisualRegionSpec":
        payload = dict(value or {}) if isinstance(value, Mapping) else {"name": str(value)}
        return cls(
            region_id=_normalize_str(payload.get("region_id") or payload.get("id") or f"region_{index}", 160),
            name=_normalize_str(payload.get("name") or payload.get("label") or f"Region {index}", 200),
            bounds=_bounds_to_tuple(payload.get("bounds") or payload.get("box") or payload.get("rect")),
            expected_text=(
                _normalize_str(payload.get("expected_text"), DEFAULT_MAX_TEXT_LENGTH)
                if payload.get("expected_text") is not None
                else None
            ),
            required=bool(payload.get("required", True)),
            weight=max(0.0, _safe_float(payload.get("weight", 1.0), 1.0)),
            threshold=_clamp(payload.get("threshold", DEFAULT_REGION_SIMILARITY_THRESHOLD)),
            metadata=_redact_sensitive(dict(payload.get("metadata") or {})),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "region_id": self.region_id,
            "name": self.name,
            "bounds": self.bounds,
            "expected_text": self.expected_text,
            "required": self.required,
            "weight": self.weight,
            "threshold": self.threshold,
            "metadata": _redact_sensitive(self.metadata),
        }


@dataclass
class VisualValidationSpec:
    """
    Normalized expected visual state.

    This can be created by the Visual Agent, Workflow Agent, Verification Agent,
    Browser Agent, or Dashboard/API.
    """

    spec_id: str
    name: str = "visual_validation_spec"
    expected_image: Any = None
    expected_text: str = ""
    expected_elements: List[VisualElement] = field(default_factory=list)
    expected_regions: List[VisualRegionSpec] = field(default_factory=list)
    required_text: List[str] = field(default_factory=list)
    forbidden_text: List[str] = field(default_factory=list)
    required_elements: List[VisualElement] = field(default_factory=list)
    forbidden_elements: List[VisualElement] = field(default_factory=list)
    expected_context: Dict[str, Any] = field(default_factory=dict)
    required_signals: Dict[str, Any] = field(default_factory=dict)
    forbidden_signals: Dict[str, Any] = field(default_factory=dict)
    thresholds: Dict[str, float] = field(default_factory=dict)
    weights: Dict[str, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, spec: Mapping[str, Any]) -> "VisualValidationSpec":
        expected_elements = [
            VisualElement.from_any(item, index=index)
            for index, item in enumerate(_as_list(spec.get("expected_elements") or spec.get("elements")))
        ][:DEFAULT_MAX_ELEMENTS]

        required_elements = [
            VisualElement.from_any(item, index=index)
            for index, item in enumerate(_as_list(spec.get("required_elements")))
        ][:DEFAULT_MAX_ELEMENTS]

        forbidden_elements = [
            VisualElement.from_any(item, index=index)
            for index, item in enumerate(_as_list(spec.get("forbidden_elements")))
        ][:DEFAULT_MAX_ELEMENTS]

        expected_regions = [
            VisualRegionSpec.from_any(item, index=index)
            for index, item in enumerate(_as_list(spec.get("expected_regions") or spec.get("regions")))
        ][:DEFAULT_MAX_REGIONS]

        return cls(
            spec_id=_normalize_str(spec.get("spec_id") or spec.get("id") or _safe_uuid("vspec"), 160),
            name=_normalize_str(spec.get("name") or "visual_validation_spec", 240),
            expected_image=spec.get("expected_image") or spec.get("image"),
            expected_text=_normalize_str(spec.get("expected_text") or spec.get("text") or "", DEFAULT_MAX_TEXT_LENGTH),
            expected_elements=expected_elements,
            expected_regions=expected_regions,
            required_text=[
                _normalize_str(item, 1000)
                for item in _as_list(spec.get("required_text"))
                if _normalize_str(item)
            ],
            forbidden_text=[
                _normalize_str(item, 1000)
                for item in _as_list(spec.get("forbidden_text"))
                if _normalize_str(item)
            ],
            required_elements=required_elements,
            forbidden_elements=forbidden_elements,
            expected_context=_redact_sensitive(dict(spec.get("expected_context") or spec.get("context") or {})),
            required_signals=_redact_sensitive(dict(spec.get("required_signals") or {})),
            forbidden_signals=_redact_sensitive(dict(spec.get("forbidden_signals") or {})),
            thresholds={
                str(key): _clamp(value)
                for key, value in dict(spec.get("thresholds") or {}).items()
            },
            weights={
                str(key): max(0.0, _safe_float(value, 0.0))
                for key, value in dict(spec.get("weights") or {}).items()
            },
            metadata=_redact_sensitive(dict(spec.get("metadata") or {})),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "spec_id": self.spec_id,
            "name": self.name,
            "expected_image_present": self.expected_image is not None,
            "expected_text": self.expected_text,
            "expected_elements": [element.to_dict() for element in self.expected_elements],
            "expected_regions": [region.to_dict() for region in self.expected_regions],
            "required_text": list(self.required_text),
            "forbidden_text": list(self.forbidden_text),
            "required_elements": [element.to_dict() for element in self.required_elements],
            "forbidden_elements": [element.to_dict() for element in self.forbidden_elements],
            "expected_context": _redact_sensitive(self.expected_context),
            "required_signals": _redact_sensitive(self.required_signals),
            "forbidden_signals": _redact_sensitive(self.forbidden_signals),
            "thresholds": dict(self.thresholds),
            "weights": dict(self.weights),
            "metadata": _redact_sensitive(self.metadata),
        }


@dataclass
class ActualVisualState:
    """
    Normalized actual screen state.
    """

    state_id: str
    actual_image: Any = None
    actual_text: str = ""
    actual_elements: List[VisualElement] = field(default_factory=list)
    actual_context: Dict[str, Any] = field(default_factory=dict)
    actual_signals: Dict[str, Any] = field(default_factory=dict)
    screen_size: Optional[Tuple[int, int]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, actual: Mapping[str, Any]) -> "ActualVisualState":
        actual_elements = [
            VisualElement.from_any(item, index=index)
            for index, item in enumerate(_as_list(actual.get("actual_elements") or actual.get("elements")))
        ][:DEFAULT_MAX_ELEMENTS]

        screen_size = None
        raw_size = actual.get("screen_size") or actual.get("image_size")
        if isinstance(raw_size, Mapping):
            screen_size = (_safe_int(raw_size.get("width")), _safe_int(raw_size.get("height")))
        elif isinstance(raw_size, (list, tuple)) and len(raw_size) >= 2:
            screen_size = (_safe_int(raw_size[0]), _safe_int(raw_size[1]))

        return cls(
            state_id=_normalize_str(actual.get("state_id") or actual.get("id") or _safe_uuid("vstate"), 160),
            actual_image=actual.get("actual_image") or actual.get("image") or actual.get("screenshot"),
            actual_text=_normalize_str(actual.get("actual_text") or actual.get("text") or actual.get("ocr_text") or "", DEFAULT_MAX_TEXT_LENGTH),
            actual_elements=actual_elements,
            actual_context=_redact_sensitive(dict(actual.get("actual_context") or actual.get("context") or {})),
            actual_signals=_redact_sensitive(dict(actual.get("actual_signals") or actual.get("signals") or {})),
            screen_size=screen_size,
            metadata=_redact_sensitive(dict(actual.get("metadata") or {})),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "state_id": self.state_id,
            "actual_image_present": self.actual_image is not None,
            "actual_text": self.actual_text,
            "actual_elements": [element.to_dict() for element in self.actual_elements],
            "actual_context": _redact_sensitive(self.actual_context),
            "actual_signals": _redact_sensitive(self.actual_signals),
            "screen_size": self.screen_size,
            "metadata": _redact_sensitive(self.metadata),
        }


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class VisualValidator(BaseAgent):
    """
    Compares expected vs actual screens for visual task validation.

    Public methods:
        - validate_screen()
        - compare_screens()
        - compare_screen_data()
        - compare_images()
        - compare_text()
        - compare_elements()
        - compare_layout()
        - compare_regions()
        - validate_signals()
        - build_expected_spec()
        - health_check()

    Master Agent:
        Can route "validate visual result" tasks here after Browser/System/App
        agents perform a user-approved action.

    Visual Agent:
        Uses this helper to decide whether screenshots, OCR, elements, and screen
        contexts match the target visual state.

    Verification Agent:
        Receives _prepare_verification_payload() output to confirm task success.

    Memory Agent:
        Receives _prepare_memory_payload() output for reusable success patterns.

    Dashboard/API:
        Receives structured dict/JSON results with scores, differences, warnings,
        recommendations, and metadata.
    """

    agent_name: ClassVar[str] = "visual_validator"
    agent_type: ClassVar[str] = "visual_agent_helper"
    registry_name: ClassVar[str] = "VisualValidator"
    version: ClassVar[str] = VISUAL_VALIDATOR_SCHEMA_VERSION

    def __init__(
        self,
        config: Optional[Mapping[str, Any]] = None,
        *,
        security_agent: Any = None,
        memory_agent: Any = None,
        audit_logger: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ) -> None:
        super().__init__(config=dict(config or {}))
        self.validator_config = VisualValidatorConfig.from_mapping(config)
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Optional[Mapping[str, Any]],
        *,
        require_user_workspace: bool = True,
    ) -> Tuple[bool, Optional[str], Dict[str, Any]]:
        """
        Validate SaaS tenant context.

        Every user-specific validation must include user_id and workspace_id.
        This prevents visual proof/results from leaking across tenants.
        """
        safe_context = dict(context or {})
        user_id = _normalize_str(safe_context.get("user_id"), 160)
        workspace_id = _normalize_str(safe_context.get("workspace_id"), 160)

        if require_user_workspace and not user_id:
            return False, "Missing required user_id for visual validation.", safe_context

        if require_user_workspace and not workspace_id:
            return False, "Missing required workspace_id for visual validation.", safe_context

        safe_context["user_id"] = user_id
        safe_context["workspace_id"] = workspace_id
        return True, None, _redact_sensitive(safe_context)

    def _requires_security_check(self, operation: str, context: Optional[Mapping[str, Any]] = None) -> bool:
        operation_name = _normalize_lower(operation, 160)
        context = context or {}

        if operation_name in RISKY_OPERATION_NAMES:
            return True

        if context.get("cross_workspace") or context.get("cross_user") or context.get("admin_override"):
            return True

        if operation_name.startswith("cross_"):
            return True

        return False

    def _request_security_approval(
        self,
        operation: str,
        context: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval if required.

        For normal visual comparisons, approval is not required. This hook exists
        for future admin/cross-scope/export/store operations.
        """
        safe_context = _redact_sensitive(dict(context or {}))
        safe_payload = _redact_sensitive(dict(payload or {}))
        operation_name = _normalize_lower(operation, 160)

        if not self._requires_security_check(operation_name, safe_context):
            return self._safe_result(
                True,
                "Security approval not required.",
                data={"approved": True, "reason": "not_required"},
                metadata={"operation": operation_name},
            )

        if bool(safe_context.get("security_approved")):
            return self._safe_result(
                True,
                "Security approval accepted from trusted context.",
                data={"approved": True, "reason": "trusted_context"},
                metadata={"operation": operation_name},
            )

        agent = self.security_agent
        if agent is None and SecurityAgent is not None:
            try:
                agent = SecurityAgent()
            except Exception:
                agent = None

        if agent is not None:
            try:
                if hasattr(agent, "approve_action"):
                    decision = agent.approve_action(
                        action=operation_name,
                        context=safe_context,
                        payload=safe_payload,
                    )
                elif hasattr(agent, "request_approval"):
                    decision = agent.request_approval(
                        operation=operation_name,
                        context=safe_context,
                        payload=safe_payload,
                    )
                else:
                    decision = {"approved": False, "reason": "security_agent_missing_approval_method"}

                approved = bool(decision.get("approved") if isinstance(decision, Mapping) else decision)

                return self._safe_result(
                    approved,
                    "Security approval granted." if approved else "Security approval denied.",
                    data={"approved": approved, "decision": _redact_sensitive(decision)},
                    metadata={"operation": operation_name},
                )
            except Exception as exc:
                logger.exception("Security approval failed.")
                return self._error_result(
                    "Security approval request failed.",
                    error=exc,
                    metadata={"operation": operation_name},
                )

        return self._safe_result(
            False,
            "Security approval required but no Security Agent approval is available.",
            data={"approved": False, "reason": "approval_unavailable"},
            metadata={"operation": operation_name},
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        success: bool = True,
        confidence: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Verification Agent compatible payload.
        """
        safe_context = _redact_sensitive(dict(context or {}))
        safe_data = _redact_sensitive(dict(data or {}))

        return {
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "success": bool(success),
            "confidence": _clamp(confidence if confidence is not None else safe_data.get("overall_score", 0.0)),
            "user_id": safe_context.get("user_id"),
            "workspace_id": safe_context.get("workspace_id"),
            "project_id": safe_context.get("project_id"),
            "task_id": safe_context.get("task_id"),
            "validation_id": safe_data.get("validation_id"),
            "data": safe_data,
            "timestamp": _utc_now_iso(),
            "schema_version": self.version,
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare a Memory Agent compatible payload.

        Useful validated visual outcomes can become future success patterns.
        """
        safe_context = _redact_sensitive(dict(context or {}))
        safe_data = _redact_sensitive(dict(data or {}))

        return {
            "memory_type": "visual_validation_pattern",
            "source_agent": self.agent_name,
            "action": action,
            "user_id": safe_context.get("user_id"),
            "workspace_id": safe_context.get("workspace_id"),
            "project_id": safe_context.get("project_id"),
            "task_id": safe_context.get("task_id"),
            "importance": "medium",
            "content": {
                "validation_id": safe_data.get("validation_id"),
                "passed": safe_data.get("passed"),
                "overall_score": safe_data.get("overall_score"),
                "screen_match_summary": safe_data.get("summary"),
                "matched_required_text": safe_data.get("matched_required_text"),
                "missing_required_text": safe_data.get("missing_required_text"),
                "matched_required_elements": safe_data.get("matched_required_elements"),
                "missing_required_elements": safe_data.get("missing_required_elements"),
            },
            "tags": ["visual", "validation", "screen_match", "verification"],
            "created_at": _utc_now_iso(),
            "schema_version": self.version,
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        if not self.validator_config.enable_agent_events:
            return

        safe_payload = _redact_sensitive(dict(payload or {}))
        safe_payload.setdefault("agent", self.agent_name)
        safe_payload.setdefault("timestamp", _utc_now_iso())

        try:
            if self.event_emitter:
                self.event_emitter(event_name, safe_payload)
                return

            if hasattr(self, "emit_event"):
                self.emit_event(event_name, safe_payload)  # type: ignore[attr-defined]
        except Exception:
            logger.debug("Failed to emit VisualValidator event.", exc_info=True)

    def _log_audit_event(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        success: bool = True,
    ) -> None:
        if not self.validator_config.enable_audit_log:
            return

        payload = {
            "agent": self.agent_name,
            "action": action,
            "success": bool(success),
            "context": _redact_sensitive(dict(context or {})),
            "data": _redact_sensitive(dict(data or {})),
            "timestamp": _utc_now_iso(),
            "schema_version": self.version,
        }

        try:
            if self.audit_logger:
                self.audit_logger(action, payload)
                return

            if hasattr(self, "log_audit"):
                self.log_audit(action, payload)  # type: ignore[attr-defined]
        except Exception:
            logger.debug("Failed to log VisualValidator audit event.", exc_info=True)

    def _safe_result(
        self,
        success: bool,
        message: str,
        *,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": bool(success),
            "message": str(message),
            "data": _redact_sensitive(dict(data or {})),
            "error": self._serialize_error(error) if error else None,
            "metadata": {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "schema_version": self.version,
                "timestamp": _utc_now_iso(),
                **_redact_sensitive(dict(metadata or {})),
            },
        }

    def _error_result(
        self,
        message: str,
        *,
        error: Optional[Any] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._safe_result(
            False,
            message,
            data=data,
            error=error,
            metadata=metadata,
        )

    @staticmethod
    def _serialize_error(error: Any) -> Dict[str, Any]:
        if error is None:
            return {}
        if isinstance(error, Mapping):
            return _redact_sensitive(dict(error))
        return {
            "type": error.__class__.__name__,
            "message": str(error),
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_screen(
        self,
        context: Mapping[str, Any],
        expected: Mapping[str, Any],
        actual: Mapping[str, Any],
        *,
        mode: str = "full",
    ) -> Dict[str, Any]:
        """
        Main visual validation method.

        Args:
            context:
                Must include user_id and workspace_id.
            expected:
                Expected visual spec.
            actual:
                Actual screen state.
            mode:
                full, image_only, text_only, elements_only, layout_only,
                regions_only, signals_only, context_only, fast.

        Returns:
            Structured result with pass/fail, scores, differences,
            verification payload, and optional memory payload.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid visual validation context.")

        mode = _normalize_lower(mode, 80) or "full"
        if mode not in SAFE_VALIDATION_MODES:
            return self._error_result(
                "Invalid visual validation mode.",
                data={"allowed_modes": sorted(SAFE_VALIDATION_MODES)},
            )

        operation = "validate_screen"
        if safe_context.get("cross_workspace") or safe_context.get("cross_user"):
            operation = "cross_workspace_validate"

        approval = self._request_security_approval(operation, safe_context, {"mode": mode})
        if not approval.get("success") or not approval.get("data", {}).get("approved"):
            return self._error_result(
                "Security approval denied for visual validation.",
                data={"approval": approval.get("data", {})},
            )

        start_time = time.time()
        validation_id = _safe_uuid("visual_validation")

        try:
            expected_spec = VisualValidationSpec.from_mapping(expected)
            actual_state = ActualVisualState.from_mapping(actual)

            component_results: Dict[str, Dict[str, Any]] = {}

            if mode in {"full", "image_only", "fast"} and self.validator_config.enable_image_comparison:
                if expected_spec.expected_image is not None or actual_state.actual_image is not None:
                    component_results["image"] = self.compare_images(
                        safe_context,
                        expected_spec.expected_image,
                        actual_state.actual_image,
                        threshold=expected_spec.thresholds.get(
                            "image",
                            self.validator_config.image_similarity_threshold,
                        ),
                    ).get("data", {})

            if mode in {"full", "text_only", "fast"} and self.validator_config.enable_text_comparison:
                component_results["text"] = self.compare_text(
                    safe_context,
                    expected_text=expected_spec.expected_text,
                    actual_text=actual_state.actual_text,
                    required_text=expected_spec.required_text,
                    forbidden_text=expected_spec.forbidden_text,
                    threshold=expected_spec.thresholds.get(
                        "text",
                        self.validator_config.text_similarity_threshold,
                    ),
                ).get("data", {})

            if mode in {"full", "elements_only", "fast"} and self.validator_config.enable_element_comparison:
                component_results["elements"] = self.compare_elements(
                    safe_context,
                    expected_elements=[
                        element.to_dict()
                        for element in expected_spec.expected_elements + expected_spec.required_elements
                    ],
                    actual_elements=[element.to_dict() for element in actual_state.actual_elements],
                    forbidden_elements=[element.to_dict() for element in expected_spec.forbidden_elements],
                    threshold=expected_spec.thresholds.get(
                        "elements",
                        self.validator_config.element_match_threshold,
                    ),
                    screen_size=actual_state.screen_size,
                ).get("data", {})

            if mode in {"full", "layout_only"} and self.validator_config.enable_layout_comparison:
                component_results["layout"] = self.compare_layout(
                    safe_context,
                    expected_elements=[element.to_dict() for element in expected_spec.expected_elements],
                    actual_elements=[element.to_dict() for element in actual_state.actual_elements],
                    threshold=expected_spec.thresholds.get(
                        "layout",
                        self.validator_config.layout_match_threshold,
                    ),
                    screen_size=actual_state.screen_size,
                ).get("data", {})

            if mode in {"full", "regions_only"} and self.validator_config.enable_region_comparison:
                if expected_spec.expected_regions:
                    component_results["regions"] = self.compare_regions(
                        safe_context,
                        expected_regions=[region.to_dict() for region in expected_spec.expected_regions],
                        expected_image=expected_spec.expected_image,
                        actual_image=actual_state.actual_image,
                        actual_text=actual_state.actual_text,
                    ).get("data", {})

            if mode in {"full", "signals_only", "fast"} and self.validator_config.enable_signal_comparison:
                component_results["signals"] = self.validate_signals(
                    safe_context,
                    required_signals=expected_spec.required_signals,
                    forbidden_signals=expected_spec.forbidden_signals,
                    actual_signals=actual_state.actual_signals,
                ).get("data", {})

            if mode in {"full", "context_only", "fast"}:
                if expected_spec.expected_context:
                    component_results["context"] = self.compare_context(
                        safe_context,
                        expected_context=expected_spec.expected_context,
                        actual_context=actual_state.actual_context,
                    ).get("data", {})

            aggregate = self._aggregate_component_results(
                component_results,
                expected_spec.weights,
                expected_spec.thresholds.get(
                    "overall",
                    self.validator_config.overall_success_threshold,
                ),
            )

            elapsed_ms = round((time.time() - start_time) * 1000.0, 3)

            summary = self._build_summary(component_results, aggregate)

            data = {
                "validation_id": validation_id,
                "passed": aggregate["passed"],
                "overall_score": aggregate["overall_score"],
                "overall_threshold": aggregate["overall_threshold"],
                "mode": mode,
                "summary": summary,
                "component_results": component_results,
                "matched_required_text": component_results.get("text", {}).get("matched_required_text", []),
                "missing_required_text": component_results.get("text", {}).get("missing_required_text", []),
                "forbidden_text_found": component_results.get("text", {}).get("forbidden_text_found", []),
                "matched_required_elements": component_results.get("elements", {}).get("matched_expected_elements", []),
                "missing_required_elements": component_results.get("elements", {}).get("missing_expected_elements", []),
                "forbidden_elements_found": component_results.get("elements", {}).get("forbidden_elements_found", []),
                "expected_spec": expected_spec.to_dict(),
                "actual_state_summary": self._actual_state_summary(actual_state),
                "elapsed_ms": elapsed_ms,
                "verification_payload": None,
                "memory_payload": None,
            }

            data["verification_payload"] = self._prepare_verification_payload(
                "validate_screen",
                safe_context,
                data,
                success=aggregate["passed"],
                confidence=aggregate["overall_score"],
            )
            data["memory_payload"] = self._prepare_memory_payload("validate_screen", safe_context, data)

            if aggregate["passed"]:
                self._send_memory_payload(data["memory_payload"])

            self._log_audit_event(
                "validate_screen",
                safe_context,
                {
                    "validation_id": validation_id,
                    "passed": aggregate["passed"],
                    "overall_score": aggregate["overall_score"],
                    "mode": mode,
                },
                success=True,
            )

            self._emit_agent_event(
                "visual_validator.validation_completed",
                {
                    "user_id": safe_context.get("user_id"),
                    "workspace_id": safe_context.get("workspace_id"),
                    "validation_id": validation_id,
                    "passed": aggregate["passed"],
                    "overall_score": aggregate["overall_score"],
                    "mode": mode,
                },
            )

            return self._safe_result(
                True,
                "Visual screen validation completed.",
                data=data,
                metadata={
                    "validation_id": validation_id,
                    "passed": aggregate["passed"],
                    "overall_score": aggregate["overall_score"],
                    "elapsed_ms": elapsed_ms,
                },
            )

        except Exception as exc:
            logger.exception("Visual screen validation failed.")
            self._log_audit_event(
                "validate_screen",
                safe_context,
                {"validation_id": validation_id, "error": str(exc)},
                success=False,
            )
            return self._error_result(
                "Visual screen validation failed.",
                error=exc,
                metadata={"validation_id": validation_id},
            )

    def compare_screens(
        self,
        context: Mapping[str, Any],
        expected_screen: Mapping[str, Any],
        actual_screen: Mapping[str, Any],
        *,
        mode: str = "full",
    ) -> Dict[str, Any]:
        """
        Alias-friendly wrapper for validate_screen().
        """
        return self.validate_screen(
            context=context,
            expected=expected_screen,
            actual=actual_screen,
            mode=mode,
        )

    def compare_screen_data(
        self,
        context: Mapping[str, Any],
        expected_data: Mapping[str, Any],
        actual_data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Compare extracted visual screen data only.

        Useful when screenshot/image bytes are unavailable but OCR, UI elements,
        app context, and signals already exist.
        """
        return self.validate_screen(
            context=context,
            expected=expected_data,
            actual=actual_data,
            mode="full",
        )

    def compare_images(
        self,
        context: Mapping[str, Any],
        expected_image: Any,
        actual_image: Any,
        *,
        threshold: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Compare two screenshots/images.

        Input can be:
            - PIL Image
            - file path
            - bytes
            - base64 string
            - data:image/... base64 URL

        If Pillow is unavailable, returns a safe degraded result.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        threshold_value = _clamp(threshold if threshold is not None else self.validator_config.image_similarity_threshold)

        if expected_image is None or actual_image is None:
            return self._safe_result(
                True,
                "Image comparison skipped because one or both images are missing.",
                data={
                    "available": False,
                    "score": 0.0,
                    "passed": False,
                    "threshold": threshold_value,
                    "reason": "missing_image",
                },
            )

        if not PIL_AVAILABLE:
            expected_hash = self._safe_image_hash(expected_image)
            actual_hash = self._safe_image_hash(actual_image)
            exact_match = bool(expected_hash and actual_hash and expected_hash == actual_hash)
            score = 1.0 if exact_match else 0.0

            return self._safe_result(
                True,
                "Image comparison completed in hash-only mode because Pillow is unavailable.",
                data={
                    "available": True,
                    "method": "hash_only",
                    "score": score,
                    "passed": score >= threshold_value,
                    "threshold": threshold_value,
                    "expected_hash": expected_hash,
                    "actual_hash": actual_hash,
                    "pillow_available": False,
                },
            )

        try:
            expected_pil = self._load_image(expected_image)
            actual_pil = self._load_image(actual_image)

            if expected_pil is None or actual_pil is None:
                return self._safe_result(
                    True,
                    "Image comparison could not load one or both images.",
                    data={
                        "available": False,
                        "score": 0.0,
                        "passed": False,
                        "threshold": threshold_value,
                        "reason": "image_load_failed",
                    },
                )

            expected_norm, actual_norm = self._normalize_image_pair(expected_pil, actual_pil)

            pixel_similarity = self._pixel_similarity(expected_norm, actual_norm)
            histogram_similarity = self._histogram_similarity(expected_norm, actual_norm)
            edge_similarity = self._edge_similarity(expected_norm, actual_norm)

            score = _clamp(
                (pixel_similarity * 0.55)
                + (histogram_similarity * 0.30)
                + (edge_similarity * 0.15),
                0.0,
                1.0,
            )

            data = {
                "available": True,
                "method": "pixel_histogram_edge",
                "score": round(score, 4),
                "passed": score >= threshold_value,
                "threshold": threshold_value,
                "pixel_similarity": round(pixel_similarity, 4),
                "histogram_similarity": round(histogram_similarity, 4),
                "edge_similarity": round(edge_similarity, 4),
                "expected_size": expected_norm.size,
                "actual_size": actual_norm.size,
                "pillow_available": True,
            }

            return self._safe_result(
                True,
                "Image comparison completed.",
                data=data,
                metadata={"score": data["score"], "passed": data["passed"]},
            )

        except Exception as exc:
            logger.exception("Image comparison failed.")
            return self._error_result("Image comparison failed.", error=exc)

    def compare_text(
        self,
        context: Mapping[str, Any],
        *,
        expected_text: str = "",
        actual_text: str = "",
        required_text: Optional[List[str]] = None,
        forbidden_text: Optional[List[str]] = None,
        threshold: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Compare OCR/text signals.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        threshold_value = _clamp(threshold if threshold is not None else self.validator_config.text_similarity_threshold)

        expected_text = _normalize_str(expected_text, self.validator_config.max_text_length)
        actual_text = _normalize_str(actual_text, self.validator_config.max_text_length)

        text_similarity = _sequence_similarity(expected_text, actual_text) if expected_text else 1.0

        required_text = [
            _normalize_str(item, 1000)
            for item in (required_text or [])
            if _normalize_str(item)
        ]
        forbidden_text = [
            _normalize_str(item, 1000)
            for item in (forbidden_text or [])
            if _normalize_str(item)
        ]

        actual_lower = actual_text.lower()
        matched_required: List[str] = []
        missing_required: List[str] = []
        forbidden_found: List[str] = []

        for item in required_text:
            if item.lower() in actual_lower:
                matched_required.append(item)
            else:
                missing_required.append(item)

        for item in forbidden_text:
            if item.lower() in actual_lower:
                forbidden_found.append(item)

        required_score = (
            len(matched_required) / max(1, len(required_text))
            if required_text
            else 1.0
        )

        forbidden_score = 1.0 if not forbidden_found else 0.0

        score = _clamp((text_similarity * 0.45) + (required_score * 0.40) + (forbidden_score * 0.15))

        passed = (
            score >= threshold_value
            and not missing_required
            and not forbidden_found
        )

        data = {
            "score": round(score, 4),
            "passed": passed,
            "threshold": threshold_value,
            "text_similarity": round(text_similarity, 4),
            "required_score": round(required_score, 4),
            "forbidden_score": round(forbidden_score, 4),
            "matched_required_text": matched_required,
            "missing_required_text": missing_required,
            "forbidden_text_found": forbidden_found,
            "expected_text_length": len(expected_text),
            "actual_text_length": len(actual_text),
        }

        return self._safe_result(
            True,
            "Text comparison completed.",
            data=data,
            metadata={"score": data["score"], "passed": passed},
        )

    def compare_elements(
        self,
        context: Mapping[str, Any],
        *,
        expected_elements: List[Mapping[str, Any]],
        actual_elements: List[Mapping[str, Any]],
        forbidden_elements: Optional[List[Mapping[str, Any]]] = None,
        threshold: Optional[float] = None,
        screen_size: Optional[Tuple[int, int]] = None,
    ) -> Dict[str, Any]:
        """
        Compare expected UI elements against actual detected UI elements.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        threshold_value = _clamp(threshold if threshold is not None else self.validator_config.element_match_threshold)

        expected = [
            VisualElement.from_any(item, index=index)
            for index, item in enumerate(expected_elements or [])
        ][: self.validator_config.max_elements]

        actual = [
            VisualElement.from_any(item, index=index)
            for index, item in enumerate(actual_elements or [])
        ][: self.validator_config.max_elements]

        forbidden = [
            VisualElement.from_any(item, index=index)
            for index, item in enumerate(forbidden_elements or [])
        ][: self.validator_config.max_elements]

        matched_expected: List[Dict[str, Any]] = []
        missing_expected: List[Dict[str, Any]] = []
        used_actual_ids: set[str] = set()

        for expected_element in expected:
            best = self._find_best_element_match(
                expected_element,
                actual,
                used_actual_ids=used_actual_ids,
                screen_size=screen_size,
            )

            if best and best["score"] >= threshold_value:
                used_actual_ids.add(best["actual_element"]["element_id"])
                matched_expected.append(
                    {
                        "expected_element": expected_element.to_dict(),
                        "actual_element": best["actual_element"],
                        "score": best["score"],
                        "details": best["details"],
                    }
                )
            else:
                missing_expected.append(expected_element.to_dict())

        forbidden_found: List[Dict[str, Any]] = []
        for forbidden_element in forbidden:
            best = self._find_best_element_match(
                forbidden_element,
                actual,
                used_actual_ids=set(),
                screen_size=screen_size,
            )
            if best and best["score"] >= threshold_value:
                forbidden_found.append(
                    {
                        "forbidden_element": forbidden_element.to_dict(),
                        "actual_element": best["actual_element"],
                        "score": best["score"],
                    }
                )

        expected_score = (
            len(matched_expected) / max(1, len(expected))
            if expected
            else 1.0
        )
        forbidden_score = 1.0 if not forbidden_found else 0.0
        confidence_score = (
            statistics.mean([item["score"] for item in matched_expected])
            if matched_expected
            else (1.0 if not expected else 0.0)
        )

        score = _clamp((expected_score * 0.65) + (confidence_score * 0.25) + (forbidden_score * 0.10))
        passed = score >= threshold_value and not missing_expected and not forbidden_found

        data = {
            "score": round(score, 4),
            "passed": passed,
            "threshold": threshold_value,
            "expected_count": len(expected),
            "actual_count": len(actual),
            "forbidden_count": len(forbidden),
            "matched_expected_count": len(matched_expected),
            "missing_expected_count": len(missing_expected),
            "forbidden_found_count": len(forbidden_found),
            "matched_expected_elements": matched_expected,
            "missing_expected_elements": missing_expected,
            "forbidden_elements_found": forbidden_found,
            "expected_score": round(expected_score, 4),
            "confidence_score": round(confidence_score, 4),
            "forbidden_score": round(forbidden_score, 4),
        }

        return self._safe_result(
            True,
            "Element comparison completed.",
            data=data,
            metadata={"score": data["score"], "passed": passed},
        )

    def compare_layout(
        self,
        context: Mapping[str, Any],
        *,
        expected_elements: List[Mapping[str, Any]],
        actual_elements: List[Mapping[str, Any]],
        threshold: Optional[float] = None,
        screen_size: Optional[Tuple[int, int]] = None,
    ) -> Dict[str, Any]:
        """
        Compare element layout/bounds between expected and actual screens.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        threshold_value = _clamp(threshold if threshold is not None else self.validator_config.layout_match_threshold)

        expected = [
            VisualElement.from_any(item, index=index)
            for index, item in enumerate(expected_elements or [])
            if _bounds_to_tuple((item or {}).get("bounds") if isinstance(item, Mapping) else None) is not None
        ][: self.validator_config.max_elements]

        actual = [
            VisualElement.from_any(item, index=index)
            for index, item in enumerate(actual_elements or [])
            if _bounds_to_tuple((item or {}).get("bounds") if isinstance(item, Mapping) else None) is not None
        ][: self.validator_config.max_elements]

        layout_matches: List[Dict[str, Any]] = []
        missing_layout: List[Dict[str, Any]] = []

        used_actual_ids: set[str] = set()

        for expected_element in expected:
            best = self._find_best_element_match(
                expected_element,
                actual,
                used_actual_ids=used_actual_ids,
                screen_size=screen_size,
                layout_priority=True,
            )

            if best:
                used_actual_ids.add(best["actual_element"]["element_id"])
                layout_matches.append(
                    {
                        "expected_element": expected_element.to_dict(),
                        "actual_element": best["actual_element"],
                        "score": best["score"],
                        "layout_score": best["details"].get("layout_score", 0.0),
                        "bounds_iou": best["details"].get("bounds_iou", 0.0),
                    }
                )
            else:
                missing_layout.append(expected_element.to_dict())

        if layout_matches:
            score = statistics.mean([item["layout_score"] for item in layout_matches])
        else:
            score = 1.0 if not expected else 0.0

        coverage = len(layout_matches) / max(1, len(expected)) if expected else 1.0
        final_score = _clamp((score * 0.70) + (coverage * 0.30))
        passed = final_score >= threshold_value and not missing_layout

        data = {
            "score": round(final_score, 4),
            "passed": passed,
            "threshold": threshold_value,
            "layout_similarity": round(score, 4),
            "coverage": round(coverage, 4),
            "expected_layout_count": len(expected),
            "actual_layout_count": len(actual),
            "matched_layout_count": len(layout_matches),
            "missing_layout_count": len(missing_layout),
            "layout_matches": layout_matches,
            "missing_layout": missing_layout,
        }

        return self._safe_result(
            True,
            "Layout comparison completed.",
            data=data,
            metadata={"score": data["score"], "passed": passed},
        )

    def compare_regions(
        self,
        context: Mapping[str, Any],
        *,
        expected_regions: List[Mapping[str, Any]],
        expected_image: Any = None,
        actual_image: Any = None,
        actual_text: str = "",
    ) -> Dict[str, Any]:
        """
        Compare specific expected screen regions.

        Region image comparison requires Pillow. Region text checks still work
        without Pillow when expected_text is provided.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        regions = [
            VisualRegionSpec.from_any(item, index=index)
            for index, item in enumerate(expected_regions or [])
        ][: self.validator_config.max_regions]

        region_results: List[Dict[str, Any]] = []
        total_weight = sum(max(0.0, region.weight) for region in regions) or 1.0
        weighted_score = 0.0
        missing_required: List[Dict[str, Any]] = []

        expected_pil = None
        actual_pil = None

        if PIL_AVAILABLE and expected_image is not None and actual_image is not None:
            expected_pil = self._load_image(expected_image)
            actual_pil = self._load_image(actual_image)
            if expected_pil is not None and actual_pil is not None:
                expected_pil, actual_pil = self._normalize_image_pair(expected_pil, actual_pil)

        actual_text_lower = _normalize_lower(actual_text, self.validator_config.max_text_length)

        for region in regions:
            region_score_parts: List[float] = []
            notes: List[str] = []

            image_score = None
            if region.bounds and expected_pil is not None and actual_pil is not None:
                cropped_expected = self._crop_image(expected_pil, region.bounds)
                cropped_actual = self._crop_image(actual_pil, region.bounds)
                if cropped_expected is not None and cropped_actual is not None:
                    image_score = self._pixel_similarity(cropped_expected, cropped_actual)
                    region_score_parts.append(image_score)
                else:
                    notes.append("region_crop_failed")

            text_score = None
            if region.expected_text:
                if region.expected_text.lower() in actual_text_lower:
                    text_score = 1.0
                else:
                    text_score = _sequence_similarity(region.expected_text, actual_text)
                region_score_parts.append(text_score)

            if not region_score_parts:
                region_score = 0.0
                notes.append("no_comparable_region_data")
            else:
                region_score = statistics.mean(region_score_parts)

            passed = region_score >= region.threshold
            if region.required and not passed:
                missing_required.append(region.to_dict())

            weighted_score += region_score * max(0.0, region.weight)

            region_results.append(
                {
                    "region": region.to_dict(),
                    "score": round(region_score, 4),
                    "passed": passed,
                    "threshold": region.threshold,
                    "image_score": round(image_score, 4) if image_score is not None else None,
                    "text_score": round(text_score, 4) if text_score is not None else None,
                    "notes": notes,
                }
            )

        final_score = _clamp(weighted_score / total_weight)
        passed = final_score >= self.validator_config.region_similarity_threshold and not missing_required

        data = {
            "score": round(final_score, 4),
            "passed": passed,
            "threshold": self.validator_config.region_similarity_threshold,
            "region_count": len(regions),
            "region_results": region_results,
            "missing_required_regions": missing_required,
            "pillow_available": PIL_AVAILABLE,
        }

        return self._safe_result(
            True,
            "Region comparison completed.",
            data=data,
            metadata={"score": data["score"], "passed": passed},
        )

    def validate_signals(
        self,
        context: Mapping[str, Any],
        *,
        required_signals: Mapping[str, Any],
        forbidden_signals: Mapping[str, Any],
        actual_signals: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Validate required and forbidden structured visual signals.

        Example signals:
            required_signals={"screen_type": "checkout", "modal_open": True}
            forbidden_signals={"error_banner": True}
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        required = dict(required_signals or {})
        forbidden = dict(forbidden_signals or {})
        actual = dict(actual_signals or {})

        matched_required: Dict[str, Any] = {}
        missing_required: Dict[str, Any] = {}
        forbidden_found: Dict[str, Any] = {}

        for key, expected_value in required.items():
            actual_value = actual.get(key)
            if self._signal_value_matches(expected_value, actual_value):
                matched_required[key] = _redact_sensitive(actual_value)
            else:
                missing_required[key] = {
                    "expected": _redact_sensitive(expected_value),
                    "actual": _redact_sensitive(actual_value),
                }

        for key, forbidden_value in forbidden.items():
            actual_value = actual.get(key)
            if self._signal_value_matches(forbidden_value, actual_value):
                forbidden_found[key] = {
                    "forbidden": _redact_sensitive(forbidden_value),
                    "actual": _redact_sensitive(actual_value),
                }

        required_score = len(matched_required) / max(1, len(required)) if required else 1.0
        forbidden_score = 1.0 if not forbidden_found else 0.0
        score = _clamp((required_score * 0.75) + (forbidden_score * 0.25))
        passed = not missing_required and not forbidden_found

        data = {
            "score": round(score, 4),
            "passed": passed,
            "required_score": round(required_score, 4),
            "forbidden_score": round(forbidden_score, 4),
            "matched_required_signals": matched_required,
            "missing_required_signals": missing_required,
            "forbidden_signals_found": forbidden_found,
            "required_count": len(required),
            "forbidden_count": len(forbidden),
        }

        return self._safe_result(
            True,
            "Signal validation completed.",
            data=data,
            metadata={"score": data["score"], "passed": passed},
        )

    def compare_context(
        self,
        context: Mapping[str, Any],
        *,
        expected_context: Mapping[str, Any],
        actual_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Compare visual/app/page context.

        Example context:
            app_name, page_type, route, domain, window_title, device_type
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        expected = dict(expected_context or {})
        actual = dict(actual_context or {})

        matched: Dict[str, Any] = {}
        mismatched: Dict[str, Any] = {}

        for key, expected_value in expected.items():
            actual_value = actual.get(key)
            if self._signal_value_matches(expected_value, actual_value):
                matched[key] = _redact_sensitive(actual_value)
            else:
                mismatched[key] = {
                    "expected": _redact_sensitive(expected_value),
                    "actual": _redact_sensitive(actual_value),
                }

        score = len(matched) / max(1, len(expected)) if expected else 1.0
        passed = not mismatched

        data = {
            "score": round(score, 4),
            "passed": passed,
            "matched_context": matched,
            "mismatched_context": mismatched,
            "expected_context_count": len(expected),
            "actual_context_count": len(actual),
        }

        return self._safe_result(
            True,
            "Context comparison completed.",
            data=data,
            metadata={"score": data["score"], "passed": passed},
        )

    def build_expected_spec(
        self,
        context: Mapping[str, Any],
        *,
        name: str,
        expected_image: Any = None,
        expected_text: str = "",
        required_text: Optional[List[str]] = None,
        forbidden_text: Optional[List[str]] = None,
        expected_elements: Optional[List[Mapping[str, Any]]] = None,
        required_elements: Optional[List[Mapping[str, Any]]] = None,
        forbidden_elements: Optional[List[Mapping[str, Any]]] = None,
        expected_context: Optional[Mapping[str, Any]] = None,
        required_signals: Optional[Mapping[str, Any]] = None,
        forbidden_signals: Optional[Mapping[str, Any]] = None,
        thresholds: Optional[Mapping[str, float]] = None,
        weights: Optional[Mapping[str, float]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build a normalized expected visual validation spec.

        Useful for API/dashboard callers and Workflow Learner recipes.
        """
        valid, error_message, safe_context = self._validate_task_context(context)
        if not valid:
            return self._error_result(error_message or "Invalid context.")

        spec_payload = {
            "spec_id": _safe_uuid("vspec"),
            "name": name,
            "expected_image": expected_image,
            "expected_text": expected_text,
            "required_text": required_text or [],
            "forbidden_text": forbidden_text or [],
            "expected_elements": expected_elements or [],
            "required_elements": required_elements or [],
            "forbidden_elements": forbidden_elements or [],
            "expected_context": dict(expected_context or {}),
            "required_signals": dict(required_signals or {}),
            "forbidden_signals": dict(forbidden_signals or {}),
            "thresholds": dict(thresholds or {}),
            "weights": dict(weights or {}),
            "metadata": dict(metadata or {}),
        }

        spec = VisualValidationSpec.from_mapping(spec_payload)

        return self._safe_result(
            True,
            "Expected visual validation spec built successfully.",
            data={"spec": spec.to_dict()},
            metadata={"spec_id": spec.spec_id},
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Health check for Agent Loader, Dashboard, FastAPI, and tests.
        """
        return self._safe_result(
            True,
            "VisualValidator is healthy.",
            data={
                "agent": self.agent_name,
                "version": self.version,
                "pillow_available": PIL_AVAILABLE,
                "numpy_available": NUMPY_AVAILABLE,
                "supported_modes": sorted(SAFE_VALIDATION_MODES),
                "image_comparison_enabled": self.validator_config.enable_image_comparison,
                "text_comparison_enabled": self.validator_config.enable_text_comparison,
                "element_comparison_enabled": self.validator_config.enable_element_comparison,
                "layout_comparison_enabled": self.validator_config.enable_layout_comparison,
                "region_comparison_enabled": self.validator_config.enable_region_comparison,
                "signal_comparison_enabled": self.validator_config.enable_signal_comparison,
            },
        )

    # ------------------------------------------------------------------
    # Internal image helpers
    # ------------------------------------------------------------------

    def _load_image(self, image_input: Any) -> Any:
        if image_input is None or not PIL_AVAILABLE:
            return None

        if Image is not None and isinstance(image_input, Image.Image):  # type: ignore[attr-defined]
            return image_input.convert("RGB")

        try:
            if isinstance(image_input, (str, os.PathLike)):
                text = str(image_input)

                if text.startswith("data:image/") and "," in text:
                    _, b64_data = text.split(",", 1)
                    raw = base64.b64decode(b64_data)
                    return Image.open(io.BytesIO(raw)).convert("RGB")  # type: ignore[union-attr]

                possible_path = Path(text)
                if possible_path.exists() and possible_path.is_file():
                    return Image.open(possible_path).convert("RGB")  # type: ignore[union-attr]

                if self._looks_like_base64(text):
                    raw = base64.b64decode(text)
                    return Image.open(io.BytesIO(raw)).convert("RGB")  # type: ignore[union-attr]

                return None

            if isinstance(image_input, bytes):
                return Image.open(io.BytesIO(image_input)).convert("RGB")  # type: ignore[union-attr]

            if isinstance(image_input, bytearray):
                return Image.open(io.BytesIO(bytes(image_input))).convert("RGB")  # type: ignore[union-attr]

        except Exception:
            logger.debug("Failed to load image input.", exc_info=True)
            return None

        return None

    @staticmethod
    def _looks_like_base64(text: str) -> bool:
        if len(text) < 32:
            return False
        if not re.fullmatch(r"[A-Za-z0-9+/=\s]+", text):
            return False
        try:
            base64.b64decode(text, validate=True)
            return True
        except Exception:
            return False

    def _safe_image_hash(self, image_input: Any) -> Optional[str]:
        try:
            if isinstance(image_input, bytes):
                return _sha256_bytes(image_input)
            if isinstance(image_input, bytearray):
                return _sha256_bytes(bytes(image_input))
            if isinstance(image_input, (str, os.PathLike)):
                text = str(image_input)
                path = Path(text)
                if path.exists() and path.is_file():
                    return _sha256_bytes(path.read_bytes())
                return _sha256_text(text)
            if PIL_AVAILABLE and Image is not None and isinstance(image_input, Image.Image):  # type: ignore[attr-defined]
                buffer = io.BytesIO()
                image_input.save(buffer, format="PNG")
                return _sha256_bytes(buffer.getvalue())
        except Exception:
            return None
        return None

    def _normalize_image_pair(self, expected: Any, actual: Any) -> Tuple[Any, Any]:
        expected = expected.convert("RGB")
        actual = actual.convert("RGB")

        expected = self._resize_down(expected)
        actual = self._resize_down(actual)

        target_width = min(expected.size[0], actual.size[0])
        target_height = min(expected.size[1], actual.size[1])

        if target_width <= 0 or target_height <= 0:
            return expected, actual

        expected = expected.resize((target_width, target_height))
        actual = actual.resize((target_width, target_height))

        return expected, actual

    def _resize_down(self, image: Any) -> Any:
        max_dim = self.validator_config.max_image_dimension
        width, height = image.size
        largest = max(width, height)

        if largest <= max_dim:
            return image

        scale = max_dim / float(largest)
        new_size = (max(1, int(width * scale)), max(1, int(height * scale)))
        return image.resize(new_size)

    def _pixel_similarity(self, expected: Any, actual: Any) -> float:
        if not PIL_AVAILABLE or ImageChops is None or ImageStat is None:
            return 0.0

        try:
            diff = ImageChops.difference(expected, actual)
            stat = ImageStat.Stat(diff)
            rms = math.sqrt(sum(value ** 2 for value in stat.rms) / len(stat.rms))
            return _clamp(1.0 - (rms / 255.0))
        except Exception:
            logger.debug("Pixel similarity failed.", exc_info=True)
            return 0.0

    def _histogram_similarity(self, expected: Any, actual: Any) -> float:
        try:
            hist_a = expected.histogram()
            hist_b = actual.histogram()
            if not hist_a or not hist_b or len(hist_a) != len(hist_b):
                return 0.0

            distance = sum(abs(a - b) for a, b in zip(hist_a, hist_b))
            total = max(sum(hist_a), sum(hist_b), 1)
            normalized = distance / float(total * 2)
            return _clamp(1.0 - normalized)
        except Exception:
            logger.debug("Histogram similarity failed.", exc_info=True)
            return 0.0

    def _edge_similarity(self, expected: Any, actual: Any) -> float:
        if not PIL_AVAILABLE or ImageFilterUnavailable():
            return self._pixel_similarity(expected, actual)

        try:
            from PIL import ImageFilter  # type: ignore

            edge_a = expected.convert("L").filter(ImageFilter.FIND_EDGES)
            edge_b = actual.convert("L").filter(ImageFilter.FIND_EDGES)
            return self._pixel_similarity(edge_a.convert("RGB"), edge_b.convert("RGB"))
        except Exception:
            logger.debug("Edge similarity failed.", exc_info=True)
            return self._pixel_similarity(expected, actual)

    def _crop_image(self, image: Any, bounds: Tuple[float, float, float, float]) -> Any:
        try:
            x, y, width, height = bounds
            left = max(0, int(x))
            top = max(0, int(y))
            right = min(image.size[0], int(x + width))
            bottom = min(image.size[1], int(y + height))

            if right <= left or bottom <= top:
                return None

            return image.crop((left, top, right, bottom))
        except Exception:
            logger.debug("Image crop failed.", exc_info=True)
            return None

    # ------------------------------------------------------------------
    # Internal element helpers
    # ------------------------------------------------------------------

    def _find_best_element_match(
        self,
        expected: VisualElement,
        actual_elements: List[VisualElement],
        *,
        used_actual_ids: set[str],
        screen_size: Optional[Tuple[int, int]] = None,
        layout_priority: bool = False,
    ) -> Optional[Dict[str, Any]]:
        best: Optional[Dict[str, Any]] = None

        for actual in actual_elements:
            if actual.element_id in used_actual_ids:
                continue

            score, details = self._score_element_match(
                expected,
                actual,
                screen_size=screen_size,
                layout_priority=layout_priority,
            )

            candidate = {
                "score": round(score, 4),
                "actual_element": actual.to_dict(),
                "details": details,
            }

            if best is None or candidate["score"] > best["score"]:
                best = candidate

        return best

    def _score_element_match(
        self,
        expected: VisualElement,
        actual: VisualElement,
        *,
        screen_size: Optional[Tuple[int, int]] = None,
        layout_priority: bool = False,
    ) -> Tuple[float, Dict[str, Any]]:
        type_score = 1.0 if expected.element_type and expected.element_type == actual.element_type else 0.0
        if expected.element_type in {"unknown", ""} or actual.element_type in {"unknown", ""}:
            type_score = 0.5

        role_score = 1.0 if expected.role and expected.role == actual.role else 0.0
        if not expected.role:
            role_score = 0.5

        expected_text_key = " ".join([expected.text, expected.label]).strip()
        actual_text_key = " ".join([actual.text, actual.label]).strip()
        text_score = _sequence_similarity(expected_text_key, actual_text_key) if expected_text_key else 0.5

        bounds_iou = 0.0
        distance = 0.0
        layout_score = 0.5

        if expected.bounds and actual.bounds:
            bounds_iou = _bounds_iou(expected.bounds, actual.bounds)
            distance = _distance_score(_bounds_center(expected.bounds), _bounds_center(actual.bounds), screen_size)
            layout_score = _clamp((bounds_iou * 0.7) + (distance * 0.3))

        visibility_score = 1.0 if expected.visible == actual.visible else 0.0
        enabled_score = 0.5
        if expected.enabled is not None and actual.enabled is not None:
            enabled_score = 1.0 if expected.enabled == actual.enabled else 0.0

        if layout_priority:
            score = _clamp(
                (layout_score * 0.55)
                + (text_score * 0.25)
                + (type_score * 0.10)
                + (role_score * 0.05)
                + (visibility_score * 0.05)
            )
        else:
            score = _clamp(
                (text_score * 0.35)
                + (type_score * 0.20)
                + (role_score * 0.15)
                + (layout_score * 0.20)
                + (visibility_score * 0.05)
                + (enabled_score * 0.05)
            )

        details = {
            "type_score": round(type_score, 4),
            "role_score": round(role_score, 4),
            "text_score": round(text_score, 4),
            "layout_score": round(layout_score, 4),
            "bounds_iou": round(bounds_iou, 4),
            "distance_score": round(distance, 4),
            "visibility_score": round(visibility_score, 4),
            "enabled_score": round(enabled_score, 4),
        }

        return score, details

    # ------------------------------------------------------------------
    # Internal aggregation helpers
    # ------------------------------------------------------------------

    def _aggregate_component_results(
        self,
        component_results: Mapping[str, Mapping[str, Any]],
        weights: Mapping[str, float],
        overall_threshold: float,
    ) -> Dict[str, Any]:
        default_weights = {
            "image": 0.25,
            "text": 0.20,
            "elements": 0.20,
            "layout": 0.15,
            "regions": 0.10,
            "signals": 0.05,
            "context": 0.05,
        }

        if weights:
            for key, value in weights.items():
                default_weights[str(key)] = max(0.0, _safe_float(value, 0.0))

        weighted_sum = 0.0
        total_weight = 0.0
        failed_required_components: List[str] = []

        for name, result in component_results.items():
            if not isinstance(result, Mapping):
                continue

            score = _clamp(result.get("score", 0.0))
            weight = max(0.0, default_weights.get(name, 0.1))

            weighted_sum += score * weight
            total_weight += weight

            if result.get("passed") is False:
                failed_required_components.append(name)

        overall_score = _clamp(weighted_sum / total_weight if total_weight else 0.0)
        overall_threshold = _clamp(overall_threshold)

        passed = overall_score >= overall_threshold and not self._has_hard_failures(component_results)

        return {
            "overall_score": round(overall_score, 4),
            "overall_threshold": overall_threshold,
            "passed": passed,
            "failed_components": failed_required_components,
            "component_count": len(component_results),
        }

    def _has_hard_failures(self, component_results: Mapping[str, Mapping[str, Any]]) -> bool:
        text_result = component_results.get("text", {})
        if text_result.get("missing_required_text") or text_result.get("forbidden_text_found"):
            return True

        element_result = component_results.get("elements", {})
        if element_result.get("missing_expected_elements") or element_result.get("forbidden_elements_found"):
            return True

        signal_result = component_results.get("signals", {})
        if signal_result.get("missing_required_signals") or signal_result.get("forbidden_signals_found"):
            return True

        region_result = component_results.get("regions", {})
        if region_result.get("missing_required_regions"):
            return True

        context_result = component_results.get("context", {})
        if context_result.get("mismatched_context"):
            return True

        return False

    def _build_summary(
        self,
        component_results: Mapping[str, Mapping[str, Any]],
        aggregate: Mapping[str, Any],
    ) -> str:
        if aggregate.get("passed"):
            return "Actual screen matches the expected visual state."

        reasons: List[str] = []

        text_result = component_results.get("text", {})
        if text_result.get("missing_required_text"):
            reasons.append(f"missing required text: {len(text_result.get('missing_required_text', []))}")
        if text_result.get("forbidden_text_found"):
            reasons.append(f"forbidden text found: {len(text_result.get('forbidden_text_found', []))}")

        element_result = component_results.get("elements", {})
        if element_result.get("missing_expected_elements"):
            reasons.append(f"missing expected elements: {len(element_result.get('missing_expected_elements', []))}")
        if element_result.get("forbidden_elements_found"):
            reasons.append(f"forbidden elements found: {len(element_result.get('forbidden_elements_found', []))}")

        signal_result = component_results.get("signals", {})
        if signal_result.get("missing_required_signals"):
            reasons.append(f"missing required signals: {len(signal_result.get('missing_required_signals', {}))}")
        if signal_result.get("forbidden_signals_found"):
            reasons.append(f"forbidden signals found: {len(signal_result.get('forbidden_signals_found', {}))}")

        context_result = component_results.get("context", {})
        if context_result.get("mismatched_context"):
            reasons.append(f"context mismatch: {len(context_result.get('mismatched_context', {}))}")

        if not reasons:
            reasons.append(
                f"overall score {aggregate.get('overall_score')} is below threshold {aggregate.get('overall_threshold')}"
            )

        return "Actual screen does not fully match expected visual state: " + "; ".join(reasons) + "."

    def _actual_state_summary(self, actual_state: ActualVisualState) -> Dict[str, Any]:
        return {
            "state_id": actual_state.state_id,
            "actual_image_present": actual_state.actual_image is not None,
            "actual_text_length": len(actual_state.actual_text or ""),
            "actual_element_count": len(actual_state.actual_elements),
            "actual_context_keys": sorted(list(actual_state.actual_context.keys())),
            "actual_signal_keys": sorted(list(actual_state.actual_signals.keys())),
            "screen_size": actual_state.screen_size,
        }

    def _signal_value_matches(self, expected_value: Any, actual_value: Any) -> bool:
        if isinstance(expected_value, Mapping):
            operator = _normalize_lower(expected_value.get("operator") or "equals", 80)
            value = expected_value.get("value")
            return self._compare_signal_values(value, actual_value, operator)

        return self._compare_signal_values(expected_value, actual_value, "equals")

    def _compare_signal_values(self, expected: Any, actual: Any, operator: str) -> bool:
        operator = _normalize_lower(operator, 80)

        if operator in {"exists", "present"}:
            return actual is not None and actual != "" and actual != []

        if operator in {"missing", "absent", "not_exists"}:
            return actual is None or actual == "" or actual == []

        expected_text = _normalize_lower(expected, 4000)
        actual_text = _normalize_lower(actual, 4000)

        if operator in {"equals", "eq", "is"}:
            return expected_text == actual_text

        if operator in {"not_equals", "neq", "not"}:
            return expected_text != actual_text

        if operator in {"contains", "includes"}:
            return expected_text in actual_text

        if operator in {"not_contains", "excludes"}:
            return expected_text not in actual_text

        if operator in {"regex", "matches_regex"}:
            try:
                return re.search(str(expected), str(actual), flags=re.IGNORECASE) is not None
            except re.error:
                return False

        if operator in {"gt", "greater_than"}:
            return _safe_float(actual, float("-inf")) > _safe_float(expected, float("inf"))

        if operator in {"gte", "greater_or_equal"}:
            return _safe_float(actual, float("-inf")) >= _safe_float(expected, float("inf"))

        if operator in {"lt", "less_than"}:
            return _safe_float(actual, float("inf")) < _safe_float(expected, float("-inf"))

        if operator in {"lte", "less_or_equal"}:
            return _safe_float(actual, float("inf")) <= _safe_float(expected, float("-inf"))

        if operator in {"one_of", "in"}:
            return actual in _as_list(expected)

        return expected_text == actual_text

    def _send_memory_payload(self, memory_payload: Mapping[str, Any]) -> None:
        if not self.validator_config.enable_memory_payloads:
            return

        agent = self.memory_agent
        if agent is None and MemoryAgent is not None:
            try:
                agent = MemoryAgent()
            except Exception:
                agent = None

        if agent is None:
            return

        try:
            if hasattr(agent, "store_memory"):
                agent.store_memory(dict(memory_payload))
            elif hasattr(agent, "remember"):
                agent.remember(dict(memory_payload))
            elif hasattr(agent, "save"):
                agent.save(dict(memory_payload))
        except Exception:
            logger.debug("Failed to send visual validation memory payload.", exc_info=True)


def ImageFilterUnavailable() -> bool:
    """
    Small helper to keep edge comparison import-safe.
    """
    try:
        from PIL import ImageFilter  # type: ignore  # noqa: F401
        return False
    except Exception:
        return True


# ---------------------------------------------------------------------------
# Registry / factory helpers
# ---------------------------------------------------------------------------

def create_visual_validator(
    config: Optional[Mapping[str, Any]] = None,
    **kwargs: Any,
) -> VisualValidator:
    """
    Factory used by Agent Loader / Agent Registry.
    """
    return VisualValidator(config=config, **kwargs)


def get_agent_metadata() -> Dict[str, Any]:
    """
    Agent Registry metadata.
    """
    return {
        "agent_name": VisualValidator.agent_name,
        "registry_name": VisualValidator.registry_name,
        "agent_type": VisualValidator.agent_type,
        "version": VisualValidator.version,
        "class_name": "VisualValidator",
        "module": "agents.visual_agent.visual_validator",
        "purpose": "Compares expected vs actual screens for visual task validation.",
        "safe_to_import": True,
        "requires_user_workspace_context": True,
        "supports_security_hooks": True,
        "supports_memory_payloads": True,
        "supports_verification_payloads": True,
        "pillow_available": PIL_AVAILABLE,
        "numpy_available": NUMPY_AVAILABLE,
        "public_methods": [
            "validate_screen",
            "compare_screens",
            "compare_screen_data",
            "compare_images",
            "compare_text",
            "compare_elements",
            "compare_layout",
            "compare_regions",
            "validate_signals",
            "compare_context",
            "build_expected_spec",
            "health_check",
        ],
    }


__all__ = [
    "VisualValidator",
    "VisualValidatorConfig",
    "VisualElement",
    "VisualRegionSpec",
    "VisualValidationSpec",
    "ActualVisualState",
    "create_visual_validator",
    "get_agent_metadata",
]


if __name__ == "__main__":
    # Safe smoke test only. No system/browser/device actions.
    validator = VisualValidator(config={"enable_audit_log": False, "enable_agent_events": False})

    demo_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "project_id": "demo_project",
        "task_id": "demo_task",
    }

    expected = {
        "name": "Dashboard success screen",
        "expected_text": "Dashboard Welcome",
        "required_text": ["Dashboard", "Welcome"],
        "forbidden_text": ["Error", "Access denied"],
        "expected_elements": [
            {
                "element_id": "btn_start",
                "element_type": "button",
                "text": "Start",
                "bounds": {"x": 100, "y": 200, "width": 120, "height": 40},
                "visible": True,
            }
        ],
        "expected_context": {
            "page_type": "dashboard",
        },
        "required_signals": {
            "screen_loaded": True,
        },
        "thresholds": {
            "overall": 0.75,
            "text": 0.70,
            "elements": 0.70,
        },
    }

    actual = {
        "actual_text": "Welcome to your Dashboard. Start here.",
        "actual_elements": [
            {
                "element_id": "actual_start_button",
                "element_type": "button",
                "text": "Start",
                "bounds": {"x": 102, "y": 202, "width": 118, "height": 39},
                "visible": True,
            }
        ],
        "actual_context": {
            "page_type": "dashboard",
        },
        "actual_signals": {
            "screen_loaded": True,
        },
        "screen_size": [1366, 768],
    }

    result = validator.validate_screen(demo_context, expected, actual, mode="full")
    print(json.dumps(result, indent=2, default=str))