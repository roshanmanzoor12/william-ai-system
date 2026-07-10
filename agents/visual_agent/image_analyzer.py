"""
agents/visual_agent/image_analyzer.py

William / Jarvis Multi-Agent AI SaaS System
Visual Agent Helper: ImageAnalyzer

Purpose:
    Analyzes images, objects, layouts, design, lighting, colors, composition,
    and creative assets in a safe, import-friendly, SaaS-isolated way.

Important:
    This module is intentionally read-only. It does not edit, delete, move,
    upload, publish, or generate images. It only inspects image files or image
    metadata and returns structured analysis results.

Architecture Compatibility:
    - Visual Agent compatible
    - Master Agent routing compatible
    - Agent Registry / Agent Loader compatible
    - Security Agent approval hook compatible
    - Verification Agent payload compatible
    - Memory Agent payload compatible
    - Dashboard / FastAPI structured response compatible
    - Safe to import even when future William files are not created yet

Supported analysis:
    - Image metadata
    - Dimensions and orientation
    - Format and mode
    - File size
    - Color profile basics
    - Dominant colors
    - Brightness / contrast / saturation estimates
    - Lighting quality estimate
    - Layout / composition heuristics
    - Creative asset review
    - Object/region heuristic detection
    - Transparency check
    - Blur/sharpness estimate
    - Screenshot/design/image type classification
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import math
import mimetypes
import os
import statistics
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional third-party imports
# ---------------------------------------------------------------------------

try:
    from PIL import Image, ImageChops, ImageEnhance, ImageFilter, ImageOps, ImageStat
    PIL_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency fallback
    Image = None  # type: ignore
    ImageChops = None  # type: ignore
    ImageEnhance = None  # type: ignore
    ImageFilter = None  # type: ignore
    ImageOps = None  # type: ignore
    ImageStat = None  # type: ignore
    PIL_AVAILABLE = False


try:
    import numpy as np
    NUMPY_AVAILABLE = True
except Exception:  # pragma: no cover - optional dependency fallback
    np = None  # type: ignore
    NUMPY_AVAILABLE = False


# ---------------------------------------------------------------------------
# Optional William / Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe while the complete William/Jarvis
        architecture is still being generated.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None


try:
    from agents.visual_agent.config import VisualAgentConfig  # type: ignore
except Exception:  # pragma: no cover
    class VisualAgentConfig:  # type: ignore
        """
        Fallback Visual Agent config.

        The future agents/visual_agent/config.py can override these defaults.
        """

        MAX_IMAGE_FILE_SIZE_BYTES = 50 * 1024 * 1024
        MAX_ANALYSIS_DIMENSION = 1400
        DOMINANT_COLOR_COUNT = 8
        OBJECT_GRID_ROWS = 3
        OBJECT_GRID_COLUMNS = 3
        SENSITIVE_PATH_KEYWORDS = [
            ".ssh",
            ".env",
            "secret",
            "secrets",
            "credential",
            "credentials",
            "token",
            "private",
            "passport",
            "license",
            "id_card",
            "bank",
            "medical",
        ]
        ALLOW_SENSITIVE_METADATA_READ = True
        ALLOW_SENSITIVE_PIXEL_ANALYSIS = False
        DEFAULT_CONFIDENCE = 0.82


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

PathLike = Union[str, Path]
RGBTuple = Tuple[int, int, int]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ImageMetadata:
    """
    Basic image/file metadata safe for dashboard, audit, verification,
    and memory payloads.
    """

    path: Optional[str]
    exists: bool
    file_name: Optional[str] = None
    file_suffix: Optional[str] = None
    mime_type: Optional[str] = None
    file_size_bytes: Optional[int] = None
    file_hash_sha256: Optional[str] = None
    format: Optional[str] = None
    mode: Optional[str] = None
    width: Optional[int] = None
    height: Optional[int] = None
    aspect_ratio: Optional[float] = None
    orientation: Optional[str] = None
    has_alpha: Optional[bool] = None
    animated: Optional[bool] = None
    frame_count: Optional[int] = None
    created_at: Optional[str] = None
    modified_at: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ColorAnalysis:
    """
    Color and tone summary for creative/design review.
    """

    dominant_colors: List[Dict[str, Any]] = field(default_factory=list)
    average_color_hex: Optional[str] = None
    average_rgb: Optional[RGBTuple] = None
    brightness_score: Optional[float] = None
    contrast_score: Optional[float] = None
    saturation_score: Optional[float] = None
    warmth_score: Optional[float] = None
    colorfulness_score: Optional[float] = None
    palette_type: Optional[str] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class LightingAnalysis:
    """
    Lighting quality estimate.
    """

    lighting_quality: Optional[str] = None
    exposure_estimate: Optional[str] = None
    shadow_level: Optional[str] = None
    highlight_level: Optional[str] = None
    brightness_score: Optional[float] = None
    contrast_score: Optional[float] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class LayoutAnalysis:
    """
    Layout/composition/design structure analysis.
    """

    orientation: Optional[str] = None
    aspect_ratio_label: Optional[str] = None
    composition_balance: Optional[str] = None
    center_focus_score: Optional[float] = None
    edge_density_score: Optional[float] = None
    empty_space_estimate: Optional[float] = None
    symmetry_estimate: Optional[float] = None
    rule_of_thirds_score: Optional[float] = None
    likely_asset_type: Optional[str] = None
    notes: List[str] = field(default_factory=list)


@dataclass
class RegionObservation:
    """
    Lightweight region/object-like observation.

    This is heuristic and does not claim exact object detection. It identifies
    visually busy or prominent regions that future ElementDetector/ObjectDetector
    modules can refine.
    """

    region_id: str
    grid_position: str
    bounds: Dict[str, int]
    prominence_score: float
    brightness_score: float
    contrast_score: float
    colorfulness_score: float
    possible_content_type: str
    confidence: float


@dataclass
class CreativeAssetAnalysis:
    """
    Design/creative asset quality summary.
    """

    asset_type: Optional[str] = None
    quality_score: float = 0.0
    readability_estimate: Optional[str] = None
    brand_safety_notes: List[str] = field(default_factory=list)
    design_notes: List[str] = field(default_factory=list)
    improvement_suggestions: List[str] = field(default_factory=list)
    strengths: List[str] = field(default_factory=list)


@dataclass
class ImageAnalysisResult:
    """
    Complete image analysis response body.
    """

    metadata: Dict[str, Any]
    color_analysis: Dict[str, Any]
    lighting_analysis: Dict[str, Any]
    layout_analysis: Dict[str, Any]
    region_observations: List[Dict[str, Any]]
    creative_asset_analysis: Dict[str, Any]
    confidence: float
    warnings: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class ImageAnalyzer(BaseAgent):
    """
    Production-ready image analyzer for William / Jarvis Visual Agent.

    Responsibilities:
        - Analyze image metadata, layout, design, lighting, and creative quality.
        - Provide structured dict/JSON style results.
        - Protect SaaS user/workspace isolation.
        - Avoid destructive or sensitive actions.
        - Prepare Verification Agent and Memory Agent payloads.
        - Remain import-safe before other architecture files exist.

    Master Agent:
        Can route image-analysis tasks here after Browser Agent, Creator Agent,
        Workflow Agent, Hologram Agent, or Visual Agent receives a visual asset.

    Security Agent:
        Sensitive paths or pixel-level analysis can trigger security approval.

    Memory Agent:
        Useful image summaries can be stored as compact metadata, not raw pixels.

    Verification Agent:
        Completed image analysis prepares a verification payload showing evidence,
        confidence, warnings, and analysis details.

    Dashboard/API:
        Public methods return structured JSON-ready dictionaries.
    """

    AGENT_NAME = "ImageAnalyzer"
    AGENT_TYPE = "visual_helper"
    AGENT_VERSION = "1.0.0"

    SUPPORTED_IMAGE_SUFFIXES = {
        ".jpg",
        ".jpeg",
        ".png",
        ".webp",
        ".bmp",
        ".gif",
        ".tiff",
        ".tif",
    }

    def __init__(
        self,
        config: Optional[Any] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=self.AGENT_NAME,
            agent_id="visual_image_analyzer",
            **kwargs,
        )
        self.config = config or VisualAgentConfig()
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.audit_logger = audit_logger
        self.event_bus = event_bus

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Every user-specific visual analysis must include user_id and workspace_id
        to avoid mixing files, memory, logs, analytics, or task history between
        tenants.
        """

        if not user_id or not isinstance(user_id, str) or not user_id.strip():
            return self._error_result(
                message="Missing or invalid user_id.",
                error="VALIDATION_ERROR",
                metadata={
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                    "extra": extra or {},
                },
            )

        if not workspace_id or not isinstance(workspace_id, str) or not workspace_id.strip():
            return self._error_result(
                message="Missing or invalid workspace_id.",
                error="VALIDATION_ERROR",
                metadata={
                    "user_id": user_id,
                    "task_id": task_id,
                    "extra": extra or {},
                },
            )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={
                "user_id": user_id.strip(),
                "workspace_id": workspace_id.strip(),
                "task_id": task_id,
                "extra": extra or {},
            },
            metadata={"validation": "passed"},
        )

    def _requires_security_check(
        self,
        image_path: Optional[PathLike] = None,
        operation: str = "image_metadata_read",
        pixel_analysis: bool = False,
        **kwargs: Any,
    ) -> bool:
        """
        Determine whether an image operation requires Security Agent approval.

        Metadata reads are usually safe. Pixel-level analysis of sensitive paths
        is stricter because screenshots/images can contain credentials, faces,
        private documents, medical records, or account information.
        """

        operation_lower = (operation or "").lower().strip()

        sensitive_operations = {
            "pixel_analysis",
            "creative_asset_analysis",
            "ocr_ready_analysis",
            "privacy_sensitive_image_analysis",
            "base64_image_analysis",
            "full_image_analysis",
        }

        if operation_lower in sensitive_operations:
            return True

        if pixel_analysis:
            return True

        if image_path is None:
            return False

        normalized = str(image_path).replace("\\", "/").lower()
        keywords = getattr(self.config, "SENSITIVE_PATH_KEYWORDS", []) or []

        return any(str(keyword).lower() in normalized for keyword in keywords)

    def _request_security_approval(
        self,
        user_id: str,
        workspace_id: str,
        operation: str,
        reason: str,
        image_path: Optional[PathLike] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval if available.

        Fallback policy:
            - Sensitive metadata read can be allowed by config.
            - Sensitive pixel analysis is blocked by default.
        """

        request_payload = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "agent": self.AGENT_NAME,
            "operation": operation,
            "image_path": str(image_path) if image_path is not None else None,
            "reason": reason,
            "metadata": metadata or {},
            "timestamp": self._utc_now(),
        }

        if self.security_agent is not None:
            try:
                approval_method = getattr(self.security_agent, "approve_action", None)
                if callable(approval_method):
                    approval = approval_method(request_payload)
                    if isinstance(approval, dict):
                        return approval
            except Exception as exc:
                logger.warning("Security approval request failed: %s", exc)

        operation_lower = operation.lower().strip()

        if "pixel" in operation_lower or "full_image" in operation_lower:
            allowed = bool(getattr(self.config, "ALLOW_SENSITIVE_PIXEL_ANALYSIS", False))
            return {
                "approved": allowed,
                "reason": (
                    "Fallback policy allows sensitive pixel analysis."
                    if allowed
                    else "Fallback policy blocks sensitive pixel analysis."
                ),
                "source": "fallback_security_policy",
                "request": request_payload,
            }

        allowed = bool(getattr(self.config, "ALLOW_SENSITIVE_METADATA_READ", True))
        return {
            "approved": allowed,
            "reason": (
                "Fallback policy allows sensitive metadata read."
                if allowed
                else "Fallback policy blocks sensitive metadata read."
            ),
            "source": "fallback_security_policy",
            "request": request_payload,
        }

    def _prepare_verification_payload(
        self,
        user_id: str,
        workspace_id: str,
        verification_type: str,
        status: str,
        confidence: float,
        evidence: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        target_path: Optional[PathLike] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.

        This can be attached to task completion reports or routed into the
        Verification Agent after Visual Agent finishes analysis.
        """

        return {
            "agent": self.AGENT_NAME,
            "agent_type": self.AGENT_TYPE,
            "agent_version": self.AGENT_VERSION,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "verification_type": verification_type,
            "target_path": str(target_path) if target_path is not None else None,
            "status": status,
            "confidence": self._clamp_confidence(confidence),
            "evidence": evidence or {},
            "timestamp": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        user_id: str,
        workspace_id: str,
        summary: str,
        data: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This stores compact visual context only. It should not store raw image
        bytes, private screenshots, or sensitive content.
        """

        return {
            "memory_type": "visual_image_analysis",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "summary": summary,
            "data": data or {},
            "source_agent": self.AGENT_NAME,
            "created_at": self._utc_now(),
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit agent event for dashboard, analytics, task history, and registry.
        """

        event = {
            "event_name": event_name,
            "agent": self.AGENT_NAME,
            "timestamp": self._utc_now(),
            "payload": payload,
        }

        try:
            if self.event_bus is not None:
                publish = getattr(self.event_bus, "publish", None)
                if callable(publish):
                    publish(event)
                    return

            emit = getattr(self, "emit_event", None)
            if callable(emit):
                emit(event_name, payload)
        except Exception as exc:
            logger.debug("Agent event emit failed: %s", exc)

    def _log_audit_event(
        self,
        user_id: str,
        workspace_id: str,
        action: str,
        outcome: str,
        task_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        A real audit logger can be injected later. Fallback logs to the module
        logger only.
        """

        payload = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "agent": self.AGENT_NAME,
            "action": action,
            "outcome": outcome,
            "details": details or {},
            "timestamp": self._utc_now(),
        }

        try:
            if self.audit_logger is not None:
                log_method = getattr(self.audit_logger, "log", None)
                if callable(log_method):
                    log_method(payload)
                    return

            logger.info("AUDIT_EVENT %s", json.dumps(payload, default=str))
        except Exception as exc:
            logger.debug("Audit logging failed: %s", exc)

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Any] = None,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured result wrapper.
        """

        return {
            "success": bool(success),
            "message": message,
            "data": data,
            "error": error,
            "metadata": {
                "agent": self.AGENT_NAME,
                "agent_type": self.AGENT_TYPE,
                "agent_version": self.AGENT_VERSION,
                "timestamp": self._utc_now(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Union[str, Exception],
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured error result wrapper.
        """

        return self._safe_result(
            success=False,
            message=message,
            data=data,
            error=str(error),
            metadata=metadata or {},
        )

    # -----------------------------------------------------------------------
    # Public methods
    # -----------------------------------------------------------------------

    def analyze_image(
        self,
        image_path: PathLike,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        analysis_depth: str = "standard",
        include_regions: bool = True,
        include_hash: bool = True,
        max_regions: int = 9,
    ) -> Dict[str, Any]:
        """
        Analyze an image file.

        Args:
            image_path: Local image file path.
            user_id: SaaS user id.
            workspace_id: SaaS workspace id.
            task_id: Optional task id.
            analysis_depth:
                - "metadata": file/image metadata only
                - "basic": metadata + basic visual summary
                - "standard": metadata + colors + lighting + layout + creative
                - "deep": standard + more region observations
            include_regions: Include heuristic region/object-like observations.
            include_hash: Include file sha256 hash in metadata.
            max_regions: Maximum region observations to return.

        Returns:
            Structured dict result.
        """

        context = self._validate_task_context(user_id, workspace_id, task_id)
        if not context["success"]:
            return context

        normalized_path = self._normalize_path(image_path)
        depth = (analysis_depth or "standard").lower().strip()

        if depth not in {"metadata", "basic", "standard", "deep"}:
            return self._error_result(
                message="Invalid analysis_depth. Use metadata, basic, standard, or deep.",
                error="VALIDATION_ERROR",
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                    "analysis_depth": analysis_depth,
                },
            )

        pixel_analysis = depth in {"basic", "standard", "deep"} or include_regions

        if self._requires_security_check(
            image_path=normalized_path,
            operation="full_image_analysis" if pixel_analysis else "image_metadata_read",
            pixel_analysis=pixel_analysis,
        ):
            approval = self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                image_path=normalized_path,
                operation="full_image_analysis" if pixel_analysis else "image_metadata_read",
                reason="Analyze image metadata and visual properties.",
                metadata={
                    "analysis_depth": depth,
                    "include_regions": include_regions,
                    "include_hash": include_hash,
                },
            )
            if not bool(approval.get("approved", False)):
                self._log_audit_event(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=task_id,
                    action="analyze_image",
                    outcome="blocked_by_security",
                    details={
                        "image_path": str(normalized_path),
                        "approval": approval,
                    },
                )
                return self._error_result(
                    message="Security approval denied for image analysis.",
                    error="SECURITY_APPROVAL_DENIED",
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "task_id": task_id,
                        "image_path": str(normalized_path),
                        "approval": approval,
                    },
                )

        started = time.time()

        try:
            metadata = self.extract_metadata(
                image_path=normalized_path,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                include_hash=include_hash,
                internal_call=True,
            )
            if not metadata["success"]:
                return metadata

            metadata_dict = metadata["data"]["metadata"]
            warnings: List[str] = []

            if not PIL_AVAILABLE:
                warnings.append(
                    "Pillow is not installed. Only file metadata analysis is available."
                )

            if depth == "metadata" or not PIL_AVAILABLE:
                result = ImageAnalysisResult(
                    metadata=metadata_dict,
                    color_analysis=asdict(ColorAnalysis(notes=["Pixel analysis not requested or unavailable."])),
                    lighting_analysis=asdict(LightingAnalysis(notes=["Pixel analysis not requested or unavailable."])),
                    layout_analysis=asdict(LayoutAnalysis(notes=["Pixel analysis not requested or unavailable."])),
                    region_observations=[],
                    creative_asset_analysis=asdict(
                        CreativeAssetAnalysis(
                            asset_type=self._estimate_asset_type_from_metadata(metadata_dict),
                            quality_score=0.0,
                            design_notes=["Only metadata was analyzed."],
                        )
                    ),
                    confidence=0.68 if not PIL_AVAILABLE else 0.78,
                    warnings=warnings,
                )
            else:
                with self._open_image(normalized_path) as img:
                    working_img = self._prepare_working_image(img)

                    color_analysis = self._analyze_colors(working_img)
                    lighting_analysis = self._analyze_lighting(working_img, color_analysis)
                    layout_analysis = self._analyze_layout(working_img, metadata_dict)
                    region_observations = (
                        self._observe_regions(
                            working_img,
                            max_regions=max_regions if depth != "deep" else max(max_regions, 12),
                        )
                        if include_regions
                        else []
                    )
                    creative_analysis = self._analyze_creative_asset(
                        metadata=metadata_dict,
                        color_analysis=color_analysis,
                        lighting_analysis=lighting_analysis,
                        layout_analysis=layout_analysis,
                        regions=region_observations,
                    )

                    confidence = self._estimate_confidence(
                        metadata_dict=metadata_dict,
                        color_analysis=color_analysis,
                        layout_analysis=layout_analysis,
                        region_count=len(region_observations),
                        depth=depth,
                    )

                    result = ImageAnalysisResult(
                        metadata=metadata_dict,
                        color_analysis=asdict(color_analysis),
                        lighting_analysis=asdict(lighting_analysis),
                        layout_analysis=asdict(layout_analysis),
                        region_observations=[asdict(region) for region in region_observations],
                        creative_asset_analysis=asdict(creative_analysis),
                        confidence=confidence,
                        warnings=warnings,
                    )

            elapsed_ms = round((time.time() - started) * 1000, 2)

            summary = self._build_summary(asdict(result))
            verification_payload = self._prepare_verification_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                verification_type="image_analysis",
                target_path=normalized_path,
                status="completed",
                confidence=result.confidence,
                evidence={
                    "summary": summary,
                    "metadata": result.metadata,
                    "analysis_depth": depth,
                    "warnings": result.warnings,
                    "elapsed_ms": elapsed_ms,
                },
            )
            memory_payload = self._prepare_memory_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                summary=summary,
                data={
                    "image_path": str(normalized_path),
                    "asset_type": result.creative_asset_analysis.get("asset_type"),
                    "quality_score": result.creative_asset_analysis.get("quality_score"),
                    "dominant_colors": result.color_analysis.get("dominant_colors", [])[:5],
                    "lighting_quality": result.lighting_analysis.get("lighting_quality"),
                    "likely_asset_type": result.layout_analysis.get("likely_asset_type"),
                },
            )

            final_data = {
                "analysis": asdict(result),
                "summary": summary,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "elapsed_ms": elapsed_ms,
                "dependencies": {
                    "pillow_available": PIL_AVAILABLE,
                    "numpy_available": NUMPY_AVAILABLE,
                },
            }

            self._emit_agent_event(
                "visual.image_analyzed",
                {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                    "image_path": str(normalized_path),
                    "analysis_depth": depth,
                    "confidence": result.confidence,
                    "elapsed_ms": elapsed_ms,
                },
            )
            self._log_audit_event(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                action="analyze_image",
                outcome="success",
                details={
                    "image_path": str(normalized_path),
                    "analysis_depth": depth,
                    "confidence": result.confidence,
                    "elapsed_ms": elapsed_ms,
                },
            )

            return self._safe_result(
                success=True,
                message="Image analyzed successfully.",
                data=final_data,
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                    "image_path": str(normalized_path),
                    "analysis_depth": depth,
                    "elapsed_ms": elapsed_ms,
                },
            )

        except Exception as exc:
            self._log_audit_event(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                action="analyze_image",
                outcome="error",
                details={
                    "image_path": str(normalized_path),
                    "error": str(exc),
                },
            )
            return self._error_result(
                message="Image analysis failed.",
                error=exc,
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                    "image_path": str(normalized_path),
                },
            )

    def extract_metadata(
        self,
        image_path: PathLike,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        include_hash: bool = True,
        internal_call: bool = False,
    ) -> Dict[str, Any]:
        """
        Extract image/file metadata.

        This method is useful for quick Verification Agent checks before deeper
        pixel-level analysis.
        """

        context = self._validate_task_context(user_id, workspace_id, task_id)
        if not context["success"]:
            return context

        normalized_path = self._normalize_path(image_path)

        if self._requires_security_check(
            image_path=normalized_path,
            operation="image_metadata_read",
            pixel_analysis=False,
        ):
            approval = self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                image_path=normalized_path,
                operation="image_metadata_read",
                reason="Read image file metadata.",
                metadata={"include_hash": include_hash},
            )
            if not bool(approval.get("approved", False)):
                return self._error_result(
                    message="Security approval denied for image metadata extraction.",
                    error="SECURITY_APPROVAL_DENIED",
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "task_id": task_id,
                        "image_path": str(normalized_path),
                        "approval": approval,
                    },
                )

        metadata = self._metadata_from_path(normalized_path, include_hash=include_hash)

        status = "metadata_extracted" if metadata.exists else "image_missing"
        confidence = 0.95 if metadata.exists else 0.99

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            verification_type="image_metadata",
            target_path=normalized_path,
            status=status,
            confidence=confidence,
            evidence={"metadata": asdict(metadata)},
        )

        if not internal_call:
            self._emit_agent_event(
                "visual.image_metadata_extracted",
                {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                    "image_path": str(normalized_path),
                    "exists": metadata.exists,
                },
            )
            self._log_audit_event(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                action="extract_metadata",
                outcome="success" if metadata.exists else "missing",
                details={"image_path": str(normalized_path)},
            )

        return self._safe_result(
            success=metadata.exists and metadata.error is None,
            message=(
                "Image metadata extracted successfully."
                if metadata.exists and metadata.error is None
                else "Image metadata could not be fully extracted."
            ),
            data={
                "metadata": asdict(metadata),
                "verification_payload": verification_payload,
            },
            error=metadata.error,
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "image_path": str(normalized_path),
            },
        )

    def analyze_creative_asset(
        self,
        image_path: PathLike,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        asset_goal: Optional[str] = None,
        platform: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Creative-focused analysis for ads, thumbnails, social posts, banners,
        website hero images, logos, and marketing assets.
        """

        analysis = self.analyze_image(
            image_path=image_path,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            analysis_depth="standard",
            include_regions=True,
            include_hash=True,
        )
        if not analysis["success"]:
            return analysis

        result = analysis["data"]["analysis"]
        creative = result.get("creative_asset_analysis", {})
        metadata = result.get("metadata", {})
        layout = result.get("layout_analysis", {})
        colors = result.get("color_analysis", {})

        platform_notes = self._platform_creative_notes(
            width=metadata.get("width"),
            height=metadata.get("height"),
            platform=platform,
            asset_goal=asset_goal,
        )

        enhanced_creative = {
            **creative,
            "asset_goal": asset_goal,
            "platform": platform,
            "platform_notes": platform_notes,
            "creative_summary": self._creative_summary(
                creative=creative,
                metadata=metadata,
                layout=layout,
                colors=colors,
                platform=platform,
                asset_goal=asset_goal,
            ),
        }

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            verification_type="creative_asset_analysis",
            target_path=image_path,
            status="completed",
            confidence=result.get("confidence", 0.8),
            evidence={
                "creative_asset_analysis": enhanced_creative,
                "metadata": metadata,
                "layout": layout,
            },
        )

        return self._safe_result(
            success=True,
            message="Creative asset analyzed successfully.",
            data={
                "creative_asset_analysis": enhanced_creative,
                "base_analysis": result,
                "verification_payload": verification_payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "image_path": str(image_path),
                "asset_goal": asset_goal,
                "platform": platform,
            },
        )

    def compare_images(
        self,
        image_path_a: PathLike,
        image_path_b: PathLike,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        include_pixel_similarity: bool = True,
    ) -> Dict[str, Any]:
        """
        Compare two images by metadata, dimensions, hash, and optional pixel
        similarity.

        Useful for Verification Agent tasks such as confirming generated asset
        changes, checking backup images, or validating before/after states.
        """

        context = self._validate_task_context(user_id, workspace_id, task_id)
        if not context["success"]:
            return context

        path_a = self._normalize_path(image_path_a)
        path_b = self._normalize_path(image_path_b)

        if include_pixel_similarity and self._requires_security_check(
            operation="pixel_analysis",
            pixel_analysis=True,
        ):
            approval = self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                image_path=path_a,
                operation="pixel_analysis",
                reason="Compare two images with pixel-level similarity.",
                metadata={
                    "image_path_a": str(path_a),
                    "image_path_b": str(path_b),
                },
            )
            if not bool(approval.get("approved", False)):
                return self._error_result(
                    message="Security approval denied for pixel-level image comparison.",
                    error="SECURITY_APPROVAL_DENIED",
                    metadata={
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "task_id": task_id,
                        "approval": approval,
                    },
                )

        meta_a_result = self.extract_metadata(
            image_path=path_a,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            include_hash=True,
            internal_call=True,
        )
        meta_b_result = self.extract_metadata(
            image_path=path_b,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            include_hash=True,
            internal_call=True,
        )

        if not meta_a_result["data"] or not meta_b_result["data"]:
            return self._error_result(
                message="Unable to compare images because metadata extraction failed.",
                error="METADATA_EXTRACTION_FAILED",
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "task_id": task_id,
                    "image_path_a": str(path_a),
                    "image_path_b": str(path_b),
                },
            )

        meta_a = meta_a_result["data"]["metadata"]
        meta_b = meta_b_result["data"]["metadata"]

        checks = {
            "both_exist": bool(meta_a.get("exists")) and bool(meta_b.get("exists")),
            "same_dimensions": (
                meta_a.get("width") == meta_b.get("width")
                and meta_a.get("height") == meta_b.get("height")
            ),
            "same_format": meta_a.get("format") == meta_b.get("format"),
            "same_file_size": meta_a.get("file_size_bytes") == meta_b.get("file_size_bytes"),
            "same_hash": (
                bool(meta_a.get("file_hash_sha256"))
                and meta_a.get("file_hash_sha256") == meta_b.get("file_hash_sha256")
            ),
        }

        pixel_similarity = None
        if include_pixel_similarity and PIL_AVAILABLE and checks["both_exist"]:
            pixel_similarity = self._pixel_similarity(path_a, path_b)

        changed = not checks["same_hash"] if checks["both_exist"] else None

        comparison = {
            "image_a": meta_a,
            "image_b": meta_b,
            "checks": checks,
            "pixel_similarity": pixel_similarity,
            "changed": changed,
        }

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            verification_type="image_comparison",
            target_path=path_b,
            status="compared",
            confidence=0.92 if PIL_AVAILABLE else 0.78,
            evidence=comparison,
        )

        return self._safe_result(
            success=True,
            message="Images compared successfully.",
            data={
                "comparison": comparison,
                "verification_payload": verification_payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "image_path_a": str(path_a),
                "image_path_b": str(path_b),
            },
        )

    def analyze_batch(
        self,
        image_paths: Iterable[PathLike],
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        analysis_depth: str = "basic",
        max_images: int = 50,
    ) -> Dict[str, Any]:
        """
        Analyze multiple images safely.

        Good for dashboard uploads, asset libraries, Creator Agent outputs,
        and workflow verification.
        """

        context = self._validate_task_context(user_id, workspace_id, task_id)
        if not context["success"]:
            return context

        paths = list(image_paths)
        if len(paths) > max_images:
            paths = paths[:max_images]

        results: List[Dict[str, Any]] = []
        success_count = 0
        failed_count = 0

        for image_path in paths:
            result = self.analyze_image(
                image_path=image_path,
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                analysis_depth=analysis_depth,
                include_regions=False,
                include_hash=True,
            )
            results.append(result)
            if result.get("success"):
                success_count += 1
            else:
                failed_count += 1

        overall_success = failed_count == 0 and len(results) > 0

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            verification_type="image_batch_analysis",
            target_path=None,
            status="completed" if overall_success else "partial_or_failed",
            confidence=0.88 if overall_success else 0.68,
            evidence={
                "total": len(results),
                "success_count": success_count,
                "failed_count": failed_count,
            },
        )

        return self._safe_result(
            success=overall_success,
            message=(
                "Batch image analysis completed successfully."
                if overall_success
                else "Batch image analysis completed with one or more failures."
            ),
            data={
                "total": len(results),
                "success_count": success_count,
                "failed_count": failed_count,
                "results": results,
                "verification_payload": verification_payload,
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "analysis_depth": analysis_depth,
                "max_images": max_images,
            },
        )

    def get_registry_metadata(self) -> Dict[str, Any]:
        """
        Agent Registry / Agent Loader metadata.

        This allows the William Agent Registry to discover this helper and its
        safe capabilities.
        """

        return {
            "agent_name": self.AGENT_NAME,
            "agent_type": self.AGENT_TYPE,
            "agent_version": self.AGENT_VERSION,
            "class_name": self.__class__.__name__,
            "module": __name__,
            "safe_import": True,
            "read_only": True,
            "requires_user_context": True,
            "requires_workspace_context": True,
            "requires_security_for_sensitive_images": True,
            "optional_dependencies": {
                "Pillow": PIL_AVAILABLE,
                "numpy": NUMPY_AVAILABLE,
            },
            "capabilities": [
                "image_metadata_extraction",
                "image_color_analysis",
                "image_lighting_analysis",
                "image_layout_analysis",
                "creative_asset_analysis",
                "heuristic_region_observation",
                "image_similarity_comparison",
                "batch_image_analysis",
                "verification_payload_generation",
                "memory_payload_generation",
            ],
            "public_methods": [
                "analyze_image",
                "extract_metadata",
                "analyze_creative_asset",
                "compare_images",
                "analyze_batch",
                "get_registry_metadata",
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
        }

    # -----------------------------------------------------------------------
    # Internal metadata helpers
    # -----------------------------------------------------------------------

    def _metadata_from_path(
        self,
        image_path: Path,
        include_hash: bool = True,
    ) -> ImageMetadata:
        """
        Build metadata from a local image path.
        """

        metadata = ImageMetadata(
            path=str(image_path),
            exists=False,
            file_name=image_path.name,
            file_suffix=image_path.suffix.lower(),
            mime_type=mimetypes.guess_type(str(image_path))[0],
        )

        try:
            if not image_path.exists():
                metadata.error = "Image path does not exist."
                return metadata

            if not image_path.is_file():
                metadata.error = "Image path is not a file."
                return metadata

            stat = image_path.stat()
            metadata.exists = True
            metadata.file_size_bytes = stat.st_size
            metadata.created_at = self._timestamp_to_iso(stat.st_ctime)
            metadata.modified_at = self._timestamp_to_iso(stat.st_mtime)

            max_size = int(getattr(self.config, "MAX_IMAGE_FILE_SIZE_BYTES", 50 * 1024 * 1024))
            if stat.st_size > max_size:
                metadata.error = f"Image file exceeds configured max size: {stat.st_size} > {max_size}"
                return metadata

            if include_hash:
                metadata.file_hash_sha256 = self._sha256_file(image_path)

            if image_path.suffix.lower() not in self.SUPPORTED_IMAGE_SUFFIXES:
                metadata.error = f"Unsupported or unknown image suffix: {image_path.suffix}"
                return metadata

            if PIL_AVAILABLE:
                try:
                    with self._open_image(image_path) as img:
                        metadata.format = getattr(img, "format", None)
                        metadata.mode = getattr(img, "mode", None)
                        metadata.width = int(img.width)
                        metadata.height = int(img.height)
                        metadata.aspect_ratio = self._safe_ratio(img.width, img.height)
                        metadata.orientation = self._orientation_label(img.width, img.height)
                        metadata.has_alpha = self._has_alpha(img)
                        metadata.animated = bool(getattr(img, "is_animated", False))
                        metadata.frame_count = int(getattr(img, "n_frames", 1))
                except Exception as exc:
                    metadata.error = f"Pillow failed to read image: {exc}"

        except Exception as exc:
            metadata.error = str(exc)

        return metadata

    def _open_image(self, image_path: Path) -> Any:
        """
        Open an image with Pillow.

        Kept as a helper so future privacy filters or file loaders can override.
        """

        if not PIL_AVAILABLE or Image is None:
            raise RuntimeError("Pillow is not available.")
        return Image.open(image_path)

    def _prepare_working_image(self, img: Any) -> Any:
        """
        Normalize image for analysis.

        Uses a resized RGB copy to keep analysis fast and memory-safe.
        """

        image = img.copy()

        try:
            image = ImageOps.exif_transpose(image)
        except Exception:
            pass

        max_dim = int(getattr(self.config, "MAX_ANALYSIS_DIMENSION", 1400))
        width, height = image.size

        if max(width, height) > max_dim:
            ratio = max_dim / float(max(width, height))
            new_size = (max(1, int(width * ratio)), max(1, int(height * ratio)))
            image = image.resize(new_size)

        if image.mode not in {"RGB", "RGBA"}:
            image = image.convert("RGBA" if self._has_alpha(image) else "RGB")

        if image.mode == "RGBA":
            background = Image.new("RGB", image.size, (255, 255, 255))
            alpha = image.getchannel("A")
            background.paste(image, mask=alpha)
            image = background
        else:
            image = image.convert("RGB")

        return image

    # -----------------------------------------------------------------------
    # Internal analysis helpers
    # -----------------------------------------------------------------------

    def _analyze_colors(self, img: Any) -> ColorAnalysis:
        """
        Analyze image colors, brightness, contrast, saturation, and palette.
        """

        analysis = ColorAnalysis()

        try:
            small = img.copy()
            small.thumbnail((160, 160))

            stat = ImageStat.Stat(small)
            mean = stat.mean[:3]
            stddev = stat.stddev[:3]

            average_rgb = tuple(int(max(0, min(255, round(v)))) for v in mean)
            analysis.average_rgb = average_rgb  # type: ignore[assignment]
            analysis.average_color_hex = self._rgb_to_hex(average_rgb)

            brightness_values = self._sample_brightness_values(small)
            saturation_values = self._sample_saturation_values(small)

            analysis.brightness_score = self._round_score(
                statistics.mean(brightness_values) / 255 if brightness_values else 0
            )
            analysis.contrast_score = self._round_score(
                statistics.pstdev(brightness_values) / 128 if len(brightness_values) > 1 else 0
            )
            analysis.saturation_score = self._round_score(
                statistics.mean(saturation_values) if saturation_values else 0
            )

            red_avg, green_avg, blue_avg = average_rgb
            warmth_raw = ((red_avg - blue_avg) + 255) / 510
            analysis.warmth_score = self._round_score(warmth_raw)

            colorfulness = self._estimate_colorfulness(stddev, average_rgb)
            analysis.colorfulness_score = self._round_score(colorfulness)

            analysis.dominant_colors = self._dominant_colors(small)

            analysis.palette_type = self._palette_type(
                brightness=analysis.brightness_score,
                saturation=analysis.saturation_score,
                colorfulness=analysis.colorfulness_score,
            )

            if analysis.brightness_score is not None:
                if analysis.brightness_score < 0.25:
                    analysis.notes.append("Image appears dark overall.")
                elif analysis.brightness_score > 0.80:
                    analysis.notes.append("Image appears very bright overall.")
                else:
                    analysis.notes.append("Brightness appears balanced.")

            if analysis.saturation_score is not None:
                if analysis.saturation_score < 0.18:
                    analysis.notes.append("Colors appear muted or grayscale-like.")
                elif analysis.saturation_score > 0.65:
                    analysis.notes.append("Colors appear vivid and attention-grabbing.")

            if analysis.contrast_score is not None:
                if analysis.contrast_score < 0.18:
                    analysis.notes.append("Contrast appears low.")
                elif analysis.contrast_score > 0.70:
                    analysis.notes.append("Contrast appears strong.")

        except Exception as exc:
            analysis.notes.append(f"Color analysis failed: {exc}")

        return analysis

    def _analyze_lighting(
        self,
        img: Any,
        color_analysis: ColorAnalysis,
    ) -> LightingAnalysis:
        """
        Estimate lighting quality and exposure.
        """

        lighting = LightingAnalysis(
            brightness_score=color_analysis.brightness_score,
            contrast_score=color_analysis.contrast_score,
        )

        try:
            brightness = color_analysis.brightness_score or 0
            contrast = color_analysis.contrast_score or 0

            gray = img.convert("L")
            histogram = gray.histogram()
            total = sum(histogram) or 1

            dark_pixels = sum(histogram[:45]) / total
            bright_pixels = sum(histogram[220:]) / total

            lighting.shadow_level = self._level_label(dark_pixels)
            lighting.highlight_level = self._level_label(bright_pixels)

            if brightness < 0.22:
                lighting.exposure_estimate = "underexposed"
                lighting.notes.append("Image may be underexposed.")
            elif brightness > 0.86:
                lighting.exposure_estimate = "overexposed"
                lighting.notes.append("Image may be overexposed.")
            else:
                lighting.exposure_estimate = "balanced"

            if dark_pixels > 0.35:
                lighting.notes.append("Heavy shadow areas detected.")

            if bright_pixels > 0.25:
                lighting.notes.append("Strong highlight areas detected.")

            if 0.32 <= brightness <= 0.78 and 0.18 <= contrast <= 0.65:
                lighting.lighting_quality = "balanced"
            elif brightness < 0.22 or brightness > 0.88:
                lighting.lighting_quality = "poor"
            elif contrast < 0.12:
                lighting.lighting_quality = "flat"
            elif contrast > 0.85:
                lighting.lighting_quality = "harsh"
            else:
                lighting.lighting_quality = "acceptable"

        except Exception as exc:
            lighting.notes.append(f"Lighting analysis failed: {exc}")

        return lighting

    def _analyze_layout(
        self,
        img: Any,
        metadata: Dict[str, Any],
    ) -> LayoutAnalysis:
        """
        Analyze composition and layout heuristically.
        """

        layout = LayoutAnalysis()

        try:
            width, height = img.size
            layout.orientation = self._orientation_label(width, height)
            layout.aspect_ratio_label = self._aspect_ratio_label(width, height)

            gray = img.convert("L")
            brightness_map = self._resize_gray_values(gray, width=48, height=48)

            center_focus = self._center_focus_score(brightness_map)
            edge_density = self._edge_density_score(gray)
            symmetry = self._symmetry_score(gray)
            empty_space = self._empty_space_estimate(gray)
            thirds = self._rule_of_thirds_score(gray)

            layout.center_focus_score = self._round_score(center_focus)
            layout.edge_density_score = self._round_score(edge_density)
            layout.symmetry_estimate = self._round_score(symmetry)
            layout.empty_space_estimate = self._round_score(empty_space)
            layout.rule_of_thirds_score = self._round_score(thirds)

            if symmetry > 0.72:
                layout.composition_balance = "symmetrical"
            elif center_focus > 0.65:
                layout.composition_balance = "center-focused"
            elif thirds > 0.60:
                layout.composition_balance = "rule-of-thirds"
            elif empty_space > 0.55:
                layout.composition_balance = "minimal / whitespace-heavy"
            else:
                layout.composition_balance = "mixed"

            layout.likely_asset_type = self._estimate_asset_type(
                width=metadata.get("width") or width,
                height=metadata.get("height") or height,
                edge_density=edge_density,
                empty_space=empty_space,
                saturation=None,
                mime_type=metadata.get("mime_type"),
                file_name=metadata.get("file_name"),
            )

            if layout.empty_space_estimate is not None:
                if layout.empty_space_estimate > 0.60:
                    layout.notes.append("Large empty/flat areas detected, useful for text overlays.")
                elif layout.empty_space_estimate < 0.18:
                    layout.notes.append("Image appears visually busy with limited whitespace.")

            if layout.edge_density_score is not None:
                if layout.edge_density_score > 0.65:
                    layout.notes.append("High detail density detected.")
                elif layout.edge_density_score < 0.12:
                    layout.notes.append("Low detail density detected, likely simple graphic or flat design.")

            if layout.center_focus_score is not None and layout.center_focus_score > 0.65:
                layout.notes.append("Strong center focus detected.")

        except Exception as exc:
            layout.notes.append(f"Layout analysis failed: {exc}")

        return layout

    def _observe_regions(
        self,
        img: Any,
        max_regions: int = 9,
    ) -> List[RegionObservation]:
        """
        Heuristic region observation.

        This is not a trained object detector. It identifies prominent visual
        regions based on brightness, contrast, and colorfulness.
        """

        rows = int(getattr(self.config, "OBJECT_GRID_ROWS", 3))
        cols = int(getattr(self.config, "OBJECT_GRID_COLUMNS", 3))

        width, height = img.size
        observations: List[RegionObservation] = []

        try:
            for row in range(rows):
                for col in range(cols):
                    left = int(col * width / cols)
                    top = int(row * height / rows)
                    right = int((col + 1) * width / cols)
                    bottom = int((row + 1) * height / rows)

                    crop = img.crop((left, top, right, bottom))
                    brightness_values = self._sample_brightness_values(crop)
                    saturation_values = self._sample_saturation_values(crop)

                    if brightness_values:
                        brightness = statistics.mean(brightness_values) / 255
                        contrast = statistics.pstdev(brightness_values) / 128 if len(brightness_values) > 1 else 0
                    else:
                        brightness = 0
                        contrast = 0

                    colorfulness = statistics.mean(saturation_values) if saturation_values else 0

                    prominence = self._round_score(
                        (contrast * 0.45)
                        + (colorfulness * 0.30)
                        + (abs(brightness - 0.5) * 0.25)
                    )

                    content_type = self._guess_region_content_type(
                        brightness=brightness,
                        contrast=contrast,
                        colorfulness=colorfulness,
                    )

                    observations.append(
                        RegionObservation(
                            region_id=f"r{row + 1}c{col + 1}",
                            grid_position=self._grid_position_label(row, col, rows, cols),
                            bounds={
                                "left": left,
                                "top": top,
                                "right": right,
                                "bottom": bottom,
                                "width": right - left,
                                "height": bottom - top,
                            },
                            prominence_score=prominence,
                            brightness_score=self._round_score(brightness),
                            contrast_score=self._round_score(contrast),
                            colorfulness_score=self._round_score(colorfulness),
                            possible_content_type=content_type,
                            confidence=self._round_score(0.55 + min(0.35, prominence * 0.35)),
                        )
                    )

            observations.sort(key=lambda item: item.prominence_score, reverse=True)
            return observations[:max_regions]

        except Exception as exc:
            logger.debug("Region observation failed: %s", exc)
            return observations[:max_regions]

    def _analyze_creative_asset(
        self,
        metadata: Dict[str, Any],
        color_analysis: ColorAnalysis,
        lighting_analysis: LightingAnalysis,
        layout_analysis: LayoutAnalysis,
        regions: List[RegionObservation],
    ) -> CreativeAssetAnalysis:
        """
        Create a practical creative/design quality analysis.
        """

        creative = CreativeAssetAnalysis()
        creative.asset_type = layout_analysis.likely_asset_type or self._estimate_asset_type_from_metadata(metadata)

        quality = 0.50

        brightness = color_analysis.brightness_score
        contrast = color_analysis.contrast_score
        saturation = color_analysis.saturation_score
        empty_space = layout_analysis.empty_space_estimate
        edge_density = layout_analysis.edge_density_score

        if brightness is not None and 0.30 <= brightness <= 0.82:
            quality += 0.10
            creative.strengths.append("Brightness is within a usable range.")
        elif brightness is not None:
            quality -= 0.08
            creative.improvement_suggestions.append("Adjust exposure/brightness for clearer viewing.")

        if contrast is not None and 0.20 <= contrast <= 0.72:
            quality += 0.10
            creative.strengths.append("Contrast appears usable.")
        elif contrast is not None and contrast < 0.18:
            quality -= 0.10
            creative.improvement_suggestions.append("Increase contrast to improve visual separation.")

        if saturation is not None and 0.18 <= saturation <= 0.72:
            quality += 0.07
        elif saturation is not None and saturation > 0.80:
            creative.design_notes.append("Very high saturation may feel aggressive depending on brand style.")

        if empty_space is not None and 0.22 <= empty_space <= 0.68:
            quality += 0.08
            creative.strengths.append("Whitespace/flat area balance appears usable.")
        elif empty_space is not None and empty_space < 0.16:
            quality -= 0.08
            creative.improvement_suggestions.append("Reduce clutter or add spacing around key content.")

        if edge_density is not None and edge_density > 0.78:
            quality -= 0.05
            creative.design_notes.append("Image appears very detailed or busy.")

        if lighting_analysis.lighting_quality in {"balanced", "acceptable"}:
            quality += 0.08
        elif lighting_analysis.lighting_quality in {"poor", "harsh", "flat"}:
            quality -= 0.08
            creative.improvement_suggestions.append("Improve lighting balance for a more polished asset.")

        if layout_analysis.composition_balance in {"center-focused", "rule-of-thirds", "symmetrical"}:
            quality += 0.08
            creative.strengths.append(f"Composition appears {layout_analysis.composition_balance}.")

        if regions:
            top_region = regions[0]
            if top_region.prominence_score > 0.55:
                creative.design_notes.append(
                    f"Most visually prominent region appears around {top_region.grid_position}."
                )

        if metadata.get("width") and metadata.get("height"):
            width = int(metadata["width"])
            height = int(metadata["height"])
            if width < 500 or height < 500:
                quality -= 0.08
                creative.improvement_suggestions.append("Use a higher-resolution version if this is for ads or web hero usage.")

        if creative.asset_type in {"social_post", "ad_creative", "thumbnail"}:
            if contrast is not None and contrast < 0.22:
                creative.readability_estimate = "low"
                creative.improvement_suggestions.append("Add stronger text/background contrast for better readability.")
            elif empty_space is not None and empty_space > 0.25:
                creative.readability_estimate = "good"
            else:
                creative.readability_estimate = "medium"
        else:
            creative.readability_estimate = "unknown"

        if not creative.improvement_suggestions:
            creative.improvement_suggestions.append("Asset is generally usable; refine based on campaign/platform requirements.")

        if not creative.design_notes:
            creative.design_notes.append("No major design issues detected from heuristic analysis.")

        creative.quality_score = self._round_score(quality)

        return creative

    # -----------------------------------------------------------------------
    # Scoring helpers
    # -----------------------------------------------------------------------

    def _dominant_colors(self, img: Any) -> List[Dict[str, Any]]:
        """
        Extract dominant colors using Pillow quantization.
        """

        try:
            color_count = int(getattr(self.config, "DOMINANT_COLOR_COUNT", 8))
            small = img.copy()
            small.thumbnail((120, 120))

            quantized = small.convert("P", palette=Image.ADAPTIVE, colors=color_count)
            palette = quantized.getpalette()
            color_counts = quantized.getcolors(maxcolors=120 * 120)

            if not palette or not color_counts:
                return []

            total = sum(count for count, _ in color_counts) or 1
            dominant: List[Dict[str, Any]] = []

            color_counts.sort(reverse=True, key=lambda item: item[0])
            for count, palette_index in color_counts[:color_count]:
                offset = palette_index * 3
                rgb = tuple(palette[offset:offset + 3])
                if len(rgb) != 3:
                    continue

                rgb_tuple = (int(rgb[0]), int(rgb[1]), int(rgb[2]))
                dominant.append(
                    {
                        "hex": self._rgb_to_hex(rgb_tuple),
                        "rgb": rgb_tuple,
                        "percentage": round((count / total) * 100, 2),
                        "label": self._color_label(rgb_tuple),
                    }
                )

            return dominant

        except Exception as exc:
            logger.debug("Dominant color extraction failed: %s", exc)
            return []

    def _sample_brightness_values(self, img: Any) -> List[int]:
        """
        Sample grayscale brightness values.
        """

        try:
            gray = img.convert("L")
            sample = gray.resize((64, 64))
            return list(sample.getdata())
        except Exception:
            return []

    def _sample_saturation_values(self, img: Any) -> List[float]:
        """
        Sample saturation values from HSV image.
        """

        try:
            hsv = img.convert("HSV").resize((64, 64))
            values = []
            for _, saturation, _ in hsv.getdata():
                values.append(float(saturation) / 255.0)
            return values
        except Exception:
            return []

    def _estimate_colorfulness(
        self,
        stddev: Sequence[float],
        average_rgb: RGBTuple,
    ) -> float:
        """
        Estimate visual colorfulness.
        """

        try:
            std_score = sum(stddev[:3]) / (3 * 128)
            r, g, b = average_rgb
            channel_spread = (max(r, g, b) - min(r, g, b)) / 255
            return max(0.0, min(1.0, (std_score * 0.65) + (channel_spread * 0.35)))
        except Exception:
            return 0.0

    def _palette_type(
        self,
        brightness: Optional[float],
        saturation: Optional[float],
        colorfulness: Optional[float],
    ) -> str:
        """
        Classify palette style.
        """

        brightness = brightness or 0
        saturation = saturation or 0
        colorfulness = colorfulness or 0

        if saturation < 0.12 and colorfulness < 0.15:
            return "monochrome / neutral"
        if brightness > 0.78 and saturation < 0.35:
            return "light / soft"
        if brightness < 0.30:
            return "dark / moody"
        if saturation > 0.65 or colorfulness > 0.65:
            return "vivid / high-energy"
        if 0.30 <= saturation <= 0.60:
            return "balanced"
        return "muted"

    def _center_focus_score(self, brightness_map: List[List[int]]) -> float:
        """
        Estimate whether visual energy is concentrated near center.
        """

        try:
            rows = len(brightness_map)
            cols = len(brightness_map[0]) if rows else 0
            if not rows or not cols:
                return 0.0

            center_values = []
            outer_values = []

            for r in range(rows):
                for c in range(cols):
                    value = brightness_map[r][c]
                    in_center = rows * 0.30 <= r <= rows * 0.70 and cols * 0.30 <= c <= cols * 0.70
                    if in_center:
                        center_values.append(value)
                    else:
                        outer_values.append(value)

            center_std = statistics.pstdev(center_values) if len(center_values) > 1 else 0
            outer_std = statistics.pstdev(outer_values) if len(outer_values) > 1 else 0
            center_mean = statistics.mean(center_values) if center_values else 0
            outer_mean = statistics.mean(outer_values) if outer_values else 0

            energy_delta = abs(center_mean - outer_mean) / 255
            texture_delta = (center_std - outer_std) / 128

            return max(0.0, min(1.0, 0.45 + energy_delta + max(0.0, texture_delta * 0.25)))

        except Exception:
            return 0.0

    def _edge_density_score(self, gray: Any) -> float:
        """
        Estimate detail/edge density.
        """

        try:
            resized = gray.resize((160, 160))
            edges = resized.filter(ImageFilter.FIND_EDGES)
            values = list(edges.getdata())
            mean_edge = statistics.mean(values) / 255 if values else 0
            return max(0.0, min(1.0, mean_edge * 2.5))
        except Exception:
            return 0.0

    def _symmetry_score(self, gray: Any) -> float:
        """
        Estimate horizontal symmetry.
        """

        try:
            resized = gray.resize((160, 160))
            flipped = ImageOps.mirror(resized)
            diff = ImageChops.difference(resized, flipped)
            stat = ImageStat.Stat(diff)
            mean_diff = stat.mean[0] / 255
            return max(0.0, min(1.0, 1.0 - mean_diff * 1.8))
        except Exception:
            return 0.0

    def _empty_space_estimate(self, gray: Any) -> float:
        """
        Estimate flat/empty visual space.
        """

        try:
            resized = gray.resize((96, 96))
            values = list(resized.getdata())
            if not values:
                return 0.0

            global_mean = statistics.mean(values)
            flat_count = 0
            for value in values:
                if abs(value - global_mean) < 18:
                    flat_count += 1

            return max(0.0, min(1.0, flat_count / len(values)))
        except Exception:
            return 0.0

    def _rule_of_thirds_score(self, gray: Any) -> float:
        """
        Heuristic score for visual activity around rule-of-thirds lines.
        """

        try:
            resized = gray.resize((180, 180))
            edges = resized.filter(ImageFilter.FIND_EDGES)
            width, height = edges.size
            pixels = edges.load()

            third_x = [width // 3, (2 * width) // 3]
            third_y = [height // 3, (2 * height) // 3]

            line_values = []
            all_values = list(edges.getdata())

            for x in third_x:
                for y in range(height):
                    line_values.append(pixels[x, y])

            for y in third_y:
                for x in range(width):
                    line_values.append(pixels[x, y])

            line_mean = statistics.mean(line_values) if line_values else 0
            all_mean = statistics.mean(all_values) if all_values else 1

            if all_mean <= 0:
                return 0.0

            ratio = line_mean / all_mean
            return max(0.0, min(1.0, ratio / 2.0))
        except Exception:
            return 0.0

    def _resize_gray_values(self, gray: Any, width: int, height: int) -> List[List[int]]:
        """
        Resize grayscale image and return nested list.
        """

        resized = gray.resize((width, height))
        data = list(resized.getdata())
        return [data[row * width:(row + 1) * width] for row in range(height)]

    def _pixel_similarity(self, path_a: Path, path_b: Path) -> Optional[Dict[str, Any]]:
        """
        Estimate pixel similarity between two images.

        Returns None if unavailable.
        """

        try:
            with self._open_image(path_a) as img_a, self._open_image(path_b) as img_b:
                a = self._prepare_working_image(img_a).resize((256, 256))
                b = self._prepare_working_image(img_b).resize((256, 256))

                diff = ImageChops.difference(a, b)
                stat = ImageStat.Stat(diff)
                mean_diff = sum(stat.mean[:3]) / 3
                similarity = max(0.0, min(1.0, 1.0 - (mean_diff / 255)))

                return {
                    "similarity_score": self._round_score(similarity),
                    "mean_pixel_difference": round(mean_diff, 3),
                    "interpretation": (
                        "nearly_identical"
                        if similarity > 0.98
                        else "very_similar"
                        if similarity > 0.90
                        else "somewhat_similar"
                        if similarity > 0.70
                        else "different"
                    ),
                }
        except Exception as exc:
            logger.debug("Pixel similarity failed: %s", exc)
            return None

    # -----------------------------------------------------------------------
    # Classification helpers
    # -----------------------------------------------------------------------

    def _estimate_asset_type(
        self,
        width: int,
        height: int,
        edge_density: Optional[float],
        empty_space: Optional[float],
        saturation: Optional[float],
        mime_type: Optional[str],
        file_name: Optional[str],
    ) -> str:
        """
        Estimate likely visual asset type.
        """

        ratio = self._safe_ratio(width, height)
        name = (file_name or "").lower()

        if "logo" in name:
            return "logo"
        if "banner" in name or "hero" in name:
            return "banner_or_hero"
        if "thumb" in name or "thumbnail" in name:
            return "thumbnail"
        if "ad" in name or "creative" in name:
            return "ad_creative"
        if "screenshot" in name or "screen" in name:
            return "screenshot"

        if width >= 1600 and height <= 700:
            return "website_banner"
        if 0.95 <= ratio <= 1.05:
            return "social_post"
        if 1.70 <= ratio <= 1.95:
            return "wide_creative"
        if 0.52 <= ratio <= 0.60:
            return "story_or_reel"
        if empty_space is not None and empty_space > 0.70 and edge_density is not None and edge_density < 0.18:
            return "simple_graphic_or_logo"
        if edge_density is not None and edge_density > 0.55:
            return "photo_or_detailed_visual"

        return "general_image"

    def _estimate_asset_type_from_metadata(self, metadata: Dict[str, Any]) -> str:
        """
        Fallback asset type estimate from metadata only.
        """

        width = metadata.get("width") or 0
        height = metadata.get("height") or 0
        return self._estimate_asset_type(
            width=int(width) if width else 0,
            height=int(height) if height else 0,
            edge_density=None,
            empty_space=None,
            saturation=None,
            mime_type=metadata.get("mime_type"),
            file_name=metadata.get("file_name"),
        )

    def _guess_region_content_type(
        self,
        brightness: float,
        contrast: float,
        colorfulness: float,
    ) -> str:
        """
        Guess possible content type in a region using visual heuristics.
        """

        if contrast < 0.10 and colorfulness < 0.15:
            return "flat_background_or_whitespace"
        if contrast > 0.60 and colorfulness < 0.25:
            return "text_or_high_contrast_detail"
        if colorfulness > 0.60 and contrast > 0.35:
            return "colorful_object_or_graphic"
        if brightness < 0.22:
            return "dark_region_or_shadow"
        if brightness > 0.85:
            return "bright_region_or_highlight"
        if contrast > 0.45:
            return "detailed_region"
        return "general_visual_region"

    def _platform_creative_notes(
        self,
        width: Optional[int],
        height: Optional[int],
        platform: Optional[str],
        asset_goal: Optional[str],
    ) -> List[str]:
        """
        Add platform-specific creative notes using basic dimensions.
        """

        notes: List[str] = []
        if not width or not height:
            return ["Platform fit could not be estimated because dimensions are unavailable."]

        ratio = self._safe_ratio(width, height)
        platform_lower = (platform or "").lower().strip()

        if platform_lower in {"facebook", "meta", "instagram", "ig"}:
            if 0.95 <= ratio <= 1.05:
                notes.append("Square ratio is suitable for many Meta feed placements.")
            elif 0.55 <= ratio <= 0.60:
                notes.append("Vertical ratio is suitable for Stories/Reels-style placements.")
            elif 1.70 <= ratio <= 1.95:
                notes.append("Wide ratio may suit landscape placements but may crop in feeds.")
            else:
                notes.append("Check platform crop rules before publishing.")
        elif platform_lower in {"youtube"}:
            if 1.70 <= ratio <= 1.85:
                notes.append("Ratio is close to a YouTube thumbnail format.")
            else:
                notes.append("For YouTube thumbnails, consider a 16:9 layout.")
        elif platform_lower in {"website", "web", "landing_page"}:
            if ratio > 2.0:
                notes.append("Wide image can work well as a website hero/banner.")
            else:
                notes.append("Image may need responsive cropping for website hero usage.")
        else:
            notes.append("No specific platform rule applied.")

        if asset_goal:
            notes.append(f"Review final design against goal: {asset_goal}.")

        return notes

    def _creative_summary(
        self,
        creative: Dict[str, Any],
        metadata: Dict[str, Any],
        layout: Dict[str, Any],
        colors: Dict[str, Any],
        platform: Optional[str],
        asset_goal: Optional[str],
    ) -> str:
        """
        Build a short creative review summary.
        """

        asset_type = creative.get("asset_type") or layout.get("likely_asset_type") or "image"
        quality_score = creative.get("quality_score")
        lighting = colors.get("palette_type") or "unknown palette"
        dimensions = (
            f"{metadata.get('width')}x{metadata.get('height')}"
            if metadata.get("width") and metadata.get("height")
            else "unknown dimensions"
        )
        platform_text = f" for {platform}" if platform else ""
        goal_text = f" Goal: {asset_goal}." if asset_goal else ""

        return (
            f"Analyzed {asset_type}{platform_text} at {dimensions}. "
            f"Estimated quality score: {quality_score}. "
            f"Palette: {lighting}. "
            f"Composition: {layout.get('composition_balance')}. "
            f"{goal_text}"
        ).strip()

    # -----------------------------------------------------------------------
    # General helpers
    # -----------------------------------------------------------------------

    def _normalize_path(self, path: PathLike) -> Path:
        """
        Normalize path without forcing existence.
        """

        return Path(str(path)).expanduser()

    def _sha256_file(self, path: Path) -> Optional[str]:
        """
        Hash image file safely.
        """

        try:
            hasher = hashlib.sha256()
            with path.open("rb") as file_obj:
                for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as exc:
            logger.debug("SHA256 hash failed: %s", exc)
            return None

    def _has_alpha(self, img: Any) -> bool:
        """
        Check whether image has transparency.
        """

        try:
            if img.mode in {"RGBA", "LA"}:
                return True
            if img.mode == "P" and "transparency" in img.info:
                return True
        except Exception:
            pass
        return False

    def _orientation_label(self, width: int, height: int) -> str:
        """
        Return portrait/landscape/square orientation.
        """

        if width == height:
            return "square"
        if width > height:
            return "landscape"
        return "portrait"

    def _aspect_ratio_label(self, width: int, height: int) -> str:
        """
        Human-friendly aspect ratio label.
        """

        ratio = self._safe_ratio(width, height)

        known = [
            (1.0, "1:1 square"),
            (16 / 9, "16:9 widescreen"),
            (9 / 16, "9:16 vertical"),
            (4 / 3, "4:3 standard"),
            (3 / 4, "3:4 portrait"),
            (1.91, "1.91:1 social landscape"),
        ]

        for target, label in known:
            if abs(ratio - target) < 0.06:
                return label

        if ratio > 2.0:
            return "ultra-wide"
        if ratio < 0.50:
            return "tall vertical"
        return f"{round(ratio, 2)}:1"

    def _safe_ratio(self, width: Union[int, float], height: Union[int, float]) -> float:
        """
        Safe width/height ratio.
        """

        try:
            if not height:
                return 0.0
            return round(float(width) / float(height), 4)
        except Exception:
            return 0.0

    def _rgb_to_hex(self, rgb: RGBTuple) -> str:
        """
        Convert RGB tuple to HEX.
        """

        return "#{:02x}{:02x}{:02x}".format(
            max(0, min(255, int(rgb[0]))),
            max(0, min(255, int(rgb[1]))),
            max(0, min(255, int(rgb[2]))),
        )

    def _color_label(self, rgb: RGBTuple) -> str:
        """
        Simple human-readable color label.
        """

        r, g, b = rgb
        brightness = (r + g + b) / 3
        max_channel = max(r, g, b)
        min_channel = min(r, g, b)

        if max_channel - min_channel < 20:
            if brightness < 45:
                return "black / charcoal"
            if brightness > 215:
                return "white / very light"
            return "gray / neutral"

        if r >= g and r >= b:
            if g > 130:
                return "orange / warm"
            return "red / warm"
        if g >= r and g >= b:
            if b > 130:
                return "cyan / teal"
            return "green"
        if b >= r and b >= g:
            if r > 130:
                return "purple / magenta"
            return "blue / cool"

        return "mixed"

    def _level_label(self, value: float) -> str:
        """
        Convert numeric level into low/medium/high.
        """

        if value < 0.12:
            return "low"
        if value < 0.30:
            return "medium"
        return "high"

    def _grid_position_label(self, row: int, col: int, rows: int, cols: int) -> str:
        """
        Human-friendly grid position label.
        """

        vertical = "top" if row == 0 else "bottom" if row == rows - 1 else "middle"
        horizontal = "left" if col == 0 else "right" if col == cols - 1 else "center"

        if vertical == "middle" and horizontal == "center":
            return "center"
        return f"{vertical}-{horizontal}"

    def _estimate_confidence(
        self,
        metadata_dict: Dict[str, Any],
        color_analysis: ColorAnalysis,
        layout_analysis: LayoutAnalysis,
        region_count: int,
        depth: str,
    ) -> float:
        """
        Estimate overall confidence for analysis.
        """

        confidence = float(getattr(self.config, "DEFAULT_CONFIDENCE", 0.82))

        if metadata_dict.get("width") and metadata_dict.get("height"):
            confidence += 0.04

        if color_analysis.dominant_colors:
            confidence += 0.04

        if layout_analysis.composition_balance:
            confidence += 0.03

        if region_count > 0:
            confidence += 0.02

        if depth == "deep":
            confidence += 0.03
        elif depth == "basic":
            confidence -= 0.04

        if metadata_dict.get("error"):
            confidence -= 0.20

        return self._round_score(confidence)

    def _build_summary(self, result: Dict[str, Any]) -> str:
        """
        Create compact summary for logs, dashboard, and Memory Agent.
        """

        metadata = result.get("metadata", {})
        colors = result.get("color_analysis", {})
        lighting = result.get("lighting_analysis", {})
        layout = result.get("layout_analysis", {})
        creative = result.get("creative_asset_analysis", {})

        file_name = metadata.get("file_name") or "image"
        dimensions = (
            f"{metadata.get('width')}x{metadata.get('height')}"
            if metadata.get("width") and metadata.get("height")
            else "unknown size"
        )
        asset_type = creative.get("asset_type") or layout.get("likely_asset_type") or "general_image"
        quality = creative.get("quality_score")
        palette = colors.get("palette_type")
        lighting_quality = lighting.get("lighting_quality")
        composition = layout.get("composition_balance")

        return (
            f"{file_name} analyzed as {asset_type}. "
            f"Dimensions: {dimensions}. "
            f"Palette: {palette}. "
            f"Lighting: {lighting_quality}. "
            f"Composition: {composition}. "
            f"Quality score: {quality}."
        )

    def _timestamp_to_iso(self, timestamp: Union[int, float]) -> str:
        """
        Convert POSIX timestamp to UTC ISO string.
        """

        return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat()

    def _utc_now(self) -> str:
        """
        Current UTC timestamp.
        """

        return datetime.now(timezone.utc).isoformat()

    def _round_score(self, value: Union[int, float]) -> float:
        """
        Clamp and round score to 0.0 - 1.0.
        """

        return round(self._clamp_confidence(value), 4)

    def _clamp_confidence(self, value: Union[int, float]) -> float:
        """
        Clamp value inside 0.0 - 1.0.
        """

        try:
            return max(0.0, min(1.0, float(value)))
        except Exception:
            return 0.0


# ---------------------------------------------------------------------------
# Module-level factory
# ---------------------------------------------------------------------------

def create_image_analyzer(**kwargs: Any) -> ImageAnalyzer:
    """
    Factory used by Agent Loader / Registry for dynamic construction.
    """

    return ImageAnalyzer(**kwargs)


# ---------------------------------------------------------------------------
# Lightweight self-test
# ---------------------------------------------------------------------------

def self_test(image_path: Optional[PathLike] = None) -> Dict[str, Any]:
    """
    Safe smoke test.

    If image_path is provided, analyzes that image.
    If not provided, returns registry metadata only to avoid creating files.
    """

    analyzer = ImageAnalyzer()

    if image_path is None:
        return analyzer._safe_result(
            success=True,
            message="ImageAnalyzer import self-test passed.",
            data={
                "registry_metadata": analyzer.get_registry_metadata(),
                "pillow_available": PIL_AVAILABLE,
                "numpy_available": NUMPY_AVAILABLE,
            },
            metadata={"self_test": True},
        )

    return analyzer.analyze_image(
        image_path=image_path,
        user_id="self_test_user",
        workspace_id="self_test_workspace",
        task_id="self_test_image_analyzer",
        analysis_depth="standard",
        include_regions=True,
        include_hash=True,
    )


__all__ = [
    "ImageAnalyzer",
    "ImageMetadata",
    "ColorAnalysis",
    "LightingAnalysis",
    "LayoutAnalysis",
    "RegionObservation",
    "CreativeAssetAnalysis",
    "ImageAnalysisResult",
    "create_image_analyzer",
    "self_test",
]


if __name__ == "__main__":
    # Safe CLI smoke test.
    # Usage:
    #   python agents/visual_agent/image_analyzer.py
    #   python agents/visual_agent/image_analyzer.py /path/to/image.png
    import sys

    test_path = sys.argv[1] if len(sys.argv) > 1 else None
    print(json.dumps(self_test(test_path), indent=2, default=str))


# FILE COMPLETE