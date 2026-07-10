"""
agents/visual_agent/config.py

VisualConfig for William / Jarvis Visual Agent.

Purpose:
    OCR/UI thresholds, video limits, redaction and screenshot privacy settings.

Architecture Fit:
    - Visual Agent imports this file to keep OCR, UI mapping, screenshot reading,
      video analysis, privacy filtering, validation, annotation, and workflow
      learning behavior consistent.
    - Master Agent / Agent Router can inspect this configuration safely.
    - Security Agent can be consulted before risky privacy/screenshot settings are
      weakened.
    - Verification Agent can receive configuration verification payloads.
    - Memory Agent can store safe preference/context summaries without storing
      sensitive screen content.
    - Dashboard/API can expose safe configuration summaries and allow controlled
      per-user/workspace overrides later.
    - Agent Registry/Loader can import this file even if the rest of the William
      platform is not created yet.

Important:
    This file is configuration-only. It does not capture screenshots, read files,
    execute OCR, process video, send messages, browse, call, or perform destructive
    actions. It only validates and returns safe configuration structures.
"""

from __future__ import annotations

import copy
import logging
import os
import re
import uuid
from dataclasses import asdict, dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this configuration module import-safe while the full William/Jarvis
        platform is being generated file-by-file.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VisualConfigProfile(str, Enum):
    """Supported configuration profiles."""

    STRICT_PRIVACY = "strict_privacy"
    BALANCED = "balanced"
    HIGH_ACCURACY = "high_accuracy"
    LOW_RESOURCE = "low_resource"
    TESTING = "testing"


class ScreenshotPrivacyMode(str, Enum):
    """Screenshot privacy modes."""

    BLOCK_PRIVATE = "block_private"
    REDACT_SENSITIVE = "redact_sensitive"
    METADATA_ONLY = "metadata_only"
    DISABLED = "disabled"


class RedactionMode(str, Enum):
    """Visual redaction behavior."""

    STRICT = "strict"
    BALANCED = "balanced"
    MINIMAL = "minimal"
    OFF = "off"


class VideoSamplingMode(str, Enum):
    """Video frame sampling modes."""

    SCENE_CHANGE = "scene_change"
    INTERVAL = "interval"
    HYBRID = "hybrid"
    KEYFRAMES_ONLY = "keyframes_only"


class OCRBackend(str, Enum):
    """OCR backend identifiers used by the OCR engine."""

    AUTO = "auto"
    TESSERACT = "tesseract"
    EASY_OCR = "easyocr"
    PADDLE_OCR = "paddleocr"
    CLOUD_DISABLED = "cloud_disabled"


class UIPlatformHint(str, Enum):
    """Platform hints for UI detection and mapping."""

    UNKNOWN = "unknown"
    WEB = "web"
    DESKTOP = "desktop"
    MOBILE_ANDROID = "mobile_android"
    MOBILE_IOS = "mobile_ios"
    BROWSER = "browser"
    WORDPRESS = "wordpress"
    GOOGLE_ADS = "google_ads"
    VS_CODE = "vs_code"
    CHROME = "chrome"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class OCRThresholdConfig:
    """OCR confidence and cleanup thresholds."""

    backend: str = OCRBackend.AUTO.value
    min_text_confidence: float = 0.55
    min_word_confidence: float = 0.45
    min_line_confidence: float = 0.50
    min_block_confidence: float = 0.50
    merge_nearby_words_px: int = 8
    merge_nearby_lines_px: int = 12
    min_text_height_px: int = 6
    max_text_height_px: int = 220
    max_image_megapixels: float = 16.0
    language_hints: Tuple[str, ...] = ("eng",)
    enable_text_cleanup: bool = True
    normalize_whitespace: bool = True
    preserve_case: bool = True
    detect_rotation: bool = True
    max_rotation_degrees: float = 8.0
    retry_low_confidence_once: bool = True


@dataclass
class UIThresholdConfig:
    """UI element detection thresholds used by element_detector and ui_mapper."""

    min_element_confidence: float = 0.58
    min_button_confidence: float = 0.60
    min_input_confidence: float = 0.60
    min_icon_confidence: float = 0.55
    min_label_confidence: float = 0.50
    min_clickable_area_px: int = 24
    max_clickable_area_ratio: float = 0.70
    min_component_width_px: int = 6
    min_component_height_px: int = 6
    max_component_overlap_ratio: float = 0.35
    group_nearby_elements_px: int = 12
    table_cell_alignment_tolerance_px: int = 10
    card_detection_min_area_ratio: float = 0.015
    form_field_label_distance_px: int = 90
    active_focus_border_threshold: float = 0.60
    disabled_opacity_threshold: float = 0.45
    platform_hint: str = UIPlatformHint.UNKNOWN.value


@dataclass
class ScreenshotPrivacyConfig:
    """Screenshot capture/privacy controls."""

    privacy_mode: str = ScreenshotPrivacyMode.REDACT_SENSITIVE.value
    allow_private_windows: bool = False
    allow_password_fields: bool = False
    allow_payment_screens: bool = False
    allow_health_or_legal_screens: bool = False
    allow_identity_documents: bool = False
    allow_clipboard_preview: bool = False
    allow_screen_without_user_context: bool = False
    block_hidden_or_background_capture: bool = True
    require_active_window_check: bool = True
    require_user_workspace_context: bool = True
    store_raw_screenshots: bool = False
    store_redacted_screenshots: bool = True
    screenshot_ttl_seconds: int = 3600
    max_screenshot_width_px: int = 1920
    max_screenshot_height_px: int = 1080
    max_screenshot_megapixels: float = 3.0
    blur_background_private_regions: bool = True
    private_window_title_patterns: Tuple[str, ...] = (
        "incognito",
        "private browsing",
        "inprivate",
        "private window",
        "secret mode",
    )


@dataclass
class RedactionConfig:
    """Sensitive visual data redaction settings."""

    mode: str = RedactionMode.STRICT.value
    redact_passwords: bool = True
    redact_payment_cards: bool = True
    redact_bank_details: bool = True
    redact_api_keys: bool = True
    redact_tokens: bool = True
    redact_private_keys: bool = True
    redact_emails: bool = True
    redact_phone_numbers: bool = True
    redact_addresses: bool = True
    redact_identity_numbers: bool = True
    redact_faces: bool = True
    redact_license_plates: bool = True
    redact_qr_codes: bool = True
    redact_barcodes: bool = True
    redact_session_cookies: bool = True
    redact_auth_headers: bool = True
    redact_min_confidence: float = 0.50
    face_redaction_min_confidence: float = 0.65
    sensitive_text_padding_px: int = 8
    sensitive_region_padding_px: int = 12
    replacement_label: str = "REDACTED"
    safe_preview_max_chars: int = 120
    sensitive_regex_patterns: Tuple[str, ...] = (
        r"(?i)\bapi[_-]?key\b\s*[:=]\s*[A-Za-z0-9_\-]{12,}",
        r"(?i)\bsecret\b\s*[:=]\s*[A-Za-z0-9_\-]{12,}",
        r"(?i)\btoken\b\s*[:=]\s*[A-Za-z0-9_\-.]{12,}",
        r"(?i)\bauthorization:\s*bearer\s+[A-Za-z0-9_\-.]+",
        r"\b(?:\d[ -]*?){13,19}\b",
        r"(?i)\bpassword\b\s*[:=]\s*\S+",
        r"(?i)\bssn\b\s*[:=]?\s*\d{3}-?\d{2}-?\d{4}",
    )


@dataclass
class VideoLimitConfig:
    """Video analysis and frame extraction limits."""

    sampling_mode: str = VideoSamplingMode.HYBRID.value
    max_video_duration_seconds: int = 300
    max_video_file_mb: int = 250
    max_frames_total: int = 600
    max_frames_per_minute: int = 90
    min_seconds_between_frames: float = 0.50
    scene_change_threshold: float = 0.18
    duplicate_frame_similarity_threshold: float = 0.96
    keyframe_min_difference_threshold: float = 0.12
    max_frame_width_px: int = 1280
    max_frame_height_px: int = 720
    max_frame_megapixels: float = 1.2
    extract_audio_transcript: bool = False
    store_extracted_frames: bool = False
    store_redacted_frames: bool = True
    frame_ttl_seconds: int = 3600
    stop_on_private_screen: bool = True


@dataclass
class ImageAnalysisConfig:
    """Image analyzer settings."""

    max_image_file_mb: int = 50
    max_image_width_px: int = 4096
    max_image_height_px: int = 4096
    max_image_megapixels: float = 16.0
    min_object_confidence: float = 0.55
    min_layout_confidence: float = 0.55
    min_design_issue_confidence: float = 0.60
    detect_faces: bool = True
    detect_objects: bool = True
    detect_layout: bool = True
    detect_lighting: bool = True
    detect_blur: bool = True
    detect_brand_assets: bool = True
    require_redaction_before_export: bool = True


@dataclass
class AnnotationConfig:
    """Annotation tool settings for boxes/labels/reports."""

    enable_annotations: bool = True
    show_confidence: bool = True
    show_labels: bool = True
    show_click_targets: bool = True
    show_error_regions: bool = True
    max_annotations_per_image: int = 200
    min_annotation_confidence: float = 0.50
    label_max_chars: int = 60
    box_thickness_px: int = 2
    text_padding_px: int = 4
    export_format: str = "png"
    require_redacted_source: bool = True


@dataclass
class WorkflowLearningConfig:
    """Visual workflow learner settings."""

    enable_workflow_learning: bool = True
    min_step_confidence: float = 0.60
    min_transition_confidence: float = 0.58
    max_steps_per_workflow: int = 120
    max_idle_gap_seconds: int = 30
    merge_similar_steps_threshold: float = 0.88
    require_user_workspace_context: bool = True
    store_raw_step_images: bool = False
    store_redacted_step_images: bool = True
    export_automation_recipe: bool = True
    block_sensitive_workflow_learning: bool = True


@dataclass
class VisualMemoryConfig:
    """Visual memory settings for repeated screen patterns and layouts."""

    enable_visual_memory: bool = True
    store_screen_patterns: bool = True
    store_error_patterns: bool = True
    store_app_layouts: bool = True
    store_ui_positions: bool = True
    store_raw_images: bool = False
    store_redacted_images: bool = True
    pattern_similarity_threshold: float = 0.90
    max_patterns_per_workspace: int = 5000
    max_patterns_per_user: int = 15000
    memory_ttl_days: int = 90
    require_redaction_before_memory: bool = True


@dataclass
class StorageConfig:
    """Storage limits and isolation controls."""

    base_storage_namespace: str = "visual_agent"
    enforce_user_workspace_partition: bool = True
    allow_cross_workspace_reads: bool = False
    allow_cross_user_reads: bool = False
    max_workspace_storage_mb: int = 2048
    max_user_storage_mb: int = 8192
    temporary_artifact_ttl_seconds: int = 3600
    audit_config_reads: bool = True
    audit_config_overrides: bool = True


@dataclass
class DashboardConfig:
    """Dashboard/API safe exposure settings."""

    expose_safe_summary: bool = True
    expose_thresholds: bool = True
    expose_sensitive_patterns: bool = False
    allow_dashboard_overrides: bool = True
    require_security_for_privacy_downgrade: bool = True
    require_security_for_raw_storage_enable: bool = True
    max_override_keys_per_request: int = 80


@dataclass
class VisualConfigData:
    """Complete Visual Agent configuration tree."""

    profile: str = VisualConfigProfile.BALANCED.value
    ocr: OCRThresholdConfig = field(default_factory=OCRThresholdConfig)
    ui: UIThresholdConfig = field(default_factory=UIThresholdConfig)
    screenshot_privacy: ScreenshotPrivacyConfig = field(default_factory=ScreenshotPrivacyConfig)
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    video: VideoLimitConfig = field(default_factory=VideoLimitConfig)
    image_analysis: ImageAnalysisConfig = field(default_factory=ImageAnalysisConfig)
    annotation: AnnotationConfig = field(default_factory=AnnotationConfig)
    workflow_learning: WorkflowLearningConfig = field(default_factory=WorkflowLearningConfig)
    visual_memory: VisualMemoryConfig = field(default_factory=VisualMemoryConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    version: str = "1.0.0"


# ---------------------------------------------------------------------------
# VisualConfig
# ---------------------------------------------------------------------------

class VisualConfig(BaseAgent):
    """
    Central configuration manager for William / Jarvis Visual Agent.

    This class:
        - provides safe default OCR/UI/video/privacy settings,
        - validates thresholds and limits,
        - supports controlled per-user/workspace overrides,
        - blocks unsafe privacy downgrades unless security approval is available,
        - returns structured William/Jarvis dict results,
        - prepares Verification Agent and Memory Agent payloads,
        - remains import-safe without the rest of the platform.

    It does NOT perform real screenshot capture, video decoding, OCR, browser
    actions, file mutation, calls, messages, or financial operations.
    """

    SENSITIVE_OVERRIDE_KEYS = {
        "screenshot_privacy.allow_private_windows",
        "screenshot_privacy.allow_password_fields",
        "screenshot_privacy.allow_payment_screens",
        "screenshot_privacy.allow_health_or_legal_screens",
        "screenshot_privacy.allow_identity_documents",
        "screenshot_privacy.allow_clipboard_preview",
        "screenshot_privacy.allow_screen_without_user_context",
        "screenshot_privacy.block_hidden_or_background_capture",
        "screenshot_privacy.require_active_window_check",
        "screenshot_privacy.require_user_workspace_context",
        "screenshot_privacy.store_raw_screenshots",
        "redaction.mode",
        "redaction.redact_passwords",
        "redaction.redact_payment_cards",
        "redaction.redact_bank_details",
        "redaction.redact_api_keys",
        "redaction.redact_tokens",
        "redaction.redact_private_keys",
        "redaction.redact_emails",
        "redaction.redact_phone_numbers",
        "redaction.redact_addresses",
        "redaction.redact_identity_numbers",
        "redaction.redact_faces",
        "redaction.redact_qr_codes",
        "redaction.redact_barcodes",
        "video.store_extracted_frames",
        "image_analysis.require_redaction_before_export",
        "workflow_learning.block_sensitive_workflow_learning",
        "visual_memory.store_raw_images",
        "visual_memory.require_redaction_before_memory",
        "storage.allow_cross_workspace_reads",
        "storage.allow_cross_user_reads",
        "dashboard.expose_sensitive_patterns",
    }

    RAW_STORAGE_KEYS = {
        "screenshot_privacy.store_raw_screenshots",
        "video.store_extracted_frames",
        "workflow_learning.store_raw_step_images",
        "visual_memory.store_raw_images",
    }

    def __init__(
        self,
        config_data: Optional[VisualConfigData] = None,
        profile: Union[str, VisualConfigProfile] = VisualConfigProfile.BALANCED,
        security_agent: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        agent_name: str = "VisualConfig",
        agent_id: str = "visual_config",
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=agent_name, agent_id=agent_id, **kwargs)
        self.logger = logger or getattr(self, "logger", logging.getLogger(agent_name))
        self.security_agent = security_agent
        self._security_agent_factory = SecurityAgent
        self.config = config_data or self._build_profile_config(profile)
        self.config.profile = self._normalize_profile(profile)
        self._workspace_overrides: Dict[str, VisualConfigData] = {}
        self._validate_and_repair_config(self.config)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_config(
        self,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        include_sensitive: bool = False,
    ) -> Dict[str, Any]:
        """
        Return full config for internal agent use.

        If user_id/workspace_id are provided, workspace-specific overrides are
        returned. Sensitive regex patterns are omitted unless include_sensitive=True.
        """

        context = self._validate_optional_context(user_id=user_id, workspace_id=workspace_id)
        if not context["success"]:
            return context

        active_config = self._get_active_config(user_id=user_id, workspace_id=workspace_id)
        data = self._config_to_dict(active_config, include_sensitive=include_sensitive)

        return self._safe_result(
            message="Visual configuration loaded.",
            data={"config": data},
            metadata=self._base_metadata(user_id, workspace_id),
        )

    def get_safe_summary(
        self,
        *,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return dashboard/API-safe configuration summary."""

        context = self._validate_optional_context(user_id=user_id, workspace_id=workspace_id)
        if not context["success"]:
            return context

        active_config = self._get_active_config(user_id=user_id, workspace_id=workspace_id)
        summary = {
            "profile": active_config.profile,
            "version": active_config.version,
            "ocr_backend": active_config.ocr.backend,
            "ocr_min_text_confidence": active_config.ocr.min_text_confidence,
            "ui_min_element_confidence": active_config.ui.min_element_confidence,
            "screenshot_privacy_mode": active_config.screenshot_privacy.privacy_mode,
            "store_raw_screenshots": active_config.screenshot_privacy.store_raw_screenshots,
            "store_redacted_screenshots": active_config.screenshot_privacy.store_redacted_screenshots,
            "redaction_mode": active_config.redaction.mode,
            "redact_faces": active_config.redaction.redact_faces,
            "video_sampling_mode": active_config.video.sampling_mode,
            "max_video_duration_seconds": active_config.video.max_video_duration_seconds,
            "max_frames_total": active_config.video.max_frames_total,
            "visual_memory_enabled": active_config.visual_memory.enable_visual_memory,
            "workflow_learning_enabled": active_config.workflow_learning.enable_workflow_learning,
            "user_workspace_partition_enforced": active_config.storage.enforce_user_workspace_partition,
            "cross_workspace_reads_allowed": active_config.storage.allow_cross_workspace_reads,
            "cross_user_reads_allowed": active_config.storage.allow_cross_user_reads,
        }

        return self._safe_result(
            message="Visual configuration safe summary loaded.",
            data={"summary": summary},
            metadata=self._base_metadata(user_id, workspace_id),
        )

    def validate_config(
        self,
        config_data: Optional[Union[VisualConfigData, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Validate config and return issues/warnings without mutating input."""

        cfg = self._copy_config(self.config)
        if config_data is not None:
            if isinstance(config_data, VisualConfigData):
                cfg = self._copy_config(config_data)
            elif isinstance(config_data, Mapping):
                cfg = self._merge_dict_into_config(cfg, config_data)
            else:
                return self._error_result(
                    message="config_data must be VisualConfigData or mapping.",
                    error={"code": "invalid_config_type"},
                )

        issues, warnings = self._collect_config_issues(cfg)

        return self._safe_result(
            success=len(issues) == 0,
            message="Visual configuration validation completed.",
            data={
                "valid": len(issues) == 0,
                "issues": issues,
                "warnings": warnings,
            },
            error={"code": "invalid_visual_config", "details": issues} if issues else None,
            metadata={"timestamp": self._utc_now_iso()},
        )

    async def apply_overrides(
        self,
        *,
        user_id: str,
        workspace_id: str,
        overrides: Mapping[str, Any],
        request_security_approval: bool = True,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Apply per-user/workspace overrides.

        This is safe for dashboard/API integration. Risky privacy downgrades and
        raw storage enabling are blocked unless Security Agent approves.
        """

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=None,
            task_type="visual_config_override",
        )
        if not context["success"]:
            return context

        if not isinstance(overrides, Mapping):
            return self._error_result(
                message="Overrides must be a mapping/dict.",
                error={"code": "invalid_overrides"},
                metadata=self._base_metadata(user_id, workspace_id),
            )

        if len(overrides) > self.config.dashboard.max_override_keys_per_request:
            return self._error_result(
                message="Too many override keys in one request.",
                error={
                    "code": "override_limit_exceeded",
                    "max_keys": self.config.dashboard.max_override_keys_per_request,
                },
                metadata=self._base_metadata(user_id, workspace_id),
            )

        flat_overrides = self._flatten_mapping(overrides)
        unsafe_keys = self._detect_sensitive_override_keys(flat_overrides)
        requires_security = self._requires_security_check(
            action="visual_config_override",
            overrides=flat_overrides,
            unsafe_keys=unsafe_keys,
        )

        if requires_security and request_security_approval:
            approval = await self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                action="visual_config_override",
                task_payload={
                    "overrides": dict(flat_overrides),
                    "unsafe_keys": sorted(unsafe_keys),
                },
                metadata=metadata,
            )
            if not approval["success"] or not approval["data"].get("approved", False):
                return self._error_result(
                    message="Visual configuration override blocked by security policy.",
                    error={
                        "code": "security_approval_required_or_denied",
                        "unsafe_keys": sorted(unsafe_keys),
                        "approval": approval.get("error"),
                    },
                    data={
                        "verification_payload": self._prepare_verification_payload(
                            user_id=user_id,
                            workspace_id=workspace_id,
                            task_id=context["data"]["task_id"],
                            status="blocked",
                            details={"unsafe_keys": sorted(unsafe_keys)},
                        ),
                        "memory_payload": self._prepare_memory_payload(
                            user_id=user_id,
                            workspace_id=workspace_id,
                            task_id=context["data"]["task_id"],
                            summary="Visual configuration override was blocked by security policy.",
                            metadata=metadata,
                        ),
                    },
                    metadata=self._base_metadata(user_id, workspace_id),
                )

        elif requires_security and not request_security_approval:
            return self._error_result(
                message="Visual configuration override requires security approval.",
                error={
                    "code": "security_approval_required",
                    "unsafe_keys": sorted(unsafe_keys),
                },
                metadata=self._base_metadata(user_id, workspace_id),
            )

        base = self._get_active_config(user_id=user_id, workspace_id=workspace_id)
        updated = self._merge_dict_into_config(base, overrides)
        self._validate_and_repair_config(updated)
        issues, warnings = self._collect_config_issues(updated)

        if issues:
            return self._error_result(
                message="Visual configuration override rejected because validation failed.",
                error={"code": "invalid_override_config", "details": issues},
                data={"warnings": warnings},
                metadata=self._base_metadata(user_id, workspace_id),
            )

        self._workspace_overrides[self._workspace_key(user_id, workspace_id)] = updated

        await self._emit_agent_event(
            event_type="visual.config.override_applied",
            payload={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "override_keys": sorted(flat_overrides.keys()),
                "unsafe_keys": sorted(unsafe_keys),
                "warnings": warnings,
            },
        )
        await self._log_audit_event(
            action="visual_config_override_applied",
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=context["data"]["task_id"],
            details={
                "override_keys": sorted(flat_overrides.keys()),
                "unsafe_keys": sorted(unsafe_keys),
                "warnings": warnings,
            },
        )

        return self._safe_result(
            message="Visual configuration overrides applied.",
            data={
                "config": self._config_to_dict(updated, include_sensitive=False),
                "override_keys": sorted(flat_overrides.keys()),
                "unsafe_keys": sorted(unsafe_keys),
                "warnings": warnings,
                "verification_payload": self._prepare_verification_payload(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=context["data"]["task_id"],
                    status="success",
                    details={"override_keys": sorted(flat_overrides.keys())},
                ),
                "memory_payload": self._prepare_memory_payload(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    task_id=context["data"]["task_id"],
                    summary="Visual Agent configuration overrides were applied safely.",
                    metadata=metadata,
                ),
            },
            metadata=self._base_metadata(user_id, workspace_id),
        )

    def reset_overrides(
        self,
        *,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Reset per-user/workspace config overrides."""

        context = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=None,
            task_type="visual_config_reset",
        )
        if not context["success"]:
            return context

        key = self._workspace_key(user_id, workspace_id)
        removed = key in self._workspace_overrides
        if removed:
            del self._workspace_overrides[key]

        return self._safe_result(
            message="Visual configuration overrides reset." if removed else "No visual configuration overrides existed.",
            data={"removed": removed},
            metadata=self._base_metadata(user_id, workspace_id),
        )

    def load_from_env(self, prefix: str = "WILLIAM_VISUAL_") -> Dict[str, Any]:
        """
        Load safe environment overrides.

        Supported examples:
            WILLIAM_VISUAL_PROFILE=strict_privacy
            WILLIAM_VISUAL_OCR_MIN_TEXT_CONFIDENCE=0.65
            WILLIAM_VISUAL_VIDEO_MAX_FRAMES_TOTAL=300

        Environment values never enable raw screenshot/frame/image storage unless
        explicitly provided and then still validated/repaired by safety rules.
        """

        env_overrides: Dict[str, Any] = {}

        profile = os.getenv(f"{prefix}PROFILE")
        if profile:
            env_overrides["profile"] = profile.strip()

        env_map = {
            f"{prefix}OCR_BACKEND": "ocr.backend",
            f"{prefix}OCR_MIN_TEXT_CONFIDENCE": "ocr.min_text_confidence",
            f"{prefix}OCR_MIN_WORD_CONFIDENCE": "ocr.min_word_confidence",
            f"{prefix}UI_MIN_ELEMENT_CONFIDENCE": "ui.min_element_confidence",
            f"{prefix}UI_MIN_BUTTON_CONFIDENCE": "ui.min_button_confidence",
            f"{prefix}SCREENSHOT_PRIVACY_MODE": "screenshot_privacy.privacy_mode",
            f"{prefix}STORE_RAW_SCREENSHOTS": "screenshot_privacy.store_raw_screenshots",
            f"{prefix}STORE_REDACTED_SCREENSHOTS": "screenshot_privacy.store_redacted_screenshots",
            f"{prefix}REDACTION_MODE": "redaction.mode",
            f"{prefix}VIDEO_MAX_DURATION_SECONDS": "video.max_video_duration_seconds",
            f"{prefix}VIDEO_MAX_FRAMES_TOTAL": "video.max_frames_total",
            f"{prefix}VIDEO_SCENE_CHANGE_THRESHOLD": "video.scene_change_threshold",
            f"{prefix}MEMORY_ENABLED": "visual_memory.enable_visual_memory",
            f"{prefix}WORKFLOW_LEARNING_ENABLED": "workflow_learning.enable_workflow_learning",
        }

        for env_key, config_key in env_map.items():
            if env_key in os.environ:
                env_overrides[config_key] = self._parse_env_value(os.environ[env_key])

        if env_overrides:
            self.config = self._merge_dict_into_config(self.config, env_overrides)
            self.config.profile = self._normalize_profile(env_overrides.get("profile", self.config.profile))
            self._validate_and_repair_config(self.config)

        return self._safe_result(
            message="Environment visual configuration loaded.",
            data={
                "loaded": bool(env_overrides),
                "override_keys": sorted(env_overrides.keys()),
                "config": self._config_to_dict(self.config, include_sensitive=False),
            },
            metadata={"timestamp": self._utc_now_iso()},
        )

    def build_profile(
        self,
        profile: Union[str, VisualConfigProfile],
    ) -> Dict[str, Any]:
        """Return a named profile configuration without mutating active config."""

        cfg = self._build_profile_config(profile)
        return self._safe_result(
            message=f"Visual configuration profile built: {cfg.profile}.",
            data={"config": self._config_to_dict(cfg, include_sensitive=False)},
            metadata={"timestamp": self._utc_now_iso()},
        )

    def set_profile(
        self,
        profile: Union[str, VisualConfigProfile],
    ) -> Dict[str, Any]:
        """Set global/default profile. Workspace overrides remain separate."""

        self.config = self._build_profile_config(profile)
        self._validate_and_repair_config(self.config)

        return self._safe_result(
            message=f"Visual configuration profile set: {self.config.profile}.",
            data={"config": self._config_to_dict(self.config, include_sensitive=False)},
            metadata={"timestamp": self._utc_now_iso()},
        )

    def get_public_status(self) -> Dict[str, Any]:
        """Return Agent Registry / Dashboard friendly status."""

        validation = self.validate_config()
        return self._safe_result(
            message="Visual configuration status ready.",
            data={
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "profile": self.config.profile,
                "version": self.config.version,
                "valid": validation["data"]["valid"],
                "issues": validation["data"]["issues"],
                "warnings": validation["data"]["warnings"],
                "workspace_override_count": len(self._workspace_overrides),
                "privacy_mode": self.config.screenshot_privacy.privacy_mode,
                "redaction_mode": self.config.redaction.mode,
                "raw_screenshot_storage": self.config.screenshot_privacy.store_raw_screenshots,
                "cross_workspace_reads_allowed": self.config.storage.allow_cross_workspace_reads,
                "cross_user_reads_allowed": self.config.storage.allow_cross_user_reads,
            },
            metadata={"timestamp": self._utc_now_iso()},
        )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        task_id: Optional[str],
        task_type: Optional[str],
    ) -> Dict[str, Any]:
        """Validate SaaS user/workspace context for config operations."""

        errors: List[str] = []

        if not isinstance(user_id, str) or not user_id.strip():
            errors.append("user_id is required.")
        if not isinstance(workspace_id, str) or not workspace_id.strip():
            errors.append("workspace_id is required.")
        if task_id is not None and not isinstance(task_id, str):
            errors.append("task_id must be a string when provided.")
        if not isinstance(task_type, str) or not task_type.strip():
            errors.append("task_type is required.")

        if errors:
            return self._error_result(
                message="Invalid VisualConfig task context.",
                error={"code": "invalid_task_context", "details": errors},
                metadata={"timestamp": self._utc_now_iso()},
            )

        return self._safe_result(
            message="VisualConfig task context is valid.",
            data={
                "user_id": user_id.strip(),
                "workspace_id": workspace_id.strip(),
                "task_id": task_id.strip() if isinstance(task_id, str) and task_id.strip() else self._new_id("visual_config_task"),
                "task_type": task_type.strip(),
            },
            metadata={"timestamp": self._utc_now_iso()},
        )

    def _requires_security_check(
        self,
        *,
        action: str,
        overrides: Optional[Mapping[str, Any]] = None,
        unsafe_keys: Optional[Iterable[str]] = None,
    ) -> bool:
        """Return True when config changes require Security Agent approval."""

        unsafe = set(unsafe_keys or [])
        flat = dict(overrides or {})

        if unsafe:
            return True

        if action in {"privacy_downgrade", "raw_storage_enable"}:
            return True

        for key, value in flat.items():
            if key in self.SENSITIVE_OVERRIDE_KEYS:
                return True
            if key in self.RAW_STORAGE_KEYS and bool(value):
                return True
            if key in {"storage.allow_cross_workspace_reads", "storage.allow_cross_user_reads"} and bool(value):
                return True
            if key == "redaction.mode" and str(value).lower() in {RedactionMode.MINIMAL.value, RedactionMode.OFF.value}:
                return True
            if key == "screenshot_privacy.privacy_mode" and str(value).lower() == ScreenshotPrivacyMode.DISABLED.value:
                return True

        return False

    async def _request_security_approval(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action: str,
        task_payload: Mapping[str, Any],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If Security Agent is missing, deny safely. This prevents accidental privacy
        downgrade while the wider system is still being assembled.
        """

        approval_payload = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "action": action,
            "task_payload": dict(task_payload),
            "metadata": dict(metadata or {}),
            "requested_by": self.agent_id,
            "timestamp": self._utc_now_iso(),
        }

        agent = self.security_agent
        if agent is None and self._security_agent_factory is not None:
            try:
                agent = self._security_agent_factory()
            except Exception as exc:
                self.logger.warning("SecurityAgent factory failed: %s", exc)
                agent = None

        if agent is None:
            return self._safe_result(
                success=False,
                message="Security Agent unavailable. Sensitive VisualConfig change denied safely.",
                data={"approved": False, "reason": "security_agent_unavailable"},
                error={"code": "security_agent_unavailable"},
                metadata=approval_payload,
            )

        try:
            if hasattr(agent, "approve_action"):
                response = agent.approve_action(approval_payload)
                if hasattr(response, "__await__"):
                    response = await response
                approved = bool(response.get("approved", response.get("success", False))) if isinstance(response, Mapping) else bool(response)
                return self._safe_result(
                    success=approved,
                    message="Security approval response received.",
                    data={"approved": approved, "response": self._safe_preview(response)},
                    metadata=approval_payload,
                )

            if hasattr(agent, "validate_permission"):
                response = agent.validate_permission(approval_payload)
                if hasattr(response, "__await__"):
                    response = await response
                approved = bool(response.get("approved", response.get("success", False))) if isinstance(response, Mapping) else bool(response)
                return self._safe_result(
                    success=approved,
                    message="Security permission response received.",
                    data={"approved": approved, "response": self._safe_preview(response)},
                    metadata=approval_payload,
                )

            return self._safe_result(
                success=False,
                message="Security Agent has no supported approval method. Sensitive change denied safely.",
                data={"approved": False, "reason": "unsupported_security_agent_interface"},
                error={"code": "unsupported_security_agent_interface"},
                metadata=approval_payload,
            )

        except Exception as exc:
            return self._error_result(
                message="Security approval request failed. Sensitive change denied safely.",
                error={
                    "code": "security_approval_failed",
                    "type": exc.__class__.__name__,
                    "details": str(exc),
                },
                data={"approved": False},
                metadata=approval_payload,
            )

    def _prepare_verification_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: str,
        status: str,
        details: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent compatible payload."""

        return {
            "agent": self.agent_id,
            "payload_type": "visual_config_verification",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "status": status,
            "details": dict(details or {}),
            "timestamp": self._utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: str,
        summary: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Memory Agent compatible payload without sensitive screen data."""

        return {
            "agent": self.agent_id,
            "memory_type": "visual_config_context",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "summary": summary,
            "metadata": dict(metadata or {}),
            "timestamp": self._utc_now_iso(),
        }

    async def _emit_agent_event(
        self,
        event_type: str,
        payload: Mapping[str, Any],
    ) -> None:
        """Emit Dashboard/API/Registry friendly event if supported."""

        try:
            if hasattr(super(), "emit_event"):
                result = super().emit_event(event_type, dict(payload))  # type: ignore[misc]
                if hasattr(result, "__await__"):
                    await result
                return
        except Exception as exc:
            self.logger.debug("BaseAgent emit_event failed: %s", exc)

        self.logger.info("VisualConfig event: %s | %s", event_type, self._safe_preview(payload))

    async def _log_audit_event(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        task_id: str,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Write audit event if BaseAgent supports it; otherwise log safely."""

        payload = {
            "action": action,
            "agent": self.agent_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "task_id": task_id,
            "details": dict(details or {}),
            "timestamp": self._utc_now_iso(),
        }

        try:
            if hasattr(super(), "log_audit"):
                result = super().log_audit(payload)  # type: ignore[misc]
                if hasattr(result, "__await__"):
                    await result
                return
        except Exception as exc:
            self.logger.debug("BaseAgent log_audit failed: %s", exc)

        self.logger.info("VisualConfig audit: %s", self._safe_preview(payload))

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        success: bool = True,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis result."""

        return {
            "success": bool(success),
            "message": message,
            "data": dict(data or {}),
            "error": dict(error or {}) if error else None,
            "metadata": dict(metadata or {}),
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis error result."""

        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error or {"code": "visual_config_error"},
            metadata=metadata or {"timestamp": self._utc_now_iso()},
        )

    # ------------------------------------------------------------------
    # Profile builders
    # ------------------------------------------------------------------

    def _build_profile_config(self, profile: Union[str, VisualConfigProfile]) -> VisualConfigData:
        """Build config for a named profile."""

        normalized = self._normalize_profile(profile)
        cfg = VisualConfigData(profile=normalized)

        if normalized == VisualConfigProfile.STRICT_PRIVACY.value:
            cfg.ocr.min_text_confidence = 0.60
            cfg.ui.min_element_confidence = 0.62
            cfg.screenshot_privacy.privacy_mode = ScreenshotPrivacyMode.REDACT_SENSITIVE.value
            cfg.screenshot_privacy.allow_private_windows = False
            cfg.screenshot_privacy.allow_password_fields = False
            cfg.screenshot_privacy.store_raw_screenshots = False
            cfg.screenshot_privacy.store_redacted_screenshots = True
            cfg.redaction.mode = RedactionMode.STRICT.value
            cfg.redaction.redact_faces = True
            cfg.video.max_frames_total = 400
            cfg.video.store_extracted_frames = False
            cfg.workflow_learning.block_sensitive_workflow_learning = True
            cfg.visual_memory.store_raw_images = False
            cfg.storage.allow_cross_workspace_reads = False
            cfg.storage.allow_cross_user_reads = False
            cfg.dashboard.expose_sensitive_patterns = False

        elif normalized == VisualConfigProfile.HIGH_ACCURACY.value:
            cfg.ocr.min_text_confidence = 0.50
            cfg.ocr.min_word_confidence = 0.40
            cfg.ocr.retry_low_confidence_once = True
            cfg.ui.min_element_confidence = 0.52
            cfg.ui.min_button_confidence = 0.55
            cfg.video.max_frames_total = 900
            cfg.video.max_frames_per_minute = 120
            cfg.video.scene_change_threshold = 0.14
            cfg.image_analysis.min_object_confidence = 0.50
            cfg.annotation.max_annotations_per_image = 300
            cfg.redaction.mode = RedactionMode.STRICT.value
            cfg.screenshot_privacy.store_raw_screenshots = False

        elif normalized == VisualConfigProfile.LOW_RESOURCE.value:
            cfg.ocr.max_image_megapixels = 6.0
            cfg.ocr.retry_low_confidence_once = False
            cfg.ui.min_element_confidence = 0.65
            cfg.video.max_video_duration_seconds = 120
            cfg.video.max_video_file_mb = 80
            cfg.video.max_frames_total = 180
            cfg.video.max_frames_per_minute = 45
            cfg.video.max_frame_width_px = 960
            cfg.video.max_frame_height_px = 540
            cfg.image_analysis.max_image_megapixels = 6.0
            cfg.annotation.max_annotations_per_image = 100
            cfg.visual_memory.max_patterns_per_workspace = 1500

        elif normalized == VisualConfigProfile.TESTING.value:
            cfg.ocr.min_text_confidence = 0.40
            cfg.ui.min_element_confidence = 0.45
            cfg.video.max_video_duration_seconds = 60
            cfg.video.max_frames_total = 60
            cfg.screenshot_privacy.screenshot_ttl_seconds = 600
            cfg.video.frame_ttl_seconds = 600
            cfg.storage.temporary_artifact_ttl_seconds = 600
            cfg.dashboard.allow_dashboard_overrides = True
            cfg.redaction.mode = RedactionMode.BALANCED.value

        else:
            cfg.profile = VisualConfigProfile.BALANCED.value

        self._validate_and_repair_config(cfg)
        return cfg

    def _normalize_profile(self, profile: Union[str, VisualConfigProfile]) -> str:
        """Normalize profile value safely."""

        value = str(profile.value if isinstance(profile, VisualConfigProfile) else profile).strip().lower()
        allowed = {item.value for item in VisualConfigProfile}
        return value if value in allowed else VisualConfigProfile.BALANCED.value

    # ------------------------------------------------------------------
    # Validation and repair
    # ------------------------------------------------------------------

    def _validate_and_repair_config(self, cfg: VisualConfigData) -> None:
        """Clamp unsafe/out-of-range values and enforce hard safety rules."""

        cfg.profile = self._normalize_profile(cfg.profile)

        cfg.ocr.backend = self._enum_value(cfg.ocr.backend, OCRBackend, OCRBackend.AUTO.value)
        cfg.ocr.min_text_confidence = self._clamp_float(cfg.ocr.min_text_confidence, 0.0, 1.0)
        cfg.ocr.min_word_confidence = self._clamp_float(cfg.ocr.min_word_confidence, 0.0, 1.0)
        cfg.ocr.min_line_confidence = self._clamp_float(cfg.ocr.min_line_confidence, 0.0, 1.0)
        cfg.ocr.min_block_confidence = self._clamp_float(cfg.ocr.min_block_confidence, 0.0, 1.0)
        cfg.ocr.merge_nearby_words_px = self._clamp_int(cfg.ocr.merge_nearby_words_px, 0, 100)
        cfg.ocr.merge_nearby_lines_px = self._clamp_int(cfg.ocr.merge_nearby_lines_px, 0, 200)
        cfg.ocr.min_text_height_px = self._clamp_int(cfg.ocr.min_text_height_px, 1, 100)
        cfg.ocr.max_text_height_px = self._clamp_int(cfg.ocr.max_text_height_px, cfg.ocr.min_text_height_px, 1000)
        cfg.ocr.max_image_megapixels = self._clamp_float(cfg.ocr.max_image_megapixels, 0.1, 64.0)
        cfg.ocr.max_rotation_degrees = self._clamp_float(cfg.ocr.max_rotation_degrees, 0.0, 45.0)

        cfg.ui.platform_hint = self._enum_value(cfg.ui.platform_hint, UIPlatformHint, UIPlatformHint.UNKNOWN.value)
        cfg.ui.min_element_confidence = self._clamp_float(cfg.ui.min_element_confidence, 0.0, 1.0)
        cfg.ui.min_button_confidence = self._clamp_float(cfg.ui.min_button_confidence, 0.0, 1.0)
        cfg.ui.min_input_confidence = self._clamp_float(cfg.ui.min_input_confidence, 0.0, 1.0)
        cfg.ui.min_icon_confidence = self._clamp_float(cfg.ui.min_icon_confidence, 0.0, 1.0)
        cfg.ui.min_label_confidence = self._clamp_float(cfg.ui.min_label_confidence, 0.0, 1.0)
        cfg.ui.min_clickable_area_px = self._clamp_int(cfg.ui.min_clickable_area_px, 1, 500)
        cfg.ui.max_clickable_area_ratio = self._clamp_float(cfg.ui.max_clickable_area_ratio, 0.01, 1.0)
        cfg.ui.max_component_overlap_ratio = self._clamp_float(cfg.ui.max_component_overlap_ratio, 0.0, 1.0)
        cfg.ui.disabled_opacity_threshold = self._clamp_float(cfg.ui.disabled_opacity_threshold, 0.0, 1.0)

        cfg.screenshot_privacy.privacy_mode = self._enum_value(
            cfg.screenshot_privacy.privacy_mode,
            ScreenshotPrivacyMode,
            ScreenshotPrivacyMode.REDACT_SENSITIVE.value,
        )
        cfg.screenshot_privacy.screenshot_ttl_seconds = self._clamp_int(cfg.screenshot_privacy.screenshot_ttl_seconds, 60, 86400)
        cfg.screenshot_privacy.max_screenshot_width_px = self._clamp_int(cfg.screenshot_privacy.max_screenshot_width_px, 320, 7680)
        cfg.screenshot_privacy.max_screenshot_height_px = self._clamp_int(cfg.screenshot_privacy.max_screenshot_height_px, 240, 4320)
        cfg.screenshot_privacy.max_screenshot_megapixels = self._clamp_float(cfg.screenshot_privacy.max_screenshot_megapixels, 0.1, 16.0)

        cfg.redaction.mode = self._enum_value(cfg.redaction.mode, RedactionMode, RedactionMode.STRICT.value)
        cfg.redaction.redact_min_confidence = self._clamp_float(cfg.redaction.redact_min_confidence, 0.0, 1.0)
        cfg.redaction.face_redaction_min_confidence = self._clamp_float(cfg.redaction.face_redaction_min_confidence, 0.0, 1.0)
        cfg.redaction.sensitive_text_padding_px = self._clamp_int(cfg.redaction.sensitive_text_padding_px, 0, 80)
        cfg.redaction.sensitive_region_padding_px = self._clamp_int(cfg.redaction.sensitive_region_padding_px, 0, 120)
        cfg.redaction.safe_preview_max_chars = self._clamp_int(cfg.redaction.safe_preview_max_chars, 0, 1000)

        cfg.video.sampling_mode = self._enum_value(cfg.video.sampling_mode, VideoSamplingMode, VideoSamplingMode.HYBRID.value)
        cfg.video.max_video_duration_seconds = self._clamp_int(cfg.video.max_video_duration_seconds, 1, 3600)
        cfg.video.max_video_file_mb = self._clamp_int(cfg.video.max_video_file_mb, 1, 4096)
        cfg.video.max_frames_total = self._clamp_int(cfg.video.max_frames_total, 1, 5000)
        cfg.video.max_frames_per_minute = self._clamp_int(cfg.video.max_frames_per_minute, 1, 1800)
        cfg.video.min_seconds_between_frames = self._clamp_float(cfg.video.min_seconds_between_frames, 0.01, 60.0)
        cfg.video.scene_change_threshold = self._clamp_float(cfg.video.scene_change_threshold, 0.01, 1.0)
        cfg.video.duplicate_frame_similarity_threshold = self._clamp_float(cfg.video.duplicate_frame_similarity_threshold, 0.50, 1.0)
        cfg.video.keyframe_min_difference_threshold = self._clamp_float(cfg.video.keyframe_min_difference_threshold, 0.01, 1.0)
        cfg.video.max_frame_width_px = self._clamp_int(cfg.video.max_frame_width_px, 160, 7680)
        cfg.video.max_frame_height_px = self._clamp_int(cfg.video.max_frame_height_px, 120, 4320)
        cfg.video.max_frame_megapixels = self._clamp_float(cfg.video.max_frame_megapixels, 0.1, 16.0)
        cfg.video.frame_ttl_seconds = self._clamp_int(cfg.video.frame_ttl_seconds, 60, 86400)

        cfg.image_analysis.max_image_file_mb = self._clamp_int(cfg.image_analysis.max_image_file_mb, 1, 1024)
        cfg.image_analysis.max_image_width_px = self._clamp_int(cfg.image_analysis.max_image_width_px, 320, 16384)
        cfg.image_analysis.max_image_height_px = self._clamp_int(cfg.image_analysis.max_image_height_px, 240, 16384)
        cfg.image_analysis.max_image_megapixels = self._clamp_float(cfg.image_analysis.max_image_megapixels, 0.1, 64.0)
        cfg.image_analysis.min_object_confidence = self._clamp_float(cfg.image_analysis.min_object_confidence, 0.0, 1.0)
        cfg.image_analysis.min_layout_confidence = self._clamp_float(cfg.image_analysis.min_layout_confidence, 0.0, 1.0)
        cfg.image_analysis.min_design_issue_confidence = self._clamp_float(cfg.image_analysis.min_design_issue_confidence, 0.0, 1.0)

        cfg.annotation.max_annotations_per_image = self._clamp_int(cfg.annotation.max_annotations_per_image, 0, 5000)
        cfg.annotation.min_annotation_confidence = self._clamp_float(cfg.annotation.min_annotation_confidence, 0.0, 1.0)
        cfg.annotation.label_max_chars = self._clamp_int(cfg.annotation.label_max_chars, 1, 300)
        cfg.annotation.box_thickness_px = self._clamp_int(cfg.annotation.box_thickness_px, 1, 20)
        cfg.annotation.text_padding_px = self._clamp_int(cfg.annotation.text_padding_px, 0, 50)
        cfg.annotation.export_format = str(cfg.annotation.export_format or "png").lower()
        if cfg.annotation.export_format not in {"png", "jpg", "jpeg", "webp"}:
            cfg.annotation.export_format = "png"

        cfg.workflow_learning.min_step_confidence = self._clamp_float(cfg.workflow_learning.min_step_confidence, 0.0, 1.0)
        cfg.workflow_learning.min_transition_confidence = self._clamp_float(cfg.workflow_learning.min_transition_confidence, 0.0, 1.0)
        cfg.workflow_learning.max_steps_per_workflow = self._clamp_int(cfg.workflow_learning.max_steps_per_workflow, 1, 2000)
        cfg.workflow_learning.max_idle_gap_seconds = self._clamp_int(cfg.workflow_learning.max_idle_gap_seconds, 1, 3600)
        cfg.workflow_learning.merge_similar_steps_threshold = self._clamp_float(cfg.workflow_learning.merge_similar_steps_threshold, 0.0, 1.0)

        cfg.visual_memory.pattern_similarity_threshold = self._clamp_float(cfg.visual_memory.pattern_similarity_threshold, 0.0, 1.0)
        cfg.visual_memory.max_patterns_per_workspace = self._clamp_int(cfg.visual_memory.max_patterns_per_workspace, 0, 100000)
        cfg.visual_memory.max_patterns_per_user = self._clamp_int(cfg.visual_memory.max_patterns_per_user, 0, 500000)
        cfg.visual_memory.memory_ttl_days = self._clamp_int(cfg.visual_memory.memory_ttl_days, 1, 3650)

        cfg.storage.max_workspace_storage_mb = self._clamp_int(cfg.storage.max_workspace_storage_mb, 1, 102400)
        cfg.storage.max_user_storage_mb = self._clamp_int(cfg.storage.max_user_storage_mb, 1, 1024000)
        cfg.storage.temporary_artifact_ttl_seconds = self._clamp_int(cfg.storage.temporary_artifact_ttl_seconds, 60, 86400)

        cfg.dashboard.max_override_keys_per_request = self._clamp_int(cfg.dashboard.max_override_keys_per_request, 1, 500)

        self._enforce_hard_safety_rules(cfg)

    def _enforce_hard_safety_rules(self, cfg: VisualConfigData) -> None:
        """Hard safety rules that cannot be weakened by ordinary config."""

        cfg.storage.enforce_user_workspace_partition = True
        cfg.storage.allow_cross_workspace_reads = False
        cfg.storage.allow_cross_user_reads = False

        if cfg.screenshot_privacy.privacy_mode == ScreenshotPrivacyMode.DISABLED.value:
            cfg.screenshot_privacy.privacy_mode = ScreenshotPrivacyMode.REDACT_SENSITIVE.value

        if cfg.redaction.mode == RedactionMode.OFF.value:
            cfg.redaction.mode = RedactionMode.BALANCED.value

        if cfg.screenshot_privacy.store_raw_screenshots:
            cfg.screenshot_privacy.store_redacted_screenshots = True

        if cfg.video.store_extracted_frames:
            cfg.video.store_redacted_frames = True

        if cfg.workflow_learning.store_raw_step_images:
            cfg.workflow_learning.store_redacted_step_images = True

        if cfg.visual_memory.store_raw_images:
            cfg.visual_memory.store_redacted_images = True

        cfg.screenshot_privacy.block_hidden_or_background_capture = True
        cfg.screenshot_privacy.require_user_workspace_context = True
        cfg.workflow_learning.require_user_workspace_context = True
        cfg.visual_memory.require_redaction_before_memory = True
        cfg.image_analysis.require_redaction_before_export = True

    def _collect_config_issues(self, cfg: VisualConfigData) -> Tuple[List[str], List[str]]:
        """Collect validation issues and warnings."""

        issues: List[str] = []
        warnings: List[str] = []

        if cfg.profile not in {item.value for item in VisualConfigProfile}:
            issues.append("profile is invalid.")

        if cfg.storage.allow_cross_workspace_reads:
            issues.append("cross-workspace reads are not allowed.")
        if cfg.storage.allow_cross_user_reads:
            issues.append("cross-user reads are not allowed.")
        if not cfg.storage.enforce_user_workspace_partition:
            issues.append("user/workspace partition enforcement must stay enabled.")

        if cfg.screenshot_privacy.privacy_mode == ScreenshotPrivacyMode.DISABLED.value:
            issues.append("screenshot privacy mode cannot be disabled.")
        if not cfg.screenshot_privacy.block_hidden_or_background_capture:
            issues.append("hidden/background capture blocking must stay enabled.")
        if not cfg.screenshot_privacy.require_user_workspace_context:
            issues.append("screenshot operations must require user/workspace context.")

        if cfg.redaction.mode == RedactionMode.OFF.value:
            issues.append("redaction mode cannot be off.")
        if not cfg.redaction.redact_passwords:
            warnings.append("password redaction is disabled; this is not recommended.")
        if not cfg.redaction.redact_api_keys:
            warnings.append("API key redaction is disabled; this is not recommended.")
        if not cfg.redaction.redact_tokens:
            warnings.append("token redaction is disabled; this is not recommended.")
        if not cfg.redaction.redact_payment_cards:
            warnings.append("payment card redaction is disabled; this is not recommended.")

        if cfg.screenshot_privacy.store_raw_screenshots:
            warnings.append("raw screenshot storage is enabled; use only with explicit approval.")
        if cfg.video.store_extracted_frames:
            warnings.append("raw extracted video frame storage is enabled; use only with explicit approval.")
        if cfg.visual_memory.store_raw_images:
            warnings.append("raw visual memory image storage is enabled; use only with explicit approval.")

        for pattern in cfg.redaction.sensitive_regex_patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                issues.append(f"invalid sensitive regex pattern: {pattern} | {exc}")

        return issues, warnings

    # ------------------------------------------------------------------
    # Config merge/serialization helpers
    # ------------------------------------------------------------------

    def _get_active_config(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> VisualConfigData:
        """Return workspace override config if available, otherwise global config."""

        if user_id and workspace_id:
            key = self._workspace_key(user_id, workspace_id)
            if key in self._workspace_overrides:
                return self._copy_config(self._workspace_overrides[key])
        return self._copy_config(self.config)

    def _copy_config(self, cfg: VisualConfigData) -> VisualConfigData:
        """Deep copy config tree."""

        return copy.deepcopy(cfg)

    def _merge_dict_into_config(
        self,
        cfg: VisualConfigData,
        overrides: Mapping[str, Any],
    ) -> VisualConfigData:
        """Merge nested or dot-path dict overrides into config dataclass."""

        updated = self._copy_config(cfg)
        flat = self._flatten_mapping(overrides)

        for dot_key, value in flat.items():
            if dot_key == "profile":
                updated.profile = self._normalize_profile(value)
                continue

            parts = dot_key.split(".")
            if len(parts) != 2:
                continue

            section_name, field_name = parts
            section = getattr(updated, section_name, None)
            if section is None or not is_dataclass(section):
                continue

            valid_fields = {item.name for item in fields(section)}
            if field_name not in valid_fields:
                continue

            current_value = getattr(section, field_name)
            setattr(section, field_name, self._coerce_value(value, current_value))

        self._validate_and_repair_config(updated)
        return updated

    def _flatten_mapping(
        self,
        mapping: Mapping[str, Any],
        parent_key: str = "",
    ) -> Dict[str, Any]:
        """Flatten nested mapping into dot-path keys."""

        flat: Dict[str, Any] = {}

        for key, value in mapping.items():
            str_key = str(key).strip()
            full_key = f"{parent_key}.{str_key}" if parent_key else str_key

            if isinstance(value, Mapping) and "." not in str_key:
                flat.update(self._flatten_mapping(value, full_key))
            else:
                flat[full_key] = value

        return flat

    def _detect_sensitive_override_keys(self, flat_overrides: Mapping[str, Any]) -> set:
        """Detect override keys that require security approval."""

        unsafe = set()

        for key, value in flat_overrides.items():
            if key in self.SENSITIVE_OVERRIDE_KEYS:
                unsafe.add(key)

            if key in self.RAW_STORAGE_KEYS and bool(value):
                unsafe.add(key)

            if key in {"storage.allow_cross_workspace_reads", "storage.allow_cross_user_reads"} and bool(value):
                unsafe.add(key)

            if key == "redaction.mode" and str(value).lower() in {RedactionMode.MINIMAL.value, RedactionMode.OFF.value}:
                unsafe.add(key)

            if key == "screenshot_privacy.privacy_mode" and str(value).lower() in {
                ScreenshotPrivacyMode.DISABLED.value,
                ScreenshotPrivacyMode.METADATA_ONLY.value,
            }:
                unsafe.add(key)

            if key.startswith("redaction.redact_") and value is False:
                unsafe.add(key)

            if key.startswith("screenshot_privacy.allow_") and value is True:
                unsafe.add(key)

        return unsafe

    def _config_to_dict(
        self,
        cfg: VisualConfigData,
        *,
        include_sensitive: bool = False,
    ) -> Dict[str, Any]:
        """Serialize config to dict, optionally hiding sensitive regex patterns."""

        data = asdict(cfg)

        if not include_sensitive:
            try:
                data["redaction"]["sensitive_regex_patterns"] = [
                    "[hidden_sensitive_pattern]"
                    for _ in data["redaction"].get("sensitive_regex_patterns", [])
                ]
            except Exception:
                pass

        return data

    # ------------------------------------------------------------------
    # Context and utility helpers
    # ------------------------------------------------------------------

    def _validate_optional_context(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> Dict[str, Any]:
        """Validate optional context when caller may be global/internal."""

        if user_id is None and workspace_id is None:
            return self._safe_result(message="Optional context is valid.", data={})

        if not isinstance(user_id, str) or not user_id.strip():
            return self._error_result(
                message="user_id is required when workspace_id is provided.",
                error={"code": "invalid_user_id"},
            )

        if not isinstance(workspace_id, str) or not workspace_id.strip():
            return self._error_result(
                message="workspace_id is required when user_id is provided.",
                error={"code": "invalid_workspace_id"},
            )

        return self._safe_result(
            message="Optional context is valid.",
            data={"user_id": user_id.strip(), "workspace_id": workspace_id.strip()},
        )

    def _workspace_key(self, user_id: str, workspace_id: str) -> str:
        """SaaS isolation key."""

        return f"{user_id.strip()}::{workspace_id.strip()}"

    def _base_metadata(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Base result metadata."""

        return {
            "agent": self.agent_id,
            "agent_name": self.agent_name,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "timestamp": self._utc_now_iso(),
        }

    def _safe_preview(self, value: Any, limit: int = 1500) -> str:
        """Bounded preview for logs/results."""

        try:
            text = str(value)
        except Exception:
            text = repr(value)
        return text[:limit]

    def _coerce_value(self, value: Any, current_value: Any) -> Any:
        """Coerce override value to current field type."""

        if isinstance(current_value, bool):
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "y", "on"}
            return bool(value)

        if isinstance(current_value, int) and not isinstance(current_value, bool):
            try:
                return int(value)
            except Exception:
                return current_value

        if isinstance(current_value, float):
            try:
                return float(value)
            except Exception:
                return current_value

        if isinstance(current_value, tuple):
            if isinstance(value, str):
                return tuple(item.strip() for item in value.split(",") if item.strip())
            if isinstance(value, list):
                return tuple(str(item) for item in value)
            if isinstance(value, tuple):
                return value
            return current_value

        if isinstance(current_value, list):
            if isinstance(value, str):
                return [item.strip() for item in value.split(",") if item.strip()]
            if isinstance(value, (list, tuple)):
                return list(value)
            return current_value

        return str(value) if current_value is not None else value

    def _parse_env_value(self, value: str) -> Any:
        """Parse environment variable string into bool/int/float/string."""

        stripped = value.strip()
        lowered = stripped.lower()

        if lowered in {"true", "yes", "y", "1", "on"}:
            return True
        if lowered in {"false", "no", "n", "0", "off"}:
            return False

        try:
            if "." in stripped:
                return float(stripped)
            return int(stripped)
        except Exception:
            return stripped

    def _enum_value(self, value: Any, enum_cls: Any, default: str) -> str:
        """Normalize enum string value."""

        allowed = {item.value for item in enum_cls}
        normalized = str(value).strip().lower()
        return normalized if normalized in allowed else default

    def _clamp_int(self, value: Any, minimum: int, maximum: int) -> int:
        """Clamp int safely."""

        try:
            numeric = int(value)
        except Exception:
            numeric = minimum
        return max(minimum, min(maximum, numeric))

    def _clamp_float(self, value: Any, minimum: float, maximum: float) -> float:
        """Clamp float safely."""

        try:
            numeric = float(value)
        except Exception:
            numeric = minimum
        return max(minimum, min(maximum, numeric))

    def _new_id(self, prefix: str) -> str:
        """Generate safe unique ID."""

        return f"{prefix}_{uuid.uuid4().hex}"

    def _utc_now_iso(self) -> str:
        """Current UTC timestamp."""

        return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Factory and module-level exports
# ---------------------------------------------------------------------------

def create_visual_config(
    profile: Union[str, VisualConfigProfile] = VisualConfigProfile.BALANCED,
    security_agent: Optional[Any] = None,
    **kwargs: Any,
) -> VisualConfig:
    """
    Factory for Agent Loader / Registry.

    Example:
        config = create_visual_config(profile="strict_privacy")
    """

    return VisualConfig(profile=profile, security_agent=security_agent, **kwargs)


DEFAULT_VISUAL_CONFIG = VisualConfig()


__all__ = [
    "VisualConfig",
    "VisualConfigData",
    "OCRThresholdConfig",
    "UIThresholdConfig",
    "ScreenshotPrivacyConfig",
    "RedactionConfig",
    "VideoLimitConfig",
    "ImageAnalysisConfig",
    "AnnotationConfig",
    "WorkflowLearningConfig",
    "VisualMemoryConfig",
    "StorageConfig",
    "DashboardConfig",
    "VisualConfigProfile",
    "ScreenshotPrivacyMode",
    "RedactionMode",
    "VideoSamplingMode",
    "OCRBackend",
    "UIPlatformHint",
    "create_visual_config",
    "DEFAULT_VISUAL_CONFIG",
]