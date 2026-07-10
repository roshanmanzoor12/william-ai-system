"""
apps/worker_nodes/windows/screen_capture.py

Permission-based screenshot and UI proof module for the William / Jarvis
Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    - Capture Windows screenshots only after permission and isolation checks.
    - Produce UI proof artifacts for completed worker actions.
    - Prepare Security Agent, Memory Agent, Audit Log, and Verification Agent payloads.
    - Avoid unsafe cross-user or cross-workspace access.
    - Import safely even when optional screenshot libraries are missing.

Optional screenshot backends:
    1. mss + Pillow        Recommended
    2. Pillow ImageGrab    Fallback on Windows/macOS if available

Security posture:
    - Screenshots are treated as sensitive.
    - Every capture requires user_id and workspace_id.
    - High-risk captures require security approval unless explicitly configured otherwise.
    - File paths are constrained to a configured proof directory.
    - Sensitive text is not OCR-read here; this module avoids OCR by design.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import socket
import time
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple


try:
    from PIL import Image, ImageDraw, ImageGrab  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    Image = None
    ImageDraw = None
    ImageGrab = None


try:
    import mss  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    mss = None


JSONDict = Dict[str, Any]


class ScreenCaptureStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    DENIED = "denied"
    NEEDS_APPROVAL = "needs_approval"
    SKIPPED = "skipped"


class ScreenCaptureRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScreenCaptureMode(str, Enum):
    FULL_SCREEN = "full_screen"
    REGION = "region"
    ACTIVE_WINDOW = "active_window"


class ScreenCaptureFormat(str, Enum):
    PNG = "png"
    JPEG = "jpeg"
    WEBP = "webp"


class ScreenCapturePermission(str, Enum):
    SCREEN_CAPTURE = "screen.capture"
    SCREEN_CAPTURE_REGION = "screen.capture.region"
    SCREEN_CAPTURE_FULL = "screen.capture.full"
    UI_PROOF_CREATE = "ui_proof.create"
    FILES_WRITE = "files.write"
    SECURITY_APPROVE = "security.approve"


@dataclass
class ScreenCaptureConfig:
    """
    Runtime configuration for permission-based screenshot capture.

    Environment fallbacks:
        WILLIAM_SCREEN_CAPTURE_DIR
        WILLIAM_SCREEN_CAPTURE_REQUIRE_APPROVAL
        WILLIAM_SCREEN_CAPTURE_MAX_WIDTH
        WILLIAM_SCREEN_CAPTURE_MAX_HEIGHT
    """

    proof_dir: str = field(
        default_factory=lambda: os.getenv(
            "WILLIAM_SCREEN_CAPTURE_DIR",
            str(Path.cwd() / "runtime" / "ui_proofs"),
        )
    )
    require_security_approval: bool = field(
        default_factory=lambda: os.getenv("WILLIAM_SCREEN_CAPTURE_REQUIRE_APPROVAL", "true").lower()
        in {"1", "true", "yes", "on"}
    )
    max_width: int = field(default_factory=lambda: int(os.getenv("WILLIAM_SCREEN_CAPTURE_MAX_WIDTH", "7680")))
    max_height: int = field(default_factory=lambda: int(os.getenv("WILLIAM_SCREEN_CAPTURE_MAX_HEIGHT", "4320")))
    default_format: ScreenCaptureFormat = ScreenCaptureFormat.PNG
    include_base64_preview: bool = False
    preview_max_bytes: int = 512_000
    jpeg_quality: int = 88
    webp_quality: int = 88
    redact_regions_by_default: bool = False
    watermark_proofs: bool = True
    allow_full_screen: bool = True
    allow_region: bool = True
    allow_active_window: bool = False
    metadata: JSONDict = field(default_factory=dict)

    def normalized(self) -> "ScreenCaptureConfig":
        proof_dir = str(self.proof_dir or "").strip() or str(Path.cwd() / "runtime" / "ui_proofs")
        return ScreenCaptureConfig(
            proof_dir=proof_dir,
            require_security_approval=bool(self.require_security_approval),
            max_width=max(100, int(self.max_width)),
            max_height=max(100, int(self.max_height)),
            default_format=self.default_format,
            include_base64_preview=bool(self.include_base64_preview),
            preview_max_bytes=max(10_000, int(self.preview_max_bytes)),
            jpeg_quality=min(100, max(1, int(self.jpeg_quality))),
            webp_quality=min(100, max(1, int(self.webp_quality))),
            redact_regions_by_default=bool(self.redact_regions_by_default),
            watermark_proofs=bool(self.watermark_proofs),
            allow_full_screen=bool(self.allow_full_screen),
            allow_region=bool(self.allow_region),
            allow_active_window=bool(self.allow_active_window),
            metadata=dict(self.metadata or {}),
        )


@dataclass
class CaptureRegion:
    left: int
    top: int
    width: int
    height: int

    def validate(self) -> List[JSONDict]:
        errors: List[JSONDict] = []

        if self.left < 0:
            errors.append({"field": "left", "error": "must_be_greater_than_or_equal_to_zero"})

        if self.top < 0:
            errors.append({"field": "top", "error": "must_be_greater_than_or_equal_to_zero"})

        if self.width <= 0:
            errors.append({"field": "width", "error": "must_be_greater_than_zero"})

        if self.height <= 0:
            errors.append({"field": "height", "error": "must_be_greater_than_zero"})

        return errors

    def to_dict(self) -> JSONDict:
        return asdict(self)


@dataclass
class RedactionRegion:
    left: int
    top: int
    width: int
    height: int
    label: str = "redacted"

    def validate(self) -> List[JSONDict]:
        return CaptureRegion(
            left=self.left,
            top=self.top,
            width=self.width,
            height=self.height,
        ).validate()

    def to_dict(self) -> JSONDict:
        return asdict(self)


@dataclass
class ScreenCaptureRequest:
    user_id: str
    workspace_id: str
    task_id: str
    requested_by_user_id: str
    mode: ScreenCaptureMode = ScreenCaptureMode.FULL_SCREEN
    reason: str = "UI proof capture"
    permissions: List[str] = field(default_factory=list)
    security_approval_id: Optional[str] = None
    region: Optional[CaptureRegion] = None
    redaction_regions: List[RedactionRegion] = field(default_factory=list)
    output_format: ScreenCaptureFormat = ScreenCaptureFormat.PNG
    include_base64_preview: Optional[bool] = None
    filename_prefix: str = "ui-proof"
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: JSONDict = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ScreenCaptureRequest":
        raw_mode = str(data.get("mode") or ScreenCaptureMode.FULL_SCREEN.value)
        raw_format = str(data.get("output_format") or data.get("format") or ScreenCaptureFormat.PNG.value)

        region_data = data.get("region")
        region = None
        if isinstance(region_data, Mapping):
            region = CaptureRegion(
                left=int(region_data.get("left", 0)),
                top=int(region_data.get("top", 0)),
                width=int(region_data.get("width", 0)),
                height=int(region_data.get("height", 0)),
            )

        redactions: List[RedactionRegion] = []
        raw_redactions = data.get("redaction_regions") or data.get("redactions") or []
        if isinstance(raw_redactions, list):
            for item in raw_redactions:
                if isinstance(item, Mapping):
                    redactions.append(
                        RedactionRegion(
                            left=int(item.get("left", 0)),
                            top=int(item.get("top", 0)),
                            width=int(item.get("width", 0)),
                            height=int(item.get("height", 0)),
                            label=str(item.get("label") or "redacted"),
                        )
                    )

        return cls(
            user_id=str(data.get("user_id") or ""),
            workspace_id=str(data.get("workspace_id") or ""),
            task_id=str(data.get("task_id") or data.get("id") or ""),
            requested_by_user_id=str(data.get("requested_by_user_id") or data.get("user_id") or ""),
            mode=ScreenCaptureMode(raw_mode) if raw_mode in ScreenCaptureMode._value2member_map_ else ScreenCaptureMode.FULL_SCREEN,
            reason=str(data.get("reason") or "UI proof capture"),
            permissions=list(data.get("permissions") or []),
            security_approval_id=data.get("security_approval_id"),
            region=region,
            redaction_regions=redactions,
            output_format=ScreenCaptureFormat(raw_format)
            if raw_format in ScreenCaptureFormat._value2member_map_
            else ScreenCaptureFormat.PNG,
            include_base64_preview=data.get("include_base64_preview"),
            filename_prefix=str(data.get("filename_prefix") or "ui-proof"),
            request_id=str(data.get("request_id") or str(uuid.uuid4())),
            metadata=dict(data.get("metadata") or {}),
        )

    def to_dict(self) -> JSONDict:
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": self.task_id,
            "requested_by_user_id": self.requested_by_user_id,
            "mode": self.mode.value,
            "reason": self.reason,
            "permissions": list(self.permissions),
            "security_approval_id": self.security_approval_id,
            "region": self.region.to_dict() if self.region else None,
            "redaction_regions": [region.to_dict() for region in self.redaction_regions],
            "output_format": self.output_format.value,
            "include_base64_preview": self.include_base64_preview,
            "filename_prefix": self.filename_prefix,
            "request_id": self.request_id,
            "metadata": dict(self.metadata),
        }


@dataclass
class ScreenCaptureResponse:
    ok: bool
    status: ScreenCaptureStatus
    message: str
    user_id: str
    workspace_id: str
    task_id: str
    request_id: str
    data: JSONDict = field(default_factory=dict)
    errors: List[JSONDict] = field(default_factory=list)
    audit_event: Optional[JSONDict] = None
    security_payload: Optional[JSONDict] = None
    memory_payload: Optional[JSONDict] = None
    verification_payload: Optional[JSONDict] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> JSONDict:
        output = asdict(self)
        output["status"] = self.status.value
        return output


class ScreenCapture:
    """
    Permission-based screenshot and UI proof capture utility.

    This class is intended to be called by Windows worker nodes after a backend
    task has already been assigned to the correct user_id and workspace_id.
    """

    MODULE_NAME = "ScreenCapture"
    VERSION = "1.0.0"

    def __init__(
        self,
        config: Optional[ScreenCaptureConfig] = None,
        worker_user_id: Optional[str] = None,
        worker_workspace_id: Optional[str] = None,
        device_id: Optional[str] = None,
        audit_logger: Optional[Callable[[JSONDict], Any]] = None,
        security_checker: Optional[Callable[[JSONDict], Any]] = None,
        memory_hook: Optional[Callable[[JSONDict], Any]] = None,
        verification_hook: Optional[Callable[[JSONDict], Any]] = None,
        logger: Optional[Callable[[str], Any]] = None,
    ) -> None:
        self.config = (config or ScreenCaptureConfig()).normalized()
        self.worker_user_id = worker_user_id or os.getenv("WILLIAM_WORKER_USER_ID", "")
        self.worker_workspace_id = worker_workspace_id or os.getenv("WILLIAM_WORKER_WORKSPACE_ID", "")
        self.device_id = device_id or os.getenv("WILLIAM_WORKER_DEVICE_ID", self._generate_device_id())
        self.audit_logger = audit_logger
        self.security_checker = security_checker
        self.memory_hook = memory_hook
        self.verification_hook = verification_hook
        self.logger = logger

    @staticmethod
    def now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def capture_ui_proof(self, request: ScreenCaptureRequest | Mapping[str, Any]) -> JSONDict:
        capture_request = (
            ScreenCaptureRequest.from_dict(request)
            if isinstance(request, Mapping)
            else request
        )

        started_at = self.now()
        audit_event = self.build_audit_event(
            action="screen_capture.requested",
            request=capture_request,
            risk_level=ScreenCaptureRiskLevel.HIGH,
            details={"mode": capture_request.mode.value, "reason": capture_request.reason},
        )
        security_payload = self.build_security_payload(capture_request)

        self._safe_hook(self.audit_logger, audit_event)

        validation_errors = self.validate_request(capture_request)
        if validation_errors:
            verification_payload = self.build_verification_payload(
                request=capture_request,
                status=ScreenCaptureStatus.DENIED,
                proof_data={},
                errors=validation_errors,
                started_at=started_at,
                finished_at=self.now(),
            )

            response = ScreenCaptureResponse(
                ok=False,
                status=ScreenCaptureStatus.DENIED,
                message="Screen capture request failed validation.",
                user_id=capture_request.user_id,
                workspace_id=capture_request.workspace_id,
                task_id=capture_request.task_id,
                request_id=capture_request.request_id,
                errors=validation_errors,
                audit_event=audit_event,
                security_payload=security_payload,
                verification_payload=verification_payload,
            )

            self._safe_hook(self.verification_hook, verification_payload)
            return response.to_dict()

        if self.config.require_security_approval and not capture_request.security_approval_id:
            if self.security_checker:
                decision = self._safe_hook(self.security_checker, security_payload)
                if self._security_denied(decision):
                    errors = [{"error": "security_agent_denied_capture", "decision": self._safe_json(decision)}]
                    verification_payload = self.build_verification_payload(
                        request=capture_request,
                        status=ScreenCaptureStatus.DENIED,
                        proof_data={},
                        errors=errors,
                        started_at=started_at,
                        finished_at=self.now(),
                    )
                    response = ScreenCaptureResponse(
                        ok=False,
                        status=ScreenCaptureStatus.DENIED,
                        message="Security Agent denied the screen capture request.",
                        user_id=capture_request.user_id,
                        workspace_id=capture_request.workspace_id,
                        task_id=capture_request.task_id,
                        request_id=capture_request.request_id,
                        errors=errors,
                        audit_event=audit_event,
                        security_payload=security_payload,
                        verification_payload=verification_payload,
                    )
                    self._safe_hook(self.verification_hook, verification_payload)
                    return response.to_dict()

                if self._security_approved(decision):
                    capture_request.security_approval_id = str(
                        decision.get("approval_id") or decision.get("security_approval_id") or capture_request.request_id
                    )
                else:
                    response = ScreenCaptureResponse(
                        ok=False,
                        status=ScreenCaptureStatus.NEEDS_APPROVAL,
                        message="Screen capture requires Security Agent approval.",
                        user_id=capture_request.user_id,
                        workspace_id=capture_request.workspace_id,
                        task_id=capture_request.task_id,
                        request_id=capture_request.request_id,
                        errors=[{"error": "missing_security_approval"}],
                        audit_event=audit_event,
                        security_payload=security_payload,
                    )
                    return response.to_dict()
            else:
                response = ScreenCaptureResponse(
                    ok=False,
                    status=ScreenCaptureStatus.NEEDS_APPROVAL,
                    message="Screen capture requires security approval before execution.",
                    user_id=capture_request.user_id,
                    workspace_id=capture_request.workspace_id,
                    task_id=capture_request.task_id,
                    request_id=capture_request.request_id,
                    errors=[{"error": "security_checker_not_configured"}],
                    audit_event=audit_event,
                    security_payload=security_payload,
                )
                return response.to_dict()

        try:
            image = self._capture_image(capture_request)

            if self.config.watermark_proofs:
                self._add_watermark(image, capture_request)

            if capture_request.redaction_regions:
                self._apply_redactions(image, capture_request.redaction_regions)
            elif self.config.redact_regions_by_default:
                self._apply_default_privacy_banner(image)

            proof_file = self._save_image(image, capture_request)
            proof_hash = self._sha256_file(proof_file)

            proof_data = self._build_proof_data(
                request=capture_request,
                file_path=proof_file,
                file_hash=proof_hash,
                image_size=image.size if hasattr(image, "size") else None,
            )

            include_preview = (
                capture_request.include_base64_preview
                if capture_request.include_base64_preview is not None
                else self.config.include_base64_preview
            )

            if include_preview:
                proof_data["base64_preview"] = self._base64_preview(proof_file)

            memory_payload = self.build_memory_payload(
                request=capture_request,
                proof_data=proof_data,
                summary="Permission-based UI proof screenshot captured.",
            )
            verification_payload = self.build_verification_payload(
                request=capture_request,
                status=ScreenCaptureStatus.SUCCESS,
                proof_data=proof_data,
                errors=[],
                started_at=started_at,
                finished_at=self.now(),
            )
            completed_audit_event = self.build_audit_event(
                action="screen_capture.completed",
                request=capture_request,
                risk_level=ScreenCaptureRiskLevel.HIGH,
                details={
                    "proof_file": str(proof_file),
                    "sha256": proof_hash,
                    "mode": capture_request.mode.value,
                },
            )

            self._safe_hook(self.audit_logger, completed_audit_event)
            self._safe_hook(self.memory_hook, memory_payload)
            self._safe_hook(self.verification_hook, verification_payload)

            response = ScreenCaptureResponse(
                ok=True,
                status=ScreenCaptureStatus.SUCCESS,
                message="UI proof screenshot captured successfully.",
                user_id=capture_request.user_id,
                workspace_id=capture_request.workspace_id,
                task_id=capture_request.task_id,
                request_id=capture_request.request_id,
                data=proof_data,
                audit_event=completed_audit_event,
                security_payload=security_payload,
                memory_payload=memory_payload,
                verification_payload=verification_payload,
            )
            return response.to_dict()

        except Exception as exc:
            safe_error = self._safe_error(exc)
            failed_audit_event = self.build_audit_event(
                action="screen_capture.failed",
                request=capture_request,
                risk_level=ScreenCaptureRiskLevel.HIGH,
                details={"error": safe_error},
            )
            verification_payload = self.build_verification_payload(
                request=capture_request,
                status=ScreenCaptureStatus.FAILED,
                proof_data={},
                errors=[safe_error],
                started_at=started_at,
                finished_at=self.now(),
            )

            self._safe_hook(self.audit_logger, failed_audit_event)
            self._safe_hook(self.verification_hook, verification_payload)

            response = ScreenCaptureResponse(
                ok=False,
                status=ScreenCaptureStatus.FAILED,
                message="Screen capture failed safely.",
                user_id=capture_request.user_id,
                workspace_id=capture_request.workspace_id,
                task_id=capture_request.task_id,
                request_id=capture_request.request_id,
                errors=[safe_error],
                audit_event=failed_audit_event,
                security_payload=security_payload,
                verification_payload=verification_payload,
            )
            return response.to_dict()

    def validate_request(self, request: ScreenCaptureRequest) -> List[JSONDict]:
        errors: List[JSONDict] = []

        if not request.user_id:
            errors.append({"field": "user_id", "error": "required"})

        if not request.workspace_id:
            errors.append({"field": "workspace_id", "error": "required"})

        if not request.task_id:
            errors.append({"field": "task_id", "error": "required"})

        if not request.requested_by_user_id:
            errors.append({"field": "requested_by_user_id", "error": "required"})

        if self.worker_user_id and request.user_id != self.worker_user_id:
            errors.append(
                {
                    "field": "user_id",
                    "error": "isolation_violation",
                    "detail": "Capture request user_id does not match worker user_id.",
                }
            )

        if self.worker_workspace_id and request.workspace_id != self.worker_workspace_id:
            errors.append(
                {
                    "field": "workspace_id",
                    "error": "isolation_violation",
                    "detail": "Capture request workspace_id does not match worker workspace_id.",
                }
            )

        required_permissions = self.required_permissions_for_mode(request.mode)
        missing_permissions = sorted(set(required_permissions) - set(request.permissions))
        if missing_permissions:
            errors.append(
                {
                    "field": "permissions",
                    "error": "missing_required_permissions",
                    "missing_permissions": missing_permissions,
                }
            )

        if request.mode == ScreenCaptureMode.FULL_SCREEN and not self.config.allow_full_screen:
            errors.append({"field": "mode", "error": "full_screen_capture_disabled"})

        if request.mode == ScreenCaptureMode.REGION and not self.config.allow_region:
            errors.append({"field": "mode", "error": "region_capture_disabled"})

        if request.mode == ScreenCaptureMode.ACTIVE_WINDOW and not self.config.allow_active_window:
            errors.append({"field": "mode", "error": "active_window_capture_disabled"})

        if request.mode == ScreenCaptureMode.REGION:
            if request.region is None:
                errors.append({"field": "region", "error": "required_for_region_capture"})
            else:
                errors.extend(request.region.validate())
                if request.region.width > self.config.max_width:
                    errors.append(
                        {
                            "field": "region.width",
                            "error": "exceeds_configured_max_width",
                            "max_width": self.config.max_width,
                        }
                    )
                if request.region.height > self.config.max_height:
                    errors.append(
                        {
                            "field": "region.height",
                            "error": "exceeds_configured_max_height",
                            "max_height": self.config.max_height,
                        }
                    )

        for index, redaction in enumerate(request.redaction_regions):
            redaction_errors = redaction.validate()
            for error in redaction_errors:
                error["field"] = f"redaction_regions[{index}].{error.get('field', '')}"
                errors.append(error)

        if request.output_format not in {
            ScreenCaptureFormat.PNG,
            ScreenCaptureFormat.JPEG,
            ScreenCaptureFormat.WEBP,
        }:
            errors.append({"field": "output_format", "error": "unsupported_format"})

        if platform.system().lower() != "windows":
            errors.append(
                {
                    "field": "platform",
                    "error": "unsupported_platform",
                    "detail": "This module is intended for Windows worker nodes.",
                    "current_platform": platform.system(),
                }
            )

        if Image is None and ImageGrab is None and mss is None:
            errors.append(
                {
                    "field": "dependencies",
                    "error": "missing_screenshot_backend",
                    "detail": "Install pillow and/or mss.",
                }
            )

        return errors

    def required_permissions_for_mode(self, mode: ScreenCaptureMode) -> Tuple[str, ...]:
        base = (
            ScreenCapturePermission.SCREEN_CAPTURE.value,
            ScreenCapturePermission.UI_PROOF_CREATE.value,
            ScreenCapturePermission.FILES_WRITE.value,
        )

        if mode == ScreenCaptureMode.FULL_SCREEN:
            return base + (ScreenCapturePermission.SCREEN_CAPTURE_FULL.value,)

        if mode == ScreenCaptureMode.REGION:
            return base + (ScreenCapturePermission.SCREEN_CAPTURE_REGION.value,)

        if mode == ScreenCaptureMode.ACTIVE_WINDOW:
            return base + (ScreenCapturePermission.SCREEN_CAPTURE_REGION.value,)

        return base

    def build_audit_event(
        self,
        action: str,
        request: ScreenCaptureRequest,
        risk_level: ScreenCaptureRiskLevel,
        details: Optional[JSONDict] = None,
    ) -> JSONDict:
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": "audit",
            "source": "apps.worker_nodes.windows.screen_capture",
            "module": self.MODULE_NAME,
            "version": self.VERSION,
            "action": action,
            "risk_level": risk_level.value,
            "device_id": self.device_id,
            "hostname": socket.gethostname(),
            "actor_user_id": request.requested_by_user_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "task_id": request.task_id,
            "request_id": request.request_id,
            "created_at": self.now(),
            "details": self._redact_sensitive_dict(details or {}),
        }

    def build_security_payload(self, request: ScreenCaptureRequest) -> JSONDict:
        return {
            "security_request_id": str(uuid.uuid4()),
            "source": "apps.worker_nodes.windows.screen_capture",
            "module": self.MODULE_NAME,
            "version": self.VERSION,
            "recommended_agent": "security",
            "action": "permission_based_screen_capture",
            "risk_level": ScreenCaptureRiskLevel.HIGH.value,
            "requires_approval": self.config.require_security_approval,
            "security_approval_id": request.security_approval_id,
            "reason": request.reason,
            "device_id": self.device_id,
            "hostname": socket.gethostname(),
            "actor_user_id": request.requested_by_user_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "task_id": request.task_id,
            "request_id": request.request_id,
            "mode": request.mode.value,
            "permissions_present": list(request.permissions),
            "permissions_required": list(self.required_permissions_for_mode(request.mode)),
            "created_at": self.now(),
            "policy": {
                "must_match_worker_user_id": True,
                "must_match_worker_workspace_id": True,
                "must_have_explicit_permission": True,
                "must_prepare_audit_event": True,
                "must_prepare_verification_payload": True,
            },
        }

    def build_memory_payload(
        self,
        request: ScreenCaptureRequest,
        proof_data: JSONDict,
        summary: str,
    ) -> JSONDict:
        return {
            "memory_event_id": str(uuid.uuid4()),
            "source": "apps.worker_nodes.windows.screen_capture",
            "module": self.MODULE_NAME,
            "recommended_agent": "memory",
            "memory_scope": "workspace",
            "safe_to_store": True,
            "summary": summary,
            "device_id": self.device_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "task_id": request.task_id,
            "request_id": request.request_id,
            "created_at": self.now(),
            "payload": {
                "proof_id": proof_data.get("proof_id"),
                "file_name": proof_data.get("file_name"),
                "sha256": proof_data.get("sha256"),
                "mode": proof_data.get("mode"),
                "captured_at": proof_data.get("captured_at"),
                "reason": request.reason,
            },
        }

    def build_verification_payload(
        self,
        request: ScreenCaptureRequest,
        status: ScreenCaptureStatus,
        proof_data: JSONDict,
        errors: List[JSONDict],
        started_at: str,
        finished_at: str,
    ) -> JSONDict:
        return {
            "verification_id": str(uuid.uuid4()),
            "source": "apps.worker_nodes.windows.screen_capture",
            "module": self.MODULE_NAME,
            "recommended_agent": "verification",
            "status": status.value,
            "device_id": self.device_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "task_id": request.task_id,
            "request_id": request.request_id,
            "created_at": self.now(),
            "started_at": started_at,
            "finished_at": finished_at,
            "checks": {
                "user_id_present": bool(request.user_id),
                "workspace_id_present": bool(request.workspace_id),
                "task_id_present": bool(request.task_id),
                "worker_user_match": not self.worker_user_id or request.user_id == self.worker_user_id,
                "worker_workspace_match": not self.worker_workspace_id
                or request.workspace_id == self.worker_workspace_id,
                "permission_checked": True,
                "security_payload_prepared": True,
                "audit_payload_prepared": True,
                "memory_payload_compatible": True,
                "file_hash_created": bool(proof_data.get("sha256")),
                "errors_empty": not bool(errors),
            },
            "proof": self._redact_sensitive_dict(proof_data),
            "errors": errors,
        }

    def _capture_image(self, request: ScreenCaptureRequest) -> Any:
        if request.mode == ScreenCaptureMode.REGION:
            return self._capture_region(request.region)

        if request.mode == ScreenCaptureMode.ACTIVE_WINDOW:
            raise RuntimeError(
                "Active window capture is disabled in this safe base module. Use region capture with explicit coordinates."
            )

        return self._capture_full_screen()

    def _capture_full_screen(self) -> Any:
        if mss is not None and Image is not None:
            with mss.mss() as screen:
                monitor = screen.monitors[1]
                shot = screen.grab(monitor)
                return Image.frombytes("RGB", shot.size, shot.rgb)

        if ImageGrab is not None:
            return ImageGrab.grab()

        raise RuntimeError("No screenshot backend available. Install pillow and/or mss.")

    def _capture_region(self, region: Optional[CaptureRegion]) -> Any:
        if region is None:
            raise ValueError("Region is required for region capture.")

        if mss is not None and Image is not None:
            with mss.mss() as screen:
                monitor = {
                    "left": region.left,
                    "top": region.top,
                    "width": region.width,
                    "height": region.height,
                }
                shot = screen.grab(monitor)
                return Image.frombytes("RGB", shot.size, shot.rgb)

        if ImageGrab is not None:
            box = (
                region.left,
                region.top,
                region.left + region.width,
                region.top + region.height,
            )
            return ImageGrab.grab(bbox=box)

        raise RuntimeError("No screenshot backend available. Install pillow and/or mss.")

    def _save_image(self, image: Any, request: ScreenCaptureRequest) -> Path:
        proof_dir = self._safe_proof_directory(request)
        proof_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        extension = request.output_format.value
        safe_prefix = self._safe_filename_part(request.filename_prefix or "ui-proof")
        file_name = f"{safe_prefix}-{timestamp}-{request.task_id}-{request.request_id}.{extension}"
        file_name = self._safe_filename_part(file_name, allow_dot=True)
        file_path = proof_dir / file_name

        if not self._is_path_inside(file_path, proof_dir):
            raise RuntimeError("Unsafe proof file path blocked.")

        save_kwargs: JSONDict = {}

        if request.output_format == ScreenCaptureFormat.JPEG:
            if hasattr(image, "convert"):
                image = image.convert("RGB")
            save_kwargs["quality"] = self.config.jpeg_quality
            save_format = "JPEG"
        elif request.output_format == ScreenCaptureFormat.WEBP:
            save_kwargs["quality"] = self.config.webp_quality
            save_format = "WEBP"
        else:
            save_format = "PNG"

        image.save(str(file_path), format=save_format, **save_kwargs)
        return file_path

    def _safe_proof_directory(self, request: ScreenCaptureRequest) -> Path:
        base = Path(self.config.proof_dir).expanduser().resolve()
        workspace_part = self._safe_filename_part(request.workspace_id)
        user_part = self._safe_filename_part(request.user_id)
        return (base / workspace_part / user_part).resolve()

    def _build_proof_data(
        self,
        request: ScreenCaptureRequest,
        file_path: Path,
        file_hash: str,
        image_size: Optional[Tuple[int, int]],
    ) -> JSONDict:
        stat = file_path.stat()
        return {
            "proof_id": str(uuid.uuid4()),
            "device_id": self.device_id,
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "task_id": request.task_id,
            "request_id": request.request_id,
            "mode": request.mode.value,
            "reason": request.reason,
            "file_path": str(file_path),
            "file_name": file_path.name,
            "file_size_bytes": stat.st_size,
            "sha256": file_hash,
            "output_format": request.output_format.value,
            "width": image_size[0] if image_size else None,
            "height": image_size[1] if image_size else None,
            "redaction_count": len(request.redaction_regions),
            "captured_at": self.now(),
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "machine": platform.machine(),
                "hostname": socket.gethostname(),
            },
            "metadata": self._redact_sensitive_dict(request.metadata),
        }

    def _apply_redactions(self, image: Any, redaction_regions: List[RedactionRegion]) -> None:
        if ImageDraw is None:
            raise RuntimeError("Pillow ImageDraw is required for redaction.")

        draw = ImageDraw.Draw(image)
        for region in redaction_regions:
            box = (
                region.left,
                region.top,
                region.left + region.width,
                region.top + region.height,
            )
            draw.rectangle(box, fill=(0, 0, 0))

    def _apply_default_privacy_banner(self, image: Any) -> None:
        if ImageDraw is None:
            return

        draw = ImageDraw.Draw(image)
        width, _height = image.size
        banner_height = 36
        draw.rectangle((0, 0, width, banner_height), fill=(0, 0, 0))
        draw.text((12, 10), "William/Jarvis UI Proof - Privacy Protected", fill=(255, 255, 255))

    def _add_watermark(self, image: Any, request: ScreenCaptureRequest) -> None:
        if ImageDraw is None:
            return

        draw = ImageDraw.Draw(image)
        width, height = image.size
        text = f"William/Jarvis UI Proof | task={request.task_id} | workspace={request.workspace_id}"
        box_height = 30
        y = max(0, height - box_height)
        draw.rectangle((0, y, width, height), fill=(0, 0, 0))
        draw.text((10, y + 8), text[:160], fill=(255, 255, 255))

    @staticmethod
    def _sha256_file(file_path: Path) -> str:
        digest = hashlib.sha256()
        with file_path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _base64_preview(self, file_path: Path) -> Optional[str]:
        try:
            if file_path.stat().st_size > self.config.preview_max_bytes:
                return None
            with file_path.open("rb") as file:
                encoded = base64.b64encode(file.read()).decode("ascii")
            return encoded
        except Exception:
            return None

    @staticmethod
    def _safe_filename_part(value: str, allow_dot: bool = False) -> str:
        allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
        if allow_dot:
            allowed.add(".")

        cleaned = "".join(character if character in allowed else "-" for character in str(value))
        cleaned = cleaned.strip("-")
        return cleaned[:180] or "safe"

    @staticmethod
    def _is_path_inside(path: Path, directory: Path) -> bool:
        try:
            path.resolve().relative_to(directory.resolve())
            return True
        except Exception:
            return False

    @staticmethod
    def _generate_device_id() -> str:
        seed = f"{platform.system()}:{socket.gethostname()}:{platform.machine()}"
        return f"device-{uuid.uuid5(uuid.NAMESPACE_DNS, seed)}"

    def _safe_hook(self, hook: Optional[Callable[[JSONDict], Any]], payload: JSONDict) -> Any:
        if hook is None:
            return None

        try:
            return hook(self._redact_sensitive_dict(payload))
        except Exception as exc:
            self._log(f"Hook failed safely: {self._safe_error(exc).get('message')}")
            return {
                "hook_failed": True,
                "error": self._safe_error(exc),
            }

    @staticmethod
    def _security_denied(decision: Any) -> bool:
        if not isinstance(decision, Mapping):
            return False

        status = str(decision.get("status", "")).lower()
        approved = decision.get("approved")
        allowed = decision.get("allowed")

        if status in {"denied", "rejected", "blocked"}:
            return True

        if approved is False:
            return True

        if allowed is False:
            return True

        return False

    @staticmethod
    def _security_approved(decision: Any) -> bool:
        if not isinstance(decision, Mapping):
            return False

        status = str(decision.get("status", "")).lower()
        approved = decision.get("approved")
        allowed = decision.get("allowed")

        if status in {"approved", "allowed", "accepted"}:
            return True

        if approved is True:
            return True

        if allowed is True:
            return True

        return False

    def _safe_error(self, error: Any) -> JSONDict:
        if isinstance(error, Mapping):
            return self._redact_sensitive_dict(dict(error))

        if isinstance(error, BaseException):
            return {
                "error": error.__class__.__name__,
                "message": self._redact_text(str(error)),
                "trace": self._redact_text(traceback.format_exc(limit=3)),
            }

        return {
            "error": "error",
            "message": self._redact_text(str(error)),
        }

    @classmethod
    def _redact_sensitive_dict(cls, data: JSONDict) -> JSONDict:
        sensitive_keys = {
            "password",
            "secret",
            "token",
            "api_token",
            "api_key",
            "apikey",
            "authorization",
            "access_token",
            "refresh_token",
            "private_key",
            "client_secret",
            "cookie",
            "session_cookie",
        }

        def redact(value: Any) -> Any:
            if isinstance(value, Mapping):
                redacted: JSONDict = {}
                for key, nested_value in value.items():
                    key_str = str(key)
                    if key_str.lower() in sensitive_keys:
                        redacted[key_str] = "[redacted]"
                    else:
                        redacted[key_str] = redact(nested_value)
                return redacted

            if isinstance(value, list):
                return [redact(item) for item in value]

            if isinstance(value, tuple):
                return tuple(redact(item) for item in value)

            if isinstance(value, str):
                return cls._redact_text(value)

            return value

        return redact(dict(data))

    @staticmethod
    def _redact_text(text: str) -> str:
        if not text:
            return ""

        redacted = str(text)
        blocked_terms = [
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "bearer",
            "access_token",
            "refresh_token",
            "private_key",
            "client_secret",
            "cookie",
        ]

        for term in blocked_terms:
            redacted = redacted.replace(term, "[redacted]")
            redacted = redacted.replace(term.upper(), "[redacted]")
            redacted = redacted.replace(term.title(), "[redacted]")

        return redacted

    @staticmethod
    def _safe_json(value: Any) -> Any:
        try:
            json.dumps(value, default=str)
            return value
        except Exception:
            return str(value)

    def _log(self, message: str) -> None:
        safe_message = self._redact_text(message)
        if self.logger:
            try:
                self.logger(safe_message)
            except Exception:
                return


def create_screen_capture_from_env() -> ScreenCapture:
    """
    Convenience factory for Windows worker entrypoints.
    """
    return ScreenCapture(
        config=ScreenCaptureConfig(),
        worker_user_id=os.getenv("WILLIAM_WORKER_USER_ID", ""),
        worker_workspace_id=os.getenv("WILLIAM_WORKER_WORKSPACE_ID", ""),
        device_id=os.getenv("WILLIAM_WORKER_DEVICE_ID", ""),
    )


__all__ = [
    "ScreenCapture",
    "ScreenCaptureConfig",
    "ScreenCaptureRequest",
    "ScreenCaptureResponse",
    "ScreenCaptureStatus",
    "ScreenCaptureRiskLevel",
    "ScreenCaptureMode",
    "ScreenCaptureFormat",
    "ScreenCapturePermission",
    "CaptureRegion",
    "RedactionRegion",
    "create_screen_capture_from_env",
]