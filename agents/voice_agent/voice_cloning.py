"""
agents/voice_agent/voice_cloning.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Consent-only custom voice cloning manager and protected voice model metadata.

Important:
    This file DOES NOT perform unsafe or unauthorized voice cloning.
    It manages consent-verified voice profile/model metadata, enrollment records,
    verification payloads, lifecycle state, audit events, and future integration hooks.

Architecture Compatibility:
    - BaseAgent compatible
    - Agent Registry compatible
    - Agent Loader compatible
    - Master Agent routing compatible
    - Security Agent approval compatible
    - Memory Agent payload compatible
    - Verification Agent payload compatible
    - Dashboard/API ready
    - SaaS user/workspace isolated

Public Class:
    VoiceCloning
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe even when the full William/Jarvis
        architecture has not been generated yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement run().",
                "data": {},
                "error": "BASE_AGENT_NOT_AVAILABLE",
                "metadata": {},
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("VoiceCloning")
if not logger.handlers:
    logging.basicConfig(
        level=os.getenv("WILLIAM_LOG_LEVEL", "INFO"),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VoiceCloneStatus(str, Enum):
    """
    Lifecycle states for consent-based voice model metadata.
    """

    PENDING_CONSENT = "pending_consent"
    CONSENT_VERIFIED = "consent_verified"
    READY_FOR_TRAINING = "ready_for_training"
    TRAINING_REQUESTED = "training_requested"
    TRAINING_IN_PROGRESS = "training_in_progress"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    DELETED = "deleted"
    FAILED = "failed"


class ConsentType(str, Enum):
    """
    Supported consent types.

    EXPLICIT_UPLOAD:
        User uploaded their own voice sample and accepted terms.

    SIGNED_FORM:
        User completed a signed legal consent document.

    ADMIN_VERIFIED:
        Workspace admin verified consent manually.

    API_VERIFIED:
        Future external consent-verification provider.

    NONE:
        No consent. This is never enough to create/activate a voice model.
    """

    NONE = "none"
    EXPLICIT_UPLOAD = "explicit_upload"
    SIGNED_FORM = "signed_form"
    ADMIN_VERIFIED = "admin_verified"
    API_VERIFIED = "api_verified"


class VoiceModelVisibility(str, Enum):
    """
    Visibility level for voice models.
    """

    PRIVATE_USER = "private_user"
    WORKSPACE_ONLY = "workspace_only"
    ADMIN_ONLY = "admin_only"


class VoiceCloneAction(str, Enum):
    """
    Supported action names for Master Agent / Router / Dashboard usage.
    """

    CREATE_MODEL_RECORD = "create_model_record"
    REGISTER_CONSENT = "register_consent"
    REQUEST_TRAINING = "request_training"
    ACTIVATE_MODEL = "activate_model"
    SUSPEND_MODEL = "suspend_model"
    REVOKE_CONSENT = "revoke_consent"
    DELETE_MODEL = "delete_model"
    GET_MODEL = "get_model"
    LIST_MODELS = "list_models"
    VERIFY_MODEL_ACCESS = "verify_model_access"
    EXPORT_METADATA = "export_metadata"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ConsentRecord:
    """
    Consent metadata for a voice model.

    This stores proof metadata only, not raw legal documents or audio.
    """

    consent_id: str
    consent_type: str
    consent_given: bool
    consent_given_at: Optional[str]
    consent_given_by_user_id: Optional[str]
    consent_scope: List[str] = field(default_factory=list)
    consent_reference_hash: Optional[str] = None
    consent_notes: Optional[str] = None
    revoked_at: Optional[str] = None
    revoked_by_user_id: Optional[str] = None
    revocation_reason: Optional[str] = None


@dataclass
class VoiceModelMetadata:
    """
    Protected metadata record for a consent-based custom voice model.

    This intentionally avoids storing raw voice samples inside this file.
    """

    model_id: str
    user_id: str
    workspace_id: str
    display_name: str
    owner_user_id: str
    status: str
    visibility: str
    provider: str
    model_reference: Optional[str]
    voice_sample_hashes: List[str]
    consent: ConsentRecord
    created_at: str
    updated_at: str
    created_by: Optional[str]
    updated_by: Optional[str]
    language: Optional[str] = None
    accent: Optional[str] = None
    gender_label: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    safety_flags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VoiceCloneEvent:
    """
    Event payload for dashboard, audit logs, analytics, or future event bus.
    """

    event_id: str
    event_type: str
    agent_name: str
    user_id: str
    workspace_id: str
    model_id: Optional[str]
    message: str
    data: Dict[str, Any]
    created_at: str


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return current UTC time as ISO string."""
    return datetime.now(timezone.utc).isoformat()


def _safe_text(value: Any, max_length: int = 500) -> str:
    """
    Convert any value to safe trimmed string.
    """
    if value is None:
        return ""
    text = str(value).strip()
    if len(text) > max_length:
        text = text[:max_length]
    return text


def _hash_value(value: str) -> str:
    """
    SHA-256 hash helper for sample references / consent references.

    Do not pass raw secrets that should not be logged elsewhere.
    """
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _normalize_list(values: Optional[List[Any]], max_items: int = 50) -> List[str]:
    """
    Normalize list values into trimmed strings.
    """
    if not values:
        return []

    clean: List[str] = []
    for item in values[:max_items]:
        text = _safe_text(item, max_length=200)
        if text:
            clean.append(text)
    return clean


# ---------------------------------------------------------------------------
# Main Class
# ---------------------------------------------------------------------------

class VoiceCloning(BaseAgent):
    """
    Consent-only custom voice model manager.

    Responsibilities:
        - Create protected voice model metadata records.
        - Enforce explicit consent before training/activation.
        - Keep user_id/workspace_id isolation.
        - Support Security Agent approval hooks.
        - Prepare Verification Agent payloads.
        - Prepare Memory Agent compatible payloads.
        - Emit agent events and audit logs.
        - Provide dashboard/API-ready structured results.

    What this file does NOT do:
        - It does not clone a person's voice directly.
        - It does not bypass consent.
        - It does not call real third-party voice APIs by default.
        - It does not store raw audio samples.
        - It does not impersonate people.

    Future integration:
        A real TTS/voice provider can be integrated behind these protected methods
        only after consent and security approval are verified.
    """

    AGENT_NAME = "VoiceCloning"
    AGENT_TYPE = "voice_agent_helper"
    VERSION = "1.0.0"

    SECURITY_REQUIRED_ACTIONS = {
        VoiceCloneAction.CREATE_MODEL_RECORD.value,
        VoiceCloneAction.REGISTER_CONSENT.value,
        VoiceCloneAction.REQUEST_TRAINING.value,
        VoiceCloneAction.ACTIVATE_MODEL.value,
        VoiceCloneAction.SUSPEND_MODEL.value,
        VoiceCloneAction.REVOKE_CONSENT.value,
        VoiceCloneAction.DELETE_MODEL.value,
        VoiceCloneAction.EXPORT_METADATA.value,
    }

    SAFE_READ_ACTIONS = {
        VoiceCloneAction.GET_MODEL.value,
        VoiceCloneAction.LIST_MODELS.value,
        VoiceCloneAction.VERIFY_MODEL_ACCESS.value,
    }

    DEFAULT_ALLOWED_CONSENT_SCOPES = {
        "tts_generation",
        "voice_assistant_response",
        "workspace_agent_voice",
        "user_private_voice",
        "testing_only",
    }

    def __init__(
        self,
        storage_path: Optional[str] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        auto_persist: bool = True,
        agent_name: str = AGENT_NAME,
        agent_id: str = "voice_cloning",
        **kwargs: Any,
    ) -> None:
        """
        Initialize VoiceCloning manager.

        Args:
            storage_path:
                Optional path for local JSON metadata storage.
                Default: .william/voice_cloning_metadata.json

            security_agent:
                Optional Security Agent instance.

            memory_agent:
                Optional Memory Agent instance.

            verification_agent:
                Optional Verification Agent instance.

            event_bus:
                Optional event bus / dashboard event emitter.

            audit_logger:
                Optional audit logger.

            auto_persist:
                If True, save metadata after write operations.
        """
        super().__init__(agent_name=agent_name, agent_id=agent_id, **kwargs)

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self.auto_persist = auto_persist

        default_storage = Path(".william") / "voice_cloning_metadata.json"
        self.storage_path = Path(storage_path) if storage_path else default_storage

        self._lock = threading.RLock()
        self._models: Dict[str, VoiceModelMetadata] = {}
        self._events: List[VoiceCloneEvent] = []

        self._load_storage()

    # -----------------------------------------------------------------------
    # Main router method
    # -----------------------------------------------------------------------

    def run(
        self,
        action: str,
        context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Master Agent / Agent Router compatible execution method.

        Args:
            action:
                Action from VoiceCloneAction.

            context:
                Must include user_id and workspace_id for SaaS isolation.

            payload:
                Action-specific data.

        Returns:
            Structured result dict.
        """
        payload = payload or {}

        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        if self._requires_security_check(action):
            approval = self._request_security_approval(
                action=action,
                context=context,
                payload=payload,
            )
            if not approval["success"]:
                return approval

        try:
            if action == VoiceCloneAction.CREATE_MODEL_RECORD.value:
                return self.create_model_record(context=context, **payload)

            if action == VoiceCloneAction.REGISTER_CONSENT.value:
                return self.register_consent(context=context, **payload)

            if action == VoiceCloneAction.REQUEST_TRAINING.value:
                return self.request_training(context=context, **payload)

            if action == VoiceCloneAction.ACTIVATE_MODEL.value:
                return self.activate_model(context=context, **payload)

            if action == VoiceCloneAction.SUSPEND_MODEL.value:
                return self.suspend_model(context=context, **payload)

            if action == VoiceCloneAction.REVOKE_CONSENT.value:
                return self.revoke_consent(context=context, **payload)

            if action == VoiceCloneAction.DELETE_MODEL.value:
                return self.delete_model(context=context, **payload)

            if action == VoiceCloneAction.GET_MODEL.value:
                return self.get_model(context=context, **payload)

            if action == VoiceCloneAction.LIST_MODELS.value:
                return self.list_models(context=context, **payload)

            if action == VoiceCloneAction.VERIFY_MODEL_ACCESS.value:
                return self.verify_model_access(context=context, **payload)

            if action == VoiceCloneAction.EXPORT_METADATA.value:
                return self.export_metadata(context=context, **payload)

            return self._error_result(
                message=f"Unsupported voice cloning action: {action}",
                error="UNSUPPORTED_ACTION",
                metadata={"action": action},
            )

        except Exception as exc:
            logger.exception("VoiceCloning run() failed.")
            return self._error_result(
                message="VoiceCloning action failed.",
                error=str(exc),
                metadata={"action": action},
            )

    # -----------------------------------------------------------------------
    # Public methods
    # -----------------------------------------------------------------------

    def create_model_record(
        self,
        context: Dict[str, Any],
        display_name: str,
        owner_user_id: Optional[str] = None,
        provider: str = "local_metadata_only",
        model_reference: Optional[str] = None,
        voice_sample_references: Optional[List[str]] = None,
        visibility: str = VoiceModelVisibility.PRIVATE_USER.value,
        language: Optional[str] = None,
        accent: Optional[str] = None,
        gender_label: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a protected voice model metadata record.

        Consent is not assumed at creation time.
        The initial status is PENDING_CONSENT unless consent is later registered.

        Args:
            context:
                SaaS context with user_id and workspace_id.

            display_name:
                Human-friendly name for this voice profile.

            owner_user_id:
                User who owns the voice. Defaults to context user_id.

            provider:
                Future provider reference. Default is metadata only.

            model_reference:
                Optional external model reference/id. Never hardcode secrets.

            voice_sample_references:
                File ids, storage references, or hashes. Stored as SHA-256 hashes.

            visibility:
                private_user, workspace_only, or admin_only.

        Returns:
            Structured result.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        user_id = self._context_user_id(context)
        workspace_id = self._context_workspace_id(context)
        owner_user_id = _safe_text(owner_user_id or user_id, 100)

        display_name_clean = _safe_text(display_name, 150)
        if not display_name_clean:
            return self._error_result(
                message="display_name is required.",
                error="VALIDATION_ERROR",
            )

        visibility_clean = self._normalize_visibility(visibility)
        provider_clean = _safe_text(provider, 100) or "local_metadata_only"

        raw_refs = voice_sample_references or []
        sample_hashes = [_hash_value(_safe_text(ref, 1000)) for ref in raw_refs if _safe_text(ref, 1000)]

        model_id = f"vcm_{uuid.uuid4().hex}"
        now = _utc_now()

        consent = ConsentRecord(
            consent_id=f"consent_{uuid.uuid4().hex}",
            consent_type=ConsentType.NONE.value,
            consent_given=False,
            consent_given_at=None,
            consent_given_by_user_id=None,
            consent_scope=[],
            consent_reference_hash=None,
            consent_notes=None,
        )

        record = VoiceModelMetadata(
            model_id=model_id,
            user_id=user_id,
            workspace_id=workspace_id,
            display_name=display_name_clean,
            owner_user_id=owner_user_id,
            status=VoiceCloneStatus.PENDING_CONSENT.value,
            visibility=visibility_clean,
            provider=provider_clean,
            model_reference=_safe_text(model_reference, 500) or None,
            voice_sample_hashes=sample_hashes,
            consent=consent,
            created_at=now,
            updated_at=now,
            created_by=user_id,
            updated_by=user_id,
            language=_safe_text(language, 80) or None,
            accent=_safe_text(accent, 80) or None,
            gender_label=_safe_text(gender_label, 80) or None,
            tags=_normalize_list(tags),
            safety_flags=["consent_required"],
            metadata=self._sanitize_metadata(metadata or {}),
        )

        with self._lock:
            self._models[model_id] = record
            self._persist_if_enabled()

        event = self._emit_agent_event(
            event_type="voice_model_record_created",
            context=context,
            model_id=model_id,
            message="Voice model metadata record created. Consent is still required.",
            data={"model_id": model_id, "status": record.status},
        )

        self._log_audit_event(
            action=VoiceCloneAction.CREATE_MODEL_RECORD.value,
            context=context,
            model_id=model_id,
            success=True,
            details={"display_name": display_name_clean, "visibility": visibility_clean},
        )

        verification = self._prepare_verification_payload(
            action=VoiceCloneAction.CREATE_MODEL_RECORD.value,
            context=context,
            model_id=model_id,
            result_data={"model_id": model_id, "status": record.status},
        )

        memory = self._prepare_memory_payload(
            action=VoiceCloneAction.CREATE_MODEL_RECORD.value,
            context=context,
            model_id=model_id,
            summary=f"Created voice model metadata record '{display_name_clean}' requiring consent.",
        )

        return self._safe_result(
            message="Voice model metadata record created. Consent must be registered before training or activation.",
            data={
                "model": self._model_to_public_dict(record),
                "event": asdict(event),
                "verification_payload": verification,
                "memory_payload": memory,
            },
            metadata={
                "agent": self.agent_name,
                "action": VoiceCloneAction.CREATE_MODEL_RECORD.value,
            },
        )

    def register_consent(
        self,
        context: Dict[str, Any],
        model_id: str,
        consent_type: str,
        consent_given_by_user_id: Optional[str] = None,
        consent_scope: Optional[List[str]] = None,
        consent_reference: Optional[str] = None,
        consent_notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Register verified consent for a voice model.

        Consent must be explicit and must include at least one allowed scope.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        consent_type_clean = _safe_text(consent_type, 80)
        if consent_type_clean not in {
            ConsentType.EXPLICIT_UPLOAD.value,
            ConsentType.SIGNED_FORM.value,
            ConsentType.ADMIN_VERIFIED.value,
            ConsentType.API_VERIFIED.value,
        }:
            return self._error_result(
                message="Valid consent_type is required.",
                error="INVALID_CONSENT_TYPE",
                metadata={
                    "allowed": [
                        ConsentType.EXPLICIT_UPLOAD.value,
                        ConsentType.SIGNED_FORM.value,
                        ConsentType.ADMIN_VERIFIED.value,
                        ConsentType.API_VERIFIED.value,
                    ]
                },
            )

        scopes = _normalize_list(consent_scope)
        invalid_scopes = [s for s in scopes if s not in self.DEFAULT_ALLOWED_CONSENT_SCOPES]
        if not scopes:
            return self._error_result(
                message="At least one consent scope is required.",
                error="CONSENT_SCOPE_REQUIRED",
                metadata={"allowed_scopes": sorted(self.DEFAULT_ALLOWED_CONSENT_SCOPES)},
            )

        if invalid_scopes:
            return self._error_result(
                message="One or more consent scopes are not allowed.",
                error="INVALID_CONSENT_SCOPE",
                metadata={
                    "invalid_scopes": invalid_scopes,
                    "allowed_scopes": sorted(self.DEFAULT_ALLOWED_CONSENT_SCOPES),
                },
            )

        with self._lock:
            record = self._get_owned_model_or_error(context, model_id)
            if isinstance(record, dict):
                return record

            if record.status in {VoiceCloneStatus.DELETED.value, VoiceCloneStatus.REVOKED.value}:
                return self._error_result(
                    message="Cannot register consent for a deleted or revoked model.",
                    error="MODEL_NOT_ELIGIBLE",
                    metadata={"model_id": model_id, "status": record.status},
                )

            now = _utc_now()
            actor_user_id = self._context_user_id(context)

            record.consent.consent_type = consent_type_clean
            record.consent.consent_given = True
            record.consent.consent_given_at = now
            record.consent.consent_given_by_user_id = _safe_text(
                consent_given_by_user_id or actor_user_id,
                100,
            )
            record.consent.consent_scope = scopes
            record.consent.consent_reference_hash = (
                _hash_value(consent_reference) if consent_reference else None
            )
            record.consent.consent_notes = _safe_text(consent_notes, 500) or None
            record.consent.revoked_at = None
            record.consent.revoked_by_user_id = None
            record.consent.revocation_reason = None

            record.status = VoiceCloneStatus.CONSENT_VERIFIED.value
            record.updated_at = now
            record.updated_by = actor_user_id
            record.safety_flags = self._remove_flag(record.safety_flags, "consent_required")
            record.safety_flags = self._add_flag(record.safety_flags, "consent_verified")

            self._persist_if_enabled()

        self._emit_agent_event(
            event_type="voice_model_consent_registered",
            context=context,
            model_id=model_id,
            message="Consent registered for voice model.",
            data={"model_id": model_id, "consent_type": consent_type_clean, "scopes": scopes},
        )

        self._log_audit_event(
            action=VoiceCloneAction.REGISTER_CONSENT.value,
            context=context,
            model_id=model_id,
            success=True,
            details={"consent_type": consent_type_clean, "scopes": scopes},
        )

        return self._safe_result(
            message="Consent registered successfully. Voice model can now be prepared for training.",
            data={
                "model": self._model_to_public_dict(record),
                "verification_payload": self._prepare_verification_payload(
                    action=VoiceCloneAction.REGISTER_CONSENT.value,
                    context=context,
                    model_id=model_id,
                    result_data={"consent_verified": True, "status": record.status},
                ),
                "memory_payload": self._prepare_memory_payload(
                    action=VoiceCloneAction.REGISTER_CONSENT.value,
                    context=context,
                    model_id=model_id,
                    summary="Consent was registered for a custom voice model.",
                ),
            },
            metadata={"agent": self.agent_name, "action": VoiceCloneAction.REGISTER_CONSENT.value},
        )

    def request_training(
        self,
        context: Dict[str, Any],
        model_id: str,
        training_options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request training for a consent-verified model.

        This does not call a real provider. It marks the metadata as
        TRAINING_REQUESTED and prepares a provider-safe payload for future workers.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        with self._lock:
            record = self._get_owned_model_or_error(context, model_id)
            if isinstance(record, dict):
                return record

            consent_check = self._assert_consent_active(record)
            if not consent_check["success"]:
                return consent_check

            if record.status not in {
                VoiceCloneStatus.CONSENT_VERIFIED.value,
                VoiceCloneStatus.READY_FOR_TRAINING.value,
                VoiceCloneStatus.FAILED.value,
            }:
                return self._error_result(
                    message="Model is not eligible for training request.",
                    error="MODEL_NOT_TRAINING_ELIGIBLE",
                    metadata={"model_id": model_id, "status": record.status},
                )

            sanitized_options = self._sanitize_metadata(training_options or {})
            now = _utc_now()

            record.status = VoiceCloneStatus.TRAINING_REQUESTED.value
            record.updated_at = now
            record.updated_by = self._context_user_id(context)
            record.metadata["training_options"] = sanitized_options
            record.metadata["training_requested_at"] = now
            record.safety_flags = self._add_flag(record.safety_flags, "training_requires_provider_worker")

            self._persist_if_enabled()

        provider_payload = {
            "model_id": record.model_id,
            "workspace_id": record.workspace_id,
            "owner_user_id": record.owner_user_id,
            "provider": record.provider,
            "sample_hash_count": len(record.voice_sample_hashes),
            "training_options": record.metadata.get("training_options", {}),
            "consent": {
                "consent_given": record.consent.consent_given,
                "consent_type": record.consent.consent_type,
                "consent_scope": record.consent.consent_scope,
                "consent_given_at": record.consent.consent_given_at,
            },
        }

        self._emit_agent_event(
            event_type="voice_model_training_requested",
            context=context,
            model_id=model_id,
            message="Voice model training requested.",
            data={"model_id": model_id},
        )

        self._log_audit_event(
            action=VoiceCloneAction.REQUEST_TRAINING.value,
            context=context,
            model_id=model_id,
            success=True,
            details={"provider": record.provider},
        )

        return self._safe_result(
            message="Training request prepared successfully.",
            data={
                "model": self._model_to_public_dict(record),
                "provider_payload": provider_payload,
                "verification_payload": self._prepare_verification_payload(
                    action=VoiceCloneAction.REQUEST_TRAINING.value,
                    context=context,
                    model_id=model_id,
                    result_data={"status": record.status},
                ),
            },
            metadata={"agent": self.agent_name, "action": VoiceCloneAction.REQUEST_TRAINING.value},
        )

    def activate_model(
        self,
        context: Dict[str, Any],
        model_id: str,
        provider_model_reference: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Activate a trained voice model.

        Requires active consent and a provider model reference if one is supplied.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        with self._lock:
            record = self._get_owned_model_or_error(context, model_id)
            if isinstance(record, dict):
                return record

            consent_check = self._assert_consent_active(record)
            if not consent_check["success"]:
                return consent_check

            if record.status not in {
                VoiceCloneStatus.TRAINING_REQUESTED.value,
                VoiceCloneStatus.TRAINING_IN_PROGRESS.value,
                VoiceCloneStatus.READY_FOR_TRAINING.value,
                VoiceCloneStatus.CONSENT_VERIFIED.value,
                VoiceCloneStatus.SUSPENDED.value,
                VoiceCloneStatus.FAILED.value,
            }:
                return self._error_result(
                    message="Model cannot be activated from its current status.",
                    error="INVALID_STATUS_TRANSITION",
                    metadata={"model_id": model_id, "status": record.status},
                )

            if provider_model_reference:
                record.model_reference = _safe_text(provider_model_reference, 500)

            record.status = VoiceCloneStatus.ACTIVE.value
            record.updated_at = _utc_now()
            record.updated_by = self._context_user_id(context)
            record.safety_flags = self._add_flag(record.safety_flags, "active_consent_based_voice_model")

            self._persist_if_enabled()

        self._emit_agent_event(
            event_type="voice_model_activated",
            context=context,
            model_id=model_id,
            message="Voice model activated.",
            data={"model_id": model_id},
        )

        self._log_audit_event(
            action=VoiceCloneAction.ACTIVATE_MODEL.value,
            context=context,
            model_id=model_id,
            success=True,
            details={"status": record.status},
        )

        return self._safe_result(
            message="Voice model activated successfully.",
            data={
                "model": self._model_to_public_dict(record),
                "verification_payload": self._prepare_verification_payload(
                    action=VoiceCloneAction.ACTIVATE_MODEL.value,
                    context=context,
                    model_id=model_id,
                    result_data={"status": record.status},
                ),
            },
            metadata={"agent": self.agent_name, "action": VoiceCloneAction.ACTIVATE_MODEL.value},
        )

    def suspend_model(
        self,
        context: Dict[str, Any],
        model_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Suspend a voice model without deleting consent metadata.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        with self._lock:
            record = self._get_owned_model_or_error(context, model_id)
            if isinstance(record, dict):
                return record

            if record.status in {VoiceCloneStatus.DELETED.value, VoiceCloneStatus.REVOKED.value}:
                return self._error_result(
                    message="Deleted or revoked model cannot be suspended.",
                    error="INVALID_STATUS_TRANSITION",
                    metadata={"model_id": model_id, "status": record.status},
                )

            record.status = VoiceCloneStatus.SUSPENDED.value
            record.updated_at = _utc_now()
            record.updated_by = self._context_user_id(context)
            record.metadata["suspended_reason"] = _safe_text(reason, 500) or "No reason provided."
            record.metadata["suspended_at"] = record.updated_at
            record.safety_flags = self._add_flag(record.safety_flags, "suspended")

            self._persist_if_enabled()

        self._emit_agent_event(
            event_type="voice_model_suspended",
            context=context,
            model_id=model_id,
            message="Voice model suspended.",
            data={"model_id": model_id, "reason": record.metadata.get("suspended_reason")},
        )

        self._log_audit_event(
            action=VoiceCloneAction.SUSPEND_MODEL.value,
            context=context,
            model_id=model_id,
            success=True,
            details={"reason": record.metadata.get("suspended_reason")},
        )

        return self._safe_result(
            message="Voice model suspended successfully.",
            data={"model": self._model_to_public_dict(record)},
            metadata={"agent": self.agent_name, "action": VoiceCloneAction.SUSPEND_MODEL.value},
        )

    def revoke_consent(
        self,
        context: Dict[str, Any],
        model_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Revoke consent and disable the model.

        Once consent is revoked, the model cannot be used unless a new record
        and consent process are created.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        with self._lock:
            record = self._get_owned_model_or_error(context, model_id)
            if isinstance(record, dict):
                return record

            now = _utc_now()
            actor_user_id = self._context_user_id(context)

            record.status = VoiceCloneStatus.REVOKED.value
            record.consent.consent_given = False
            record.consent.revoked_at = now
            record.consent.revoked_by_user_id = actor_user_id
            record.consent.revocation_reason = _safe_text(reason, 500) or "Consent revoked."
            record.updated_at = now
            record.updated_by = actor_user_id
            record.safety_flags = self._add_flag(record.safety_flags, "consent_revoked")
            record.safety_flags = self._remove_flag(record.safety_flags, "active_consent_based_voice_model")

            self._persist_if_enabled()

        self._emit_agent_event(
            event_type="voice_model_consent_revoked",
            context=context,
            model_id=model_id,
            message="Voice model consent revoked.",
            data={"model_id": model_id, "reason": record.consent.revocation_reason},
        )

        self._log_audit_event(
            action=VoiceCloneAction.REVOKE_CONSENT.value,
            context=context,
            model_id=model_id,
            success=True,
            details={"reason": record.consent.revocation_reason},
        )

        return self._safe_result(
            message="Consent revoked. Voice model is no longer usable.",
            data={
                "model": self._model_to_public_dict(record),
                "verification_payload": self._prepare_verification_payload(
                    action=VoiceCloneAction.REVOKE_CONSENT.value,
                    context=context,
                    model_id=model_id,
                    result_data={"status": record.status, "consent_given": False},
                ),
            },
            metadata={"agent": self.agent_name, "action": VoiceCloneAction.REVOKE_CONSENT.value},
        )

    def delete_model(
        self,
        context: Dict[str, Any],
        model_id: str,
        hard_delete: bool = False,
    ) -> Dict[str, Any]:
        """
        Delete a model metadata record.

        Soft delete:
            Keeps a minimal record with status=deleted for audit continuity.

        Hard delete:
            Removes metadata from local storage. Use carefully.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        with self._lock:
            record = self._get_owned_model_or_error(context, model_id)
            if isinstance(record, dict):
                return record

            if hard_delete:
                public_before_delete = self._model_to_public_dict(record)
                del self._models[model_id]
                self._persist_if_enabled()

                self._log_audit_event(
                    action=VoiceCloneAction.DELETE_MODEL.value,
                    context=context,
                    model_id=model_id,
                    success=True,
                    details={"hard_delete": True},
                )

                return self._safe_result(
                    message="Voice model metadata hard-deleted successfully.",
                    data={
                        "deleted_model": public_before_delete,
                        "hard_delete": True,
                    },
                    metadata={"agent": self.agent_name, "action": VoiceCloneAction.DELETE_MODEL.value},
                )

            record.status = VoiceCloneStatus.DELETED.value
            record.updated_at = _utc_now()
            record.updated_by = self._context_user_id(context)
            record.model_reference = None
            record.voice_sample_hashes = []
            record.safety_flags = self._add_flag(record.safety_flags, "deleted")
            record.safety_flags = self._remove_flag(record.safety_flags, "active_consent_based_voice_model")

            self._persist_if_enabled()

        self._emit_agent_event(
            event_type="voice_model_deleted",
            context=context,
            model_id=model_id,
            message="Voice model metadata soft-deleted.",
            data={"model_id": model_id, "hard_delete": False},
        )

        self._log_audit_event(
            action=VoiceCloneAction.DELETE_MODEL.value,
            context=context,
            model_id=model_id,
            success=True,
            details={"hard_delete": False},
        )

        return self._safe_result(
            message="Voice model metadata soft-deleted successfully.",
            data={"model": self._model_to_public_dict(record), "hard_delete": False},
            metadata={"agent": self.agent_name, "action": VoiceCloneAction.DELETE_MODEL.value},
        )

    def get_model(
        self,
        context: Dict[str, Any],
        model_id: str,
        include_private_metadata: bool = False,
    ) -> Dict[str, Any]:
        """
        Get one model by id with user/workspace isolation.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        with self._lock:
            record = self._get_owned_model_or_error(context, model_id)
            if isinstance(record, dict):
                return record

            data = self._model_to_public_dict(
                record,
                include_private_metadata=include_private_metadata,
            )

        return self._safe_result(
            message="Voice model metadata loaded successfully.",
            data={"model": data},
            metadata={"agent": self.agent_name, "action": VoiceCloneAction.GET_MODEL.value},
        )

    def list_models(
        self,
        context: Dict[str, Any],
        status: Optional[str] = None,
        visibility: Optional[str] = None,
        include_deleted: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """
        List models scoped to the current user/workspace.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        user_id = self._context_user_id(context)
        workspace_id = self._context_workspace_id(context)

        limit = max(1, min(int(limit or 100), 500))
        offset = max(0, int(offset or 0))

        status_clean = _safe_text(status, 80) or None
        visibility_clean = _safe_text(visibility, 80) or None

        with self._lock:
            records = []
            for record in self._models.values():
                if record.user_id != user_id or record.workspace_id != workspace_id:
                    continue

                if not include_deleted and record.status == VoiceCloneStatus.DELETED.value:
                    continue

                if status_clean and record.status != status_clean:
                    continue

                if visibility_clean and record.visibility != visibility_clean:
                    continue

                records.append(record)

            records.sort(key=lambda item: item.created_at, reverse=True)
            paginated = records[offset: offset + limit]

        return self._safe_result(
            message="Voice model list loaded successfully.",
            data={
                "models": [self._model_to_public_dict(item) for item in paginated],
                "count": len(paginated),
                "total": len(records),
                "limit": limit,
                "offset": offset,
            },
            metadata={"agent": self.agent_name, "action": VoiceCloneAction.LIST_MODELS.value},
        )

    def verify_model_access(
        self,
        context: Dict[str, Any],
        model_id: str,
        required_scope: str = "tts_generation",
    ) -> Dict[str, Any]:
        """
        Verify whether current context can use a voice model for a given scope.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        required_scope_clean = _safe_text(required_scope, 100)
        if not required_scope_clean:
            return self._error_result(
                message="required_scope is required.",
                error="VALIDATION_ERROR",
            )

        with self._lock:
            record = self._get_owned_model_or_error(context, model_id)
            if isinstance(record, dict):
                return record

            if record.status != VoiceCloneStatus.ACTIVE.value:
                return self._safe_result(
                    message="Voice model access denied because model is not active.",
                    data={
                        "allowed": False,
                        "reason": "MODEL_NOT_ACTIVE",
                        "status": record.status,
                    },
                    metadata={"agent": self.agent_name},
                )

            consent_check = self._assert_consent_active(record)
            if not consent_check["success"]:
                return self._safe_result(
                    message="Voice model access denied because consent is not active.",
                    data={
                        "allowed": False,
                        "reason": consent_check.get("error", "CONSENT_NOT_ACTIVE"),
                        "status": record.status,
                    },
                    metadata={"agent": self.agent_name},
                )

            if required_scope_clean not in record.consent.consent_scope:
                return self._safe_result(
                    message="Voice model access denied because required scope is missing.",
                    data={
                        "allowed": False,
                        "reason": "SCOPE_NOT_GRANTED",
                        "required_scope": required_scope_clean,
                        "granted_scopes": record.consent.consent_scope,
                    },
                    metadata={"agent": self.agent_name},
                )

        return self._safe_result(
            message="Voice model access verified.",
            data={
                "allowed": True,
                "model_id": model_id,
                "required_scope": required_scope_clean,
                "status": record.status,
            },
            metadata={"agent": self.agent_name, "action": VoiceCloneAction.VERIFY_MODEL_ACCESS.value},
        )

    def export_metadata(
        self,
        context: Dict[str, Any],
        model_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Export sanitized metadata for dashboard/admin/reporting.

        This export is scoped by user_id/workspace_id.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        if model_id:
            model_result = self.get_model(
                context=context,
                model_id=model_id,
                include_private_metadata=True,
            )
            if not model_result["success"]:
                return model_result

            return self._safe_result(
                message="Voice model metadata exported successfully.",
                data={"export": model_result["data"]["model"]},
                metadata={"agent": self.agent_name, "action": VoiceCloneAction.EXPORT_METADATA.value},
            )

        list_result = self.list_models(
            context=context,
            include_deleted=True,
            limit=500,
            offset=0,
        )
        if not list_result["success"]:
            return list_result

        return self._safe_result(
            message="Voice model metadata exported successfully.",
            data={"export": list_result["data"]},
            metadata={"agent": self.agent_name, "action": VoiceCloneAction.EXPORT_METADATA.value},
        )

    # -----------------------------------------------------------------------
    # Required architecture hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Every user-specific execution must include:
            - user_id
            - workspace_id
        """
        if not isinstance(context, dict):
            return self._error_result(
                message="Context must be a dictionary.",
                error="INVALID_CONTEXT",
            )

        user_id = _safe_text(context.get("user_id"), 100)
        workspace_id = _safe_text(context.get("workspace_id"), 100)

        if not user_id:
            return self._error_result(
                message="user_id is required for VoiceCloning operations.",
                error="USER_ID_REQUIRED",
            )

        if not workspace_id:
            return self._error_result(
                message="workspace_id is required for VoiceCloning operations.",
                error="WORKSPACE_ID_REQUIRED",
            )

        return self._safe_result(
            message="Context validated.",
            data={"user_id": user_id, "workspace_id": workspace_id},
            metadata={"agent": self.agent_name},
        )

    def _requires_security_check(self, action: str) -> bool:
        """
        Return True when an action requires Security Agent approval.
        """
        return action in self.SECURITY_REQUIRED_ACTIONS

    def _request_security_approval(
        self,
        action: str,
        context: Dict[str, Any],
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Fallback behavior:
            If no Security Agent exists yet, allow only safe local metadata actions
            but attach a warning flag. This keeps development import-safe while
            making production integration clear.
        """
        approval_payload = {
            "agent": self.agent_name,
            "action": action,
            "user_id": self._context_user_id(context),
            "workspace_id": self._context_workspace_id(context),
            "risk_level": self._security_risk_level(action),
            "resource_type": "voice_model_metadata",
            "payload_summary": self._summarize_payload(payload),
            "timestamp": _utc_now(),
        }

        if self.security_agent and hasattr(self.security_agent, "approve"):
            try:
                response = self.security_agent.approve(approval_payload)
                if isinstance(response, dict) and response.get("success") is True:
                    return self._safe_result(
                        message="Security approval granted.",
                        data={"approval": response},
                        metadata={"agent": self.agent_name, "security_checked": True},
                    )

                return self._error_result(
                    message="Security approval denied.",
                    error="SECURITY_APPROVAL_DENIED",
                    metadata={"security_response": response},
                )

            except Exception as exc:
                logger.exception("Security Agent approval failed.")
                return self._error_result(
                    message="Security Agent approval failed.",
                    error=str(exc),
                    metadata={"approval_payload": approval_payload},
                )

        return self._safe_result(
            message="Security Agent not connected. Development fallback approval used.",
            data={
                "approval": {
                    "approved": True,
                    "fallback": True,
                    "warning": "Connect Security Agent in production.",
                    "approval_payload": approval_payload,
                }
            },
            metadata={
                "agent": self.agent_name,
                "security_checked": False,
                "fallback_security": True,
            },
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: Dict[str, Any],
        model_id: Optional[str],
        result_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.
        """
        payload = {
            "verification_id": f"verify_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "action": action,
            "user_id": self._context_user_id(context),
            "workspace_id": self._context_workspace_id(context),
            "model_id": model_id,
            "result_data": result_data or {},
            "checks": {
                "context_validated": True,
                "workspace_isolated": True,
                "consent_required": True,
                "raw_audio_not_stored_here": True,
                "structured_result": True,
            },
            "created_at": _utc_now(),
        }

        if self.verification_agent and hasattr(self.verification_agent, "prepare"):
            try:
                prepared = self.verification_agent.prepare(payload)
                if isinstance(prepared, dict):
                    return prepared
            except Exception:
                logger.exception("Verification Agent prepare() failed. Returning local payload.")

        return payload

    def _prepare_memory_payload(
        self,
        action: str,
        context: Dict[str, Any],
        model_id: Optional[str],
        summary: str,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        It stores only safe operational memory, not private voice samples.
        """
        payload = {
            "memory_id": f"memory_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "action": action,
            "user_id": self._context_user_id(context),
            "workspace_id": self._context_workspace_id(context),
            "model_id": model_id,
            "summary": _safe_text(summary, 500),
            "safe_to_store": True,
            "contains_raw_audio": False,
            "contains_secret": False,
            "created_at": _utc_now(),
        }

        if self.memory_agent and hasattr(self.memory_agent, "prepare_memory"):
            try:
                prepared = self.memory_agent.prepare_memory(payload)
                if isinstance(prepared, dict):
                    return prepared
            except Exception:
                logger.exception("Memory Agent prepare_memory() failed. Returning local payload.")

        return payload

    def _emit_agent_event(
        self,
        event_type: str,
        context: Dict[str, Any],
        model_id: Optional[str],
        message: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> VoiceCloneEvent:
        """
        Emit event for dashboard/API/event bus.

        Safe fallback stores events in local memory.
        """
        event = VoiceCloneEvent(
            event_id=f"evt_{uuid.uuid4().hex}",
            event_type=_safe_text(event_type, 120),
            agent_name=self.agent_name,
            user_id=self._context_user_id(context),
            workspace_id=self._context_workspace_id(context),
            model_id=model_id,
            message=_safe_text(message, 500),
            data=self._sanitize_metadata(data or {}),
            created_at=_utc_now(),
        )

        with self._lock:
            self._events.append(event)
            self._events = self._events[-1000:]

        if self.event_bus and hasattr(self.event_bus, "emit"):
            try:
                self.event_bus.emit(asdict(event))
            except Exception:
                logger.exception("Event bus emit failed.")

        return event

    def _log_audit_event(
        self,
        action: str,
        context: Dict[str, Any],
        model_id: Optional[str],
        success: bool,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        This is required for sensitive voice model operations.
        """
        audit_payload = {
            "audit_id": f"audit_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "action": action,
            "user_id": self._context_user_id(context),
            "workspace_id": self._context_workspace_id(context),
            "model_id": model_id,
            "success": success,
            "details": self._sanitize_metadata(details or {}),
            "created_at": _utc_now(),
        }

        if self.audit_logger and hasattr(self.audit_logger, "log"):
            try:
                self.audit_logger.log(audit_payload)
                return
            except Exception:
                logger.exception("External audit logger failed.")

        logger.info("AUDIT_EVENT | %s", json.dumps(audit_payload, ensure_ascii=False))

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success result.
        """
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result.
        """
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _context_user_id(self, context: Dict[str, Any]) -> str:
        return _safe_text(context.get("user_id"), 100)

    def _context_workspace_id(self, context: Dict[str, Any]) -> str:
        return _safe_text(context.get("workspace_id"), 100)

    def _normalize_visibility(self, visibility: str) -> str:
        visibility_clean = _safe_text(visibility, 100)
        allowed = {item.value for item in VoiceModelVisibility}
        if visibility_clean not in allowed:
            return VoiceModelVisibility.PRIVATE_USER.value
        return visibility_clean

    def _sanitize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize arbitrary metadata.

        Prevents accidental storage of massive data, raw audio blobs, secrets,
        or unsafe objects.
        """
        if not isinstance(metadata, dict):
            return {}

        blocked_keys = {
            "password",
            "secret",
            "token",
            "api_key",
            "private_key",
            "raw_audio",
            "audio_bytes",
            "voice_bytes",
            "base64_audio",
        }

        clean: Dict[str, Any] = {}

        for key, value in metadata.items():
            key_clean = _safe_text(key, 100)
            if not key_clean:
                continue

            lowered = key_clean.lower()
            if any(blocked in lowered for blocked in blocked_keys):
                clean[key_clean] = "[REDACTED]"
                continue

            clean[key_clean] = self._sanitize_value(value)

        return clean

    def _sanitize_value(self, value: Any) -> Any:
        """
        Sanitize metadata value.
        """
        if value is None:
            return None

        if isinstance(value, (bool, int, float)):
            return value

        if isinstance(value, str):
            return _safe_text(value, 1000)

        if isinstance(value, list):
            return [self._sanitize_value(item) for item in value[:50]]

        if isinstance(value, dict):
            return self._sanitize_metadata(value)

        return _safe_text(value, 500)

    def _summarize_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Summarize payload for security approval without leaking sensitive data.
        """
        clean = self._sanitize_metadata(payload)
        summary: Dict[str, Any] = {}

        for key, value in clean.items():
            if isinstance(value, str) and len(value) > 120:
                summary[key] = value[:120] + "..."
            else:
                summary[key] = value

        return summary

    def _security_risk_level(self, action: str) -> str:
        """
        Risk level mapping for Security Agent.
        """
        if action in {
            VoiceCloneAction.DELETE_MODEL.value,
            VoiceCloneAction.REVOKE_CONSENT.value,
            VoiceCloneAction.ACTIVATE_MODEL.value,
        }:
            return "high"

        if action in {
            VoiceCloneAction.REGISTER_CONSENT.value,
            VoiceCloneAction.REQUEST_TRAINING.value,
            VoiceCloneAction.EXPORT_METADATA.value,
        }:
            return "medium"

        return "low"

    def _get_owned_model_or_error(
        self,
        context: Dict[str, Any],
        model_id: str,
    ) -> VoiceModelMetadata | Dict[str, Any]:
        """
        Fetch a model and enforce user/workspace isolation.
        """
        model_id_clean = _safe_text(model_id, 120)
        if not model_id_clean:
            return self._error_result(
                message="model_id is required.",
                error="MODEL_ID_REQUIRED",
            )

        record = self._models.get(model_id_clean)
        if not record:
            return self._error_result(
                message="Voice model not found.",
                error="MODEL_NOT_FOUND",
                metadata={"model_id": model_id_clean},
            )

        user_id = self._context_user_id(context)
        workspace_id = self._context_workspace_id(context)

        if record.user_id != user_id or record.workspace_id != workspace_id:
            self._log_audit_event(
                action="unauthorized_model_access_attempt",
                context=context,
                model_id=model_id_clean,
                success=False,
                details={
                    "record_user_id": record.user_id,
                    "record_workspace_id": record.workspace_id,
                },
            )
            return self._error_result(
                message="Voice model not found in this user/workspace scope.",
                error="MODEL_SCOPE_DENIED",
                metadata={"model_id": model_id_clean},
            )

        return record

    def _assert_consent_active(self, record: VoiceModelMetadata) -> Dict[str, Any]:
        """
        Verify active consent on a model.
        """
        if not record.consent.consent_given:
            return self._error_result(
                message="Consent has not been granted for this voice model.",
                error="CONSENT_NOT_GRANTED",
                metadata={"model_id": record.model_id},
            )

        if record.consent.revoked_at:
            return self._error_result(
                message="Consent has been revoked for this voice model.",
                error="CONSENT_REVOKED",
                metadata={
                    "model_id": record.model_id,
                    "revoked_at": record.consent.revoked_at,
                },
            )

        if record.consent.consent_type == ConsentType.NONE.value:
            return self._error_result(
                message="Valid consent type is missing.",
                error="CONSENT_TYPE_MISSING",
                metadata={"model_id": record.model_id},
            )

        if not record.consent.consent_scope:
            return self._error_result(
                message="Consent scope is missing.",
                error="CONSENT_SCOPE_MISSING",
                metadata={"model_id": record.model_id},
            )

        return self._safe_result(
            message="Consent is active.",
            data={"model_id": record.model_id},
        )

    def _model_to_public_dict(
        self,
        record: VoiceModelMetadata,
        include_private_metadata: bool = False,
    ) -> Dict[str, Any]:
        """
        Convert internal metadata to public/dashboard-safe dict.
        """
        data = asdict(record)

        data["voice_sample_hash_count"] = len(record.voice_sample_hashes)

        if not include_private_metadata:
            data.pop("voice_sample_hashes", None)
            data["metadata"] = {
                key: value
                for key, value in data.get("metadata", {}).items()
                if key not in {"training_options"}
            }

        return data

    def _add_flag(self, flags: List[str], flag: str) -> List[str]:
        """
        Add unique safety flag.
        """
        flag_clean = _safe_text(flag, 100)
        clean = list(dict.fromkeys(flags or []))
        if flag_clean and flag_clean not in clean:
            clean.append(flag_clean)
        return clean

    def _remove_flag(self, flags: List[str], flag: str) -> List[str]:
        """
        Remove safety flag.
        """
        flag_clean = _safe_text(flag, 100)
        return [item for item in flags or [] if item != flag_clean]

    # -----------------------------------------------------------------------
    # Storage
    # -----------------------------------------------------------------------

    def _load_storage(self) -> None:
        """
        Load metadata from local JSON storage.

        This is a safe dev/local persistence layer.
        In production, replace with database repository while keeping public
        methods unchanged.
        """
        try:
            if not self.storage_path.exists():
                return

            with self.storage_path.open("r", encoding="utf-8") as file:
                raw = json.load(file)

            models = raw.get("models", {})
            if not isinstance(models, dict):
                return

            loaded: Dict[str, VoiceModelMetadata] = {}

            for model_id, item in models.items():
                try:
                    consent_raw = item.get("consent", {})
                    consent = ConsentRecord(
                        consent_id=consent_raw.get("consent_id", f"consent_{uuid.uuid4().hex}"),
                        consent_type=consent_raw.get("consent_type", ConsentType.NONE.value),
                        consent_given=bool(consent_raw.get("consent_given", False)),
                        consent_given_at=consent_raw.get("consent_given_at"),
                        consent_given_by_user_id=consent_raw.get("consent_given_by_user_id"),
                        consent_scope=list(consent_raw.get("consent_scope", [])),
                        consent_reference_hash=consent_raw.get("consent_reference_hash"),
                        consent_notes=consent_raw.get("consent_notes"),
                        revoked_at=consent_raw.get("revoked_at"),
                        revoked_by_user_id=consent_raw.get("revoked_by_user_id"),
                        revocation_reason=consent_raw.get("revocation_reason"),
                    )

                    record = VoiceModelMetadata(
                        model_id=item.get("model_id", model_id),
                        user_id=item["user_id"],
                        workspace_id=item["workspace_id"],
                        display_name=item.get("display_name", "Voice Model"),
                        owner_user_id=item.get("owner_user_id", item["user_id"]),
                        status=item.get("status", VoiceCloneStatus.PENDING_CONSENT.value),
                        visibility=item.get("visibility", VoiceModelVisibility.PRIVATE_USER.value),
                        provider=item.get("provider", "local_metadata_only"),
                        model_reference=item.get("model_reference"),
                        voice_sample_hashes=list(item.get("voice_sample_hashes", [])),
                        consent=consent,
                        created_at=item.get("created_at", _utc_now()),
                        updated_at=item.get("updated_at", _utc_now()),
                        created_by=item.get("created_by"),
                        updated_by=item.get("updated_by"),
                        language=item.get("language"),
                        accent=item.get("accent"),
                        gender_label=item.get("gender_label"),
                        tags=list(item.get("tags", [])),
                        safety_flags=list(item.get("safety_flags", [])),
                        metadata=dict(item.get("metadata", {})),
                    )

                    loaded[record.model_id] = record

                except Exception:
                    logger.exception("Failed to load one voice model record safely.")

            self._models = loaded

        except Exception:
            logger.exception("VoiceCloning storage load failed. Continuing with empty storage.")
            self._models = {}

    def _persist_if_enabled(self) -> None:
        """
        Persist metadata if auto_persist is enabled.
        """
        if not self.auto_persist:
            return
        self._save_storage()

    def _save_storage(self) -> None:
        """
        Save metadata to local JSON storage.
        """
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)

            raw = {
                "version": self.VERSION,
                "agent": self.agent_name,
                "updated_at": _utc_now(),
                "models": {
                    model_id: asdict(record)
                    for model_id, record in self._models.items()
                },
            }

            tmp_path = self.storage_path.with_suffix(".tmp")
            with tmp_path.open("w", encoding="utf-8") as file:
                json.dump(raw, file, indent=2, ensure_ascii=False)

            tmp_path.replace(self.storage_path)

        except Exception:
            logger.exception("VoiceCloning storage save failed.")

    # -----------------------------------------------------------------------
    # Dashboard/API helper methods
    # -----------------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Return registry/dashboard compatible manifest.
        """
        return {
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "agent_type": self.AGENT_TYPE,
            "version": self.VERSION,
            "description": "Consent-only custom voice cloning metadata manager.",
            "actions": [action.value for action in VoiceCloneAction],
            "security_required_actions": sorted(self.SECURITY_REQUIRED_ACTIONS),
            "safe_read_actions": sorted(self.SAFE_READ_ACTIONS),
            "requires_user_id": True,
            "requires_workspace_id": True,
            "stores_raw_audio": False,
            "stores_voice_metadata": True,
            "supports_verification_payload": True,
            "supports_memory_payload": True,
            "supports_audit_log": True,
            "supports_events": True,
        }

    def get_recent_events(
        self,
        context: Dict[str, Any],
        limit: int = 50,
    ) -> Dict[str, Any]:
        """
        Return recent events scoped to user/workspace.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        user_id = self._context_user_id(context)
        workspace_id = self._context_workspace_id(context)
        limit = max(1, min(int(limit or 50), 200))

        with self._lock:
            events = [
                event for event in self._events
                if event.user_id == user_id and event.workspace_id == workspace_id
            ][-limit:]

        return self._safe_result(
            message="Recent voice cloning events loaded.",
            data={"events": [asdict(event) for event in events]},
            metadata={"agent": self.agent_name},
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Basic health check for dashboard/API.
        """
        with self._lock:
            model_count = len(self._models)
            event_count = len(self._events)

        return self._safe_result(
            message="VoiceCloning is healthy.",
            data={
                "agent": self.agent_name,
                "version": self.VERSION,
                "model_count": model_count,
                "event_count": event_count,
                "storage_path": str(self.storage_path),
                "auto_persist": self.auto_persist,
            },
            metadata={"agent": self.agent_name},
        )


# ---------------------------------------------------------------------------
# Local smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    manager = VoiceCloning(
        storage_path=".william/dev_voice_cloning_metadata.json",
        auto_persist=False,
    )

    test_context = {
        "user_id": "user_demo_1",
        "workspace_id": "workspace_demo_1",
        "role": "owner",
    }

    created = manager.create_model_record(
        context=test_context,
        display_name="Demo Consent Voice",
        voice_sample_references=["sample-file-id-1", "sample-file-id-2"],
        language="en",
        accent="neutral",
        tags=["demo", "testing_only"],
    )

    print(json.dumps(created, indent=2))

    if created["success"]:
        created_model_id = created["data"]["model"]["model_id"]

        consent = manager.register_consent(
            context=test_context,
            model_id=created_model_id,
            consent_type=ConsentType.EXPLICIT_UPLOAD.value,
            consent_scope=["tts_generation", "testing_only"],
            consent_reference="demo-consent-reference",
            consent_notes="Demo consent for local smoke test.",
        )

        print(json.dumps(consent, indent=2))

        training = manager.request_training(
            context=test_context,
            model_id=created_model_id,
            training_options={"quality": "standard", "language": "en"},
        )

        print(json.dumps(training, indent=2))

        activated = manager.activate_model(
            context=test_context,
            model_id=created_model_id,
            provider_model_reference="provider-model-demo-reference",
        )

        print(json.dumps(activated, indent=2))

        access = manager.verify_model_access(
            context=test_context,
            model_id=created_model_id,
            required_scope="tts_generation",
        )

        print(json.dumps(access, indent=2))

    print("FILE COMPLETE")