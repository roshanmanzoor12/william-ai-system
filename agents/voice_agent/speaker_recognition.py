"""
agents/voice_agent/speaker_recognition.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Verifies WHO is speaking (voice identity), for Phase 9's trusted-voice
    access control -- distinct from agents/voice_agent/emotion_detector.py
    (which analyzes tone/urgency/stress in speech, not identity).

Root-cause note: this file previously existed as a byte-for-byte duplicate of
emotion_detector.py (same class, same content, wrong filename) -- there was
no real speaker-recognition implementation anywhere in the codebase. This is
the real implementation.

This file does not perform real biometric voice matching itself -- no local
model ships with this repo. It is a provider-routing engine, exactly like
stt_engine.py/tts_engine.py: real verification happens through an injected
`provider_callbacks` entry if one is configured; with no provider configured,
every enrollment/verification attempt returns a structured
`external_dependency_required` result rather than a fake success.

Hard rules enforced here:
    - Raw audio is never stored. Callers pass an opaque `voice_sample_ref`
      (a handle/path/id the caller -- e.g. the voice worker -- manages and
      discards; this engine never persists it). Only a provider-returned
      `voiceprint_reference_id` (an opaque string) may be persisted, by the
      caller, onto a VoiceIdentityProfile row.
    - No fake "verified" result is ever returned when no provider is
      configured -- the mock path used by stt_engine.py/tts_engine.py
      (a friendly but effectively empty fallback) is deliberately NOT used
      here, because speaker verification is an access-control decision, not
      a UX nicety; a fake "verified" would be a real security hole.
    - A narrow, explicit dev-only bypass exists for local development so the
      voice pipeline can be smoke-tested without a real biometric provider.
      It requires BOTH `WILLIAM_VOICE_DEV_ADMIN_BYPASS=true` AND a
      non-production environment (`WILLIAM_ENVIRONMENT`/`ENVIRONMENT` not
      "production"), and it only ever resolves to the workspace OWNER
      identity -- never to an arbitrary trusted profile -- so it cannot be
      used to impersonate a specific trusted voice. Every bypass use is
      logged via audit event with `dev_bypass: true` so it is never silently
      indistinguishable from a real verification in logs/dashboard.
"""

from __future__ import annotations

import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:
        """Fallback BaseAgent stub, keeps this file import-safe."""

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "voice_agent")


logger = logging.getLogger("william.voice_agent.speaker_recognition")
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------
# Enums / Dataclasses
# ---------------------------------------------------------------------

class SpeakerRecognitionProvider(str, Enum):
    AUTO = "auto"
    LOCAL_MODEL = "local_model"
    CLOUD = "cloud"
    MOCK = "mock"


class SpeakerVerificationStatus(str, Enum):
    MATCHED = "matched"
    NO_MATCH = "no_match"
    UNKNOWN_SPEAKER = "unknown_speaker"
    EXTERNAL_DEPENDENCY_REQUIRED = "external_dependency_required"
    DEV_BYPASS = "dev_bypass"
    ERROR = "error"


@dataclass
class SpeakerRecognitionContext:
    """SaaS-isolated context, matching STTContext/TTSContext's shape."""

    user_id: Optional[str] = None
    workspace_id: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SpeakerEnrollmentResult:
    success: bool
    status: SpeakerVerificationStatus
    voiceprint_reference_id: Optional[str] = None
    provider: SpeakerRecognitionProvider = SpeakerRecognitionProvider.AUTO
    message: str = ""
    raw_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SpeakerVerificationResult:
    success: bool
    status: SpeakerVerificationStatus
    matched_profile_id: Optional[str] = None
    confidence: float = 0.0
    provider: SpeakerRecognitionProvider = SpeakerRecognitionProvider.AUTO
    dev_bypass: bool = False
    message: str = ""
    raw_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SpeakerRecognitionConfig:
    default_provider: SpeakerRecognitionProvider = SpeakerRecognitionProvider.AUTO
    min_confidence: float = 0.75
    require_user_context: bool = True
    require_workspace_context: bool = True
    emit_events: bool = True
    audit_enabled: bool = True
    verification_enabled: bool = True


# ---------------------------------------------------------------------
# Dev bypass helpers
# ---------------------------------------------------------------------

def _truthy_env(value: Optional[str]) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def dev_admin_voice_bypass_active() -> bool:
    """
    True only when WILLIAM_VOICE_DEV_ADMIN_BYPASS is explicitly enabled AND
    the environment is not production. Documented, narrow, dev-only escape
    hatch -- see module docstring. NEVER enable
    WILLIAM_VOICE_DEV_ADMIN_BYPASS in a production deployment.
    """
    if not _truthy_env(os.getenv("WILLIAM_VOICE_DEV_ADMIN_BYPASS")):
        return False

    environment = (os.getenv("WILLIAM_ENVIRONMENT") or os.getenv("ENVIRONMENT") or "development").strip().lower()
    if environment == "production":
        logger.warning(
            "WILLIAM_VOICE_DEV_ADMIN_BYPASS is set but environment=production -- bypass refused."
        )
        return False

    return True


# ---------------------------------------------------------------------
# Main Engine
# ---------------------------------------------------------------------

class SpeakerRecognitionEngine(BaseAgent):
    """
    Provider-routing speaker identity engine for the Voice Agent.

    Real verification requires a provider callback registered under
    `provider_callbacks["local_model"]` or `provider_callbacks["cloud"]`,
    each a `Callable[[dict], dict]`. With none configured, every call
    returns a structured external_dependency_required result (or, in
    explicit dev-only mode, an owner-identity bypass result) -- never a
    fake match.
    """

    def __init__(
        self,
        config: Optional[SpeakerRecognitionConfig] = None,
        provider_callbacks: Optional[Dict[str, Callable[..., Dict[str, Any]]]] = None,
        security_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            agent_name=kwargs.pop("agent_name", "SpeakerRecognitionEngine"),
            agent_type=kwargs.pop("agent_type", "voice_agent"),
            *args,
            **kwargs,
        )
        self.config = config or SpeakerRecognitionConfig()
        self.provider_callbacks = provider_callbacks or {}
        self.security_callback = security_callback
        self.audit_callback = audit_callback
        self.event_callback = event_callback

    # -------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------

    def enroll_speaker(
        self,
        voice_sample_ref: Any,
        *,
        profile_id: str,
        context: Optional[Union[SpeakerRecognitionContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Enroll a voiceprint for `profile_id`. Never stores raw audio -- only
        forwards the caller-managed `voice_sample_ref` handle to a real
        provider callback if one is configured, and persists nothing itself
        (the caller is responsible for storing the returned
        voiceprint_reference_id onto the VoiceIdentityProfile row).
        """
        context_check = self._validate_task_context(context)
        if not context_check["success"]:
            return context_check

        provider, callback = self._resolve_provider("enroll")

        if callback is None:
            result = SpeakerEnrollmentResult(
                success=False,
                status=SpeakerVerificationStatus.EXTERNAL_DEPENDENCY_REQUIRED,
                provider=provider,
                message=(
                    "No real speaker-recognition provider is configured. "
                    "Enrollment cannot proceed until one is connected."
                ),
                raw_metadata={"required_integrations": ["speaker_recognition_provider"]},
            )
            self._log_audit_event("speaker_enroll_unavailable", context, {"profile_id": profile_id})
            return self._result_from_enrollment(result, profile_id)

        try:
            raw = callback({"voice_sample_ref": voice_sample_ref, "profile_id": profile_id, "context": self._context_to_public_dict(context)})
            voiceprint_reference_id = raw.get("voiceprint_reference_id") if isinstance(raw, dict) else None

            if not voiceprint_reference_id:
                result = SpeakerEnrollmentResult(
                    success=False,
                    status=SpeakerVerificationStatus.ERROR,
                    provider=provider,
                    message="Provider did not return a voiceprint_reference_id.",
                    raw_metadata={"provider_response": raw},
                )
            else:
                result = SpeakerEnrollmentResult(
                    success=True,
                    status=SpeakerVerificationStatus.MATCHED,
                    voiceprint_reference_id=str(voiceprint_reference_id),
                    provider=provider,
                    message="Voiceprint enrolled.",
                )
        except Exception as exc:  # noqa: BLE001
            result = SpeakerEnrollmentResult(
                success=False,
                status=SpeakerVerificationStatus.ERROR,
                provider=provider,
                message=f"Enrollment provider raised an error: {exc}",
            )

        self._log_audit_event("speaker_enroll_attempted", context, {"profile_id": profile_id, "success": result.success})
        return self._result_from_enrollment(result, profile_id)

    def verify_speaker(
        self,
        voice_sample_ref: Any,
        *,
        candidate_profiles: Optional[Sequence[Dict[str, Any]]] = None,
        context: Optional[Union[SpeakerRecognitionContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Verify a spoken sample against `candidate_profiles` (each expected to
        carry at least `profile_id` and `voiceprint_reference_id`). Returns
        the best match if confidence >= config.min_confidence, otherwise
        NO_MATCH/UNKNOWN_SPEAKER. With no provider configured, returns
        EXTERNAL_DEPENDENCY_REQUIRED unless the explicit dev bypass is active
        (see dev_admin_voice_bypass_active()), in which case the result
        always resolves to the workspace owner identity, clearly flagged
        dev_bypass=True.
        """
        context_check = self._validate_task_context(context)
        if not context_check["success"]:
            return context_check

        provider, callback = self._resolve_provider("verify")

        if callback is None:
            if dev_admin_voice_bypass_active():
                result = SpeakerVerificationResult(
                    success=True,
                    status=SpeakerVerificationStatus.DEV_BYPASS,
                    matched_profile_id="owner",
                    confidence=1.0,
                    provider=SpeakerRecognitionProvider.MOCK,
                    dev_bypass=True,
                    message=(
                        "WILLIAM_VOICE_DEV_ADMIN_BYPASS is active (non-production only): "
                        "identity resolved to the workspace owner without real speaker "
                        "verification. Never enable this in production."
                    ),
                )
                self._log_audit_event(
                    "speaker_verify_dev_bypass",
                    context,
                    {"dev_bypass": True, "resolved_identity": "owner"},
                )
                return self._result_from_verification(result)

            result = SpeakerVerificationResult(
                success=False,
                status=SpeakerVerificationStatus.EXTERNAL_DEPENDENCY_REQUIRED,
                provider=provider,
                message=(
                    "No real speaker-recognition provider is configured. "
                    "Voice commands cannot be attributed to a verified speaker."
                ),
                raw_metadata={"required_integrations": ["speaker_recognition_provider"]},
            )
            self._log_audit_event("speaker_verify_unavailable", context, {})
            return self._result_from_verification(result)

        try:
            raw = callback(
                {
                    "voice_sample_ref": voice_sample_ref,
                    "candidate_profiles": list(candidate_profiles or []),
                    "context": self._context_to_public_dict(context),
                }
            )
            matched_profile_id = raw.get("matched_profile_id") if isinstance(raw, dict) else None
            confidence = float(raw.get("confidence", 0.0)) if isinstance(raw, dict) else 0.0

            if matched_profile_id and confidence >= self.config.min_confidence:
                result = SpeakerVerificationResult(
                    success=True,
                    status=SpeakerVerificationStatus.MATCHED,
                    matched_profile_id=str(matched_profile_id),
                    confidence=confidence,
                    provider=provider,
                    message="Speaker verified.",
                )
            else:
                result = SpeakerVerificationResult(
                    success=False,
                    status=SpeakerVerificationStatus.UNKNOWN_SPEAKER,
                    confidence=confidence,
                    provider=provider,
                    message="Speaker could not be matched to any enrolled voice profile.",
                )
        except Exception as exc:  # noqa: BLE001
            result = SpeakerVerificationResult(
                success=False,
                status=SpeakerVerificationStatus.ERROR,
                provider=provider,
                message=f"Verification provider raised an error: {exc}",
            )

        self._log_audit_event(
            "speaker_verify_attempted",
            context,
            {"success": result.success, "matched_profile_id": result.matched_profile_id},
        )
        return self._result_from_verification(result)

    def health_check(self) -> Dict[str, Any]:
        configured_providers = sorted(self.provider_callbacks.keys())
        return self._safe_result(
            message="SpeakerRecognitionEngine health check.",
            data={
                "configured_providers": configured_providers,
                "provider_configured": bool(configured_providers),
                "dev_bypass_available": dev_admin_voice_bypass_active(),
            },
        )

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """BaseAgent-compatible dispatcher."""
        task = task or {}
        action = str(task.get("action") or "").strip().lower()
        context = task.get("context")

        if action == "enroll":
            return self.enroll_speaker(
                task.get("voice_sample_ref"),
                profile_id=task.get("profile_id"),
                context=context,
            )
        if action == "verify":
            return self.verify_speaker(
                task.get("voice_sample_ref"),
                candidate_profiles=task.get("candidate_profiles"),
                context=context,
            )
        if action == "health_check":
            return self.health_check()

        return self._error_result(
            f"Unsupported SpeakerRecognitionEngine action: {action}",
            ValueError(f"Unsupported action: {action}"),
        )

    # -------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------

    def _resolve_provider(self, operation: str) -> Tuple[SpeakerRecognitionProvider, Optional[Callable]]:
        for candidate in (SpeakerRecognitionProvider.LOCAL_MODEL, SpeakerRecognitionProvider.CLOUD):
            callback = self.provider_callbacks.get(candidate.value)
            if callable(callback):
                return candidate, callback
        return SpeakerRecognitionProvider.AUTO, None

    def _context_to_dict(self, context: Optional[Union[SpeakerRecognitionContext, Dict[str, Any]]]) -> Dict[str, Any]:
        if context is None:
            return {}
        if isinstance(context, SpeakerRecognitionContext):
            return asdict(context)
        if isinstance(context, dict):
            return dict(context)
        return {}

    def _context_to_public_dict(self, context: Optional[Union[SpeakerRecognitionContext, Dict[str, Any]]]) -> Dict[str, Any]:
        ctx = self._context_to_dict(context)
        return {
            "user_id": ctx.get("user_id"),
            "workspace_id": ctx.get("workspace_id"),
            "device_id": ctx.get("device_id"),
            "session_id": ctx.get("session_id"),
            "request_id": ctx.get("request_id"),
        }

    def _validate_task_context(
        self,
        context: Optional[Union[SpeakerRecognitionContext, Dict[str, Any]]],
    ) -> Dict[str, Any]:
        if context is None:
            if self.config.require_user_context or self.config.require_workspace_context:
                return self._error_result(
                    "Context validation failed.",
                    ValueError("user_id and workspace_id are required."),
                )
            return self._safe_result(message="Context validation skipped.", data={"valid": True})

        ctx = self._context_to_dict(context)
        user_id = ctx.get("user_id")
        workspace_id = ctx.get("workspace_id")

        if self.config.require_user_context and not user_id:
            return self._error_result("Context validation failed.", ValueError("user_id is required."))
        if self.config.require_workspace_context and not workspace_id:
            return self._error_result("Context validation failed.", ValueError("workspace_id is required."))

        return self._safe_result(message="Context validation passed.", data={"valid": True})

    def _result_from_enrollment(
        self,
        result: SpeakerEnrollmentResult,
        profile_id: str,
    ) -> Dict[str, Any]:
        data = asdict(result)
        data["status"] = result.status.value
        data["provider"] = result.provider.value
        data["profile_id"] = profile_id

        if result.success:
            return self._safe_result(message=result.message, data=data)
        return self._error_result(result.message, RuntimeError(result.status.value), data=data)

    def _result_from_verification(self, result: SpeakerVerificationResult) -> Dict[str, Any]:
        data = asdict(result)
        data["status"] = result.status.value
        data["provider"] = result.provider.value

        if result.success:
            return self._safe_result(message=result.message, data=data)
        return self._error_result(result.message, RuntimeError(result.status.value), data=data)

    def _emit_agent_event(self, event_type: str, payload: Optional[Dict[str, Any]] = None) -> None:
        if not self.config.emit_events or not self.event_callback:
            return
        try:
            self.event_callback({
                "event_id": str(uuid.uuid4()),
                "event_type": event_type,
                "agent": "SpeakerRecognitionEngine",
                "payload": payload or {},
                "timestamp": time.time(),
            })
        except Exception:
            logger.exception("Failed to emit SpeakerRecognitionEngine event.")

    def _log_audit_event(
        self,
        action: str,
        context: Optional[Union[SpeakerRecognitionContext, Dict[str, Any]]],
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        if not self.config.audit_enabled:
            return
        audit = {
            "audit_id": str(uuid.uuid4()),
            "agent": "SpeakerRecognitionEngine",
            "action": action,
            "context": self._context_to_public_dict(context),
            "details": details or {},
            "timestamp": time.time(),
        }
        try:
            if self.audit_callback:
                self.audit_callback(audit)
            else:
                logger.info("AUDIT | %s", audit)
        except Exception:
            logger.exception("Failed to log SpeakerRecognitionEngine audit event.")

    def _safe_result(self, message: str, data: Optional[Dict[str, Any]] = None, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {"success": True, "message": message, "data": data or {}, "error": None, "metadata": metadata or {}}

    def _error_result(self, message: str, error: Exception, data: Optional[Dict[str, Any]] = None, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {"type": error.__class__.__name__, "message": str(error)},
            "metadata": metadata or {},
        }


__all__ = [
    "SpeakerRecognitionEngine",
    "SpeakerRecognitionConfig",
    "SpeakerRecognitionContext",
    "SpeakerRecognitionProvider",
    "SpeakerVerificationStatus",
    "SpeakerEnrollmentResult",
    "SpeakerVerificationResult",
    "dev_admin_voice_bypass_active",
]
