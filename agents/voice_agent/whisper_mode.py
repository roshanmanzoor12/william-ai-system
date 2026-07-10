"""
agents/voice_agent/whisper_mode.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Private low-volume mode and text fallback for sensitive contexts.

This module is part of the Voice Agent. It decides whether William should:
    - Speak quietly
    - Reduce TTS volume/speed
    - Switch to text-only fallback
    - Hide sensitive content from spoken output
    - Route sensitive/private contexts to Security Agent metadata
    - Prepare Memory Agent and Verification Agent payloads
    - Emit dashboard/agent events safely

This file is safe to import even if the rest of the William/Jarvis system
is not fully created yet.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Union


# =============================================================================
# Safe Optional BaseAgent Import
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe before the real BaseAgent exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s | %s", event_name, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback audit_log: %s", payload)


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("WhisperMode")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Enums
# =============================================================================

class WhisperModeState(str, Enum):
    """Whisper mode state."""

    OFF = "off"
    ON = "on"
    AUTO = "auto"
    TEXT_ONLY = "text_only"
    MUTED = "muted"


class PrivacyLevel(str, Enum):
    """Privacy/sensitivity level for response routing."""

    PUBLIC = "public"
    NORMAL = "normal"
    PRIVATE = "private"
    SENSITIVE = "sensitive"
    HIGHLY_SENSITIVE = "highly_sensitive"


class OutputChannel(str, Enum):
    """Final output channel recommendation."""

    VOICE = "voice"
    LOW_VOLUME_VOICE = "low_volume_voice"
    TEXT = "text"
    BOTH = "both"
    SILENT = "silent"


class WhisperReason(str, Enum):
    """Reasons why whisper/text fallback may be activated."""

    USER_REQUESTED = "user_requested"
    LOW_VOLUME_CONTEXT = "low_volume_context"
    SENSITIVE_CONTENT = "sensitive_content"
    PRIVATE_CONTEXT = "private_context"
    SECURITY_POLICY = "security_policy"
    DEVICE_PRIVACY = "device_privacy"
    QUIET_HOURS = "quiet_hours"
    EMOTION_DETECTED_WHISPER = "emotion_detected_whisper"
    UNKNOWN = "unknown"


class SecuritySensitivity(str, Enum):
    """Security handling level."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class WhisperModeConfig:
    """
    Configuration for WhisperMode.

    This can later be loaded per user/workspace from dashboard settings.
    """

    agent_name: str = "WhisperMode"
    agent_id: str = "voice_agent.whisper_mode"

    default_state: WhisperModeState = WhisperModeState.AUTO

    enable_auto_detection: bool = True
    enable_text_fallback: bool = True
    enable_low_volume_voice: bool = True
    enable_sensitive_content_filter: bool = True
    enable_quiet_hours: bool = False
    enable_device_privacy_mode: bool = True

    default_voice_volume: float = 0.75
    whisper_voice_volume: float = 0.28
    sensitive_voice_volume: float = 0.18
    muted_voice_volume: float = 0.0

    default_tts_speed: float = 1.0
    whisper_tts_speed: float = 0.90
    sensitive_tts_speed: float = 0.86

    default_tts_pitch: float = 1.0
    whisper_tts_pitch: float = 0.94

    max_spoken_sensitive_chars: int = 120
    max_text_preview_chars: int = 500

    store_raw_text_in_memory_payload: bool = False
    store_sensitive_text_in_logs: bool = False

    quiet_hours_start: Optional[int] = None
    quiet_hours_end: Optional[int] = None

    require_security_for_highly_sensitive: bool = True
    allow_security_escalation: bool = True

    audit_enabled: bool = True
    event_enabled: bool = True


@dataclass
class WhisperContext:
    """
    Optional context passed from Voice Agent, Master Agent, dashboard, or device layer.
    """

    current_mode: Optional[WhisperModeState] = None
    user_requested_whisper: bool = False
    user_requested_text_only: bool = False
    user_requested_mute: bool = False

    device_is_public: bool = False
    device_has_headphones: bool = False
    device_volume_level: Optional[float] = None
    environment_noise_level: Optional[float] = None

    emotion_whisper_detected: bool = False
    emotion_stress_level: Optional[str] = None
    emotion_urgency_level: Optional[str] = None

    privacy_level: Optional[PrivacyLevel] = None
    current_hour: Optional[int] = None

    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WhisperDecision:
    """
    Final whisper-mode decision.
    """

    mode_state: WhisperModeState
    output_channel: OutputChannel
    privacy_level: PrivacyLevel
    security_sensitivity: SecuritySensitivity
    should_speak: bool
    should_use_text_fallback: bool
    should_redact_spoken_output: bool
    voice_settings: Dict[str, Any]
    text_settings: Dict[str, Any]
    reasons: List[str]
    safe_spoken_text: Optional[str]
    safe_text_output: Optional[str]
    warnings: List[str]


# =============================================================================
# Whisper Mode
# =============================================================================

class WhisperMode(BaseAgent):
    """
    Private low-volume mode and text fallback manager.

    Main public methods:
        - decide()
        - enable()
        - disable()
        - force_text_only()
        - mute()
        - prepare_output()
        - sanitize_spoken_text()
        - detect_privacy_level()

    This class does not execute real TTS.
    It only prepares safe metadata and output instructions for:
        - Voice Agent
        - TTS Engine
        - Master Agent
        - Security Agent
        - Verification Agent
        - Memory Agent
        - Dashboard/API
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        config: Optional[WhisperModeConfig] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self.config = config or WhisperModeConfig()

        super().__init__(
            agent_name=self.config.agent_name,
            agent_id=self.config.agent_id,
            *args,
            **kwargs,
        )

        self.logger = logging.getLogger(self.config.agent_name)

        self._session_states: Dict[str, WhisperModeState] = {}
        self._private_keywords = self._build_private_keywords()
        self._sensitive_keywords = self._build_sensitive_keywords()
        self._highly_sensitive_keywords = self._build_highly_sensitive_keywords()
        self._whisper_request_patterns = self._build_whisper_request_patterns()
        self._text_only_patterns = self._build_text_only_patterns()
        self._mute_patterns = self._build_mute_patterns()

    # =========================================================================
    # Public Main API
    # =========================================================================

    def decide(
        self,
        text: Optional[str] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        session_id: Optional[str] = None,
        task_id: Optional[str] = None,
        context: Optional[Union[WhisperContext, Dict[str, Any]]] = None,
        requested_mode: Optional[Union[str, WhisperModeState]] = None,
    ) -> Dict[str, Any]:
        """
        Decide whether William should whisper, speak normally, mute, or use text fallback.
        """

        started_at = time.time()
        request_id = self._new_request_id()

        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            request_id=request_id,
            context=context,
        )

        if not validation["success"]:
            return validation

        safe_text = self._normalize_text(text)
        whisper_context = self._normalize_context(context)

        if requested_mode is not None:
            whisper_context.current_mode = self._to_mode_state(requested_mode)

        decision = self._make_decision(
            text=safe_text,
            context=whisper_context,
            session_id=session_id,
        )

        security_required = self._requires_security_check(
            text=safe_text,
            decision=decision,
            context=whisper_context,
        )

        security_payload = None
        if security_required:
            security_payload = self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                session_id=session_id,
                task_id=task_id,
                request_id=request_id,
                text=safe_text,
                decision=decision,
                context=whisper_context,
            )

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            request_id=request_id,
            decision=decision,
            security_payload=security_payload,
        )

        memory_payload = self._prepare_memory_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            request_id=request_id,
            text=safe_text,
            decision=decision,
        )

        audit_payload = self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            request_id=request_id,
            action="whisper_mode_decision_completed",
            decision=decision,
            context=whisper_context,
        )

        event_payload = self._emit_agent_event(
            event_name="voice.whisper_mode_decided",
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            request_id=request_id,
            decision=decision,
        )

        metadata = self._base_metadata(
            request_id=request_id,
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            started_at=started_at,
        )

        metadata.update(
            {
                "security_check_required": security_required,
                "security_payload": security_payload,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "audit_payload": audit_payload,
                "event_payload": event_payload,
                "version": self.VERSION,
            }
        )

        return self._safe_result(
            message="Whisper mode decision completed successfully.",
            data=self._decision_to_dict(decision),
            metadata=metadata,
        )

    def prepare_output(
        self,
        response_text: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        session_id: Optional[str] = None,
        task_id: Optional[str] = None,
        context: Optional[Union[WhisperContext, Dict[str, Any]]] = None,
        requested_mode: Optional[Union[str, WhisperModeState]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare final voice/text output instructions for TTS Engine or UI.

        This does not speak. It only returns:
            - output_channel
            - safe_spoken_text
            - safe_text_output
            - TTS volume/speed/pitch
            - privacy metadata
        """

        decision_result = self.decide(
            text=response_text,
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            context=context,
            requested_mode=requested_mode,
        )

        if not decision_result["success"]:
            return decision_result

        decision_data = decision_result["data"]

        return self._safe_result(
            message="Whisper-safe output prepared.",
            data={
                "output_channel": decision_data["output_channel"],
                "should_speak": decision_data["should_speak"],
                "should_use_text_fallback": decision_data["should_use_text_fallback"],
                "safe_spoken_text": decision_data["safe_spoken_text"],
                "safe_text_output": decision_data["safe_text_output"],
                "voice_settings": decision_data["voice_settings"],
                "text_settings": decision_data["text_settings"],
                "privacy_level": decision_data["privacy_level"],
                "security_sensitivity": decision_data["security_sensitivity"],
                "reasons": decision_data["reasons"],
                "warnings": decision_data["warnings"],
            },
            metadata=decision_result["metadata"],
        )

    def enable(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        session_id: str,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Enable whisper mode for a session.
        """

        return self._set_session_mode(
            mode=WhisperModeState.ON,
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            action="whisper_mode_enabled",
        )

    def disable(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        session_id: str,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Disable whisper mode for a session.
        """

        return self._set_session_mode(
            mode=WhisperModeState.OFF,
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            action="whisper_mode_disabled",
        )

    def force_text_only(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        session_id: str,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Force text-only output for a session.
        """

        return self._set_session_mode(
            mode=WhisperModeState.TEXT_ONLY,
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            action="whisper_mode_text_only_enabled",
        )

    def mute(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        session_id: str,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Mute voice output for a session.
        """

        return self._set_session_mode(
            mode=WhisperModeState.MUTED,
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            action="whisper_mode_muted",
        )

    def get_session_mode(self, session_id: Optional[str]) -> WhisperModeState:
        """
        Get current session whisper mode.
        """

        if not session_id:
            return self.config.default_state

        return self._session_states.get(session_id, self.config.default_state)

    def sanitize_spoken_text(
        self,
        text: str,
        privacy_level: Union[str, PrivacyLevel] = PrivacyLevel.NORMAL,
    ) -> Dict[str, Any]:
        """
        Sanitize text before it goes to TTS.

        Sensitive/private content can be shortened or replaced with a safer spoken message.
        """

        safe_text = self._normalize_text(text)
        level = self._to_privacy_level(privacy_level)

        sanitized, redacted, warnings = self._sanitize_for_voice(
            text=safe_text,
            privacy_level=level,
        )

        return self._safe_result(
            message="Spoken text sanitized.",
            data={
                "original_length": len(safe_text),
                "sanitized_length": len(sanitized or ""),
                "redacted": redacted,
                "safe_spoken_text": sanitized,
                "privacy_level": level.value,
                "warnings": warnings,
            },
            metadata={
                "timestamp": self._now(),
                "version": self.VERSION,
            },
        )

    def detect_privacy_level(
        self,
        text: Optional[str] = None,
        context: Optional[Union[WhisperContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Detect privacy level from text and context.
        """

        safe_text = self._normalize_text(text)
        whisper_context = self._normalize_context(context)

        privacy_level, sensitivity, reasons = self._detect_privacy_and_sensitivity(
            text=safe_text,
            context=whisper_context,
        )

        return self._safe_result(
            message="Privacy level detected.",
            data={
                "privacy_level": privacy_level.value,
                "security_sensitivity": sensitivity.value,
                "reasons": reasons,
            },
            metadata={
                "timestamp": self._now(),
                "version": self.VERSION,
            },
        )

    # =========================================================================
    # Compatibility Hooks
    # =========================================================================

    def _validate_task_context(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        session_id: Optional[str] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        context: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation.

        Every user-specific execution should include user_id and workspace_id.
        """

        missing: List[str] = []

        if user_id is None or str(user_id).strip() == "":
            missing.append("user_id")

        if workspace_id is None or str(workspace_id).strip() == "":
            missing.append("workspace_id")

        if missing:
            return self._error_result(
                message="Missing required SaaS isolation context.",
                error_code="MISSING_CONTEXT",
                data={
                    "missing_fields": missing,
                    "required_fields": ["user_id", "workspace_id"],
                    "session_id": session_id,
                    "task_id": task_id,
                },
                metadata={
                    "request_id": request_id,
                    "timestamp": self._now(),
                    "agent_id": self.config.agent_id,
                },
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "session_id": session_id,
                "task_id": task_id,
            },
            metadata={
                "request_id": request_id,
                "timestamp": self._now(),
            },
        )

    def _requires_security_check(
        self,
        text: Optional[str],
        decision: WhisperDecision,
        context: WhisperContext,
    ) -> bool:
        """
        Decide if Security Agent should review this whisper/privacy event.
        """

        if not self.config.allow_security_escalation:
            return False

        if decision.security_sensitivity in {
            SecuritySensitivity.HIGH,
            SecuritySensitivity.CRITICAL,
        }:
            return True

        if decision.privacy_level == PrivacyLevel.HIGHLY_SENSITIVE:
            return self.config.require_security_for_highly_sensitive

        if context.metadata.get("force_security_check") is True:
            return True

        if self._contains_highly_sensitive_text(text or ""):
            return True

        return False

    def _request_security_approval(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        session_id: Optional[str],
        task_id: Optional[str],
        request_id: str,
        text: Optional[str],
        decision: WhisperDecision,
        context: WhisperContext,
    ) -> Dict[str, Any]:
        """
        Prepare Security Agent-compatible payload.

        This file does not call Security Agent directly. The Master Agent or
        Agent Router can forward this payload.
        """

        return {
            "target_agent": "security_agent",
            "action": "review_whisper_mode_privacy_decision",
            "requires_approval": False,
            "requires_safe_routing": True,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "session_id": session_id,
            "task_id": task_id,
            "request_id": request_id,
            "privacy_level": decision.privacy_level.value,
            "security_sensitivity": decision.security_sensitivity.value,
            "output_channel": decision.output_channel.value,
            "should_use_text_fallback": decision.should_use_text_fallback,
            "should_redact_spoken_output": decision.should_redact_spoken_output,
            "reasons": decision.reasons,
            "raw_text_included": False,
            "context": {
                "source_agent": self.config.agent_id,
                "purpose": "privacy_safe_voice_output",
                "device_is_public": context.device_is_public,
                "device_has_headphones": context.device_has_headphones,
                "timestamp": self._now(),
            },
        }

    def _prepare_verification_payload(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        session_id: Optional[str],
        task_id: Optional[str],
        request_id: str,
        decision: WhisperDecision,
        security_payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent-compatible payload.
        """

        return {
            "target_agent": "verification_agent",
            "source_agent": self.config.agent_id,
            "verification_type": "whisper_mode_decision",
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "session_id": session_id,
            "task_id": task_id,
            "request_id": request_id,
            "result_summary": {
                "mode_state": decision.mode_state.value,
                "output_channel": decision.output_channel.value,
                "privacy_level": decision.privacy_level.value,
                "security_sensitivity": decision.security_sensitivity.value,
                "should_speak": decision.should_speak,
                "should_use_text_fallback": decision.should_use_text_fallback,
                "should_redact_spoken_output": decision.should_redact_spoken_output,
            },
            "checks": {
                "has_output_channel": bool(decision.output_channel.value),
                "voice_settings_present": bool(decision.voice_settings),
                "text_settings_present": bool(decision.text_settings),
                "security_payload_prepared": security_payload is not None,
                "no_raw_sensitive_text_required": True,
            },
            "timestamp": self._now(),
        }

    def _prepare_memory_payload(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        session_id: Optional[str],
        task_id: Optional[str],
        request_id: str,
        text: Optional[str],
        decision: WhisperDecision,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        Raw text is not stored by default.
        """

        payload: Dict[str, Any] = {
            "target_agent": "memory_agent",
            "source_agent": self.config.agent_id,
            "memory_type": "voice_whisper_mode_metadata",
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "session_id": session_id,
            "task_id": task_id,
            "request_id": request_id,
            "importance": self._memory_importance_from_decision(decision),
            "data": {
                "mode_state": decision.mode_state.value,
                "output_channel": decision.output_channel.value,
                "privacy_level": decision.privacy_level.value,
                "security_sensitivity": decision.security_sensitivity.value,
                "should_speak": decision.should_speak,
                "should_use_text_fallback": decision.should_use_text_fallback,
                "should_redact_spoken_output": decision.should_redact_spoken_output,
                "reasons": decision.reasons,
            },
            "privacy": {
                "raw_text_included": self.config.store_raw_text_in_memory_payload,
                "sensitive_text_included": False,
            },
            "timestamp": self._now(),
        }

        if self.config.store_raw_text_in_memory_payload:
            payload["data"]["text"] = text

        return payload

    def _emit_agent_event(
        self,
        event_name: str,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        session_id: Optional[str],
        task_id: Optional[str],
        request_id: str,
        decision: WhisperDecision,
    ) -> Dict[str, Any]:
        """
        Emit dashboard/agent event safely.
        """

        payload = {
            "event_name": event_name,
            "source_agent": self.config.agent_id,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "session_id": session_id,
            "task_id": task_id,
            "request_id": request_id,
            "data": {
                "mode_state": decision.mode_state.value,
                "output_channel": decision.output_channel.value,
                "privacy_level": decision.privacy_level.value,
                "security_sensitivity": decision.security_sensitivity.value,
                "reasons": decision.reasons,
            },
            "timestamp": self._now(),
        }

        if self.config.event_enabled:
            try:
                if hasattr(super(), "emit_event"):
                    super().emit_event(event_name, payload)  # type: ignore
                elif hasattr(self, "emit_event"):
                    self.emit_event(event_name, payload)  # type: ignore
            except Exception as exc:
                self.logger.debug("Event emit skipped safely: %s", exc)

        return payload

    def _log_audit_event(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        session_id: Optional[str],
        task_id: Optional[str],
        request_id: str,
        action: str,
        decision: WhisperDecision,
        context: WhisperContext,
    ) -> Dict[str, Any]:
        """
        Prepare and optionally log audit event.

        Raw text is intentionally excluded.
        """

        payload = {
            "action": action,
            "source_agent": self.config.agent_id,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "session_id": session_id,
            "task_id": task_id,
            "request_id": request_id,
            "audit_category": "voice_whisper_mode",
            "data": {
                "mode_state": decision.mode_state.value,
                "output_channel": decision.output_channel.value,
                "privacy_level": decision.privacy_level.value,
                "security_sensitivity": decision.security_sensitivity.value,
                "should_speak": decision.should_speak,
                "should_use_text_fallback": decision.should_use_text_fallback,
                "should_redact_spoken_output": decision.should_redact_spoken_output,
                "reasons": decision.reasons,
            },
            "device_context": {
                "device_is_public": context.device_is_public,
                "device_has_headphones": context.device_has_headphones,
                "device_volume_level": context.device_volume_level,
            },
            "raw_text_included": self.config.store_sensitive_text_in_logs,
            "timestamp": self._now(),
        }

        if self.config.audit_enabled:
            try:
                if hasattr(super(), "log_audit"):
                    super().log_audit(payload)  # type: ignore
                elif hasattr(self, "log_audit"):
                    self.log_audit(payload)  # type: ignore
            except Exception as exc:
                self.logger.debug("Audit log skipped safely: %s", exc)

        return payload

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success response.
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
        error_code: str = "ERROR",
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error response.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {
                "code": error_code,
                "message": message,
            },
            "metadata": metadata or {},
        }

    # =========================================================================
    # Core Decision Logic
    # =========================================================================

    def _make_decision(
        self,
        text: str,
        context: WhisperContext,
        session_id: Optional[str],
    ) -> WhisperDecision:
        """
        Main internal whisper-mode decision engine.
        """

        warnings: List[str] = []
        reasons: List[str] = []

        session_mode = self.get_session_mode(session_id)
        current_mode = context.current_mode or session_mode or self.config.default_state

        privacy_level, sensitivity, privacy_reasons = self._detect_privacy_and_sensitivity(
            text=text,
            context=context,
        )
        reasons.extend(privacy_reasons)

        user_text_mode = self._detect_user_requested_modes(text)

        if user_text_mode == WhisperModeState.ON:
            current_mode = WhisperModeState.ON
            reasons.append(WhisperReason.USER_REQUESTED.value)

        elif user_text_mode == WhisperModeState.TEXT_ONLY:
            current_mode = WhisperModeState.TEXT_ONLY
            reasons.append(WhisperReason.USER_REQUESTED.value)

        elif user_text_mode == WhisperModeState.MUTED:
            current_mode = WhisperModeState.MUTED
            reasons.append(WhisperReason.USER_REQUESTED.value)

        if context.user_requested_whisper:
            current_mode = WhisperModeState.ON
            reasons.append(WhisperReason.USER_REQUESTED.value)

        if context.user_requested_text_only:
            current_mode = WhisperModeState.TEXT_ONLY
            reasons.append(WhisperReason.USER_REQUESTED.value)

        if context.user_requested_mute:
            current_mode = WhisperModeState.MUTED
            reasons.append(WhisperReason.USER_REQUESTED.value)

        if self._is_quiet_hours(context):
            if current_mode == WhisperModeState.AUTO:
                current_mode = WhisperModeState.ON
            reasons.append(WhisperReason.QUIET_HOURS.value)

        if context.emotion_whisper_detected:
            if current_mode == WhisperModeState.AUTO:
                current_mode = WhisperModeState.ON
            reasons.append(WhisperReason.EMOTION_DETECTED_WHISPER.value)

        if context.device_is_public and self.config.enable_device_privacy_mode:
            if privacy_level in {
                PrivacyLevel.PRIVATE,
                PrivacyLevel.SENSITIVE,
                PrivacyLevel.HIGHLY_SENSITIVE,
            }:
                current_mode = WhisperModeState.TEXT_ONLY
                reasons.append(WhisperReason.DEVICE_PRIVACY.value)

        if privacy_level == PrivacyLevel.HIGHLY_SENSITIVE:
            current_mode = WhisperModeState.TEXT_ONLY
            reasons.append(WhisperReason.SENSITIVE_CONTENT.value)

        elif privacy_level == PrivacyLevel.SENSITIVE:
            if self.config.enable_text_fallback:
                current_mode = WhisperModeState.TEXT_ONLY
                reasons.append(WhisperReason.SENSITIVE_CONTENT.value)
            else:
                current_mode = WhisperModeState.ON
                reasons.append(WhisperReason.LOW_VOLUME_CONTEXT.value)

        elif privacy_level == PrivacyLevel.PRIVATE and current_mode == WhisperModeState.AUTO:
            current_mode = WhisperModeState.ON
            reasons.append(WhisperReason.PRIVATE_CONTEXT.value)

        output_channel = self._output_channel_from_mode(current_mode)
        should_speak = output_channel in {
            OutputChannel.VOICE,
            OutputChannel.LOW_VOLUME_VOICE,
            OutputChannel.BOTH,
        }

        should_use_text_fallback = output_channel in {
            OutputChannel.TEXT,
            OutputChannel.BOTH,
        }

        should_redact_spoken_output = privacy_level in {
            PrivacyLevel.SENSITIVE,
            PrivacyLevel.HIGHLY_SENSITIVE,
        }

        safe_spoken_text, redacted, sanitize_warnings = self._sanitize_for_voice(
            text=text,
            privacy_level=privacy_level,
        )
        warnings.extend(sanitize_warnings)

        if redacted:
            should_redact_spoken_output = True

        if output_channel == OutputChannel.TEXT:
            safe_spoken_text = None

        if output_channel == OutputChannel.SILENT:
            safe_spoken_text = None

        safe_text_output = self._prepare_safe_text_output(text)

        voice_settings = self._build_voice_settings(
            mode=current_mode,
            privacy_level=privacy_level,
            output_channel=output_channel,
        )

        text_settings = self._build_text_settings(
            privacy_level=privacy_level,
            output_channel=output_channel,
        )

        return WhisperDecision(
            mode_state=current_mode,
            output_channel=output_channel,
            privacy_level=privacy_level,
            security_sensitivity=sensitivity,
            should_speak=should_speak,
            should_use_text_fallback=should_use_text_fallback,
            should_redact_spoken_output=should_redact_spoken_output,
            voice_settings=voice_settings,
            text_settings=text_settings,
            reasons=self._unique_preserve_order(reasons),
            safe_spoken_text=safe_spoken_text,
            safe_text_output=safe_text_output,
            warnings=self._unique_preserve_order(warnings),
        )

    def _detect_privacy_and_sensitivity(
        self,
        text: str,
        context: WhisperContext,
    ) -> tuple[PrivacyLevel, SecuritySensitivity, List[str]]:
        """
        Detect privacy level and security sensitivity.
        """

        reasons: List[str] = []

        if context.privacy_level:
            privacy_level = context.privacy_level
            reasons.append(WhisperReason.PRIVATE_CONTEXT.value)
        else:
            privacy_level = PrivacyLevel.NORMAL

        lowered = text.lower()

        if self._contains_highly_sensitive_text(lowered):
            privacy_level = PrivacyLevel.HIGHLY_SENSITIVE
            reasons.append(WhisperReason.SENSITIVE_CONTENT.value)

        elif self._contains_sensitive_text(lowered):
            if privacy_level not in {PrivacyLevel.HIGHLY_SENSITIVE}:
                privacy_level = PrivacyLevel.SENSITIVE
            reasons.append(WhisperReason.SENSITIVE_CONTENT.value)

        elif self._contains_private_text(lowered):
            if privacy_level not in {PrivacyLevel.SENSITIVE, PrivacyLevel.HIGHLY_SENSITIVE}:
                privacy_level = PrivacyLevel.PRIVATE
            reasons.append(WhisperReason.PRIVATE_CONTEXT.value)

        if context.device_is_public and privacy_level in {
            PrivacyLevel.PRIVATE,
            PrivacyLevel.SENSITIVE,
            PrivacyLevel.HIGHLY_SENSITIVE,
        }:
            reasons.append(WhisperReason.DEVICE_PRIVACY.value)

        sensitivity = self._security_sensitivity_from_privacy(privacy_level)

        return privacy_level, sensitivity, self._unique_preserve_order(reasons)

    def _detect_user_requested_modes(self, text: str) -> Optional[WhisperModeState]:
        """
        Detect direct user commands like:
            - whisper
            - speak quietly
            - text only
            - don't speak
            - mute
        """

        lowered = text.lower()

        for pattern in self._mute_patterns:
            if re.search(pattern, lowered):
                return WhisperModeState.MUTED

        for pattern in self._text_only_patterns:
            if re.search(pattern, lowered):
                return WhisperModeState.TEXT_ONLY

        for pattern in self._whisper_request_patterns:
            if re.search(pattern, lowered):
                return WhisperModeState.ON

        return None

    def _output_channel_from_mode(self, mode: WhisperModeState) -> OutputChannel:
        """
        Convert whisper mode state to output channel.
        """

        if mode == WhisperModeState.ON:
            return OutputChannel.LOW_VOLUME_VOICE

        if mode == WhisperModeState.TEXT_ONLY:
            return OutputChannel.TEXT

        if mode == WhisperModeState.MUTED:
            return OutputChannel.SILENT

        if mode == WhisperModeState.OFF:
            return OutputChannel.VOICE

        if mode == WhisperModeState.AUTO:
            return OutputChannel.VOICE

        return OutputChannel.VOICE

    def _build_voice_settings(
        self,
        mode: WhisperModeState,
        privacy_level: PrivacyLevel,
        output_channel: OutputChannel,
    ) -> Dict[str, Any]:
        """
        Build TTS/voice settings.
        """

        if output_channel == OutputChannel.SILENT:
            return {
                "enabled": False,
                "volume": self.config.muted_voice_volume,
                "speed": self.config.default_tts_speed,
                "pitch": self.config.default_tts_pitch,
                "privacy_mode": True,
                "speak_sensitive_content": False,
            }

        if output_channel == OutputChannel.TEXT:
            return {
                "enabled": False,
                "volume": self.config.muted_voice_volume,
                "speed": self.config.default_tts_speed,
                "pitch": self.config.default_tts_pitch,
                "privacy_mode": True,
                "speak_sensitive_content": False,
            }

        if privacy_level in {PrivacyLevel.SENSITIVE, PrivacyLevel.HIGHLY_SENSITIVE}:
            return {
                "enabled": True,
                "volume": self.config.sensitive_voice_volume,
                "speed": self.config.sensitive_tts_speed,
                "pitch": self.config.whisper_tts_pitch,
                "privacy_mode": True,
                "speak_sensitive_content": False,
                "max_spoken_chars": self.config.max_spoken_sensitive_chars,
            }

        if mode == WhisperModeState.ON or output_channel == OutputChannel.LOW_VOLUME_VOICE:
            return {
                "enabled": True,
                "volume": self.config.whisper_voice_volume,
                "speed": self.config.whisper_tts_speed,
                "pitch": self.config.whisper_tts_pitch,
                "privacy_mode": True,
                "speak_sensitive_content": False,
            }

        return {
            "enabled": True,
            "volume": self.config.default_voice_volume,
            "speed": self.config.default_tts_speed,
            "pitch": self.config.default_tts_pitch,
            "privacy_mode": False,
            "speak_sensitive_content": True,
        }

    def _build_text_settings(
        self,
        privacy_level: PrivacyLevel,
        output_channel: OutputChannel,
    ) -> Dict[str, Any]:
        """
        Build UI/text fallback settings.
        """

        return {
            "enabled": output_channel in {
                OutputChannel.TEXT,
                OutputChannel.BOTH,
                OutputChannel.SILENT,
            },
            "show_privacy_badge": privacy_level in {
                PrivacyLevel.PRIVATE,
                PrivacyLevel.SENSITIVE,
                PrivacyLevel.HIGHLY_SENSITIVE,
            },
            "privacy_badge": privacy_level.value,
            "auto_hide_after_seconds": 30 if privacy_level in {
                PrivacyLevel.SENSITIVE,
                PrivacyLevel.HIGHLY_SENSITIVE,
            } else None,
            "max_preview_chars": self.config.max_text_preview_chars,
            "copy_disabled": privacy_level == PrivacyLevel.HIGHLY_SENSITIVE,
            "screen_lock_recommended": privacy_level == PrivacyLevel.HIGHLY_SENSITIVE,
        }

    def _sanitize_for_voice(
        self,
        text: str,
        privacy_level: PrivacyLevel,
    ) -> tuple[Optional[str], bool, List[str]]:
        """
        Sanitize content before spoken output.
        """

        warnings: List[str] = []

        if not text:
            return "", False, warnings

        if privacy_level == PrivacyLevel.HIGHLY_SENSITIVE:
            warnings.append("Highly sensitive content blocked from spoken output.")
            return "I found sensitive information. I will show it privately in text instead.", True, warnings

        if privacy_level == PrivacyLevel.SENSITIVE:
            warnings.append("Sensitive content redacted from spoken output.")
            return "This looks sensitive. I will keep the details private and show them in text.", True, warnings

        if privacy_level == PrivacyLevel.PRIVATE:
            if len(text) > self.config.max_spoken_sensitive_chars:
                warnings.append("Private spoken output shortened.")
                return text[: self.config.max_spoken_sensitive_chars].rstrip() + "...", True, warnings

        return text, False, warnings

    def _prepare_safe_text_output(self, text: str) -> str:
        """
        Prepare text fallback output.

        Text output remains intact because it is shown privately in UI,
        but preview length is managed by text settings.
        """

        return text or ""

    # =========================================================================
    # Session Mode Management
    # =========================================================================

    def _set_session_mode(
        self,
        mode: WhisperModeState,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        session_id: str,
        task_id: Optional[str],
        action: str,
    ) -> Dict[str, Any]:
        """
        Set session whisper mode safely.
        """

        started_at = time.time()
        request_id = self._new_request_id()

        validation = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            request_id=request_id,
        )

        if not validation["success"]:
            return validation

        if not session_id:
            return self._error_result(
                message="session_id is required to set whisper mode.",
                error_code="MISSING_SESSION_ID",
                metadata={
                    "request_id": request_id,
                    "timestamp": self._now(),
                },
            )

        self._session_states[session_id] = mode

        event_payload = {
            "event_name": f"voice.{action}",
            "source_agent": self.config.agent_id,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "session_id": session_id,
            "task_id": task_id,
            "request_id": request_id,
            "data": {
                "mode_state": mode.value,
            },
            "timestamp": self._now(),
        }

        if self.config.event_enabled:
            try:
                if hasattr(super(), "emit_event"):
                    super().emit_event(event_payload["event_name"], event_payload)  # type: ignore
                elif hasattr(self, "emit_event"):
                    self.emit_event(event_payload["event_name"], event_payload)  # type: ignore
            except Exception as exc:
                self.logger.debug("Session mode event skipped safely: %s", exc)

        metadata = self._base_metadata(
            request_id=request_id,
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            started_at=started_at,
        )

        metadata["event_payload"] = event_payload

        return self._safe_result(
            message=f"Whisper mode set to {mode.value}.",
            data={
                "session_id": session_id,
                "mode_state": mode.value,
            },
            metadata=metadata,
        )

    # =========================================================================
    # Detection Helpers
    # =========================================================================

    def _contains_private_text(self, text: str) -> bool:
        """
        Detect private but not necessarily high-risk content.
        """

        lowered = text.lower()

        for keyword in self._private_keywords:
            if keyword in lowered:
                return True

        return False

    def _contains_sensitive_text(self, text: str) -> bool:
        """
        Detect sensitive content.
        """

        lowered = text.lower()

        for keyword in self._sensitive_keywords:
            if keyword in lowered:
                return True

        sensitive_patterns = [
            r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b",
            r"\b\d{4}[-.\s]?\d{4}[-.\s]?\d{4}[-.\s]?\d{4}\b",
            r"\bpassword\s*[:=]",
            r"\bapi[_\s-]?key\s*[:=]",
            r"\bsecret\s*[:=]",
            r"\botp\b",
            r"\b2fa\b",
        ]

        for pattern in sensitive_patterns:
            if re.search(pattern, lowered):
                return True

        return False

    def _contains_highly_sensitive_text(self, text: str) -> bool:
        """
        Detect highly sensitive content.
        """

        lowered = text.lower()

        for keyword in self._highly_sensitive_keywords:
            if keyword in lowered:
                return True

        high_patterns = [
            r"\bprivate key\b",
            r"\bseed phrase\b",
            r"\brecovery phrase\b",
            r"\bbank account\b",
            r"\bcredit card number\b",
            r"\bcard cvv\b",
            r"\bcvv\b",
            r"\bssn\b",
            r"\bsocial security number\b",
        ]

        for pattern in high_patterns:
            if re.search(pattern, lowered):
                return True

        return False

    def _is_quiet_hours(self, context: WhisperContext) -> bool:
        """
        Check quiet hours if enabled.
        """

        if not self.config.enable_quiet_hours:
            return False

        if self.config.quiet_hours_start is None or self.config.quiet_hours_end is None:
            return False

        if context.current_hour is None:
            return False

        hour = int(context.current_hour)

        start = int(self.config.quiet_hours_start)
        end = int(self.config.quiet_hours_end)

        if start == end:
            return False

        if start < end:
            return start <= hour < end

        return hour >= start or hour < end

    def _security_sensitivity_from_privacy(
        self,
        privacy_level: PrivacyLevel,
    ) -> SecuritySensitivity:
        """
        Map privacy level to security sensitivity.
        """

        if privacy_level == PrivacyLevel.HIGHLY_SENSITIVE:
            return SecuritySensitivity.HIGH

        if privacy_level == PrivacyLevel.SENSITIVE:
            return SecuritySensitivity.MEDIUM

        if privacy_level == PrivacyLevel.PRIVATE:
            return SecuritySensitivity.LOW

        return SecuritySensitivity.NONE

    # =========================================================================
    # Keyword Builders
    # =========================================================================

    def _build_private_keywords(self) -> List[str]:
        """
        Keywords that suggest private context.
        """

        return [
            "private",
            "quiet",
            "secret",
            "confidential",
            "personal",
            "don't say this out loud",
            "dont say this out loud",
            "keep this private",
            "between us",
            "not in public",
            "someone is listening",
        ]

    def _build_sensitive_keywords(self) -> List[str]:
        """
        Keywords that suggest sensitive content.
        """

        return [
            "password",
            "passcode",
            "pin code",
            "otp",
            "verification code",
            "login code",
            "api key",
            "secret key",
            "token",
            "access token",
            "auth token",
            "medical",
            "diagnosis",
            "legal case",
            "lawsuit",
            "salary",
            "invoice",
            "tax",
            "bank",
            "payment",
        ]

    def _build_highly_sensitive_keywords(self) -> List[str]:
        """
        Keywords that suggest highly sensitive content.
        """

        return [
            "private key",
            "seed phrase",
            "recovery phrase",
            "credit card",
            "cvv",
            "social security",
            "ssn",
            "bank account",
            "routing number",
            "passport number",
            "national id",
            "identity card",
        ]

    def _build_whisper_request_patterns(self) -> List[str]:
        """
        Regex patterns for user-requested whisper mode.
        """

        return [
            r"\bwhisper\b",
            r"\bspeak quietly\b",
            r"\bspeak low\b",
            r"\blower your voice\b",
            r"\bquiet mode\b",
            r"\bprivate mode\b",
            r"\bdon'?t speak loud\b",
            r"\bdont speak loud\b",
        ]

    def _build_text_only_patterns(self) -> List[str]:
        """
        Regex patterns for user-requested text-only mode.
        """

        return [
            r"\btext only\b",
            r"\btype only\b",
            r"\bdon'?t speak\b",
            r"\bdont speak\b",
            r"\bno voice\b",
            r"\bwrite only\b",
            r"\bshow in text\b",
        ]

    def _build_mute_patterns(self) -> List[str]:
        """
        Regex patterns for user-requested mute mode.
        """

        return [
            r"\bmute\b",
            r"\bstop speaking\b",
            r"\bsilent mode\b",
            r"\bbe silent\b",
            r"\bturn off voice\b",
        ]

    # =========================================================================
    # Normalization / Conversion Helpers
    # =========================================================================

    def _normalize_context(
        self,
        context: Optional[Union[WhisperContext, Dict[str, Any]]],
    ) -> WhisperContext:
        """
        Convert dict context to WhisperContext.
        """

        if context is None:
            return WhisperContext()

        if isinstance(context, WhisperContext):
            return context

        if not isinstance(context, dict):
            return WhisperContext(metadata={"raw_context_type": str(type(context))})

        allowed = {
            "current_mode",
            "user_requested_whisper",
            "user_requested_text_only",
            "user_requested_mute",
            "device_is_public",
            "device_has_headphones",
            "device_volume_level",
            "environment_noise_level",
            "emotion_whisper_detected",
            "emotion_stress_level",
            "emotion_urgency_level",
            "privacy_level",
            "current_hour",
            "metadata",
        }

        clean: Dict[str, Any] = {}

        for key, value in context.items():
            if key in allowed:
                clean[key] = value

        if "current_mode" in clean and clean["current_mode"] is not None:
            clean["current_mode"] = self._to_mode_state(clean["current_mode"])

        if "privacy_level" in clean and clean["privacy_level"] is not None:
            clean["privacy_level"] = self._to_privacy_level(clean["privacy_level"])

        if "metadata" not in clean or not isinstance(clean.get("metadata"), dict):
            clean["metadata"] = {}

        return WhisperContext(**clean)

    def _normalize_text(self, text: Optional[str]) -> str:
        """
        Normalize text safely.
        """

        if text is None:
            return ""

        if not isinstance(text, str):
            text = str(text)

        text = text.replace("\x00", "")
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def _to_mode_state(
        self,
        value: Union[str, WhisperModeState],
    ) -> WhisperModeState:
        """
        Convert value to WhisperModeState safely.
        """

        if isinstance(value, WhisperModeState):
            return value

        try:
            return WhisperModeState(str(value).lower())
        except Exception:
            return self.config.default_state

    def _to_privacy_level(
        self,
        value: Union[str, PrivacyLevel],
    ) -> PrivacyLevel:
        """
        Convert value to PrivacyLevel safely.
        """

        if isinstance(value, PrivacyLevel):
            return value

        try:
            return PrivacyLevel(str(value).lower())
        except Exception:
            return PrivacyLevel.NORMAL

    def _decision_to_dict(self, decision: WhisperDecision) -> Dict[str, Any]:
        """
        Convert decision dataclass to JSON-safe dict.
        """

        return {
            "mode_state": decision.mode_state.value,
            "output_channel": decision.output_channel.value,
            "privacy_level": decision.privacy_level.value,
            "security_sensitivity": decision.security_sensitivity.value,
            "should_speak": decision.should_speak,
            "should_use_text_fallback": decision.should_use_text_fallback,
            "should_redact_spoken_output": decision.should_redact_spoken_output,
            "voice_settings": decision.voice_settings,
            "text_settings": decision.text_settings,
            "reasons": decision.reasons,
            "safe_spoken_text": decision.safe_spoken_text,
            "safe_text_output": decision.safe_text_output,
            "warnings": decision.warnings,
        }

    def _memory_importance_from_decision(self, decision: WhisperDecision) -> str:
        """
        Decide Memory Agent importance.
        """

        if decision.privacy_level == PrivacyLevel.HIGHLY_SENSITIVE:
            return "high"

        if decision.security_sensitivity in {
            SecuritySensitivity.HIGH,
            SecuritySensitivity.CRITICAL,
        }:
            return "high"

        if decision.output_channel in {
            OutputChannel.TEXT,
            OutputChannel.SILENT,
        }:
            return "medium"

        return "low"

    def _unique_preserve_order(self, items: List[str]) -> List[str]:
        """
        Remove duplicates while preserving order.
        """

        seen = set()
        result: List[str] = []

        for item in items:
            if item not in seen:
                seen.add(item)
                result.append(item)

        return result

    def _new_request_id(self) -> str:
        """
        Generate unique request ID.
        """

        return f"whisper_{uuid.uuid4().hex}"

    def _now(self) -> float:
        """
        Current timestamp.
        """

        return time.time()

    def _base_metadata(
        self,
        request_id: str,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        session_id: Optional[str],
        task_id: Optional[str],
        started_at: float,
    ) -> Dict[str, Any]:
        """
        Common metadata block.
        """

        finished_at = self._now()

        return {
            "request_id": request_id,
            "agent_name": self.config.agent_name,
            "agent_id": self.config.agent_id,
            "version": self.VERSION,
            "user_id": str(user_id) if user_id is not None else None,
            "workspace_id": str(workspace_id) if workspace_id is not None else None,
            "session_id": session_id,
            "task_id": task_id,
            "started_at": started_at,
            "finished_at": finished_at,
            "duration_ms": round((finished_at - started_at) * 1000, 3),
        }

    # =========================================================================
    # Registry / Dashboard Helpers
    # =========================================================================

    def health_check(self) -> Dict[str, Any]:
        """
        Health check for Agent Registry, Agent Loader, Dashboard, or API.
        """

        return self._safe_result(
            message="WhisperMode is healthy.",
            data={
                "agent_name": self.config.agent_name,
                "agent_id": self.config.agent_id,
                "version": self.VERSION,
                "capabilities": self.capabilities(),
                "config": {
                    "default_state": self.config.default_state.value,
                    "enable_auto_detection": self.config.enable_auto_detection,
                    "enable_text_fallback": self.config.enable_text_fallback,
                    "enable_low_volume_voice": self.config.enable_low_volume_voice,
                    "enable_sensitive_content_filter": self.config.enable_sensitive_content_filter,
                    "enable_quiet_hours": self.config.enable_quiet_hours,
                    "enable_device_privacy_mode": self.config.enable_device_privacy_mode,
                },
                "active_sessions": len(self._session_states),
            },
            metadata={
                "timestamp": self._now(),
            },
        )

    def capabilities(self) -> List[str]:
        """
        Return supported capabilities for Agent Registry.
        """

        return [
            "voice.whisper_mode.decide",
            "voice.whisper_mode.enable",
            "voice.whisper_mode.disable",
            "voice.whisper_mode.text_only",
            "voice.whisper_mode.mute",
            "voice.output.sanitize",
            "voice.privacy.detect",
            "voice.low_volume.prepare",
            "voice.text_fallback.prepare",
            "voice.verification_payload.prepare",
            "voice.memory_payload.prepare",
        ]

    def get_registry_manifest(self) -> Dict[str, Any]:
        """
        Return Agent Registry-compatible manifest.
        """

        return {
            "agent_name": self.config.agent_name,
            "agent_id": self.config.agent_id,
            "module": "agents.voice_agent.whisper_mode",
            "class_name": "WhisperMode",
            "version": self.VERSION,
            "type": "voice_agent_helper",
            "capabilities": self.capabilities(),
            "requires_user_context": True,
            "requires_workspace_context": True,
            "security_sensitive": True,
            "memory_compatible": True,
            "verification_compatible": True,
            "dashboard_compatible": True,
            "import_safe": True,
        }


# =============================================================================
# Module-Level Convenience Factory
# =============================================================================

def create_whisper_mode(
    config: Optional[WhisperModeConfig] = None,
) -> WhisperMode:
    """
    Factory used by Agent Loader or tests.
    """

    return WhisperMode(config=config)


# =============================================================================
# Minimal Self-Test
# =============================================================================

def _self_test() -> Dict[str, Any]:
    """
    Lightweight self-test.

    Run:
        python agents/voice_agent/whisper_mode.py
    """

    whisper = WhisperMode()

    return whisper.prepare_output(
        response_text="Your password reset code is 123456. I will keep this private.",
        user_id="self_test_user",
        workspace_id="self_test_workspace",
        session_id="self_test_session",
        task_id="self_test_task",
        context={
            "device_is_public": True,
            "emotion_whisper_detected": True,
            "metadata": {
                "source": "self_test",
            },
        },
    )


if __name__ == "__main__":
    import json

    result = _self_test()
    print(json.dumps(result, indent=2, ensure_ascii=False))