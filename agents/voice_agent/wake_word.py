"""
agents/voice_agent/wake_word.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Detects William wake word, custom wake words, clap/tap activation,
    and gesture activation for the Voice Agent.

This file is designed to be:
    - Import-safe
    - SaaS user/workspace aware
    - Compatible with BaseAgent / Agent Registry / Agent Loader / Master Agent
    - Ready for FastAPI/dashboard integration
    - Safe for future STT, audio stream, gesture, clap, and tap modules

Important:
    This file does not directly open microphones, execute OS actions,
    place calls, send messages, or perform destructive actions.
    It only detects activation intent from provided text/audio/gesture signals.
"""

from __future__ import annotations

import logging
import math
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # fallback stub for import safety
        """
        Fallback BaseAgent stub.

        This keeps wake_word.py import-safe even when the full William
        architecture is not yet created.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "voice_agent")


# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------

logger = logging.getLogger("william.voice_agent.wake_word")
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------
# Enums / Dataclasses
# ---------------------------------------------------------------------

class ActivationType(str, Enum):
    """Supported activation types for Voice Agent wake detection."""

    WAKE_WORD = "wake_word"
    CUSTOM_WAKE_WORD = "custom_wake_word"
    CLAP = "clap"
    TAP = "tap"
    GESTURE = "gesture"
    UNKNOWN = "unknown"


class WakeWordStatus(str, Enum):
    """Wake detector status."""

    IDLE = "idle"
    LISTENING = "listening"
    DETECTED = "detected"
    DISABLED = "disabled"
    ERROR = "error"


@dataclass
class WakeWordConfig:
    """
    Runtime configuration for WakeWordDetector.

    This config is intentionally simple and dependency-free so it can be
    stored in database JSON fields, dashboard settings, or workspace configs.
    """

    default_wake_words: List[str] = field(default_factory=lambda: ["william", "jarvis"])
    custom_wake_words: List[str] = field(default_factory=list)

    case_sensitive: bool = False
    allow_partial_match: bool = False
    min_confidence: float = 0.72

    clap_enabled: bool = True
    tap_enabled: bool = True
    gesture_enabled: bool = True
    wake_word_enabled: bool = True

    clap_amplitude_threshold: float = 0.78
    tap_amplitude_threshold: float = 0.62
    double_tap_max_interval_seconds: float = 0.45
    clap_cooldown_seconds: float = 1.25
    tap_cooldown_seconds: float = 0.75
    wake_word_cooldown_seconds: float = 0.8
    gesture_cooldown_seconds: float = 0.8

    supported_gestures: List[str] = field(
        default_factory=lambda: [
            "raise_hand",
            "wave",
            "two_finger_tap",
            "palm_open",
            "thumbs_up",
            "head_nod",
        ]
    )

    require_user_context: bool = True
    require_workspace_context: bool = True

    emit_events: bool = True
    audit_enabled: bool = True
    memory_enabled: bool = True
    verification_enabled: bool = True


@dataclass
class DetectionContext:
    """
    SaaS isolation context.

    Every user-specific activation should carry user_id and workspace_id
    to prevent cross-user/cross-workspace mixing.
    """

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    """Internal detection result before conversion to structured dict."""

    detected: bool
    activation_type: ActivationType
    confidence: float
    trigger: Optional[str] = None
    message: str = ""
    raw_input: Optional[Any] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------
# WakeWordDetector
# ---------------------------------------------------------------------

class WakeWordDetector(BaseAgent):
    """
    Detects wake words and non-verbal activation triggers.

    Responsibilities:
        - Detect default wake words: "William", "Jarvis"
        - Detect user/workspace custom wake words
        - Detect clap activation from audio amplitude peaks
        - Detect tap / double-tap activation
        - Detect gesture activation from structured gesture events
        - Return safe structured JSON/dict results
        - Prepare Security, Memory, Verification, Audit, and Dashboard payloads

    How this connects to William/Jarvis architecture:
        - Master Agent:
            Can call detect_from_text(), detect_from_audio_features(),
            detect_from_gesture(), or detect_any() to decide whether to route
            user input into active conversation mode.

        - Security Agent:
            This file does not execute sensitive actions. However, activation
            events can still require permission checks when context is missing
            or a disabled trigger type is requested.

        - Memory Agent:
            Activation preferences and useful non-sensitive wake context can be
            passed through _prepare_memory_payload().

        - Verification Agent:
            Every completed detection prepares a verification payload showing
            what trigger was detected and under which isolated context.

        - Dashboard/API:
            Structured results are ready for FastAPI endpoints, analytics,
            task history, and audit logs.

        - Agent Registry / Loader:
            Public metadata is exposed through get_agent_manifest().
    """

    def __init__(
        self,
        config: Optional[WakeWordConfig] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        memory_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        verification_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="WakeWordDetector", agent_type="voice_agent", **kwargs)

        self.config = config or WakeWordConfig()
        self.status = WakeWordStatus.IDLE

        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.security_callback = security_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback

        self._last_detection_at: Dict[str, float] = {
            ActivationType.WAKE_WORD.value: 0.0,
            ActivationType.CUSTOM_WAKE_WORD.value: 0.0,
            ActivationType.CLAP.value: 0.0,
            ActivationType.TAP.value: 0.0,
            ActivationType.GESTURE.value: 0.0,
        }

        self._last_tap_at: Optional[float] = None
        self._last_tap_count: int = 0

        self._compiled_wake_patterns: List[Tuple[str, re.Pattern[str]]] = []
        self._refresh_patterns()

    # -----------------------------------------------------------------
    # Public metadata
    # -----------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Registry/Loader compatible manifest.

        Returns:
            Dict with agent identity, capabilities, public methods,
            and supported activation types.
        """

        return {
            "success": True,
            "message": "WakeWordDetector manifest loaded.",
            "data": {
                "agent_name": "WakeWordDetector",
                "agent_type": "voice_agent",
                "module": "agents.voice_agent.wake_word",
                "class_name": "WakeWordDetector",
                "version": "1.0.0",
                "status": self.status.value,
                "capabilities": [
                    "default_wake_word_detection",
                    "custom_wake_word_detection",
                    "clap_activation_detection",
                    "tap_activation_detection",
                    "gesture_activation_detection",
                    "saas_context_validation",
                    "audit_event_payloads",
                    "memory_payloads",
                    "verification_payloads",
                ],
                "public_methods": [
                    "detect_from_text",
                    "detect_from_audio_features",
                    "detect_from_gesture",
                    "detect_any",
                    "set_custom_wake_words",
                    "add_custom_wake_word",
                    "remove_custom_wake_word",
                    "get_config",
                    "update_config",
                    "reset_runtime_state",
                    "health_check",
                ],
                "supported_activation_types": [item.value for item in ActivationType],
            },
            "error": None,
            "metadata": self._base_metadata(),
        }

    def health_check(self) -> Dict[str, Any]:
        """Returns detector health for dashboard/API."""

        try:
            return self._safe_result(
                message="WakeWordDetector is healthy.",
                data={
                    "status": self.status.value,
                    "wake_word_enabled": self.config.wake_word_enabled,
                    "clap_enabled": self.config.clap_enabled,
                    "tap_enabled": self.config.tap_enabled,
                    "gesture_enabled": self.config.gesture_enabled,
                    "default_wake_words_count": len(self.config.default_wake_words),
                    "custom_wake_words_count": len(self.config.custom_wake_words),
                    "compiled_patterns_count": len(self._compiled_wake_patterns),
                },
            )
        except Exception as exc:
            return self._error_result("WakeWordDetector health check failed.", exc)

    # -----------------------------------------------------------------
    # Config methods
    # -----------------------------------------------------------------

    def get_config(self) -> Dict[str, Any]:
        """Returns safe config snapshot."""

        return self._safe_result(
            message="Wake word config loaded.",
            data=asdict(self.config),
        )

    def update_config(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """
        Updates config values safely.

        Args:
            updates: Dict of WakeWordConfig field names and new values.

        Returns:
            Structured result.
        """

        try:
            if not isinstance(updates, dict):
                return self._error_result(
                    "Config update failed.",
                    ValueError("updates must be a dictionary."),
                )

            valid_fields = set(WakeWordConfig.__dataclass_fields__.keys())
            changed: Dict[str, Any] = {}

            for key, value in updates.items():
                if key not in valid_fields:
                    continue

                setattr(self.config, key, value)
                changed[key] = value

            self._refresh_patterns()

            result = self._safe_result(
                message="Wake word config updated.",
                data={
                    "changed": changed,
                    "config": asdict(self.config),
                },
            )

            self._emit_agent_event(
                event_type="wake_word_config_updated",
                payload={
                    "changed": changed,
                    "config_keys": list(changed.keys()),
                },
            )

            return result

        except Exception as exc:
            return self._error_result("Config update failed.", exc)

    def set_custom_wake_words(
        self,
        wake_words: Sequence[str],
        context: Optional[Union[DetectionContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Replaces custom wake words.

        Args:
            wake_words: New list of custom wake words.
            context: Optional SaaS context.

        Returns:
            Structured result.
        """

        try:
            ctx_result = self._validate_task_context(context, allow_missing=True)
            if not ctx_result["success"]:
                return ctx_result

            cleaned = self._clean_wake_words(wake_words)
            self.config.custom_wake_words = cleaned
            self._refresh_patterns()

            result = self._safe_result(
                message="Custom wake words updated.",
                data={
                    "custom_wake_words": cleaned,
                    "count": len(cleaned),
                },
                metadata={
                    "context": self._context_to_public_dict(context),
                },
            )

            self._log_audit_event(
                action="set_custom_wake_words",
                context=context,
                details={"count": len(cleaned)},
            )

            return result

        except Exception as exc:
            return self._error_result("Failed to set custom wake words.", exc)

    def add_custom_wake_word(
        self,
        wake_word: str,
        context: Optional[Union[DetectionContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Adds one custom wake word."""

        try:
            if not isinstance(wake_word, str) or not wake_word.strip():
                return self._error_result(
                    "Failed to add custom wake word.",
                    ValueError("wake_word must be a non-empty string."),
                )

            normalized = self._normalize_text(wake_word)
            existing = {self._normalize_text(word) for word in self.config.custom_wake_words}

            if normalized not in existing:
                self.config.custom_wake_words.append(wake_word.strip())

            self._refresh_patterns()

            self._log_audit_event(
                action="add_custom_wake_word",
                context=context,
                details={"wake_word": self._mask_trigger(wake_word)},
            )

            return self._safe_result(
                message="Custom wake word added.",
                data={
                    "wake_word": wake_word.strip(),
                    "custom_wake_words": self.config.custom_wake_words,
                },
                metadata={
                    "context": self._context_to_public_dict(context),
                },
            )

        except Exception as exc:
            return self._error_result("Failed to add custom wake word.", exc)

    def remove_custom_wake_word(
        self,
        wake_word: str,
        context: Optional[Union[DetectionContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Removes one custom wake word."""

        try:
            normalized = self._normalize_text(wake_word)
            before = len(self.config.custom_wake_words)

            self.config.custom_wake_words = [
                word for word in self.config.custom_wake_words
                if self._normalize_text(word) != normalized
            ]

            removed = before != len(self.config.custom_wake_words)
            self._refresh_patterns()

            self._log_audit_event(
                action="remove_custom_wake_word",
                context=context,
                details={
                    "removed": removed,
                    "wake_word": self._mask_trigger(wake_word),
                },
            )

            return self._safe_result(
                message="Custom wake word removed." if removed else "Custom wake word was not found.",
                data={
                    "removed": removed,
                    "custom_wake_words": self.config.custom_wake_words,
                },
                metadata={
                    "context": self._context_to_public_dict(context),
                },
            )

        except Exception as exc:
            return self._error_result("Failed to remove custom wake word.", exc)

    def reset_runtime_state(self) -> Dict[str, Any]:
        """Resets cooldown and runtime tap/clap state."""

        try:
            for key in self._last_detection_at:
                self._last_detection_at[key] = 0.0

            self._last_tap_at = None
            self._last_tap_count = 0
            self.status = WakeWordStatus.IDLE

            return self._safe_result(
                message="WakeWordDetector runtime state reset.",
                data={
                    "status": self.status.value,
                },
            )

        except Exception as exc:
            return self._error_result("Failed to reset wake detector runtime state.", exc)

    # -----------------------------------------------------------------
    # Detection methods
    # -----------------------------------------------------------------

    def detect_from_text(
        self,
        text: str,
        context: Optional[Union[DetectionContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detects default/custom wake words from text.

        This method is usually called after STT converts speech to text.

        Args:
            text: Transcribed user speech.
            context: SaaS context.
            metadata: Optional extra metadata.

        Returns:
            Structured detection result.
        """

        try:
            self.status = WakeWordStatus.LISTENING

            validation = self._validate_task_context(context)
            if not validation["success"]:
                self.status = WakeWordStatus.ERROR
                return validation

            if not self.config.wake_word_enabled:
                return self._finalize_detection(
                    DetectionResult(
                        detected=False,
                        activation_type=ActivationType.WAKE_WORD,
                        confidence=0.0,
                        message="Wake word detection is disabled.",
                        raw_input=text,
                        metadata=metadata or {},
                    ),
                    context=context,
                )

            if not isinstance(text, str) or not text.strip():
                return self._finalize_detection(
                    DetectionResult(
                        detected=False,
                        activation_type=ActivationType.WAKE_WORD,
                        confidence=0.0,
                        message="No text provided for wake word detection.",
                        raw_input=text,
                        metadata=metadata or {},
                    ),
                    context=context,
                )

            if self._is_in_cooldown(ActivationType.WAKE_WORD):
                return self._finalize_detection(
                    DetectionResult(
                        detected=False,
                        activation_type=ActivationType.WAKE_WORD,
                        confidence=0.0,
                        message="Wake word ignored due to cooldown.",
                        raw_input=text,
                        metadata={
                            **(metadata or {}),
                            "cooldown_active": True,
                        },
                    ),
                    context=context,
                )

            normalized_text = text if self.config.case_sensitive else text.lower()

            best_match: Optional[DetectionResult] = None

            for wake_word, pattern in self._compiled_wake_patterns:
                match = pattern.search(normalized_text)

                if not match:
                    continue

                activation_type = (
                    ActivationType.CUSTOM_WAKE_WORD
                    if self._normalize_text(wake_word) in {
                        self._normalize_text(word)
                        for word in self.config.custom_wake_words
                    }
                    else ActivationType.WAKE_WORD
                )

                confidence = self._estimate_text_confidence(
                    text=normalized_text,
                    wake_word=wake_word,
                    match_span=match.span(),
                )

                if confidence >= self.config.min_confidence:
                    candidate = DetectionResult(
                        detected=True,
                        activation_type=activation_type,
                        confidence=confidence,
                        trigger=wake_word,
                        message=f"{activation_type.value} detected.",
                        raw_input=text,
                        metadata={
                            **(metadata or {}),
                            "match_start": match.start(),
                            "match_end": match.end(),
                            "matched_text": match.group(0),
                        },
                    )

                    if best_match is None or candidate.confidence > best_match.confidence:
                        best_match = candidate

            if best_match:
                self._mark_detection(best_match.activation_type)
                self.status = WakeWordStatus.DETECTED
                return self._finalize_detection(best_match, context=context)

            return self._finalize_detection(
                DetectionResult(
                    detected=False,
                    activation_type=ActivationType.WAKE_WORD,
                    confidence=0.0,
                    message="No wake word detected.",
                    raw_input=text,
                    metadata=metadata or {},
                ),
                context=context,
            )

        except Exception as exc:
            self.status = WakeWordStatus.ERROR
            return self._error_result("Text wake word detection failed.", exc)

    def detect_from_audio_features(
        self,
        audio_features: Dict[str, Any],
        context: Optional[Union[DetectionContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detects clap/tap activation using audio feature dictionaries.

        Expected audio_features examples:
            {
                "peak_amplitude": 0.91,
                "rms": 0.42,
                "duration_ms": 95,
                "zero_crossing_rate": 0.18,
                "event_type": "clap"
            }

            {
                "peak_amplitude": 0.68,
                "duration_ms": 50,
                "event_type": "tap"
            }

        This method does not read microphone directly. The future device_stream.py
        or audio_router.py should provide extracted features.

        Returns:
            Structured detection result.
        """

        try:
            self.status = WakeWordStatus.LISTENING

            validation = self._validate_task_context(context)
            if not validation["success"]:
                self.status = WakeWordStatus.ERROR
                return validation

            if not isinstance(audio_features, dict):
                return self._error_result(
                    "Audio feature detection failed.",
                    ValueError("audio_features must be a dictionary."),
                )

            event_type = str(audio_features.get("event_type", "")).strip().lower()
            peak_amplitude = self._safe_float(audio_features.get("peak_amplitude"), default=0.0)
            duration_ms = self._safe_float(audio_features.get("duration_ms"), default=0.0)
            rms = self._safe_float(audio_features.get("rms"), default=0.0)
            zcr = self._safe_float(audio_features.get("zero_crossing_rate"), default=0.0)

            if event_type == "clap" or self._looks_like_clap(peak_amplitude, duration_ms, rms, zcr):
                return self._detect_clap(
                    audio_features=audio_features,
                    context=context,
                    metadata=metadata,
                )

            if event_type in {"tap", "double_tap"} or self._looks_like_tap(peak_amplitude, duration_ms, rms):
                return self._detect_tap(
                    audio_features=audio_features,
                    context=context,
                    metadata=metadata,
                )

            return self._finalize_detection(
                DetectionResult(
                    detected=False,
                    activation_type=ActivationType.UNKNOWN,
                    confidence=0.0,
                    message="No clap or tap activation detected.",
                    raw_input=audio_features,
                    metadata=metadata or {},
                ),
                context=context,
            )

        except Exception as exc:
            self.status = WakeWordStatus.ERROR
            return self._error_result("Audio feature detection failed.", exc)

    def detect_from_gesture(
        self,
        gesture_event: Dict[str, Any],
        context: Optional[Union[DetectionContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detects activation from gesture events.

        Expected gesture_event example:
            {
                "gesture": "raise_hand",
                "confidence": 0.88,
                "source": "camera",
                "device_id": "device_001"
            }

        This file does not access camera directly. The future visual agent or
        gesture_trigger.py should provide structured gesture events.

        Returns:
            Structured detection result.
        """

        try:
            self.status = WakeWordStatus.LISTENING

            validation = self._validate_task_context(context)
            if not validation["success"]:
                self.status = WakeWordStatus.ERROR
                return validation

            if not self.config.gesture_enabled:
                return self._finalize_detection(
                    DetectionResult(
                        detected=False,
                        activation_type=ActivationType.GESTURE,
                        confidence=0.0,
                        message="Gesture activation is disabled.",
                        raw_input=gesture_event,
                        metadata=metadata or {},
                    ),
                    context=context,
                )

            if self._is_in_cooldown(ActivationType.GESTURE):
                return self._finalize_detection(
                    DetectionResult(
                        detected=False,
                        activation_type=ActivationType.GESTURE,
                        confidence=0.0,
                        message="Gesture activation ignored due to cooldown.",
                        raw_input=gesture_event,
                        metadata={
                            **(metadata or {}),
                            "cooldown_active": True,
                        },
                    ),
                    context=context,
                )

            if not isinstance(gesture_event, dict):
                return self._error_result(
                    "Gesture detection failed.",
                    ValueError("gesture_event must be a dictionary."),
                )

            gesture = str(gesture_event.get("gesture", "")).strip().lower()
            confidence = self._safe_float(gesture_event.get("confidence"), default=0.0)

            supported = {
                self._normalize_text(item)
                for item in self.config.supported_gestures
            }

            if gesture in supported and confidence >= self.config.min_confidence:
                self._mark_detection(ActivationType.GESTURE)
                self.status = WakeWordStatus.DETECTED

                return self._finalize_detection(
                    DetectionResult(
                        detected=True,
                        activation_type=ActivationType.GESTURE,
                        confidence=confidence,
                        trigger=gesture,
                        message="Gesture activation detected.",
                        raw_input=gesture_event,
                        metadata={
                            **(metadata or {}),
                            "source": gesture_event.get("source"),
                            "device_id": gesture_event.get("device_id"),
                        },
                    ),
                    context=context,
                )

            return self._finalize_detection(
                DetectionResult(
                    detected=False,
                    activation_type=ActivationType.GESTURE,
                    confidence=confidence,
                    trigger=gesture or None,
                    message="No supported gesture activation detected.",
                    raw_input=gesture_event,
                    metadata={
                        **(metadata or {}),
                        "supported_gestures": self.config.supported_gestures,
                    },
                ),
                context=context,
            )

        except Exception as exc:
            self.status = WakeWordStatus.ERROR
            return self._error_result("Gesture detection failed.", exc)

    def detect_any(
        self,
        text: Optional[str] = None,
        audio_features: Optional[Dict[str, Any]] = None,
        gesture_event: Optional[Dict[str, Any]] = None,
        context: Optional[Union[DetectionContext, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Runs all provided detection channels and returns the strongest result.

        Priority:
            1. Text wake word / custom wake word
            2. Gesture activation
            3. Clap/tap activation

        Args:
            text: Optional STT text.
            audio_features: Optional audio feature dictionary.
            gesture_event: Optional gesture event dictionary.
            context: SaaS context.
            metadata: Optional metadata.

        Returns:
            Structured result.
        """

        try:
            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            results: List[Dict[str, Any]] = []

            if text is not None:
                results.append(
                    self.detect_from_text(
                        text=text,
                        context=context,
                        metadata={
                            **(metadata or {}),
                            "channel": "text",
                        },
                    )
                )

            if gesture_event is not None:
                results.append(
                    self.detect_from_gesture(
                        gesture_event=gesture_event,
                        context=context,
                        metadata={
                            **(metadata or {}),
                            "channel": "gesture",
                        },
                    )
                )

            if audio_features is not None:
                results.append(
                    self.detect_from_audio_features(
                        audio_features=audio_features,
                        context=context,
                        metadata={
                            **(metadata or {}),
                            "channel": "audio_features",
                        },
                    )
                )

            if not results:
                return self._safe_result(
                    message="No detection input provided.",
                    data={
                        "detected": False,
                        "activation_type": ActivationType.UNKNOWN.value,
                        "confidence": 0.0,
                    },
                    metadata={
                        "context": self._context_to_public_dict(context),
                    },
                )

            successful_results = [item for item in results if item.get("success")]
            detected_results = [
                item for item in successful_results
                if item.get("data", {}).get("detected") is True
            ]

            if detected_results:
                strongest = max(
                    detected_results,
                    key=lambda item: float(item.get("data", {}).get("confidence", 0.0)),
                )

                return self._safe_result(
                    message="Activation detected from one or more channels.",
                    data={
                        "detected": True,
                        "best_result": strongest.get("data"),
                        "all_results": [item.get("data") for item in results],
                    },
                    metadata={
                        "context": self._context_to_public_dict(context),
                        "request_id": self._get_request_id(context),
                    },
                )

            return self._safe_result(
                message="No activation detected.",
                data={
                    "detected": False,
                    "all_results": [item.get("data") for item in results],
                },
                metadata={
                    "context": self._context_to_public_dict(context),
                    "request_id": self._get_request_id(context),
                },
            )

        except Exception as exc:
            return self._error_result("Multi-channel activation detection failed.", exc)

    # -----------------------------------------------------------------
    # Internal audio trigger detection
    # -----------------------------------------------------------------

    def _detect_clap(
        self,
        audio_features: Dict[str, Any],
        context: Optional[Union[DetectionContext, Dict[str, Any]]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Internal clap detection."""

        if not self.config.clap_enabled:
            return self._finalize_detection(
                DetectionResult(
                    detected=False,
                    activation_type=ActivationType.CLAP,
                    confidence=0.0,
                    message="Clap activation is disabled.",
                    raw_input=audio_features,
                    metadata=metadata or {},
                ),
                context=context,
            )

        if self._is_in_cooldown(ActivationType.CLAP):
            return self._finalize_detection(
                DetectionResult(
                    detected=False,
                    activation_type=ActivationType.CLAP,
                    confidence=0.0,
                    message="Clap activation ignored due to cooldown.",
                    raw_input=audio_features,
                    metadata={
                        **(metadata or {}),
                        "cooldown_active": True,
                    },
                ),
                context=context,
            )

        peak = self._safe_float(audio_features.get("peak_amplitude"), default=0.0)
        duration_ms = self._safe_float(audio_features.get("duration_ms"), default=0.0)
        rms = self._safe_float(audio_features.get("rms"), default=0.0)
        zcr = self._safe_float(audio_features.get("zero_crossing_rate"), default=0.0)

        confidence = self._score_clap(peak, duration_ms, rms, zcr)

        if confidence >= self.config.min_confidence:
            self._mark_detection(ActivationType.CLAP)
            self.status = WakeWordStatus.DETECTED

            return self._finalize_detection(
                DetectionResult(
                    detected=True,
                    activation_type=ActivationType.CLAP,
                    confidence=confidence,
                    trigger="clap",
                    message="Clap activation detected.",
                    raw_input=audio_features,
                    metadata=metadata or {},
                ),
                context=context,
            )

        return self._finalize_detection(
            DetectionResult(
                detected=False,
                activation_type=ActivationType.CLAP,
                confidence=confidence,
                trigger="clap",
                message="Audio event did not meet clap activation threshold.",
                raw_input=audio_features,
                metadata=metadata or {},
            ),
            context=context,
        )

    def _detect_tap(
        self,
        audio_features: Dict[str, Any],
        context: Optional[Union[DetectionContext, Dict[str, Any]]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Internal tap and double-tap detection."""

        if not self.config.tap_enabled:
            return self._finalize_detection(
                DetectionResult(
                    detected=False,
                    activation_type=ActivationType.TAP,
                    confidence=0.0,
                    message="Tap activation is disabled.",
                    raw_input=audio_features,
                    metadata=metadata or {},
                ),
                context=context,
            )

        if self._is_in_cooldown(ActivationType.TAP):
            return self._finalize_detection(
                DetectionResult(
                    detected=False,
                    activation_type=ActivationType.TAP,
                    confidence=0.0,
                    message="Tap activation ignored due to cooldown.",
                    raw_input=audio_features,
                    metadata={
                        **(metadata or {}),
                        "cooldown_active": True,
                    },
                ),
                context=context,
            )

        now = time.time()
        peak = self._safe_float(audio_features.get("peak_amplitude"), default=0.0)
        duration_ms = self._safe_float(audio_features.get("duration_ms"), default=0.0)
        rms = self._safe_float(audio_features.get("rms"), default=0.0)
        event_type = str(audio_features.get("event_type", "")).strip().lower()

        confidence = self._score_tap(peak, duration_ms, rms)

        is_double_tap = False
        if event_type == "double_tap":
            is_double_tap = True
            confidence = max(confidence, self.config.min_confidence)

        if self._last_tap_at is not None:
            interval = now - self._last_tap_at
            if interval <= self.config.double_tap_max_interval_seconds:
                self._last_tap_count += 1
                is_double_tap = self._last_tap_count >= 2
            else:
                self._last_tap_count = 1
        else:
            self._last_tap_count = 1

        self._last_tap_at = now

        if confidence >= self.config.min_confidence:
            self._mark_detection(ActivationType.TAP)
            self.status = WakeWordStatus.DETECTED

            trigger = "double_tap" if is_double_tap else "tap"

            return self._finalize_detection(
                DetectionResult(
                    detected=True,
                    activation_type=ActivationType.TAP,
                    confidence=confidence,
                    trigger=trigger,
                    message=f"{trigger.replace('_', ' ').title()} activation detected.",
                    raw_input=audio_features,
                    metadata={
                        **(metadata or {}),
                        "tap_count": self._last_tap_count,
                        "is_double_tap": is_double_tap,
                    },
                ),
                context=context,
            )

        return self._finalize_detection(
            DetectionResult(
                detected=False,
                activation_type=ActivationType.TAP,
                confidence=confidence,
                trigger="tap",
                message="Audio event did not meet tap activation threshold.",
                raw_input=audio_features,
                metadata={
                    **(metadata or {}),
                    "tap_count": self._last_tap_count,
                },
            ),
            context=context,
        )

    # -----------------------------------------------------------------
    # Compatibility hooks
    # -----------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Optional[Union[DetectionContext, Dict[str, Any]]],
        allow_missing: bool = False,
    ) -> Dict[str, Any]:
        """
        Validates SaaS user/workspace context.

        Never allow cross-user or cross-workspace mixing.
        """

        if allow_missing and context is None:
            return self._safe_result(
                message="Context validation skipped because missing context is allowed.",
                data={"valid": True},
            )

        if context is None:
            if self.config.require_user_context or self.config.require_workspace_context:
                return self._error_result(
                    "Context validation failed.",
                    ValueError("user_id and workspace_id are required."),
                    metadata={"missing_context": True},
                )

            return self._safe_result(
                message="Context validation passed.",
                data={"valid": True},
            )

        context_dict = self._context_to_dict(context)

        user_id = context_dict.get("user_id")
        workspace_id = context_dict.get("workspace_id")

        if self.config.require_user_context and (user_id is None or str(user_id).strip() == ""):
            return self._error_result(
                "Context validation failed.",
                ValueError("user_id is required."),
                metadata={"missing_user_id": True},
            )

        if self.config.require_workspace_context and (
            workspace_id is None or str(workspace_id).strip() == ""
        ):
            return self._error_result(
                "Context validation failed.",
                ValueError("workspace_id is required."),
                metadata={"missing_workspace_id": True},
            )

        return self._safe_result(
            message="Context validation passed.",
            data={
                "valid": True,
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def _requires_security_check(
        self,
        activation_type: ActivationType,
        context: Optional[Union[DetectionContext, Dict[str, Any]]] = None,
    ) -> bool:
        """
        Determines whether this detection needs Security Agent approval.

        Detection alone is usually not sensitive. A security check is required
        when context is missing, activation type is disabled, or the activation
        could start an agent session without permission.
        """

        context_valid = self._validate_task_context(context)
        if not context_valid.get("success"):
            return True

        if activation_type == ActivationType.CLAP and not self.config.clap_enabled:
            return True

        if activation_type == ActivationType.TAP and not self.config.tap_enabled:
            return True

        if activation_type == ActivationType.GESTURE and not self.config.gesture_enabled:
            return True

        if activation_type in {ActivationType.WAKE_WORD, ActivationType.CUSTOM_WAKE_WORD}:
            return not self.config.wake_word_enabled

        return False

    def _request_security_approval(
        self,
        action: str,
        context: Optional[Union[DetectionContext, Dict[str, Any]]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Requests approval from Security Agent callback if available.

        This file does not block normal non-sensitive detection unless
        the security callback explicitly denies it.
        """

        payload = {
            "action": action,
            "agent": "WakeWordDetector",
            "agent_type": "voice_agent",
            "context": self._context_to_public_dict(context),
            "details": details or {},
            "timestamp": time.time(),
        }

        if self.security_callback is None:
            return self._safe_result(
                message="Security callback not configured; default safe approval applied.",
                data={
                    "approved": True,
                    "fallback": True,
                    "payload": payload,
                },
            )

        try:
            response = self.security_callback(payload)
            approved = bool(response.get("approved", response.get("success", False)))

            if not approved:
                return self._error_result(
                    "Security approval denied.",
                    PermissionError("Security Agent denied wake activation."),
                    metadata={
                        "security_response": response,
                    },
                )

            return self._safe_result(
                message="Security approval granted.",
                data=response,
            )

        except Exception as exc:
            return self._error_result("Security approval request failed.", exc)

    def _prepare_verification_payload(
        self,
        detection: DetectionResult,
        context: Optional[Union[DetectionContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Prepares Verification Agent compatible payload."""

        return {
            "verification_id": str(uuid.uuid4()),
            "agent": "WakeWordDetector",
            "agent_type": "voice_agent",
            "event": "wake_activation_detection_completed",
            "detected": detection.detected,
            "activation_type": detection.activation_type.value,
            "confidence": detection.confidence,
            "trigger": self._mask_trigger(detection.trigger),
            "message": detection.message,
            "context": self._context_to_public_dict(context),
            "timestamp": time.time(),
            "requires_followup_verification": False,
        }

    def _prepare_memory_payload(
        self,
        detection: DetectionResult,
        context: Optional[Union[DetectionContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Prepares Memory Agent compatible payload.

        Only non-sensitive activation metadata is included.
        """

        return {
            "memory_id": str(uuid.uuid4()),
            "agent": "WakeWordDetector",
            "agent_type": "voice_agent",
            "memory_type": "voice_activation_event",
            "context": self._context_to_public_dict(context),
            "content": {
                "detected": detection.detected,
                "activation_type": detection.activation_type.value,
                "confidence": detection.confidence,
                "trigger": self._mask_trigger(detection.trigger),
                "status": self.status.value,
            },
            "metadata": {
                "safe_to_store": True,
                "contains_secret": False,
                "timestamp": time.time(),
            },
        }

    def _emit_agent_event(
        self,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emits event to dashboard/event bus callback.

        Safe no-op if callback is missing.
        """

        if not self.config.emit_events:
            return

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": "WakeWordDetector",
            "agent_type": "voice_agent",
            "payload": payload or {},
            "timestamp": time.time(),
        }

        try:
            if self.event_callback:
                self.event_callback(event)
        except Exception:
            logger.exception("Failed to emit WakeWordDetector event.")

    def _log_audit_event(
        self,
        action: str,
        context: Optional[Union[DetectionContext, Dict[str, Any]]] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Logs audit event.

        Safe no-op if audit callback is missing.
        """

        if not self.config.audit_enabled:
            return

        audit = {
            "audit_id": str(uuid.uuid4()),
            "agent": "WakeWordDetector",
            "agent_type": "voice_agent",
            "action": action,
            "context": self._context_to_public_dict(context),
            "details": details or {},
            "timestamp": time.time(),
        }

        try:
            if self.audit_callback:
                self.audit_callback(audit)
        except Exception:
            logger.exception("Failed to log WakeWordDetector audit event.")

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Returns standard success response."""

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                **self._base_metadata(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Exception,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Returns standard error response."""

        logger.debug("%s: %s", message, error)

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": {
                "type": error.__class__.__name__,
                "message": str(error),
            },
            "metadata": {
                **self._base_metadata(),
                **(metadata or {}),
            },
        }

    # -----------------------------------------------------------------
    # Finalization
    # -----------------------------------------------------------------

    def _finalize_detection(
        self,
        detection: DetectionResult,
        context: Optional[Union[DetectionContext, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Finalizes detection with events, audit, memory, and verification payloads.
        """

        if detection.detected:
            self.status = WakeWordStatus.DETECTED
        elif self.status != WakeWordStatus.ERROR:
            self.status = WakeWordStatus.LISTENING

        verification_payload = (
            self._prepare_verification_payload(detection, context)
            if self.config.verification_enabled
            else None
        )

        memory_payload = (
            self._prepare_memory_payload(detection, context)
            if self.config.memory_enabled
            else None
        )

        if detection.detected:
            self._emit_agent_event(
                event_type="wake_activation_detected",
                payload={
                    "activation_type": detection.activation_type.value,
                    "confidence": detection.confidence,
                    "trigger": self._mask_trigger(detection.trigger),
                    "context": self._context_to_public_dict(context),
                },
            )

            self._log_audit_event(
                action="wake_activation_detected",
                context=context,
                details={
                    "activation_type": detection.activation_type.value,
                    "confidence": detection.confidence,
                    "trigger": self._mask_trigger(detection.trigger),
                },
            )

            if self.memory_callback and memory_payload:
                try:
                    self.memory_callback(memory_payload)
                except Exception:
                    logger.exception("Failed to send wake detection payload to Memory Agent.")

            if self.verification_callback and verification_payload:
                try:
                    self.verification_callback(verification_payload)
                except Exception:
                    logger.exception("Failed to send wake detection payload to Verification Agent.")

        return self._safe_result(
            message=detection.message,
            data={
                "detected": detection.detected,
                "activation_type": detection.activation_type.value,
                "confidence": round(float(detection.confidence), 4),
                "trigger": detection.trigger,
                "status": self.status.value,
                "metadata": detection.metadata,
            },
            metadata={
                "context": self._context_to_public_dict(context),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "request_id": self._get_request_id(context),
            },
        )

    # -----------------------------------------------------------------
    # Pattern helpers
    # -----------------------------------------------------------------

    def _refresh_patterns(self) -> None:
        """Rebuilds compiled wake-word regex patterns."""

        self._compiled_wake_patterns.clear()

        all_words = self._clean_wake_words(
            list(self.config.default_wake_words) + list(self.config.custom_wake_words)
        )

        flags = 0 if self.config.case_sensitive else re.IGNORECASE

        for word in all_words:
            escaped = re.escape(word.strip())

            if self.config.allow_partial_match:
                pattern_text = escaped
            else:
                pattern_text = rf"(?<!\w){escaped}(?!\w)"

            try:
                self._compiled_wake_patterns.append(
                    (word, re.compile(pattern_text, flags=flags))
                )
            except re.error:
                logger.warning("Invalid wake word pattern skipped: %s", word)

    def _clean_wake_words(self, wake_words: Sequence[str]) -> List[str]:
        """Normalizes and deduplicates wake words while preserving readable text."""

        cleaned: List[str] = []
        seen: set[str] = set()

        for item in wake_words:
            if not isinstance(item, str):
                continue

            word = item.strip()
            if not word:
                continue

            normalized = self._normalize_text(word)
            if normalized in seen:
                continue

            seen.add(normalized)
            cleaned.append(word)

        return cleaned

    def _normalize_text(self, text: Optional[str]) -> str:
        """Normalizes text for comparison."""

        if text is None:
            return ""

        value = str(text).strip()
        if not self.config.case_sensitive:
            value = value.lower()

        value = re.sub(r"\s+", " ", value)
        return value

    def _estimate_text_confidence(
        self,
        text: str,
        wake_word: str,
        match_span: Tuple[int, int],
    ) -> float:
        """
        Lightweight confidence scoring for text detection.

        Exact word boundary matches score high. Partial and noisy matches score lower.
        """

        if not text or not wake_word:
            return 0.0

        start, end = match_span
        matched_length = max(1, end - start)
        wake_length = max(1, len(wake_word))

        length_score = min(1.0, matched_length / wake_length)

        boundary_score = 1.0
        if start > 0 and text[start - 1].isalnum():
            boundary_score -= 0.18
        if end < len(text) and text[end:end + 1].isalnum():
            boundary_score -= 0.18

        wake_word_count = max(1, len(text.split()))
        context_score = max(0.75, 1.0 - min(0.2, wake_word_count / 100.0))

        confidence = (length_score * 0.45) + (boundary_score * 0.35) + (context_score * 0.20)

        return max(0.0, min(1.0, confidence))

    # -----------------------------------------------------------------
    # Audio scoring helpers
    # -----------------------------------------------------------------

    def _looks_like_clap(
        self,
        peak: float,
        duration_ms: float,
        rms: float,
        zcr: float,
    ) -> bool:
        """Heuristic pre-check for clap-like signal."""

        return (
            peak >= self.config.clap_amplitude_threshold
            and 20 <= duration_ms <= 350
            and rms >= 0.20
            and zcr >= 0.05
        )

    def _looks_like_tap(
        self,
        peak: float,
        duration_ms: float,
        rms: float,
    ) -> bool:
        """Heuristic pre-check for tap-like signal."""

        return (
            peak >= self.config.tap_amplitude_threshold
            and 10 <= duration_ms <= 180
            and rms >= 0.08
        )

    def _score_clap(
        self,
        peak: float,
        duration_ms: float,
        rms: float,
        zcr: float,
    ) -> float:
        """Scores clap confidence from simple extracted audio features."""

        peak_score = min(1.0, peak / max(0.01, self.config.clap_amplitude_threshold))
        rms_score = min(1.0, rms / 0.35)
        zcr_score = min(1.0, zcr / 0.18)

        if 40 <= duration_ms <= 180:
            duration_score = 1.0
        elif 20 <= duration_ms < 40 or 180 < duration_ms <= 350:
            duration_score = 0.75
        else:
            duration_score = 0.25

        confidence = (
            peak_score * 0.40
            + rms_score * 0.20
            + zcr_score * 0.20
            + duration_score * 0.20
        )

        return max(0.0, min(1.0, confidence))

    def _score_tap(
        self,
        peak: float,
        duration_ms: float,
        rms: float,
    ) -> float:
        """Scores tap confidence from simple extracted audio features."""

        peak_score = min(1.0, peak / max(0.01, self.config.tap_amplitude_threshold))
        rms_score = min(1.0, rms / 0.22)

        if 15 <= duration_ms <= 90:
            duration_score = 1.0
        elif 10 <= duration_ms < 15 or 90 < duration_ms <= 180:
            duration_score = 0.70
        else:
            duration_score = 0.25

        confidence = (
            peak_score * 0.50
            + rms_score * 0.20
            + duration_score * 0.30
        )

        return max(0.0, min(1.0, confidence))

    # -----------------------------------------------------------------
    # Cooldown helpers
    # -----------------------------------------------------------------

    def _is_in_cooldown(self, activation_type: ActivationType) -> bool:
        """Checks activation cooldown."""

        now = time.time()
        last = self._last_detection_at.get(activation_type.value, 0.0)

        cooldown = {
            ActivationType.WAKE_WORD.value: self.config.wake_word_cooldown_seconds,
            ActivationType.CUSTOM_WAKE_WORD.value: self.config.wake_word_cooldown_seconds,
            ActivationType.CLAP.value: self.config.clap_cooldown_seconds,
            ActivationType.TAP.value: self.config.tap_cooldown_seconds,
            ActivationType.GESTURE.value: self.config.gesture_cooldown_seconds,
        }.get(activation_type.value, 0.0)

        return (now - last) < cooldown

    def _mark_detection(self, activation_type: ActivationType) -> None:
        """Marks activation timestamp."""

        now = time.time()
        self._last_detection_at[activation_type.value] = now

        if activation_type == ActivationType.CUSTOM_WAKE_WORD:
            self._last_detection_at[ActivationType.WAKE_WORD.value] = now

    # -----------------------------------------------------------------
    # Utility helpers
    # -----------------------------------------------------------------

    def _safe_float(self, value: Any, default: float = 0.0) -> float:
        """Safely converts value to float."""

        try:
            number = float(value)
            if math.isnan(number) or math.isinf(number):
                return default
            return number
        except Exception:
            return default

    def _context_to_dict(
        self,
        context: Optional[Union[DetectionContext, Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """Converts context dataclass/dict to dict."""

        if context is None:
            return {}

        if isinstance(context, DetectionContext):
            return asdict(context)

        if isinstance(context, dict):
            return dict(context)

        return {}

    def _context_to_public_dict(
        self,
        context: Optional[Union[DetectionContext, Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """
        Returns safe public context.

        Does not include secrets/tokens.
        """

        ctx = self._context_to_dict(context)

        allowed_keys = {
            "user_id",
            "workspace_id",
            "device_id",
            "session_id",
            "request_id",
            "role",
            "subscription_plan",
        }

        public = {key: ctx.get(key) for key in allowed_keys if key in ctx}

        metadata = ctx.get("metadata")
        if isinstance(metadata, dict):
            public["metadata_keys"] = list(metadata.keys())

        permissions = ctx.get("permissions")
        if isinstance(permissions, list):
            public["permissions_count"] = len(permissions)

        return public

    def _get_request_id(
        self,
        context: Optional[Union[DetectionContext, Dict[str, Any]]],
    ) -> str:
        """Returns existing request_id or creates one."""

        ctx = self._context_to_dict(context)
        request_id = ctx.get("request_id")

        if request_id:
            return str(request_id)

        return str(uuid.uuid4())

    def _mask_trigger(self, trigger: Optional[str]) -> Optional[str]:
        """
        Masks trigger lightly for audit/memory safety.

        Wake words are usually not sensitive, but custom phrases can be.
        """

        if not trigger:
            return None

        value = str(trigger)

        if len(value) <= 2:
            return "*" * len(value)

        if len(value) <= 6:
            return value[0] + "*" * (len(value) - 2) + value[-1]

        return value[:2] + "*" * (len(value) - 4) + value[-2:]

    def _base_metadata(self) -> Dict[str, Any]:
        """Base metadata attached to every result."""

        return {
            "agent": "WakeWordDetector",
            "agent_type": "voice_agent",
            "module": "agents.voice_agent.wake_word",
            "timestamp": time.time(),
            "version": "1.0.0",
        }


# ---------------------------------------------------------------------
# Optional simple self-test
# ---------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    detector = WakeWordDetector()

    demo_context = DetectionContext(
        user_id="demo_user",
        workspace_id="demo_workspace",
        device_id="demo_device",
        session_id="demo_session",
        request_id="demo_request",
    )

    print(
        detector.detect_from_text(
            text="Hey William, open my dashboard.",
            context=demo_context,
        )
    )

    print(
        detector.detect_from_audio_features(
            audio_features={
                "event_type": "clap",
                "peak_amplitude": 0.91,
                "rms": 0.42,
                "duration_ms": 95,
                "zero_crossing_rate": 0.18,
            },
            context=demo_context,
        )
    )

    print(
        detector.detect_from_gesture(
            gesture_event={
                "gesture": "raise_hand",
                "confidence": 0.91,
                "source": "camera",
            },
            context=demo_context,
        )
    )