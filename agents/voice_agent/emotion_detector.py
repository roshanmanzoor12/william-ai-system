"""
agents/voice_agent/emotion_detector.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Detects urgency, stress, emotion, whispering, and adjusts response tone metadata.

This module is part of the Voice Agent. It is designed to be safe to import even when
the rest of the William/Jarvis system is still under construction.

Architecture Compatibility:
    - Master Agent routing
    - BaseAgent compatibility
    - Agent Registry / Agent Loader
    - Security Agent approval flow
    - Verification Agent payload preparation
    - Memory Agent payload preparation
    - Dashboard / API structured responses
    - SaaS user/workspace isolation

Important:
    This file does not perform destructive actions.
    This file does not record or store raw audio by default.
    This file only analyzes provided text/audio metadata/features.
"""

from __future__ import annotations

import math
import re
import time
import uuid
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


# =============================================================================
# Safe Optional BaseAgent Import
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:
        """
        Fallback BaseAgent stub.

        This allows the file to import safely before the real William/Jarvis
        BaseAgent is created. The real BaseAgent should provide richer routing,
        registry, event, permission, and lifecycle support.
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

logger = logging.getLogger("EmotionDetector")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Enums
# =============================================================================

class EmotionLabel(str, Enum):
    """
    Supported emotion labels.

    These labels are intentionally practical for assistant behavior:
    they help the Master Agent decide how William should respond.
    """

    NEUTRAL = "neutral"
    HAPPY = "happy"
    EXCITED = "excited"
    SAD = "sad"
    ANGRY = "angry"
    FEARFUL = "fearful"
    STRESSED = "stressed"
    CONFUSED = "confused"
    FRUSTRATED = "frustrated"
    URGENT = "urgent"
    WHISPERING = "whispering"
    TIRED = "tired"
    CALM = "calm"
    UNKNOWN = "unknown"


class UrgencyLevel(str, Enum):
    """User urgency level."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StressLevel(str, Enum):
    """Detected stress level."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    EXTREME = "extreme"


class ResponseTone(str, Enum):
    """
    Tone metadata that downstream response builders, TTS, or Master Agent can use.
    """

    NORMAL = "normal"
    CALM = "calm"
    REASSURING = "reassuring"
    SUPPORTIVE = "supportive"
    DIRECT = "direct"
    URGENT = "urgent"
    GENTLE = "gentle"
    CONFIDENT = "confident"
    CLARIFYING = "clarifying"
    QUIET = "quiet"
    EMPATHETIC = "empathetic"


class RiskSignal(str, Enum):
    """
    Safety-related risk signal.

    This file does not diagnose or perform crisis intervention.
    It only flags metadata so Security Agent / Master Agent can route safely.
    """

    NONE = "none"
    DISTRESS = "distress"
    PANIC = "panic"
    POSSIBLE_SELF_HARM = "possible_self_harm"
    POSSIBLE_VIOLENCE = "possible_violence"
    EMERGENCY = "emergency"
    UNKNOWN = "unknown"


# =============================================================================
# Data Structures
# =============================================================================

@dataclass
class EmotionDetectorConfig:
    """
    Configuration for EmotionDetector.

    The defaults are conservative and SaaS-safe. You can override them from
    dashboard/API settings later per workspace.
    """

    agent_name: str = "EmotionDetector"
    agent_id: str = "voice_agent.emotion_detector"

    enable_text_analysis: bool = True
    enable_audio_feature_analysis: bool = True
    enable_whisper_detection: bool = True
    enable_urgency_detection: bool = True
    enable_stress_detection: bool = True
    enable_safety_signal_detection: bool = True

    store_raw_text_in_memory_payload: bool = False
    store_raw_audio_features_in_memory_payload: bool = False

    min_confidence: float = 0.15
    high_confidence_threshold: float = 0.70

    whisper_volume_threshold: float = 0.22
    whisper_energy_threshold: float = 0.18
    whisper_speech_rate_max: float = 2.7

    high_stress_score_threshold: float = 0.70
    medium_stress_score_threshold: float = 0.42

    critical_urgency_score_threshold: float = 0.85
    high_urgency_score_threshold: float = 0.66
    medium_urgency_score_threshold: float = 0.38

    max_text_length: int = 8000

    default_language: str = "auto"

    allow_security_escalation: bool = True
    audit_enabled: bool = True
    event_enabled: bool = True


@dataclass
class AudioEmotionFeatures:
    """
    Optional normalized audio features.

    Expected value ranges:
        average_volume: 0.0 to 1.0
        peak_volume: 0.0 to 1.0
        energy: 0.0 to 1.0
        pitch_mean: Hz or normalized float
        pitch_variance: normalized float
        speech_rate_wps: words per second
        silence_ratio: 0.0 to 1.0
        tremor_score: 0.0 to 1.0
        breathiness_score: 0.0 to 1.0
    """

    average_volume: Optional[float] = None
    peak_volume: Optional[float] = None
    energy: Optional[float] = None
    pitch_mean: Optional[float] = None
    pitch_variance: Optional[float] = None
    speech_rate_wps: Optional[float] = None
    silence_ratio: Optional[float] = None
    tremor_score: Optional[float] = None
    breathiness_score: Optional[float] = None
    duration_seconds: Optional[float] = None
    sample_rate: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EmotionAnalysisResult:
    """
    Internal structured analysis result.
    """

    primary_emotion: EmotionLabel
    secondary_emotions: List[EmotionLabel]
    emotion_scores: Dict[str, float]
    urgency_level: UrgencyLevel
    urgency_score: float
    stress_level: StressLevel
    stress_score: float
    whisper_detected: bool
    whisper_score: float
    risk_signal: RiskSignal
    risk_score: float
    confidence: float
    response_tone: ResponseTone
    response_metadata: Dict[str, Any]
    detected_markers: List[str]
    warnings: List[str]


# =============================================================================
# Emotion Detector
# =============================================================================

class EmotionDetector(BaseAgent):
    """
    Detects emotional metadata from text and optional audio features.

    Main public methods:
        - analyze()
        - analyze_text()
        - analyze_audio_features()
        - detect_whisper()
        - detect_urgency()
        - detect_stress()
        - get_response_tone_metadata()

    This class returns structured dict results compatible with Master Agent,
    Voice Agent, Verification Agent, Memory Agent, Security Agent, and Dashboard.
    """

    VERSION = "1.0.0"

    def __init__(
        self,
        config: Optional[EmotionDetectorConfig] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self.config = config or EmotionDetectorConfig()

        super().__init__(
            agent_name=self.config.agent_name,
            agent_id=self.config.agent_id,
            *args,
            **kwargs,
        )

        self.logger = logging.getLogger(self.config.agent_name)

        self._emotion_keywords = self._build_emotion_keywords()
        self._urgency_keywords = self._build_urgency_keywords()
        self._stress_keywords = self._build_stress_keywords()
        self._risk_keywords = self._build_risk_keywords()
        self._tone_rules = self._build_tone_rules()

    # =========================================================================
    # Public Main API
    # =========================================================================

    def analyze(
        self,
        text: Optional[str] = None,
        audio_features: Optional[Union[AudioEmotionFeatures, Dict[str, Any]]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        session_id: Optional[str] = None,
        task_id: Optional[str] = None,
        language: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze user emotion from text and optional audio features.

        Args:
            text:
                User utterance/transcript. Raw text is not stored in memory payload
                unless config.store_raw_text_in_memory_payload is True.
            audio_features:
                Optional normalized audio metadata/features.
            user_id:
                SaaS user ID.
            workspace_id:
                SaaS workspace ID.
            session_id:
                Voice/session ID.
            task_id:
                Optional task ID.
            language:
                Detected language or "auto".
            context:
                Additional request context.

        Returns:
            Structured dict:
                {
                    success,
                    message,
                    data,
                    error,
                    metadata
                }
        """

        started_at = time.time()
        request_id = self._new_request_id()
        context = context or {}

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
        audio_obj = self._normalize_audio_features(audio_features)
        warnings: List[str] = []

        if not safe_text and audio_obj is None:
            return self._error_result(
                message="No text or audio features provided for emotion detection.",
                error_code="NO_INPUT",
                data={
                    "primary_emotion": EmotionLabel.UNKNOWN.value,
                    "confidence": 0.0,
                },
                metadata=self._base_metadata(
                    request_id=request_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    session_id=session_id,
                    task_id=task_id,
                    started_at=started_at,
                ),
            )

        if safe_text and len(safe_text) > self.config.max_text_length:
            warnings.append(
                f"Text exceeded max_text_length={self.config.max_text_length}; truncated for analysis."
            )
            safe_text = safe_text[: self.config.max_text_length]

        security_check_required = self._requires_security_check(
            text=safe_text,
            audio_features=audio_obj,
            context=context,
        )

        security_payload = None
        if security_check_required:
            security_payload = self._request_security_approval(
                user_id=user_id,
                workspace_id=workspace_id,
                session_id=session_id,
                task_id=task_id,
                request_id=request_id,
                text=safe_text,
                audio_features=audio_obj,
                context=context,
            )

        text_result = self._empty_text_analysis()
        audio_result = self._empty_audio_analysis()

        if self.config.enable_text_analysis and safe_text:
            text_result = self._analyze_text_internal(safe_text)

        if self.config.enable_audio_feature_analysis and audio_obj:
            audio_result = self._analyze_audio_internal(audio_obj)

        merged = self._merge_analysis(
            text_analysis=text_result,
            audio_analysis=audio_result,
            warnings=warnings,
        )

        verification_payload = self._prepare_verification_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            request_id=request_id,
            analysis=merged,
            security_payload=security_payload,
        )

        memory_payload = self._prepare_memory_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            request_id=request_id,
            text=safe_text,
            audio_features=audio_obj,
            analysis=merged,
        )

        audit_payload = self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            request_id=request_id,
            action="emotion_detection_completed",
            analysis=merged,
            context=context,
        )

        event_payload = self._emit_agent_event(
            event_name="voice.emotion_detected",
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            request_id=request_id,
            analysis=merged,
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
                "language": language or self.config.default_language,
                "security_check_required": security_check_required,
                "security_payload": security_payload,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "audit_payload": audit_payload,
                "event_payload": event_payload,
                "version": self.VERSION,
            }
        )

        return self._safe_result(
            message="Emotion analysis completed successfully.",
            data=self._analysis_to_dict(merged),
            metadata=metadata,
        )

    def analyze_text(
        self,
        text: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        session_id: Optional[str] = None,
        task_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze text only.
        """

        return self.analyze(
            text=text,
            audio_features=None,
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            context=context,
        )

    def analyze_audio_features(
        self,
        audio_features: Union[AudioEmotionFeatures, Dict[str, Any]],
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        session_id: Optional[str] = None,
        task_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze audio features only.
        """

        return self.analyze(
            text=None,
            audio_features=audio_features,
            user_id=user_id,
            workspace_id=workspace_id,
            session_id=session_id,
            task_id=task_id,
            context=context,
        )

    def detect_whisper(
        self,
        audio_features: Optional[Union[AudioEmotionFeatures, Dict[str, Any]]] = None,
        text: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Detect whether the user appears to be whispering.

        This is useful for Whisper Mode, TTS volume adjustment, quiet response tone,
        and privacy-sensitive UX.
        """

        audio_obj = self._normalize_audio_features(audio_features)
        safe_text = self._normalize_text(text)

        score = 0.0
        markers: List[str] = []

        if audio_obj:
            audio_score, audio_markers = self._score_whisper_audio(audio_obj)
            score += audio_score * 0.75
            markers.extend(audio_markers)

        if safe_text:
            text_score, text_markers = self._score_whisper_text(safe_text)
            score += text_score * 0.25
            markers.extend(text_markers)

        score = self._clamp(score)
        detected = score >= 0.50

        return self._safe_result(
            message="Whisper detection completed.",
            data={
                "whisper_detected": detected,
                "whisper_score": round(score, 4),
                "markers": markers,
                "recommended_tone": ResponseTone.QUIET.value if detected else ResponseTone.NORMAL.value,
                "recommended_tts_volume": 0.35 if detected else 0.75,
                "recommended_tts_speed": 0.92 if detected else 1.0,
            },
            metadata={
                "version": self.VERSION,
                "timestamp": self._now(),
            },
        )

    def detect_urgency(self, text: str) -> Dict[str, Any]:
        """
        Detect urgency from text.
        """

        safe_text = self._normalize_text(text)
        score, markers = self._score_urgency_text(safe_text)
        level = self._urgency_level_from_score(score)

        return self._safe_result(
            message="Urgency detection completed.",
            data={
                "urgency_level": level.value,
                "urgency_score": round(score, 4),
                "markers": markers,
            },
            metadata={
                "version": self.VERSION,
                "timestamp": self._now(),
            },
        )

    def detect_stress(
        self,
        text: Optional[str] = None,
        audio_features: Optional[Union[AudioEmotionFeatures, Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Detect stress from text and/or audio features.
        """

        safe_text = self._normalize_text(text)
        audio_obj = self._normalize_audio_features(audio_features)

        score = 0.0
        markers: List[str] = []

        if safe_text:
            text_score, text_markers = self._score_stress_text(safe_text)
            score += text_score * 0.65
            markers.extend(text_markers)

        if audio_obj:
            audio_score, audio_markers = self._score_stress_audio(audio_obj)
            score += audio_score * 0.35
            markers.extend(audio_markers)

        score = self._clamp(score)
        level = self._stress_level_from_score(score)

        return self._safe_result(
            message="Stress detection completed.",
            data={
                "stress_level": level.value,
                "stress_score": round(score, 4),
                "markers": markers,
            },
            metadata={
                "version": self.VERSION,
                "timestamp": self._now(),
            },
        )

    def get_response_tone_metadata(
        self,
        primary_emotion: Union[str, EmotionLabel],
        urgency_level: Union[str, UrgencyLevel] = UrgencyLevel.NONE,
        stress_level: Union[str, StressLevel] = StressLevel.NONE,
        whisper_detected: bool = False,
        risk_signal: Union[str, RiskSignal] = RiskSignal.NONE,
    ) -> Dict[str, Any]:
        """
        Produce response/TTS metadata from detected emotional state.
        """

        emotion = self._to_emotion_label(primary_emotion)
        urgency = self._to_urgency_level(urgency_level)
        stress = self._to_stress_level(stress_level)
        risk = self._to_risk_signal(risk_signal)

        tone = self._select_response_tone(
            primary_emotion=emotion,
            urgency_level=urgency,
            stress_level=stress,
            whisper_detected=whisper_detected,
            risk_signal=risk,
        )

        metadata = self._build_response_metadata(
            tone=tone,
            primary_emotion=emotion,
            urgency_level=urgency,
            stress_level=stress,
            whisper_detected=whisper_detected,
            risk_signal=risk,
        )

        return self._safe_result(
            message="Response tone metadata prepared.",
            data=metadata,
            metadata={
                "version": self.VERSION,
                "timestamp": self._now(),
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
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Every user/workspace-specific execution should include user_id and
        workspace_id. This prevents accidental mixing of memory, analytics,
        logs, tasks, or dashboard data.
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
                "context_keys": sorted(list((context or {}).keys())),
            },
            metadata={
                "request_id": request_id,
                "timestamp": self._now(),
            },
        )

    def _requires_security_check(
        self,
        text: Optional[str] = None,
        audio_features: Optional[AudioEmotionFeatures] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """
        Determine whether Security Agent should be notified.

        Emotion detection itself is non-destructive, but high-risk signals should
        be escalated for safe routing.
        """

        if not self.config.allow_security_escalation:
            return False

        if not self.config.enable_safety_signal_detection:
            return False

        safe_text = self._normalize_text(text)
        if safe_text:
            risk_score, _, risk_signal = self._score_risk_text(safe_text)
            if risk_signal != RiskSignal.NONE and risk_score >= 0.35:
                return True

        if audio_features:
            audio_stress, _ = self._score_stress_audio(audio_features)
            if audio_stress >= 0.82:
                return True

        context = context or {}
        if context.get("force_security_check") is True:
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
        audio_features: Optional[AudioEmotionFeatures],
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Security Agent approval/escalation payload.

        This method does not call external services directly. The Master Agent
        or Agent Router can forward this payload to Security Agent.
        """

        safe_text = self._normalize_text(text)
        risk_score, markers, risk_signal = self._score_risk_text(safe_text)

        return {
            "target_agent": "security_agent",
            "action": "review_emotion_risk_signal",
            "requires_approval": False,
            "requires_safe_routing": True,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "session_id": session_id,
            "task_id": task_id,
            "request_id": request_id,
            "risk_signal": risk_signal.value,
            "risk_score": round(risk_score, 4),
            "markers": markers,
            "raw_text_included": False,
            "raw_audio_included": False,
            "context": {
                "source_agent": self.config.agent_id,
                "purpose": "emotion_safety_metadata",
                "timestamp": self._now(),
                "context_keys": sorted(list((context or {}).keys())),
            },
        }

    def _prepare_verification_payload(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        session_id: Optional[str],
        task_id: Optional[str],
        request_id: str,
        analysis: EmotionAnalysisResult,
        security_payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent-compatible payload.
        """

        return {
            "target_agent": "verification_agent",
            "source_agent": self.config.agent_id,
            "verification_type": "emotion_analysis_result",
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "session_id": session_id,
            "task_id": task_id,
            "request_id": request_id,
            "result_summary": {
                "primary_emotion": analysis.primary_emotion.value,
                "urgency_level": analysis.urgency_level.value,
                "stress_level": analysis.stress_level.value,
                "whisper_detected": analysis.whisper_detected,
                "risk_signal": analysis.risk_signal.value,
                "confidence": round(analysis.confidence, 4),
                "response_tone": analysis.response_tone.value,
            },
            "checks": {
                "has_primary_emotion": analysis.primary_emotion != EmotionLabel.UNKNOWN,
                "confidence_above_minimum": analysis.confidence >= self.config.min_confidence,
                "safe_routing_required": analysis.risk_signal != RiskSignal.NONE,
                "security_payload_prepared": security_payload is not None,
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
        audio_features: Optional[AudioEmotionFeatures],
        analysis: EmotionAnalysisResult,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        Default behavior stores only emotion metadata, not raw text/audio.
        """

        payload: Dict[str, Any] = {
            "target_agent": "memory_agent",
            "source_agent": self.config.agent_id,
            "memory_type": "voice_emotion_metadata",
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "session_id": session_id,
            "task_id": task_id,
            "request_id": request_id,
            "importance": self._memory_importance_from_analysis(analysis),
            "data": {
                "primary_emotion": analysis.primary_emotion.value,
                "secondary_emotions": [item.value for item in analysis.secondary_emotions],
                "urgency_level": analysis.urgency_level.value,
                "urgency_score": round(analysis.urgency_score, 4),
                "stress_level": analysis.stress_level.value,
                "stress_score": round(analysis.stress_score, 4),
                "whisper_detected": analysis.whisper_detected,
                "whisper_score": round(analysis.whisper_score, 4),
                "risk_signal": analysis.risk_signal.value,
                "confidence": round(analysis.confidence, 4),
                "response_tone": analysis.response_tone.value,
            },
            "privacy": {
                "raw_text_included": self.config.store_raw_text_in_memory_payload,
                "raw_audio_features_included": self.config.store_raw_audio_features_in_memory_payload,
            },
            "timestamp": self._now(),
        }

        if self.config.store_raw_text_in_memory_payload:
            payload["data"]["text"] = text

        if self.config.store_raw_audio_features_in_memory_payload and audio_features:
            payload["data"]["audio_features"] = asdict(audio_features)

        return payload

    def _emit_agent_event(
        self,
        event_name: str,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        session_id: Optional[str],
        task_id: Optional[str],
        request_id: str,
        analysis: EmotionAnalysisResult,
    ) -> Dict[str, Any]:
        """
        Emit dashboard/registry-compatible event payload.

        Uses BaseAgent.emit_event when available, otherwise logs safely.
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
                "primary_emotion": analysis.primary_emotion.value,
                "urgency_level": analysis.urgency_level.value,
                "stress_level": analysis.stress_level.value,
                "whisper_detected": analysis.whisper_detected,
                "risk_signal": analysis.risk_signal.value,
                "response_tone": analysis.response_tone.value,
                "confidence": round(analysis.confidence, 4),
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
        analysis: EmotionAnalysisResult,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare and optionally log audit event.
        """

        payload = {
            "action": action,
            "source_agent": self.config.agent_id,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "session_id": session_id,
            "task_id": task_id,
            "request_id": request_id,
            "audit_category": "voice_emotion_detection",
            "data": {
                "primary_emotion": analysis.primary_emotion.value,
                "urgency_level": analysis.urgency_level.value,
                "stress_level": analysis.stress_level.value,
                "whisper_detected": analysis.whisper_detected,
                "risk_signal": analysis.risk_signal.value,
                "confidence": round(analysis.confidence, 4),
            },
            "context_keys": sorted(list((context or {}).keys())),
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
    # Internal Text Analysis
    # =========================================================================

    def _analyze_text_internal(self, text: str) -> Dict[str, Any]:
        """
        Internal text emotion scoring.
        """

        emotion_scores: Dict[str, float] = {emotion.value: 0.0 for emotion in EmotionLabel}
        markers: List[str] = []

        lowered = text.lower()
        tokens = self._tokenize(lowered)

        for emotion, keyword_groups in self._emotion_keywords.items():
            score, found = self._score_keywords(lowered, tokens, keyword_groups)
            emotion_scores[emotion.value] = self._clamp(score)
            markers.extend(found)

        punctuation_score, punctuation_markers = self._score_punctuation(text)
        markers.extend(punctuation_markers)

        caps_score, caps_markers = self._score_caps_intensity(text)
        markers.extend(caps_markers)

        urgency_score, urgency_markers = self._score_urgency_text(text)
        stress_score, stress_markers = self._score_stress_text(text)
        risk_score, risk_markers, risk_signal = self._score_risk_text(text)
        whisper_score, whisper_markers = self._score_whisper_text(text)

        markers.extend(urgency_markers)
        markers.extend(stress_markers)
        markers.extend(risk_markers)
        markers.extend(whisper_markers)

        emotion_scores[EmotionLabel.URGENT.value] = max(
            emotion_scores[EmotionLabel.URGENT.value],
            urgency_score,
        )

        emotion_scores[EmotionLabel.STRESSED.value] = max(
            emotion_scores[EmotionLabel.STRESSED.value],
            stress_score,
        )

        if whisper_score >= 0.50:
            emotion_scores[EmotionLabel.WHISPERING.value] = max(
                emotion_scores[EmotionLabel.WHISPERING.value],
                whisper_score,
            )

        if punctuation_score > 0.30:
            emotion_scores[EmotionLabel.EXCITED.value] = max(
                emotion_scores[EmotionLabel.EXCITED.value],
                punctuation_score * 0.72,
            )

        if caps_score > 0.35:
            emotion_scores[EmotionLabel.ANGRY.value] = max(
                emotion_scores[EmotionLabel.ANGRY.value],
                caps_score * 0.70,
            )
            emotion_scores[EmotionLabel.URGENT.value] = max(
                emotion_scores[EmotionLabel.URGENT.value],
                caps_score * 0.52,
            )

        primary, secondary = self._rank_emotions(emotion_scores)
        confidence = self._confidence_from_scores(emotion_scores)

        if primary == EmotionLabel.UNKNOWN and text.strip():
            primary = EmotionLabel.NEUTRAL
            emotion_scores[EmotionLabel.NEUTRAL.value] = max(
                emotion_scores[EmotionLabel.NEUTRAL.value],
                0.25,
            )
            confidence = max(confidence, 0.25)

        return {
            "emotion_scores": emotion_scores,
            "primary_emotion": primary,
            "secondary_emotions": secondary,
            "urgency_score": urgency_score,
            "stress_score": stress_score,
            "whisper_score": whisper_score,
            "risk_score": risk_score,
            "risk_signal": risk_signal,
            "markers": self._unique_preserve_order(markers),
            "confidence": confidence,
        }

    def _empty_text_analysis(self) -> Dict[str, Any]:
        """
        Empty text analysis structure.
        """

        return {
            "emotion_scores": {emotion.value: 0.0 for emotion in EmotionLabel},
            "primary_emotion": EmotionLabel.UNKNOWN,
            "secondary_emotions": [],
            "urgency_score": 0.0,
            "stress_score": 0.0,
            "whisper_score": 0.0,
            "risk_score": 0.0,
            "risk_signal": RiskSignal.NONE,
            "markers": [],
            "confidence": 0.0,
        }

    # =========================================================================
    # Internal Audio Analysis
    # =========================================================================

    def _analyze_audio_internal(self, audio: AudioEmotionFeatures) -> Dict[str, Any]:
        """
        Internal audio feature analysis.
        """

        emotion_scores: Dict[str, float] = {emotion.value: 0.0 for emotion in EmotionLabel}
        markers: List[str] = []

        stress_score, stress_markers = self._score_stress_audio(audio)
        whisper_score, whisper_markers = self._score_whisper_audio(audio)
        urgency_score, urgency_markers = self._score_urgency_audio(audio)

        markers.extend(stress_markers)
        markers.extend(whisper_markers)
        markers.extend(urgency_markers)

        emotion_scores[EmotionLabel.STRESSED.value] = stress_score
        emotion_scores[EmotionLabel.URGENT.value] = urgency_score

        if whisper_score >= 0.50:
            emotion_scores[EmotionLabel.WHISPERING.value] = whisper_score

        if self._safe_float(audio.energy) >= 0.72 and self._safe_float(audio.speech_rate_wps) >= 3.2:
            emotion_scores[EmotionLabel.EXCITED.value] = max(
                emotion_scores[EmotionLabel.EXCITED.value],
                0.48,
            )
            markers.append("audio:high_energy_fast_speech")

        if self._safe_float(audio.silence_ratio) >= 0.45 and self._safe_float(audio.energy) <= 0.25:
            emotion_scores[EmotionLabel.SAD.value] = max(
                emotion_scores[EmotionLabel.SAD.value],
                0.36,
            )
            markers.append("audio:long_silence_low_energy")

        if self._safe_float(audio.tremor_score) >= 0.55:
            emotion_scores[EmotionLabel.FEARFUL.value] = max(
                emotion_scores[EmotionLabel.FEARFUL.value],
                self._safe_float(audio.tremor_score),
            )
            markers.append("audio:vocal_tremor")

        primary, secondary = self._rank_emotions(emotion_scores)
        confidence = self._confidence_from_scores(emotion_scores)

        return {
            "emotion_scores": emotion_scores,
            "primary_emotion": primary,
            "secondary_emotions": secondary,
            "urgency_score": urgency_score,
            "stress_score": stress_score,
            "whisper_score": whisper_score,
            "risk_score": 0.0,
            "risk_signal": RiskSignal.NONE,
            "markers": self._unique_preserve_order(markers),
            "confidence": confidence,
        }

    def _empty_audio_analysis(self) -> Dict[str, Any]:
        """
        Empty audio analysis structure.
        """

        return {
            "emotion_scores": {emotion.value: 0.0 for emotion in EmotionLabel},
            "primary_emotion": EmotionLabel.UNKNOWN,
            "secondary_emotions": [],
            "urgency_score": 0.0,
            "stress_score": 0.0,
            "whisper_score": 0.0,
            "risk_score": 0.0,
            "risk_signal": RiskSignal.NONE,
            "markers": [],
            "confidence": 0.0,
        }

    # =========================================================================
    # Merge Analysis
    # =========================================================================

    def _merge_analysis(
        self,
        text_analysis: Dict[str, Any],
        audio_analysis: Dict[str, Any],
        warnings: Optional[List[str]] = None,
    ) -> EmotionAnalysisResult:
        """
        Merge text and audio analysis into one final result.
        """

        warnings = warnings or []

        merged_scores: Dict[str, float] = {}
        all_emotions = [emotion.value for emotion in EmotionLabel]

        for emotion in all_emotions:
            text_score = float(text_analysis["emotion_scores"].get(emotion, 0.0))
            audio_score = float(audio_analysis["emotion_scores"].get(emotion, 0.0))

            if text_analysis["confidence"] > 0 and audio_analysis["confidence"] > 0:
                merged_scores[emotion] = self._clamp((text_score * 0.65) + (audio_score * 0.35))
            elif text_analysis["confidence"] > 0:
                merged_scores[emotion] = self._clamp(text_score)
            elif audio_analysis["confidence"] > 0:
                merged_scores[emotion] = self._clamp(audio_score)
            else:
                merged_scores[emotion] = 0.0

        urgency_score = max(
            float(text_analysis.get("urgency_score", 0.0)),
            float(audio_analysis.get("urgency_score", 0.0)) * 0.85,
            merged_scores.get(EmotionLabel.URGENT.value, 0.0),
        )

        stress_score = max(
            float(text_analysis.get("stress_score", 0.0)),
            float(audio_analysis.get("stress_score", 0.0)) * 0.90,
            merged_scores.get(EmotionLabel.STRESSED.value, 0.0),
        )

        whisper_score = max(
            float(text_analysis.get("whisper_score", 0.0)),
            float(audio_analysis.get("whisper_score", 0.0)),
            merged_scores.get(EmotionLabel.WHISPERING.value, 0.0),
        )

        risk_score = max(
            float(text_analysis.get("risk_score", 0.0)),
            float(audio_analysis.get("risk_score", 0.0)),
        )

        risk_signal = text_analysis.get("risk_signal") or audio_analysis.get("risk_signal") or RiskSignal.NONE
        if isinstance(risk_signal, str):
            risk_signal = self._to_risk_signal(risk_signal)

        urgency_level = self._urgency_level_from_score(urgency_score)
        stress_level = self._stress_level_from_score(stress_score)
        whisper_detected = whisper_score >= 0.50

        primary, secondary = self._rank_emotions(merged_scores)

        if primary == EmotionLabel.UNKNOWN:
            if urgency_level in {UrgencyLevel.HIGH, UrgencyLevel.CRITICAL}:
                primary = EmotionLabel.URGENT
            elif stress_level in {StressLevel.HIGH, StressLevel.EXTREME}:
                primary = EmotionLabel.STRESSED
            elif whisper_detected:
                primary = EmotionLabel.WHISPERING
            else:
                primary = EmotionLabel.NEUTRAL
                merged_scores[EmotionLabel.NEUTRAL.value] = max(
                    merged_scores.get(EmotionLabel.NEUTRAL.value, 0.0),
                    0.25,
                )

        confidence = max(
            self._confidence_from_scores(merged_scores),
            float(text_analysis.get("confidence", 0.0)) * 0.65,
            float(audio_analysis.get("confidence", 0.0)) * 0.35,
        )
        confidence = self._clamp(confidence)

        tone = self._select_response_tone(
            primary_emotion=primary,
            urgency_level=urgency_level,
            stress_level=stress_level,
            whisper_detected=whisper_detected,
            risk_signal=risk_signal,
        )

        response_metadata = self._build_response_metadata(
            tone=tone,
            primary_emotion=primary,
            urgency_level=urgency_level,
            stress_level=stress_level,
            whisper_detected=whisper_detected,
            risk_signal=risk_signal,
        )

        markers = self._unique_preserve_order(
            list(text_analysis.get("markers", [])) + list(audio_analysis.get("markers", []))
        )

        return EmotionAnalysisResult(
            primary_emotion=primary,
            secondary_emotions=secondary,
            emotion_scores={key: round(self._clamp(value), 4) for key, value in merged_scores.items()},
            urgency_level=urgency_level,
            urgency_score=round(self._clamp(urgency_score), 4),
            stress_level=stress_level,
            stress_score=round(self._clamp(stress_score), 4),
            whisper_detected=whisper_detected,
            whisper_score=round(self._clamp(whisper_score), 4),
            risk_signal=risk_signal,
            risk_score=round(self._clamp(risk_score), 4),
            confidence=round(confidence, 4),
            response_tone=tone,
            response_metadata=response_metadata,
            detected_markers=markers,
            warnings=warnings,
        )

    # =========================================================================
    # Scoring Helpers
    # =========================================================================

    def _score_keywords(
        self,
        lowered_text: str,
        tokens: List[str],
        keyword_groups: Dict[str, float],
    ) -> Tuple[float, List[str]]:
        """
        Score keyword matches with weighted markers.
        """

        score = 0.0
        found: List[str] = []
        token_set = set(tokens)

        for phrase, weight in keyword_groups.items():
            phrase_lower = phrase.lower()
            if " " in phrase_lower:
                if phrase_lower in lowered_text:
                    score += weight
                    found.append(f"text:{phrase_lower}")
            else:
                if phrase_lower in token_set:
                    score += weight
                    found.append(f"text:{phrase_lower}")

        return self._clamp(score), found

    def _score_punctuation(self, text: str) -> Tuple[float, List[str]]:
        """
        Detect emotional intensity from punctuation.
        """

        markers: List[str] = []
        exclamations = text.count("!")
        question_marks = text.count("?")
        repeated = len(re.findall(r"([!?])\1{1,}", text))

        score = 0.0

        if exclamations >= 1:
            score += min(0.12 * exclamations, 0.36)
            markers.append("punctuation:exclamation")

        if question_marks >= 2:
            score += min(0.08 * question_marks, 0.24)
            markers.append("punctuation:multiple_questions")

        if repeated:
            score += min(0.15 * repeated, 0.30)
            markers.append("punctuation:repeated_marks")

        return self._clamp(score), markers

    def _score_caps_intensity(self, text: str) -> Tuple[float, List[str]]:
        """
        Detect intensity from uppercase words.
        """

        words = re.findall(r"\b[A-Z]{2,}\b", text)
        markers: List[str] = []

        if not words:
            return 0.0, markers

        total_words = max(len(re.findall(r"\b\w+\b", text)), 1)
        ratio = len(words) / total_words
        score = min(0.80, ratio * 2.5)

        if len(words) >= 2:
            markers.append("text:multiple_uppercase_words")

        if ratio >= 0.25:
            markers.append("text:high_caps_ratio")

        return self._clamp(score), markers

    def _score_urgency_text(self, text: str) -> Tuple[float, List[str]]:
        """
        Score urgency from text.
        """

        lowered = text.lower()
        tokens = self._tokenize(lowered)
        score, markers = self._score_keywords(lowered, tokens, self._urgency_keywords)

        punctuation_score, punctuation_markers = self._score_punctuation(text)
        caps_score, caps_markers = self._score_caps_intensity(text)

        score += punctuation_score * 0.45
        score += caps_score * 0.35

        markers.extend(punctuation_markers)
        markers.extend(caps_markers)

        time_pressure_patterns = [
            r"\bright now\b",
            r"\basap\b",
            r"\bimmediately\b",
            r"\bwithin\s+\d+\s+(minute|minutes|hour|hours)\b",
            r"\bdeadline\b",
            r"\bemergency\b",
        ]

        for pattern in time_pressure_patterns:
            if re.search(pattern, lowered):
                score += 0.18
                markers.append(f"urgency_pattern:{pattern}")

        return self._clamp(score), self._unique_preserve_order(markers)

    def _score_urgency_audio(self, audio: AudioEmotionFeatures) -> Tuple[float, List[str]]:
        """
        Score urgency from audio features.
        """

        score = 0.0
        markers: List[str] = []

        speech_rate = self._safe_float(audio.speech_rate_wps)
        energy = self._safe_float(audio.energy)
        peak_volume = self._safe_float(audio.peak_volume)
        pitch_var = self._safe_float(audio.pitch_variance)

        if speech_rate >= 3.4:
            score += 0.28
            markers.append("audio:fast_speech")

        if energy >= 0.70:
            score += 0.22
            markers.append("audio:high_energy")

        if peak_volume >= 0.82:
            score += 0.18
            markers.append("audio:high_peak_volume")

        if pitch_var >= 0.58:
            score += 0.18
            markers.append("audio:high_pitch_variance")

        return self._clamp(score), markers

    def _score_stress_text(self, text: str) -> Tuple[float, List[str]]:
        """
        Score stress from text.
        """

        lowered = text.lower()
        tokens = self._tokenize(lowered)
        score, markers = self._score_keywords(lowered, tokens, self._stress_keywords)

        stress_patterns = [
            r"\bi can't handle\b",
            r"\bi cannot handle\b",
            r"\bi don'?t know what to do\b",
            r"\bi'?m losing it\b",
            r"\btoo much\b",
            r"\boverwhelmed\b",
            r"\bpressure\b",
            r"\bpanic\b",
        ]

        for pattern in stress_patterns:
            if re.search(pattern, lowered):
                score += 0.20
                markers.append(f"stress_pattern:{pattern}")

        punctuation_score, punctuation_markers = self._score_punctuation(text)
        score += punctuation_score * 0.20
        markers.extend(punctuation_markers)

        return self._clamp(score), self._unique_preserve_order(markers)

    def _score_stress_audio(self, audio: AudioEmotionFeatures) -> Tuple[float, List[str]]:
        """
        Score stress from normalized audio features.
        """

        score = 0.0
        markers: List[str] = []

        pitch_var = self._safe_float(audio.pitch_variance)
        tremor = self._safe_float(audio.tremor_score)
        speech_rate = self._safe_float(audio.speech_rate_wps)
        breathiness = self._safe_float(audio.breathiness_score)
        silence = self._safe_float(audio.silence_ratio)
        energy = self._safe_float(audio.energy)

        if pitch_var >= 0.52:
            score += 0.20
            markers.append("audio:stress_pitch_variance")

        if tremor >= 0.42:
            score += 0.24
            markers.append("audio:vocal_tremor")

        if speech_rate >= 3.5:
            score += 0.18
            markers.append("audio:rapid_speech")

        if breathiness >= 0.50:
            score += 0.15
            markers.append("audio:breathiness")

        if silence >= 0.45 and energy <= 0.30:
            score += 0.12
            markers.append("audio:silence_low_energy")

        if energy >= 0.84:
            score += 0.12
            markers.append("audio:high_emotional_energy")

        return self._clamp(score), markers

    def _score_whisper_text(self, text: str) -> Tuple[float, List[str]]:
        """
        Score whisper/private mode from text.
        """

        lowered = text.lower()
        markers: List[str] = []
        score = 0.0

        phrases = {
            "whisper": 0.45,
            "speak quietly": 0.42,
            "quietly": 0.25,
            "be quiet": 0.35,
            "lower your voice": 0.45,
            "don't speak loud": 0.45,
            "dont speak loud": 0.45,
            "private": 0.18,
            "secret": 0.15,
        }

        for phrase, weight in phrases.items():
            if phrase in lowered:
                score += weight
                markers.append(f"whisper_text:{phrase}")

        if text.strip().islower() and len(text.strip()) < 120:
            score += 0.05
            markers.append("whisper_text:short_lowercase_utterance")

        return self._clamp(score), self._unique_preserve_order(markers)

    def _score_whisper_audio(self, audio: AudioEmotionFeatures) -> Tuple[float, List[str]]:
        """
        Score whispering from audio features.
        """

        score = 0.0
        markers: List[str] = []

        avg_volume = self._safe_float(audio.average_volume)
        peak_volume = self._safe_float(audio.peak_volume)
        energy = self._safe_float(audio.energy)
        speech_rate = self._safe_float(audio.speech_rate_wps)
        breathiness = self._safe_float(audio.breathiness_score)

        if avg_volume > 0 and avg_volume <= self.config.whisper_volume_threshold:
            score += 0.30
            markers.append("audio:low_average_volume")

        if peak_volume > 0 and peak_volume <= 0.36:
            score += 0.18
            markers.append("audio:low_peak_volume")

        if energy > 0 and energy <= self.config.whisper_energy_threshold:
            score += 0.24
            markers.append("audio:low_energy")

        if breathiness >= 0.45:
            score += 0.18
            markers.append("audio:breathy_voice")

        if 0 < speech_rate <= self.config.whisper_speech_rate_max:
            score += 0.08
            markers.append("audio:slow_or_controlled_speech")

        return self._clamp(score), self._unique_preserve_order(markers)

    def _score_risk_text(self, text: str) -> Tuple[float, List[str], RiskSignal]:
        """
        Detect broad safety escalation signals.

        This does not make clinical/legal claims. It only flags risk metadata
        for Security Agent and Master Agent routing.
        """

        if not text:
            return 0.0, [], RiskSignal.NONE

        lowered = text.lower()
        tokens = self._tokenize(lowered)

        score = 0.0
        markers: List[str] = []
        selected_signal = RiskSignal.NONE

        for signal, keyword_groups in self._risk_keywords.items():
            signal_score, found = self._score_keywords(lowered, tokens, keyword_groups)
            if signal_score > score:
                score = signal_score
                selected_signal = signal
            markers.extend(found)

        emergency_patterns = [
            r"\bcall\s+911\b",
            r"\bcall\s+emergency\b",
            r"\bemergency\b",
            r"\bambulance\b",
            r"\bpolice\b",
            r"\bfire\b",
        ]

        for pattern in emergency_patterns:
            if re.search(pattern, lowered):
                score += 0.25
                selected_signal = RiskSignal.EMERGENCY
                markers.append(f"risk_pattern:{pattern}")

        return self._clamp(score), self._unique_preserve_order(markers), selected_signal

    # =========================================================================
    # Level / Tone Mapping
    # =========================================================================

    def _urgency_level_from_score(self, score: float) -> UrgencyLevel:
        """
        Convert urgency score to urgency level.
        """

        score = self._clamp(score)

        if score >= self.config.critical_urgency_score_threshold:
            return UrgencyLevel.CRITICAL
        if score >= self.config.high_urgency_score_threshold:
            return UrgencyLevel.HIGH
        if score >= self.config.medium_urgency_score_threshold:
            return UrgencyLevel.MEDIUM
        if score > 0.08:
            return UrgencyLevel.LOW
        return UrgencyLevel.NONE

    def _stress_level_from_score(self, score: float) -> StressLevel:
        """
        Convert stress score to stress level.
        """

        score = self._clamp(score)

        if score >= 0.88:
            return StressLevel.EXTREME
        if score >= self.config.high_stress_score_threshold:
            return StressLevel.HIGH
        if score >= self.config.medium_stress_score_threshold:
            return StressLevel.MEDIUM
        if score > 0.08:
            return StressLevel.LOW
        return StressLevel.NONE

    def _select_response_tone(
        self,
        primary_emotion: EmotionLabel,
        urgency_level: UrgencyLevel,
        stress_level: StressLevel,
        whisper_detected: bool,
        risk_signal: RiskSignal,
    ) -> ResponseTone:
        """
        Select assistant tone based on emotion metadata.
        """

        if whisper_detected:
            return ResponseTone.QUIET

        if risk_signal in {
            RiskSignal.EMERGENCY,
            RiskSignal.PANIC,
            RiskSignal.POSSIBLE_SELF_HARM,
            RiskSignal.POSSIBLE_VIOLENCE,
        }:
            return ResponseTone.CALM

        if urgency_level in {UrgencyLevel.CRITICAL, UrgencyLevel.HIGH}:
            return ResponseTone.URGENT

        if stress_level in {StressLevel.EXTREME, StressLevel.HIGH}:
            return ResponseTone.REASSURING

        if primary_emotion in {EmotionLabel.SAD, EmotionLabel.FEARFUL, EmotionLabel.STRESSED}:
            return ResponseTone.EMPATHETIC

        if primary_emotion in {EmotionLabel.ANGRY, EmotionLabel.FRUSTRATED}:
            return ResponseTone.CALM

        if primary_emotion == EmotionLabel.CONFUSED:
            return ResponseTone.CLARIFYING

        if primary_emotion in {EmotionLabel.HAPPY, EmotionLabel.EXCITED}:
            return ResponseTone.CONFIDENT

        if primary_emotion == EmotionLabel.TIRED:
            return ResponseTone.GENTLE

        return ResponseTone.NORMAL

    def _build_response_metadata(
        self,
        tone: ResponseTone,
        primary_emotion: EmotionLabel,
        urgency_level: UrgencyLevel,
        stress_level: StressLevel,
        whisper_detected: bool,
        risk_signal: RiskSignal,
    ) -> Dict[str, Any]:
        """
        Build response behavior metadata for Master Agent, Response Builder, and TTS.
        """

        base = {
            "response_tone": tone.value,
            "primary_emotion": primary_emotion.value,
            "urgency_level": urgency_level.value,
            "stress_level": stress_level.value,
            "whisper_detected": whisper_detected,
            "risk_signal": risk_signal.value,
            "tts": {
                "volume": 0.75,
                "speed": 1.0,
                "pitch": 1.0,
                "pause_factor": 1.0,
            },
            "response_style": {
                "use_short_sentences": False,
                "ask_clarifying_question": False,
                "avoid_jokes": False,
                "be_extra_direct": False,
                "be_extra_reassuring": False,
                "privacy_sensitive": False,
            },
            "routing": {
                "send_to_security_agent": risk_signal != RiskSignal.NONE,
                "send_to_verification_agent": True,
                "memory_candidate": True,
            },
        }

        if tone == ResponseTone.QUIET:
            base["tts"].update({"volume": 0.35, "speed": 0.92, "pitch": 0.95})
            base["response_style"].update(
                {
                    "use_short_sentences": True,
                    "privacy_sensitive": True,
                }
            )

        elif tone == ResponseTone.CALM:
            base["tts"].update({"volume": 0.62, "speed": 0.88, "pitch": 0.96, "pause_factor": 1.18})
            base["response_style"].update(
                {
                    "use_short_sentences": True,
                    "avoid_jokes": True,
                    "be_extra_reassuring": True,
                }
            )

        elif tone == ResponseTone.URGENT:
            base["tts"].update({"volume": 0.82, "speed": 1.05, "pitch": 1.0, "pause_factor": 0.92})
            base["response_style"].update(
                {
                    "use_short_sentences": True,
                    "be_extra_direct": True,
                    "avoid_jokes": True,
                }
            )

        elif tone == ResponseTone.REASSURING:
            base["tts"].update({"volume": 0.68, "speed": 0.92, "pitch": 0.98, "pause_factor": 1.10})
            base["response_style"].update(
                {
                    "use_short_sentences": True,
                    "be_extra_reassuring": True,
                    "avoid_jokes": True,
                }
            )

        elif tone == ResponseTone.CLARIFYING:
            base["response_style"].update(
                {
                    "ask_clarifying_question": True,
                    "use_short_sentences": True,
                }
            )

        elif tone == ResponseTone.EMPATHETIC:
            base["tts"].update({"volume": 0.66, "speed": 0.94, "pitch": 0.98, "pause_factor": 1.08})
            base["response_style"].update(
                {
                    "be_extra_reassuring": True,
                    "avoid_jokes": True,
                }
            )

        elif tone == ResponseTone.GENTLE:
            base["tts"].update({"volume": 0.58, "speed": 0.90, "pitch": 0.96, "pause_factor": 1.12})
            base["response_style"].update(
                {
                    "use_short_sentences": True,
                    "avoid_jokes": True,
                }
            )

        elif tone == ResponseTone.CONFIDENT:
            base["tts"].update({"volume": 0.78, "speed": 1.02, "pitch": 1.02})
            base["response_style"].update(
                {
                    "be_extra_direct": False,
                }
            )

        return base

    # =========================================================================
    # Keyword Dictionaries
    # =========================================================================

    def _build_emotion_keywords(self) -> Dict[EmotionLabel, Dict[str, float]]:
        """
        Build emotion keyword map.

        This is intentionally simple and deterministic for production reliability.
        A future ML classifier can be added behind the same public methods.
        """

        return {
            EmotionLabel.HAPPY: {
                "happy": 0.35,
                "great": 0.18,
                "awesome": 0.25,
                "amazing": 0.24,
                "love it": 0.35,
                "perfect": 0.22,
                "good news": 0.30,
                "thank you": 0.12,
                "thanks": 0.10,
            },
            EmotionLabel.EXCITED: {
                "excited": 0.38,
                "can't wait": 0.32,
                "lets go": 0.28,
                "let's go": 0.28,
                "wow": 0.18,
                "unbelievable": 0.18,
                "fantastic": 0.26,
            },
            EmotionLabel.SAD: {
                "sad": 0.38,
                "upset": 0.30,
                "hurt": 0.30,
                "crying": 0.42,
                "depressed": 0.50,
                "heartbroken": 0.46,
                "lonely": 0.35,
                "hopeless": 0.48,
            },
            EmotionLabel.ANGRY: {
                "angry": 0.42,
                "mad": 0.32,
                "furious": 0.50,
                "hate": 0.32,
                "annoyed": 0.25,
                "ridiculous": 0.22,
                "stupid": 0.20,
                "shut up": 0.40,
            },
            EmotionLabel.FEARFUL: {
                "afraid": 0.38,
                "scared": 0.40,
                "fear": 0.30,
                "terrified": 0.55,
                "worried": 0.26,
                "anxious": 0.36,
                "panic": 0.50,
            },
            EmotionLabel.CONFUSED: {
                "confused": 0.40,
                "don't understand": 0.36,
                "dont understand": 0.36,
                "what does this mean": 0.34,
                "not clear": 0.25,
                "unclear": 0.25,
                "lost": 0.22,
                "explain again": 0.32,
            },
            EmotionLabel.FRUSTRATED: {
                "frustrated": 0.45,
                "again and again": 0.28,
                "not working": 0.28,
                "same issue": 0.30,
                "why is this": 0.22,
                "i tried": 0.14,
                "still broken": 0.34,
                "fed up": 0.42,
            },
            EmotionLabel.TIRED: {
                "tired": 0.35,
                "exhausted": 0.42,
                "sleepy": 0.28,
                "burned out": 0.45,
                "burnt out": 0.45,
                "drained": 0.38,
            },
            EmotionLabel.CALM: {
                "calm": 0.30,
                "fine": 0.12,
                "okay": 0.10,
                "relaxed": 0.32,
                "no problem": 0.18,
            },
            EmotionLabel.STRESSED: {},
            EmotionLabel.URGENT: {},
            EmotionLabel.WHISPERING: {},
            EmotionLabel.NEUTRAL: {},
            EmotionLabel.UNKNOWN: {},
        }

    def _build_urgency_keywords(self) -> Dict[str, float]:
        """
        Build urgency keyword map.
        """

        return {
            "urgent": 0.45,
            "emergency": 0.70,
            "now": 0.18,
            "right now": 0.38,
            "asap": 0.45,
            "quick": 0.20,
            "quickly": 0.22,
            "immediately": 0.46,
            "fast": 0.16,
            "hurry": 0.40,
            "deadline": 0.34,
            "critical": 0.42,
            "important": 0.20,
            "can't wait": 0.38,
            "cannot wait": 0.38,
            "help me now": 0.55,
            "please help": 0.24,
        }

    def _build_stress_keywords(self) -> Dict[str, float]:
        """
        Build stress keyword map.
        """

        return {
            "stressed": 0.44,
            "stress": 0.35,
            "panic": 0.55,
            "panicking": 0.58,
            "overwhelmed": 0.50,
            "too much": 0.32,
            "pressure": 0.28,
            "worried": 0.28,
            "anxious": 0.42,
            "nervous": 0.30,
            "can't handle": 0.50,
            "cannot handle": 0.50,
            "losing it": 0.48,
            "breakdown": 0.42,
            "help": 0.16,
        }

    def _build_risk_keywords(self) -> Dict[RiskSignal, Dict[str, float]]:
        """
        Build broad risk keyword map for safe routing.
        """

        return {
            RiskSignal.DISTRESS: {
                "help me": 0.25,
                "i can't cope": 0.45,
                "i cannot cope": 0.45,
                "i can't take it": 0.50,
                "i cannot take it": 0.50,
                "hopeless": 0.38,
            },
            RiskSignal.PANIC: {
                "panic": 0.50,
                "panicking": 0.55,
                "can't breathe": 0.60,
                "cannot breathe": 0.60,
                "heart racing": 0.35,
            },
            RiskSignal.POSSIBLE_SELF_HARM: {
                "hurt myself": 0.78,
                "harm myself": 0.78,
                "end my life": 0.95,
                "kill myself": 0.98,
                "suicide": 0.95,
                "don't want to live": 0.85,
                "dont want to live": 0.85,
            },
            RiskSignal.POSSIBLE_VIOLENCE: {
                "hurt someone": 0.75,
                "attack": 0.42,
                "kill them": 0.88,
                "kill him": 0.88,
                "kill her": 0.88,
                "violence": 0.50,
            },
            RiskSignal.EMERGENCY: {
                "emergency": 0.70,
                "ambulance": 0.80,
                "police": 0.55,
                "fire": 0.45,
                "accident": 0.38,
                "bleeding": 0.65,
            },
        }

    def _build_tone_rules(self) -> Dict[str, Any]:
        """
        Placeholder-free tone rules for dashboard visibility.

        These are used indirectly by _select_response_tone and can be exposed
        through future config/dashboard APIs.
        """

        return {
            "critical_risk": ResponseTone.CALM.value,
            "high_urgency": ResponseTone.URGENT.value,
            "high_stress": ResponseTone.REASSURING.value,
            "whisper": ResponseTone.QUIET.value,
            "confusion": ResponseTone.CLARIFYING.value,
            "anger": ResponseTone.CALM.value,
            "sadness": ResponseTone.EMPATHETIC.value,
            "default": ResponseTone.NORMAL.value,
        }

    # =========================================================================
    # Utility Helpers
    # =========================================================================

    def _normalize_text(self, text: Optional[str]) -> str:
        """
        Normalize input text safely.
        """

        if text is None:
            return ""

        if not isinstance(text, str):
            text = str(text)

        text = text.replace("\x00", "")
        text = re.sub(r"\s+", " ", text).strip()
        return text

    def _normalize_audio_features(
        self,
        audio_features: Optional[Union[AudioEmotionFeatures, Dict[str, Any]]],
    ) -> Optional[AudioEmotionFeatures]:
        """
        Convert dict audio features into AudioEmotionFeatures.
        """

        if audio_features is None:
            return None

        if isinstance(audio_features, AudioEmotionFeatures):
            return audio_features

        if not isinstance(audio_features, dict):
            return None

        allowed_keys = {
            "average_volume",
            "peak_volume",
            "energy",
            "pitch_mean",
            "pitch_variance",
            "speech_rate_wps",
            "silence_ratio",
            "tremor_score",
            "breathiness_score",
            "duration_seconds",
            "sample_rate",
            "metadata",
        }

        clean: Dict[str, Any] = {}
        for key, value in audio_features.items():
            if key in allowed_keys:
                clean[key] = value

        metadata = clean.get("metadata")
        if metadata is None or not isinstance(metadata, dict):
            clean["metadata"] = {}

        return AudioEmotionFeatures(**clean)

    def _tokenize(self, text: str) -> List[str]:
        """
        Simple tokenization.
        """

        return re.findall(r"\b[\w']+\b", text.lower())

    def _rank_emotions(
        self,
        emotion_scores: Dict[str, float],
    ) -> Tuple[EmotionLabel, List[EmotionLabel]]:
        """
        Rank emotions by score.
        """

        filtered = {
            key: self._clamp(float(value))
            for key, value in emotion_scores.items()
            if key not in {EmotionLabel.UNKNOWN.value}
        }

        ranked = sorted(filtered.items(), key=lambda item: item[1], reverse=True)

        if not ranked or ranked[0][1] <= 0.05:
            return EmotionLabel.UNKNOWN, []

        primary = self._to_emotion_label(ranked[0][0])

        secondary: List[EmotionLabel] = []
        for key, score in ranked[1:4]:
            if score >= 0.15:
                label = self._to_emotion_label(key)
                if label != primary and label not in secondary:
                    secondary.append(label)

        return primary, secondary

    def _confidence_from_scores(self, emotion_scores: Dict[str, float]) -> float:
        """
        Calculate confidence from score distribution.
        """

        scores = sorted(
            [self._clamp(float(value)) for value in emotion_scores.values()],
            reverse=True,
        )

        if not scores or scores[0] <= 0.0:
            return 0.0

        top = scores[0]
        second = scores[1] if len(scores) > 1 else 0.0
        gap = max(0.0, top - second)

        confidence = (top * 0.72) + (gap * 0.28)
        return self._clamp(confidence)

    def _memory_importance_from_analysis(self, analysis: EmotionAnalysisResult) -> str:
        """
        Decide memory importance level.
        """

        if analysis.risk_signal != RiskSignal.NONE:
            return "high"

        if analysis.urgency_level in {UrgencyLevel.HIGH, UrgencyLevel.CRITICAL}:
            return "high"

        if analysis.stress_level in {StressLevel.HIGH, StressLevel.EXTREME}:
            return "high"

        if analysis.primary_emotion in {
            EmotionLabel.SAD,
            EmotionLabel.ANGRY,
            EmotionLabel.FRUSTRATED,
            EmotionLabel.FEARFUL,
        }:
            return "medium"

        return "low"

    def _analysis_to_dict(self, analysis: EmotionAnalysisResult) -> Dict[str, Any]:
        """
        Convert analysis dataclass to JSON-safe dict.
        """

        return {
            "primary_emotion": analysis.primary_emotion.value,
            "secondary_emotions": [item.value for item in analysis.secondary_emotions],
            "emotion_scores": analysis.emotion_scores,
            "urgency_level": analysis.urgency_level.value,
            "urgency_score": analysis.urgency_score,
            "stress_level": analysis.stress_level.value,
            "stress_score": analysis.stress_score,
            "whisper_detected": analysis.whisper_detected,
            "whisper_score": analysis.whisper_score,
            "risk_signal": analysis.risk_signal.value,
            "risk_score": analysis.risk_score,
            "confidence": analysis.confidence,
            "response_tone": analysis.response_tone.value,
            "response_metadata": analysis.response_metadata,
            "detected_markers": analysis.detected_markers,
            "warnings": analysis.warnings,
        }

    def _to_emotion_label(self, value: Union[str, EmotionLabel]) -> EmotionLabel:
        """
        Convert value to EmotionLabel safely.
        """

        if isinstance(value, EmotionLabel):
            return value

        try:
            return EmotionLabel(str(value).lower())
        except Exception:
            return EmotionLabel.UNKNOWN

    def _to_urgency_level(self, value: Union[str, UrgencyLevel]) -> UrgencyLevel:
        """
        Convert value to UrgencyLevel safely.
        """

        if isinstance(value, UrgencyLevel):
            return value

        try:
            return UrgencyLevel(str(value).lower())
        except Exception:
            return UrgencyLevel.NONE

    def _to_stress_level(self, value: Union[str, StressLevel]) -> StressLevel:
        """
        Convert value to StressLevel safely.
        """

        if isinstance(value, StressLevel):
            return value

        try:
            return StressLevel(str(value).lower())
        except Exception:
            return StressLevel.NONE

    def _to_risk_signal(self, value: Union[str, RiskSignal]) -> RiskSignal:
        """
        Convert value to RiskSignal safely.
        """

        if isinstance(value, RiskSignal):
            return value

        try:
            return RiskSignal(str(value).lower())
        except Exception:
            return RiskSignal.UNKNOWN

    def _safe_float(self, value: Optional[Any], default: float = 0.0) -> float:
        """
        Convert value to safe float.
        """

        if value is None:
            return default

        try:
            number = float(value)
            if math.isnan(number) or math.isinf(number):
                return default
            return number
        except Exception:
            return default

    def _clamp(self, value: float, low: float = 0.0, high: float = 1.0) -> float:
        """
        Clamp float to range.
        """

        try:
            value = float(value)
        except Exception:
            value = low

        if math.isnan(value) or math.isinf(value):
            return low

        return max(low, min(high, value))

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
        Generate request ID.
        """

        return f"emotion_{uuid.uuid4().hex}"

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
        Health check for Agent Registry, Loader, Dashboard, or API.
        """

        return self._safe_result(
            message="EmotionDetector is healthy.",
            data={
                "agent_name": self.config.agent_name,
                "agent_id": self.config.agent_id,
                "version": self.VERSION,
                "capabilities": self.capabilities(),
                "config": {
                    "enable_text_analysis": self.config.enable_text_analysis,
                    "enable_audio_feature_analysis": self.config.enable_audio_feature_analysis,
                    "enable_whisper_detection": self.config.enable_whisper_detection,
                    "enable_urgency_detection": self.config.enable_urgency_detection,
                    "enable_stress_detection": self.config.enable_stress_detection,
                    "enable_safety_signal_detection": self.config.enable_safety_signal_detection,
                },
            },
            metadata={
                "timestamp": self._now(),
            },
        )

    def capabilities(self) -> List[str]:
        """
        Return supported capabilities for registry routing.
        """

        return [
            "voice.emotion.detect",
            "voice.urgency.detect",
            "voice.stress.detect",
            "voice.whisper.detect",
            "voice.response_tone.prepare",
            "voice.safety_signal.detect",
            "voice.memory_payload.prepare",
            "voice.verification_payload.prepare",
        ]

    def get_registry_manifest(self) -> Dict[str, Any]:
        """
        Return Agent Registry-compatible manifest.
        """

        return {
            "agent_name": self.config.agent_name,
            "agent_id": self.config.agent_id,
            "module": "agents.voice_agent.emotion_detector",
            "class_name": "EmotionDetector",
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

def create_emotion_detector(
    config: Optional[EmotionDetectorConfig] = None,
) -> EmotionDetector:
    """
    Factory used by Agent Loader or tests.
    """

    return EmotionDetector(config=config)


# =============================================================================
# Minimal Self-Test
# =============================================================================

def _self_test() -> Dict[str, Any]:
    """
    Lightweight self-test.

    Run:
        python agents/voice_agent/emotion_detector.py

    This does not require any external dependency.
    """

    detector = EmotionDetector()

    return detector.analyze(
        text="Please help me right now, I am stressed and confused!",
        audio_features={
            "average_volume": 0.62,
            "peak_volume": 0.88,
            "energy": 0.74,
            "pitch_variance": 0.60,
            "speech_rate_wps": 3.6,
            "tremor_score": 0.25,
            "breathiness_score": 0.18,
            "silence_ratio": 0.08,
        },
        user_id="self_test_user",
        workspace_id="self_test_workspace",
        session_id="self_test_session",
        task_id="self_test_task",
        context={"source": "self_test"},
    )


if __name__ == "__main__":
    import json

    result = _self_test()
    print(json.dumps(result, indent=2, ensure_ascii=False))