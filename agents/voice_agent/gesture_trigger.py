"""
agents/voice_agent/gesture_trigger.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Detects clap, tap, smart glasses, and hand gesture triggers.

Architecture Compatibility:
    - BaseAgent compatible
    - Agent Registry compatible
    - Agent Loader compatible
    - Agent Router compatible
    - Master Agent routing compatible
    - Security Agent approval compatible
    - Memory Agent payload compatible
    - Verification Agent payload compatible
    - Dashboard/API ready
    - SaaS user/workspace isolated

Important:
    This file does not directly execute destructive/system/browser/call actions.
    It only detects and normalizes gesture trigger events, then returns safe,
    structured routing payloads for the Master Agent or Voice Agent.

Public Class:
    GestureTrigger
"""

from __future__ import annotations

import json
import logging
import math
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe even before the full William/Jarvis
        architecture exists.
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

logger = logging.getLogger("GestureTrigger")
if not logger.handlers:
    logging.basicConfig(
        level=os.getenv("WILLIAM_LOG_LEVEL", "INFO"),
        format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    )


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return current UTC datetime in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def _now_ms() -> int:
    """Return current unix timestamp in milliseconds."""
    return int(time.time() * 1000)


def _safe_text(value: Any, max_length: int = 500) -> str:
    """Convert value into safe trimmed string."""
    if value is None:
        return ""
    text = str(value).strip()
    if len(text) > max_length:
        text = text[:max_length]
    return text


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert value to float."""
    try:
        if value is None:
            return default
        result = float(value)
        if math.isnan(result) or math.isinf(result):
            return default
        return result
    except Exception:
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    """Safely convert value to int."""
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def _clamp(value: float, minimum: float, maximum: float) -> float:
    """Clamp a float value."""
    return max(minimum, min(maximum, value))


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class GestureTriggerAction(str, Enum):
    """
    Supported Master Agent / Router actions for this file.
    """

    PROCESS_AUDIO_FRAME = "process_audio_frame"
    PROCESS_MOTION_FRAME = "process_motion_frame"
    PROCESS_CAMERA_GESTURE = "process_camera_gesture"
    PROCESS_SMART_GLASSES_EVENT = "process_smart_glasses_event"
    REGISTER_TRIGGER_RULE = "register_trigger_rule"
    UPDATE_TRIGGER_RULE = "update_trigger_rule"
    DELETE_TRIGGER_RULE = "delete_trigger_rule"
    LIST_TRIGGER_RULES = "list_trigger_rules"
    GET_TRIGGER_RULE = "get_trigger_rule"
    ENABLE_TRIGGER = "enable_trigger"
    DISABLE_TRIGGER = "disable_trigger"
    RESET_SESSION = "reset_session"
    GET_SESSION_STATE = "get_session_state"
    GET_RECENT_EVENTS = "get_recent_events"
    HEALTH_CHECK = "health_check"


class TriggerType(str, Enum):
    """
    Supported trigger types.
    """

    CLAP = "clap"
    DOUBLE_CLAP = "double_clap"
    TAP = "tap"
    DOUBLE_TAP = "double_tap"
    SMART_GLASSES_TAP = "smart_glasses_tap"
    SMART_GLASSES_BUTTON = "smart_glasses_button"
    SMART_GLASSES_HEAD_NOD = "smart_glasses_head_nod"
    SMART_GLASSES_HEAD_SHAKE = "smart_glasses_head_shake"
    HAND_RAISE = "hand_raise"
    HAND_WAVE = "hand_wave"
    PALM_OPEN = "palm_open"
    FIST = "fist"
    PINCH = "pinch"
    THUMBS_UP = "thumbs_up"
    CUSTOM = "custom"


class TriggerSource(str, Enum):
    """
    Supported input sources.
    """

    MICROPHONE = "microphone"
    DEVICE_MOTION = "device_motion"
    CAMERA = "camera"
    SMART_GLASSES = "smart_glasses"
    API = "api"
    SIMULATED = "simulated"


class TriggerStatus(str, Enum):
    """
    Trigger rule status.
    """

    ENABLED = "enabled"
    DISABLED = "disabled"


class GestureConfidenceLevel(str, Enum):
    """
    Confidence labels for detected triggers.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TriggerRule:
    """
    A configurable trigger rule.

    This is scoped per user/workspace and can be controlled from dashboard/API.
    """

    trigger_id: str
    user_id: str
    workspace_id: str
    trigger_type: str
    source: str
    status: str
    command: str
    description: str
    threshold: float
    cooldown_ms: int
    required_count: int
    count_window_ms: int
    sensitivity: float
    created_at: str
    updated_at: str
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GestureEvent:
    """
    A detected or processed gesture event.

    This is dashboard/API/event-bus friendly.
    """

    event_id: str
    user_id: str
    workspace_id: str
    trigger_id: Optional[str]
    trigger_type: str
    source: str
    detected: bool
    confidence: float
    confidence_level: str
    command: Optional[str]
    message: str
    raw_summary: Dict[str, Any]
    created_at: str
    timestamp_ms: int


@dataclass
class GestureSessionState:
    """
    Runtime state for a user/workspace detection session.
    """

    user_id: str
    workspace_id: str
    last_triggered_at: Dict[str, int] = field(default_factory=dict)
    clap_peaks: List[int] = field(default_factory=list)
    tap_peaks: List[int] = field(default_factory=list)
    motion_history: List[Dict[str, Any]] = field(default_factory=list)
    camera_gesture_history: List[Dict[str, Any]] = field(default_factory=list)
    smart_glasses_history: List[Dict[str, Any]] = field(default_factory=list)
    event_count: int = 0
    last_event_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Main Class
# ---------------------------------------------------------------------------

class GestureTrigger(BaseAgent):
    """
    Detects clap, tap, smart glasses, and hand gesture triggers.

    Responsibilities:
        - Detect clap / double clap from audio frame summaries.
        - Detect tap / double tap from motion frames.
        - Detect smart glasses tap, button, nod, and shake events.
        - Detect hand gestures from camera/vision outputs.
        - Maintain per-user/per-workspace trigger rules.
        - Return safe Master Agent routing payloads.
        - Emit audit, memory, verification, and dashboard events.

    Expected input style:
        This class is designed to receive preprocessed summaries from audio,
        motion, smart glasses, or vision modules. It does not require heavy
        native dependencies and remains import-safe.

    Example audio frame:
        {
            "rms": 0.2,
            "peak": 0.91,
            "zcr": 0.35,
            "timestamp_ms": 123456789
        }

    Example motion frame:
        {
            "accel_x": 0.1,
            "accel_y": 0.2,
            "accel_z": 14.5,
            "gyro_x": 0.1,
            "gyro_y": 0.2,
            "gyro_z": 0.3,
            "timestamp_ms": 123456789
        }

    Example camera gesture:
        {
            "gesture": "hand_wave",
            "confidence": 0.88,
            "landmarks": [],
            "timestamp_ms": 123456789
        }

    Example smart glasses event:
        {
            "event_type": "tap",
            "side": "right",
            "confidence": 0.95,
            "timestamp_ms": 123456789
        }
    """

    AGENT_NAME = "GestureTrigger"
    AGENT_TYPE = "voice_agent_helper"
    VERSION = "1.0.0"

    SECURITY_REQUIRED_ACTIONS = {
        GestureTriggerAction.REGISTER_TRIGGER_RULE.value,
        GestureTriggerAction.UPDATE_TRIGGER_RULE.value,
        GestureTriggerAction.DELETE_TRIGGER_RULE.value,
        GestureTriggerAction.ENABLE_TRIGGER.value,
        GestureTriggerAction.DISABLE_TRIGGER.value,
        GestureTriggerAction.RESET_SESSION.value,
    }

    SAFE_READ_ACTIONS = {
        GestureTriggerAction.LIST_TRIGGER_RULES.value,
        GestureTriggerAction.GET_TRIGGER_RULE.value,
        GestureTriggerAction.GET_SESSION_STATE.value,
        GestureTriggerAction.GET_RECENT_EVENTS.value,
        GestureTriggerAction.HEALTH_CHECK.value,
    }

    DEFAULT_MAX_EVENTS = 1000
    DEFAULT_MAX_HISTORY = 120

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        master_agent_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
        agent_name: str = AGENT_NAME,
        agent_id: str = "gesture_trigger",
        **kwargs: Any,
    ) -> None:
        """
        Initialize GestureTrigger.

        Args:
            security_agent:
                Optional Security Agent instance.

            memory_agent:
                Optional Memory Agent instance.

            verification_agent:
                Optional Verification Agent instance.

            event_bus:
                Optional dashboard/event bus emitter.

            audit_logger:
                Optional audit logger.

            master_agent_callback:
                Optional callback that receives safe trigger routing payloads.
                This file never directly performs sensitive actions.
        """
        super().__init__(agent_name=agent_name, agent_id=agent_id, **kwargs)

        self.agent_name = agent_name
        self.agent_id = agent_id

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self.master_agent_callback = master_agent_callback

        self._lock = threading.RLock()
        self._rules: Dict[str, TriggerRule] = {}
        self._sessions: Dict[str, GestureSessionState] = {}
        self._events: List[GestureEvent] = []

        self._install_default_rules_enabled = True

    # -----------------------------------------------------------------------
    # Master Agent / Router compatible method
    # -----------------------------------------------------------------------

    def run(
        self,
        action: str,
        context: Dict[str, Any],
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Main router-compatible execution method.
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
            if action == GestureTriggerAction.PROCESS_AUDIO_FRAME.value:
                return self.process_audio_frame(context=context, frame=payload)

            if action == GestureTriggerAction.PROCESS_MOTION_FRAME.value:
                return self.process_motion_frame(context=context, frame=payload)

            if action == GestureTriggerAction.PROCESS_CAMERA_GESTURE.value:
                return self.process_camera_gesture(context=context, frame=payload)

            if action == GestureTriggerAction.PROCESS_SMART_GLASSES_EVENT.value:
                return self.process_smart_glasses_event(context=context, event=payload)

            if action == GestureTriggerAction.REGISTER_TRIGGER_RULE.value:
                return self.register_trigger_rule(context=context, **payload)

            if action == GestureTriggerAction.UPDATE_TRIGGER_RULE.value:
                return self.update_trigger_rule(context=context, **payload)

            if action == GestureTriggerAction.DELETE_TRIGGER_RULE.value:
                return self.delete_trigger_rule(context=context, **payload)

            if action == GestureTriggerAction.LIST_TRIGGER_RULES.value:
                return self.list_trigger_rules(context=context, **payload)

            if action == GestureTriggerAction.GET_TRIGGER_RULE.value:
                return self.get_trigger_rule(context=context, **payload)

            if action == GestureTriggerAction.ENABLE_TRIGGER.value:
                return self.enable_trigger(context=context, **payload)

            if action == GestureTriggerAction.DISABLE_TRIGGER.value:
                return self.disable_trigger(context=context, **payload)

            if action == GestureTriggerAction.RESET_SESSION.value:
                return self.reset_session(context=context)

            if action == GestureTriggerAction.GET_SESSION_STATE.value:
                return self.get_session_state(context=context)

            if action == GestureTriggerAction.GET_RECENT_EVENTS.value:
                return self.get_recent_events(context=context, **payload)

            if action == GestureTriggerAction.HEALTH_CHECK.value:
                return self.health_check()

            return self._error_result(
                message=f"Unsupported gesture trigger action: {action}",
                error="UNSUPPORTED_ACTION",
                metadata={"action": action},
            )

        except Exception as exc:
            logger.exception("GestureTrigger run() failed.")
            return self._error_result(
                message="GestureTrigger action failed.",
                error=str(exc),
                metadata={"action": action},
            )

    # -----------------------------------------------------------------------
    # Frame processing methods
    # -----------------------------------------------------------------------

    def process_audio_frame(
        self,
        context: Dict[str, Any],
        frame: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Process microphone/audio summary frame to detect clap/double clap.

        This method expects lightweight audio features, not raw audio bytes.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        frame = self._sanitize_metadata(frame or {})
        session = self._get_session(context)

        timestamp_ms = _safe_int(frame.get("timestamp_ms"), _now_ms())
        peak = _safe_float(frame.get("peak"), 0.0)
        rms = _safe_float(frame.get("rms"), 0.0)
        zcr = _safe_float(frame.get("zcr"), 0.0)

        self._ensure_default_rules(context)

        detected_events: List[GestureEvent] = []

        clap_score = self._calculate_clap_score(peak=peak, rms=rms, zcr=zcr)

        clap_rules = self._find_rules(
            context=context,
            source=TriggerSource.MICROPHONE.value,
            trigger_types=[
                TriggerType.CLAP.value,
                TriggerType.DOUBLE_CLAP.value,
            ],
            enabled_only=True,
        )

        for rule in clap_rules:
            if clap_score < rule.threshold:
                continue

            if not self._cooldown_ready(session, rule, timestamp_ms):
                continue

            if rule.trigger_type == TriggerType.CLAP.value:
                event = self._create_detected_event(
                    context=context,
                    rule=rule,
                    source=TriggerSource.MICROPHONE.value,
                    trigger_type=TriggerType.CLAP.value,
                    confidence=clap_score,
                    raw_summary={
                        "peak": peak,
                        "rms": rms,
                        "zcr": zcr,
                        "score": clap_score,
                    },
                    timestamp_ms=timestamp_ms,
                    message="Clap trigger detected.",
                )
                detected_events.append(event)
                self._mark_triggered(session, rule, timestamp_ms)

            elif rule.trigger_type == TriggerType.DOUBLE_CLAP.value:
                session.clap_peaks.append(timestamp_ms)
                session.clap_peaks = self._trim_timestamps(
                    timestamps=session.clap_peaks,
                    timestamp_ms=timestamp_ms,
                    window_ms=rule.count_window_ms,
                )

                if len(session.clap_peaks) >= max(2, rule.required_count):
                    event = self._create_detected_event(
                        context=context,
                        rule=rule,
                        source=TriggerSource.MICROPHONE.value,
                        trigger_type=TriggerType.DOUBLE_CLAP.value,
                        confidence=clap_score,
                        raw_summary={
                            "peak": peak,
                            "rms": rms,
                            "zcr": zcr,
                            "score": clap_score,
                            "count": len(session.clap_peaks),
                            "window_ms": rule.count_window_ms,
                        },
                        timestamp_ms=timestamp_ms,
                        message="Double clap trigger detected.",
                    )
                    detected_events.append(event)
                    session.clap_peaks.clear()
                    self._mark_triggered(session, rule, timestamp_ms)

        return self._process_detection_response(
            context=context,
            source=TriggerSource.MICROPHONE.value,
            detected_events=detected_events,
            frame_summary={
                "peak": peak,
                "rms": rms,
                "zcr": zcr,
                "clap_score": clap_score,
            },
        )

    def process_motion_frame(
        self,
        context: Dict[str, Any],
        frame: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Process device motion frame to detect tap/double tap.

        Works for phone, watch, wearable, or motion-capable device streams.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        frame = self._sanitize_metadata(frame or {})
        session = self._get_session(context)

        timestamp_ms = _safe_int(frame.get("timestamp_ms"), _now_ms())

        accel_x = _safe_float(frame.get("accel_x"), 0.0)
        accel_y = _safe_float(frame.get("accel_y"), 0.0)
        accel_z = _safe_float(frame.get("accel_z"), 0.0)
        gyro_x = _safe_float(frame.get("gyro_x"), 0.0)
        gyro_y = _safe_float(frame.get("gyro_y"), 0.0)
        gyro_z = _safe_float(frame.get("gyro_z"), 0.0)

        magnitude = math.sqrt((accel_x ** 2) + (accel_y ** 2) + (accel_z ** 2))
        gyro_magnitude = math.sqrt((gyro_x ** 2) + (gyro_y ** 2) + (gyro_z ** 2))

        motion_summary = {
            "timestamp_ms": timestamp_ms,
            "accel_magnitude": magnitude,
            "gyro_magnitude": gyro_magnitude,
        }

        session.motion_history.append(motion_summary)
        session.motion_history = session.motion_history[-self.DEFAULT_MAX_HISTORY:]

        self._ensure_default_rules(context)

        tap_score = self._calculate_tap_score(
            accel_magnitude=magnitude,
            gyro_magnitude=gyro_magnitude,
        )

        detected_events: List[GestureEvent] = []

        tap_rules = self._find_rules(
            context=context,
            source=TriggerSource.DEVICE_MOTION.value,
            trigger_types=[
                TriggerType.TAP.value,
                TriggerType.DOUBLE_TAP.value,
            ],
            enabled_only=True,
        )

        for rule in tap_rules:
            if tap_score < rule.threshold:
                continue

            if not self._cooldown_ready(session, rule, timestamp_ms):
                continue

            if rule.trigger_type == TriggerType.TAP.value:
                event = self._create_detected_event(
                    context=context,
                    rule=rule,
                    source=TriggerSource.DEVICE_MOTION.value,
                    trigger_type=TriggerType.TAP.value,
                    confidence=tap_score,
                    raw_summary={
                        "accel_magnitude": magnitude,
                        "gyro_magnitude": gyro_magnitude,
                        "score": tap_score,
                    },
                    timestamp_ms=timestamp_ms,
                    message="Tap trigger detected.",
                )
                detected_events.append(event)
                self._mark_triggered(session, rule, timestamp_ms)

            elif rule.trigger_type == TriggerType.DOUBLE_TAP.value:
                session.tap_peaks.append(timestamp_ms)
                session.tap_peaks = self._trim_timestamps(
                    timestamps=session.tap_peaks,
                    timestamp_ms=timestamp_ms,
                    window_ms=rule.count_window_ms,
                )

                if len(session.tap_peaks) >= max(2, rule.required_count):
                    event = self._create_detected_event(
                        context=context,
                        rule=rule,
                        source=TriggerSource.DEVICE_MOTION.value,
                        trigger_type=TriggerType.DOUBLE_TAP.value,
                        confidence=tap_score,
                        raw_summary={
                            "accel_magnitude": magnitude,
                            "gyro_magnitude": gyro_magnitude,
                            "score": tap_score,
                            "count": len(session.tap_peaks),
                            "window_ms": rule.count_window_ms,
                        },
                        timestamp_ms=timestamp_ms,
                        message="Double tap trigger detected.",
                    )
                    detected_events.append(event)
                    session.tap_peaks.clear()
                    self._mark_triggered(session, rule, timestamp_ms)

        return self._process_detection_response(
            context=context,
            source=TriggerSource.DEVICE_MOTION.value,
            detected_events=detected_events,
            frame_summary={
                "accel_magnitude": magnitude,
                "gyro_magnitude": gyro_magnitude,
                "tap_score": tap_score,
            },
        )

    def process_camera_gesture(
        self,
        context: Dict[str, Any],
        frame: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Process pre-detected camera/vision gesture output.

        This file does not do heavy computer vision by itself. It accepts
        safe gesture labels from Visual Agent, MediaPipe, OpenCV, mobile camera
        worker, smart glasses camera, or dashboard API.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        frame = self._sanitize_metadata(frame or {})
        session = self._get_session(context)

        timestamp_ms = _safe_int(frame.get("timestamp_ms"), _now_ms())
        gesture_label = _safe_text(frame.get("gesture") or frame.get("gesture_type"), 100)
        confidence = _clamp(_safe_float(frame.get("confidence"), 0.0), 0.0, 1.0)

        session.camera_gesture_history.append(
            {
                "timestamp_ms": timestamp_ms,
                "gesture": gesture_label,
                "confidence": confidence,
            }
        )
        session.camera_gesture_history = session.camera_gesture_history[-self.DEFAULT_MAX_HISTORY:]

        self._ensure_default_rules(context)

        detected_events: List[GestureEvent] = []

        if not gesture_label:
            return self._process_detection_response(
                context=context,
                source=TriggerSource.CAMERA.value,
                detected_events=[],
                frame_summary={
                    "gesture": None,
                    "confidence": confidence,
                    "reason": "missing_gesture_label",
                },
            )

        camera_rules = self._find_rules(
            context=context,
            source=TriggerSource.CAMERA.value,
            trigger_types=[gesture_label],
            enabled_only=True,
        )

        for rule in camera_rules:
            adjusted_confidence = _clamp(confidence * rule.sensitivity, 0.0, 1.0)

            if adjusted_confidence < rule.threshold:
                continue

            if not self._cooldown_ready(session, rule, timestamp_ms):
                continue

            event = self._create_detected_event(
                context=context,
                rule=rule,
                source=TriggerSource.CAMERA.value,
                trigger_type=gesture_label,
                confidence=adjusted_confidence,
                raw_summary={
                    "gesture": gesture_label,
                    "input_confidence": confidence,
                    "adjusted_confidence": adjusted_confidence,
                },
                timestamp_ms=timestamp_ms,
                message=f"Camera gesture detected: {gesture_label}",
            )
            detected_events.append(event)
            self._mark_triggered(session, rule, timestamp_ms)

        return self._process_detection_response(
            context=context,
            source=TriggerSource.CAMERA.value,
            detected_events=detected_events,
            frame_summary={
                "gesture": gesture_label,
                "confidence": confidence,
            },
        )

    def process_smart_glasses_event(
        self,
        context: Dict[str, Any],
        event: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Process smart glasses event.

        Supported examples:
            - tap
            - button
            - head_nod
            - head_shake

        This supports future AR glasses, wearable SDKs, Bluetooth devices,
        and mobile companion apps.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        event = self._sanitize_metadata(event or {})
        session = self._get_session(context)

        timestamp_ms = _safe_int(event.get("timestamp_ms"), _now_ms())
        event_type = _safe_text(event.get("event_type") or event.get("type"), 100)
        confidence = _clamp(_safe_float(event.get("confidence"), 1.0), 0.0, 1.0)

        normalized_type = self._normalize_smart_glasses_type(event_type)

        session.smart_glasses_history.append(
            {
                "timestamp_ms": timestamp_ms,
                "event_type": normalized_type,
                "confidence": confidence,
                "device": _safe_text(event.get("device"), 100),
            }
        )
        session.smart_glasses_history = session.smart_glasses_history[-self.DEFAULT_MAX_HISTORY:]

        self._ensure_default_rules(context)

        detected_events: List[GestureEvent] = []

        if not normalized_type:
            return self._process_detection_response(
                context=context,
                source=TriggerSource.SMART_GLASSES.value,
                detected_events=[],
                frame_summary={
                    "event_type": event_type,
                    "normalized_type": None,
                    "confidence": confidence,
                    "reason": "unsupported_smart_glasses_event",
                },
            )

        rules = self._find_rules(
            context=context,
            source=TriggerSource.SMART_GLASSES.value,
            trigger_types=[normalized_type],
            enabled_only=True,
        )

        for rule in rules:
            adjusted_confidence = _clamp(confidence * rule.sensitivity, 0.0, 1.0)

            if adjusted_confidence < rule.threshold:
                continue

            if not self._cooldown_ready(session, rule, timestamp_ms):
                continue

            detected_event = self._create_detected_event(
                context=context,
                rule=rule,
                source=TriggerSource.SMART_GLASSES.value,
                trigger_type=normalized_type,
                confidence=adjusted_confidence,
                raw_summary={
                    "event_type": event_type,
                    "normalized_type": normalized_type,
                    "input_confidence": confidence,
                    "adjusted_confidence": adjusted_confidence,
                    "device": _safe_text(event.get("device"), 100),
                    "side": _safe_text(event.get("side"), 50),
                },
                timestamp_ms=timestamp_ms,
                message=f"Smart glasses trigger detected: {normalized_type}",
            )
            detected_events.append(detected_event)
            self._mark_triggered(session, rule, timestamp_ms)

        return self._process_detection_response(
            context=context,
            source=TriggerSource.SMART_GLASSES.value,
            detected_events=detected_events,
            frame_summary={
                "event_type": event_type,
                "normalized_type": normalized_type,
                "confidence": confidence,
            },
        )

    # -----------------------------------------------------------------------
    # Trigger rule management
    # -----------------------------------------------------------------------

    def register_trigger_rule(
        self,
        context: Dict[str, Any],
        trigger_type: str,
        source: str,
        command: str,
        description: str = "",
        threshold: float = 0.75,
        cooldown_ms: int = 1500,
        required_count: int = 1,
        count_window_ms: int = 700,
        sensitivity: float = 1.0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register a new trigger rule for a user/workspace.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        trigger_type_clean = _safe_text(trigger_type, 100)
        source_clean = _safe_text(source, 100)
        command_clean = _safe_text(command, 200)

        if not trigger_type_clean:
            return self._error_result(
                message="trigger_type is required.",
                error="TRIGGER_TYPE_REQUIRED",
            )

        if source_clean not in {item.value for item in TriggerSource}:
            return self._error_result(
                message="Invalid trigger source.",
                error="INVALID_TRIGGER_SOURCE",
                metadata={"allowed_sources": [item.value for item in TriggerSource]},
            )

        if not command_clean:
            return self._error_result(
                message="command is required.",
                error="COMMAND_REQUIRED",
            )

        now = _utc_now()
        trigger_id = f"trg_{uuid.uuid4().hex}"

        rule = TriggerRule(
            trigger_id=trigger_id,
            user_id=self._context_user_id(context),
            workspace_id=self._context_workspace_id(context),
            trigger_type=trigger_type_clean,
            source=source_clean,
            status=TriggerStatus.ENABLED.value,
            command=command_clean,
            description=_safe_text(description, 500),
            threshold=_clamp(_safe_float(threshold, 0.75), 0.0, 1.0),
            cooldown_ms=max(0, _safe_int(cooldown_ms, 1500)),
            required_count=max(1, _safe_int(required_count, 1)),
            count_window_ms=max(100, _safe_int(count_window_ms, 700)),
            sensitivity=_clamp(_safe_float(sensitivity, 1.0), 0.1, 3.0),
            created_at=now,
            updated_at=now,
            created_by=self._context_user_id(context),
            updated_by=self._context_user_id(context),
            metadata=self._sanitize_metadata(metadata or {}),
        )

        with self._lock:
            self._rules[trigger_id] = rule

        self._log_audit_event(
            action=GestureTriggerAction.REGISTER_TRIGGER_RULE.value,
            context=context,
            trigger_id=trigger_id,
            success=True,
            details={
                "trigger_type": rule.trigger_type,
                "source": rule.source,
                "command": rule.command,
            },
        )

        self._emit_agent_event(
            event_type="trigger_rule_registered",
            context=context,
            trigger_id=trigger_id,
            trigger_type=rule.trigger_type,
            source=rule.source,
            detected=False,
            confidence=1.0,
            command=rule.command,
            message="Trigger rule registered.",
            raw_summary={"rule": asdict(rule)},
        )

        return self._safe_result(
            message="Trigger rule registered successfully.",
            data={
                "rule": asdict(rule),
                "verification_payload": self._prepare_verification_payload(
                    action=GestureTriggerAction.REGISTER_TRIGGER_RULE.value,
                    context=context,
                    result_data={"trigger_id": trigger_id},
                ),
                "memory_payload": self._prepare_memory_payload(
                    action=GestureTriggerAction.REGISTER_TRIGGER_RULE.value,
                    context=context,
                    summary=f"Registered gesture trigger rule: {rule.trigger_type} -> {rule.command}",
                    data={"trigger_id": trigger_id},
                ),
            },
            metadata={"agent": self.agent_name, "action": GestureTriggerAction.REGISTER_TRIGGER_RULE.value},
        )

    def update_trigger_rule(
        self,
        context: Dict[str, Any],
        trigger_id: str,
        **updates: Any,
    ) -> Dict[str, Any]:
        """
        Update an existing trigger rule.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        with self._lock:
            rule = self._get_owned_rule_or_error(context, trigger_id)
            if isinstance(rule, dict):
                return rule

            allowed_fields = {
                "trigger_type",
                "source",
                "command",
                "description",
                "threshold",
                "cooldown_ms",
                "required_count",
                "count_window_ms",
                "sensitivity",
                "metadata",
            }

            changed: Dict[str, Any] = {}

            for key, value in updates.items():
                if key not in allowed_fields:
                    continue

                if key == "trigger_type":
                    cleaned = _safe_text(value, 100)
                    if cleaned:
                        rule.trigger_type = cleaned
                        changed[key] = cleaned

                elif key == "source":
                    cleaned = _safe_text(value, 100)
                    if cleaned in {item.value for item in TriggerSource}:
                        rule.source = cleaned
                        changed[key] = cleaned

                elif key == "command":
                    cleaned = _safe_text(value, 200)
                    if cleaned:
                        rule.command = cleaned
                        changed[key] = cleaned

                elif key == "description":
                    cleaned = _safe_text(value, 500)
                    rule.description = cleaned
                    changed[key] = cleaned

                elif key == "threshold":
                    cleaned = _clamp(_safe_float(value, rule.threshold), 0.0, 1.0)
                    rule.threshold = cleaned
                    changed[key] = cleaned

                elif key == "cooldown_ms":
                    cleaned = max(0, _safe_int(value, rule.cooldown_ms))
                    rule.cooldown_ms = cleaned
                    changed[key] = cleaned

                elif key == "required_count":
                    cleaned = max(1, _safe_int(value, rule.required_count))
                    rule.required_count = cleaned
                    changed[key] = cleaned

                elif key == "count_window_ms":
                    cleaned = max(100, _safe_int(value, rule.count_window_ms))
                    rule.count_window_ms = cleaned
                    changed[key] = cleaned

                elif key == "sensitivity":
                    cleaned = _clamp(_safe_float(value, rule.sensitivity), 0.1, 3.0)
                    rule.sensitivity = cleaned
                    changed[key] = cleaned

                elif key == "metadata":
                    cleaned = self._sanitize_metadata(value or {})
                    rule.metadata = cleaned
                    changed[key] = cleaned

            rule.updated_at = _utc_now()
            rule.updated_by = self._context_user_id(context)

        self._log_audit_event(
            action=GestureTriggerAction.UPDATE_TRIGGER_RULE.value,
            context=context,
            trigger_id=trigger_id,
            success=True,
            details={"changed": changed},
        )

        return self._safe_result(
            message="Trigger rule updated successfully.",
            data={"rule": asdict(rule), "changed": changed},
            metadata={"agent": self.agent_name, "action": GestureTriggerAction.UPDATE_TRIGGER_RULE.value},
        )

    def delete_trigger_rule(
        self,
        context: Dict[str, Any],
        trigger_id: str,
    ) -> Dict[str, Any]:
        """
        Delete trigger rule from current user/workspace.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        with self._lock:
            rule = self._get_owned_rule_or_error(context, trigger_id)
            if isinstance(rule, dict):
                return rule

            deleted = asdict(rule)
            del self._rules[rule.trigger_id]

        self._log_audit_event(
            action=GestureTriggerAction.DELETE_TRIGGER_RULE.value,
            context=context,
            trigger_id=trigger_id,
            success=True,
            details={"deleted": deleted},
        )

        return self._safe_result(
            message="Trigger rule deleted successfully.",
            data={"deleted_rule": deleted},
            metadata={"agent": self.agent_name, "action": GestureTriggerAction.DELETE_TRIGGER_RULE.value},
        )

    def list_trigger_rules(
        self,
        context: Dict[str, Any],
        source: Optional[str] = None,
        trigger_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List trigger rules scoped by user/workspace.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        self._ensure_default_rules(context)

        user_id = self._context_user_id(context)
        workspace_id = self._context_workspace_id(context)

        source_clean = _safe_text(source, 100) or None
        trigger_type_clean = _safe_text(trigger_type, 100) or None
        status_clean = _safe_text(status, 100) or None

        with self._lock:
            rules = []
            for rule in self._rules.values():
                if rule.user_id != user_id or rule.workspace_id != workspace_id:
                    continue

                if source_clean and rule.source != source_clean:
                    continue

                if trigger_type_clean and rule.trigger_type != trigger_type_clean:
                    continue

                if status_clean and rule.status != status_clean:
                    continue

                rules.append(rule)

            rules.sort(key=lambda item: item.created_at)

        return self._safe_result(
            message="Trigger rules loaded successfully.",
            data={
                "rules": [asdict(rule) for rule in rules],
                "count": len(rules),
            },
            metadata={"agent": self.agent_name, "action": GestureTriggerAction.LIST_TRIGGER_RULES.value},
        )

    def get_trigger_rule(
        self,
        context: Dict[str, Any],
        trigger_id: str,
    ) -> Dict[str, Any]:
        """
        Get one trigger rule.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        with self._lock:
            rule = self._get_owned_rule_or_error(context, trigger_id)
            if isinstance(rule, dict):
                return rule

        return self._safe_result(
            message="Trigger rule loaded successfully.",
            data={"rule": asdict(rule)},
            metadata={"agent": self.agent_name, "action": GestureTriggerAction.GET_TRIGGER_RULE.value},
        )

    def enable_trigger(
        self,
        context: Dict[str, Any],
        trigger_id: str,
    ) -> Dict[str, Any]:
        """
        Enable a trigger rule.
        """
        return self._set_trigger_status(
            context=context,
            trigger_id=trigger_id,
            status=TriggerStatus.ENABLED.value,
            action=GestureTriggerAction.ENABLE_TRIGGER.value,
        )

    def disable_trigger(
        self,
        context: Dict[str, Any],
        trigger_id: str,
    ) -> Dict[str, Any]:
        """
        Disable a trigger rule.
        """
        return self._set_trigger_status(
            context=context,
            trigger_id=trigger_id,
            status=TriggerStatus.DISABLED.value,
            action=GestureTriggerAction.DISABLE_TRIGGER.value,
        )

    # -----------------------------------------------------------------------
    # Session and event methods
    # -----------------------------------------------------------------------

    def reset_session(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Reset detection runtime state for current user/workspace.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        key = self._session_key(context)

        with self._lock:
            self._sessions[key] = GestureSessionState(
                user_id=self._context_user_id(context),
                workspace_id=self._context_workspace_id(context),
            )

        self._log_audit_event(
            action=GestureTriggerAction.RESET_SESSION.value,
            context=context,
            trigger_id=None,
            success=True,
            details={"session_key": key},
        )

        return self._safe_result(
            message="Gesture trigger session reset successfully.",
            data={"session_key": key},
            metadata={"agent": self.agent_name, "action": GestureTriggerAction.RESET_SESSION.value},
        )

    def get_session_state(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return safe session state.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        session = self._get_session(context)

        return self._safe_result(
            message="Gesture trigger session state loaded.",
            data={"session": asdict(session)},
            metadata={"agent": self.agent_name, "action": GestureTriggerAction.GET_SESSION_STATE.value},
        )

    def get_recent_events(
        self,
        context: Dict[str, Any],
        limit: int = 50,
    ) -> Dict[str, Any]:
        """
        Return recent gesture events for current user/workspace.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        user_id = self._context_user_id(context)
        workspace_id = self._context_workspace_id(context)
        limit = max(1, min(_safe_int(limit, 50), 200))

        with self._lock:
            events = [
                event for event in self._events
                if event.user_id == user_id and event.workspace_id == workspace_id
            ][-limit:]

        return self._safe_result(
            message="Recent gesture trigger events loaded.",
            data={"events": [asdict(event) for event in events], "count": len(events)},
            metadata={"agent": self.agent_name, "action": GestureTriggerAction.GET_RECENT_EVENTS.value},
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Dashboard/API health check.
        """
        with self._lock:
            rule_count = len(self._rules)
            session_count = len(self._sessions)
            event_count = len(self._events)

        return self._safe_result(
            message="GestureTrigger is healthy.",
            data={
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.VERSION,
                "rule_count": rule_count,
                "session_count": session_count,
                "event_count": event_count,
                "supported_sources": [item.value for item in TriggerSource],
                "supported_trigger_types": [item.value for item in TriggerType],
            },
            metadata={"agent": self.agent_name},
        )

    # -----------------------------------------------------------------------
    # Required architecture hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate required SaaS context.

        Every user-specific operation must include:
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
                message="user_id is required for GestureTrigger operations.",
                error="USER_ID_REQUIRED",
            )

        if not workspace_id:
            return self._error_result(
                message="workspace_id is required for GestureTrigger operations.",
                error="WORKSPACE_ID_REQUIRED",
            )

        return self._safe_result(
            message="Context validated.",
            data={"user_id": user_id, "workspace_id": workspace_id},
            metadata={"agent": self.agent_name},
        )

    def _requires_security_check(self, action: str) -> bool:
        """
        Return True if action requires Security Agent approval.
        """
        return action in self.SECURITY_REQUIRED_ACTIONS

    def _request_security_approval(
        self,
        action: str,
        context: Dict[str, Any],
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent.

        Development fallback allows local safe metadata/rule operations while
        clearly marking fallback security mode.
        """
        approval_payload = {
            "approval_id": f"approval_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "action": action,
            "user_id": self._context_user_id(context),
            "workspace_id": self._context_workspace_id(context),
            "risk_level": self._security_risk_level(action),
            "resource_type": "gesture_trigger_rule_or_session",
            "payload_summary": self._summarize_payload(payload),
            "created_at": _utc_now(),
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
                logger.exception("Security approval failed.")
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
            "result_data": result_data or {},
            "checks": {
                "context_validated": True,
                "workspace_isolated": True,
                "structured_result": True,
                "no_direct_destructive_action": True,
                "safe_master_agent_payload_only": True,
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
        summary: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Stores only safe trigger preferences or operational summaries.
        """
        payload = {
            "memory_id": f"memory_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "action": action,
            "user_id": self._context_user_id(context),
            "workspace_id": self._context_workspace_id(context),
            "summary": _safe_text(summary, 500),
            "data": self._sanitize_metadata(data or {}),
            "safe_to_store": True,
            "contains_secret": False,
            "contains_biometric_identity": False,
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
        trigger_id: Optional[str],
        trigger_type: str,
        source: str,
        detected: bool,
        confidence: float,
        command: Optional[str],
        message: str,
        raw_summary: Optional[Dict[str, Any]] = None,
        timestamp_ms: Optional[int] = None,
    ) -> GestureEvent:
        """
        Emit/store a gesture event for dashboard/API/event bus.
        """
        event = GestureEvent(
            event_id=f"evt_{uuid.uuid4().hex}",
            user_id=self._context_user_id(context),
            workspace_id=self._context_workspace_id(context),
            trigger_id=trigger_id,
            trigger_type=_safe_text(trigger_type, 100),
            source=_safe_text(source, 100),
            detected=bool(detected),
            confidence=_clamp(confidence, 0.0, 1.0),
            confidence_level=self._confidence_level(confidence),
            command=_safe_text(command, 200) or None,
            message=_safe_text(message, 500),
            raw_summary=self._sanitize_metadata(raw_summary or {}),
            created_at=_utc_now(),
            timestamp_ms=timestamp_ms or _now_ms(),
        )

        with self._lock:
            self._events.append(event)
            self._events = self._events[-self.DEFAULT_MAX_EVENTS:]

            session = self._get_session(context)
            session.event_count += 1
            session.last_event_at = event.created_at

        if self.event_bus and hasattr(self.event_bus, "emit"):
            try:
                self.event_bus.emit(asdict(event))
            except Exception:
                logger.exception("GestureTrigger event bus emit failed.")

        return event

    def _log_audit_event(
        self,
        action: str,
        context: Dict[str, Any],
        trigger_id: Optional[str],
        success: bool,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event for sensitive trigger operations.
        """
        audit_payload = {
            "audit_id": f"audit_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "action": action,
            "user_id": self._context_user_id(context),
            "workspace_id": self._context_workspace_id(context),
            "trigger_id": trigger_id,
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
    # Internal detection helpers
    # -----------------------------------------------------------------------

    def _calculate_clap_score(self, peak: float, rms: float, zcr: float) -> float:
        """
        Calculate clap confidence score from audio features.

        Clap usually has:
            - high peak
            - moderate/high RMS
            - sharp transient
            - higher zero-crossing activity
        """
        peak_component = _clamp(peak, 0.0, 1.0) * 0.55
        rms_component = _clamp(rms * 2.0, 0.0, 1.0) * 0.25
        zcr_component = _clamp(zcr, 0.0, 1.0) * 0.20

        return _clamp(peak_component + rms_component + zcr_component, 0.0, 1.0)

    def _calculate_tap_score(
        self,
        accel_magnitude: float,
        gyro_magnitude: float,
    ) -> float:
        """
        Calculate tap confidence from motion features.

        Standard gravity is ~9.8m/s². A tap usually appears as a sudden spike.
        """
        gravity_delta = abs(accel_magnitude - 9.81)
        accel_component = _clamp(gravity_delta / 8.0, 0.0, 1.0) * 0.75
        gyro_component = _clamp(gyro_magnitude / 4.0, 0.0, 1.0) * 0.25

        return _clamp(accel_component + gyro_component, 0.0, 1.0)

    def _normalize_smart_glasses_type(self, event_type: str) -> Optional[str]:
        """
        Normalize smart glasses SDK event names.
        """
        value = _safe_text(event_type, 100).lower().replace("-", "_").replace(" ", "_")

        mapping = {
            "tap": TriggerType.SMART_GLASSES_TAP.value,
            "single_tap": TriggerType.SMART_GLASSES_TAP.value,
            "double_tap": TriggerType.SMART_GLASSES_TAP.value,
            "button": TriggerType.SMART_GLASSES_BUTTON.value,
            "button_press": TriggerType.SMART_GLASSES_BUTTON.value,
            "press": TriggerType.SMART_GLASSES_BUTTON.value,
            "head_nod": TriggerType.SMART_GLASSES_HEAD_NOD.value,
            "nod": TriggerType.SMART_GLASSES_HEAD_NOD.value,
            "yes": TriggerType.SMART_GLASSES_HEAD_NOD.value,
            "head_shake": TriggerType.SMART_GLASSES_HEAD_SHAKE.value,
            "shake": TriggerType.SMART_GLASSES_HEAD_SHAKE.value,
            "no": TriggerType.SMART_GLASSES_HEAD_SHAKE.value,
        }

        return mapping.get(value)

    def _confidence_level(self, confidence: float) -> str:
        """
        Convert confidence score into label.
        """
        confidence = _clamp(confidence, 0.0, 1.0)
        if confidence >= 0.85:
            return GestureConfidenceLevel.HIGH.value
        if confidence >= 0.60:
            return GestureConfidenceLevel.MEDIUM.value
        return GestureConfidenceLevel.LOW.value

    def _process_detection_response(
        self,
        context: Dict[str, Any],
        source: str,
        detected_events: List[GestureEvent],
        frame_summary: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Build standardized detection response and optionally notify Master Agent.
        """
        route_payloads = []

        for event in detected_events:
            payload = self._build_master_agent_payload(context=context, event=event)
            route_payloads.append(payload)

            if self.master_agent_callback:
                try:
                    self.master_agent_callback(payload)
                except Exception:
                    logger.exception("Master Agent callback failed.")

        return self._safe_result(
            message=(
                "Gesture trigger detected."
                if detected_events
                else "No gesture trigger detected."
            ),
            data={
                "detected": bool(detected_events),
                "source": source,
                "events": [asdict(event) for event in detected_events],
                "route_payloads": route_payloads,
                "frame_summary": self._sanitize_metadata(frame_summary),
                "verification_payload": self._prepare_verification_payload(
                    action=f"detect_from_{source}",
                    context=context,
                    result_data={
                        "detected": bool(detected_events),
                        "event_count": len(detected_events),
                        "source": source,
                    },
                ),
            },
            metadata={
                "agent": self.agent_name,
                "source": source,
                "event_count": len(detected_events),
            },
        )

    def _create_detected_event(
        self,
        context: Dict[str, Any],
        rule: TriggerRule,
        source: str,
        trigger_type: str,
        confidence: float,
        raw_summary: Dict[str, Any],
        timestamp_ms: int,
        message: str,
    ) -> GestureEvent:
        """
        Create and emit a detected gesture event.
        """
        return self._emit_agent_event(
            event_type="gesture_trigger_detected",
            context=context,
            trigger_id=rule.trigger_id,
            trigger_type=trigger_type,
            source=source,
            detected=True,
            confidence=confidence,
            command=rule.command,
            message=message,
            raw_summary=raw_summary,
            timestamp_ms=timestamp_ms,
        )

    def _build_master_agent_payload(
        self,
        context: Dict[str, Any],
        event: GestureEvent,
    ) -> Dict[str, Any]:
        """
        Prepare safe Master Agent routing payload.

        This file only recommends/requests routing. It does not execute the
        final command directly.
        """
        return {
            "route_id": f"route_{uuid.uuid4().hex}",
            "source_agent": self.agent_name,
            "target_agent": "MasterAgent",
            "user_id": self._context_user_id(context),
            "workspace_id": self._context_workspace_id(context),
            "trigger_event": asdict(event),
            "command": event.command,
            "requires_master_agent_decision": True,
            "requires_permission_check": True,
            "created_at": _utc_now(),
        }

    # -----------------------------------------------------------------------
    # Rule/session helpers
    # -----------------------------------------------------------------------

    def _ensure_default_rules(self, context: Dict[str, Any]) -> None:
        """
        Install default rules per user/workspace once.

        Default rules are safe routing commands, not direct actions.
        """
        if not self._install_default_rules_enabled:
            return

        user_id = self._context_user_id(context)
        workspace_id = self._context_workspace_id(context)

        with self._lock:
            existing = [
                rule for rule in self._rules.values()
                if rule.user_id == user_id and rule.workspace_id == workspace_id
            ]

            if existing:
                return

            now = _utc_now()

            defaults = [
                {
                    "trigger_type": TriggerType.CLAP.value,
                    "source": TriggerSource.MICROPHONE.value,
                    "command": "voice_agent.toggle_listening",
                    "description": "Single clap toggles listening mode.",
                    "threshold": 0.78,
                    "cooldown_ms": 1400,
                    "required_count": 1,
                    "count_window_ms": 700,
                    "sensitivity": 1.0,
                },
                {
                    "trigger_type": TriggerType.DOUBLE_CLAP.value,
                    "source": TriggerSource.MICROPHONE.value,
                    "command": "voice_agent.wake",
                    "description": "Double clap wakes William.",
                    "threshold": 0.76,
                    "cooldown_ms": 2200,
                    "required_count": 2,
                    "count_window_ms": 850,
                    "sensitivity": 1.0,
                },
                {
                    "trigger_type": TriggerType.TAP.value,
                    "source": TriggerSource.DEVICE_MOTION.value,
                    "command": "voice_agent.push_to_talk",
                    "description": "Device tap starts push-to-talk.",
                    "threshold": 0.72,
                    "cooldown_ms": 1200,
                    "required_count": 1,
                    "count_window_ms": 600,
                    "sensitivity": 1.0,
                },
                {
                    "trigger_type": TriggerType.DOUBLE_TAP.value,
                    "source": TriggerSource.DEVICE_MOTION.value,
                    "command": "voice_agent.stop_speaking",
                    "description": "Double tap interrupts speaking.",
                    "threshold": 0.70,
                    "cooldown_ms": 1500,
                    "required_count": 2,
                    "count_window_ms": 750,
                    "sensitivity": 1.0,
                },
                {
                    "trigger_type": TriggerType.HAND_RAISE.value,
                    "source": TriggerSource.CAMERA.value,
                    "command": "voice_agent.attention",
                    "description": "Raised hand requests attention.",
                    "threshold": 0.82,
                    "cooldown_ms": 1800,
                    "required_count": 1,
                    "count_window_ms": 700,
                    "sensitivity": 1.0,
                },
                {
                    "trigger_type": TriggerType.HAND_WAVE.value,
                    "source": TriggerSource.CAMERA.value,
                    "command": "voice_agent.wake",
                    "description": "Hand wave wakes William.",
                    "threshold": 0.80,
                    "cooldown_ms": 1800,
                    "required_count": 1,
                    "count_window_ms": 700,
                    "sensitivity": 1.0,
                },
                {
                    "trigger_type": TriggerType.PALM_OPEN.value,
                    "source": TriggerSource.CAMERA.value,
                    "command": "voice_agent.pause",
                    "description": "Open palm pauses voice output.",
                    "threshold": 0.82,
                    "cooldown_ms": 1800,
                    "required_count": 1,
                    "count_window_ms": 700,
                    "sensitivity": 1.0,
                },
                {
                    "trigger_type": TriggerType.FIST.value,
                    "source": TriggerSource.CAMERA.value,
                    "command": "voice_agent.stop",
                    "description": "Fist gesture stops current voice operation.",
                    "threshold": 0.84,
                    "cooldown_ms": 2000,
                    "required_count": 1,
                    "count_window_ms": 700,
                    "sensitivity": 1.0,
                },
                {
                    "trigger_type": TriggerType.SMART_GLASSES_TAP.value,
                    "source": TriggerSource.SMART_GLASSES.value,
                    "command": "voice_agent.push_to_talk",
                    "description": "Smart glasses tap starts push-to-talk.",
                    "threshold": 0.75,
                    "cooldown_ms": 1200,
                    "required_count": 1,
                    "count_window_ms": 600,
                    "sensitivity": 1.0,
                },
                {
                    "trigger_type": TriggerType.SMART_GLASSES_HEAD_NOD.value,
                    "source": TriggerSource.SMART_GLASSES.value,
                    "command": "voice_agent.confirm",
                    "description": "Head nod confirms pending action.",
                    "threshold": 0.75,
                    "cooldown_ms": 1400,
                    "required_count": 1,
                    "count_window_ms": 600,
                    "sensitivity": 1.0,
                },
                {
                    "trigger_type": TriggerType.SMART_GLASSES_HEAD_SHAKE.value,
                    "source": TriggerSource.SMART_GLASSES.value,
                    "command": "voice_agent.cancel",
                    "description": "Head shake cancels pending action.",
                    "threshold": 0.75,
                    "cooldown_ms": 1400,
                    "required_count": 1,
                    "count_window_ms": 600,
                    "sensitivity": 1.0,
                },
            ]

            for item in defaults:
                trigger_id = f"trg_{uuid.uuid4().hex}"
                self._rules[trigger_id] = TriggerRule(
                    trigger_id=trigger_id,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    trigger_type=item["trigger_type"],
                    source=item["source"],
                    status=TriggerStatus.ENABLED.value,
                    command=item["command"],
                    description=item["description"],
                    threshold=item["threshold"],
                    cooldown_ms=item["cooldown_ms"],
                    required_count=item["required_count"],
                    count_window_ms=item["count_window_ms"],
                    sensitivity=item["sensitivity"],
                    created_at=now,
                    updated_at=now,
                    created_by=user_id,
                    updated_by=user_id,
                    metadata={"default_rule": True},
                )

    def _find_rules(
        self,
        context: Dict[str, Any],
        source: str,
        trigger_types: List[str],
        enabled_only: bool = True,
    ) -> List[TriggerRule]:
        """
        Find matching rules for user/workspace/source/type.
        """
        user_id = self._context_user_id(context)
        workspace_id = self._context_workspace_id(context)
        trigger_type_set = set(trigger_types)

        with self._lock:
            rules = []
            for rule in self._rules.values():
                if rule.user_id != user_id or rule.workspace_id != workspace_id:
                    continue

                if rule.source != source:
                    continue

                if rule.trigger_type not in trigger_type_set:
                    continue

                if enabled_only and rule.status != TriggerStatus.ENABLED.value:
                    continue

                rules.append(rule)

        return rules

    def _get_owned_rule_or_error(
        self,
        context: Dict[str, Any],
        trigger_id: str,
    ) -> TriggerRule | Dict[str, Any]:
        """
        Fetch rule and enforce SaaS isolation.
        """
        trigger_id_clean = _safe_text(trigger_id, 120)

        if not trigger_id_clean:
            return self._error_result(
                message="trigger_id is required.",
                error="TRIGGER_ID_REQUIRED",
            )

        rule = self._rules.get(trigger_id_clean)
        if not rule:
            return self._error_result(
                message="Trigger rule not found.",
                error="TRIGGER_RULE_NOT_FOUND",
                metadata={"trigger_id": trigger_id_clean},
            )

        user_id = self._context_user_id(context)
        workspace_id = self._context_workspace_id(context)

        if rule.user_id != user_id or rule.workspace_id != workspace_id:
            self._log_audit_event(
                action="unauthorized_trigger_rule_access",
                context=context,
                trigger_id=trigger_id_clean,
                success=False,
                details={
                    "record_user_id": rule.user_id,
                    "record_workspace_id": rule.workspace_id,
                },
            )
            return self._error_result(
                message="Trigger rule not found in this user/workspace scope.",
                error="TRIGGER_SCOPE_DENIED",
                metadata={"trigger_id": trigger_id_clean},
            )

        return rule

    def _set_trigger_status(
        self,
        context: Dict[str, Any],
        trigger_id: str,
        status: str,
        action: str,
    ) -> Dict[str, Any]:
        """
        Enable/disable helper.
        """
        ctx = self._validate_task_context(context)
        if not ctx["success"]:
            return ctx

        with self._lock:
            rule = self._get_owned_rule_or_error(context, trigger_id)
            if isinstance(rule, dict):
                return rule

            rule.status = status
            rule.updated_at = _utc_now()
            rule.updated_by = self._context_user_id(context)

        self._log_audit_event(
            action=action,
            context=context,
            trigger_id=trigger_id,
            success=True,
            details={"status": status},
        )

        return self._safe_result(
            message=f"Trigger rule {status} successfully.",
            data={"rule": asdict(rule)},
            metadata={"agent": self.agent_name, "action": action},
        )

    def _session_key(self, context: Dict[str, Any]) -> str:
        """
        Build stable session key.
        """
        return f"{self._context_user_id(context)}::{self._context_workspace_id(context)}"

    def _get_session(self, context: Dict[str, Any]) -> GestureSessionState:
        """
        Get or create runtime session state.
        """
        key = self._session_key(context)

        with self._lock:
            if key not in self._sessions:
                self._sessions[key] = GestureSessionState(
                    user_id=self._context_user_id(context),
                    workspace_id=self._context_workspace_id(context),
                )

            return self._sessions[key]

    def _cooldown_ready(
        self,
        session: GestureSessionState,
        rule: TriggerRule,
        timestamp_ms: int,
    ) -> bool:
        """
        Check rule cooldown.
        """
        last = session.last_triggered_at.get(rule.trigger_id)
        if last is None:
            return True

        return (timestamp_ms - last) >= rule.cooldown_ms

    def _mark_triggered(
        self,
        session: GestureSessionState,
        rule: TriggerRule,
        timestamp_ms: int,
    ) -> None:
        """
        Mark rule triggered timestamp.
        """
        session.last_triggered_at[rule.trigger_id] = timestamp_ms

    def _trim_timestamps(
        self,
        timestamps: List[int],
        timestamp_ms: int,
        window_ms: int,
    ) -> List[int]:
        """
        Keep only timestamps inside count window.
        """
        cutoff = timestamp_ms - window_ms
        return [item for item in timestamps if item >= cutoff]

    # -----------------------------------------------------------------------
    # Sanitization and metadata helpers
    # -----------------------------------------------------------------------

    def _sanitize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize arbitrary metadata.

        Prevents accidental storage of secrets, huge data, raw images/audio,
        raw video frames, or sensitive blobs.
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
            "raw_image",
            "image_bytes",
            "raw_video",
            "video_bytes",
            "frame_bytes",
            "base64",
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
        Sanitize a nested value.
        """
        if value is None:
            return None

        if isinstance(value, (bool, int, float)):
            return value

        if isinstance(value, str):
            return _safe_text(value, 1000)

        if isinstance(value, list):
            return [self._sanitize_value(item) for item in value[:80]]

        if isinstance(value, dict):
            return self._sanitize_metadata(value)

        return _safe_text(value, 500)

    def _summarize_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Summarize payload for Security Agent approval.
        """
        clean = self._sanitize_metadata(payload or {})
        summary: Dict[str, Any] = {}

        for key, value in clean.items():
            if isinstance(value, str) and len(value) > 120:
                summary[key] = value[:120] + "..."
            else:
                summary[key] = value

        return summary

    def _security_risk_level(self, action: str) -> str:
        """
        Security risk mapping.
        """
        if action in {
            GestureTriggerAction.DELETE_TRIGGER_RULE.value,
            GestureTriggerAction.RESET_SESSION.value,
        }:
            return "medium"

        if action in {
            GestureTriggerAction.REGISTER_TRIGGER_RULE.value,
            GestureTriggerAction.UPDATE_TRIGGER_RULE.value,
            GestureTriggerAction.ENABLE_TRIGGER.value,
            GestureTriggerAction.DISABLE_TRIGGER.value,
        }:
            return "low"

        return "low"

    def _context_user_id(self, context: Dict[str, Any]) -> str:
        """Return normalized user_id."""
        return _safe_text(context.get("user_id"), 100)

    def _context_workspace_id(self, context: Dict[str, Any]) -> str:
        """Return normalized workspace_id."""
        return _safe_text(context.get("workspace_id"), 100)

    # -----------------------------------------------------------------------
    # Registry/dashboard compatibility
    # -----------------------------------------------------------------------

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Return Agent Registry / Dashboard compatible manifest.
        """
        return {
            "agent_name": self.agent_name,
            "agent_id": self.agent_id,
            "agent_type": self.AGENT_TYPE,
            "version": self.VERSION,
            "description": "Detects clap, tap, smart glasses, and hand gesture triggers.",
            "actions": [item.value for item in GestureTriggerAction],
            "supported_sources": [item.value for item in TriggerSource],
            "supported_trigger_types": [item.value for item in TriggerType],
            "security_required_actions": sorted(self.SECURITY_REQUIRED_ACTIONS),
            "safe_read_actions": sorted(self.SAFE_READ_ACTIONS),
            "requires_user_id": True,
            "requires_workspace_id": True,
            "directly_executes_sensitive_actions": False,
            "routes_to_master_agent": True,
            "supports_verification_payload": True,
            "supports_memory_payload": True,
            "supports_audit_log": True,
            "supports_dashboard_events": True,
        }


# ---------------------------------------------------------------------------
# Local smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    trigger = GestureTrigger()

    test_context = {
        "user_id": "user_demo_1",
        "workspace_id": "workspace_demo_1",
        "role": "owner",
    }

    print("\n--- Health Check ---")
    print(json.dumps(trigger.health_check(), indent=2))

    print("\n--- List Default Rules ---")
    print(json.dumps(trigger.list_trigger_rules(test_context), indent=2))

    print("\n--- Simulated Clap Frame ---")
    clap_result = trigger.process_audio_frame(
        context=test_context,
        frame={
            "peak": 0.95,
            "rms": 0.42,
            "zcr": 0.62,
            "timestamp_ms": _now_ms(),
        },
    )
    print(json.dumps(clap_result, indent=2))

    print("\n--- Simulated Tap Frame ---")
    tap_result = trigger.process_motion_frame(
        context=test_context,
        frame={
            "accel_x": 0.4,
            "accel_y": 0.2,
            "accel_z": 18.2,
            "gyro_x": 0.3,
            "gyro_y": 0.2,
            "gyro_z": 1.1,
            "timestamp_ms": _now_ms(),
        },
    )
    print(json.dumps(tap_result, indent=2))

    print("\n--- Simulated Camera Gesture ---")
    camera_result = trigger.process_camera_gesture(
        context=test_context,
        frame={
            "gesture": "hand_wave",
            "confidence": 0.91,
            "timestamp_ms": _now_ms(),
        },
    )
    print(json.dumps(camera_result, indent=2))

    print("\n--- Simulated Smart Glasses Event ---")
    glasses_result = trigger.process_smart_glasses_event(
        context=test_context,
        event={
            "event_type": "head_nod",
            "side": "right",
            "device": "demo_glasses",
            "confidence": 0.94,
            "timestamp_ms": _now_ms(),
        },
    )
    print(json.dumps(glasses_result, indent=2))

    print("\nFILE COMPLETE")