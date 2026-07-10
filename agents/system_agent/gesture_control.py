"""
agents/system_agent/gesture_control.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Hand/glass/tap/clap gestures mapped to safe system commands.

This module provides the GestureControl class for the System Agent. It handles:
    - Gesture registration
    - Gesture recognition from normalized events
    - Safe command mapping
    - Per-user/per-workspace gesture profiles
    - Gesture enable/disable rules
    - Security approval for sensitive commands
    - Verification payload preparation
    - Memory payload preparation
    - Audit logging
    - Dashboard/API-friendly structured responses

Important safety behavior:
    This file does NOT directly execute real system commands.
    It converts gestures into safe structured command requests that can be routed
    to Master Agent, System Agent, Router, or Security Agent.

Architecture compatibility:
    - BaseAgent compatible
    - Agent Registry compatible
    - Agent Loader compatible
    - Agent Router compatible
    - Master Agent compatible
    - Security Agent compatible
    - Memory Agent compatible
    - Verification Agent compatible
    - Dashboard/API ready
"""

from __future__ import annotations

import copy
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


# -------------------------------------------------------------------------
# Safe optional BaseAgent import
# -------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:
        """
        Fallback BaseAgent stub.

        This keeps gesture_control.py import-safe even if the real William/Jarvis
        BaseAgent file has not been created yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "system")
            self.logger = logging.getLogger(self.agent_name)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() called.",
                "data": {},
                "error": None,
                "metadata": {},
            }


# -------------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------------

logger = logging.getLogger("GestureControl")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# -------------------------------------------------------------------------
# Enums and constants
# -------------------------------------------------------------------------

class GestureSource(str, Enum):
    HAND = "hand"
    GLASSES = "glasses"
    TAP = "tap"
    CLAP = "clap"
    WATCH = "watch"
    PHONE = "phone"
    CAMERA = "camera"
    MICROPHONE = "microphone"
    UNKNOWN = "unknown"


class GestureType(str, Enum):
    HAND_OPEN = "hand_open"
    HAND_CLOSE = "hand_close"
    HAND_WAVE_LEFT = "hand_wave_left"
    HAND_WAVE_RIGHT = "hand_wave_right"
    HAND_POINT = "hand_point"
    HAND_THUMBS_UP = "hand_thumbs_up"
    HAND_THUMBS_DOWN = "hand_thumbs_down"
    HAND_PINCH = "hand_pinch"
    HAND_SWIPE_UP = "hand_swipe_up"
    HAND_SWIPE_DOWN = "hand_swipe_down"
    GLASSES_LOOK_LEFT = "glasses_look_left"
    GLASSES_LOOK_RIGHT = "glasses_look_right"
    GLASSES_LOOK_UP = "glasses_look_up"
    GLASSES_LOOK_DOWN = "glasses_look_down"
    GLASSES_BLINK_DOUBLE = "glasses_blink_double"
    TAP_SINGLE = "tap_single"
    TAP_DOUBLE = "tap_double"
    TAP_TRIPLE = "tap_triple"
    TAP_LONG = "tap_long"
    CLAP_SINGLE = "clap_single"
    CLAP_DOUBLE = "clap_double"
    CLAP_PATTERN = "clap_pattern"
    UNKNOWN = "unknown"


class GestureStatus(str, Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    BLOCKED = "blocked"


class CommandRisk(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKED = "blocked"


class CommandCategory(str, Enum):
    NAVIGATION = "navigation"
    NOTIFICATION = "notification"
    MEDIA = "media"
    DISPLAY = "display"
    WORKFLOW = "workflow"
    SYSTEM = "system"
    ACCESSIBILITY = "accessibility"
    DASHBOARD = "dashboard"
    UNKNOWN = "unknown"


DEFAULT_MAX_EVENT_LOG = 500
DEFAULT_MAX_AUDIT_LOG = 500
DEFAULT_MAX_HISTORY = 500
DEFAULT_CONFIDENCE_THRESHOLD = 0.60
DEFAULT_GESTURE_COOLDOWN_SECONDS = 0.40


SUPPORTED_SOURCES = {item.value for item in GestureSource}
SUPPORTED_GESTURE_TYPES = {item.value for item in GestureType}


SENSITIVE_COMMAND_KEYWORDS = {
    "delete",
    "remove",
    "shutdown",
    "restart",
    "reboot",
    "payment",
    "finance",
    "transfer",
    "send_message",
    "send_email",
    "call",
    "browser_submit",
    "install",
    "uninstall",
    "file_write",
    "file_delete",
    "permission",
    "security",
}


BLOCKED_COMMAND_KEYWORDS = {
    "format_disk",
    "wipe_device",
    "disable_security",
    "exfiltrate",
    "steal",
    "bypass",
    "malware",
    "credential_dump",
}


DEFAULT_GESTURE_COMMANDS = {
    GestureType.HAND_OPEN.value: {
        "command": "pause_current_task",
        "category": CommandCategory.WORKFLOW.value,
        "risk": CommandRisk.LOW.value,
        "description": "Pause the current active task safely.",
    },
    GestureType.HAND_CLOSE.value: {
        "command": "resume_current_task",
        "category": CommandCategory.WORKFLOW.value,
        "risk": CommandRisk.LOW.value,
        "description": "Resume the current paused task safely.",
    },
    GestureType.HAND_WAVE_LEFT.value: {
        "command": "navigate_previous",
        "category": CommandCategory.NAVIGATION.value,
        "risk": CommandRisk.SAFE.value,
        "description": "Move to the previous item or screen.",
    },
    GestureType.HAND_WAVE_RIGHT.value: {
        "command": "navigate_next",
        "category": CommandCategory.NAVIGATION.value,
        "risk": CommandRisk.SAFE.value,
        "description": "Move to the next item or screen.",
    },
    GestureType.HAND_POINT.value: {
        "command": "select_focused_item",
        "category": CommandCategory.ACCESSIBILITY.value,
        "risk": CommandRisk.LOW.value,
        "description": "Select the currently focused item.",
    },
    GestureType.HAND_THUMBS_UP.value: {
        "command": "confirm_safe_action",
        "category": CommandCategory.WORKFLOW.value,
        "risk": CommandRisk.MEDIUM.value,
        "description": "Confirm a safe pending action.",
    },
    GestureType.HAND_THUMBS_DOWN.value: {
        "command": "cancel_pending_action",
        "category": CommandCategory.WORKFLOW.value,
        "risk": CommandRisk.SAFE.value,
        "description": "Cancel the current pending action.",
    },
    GestureType.HAND_PINCH.value: {
        "command": "open_quick_actions",
        "category": CommandCategory.DASHBOARD.value,
        "risk": CommandRisk.SAFE.value,
        "description": "Open quick action menu.",
    },
    GestureType.HAND_SWIPE_UP.value: {
        "command": "scroll_up",
        "category": CommandCategory.NAVIGATION.value,
        "risk": CommandRisk.SAFE.value,
        "description": "Scroll up safely.",
    },
    GestureType.HAND_SWIPE_DOWN.value: {
        "command": "scroll_down",
        "category": CommandCategory.NAVIGATION.value,
        "risk": CommandRisk.SAFE.value,
        "description": "Scroll down safely.",
    },
    GestureType.GLASSES_LOOK_LEFT.value: {
        "command": "focus_previous_panel",
        "category": CommandCategory.DISPLAY.value,
        "risk": CommandRisk.SAFE.value,
        "description": "Focus previous AR/dashboard panel.",
    },
    GestureType.GLASSES_LOOK_RIGHT.value: {
        "command": "focus_next_panel",
        "category": CommandCategory.DISPLAY.value,
        "risk": CommandRisk.SAFE.value,
        "description": "Focus next AR/dashboard panel.",
    },
    GestureType.GLASSES_LOOK_UP.value: {
        "command": "show_status_overlay",
        "category": CommandCategory.DISPLAY.value,
        "risk": CommandRisk.SAFE.value,
        "description": "Show system status overlay.",
    },
    GestureType.GLASSES_LOOK_DOWN.value: {
        "command": "hide_status_overlay",
        "category": CommandCategory.DISPLAY.value,
        "risk": CommandRisk.SAFE.value,
        "description": "Hide system status overlay.",
    },
    GestureType.GLASSES_BLINK_DOUBLE.value: {
        "command": "toggle_focus_mode",
        "category": CommandCategory.DISPLAY.value,
        "risk": CommandRisk.LOW.value,
        "description": "Toggle focus mode safely.",
    },
    GestureType.TAP_SINGLE.value: {
        "command": "select_focused_item",
        "category": CommandCategory.ACCESSIBILITY.value,
        "risk": CommandRisk.LOW.value,
        "description": "Select focused item.",
    },
    GestureType.TAP_DOUBLE.value: {
        "command": "open_quick_actions",
        "category": CommandCategory.DASHBOARD.value,
        "risk": CommandRisk.SAFE.value,
        "description": "Open quick actions.",
    },
    GestureType.TAP_TRIPLE.value: {
        "command": "emergency_pause_all",
        "category": CommandCategory.SYSTEM.value,
        "risk": CommandRisk.HIGH.value,
        "description": "Pause all active automations safely.",
    },
    GestureType.TAP_LONG.value: {
        "command": "listen_for_voice_command",
        "category": CommandCategory.ACCESSIBILITY.value,
        "risk": CommandRisk.LOW.value,
        "description": "Start listening for voice command.",
    },
    GestureType.CLAP_SINGLE.value: {
        "command": "wake_agent",
        "category": CommandCategory.SYSTEM.value,
        "risk": CommandRisk.LOW.value,
        "description": "Wake William/Jarvis agent.",
    },
    GestureType.CLAP_DOUBLE.value: {
        "command": "mute_or_unmute_voice",
        "category": CommandCategory.MEDIA.value,
        "risk": CommandRisk.LOW.value,
        "description": "Mute or unmute voice interface.",
    },
    GestureType.CLAP_PATTERN.value: {
        "command": "trigger_configured_workflow",
        "category": CommandCategory.WORKFLOW.value,
        "risk": CommandRisk.MEDIUM.value,
        "description": "Trigger a configured safe workflow.",
    },
}


# -------------------------------------------------------------------------
# Data structures
# -------------------------------------------------------------------------

@dataclass
class GestureEvent:
    """
    Normalized gesture event.

    This is the input format expected from Visual Agent, Hologram Agent,
    glasses camera, microphone clap detector, phone tap detector, watch, or
    dashboard testing UI.
    """

    event_id: str
    user_id: str
    workspace_id: str
    gesture_type: str
    source: str = GestureSource.UNKNOWN.value
    confidence: float = 1.0
    device_id: Optional[str] = None
    raw_payload: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass
class GestureCommand:
    """
    Safe mapped command request.

    This object is not direct execution. It is a structured command request
    intended for Master Agent / Router / System Agent / Dashboard API.
    """

    command_id: str
    user_id: str
    workspace_id: str
    gesture_event_id: str
    gesture_type: str
    source: str
    command: str
    category: str = CommandCategory.UNKNOWN.value
    risk: str = CommandRisk.SAFE.value
    payload: Dict[str, Any] = field(default_factory=dict)
    requires_security: bool = False
    status: str = "prepared"
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GestureRule:
    """
    User/workspace-specific mapping rule.

    A rule maps one gesture type to one safe command.
    """

    rule_id: str
    user_id: str
    workspace_id: str
    gesture_type: str
    command: str
    source: Optional[str] = None
    category: str = CommandCategory.UNKNOWN.value
    risk: str = CommandRisk.SAFE.value
    enabled: bool = True
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD
    cooldown_seconds: float = DEFAULT_GESTURE_COOLDOWN_SECONDS
    payload_template: Dict[str, Any] = field(default_factory=dict)
    description: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)


@dataclass
class GestureProfile:
    """
    Isolated profile for one user/workspace.
    """

    user_id: str
    workspace_id: str
    enabled: bool = True
    profile_name: str = "default"
    rules: Dict[str, GestureRule] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


# -------------------------------------------------------------------------
# GestureControl
# -------------------------------------------------------------------------

class GestureControl(BaseAgent):
    """
    GestureControl maps hand/glass/tap/clap gestures to safe system commands.

    Master Agent:
        Can call process_gesture() or run(action="process_gesture") to convert
        a gesture into a command request.

    Security Agent:
        Sensitive command requests pass through _request_security_approval().

    Memory Agent:
        Useful gesture preferences and usage context can be prepared through
        _prepare_memory_payload().

    Verification Agent:
        Completed gesture mapping prepares verification payloads.

    Dashboard/API:
        Public methods return structured dict responses.

    Registry/Router:
        run() exposes stable action names for agent routing.
    """

    def __init__(
        self,
        agent_name: str = "GestureControl",
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
        max_event_log: int = DEFAULT_MAX_EVENT_LOG,
        max_audit_log: int = DEFAULT_MAX_AUDIT_LOG,
        max_history: int = DEFAULT_MAX_HISTORY,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=agent_name, agent_type="system", **kwargs)

        self.agent_name = agent_name
        self.confidence_threshold = max(0.0, min(1.0, float(confidence_threshold)))
        self.max_event_log = max_event_log
        self.max_audit_log = max_audit_log
        self.max_history = max_history

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger

        self._lock = threading.RLock()

        # key = (user_id, workspace_id)
        self._profiles: Dict[Tuple[str, str], GestureProfile] = {}

        # command_id -> GestureCommand
        self._command_history: Dict[str, GestureCommand] = {}

        # event_id -> GestureEvent
        self._gesture_history: Dict[str, GestureEvent] = {}

        # (user_id, workspace_id, gesture_type, source/device) -> timestamp
        self._last_gesture_at: Dict[Tuple[str, str, str, str], float] = {}

        self._event_log: List[Dict[str, Any]] = []
        self._audit_log: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # BaseAgent-compatible run method
    # ------------------------------------------------------------------

    def run(self, task: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        """
        Router-friendly generic run method.

        Supported actions:
            - create_profile
            - get_profile
            - enable_profile
            - disable_profile
            - register_rule
            - update_rule
            - remove_rule
            - list_rules
            - process_gesture
            - map_gesture
            - get_history
            - export_workspace_snapshot
        """

        task = task or {}
        action = task.get("action") or kwargs.get("action")
        payload = task.get("payload") or kwargs.get("payload") or {}
        context = task.get("context") or kwargs.get("context") or {}

        if not action:
            return self._error_result(
                message="No action provided for GestureControl.",
                error_code="missing_action",
                metadata={"supported_actions": self.supported_actions()},
            )

        action_map = {
            "create_profile": self.create_profile,
            "get_profile": self.get_profile,
            "enable_profile": self.enable_profile,
            "disable_profile": self.disable_profile,
            "register_rule": self.register_rule,
            "update_rule": self.update_rule,
            "remove_rule": self.remove_rule,
            "list_rules": self.list_rules,
            "process_gesture": self.process_gesture,
            "map_gesture": self.process_gesture,
            "get_history": self.get_history,
            "export_workspace_snapshot": self.export_workspace_snapshot,
        }

        handler = action_map.get(str(action))
        if not handler:
            return self._error_result(
                message=f"Unsupported GestureControl action: {action}",
                error_code="unsupported_action",
                metadata={"supported_actions": self.supported_actions()},
            )

        try:
            return handler(context=context, **payload)
        except TypeError as exc:
            return self._error_result(
                message=f"Invalid payload for action '{action}'.",
                error=str(exc),
                error_code="invalid_payload",
            )
        except Exception as exc:
            logger.exception("GestureControl run() failed.")
            return self._error_result(
                message=f"GestureControl action '{action}' failed.",
                error=str(exc),
                error_code="action_failed",
            )

    def supported_actions(self) -> List[str]:
        return [
            "create_profile",
            "get_profile",
            "enable_profile",
            "disable_profile",
            "register_rule",
            "update_rule",
            "remove_rule",
            "list_rules",
            "process_gesture",
            "map_gesture",
            "get_history",
            "export_workspace_snapshot",
        ]

    # ------------------------------------------------------------------
    # Profile methods
    # ------------------------------------------------------------------

    def create_profile(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        profile_name: str = "default",
        enabled: bool = True,
        include_default_rules: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create or update a gesture profile for one user/workspace.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        now = time.time()

        with self._lock:
            key = self._profile_key(user_id, workspace_id)
            profile = self._profiles.get(key)

            if not profile:
                profile = GestureProfile(
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                    enabled=bool(enabled),
                    profile_name=str(profile_name or "default"),
                    metadata=metadata or {},
                    created_at=now,
                    updated_at=now,
                )
                self._profiles[key] = profile
                message = "Gesture profile created successfully."
            else:
                profile.enabled = bool(enabled)
                profile.profile_name = str(profile_name or profile.profile_name)
                profile.updated_at = now
                if metadata:
                    profile.metadata.update(metadata)
                message = "Gesture profile updated successfully."

            if include_default_rules and not profile.rules:
                for gesture_type, command_config in DEFAULT_GESTURE_COMMANDS.items():
                    rule = self._make_rule_from_default(
                        user_id=str(user_id),
                        workspace_id=str(workspace_id),
                        gesture_type=gesture_type,
                        command_config=command_config,
                    )
                    profile.rules[rule.rule_id] = rule

            profile_dict = self._profile_to_dict(profile)

        audit = self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            action="create_profile",
            resource_id=profile.profile_name,
            details={
                "enabled": enabled,
                "include_default_rules": include_default_rules,
                "rule_count": len(profile.rules),
            },
        )

        event = self._emit_agent_event(
            event_type="gesture.profile_saved",
            user_id=user_id,
            workspace_id=workspace_id,
            data=profile_dict,
        )

        verification = self._prepare_verification_payload(
            operation="create_profile",
            user_id=user_id,
            workspace_id=workspace_id,
            data=profile_dict,
        )

        memory = self._prepare_memory_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type="gesture_profile_context",
            content={
                "profile_name": profile.profile_name,
                "enabled": profile.enabled,
                "rule_count": len(profile.rules),
            },
        )

        return self._safe_result(
            message=message,
            data={
                "profile": profile_dict,
                "verification_payload": verification,
                "memory_payload": memory,
                "audit_event": audit,
                "agent_event": event,
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    def get_profile(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        auto_create: bool = True,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Get a workspace gesture profile.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        with self._lock:
            profile = self._profiles.get(self._profile_key(user_id, workspace_id))

        if not profile and auto_create:
            return self.create_profile(
                user_id=user_id,
                workspace_id=workspace_id,
                include_default_rules=True,
                context=context,
            )

        if not profile:
            return self._error_result(
                message="Gesture profile not found.",
                error_code="profile_not_found",
                metadata={
                    "user_id": str(user_id),
                    "workspace_id": str(workspace_id),
                },
            )

        return self._safe_result(
            message="Gesture profile found.",
            data={"profile": self._profile_to_dict(profile)},
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    def enable_profile(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Enable gesture processing for one workspace profile.
        """

        return self._set_profile_enabled(
            user_id=user_id,
            workspace_id=workspace_id,
            enabled=True,
            context=context,
        )

    def disable_profile(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Disable gesture processing for one workspace profile.
        """

        return self._set_profile_enabled(
            user_id=user_id,
            workspace_id=workspace_id,
            enabled=False,
            context=context,
        )

    # ------------------------------------------------------------------
    # Rule methods
    # ------------------------------------------------------------------

    def register_rule(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        gesture_type: Optional[str] = None,
        command: Optional[str] = None,
        source: Optional[str] = None,
        category: str = CommandCategory.UNKNOWN.value,
        risk: str = CommandRisk.SAFE.value,
        enabled: bool = True,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
        cooldown_seconds: float = DEFAULT_GESTURE_COOLDOWN_SECONDS,
        payload_template: Optional[Dict[str, Any]] = None,
        description: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register a custom gesture mapping rule.

        This does not allow blocked command names.
        Sensitive commands are allowed only as safe command requests and must
        pass Security Agent approval during processing.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        if not gesture_type:
            return self._error_result(
                message="gesture_type is required.",
                error_code="missing_gesture_type",
            )

        if not command:
            return self._error_result(
                message="command is required.",
                error_code="missing_command",
            )

        safe_gesture_type = self._normalize_gesture_type(gesture_type)
        safe_source = self._normalize_source(source) if source else None
        safe_command = self._sanitize_command_name(command)

        if self._is_blocked_command(safe_command):
            return self._error_result(
                message="Blocked command cannot be registered.",
                error_code="blocked_command",
                metadata={"command": safe_command},
            )

        safe_risk = self._normalize_risk(risk)
        safe_category = self._normalize_category(category)
        safe_threshold = self._normalize_confidence(confidence_threshold)
        safe_cooldown = self._normalize_cooldown(cooldown_seconds)

        operation = "register_gesture_rule"
        if self._requires_security_check(operation=operation, command=safe_command, risk=safe_risk):
            approval = self._request_security_approval(
                operation=operation,
                user_id=user_id,
                workspace_id=workspace_id,
                payload={
                    "gesture_type": safe_gesture_type,
                    "source": safe_source,
                    "command": safe_command,
                    "risk": safe_risk,
                },
            )
            if not approval["success"]:
                return approval

        now = time.time()

        with self._lock:
            profile = self._get_or_create_profile_locked(
                user_id=str(user_id),
                workspace_id=str(workspace_id),
            )

            rule = GestureRule(
                rule_id=self._generate_rule_id(),
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                gesture_type=safe_gesture_type,
                source=safe_source,
                command=safe_command,
                category=safe_category,
                risk=safe_risk,
                enabled=bool(enabled),
                confidence_threshold=safe_threshold,
                cooldown_seconds=safe_cooldown,
                payload_template=copy.deepcopy(payload_template or {}),
                description=description,
                created_at=now,
                updated_at=now,
            )

            profile.rules[rule.rule_id] = rule
            profile.updated_at = now
            rule_dict = asdict(rule)

        audit = self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            action=operation,
            resource_id=rule.rule_id,
            details=rule_dict,
        )

        event = self._emit_agent_event(
            event_type="gesture.rule_registered",
            user_id=user_id,
            workspace_id=workspace_id,
            data=rule_dict,
        )

        verification = self._prepare_verification_payload(
            operation=operation,
            user_id=user_id,
            workspace_id=workspace_id,
            data=rule_dict,
        )

        memory = self._prepare_memory_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type="gesture_rule_context",
            content={
                "gesture_type": safe_gesture_type,
                "source": safe_source,
                "command": safe_command,
                "risk": safe_risk,
            },
        )

        return self._safe_result(
            message="Gesture rule registered successfully.",
            data={
                "rule": rule_dict,
                "verification_payload": verification,
                "memory_payload": memory,
                "audit_event": audit,
                "agent_event": event,
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "rule_id": rule.rule_id,
            },
        )

    def update_rule(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        rule_id: Optional[str] = None,
        command: Optional[str] = None,
        enabled: Optional[bool] = None,
        risk: Optional[str] = None,
        category: Optional[str] = None,
        confidence_threshold: Optional[float] = None,
        cooldown_seconds: Optional[float] = None,
        payload_template: Optional[Dict[str, Any]] = None,
        description: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Update a gesture rule.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        if not rule_id:
            return self._error_result(
                message="rule_id is required.",
                error_code="missing_rule_id",
            )

        operation = "update_gesture_rule"

        with self._lock:
            profile = self._profiles.get(self._profile_key(user_id, workspace_id))
            if not profile or rule_id not in profile.rules:
                return self._error_result(
                    message="Gesture rule not found.",
                    error_code="rule_not_found",
                    metadata={"rule_id": rule_id},
                )

            rule = profile.rules[rule_id]

            if command is not None:
                safe_command = self._sanitize_command_name(command)
                if self._is_blocked_command(safe_command):
                    return self._error_result(
                        message="Blocked command cannot be used.",
                        error_code="blocked_command",
                        metadata={"command": safe_command},
                    )
                rule.command = safe_command

            if enabled is not None:
                rule.enabled = bool(enabled)

            if risk is not None:
                rule.risk = self._normalize_risk(risk)

            if category is not None:
                rule.category = self._normalize_category(category)

            if confidence_threshold is not None:
                rule.confidence_threshold = self._normalize_confidence(confidence_threshold)

            if cooldown_seconds is not None:
                rule.cooldown_seconds = self._normalize_cooldown(cooldown_seconds)

            if payload_template is not None:
                rule.payload_template = copy.deepcopy(payload_template)

            if description is not None:
                rule.description = description

            rule.updated_at = time.time()
            profile.updated_at = rule.updated_at
            rule_dict = asdict(rule)

        if self._requires_security_check(operation=operation, command=rule.command, risk=rule.risk):
            approval = self._request_security_approval(
                operation=operation,
                user_id=user_id,
                workspace_id=workspace_id,
                payload=rule_dict,
            )
            if not approval["success"]:
                return approval

        audit = self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            action=operation,
            resource_id=rule_id,
            details=rule_dict,
        )

        event = self._emit_agent_event(
            event_type="gesture.rule_updated",
            user_id=user_id,
            workspace_id=workspace_id,
            data=rule_dict,
        )

        verification = self._prepare_verification_payload(
            operation=operation,
            user_id=user_id,
            workspace_id=workspace_id,
            data=rule_dict,
        )

        return self._safe_result(
            message="Gesture rule updated successfully.",
            data={
                "rule": rule_dict,
                "verification_payload": verification,
                "audit_event": audit,
                "agent_event": event,
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "rule_id": rule_id,
            },
        )

    def remove_rule(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        rule_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Remove a gesture rule.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        if not rule_id:
            return self._error_result(
                message="rule_id is required.",
                error_code="missing_rule_id",
            )

        operation = "remove_gesture_rule"
        if self._requires_security_check(operation=operation):
            approval = self._request_security_approval(
                operation=operation,
                user_id=user_id,
                workspace_id=workspace_id,
                payload={"rule_id": rule_id},
            )
            if not approval["success"]:
                return approval

        with self._lock:
            profile = self._profiles.get(self._profile_key(user_id, workspace_id))
            if not profile or rule_id not in profile.rules:
                return self._error_result(
                    message="Gesture rule not found.",
                    error_code="rule_not_found",
                    metadata={"rule_id": rule_id},
                )

            removed = profile.rules.pop(rule_id)
            profile.updated_at = time.time()

        audit = self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            action=operation,
            resource_id=rule_id,
            details={"removed_rule": asdict(removed)},
        )

        event = self._emit_agent_event(
            event_type="gesture.rule_removed",
            user_id=user_id,
            workspace_id=workspace_id,
            data={"rule_id": rule_id},
        )

        verification = self._prepare_verification_payload(
            operation=operation,
            user_id=user_id,
            workspace_id=workspace_id,
            data={"rule_id": rule_id},
        )

        return self._safe_result(
            message="Gesture rule removed successfully.",
            data={
                "removed_rule": asdict(removed),
                "verification_payload": verification,
                "audit_event": audit,
                "agent_event": event,
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "rule_id": rule_id,
            },
        )

    def list_rules(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        gesture_type: Optional[str] = None,
        source: Optional[str] = None,
        enabled_only: bool = False,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        List gesture rules for one workspace.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        safe_gesture_type = self._normalize_gesture_type(gesture_type) if gesture_type else None
        safe_source = self._normalize_source(source) if source else None

        with self._lock:
            profile = self._get_or_create_profile_locked(
                user_id=str(user_id),
                workspace_id=str(workspace_id),
            )

            rules = []
            for rule in profile.rules.values():
                if safe_gesture_type and rule.gesture_type != safe_gesture_type:
                    continue
                if safe_source and rule.source and rule.source != safe_source:
                    continue
                if enabled_only and not rule.enabled:
                    continue
                rules.append(asdict(rule))

        rules.sort(key=lambda item: (item.get("gesture_type", ""), item.get("source") or ""))

        return self._safe_result(
            message="Gesture rules listed successfully.",
            data={
                "rules": rules,
                "count": len(rules),
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "filters": {
                    "gesture_type": safe_gesture_type,
                    "source": safe_source,
                    "enabled_only": enabled_only,
                },
            },
        )

    # ------------------------------------------------------------------
    # Gesture processing
    # ------------------------------------------------------------------

    def process_gesture(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        gesture_type: Optional[str] = None,
        source: str = GestureSource.UNKNOWN.value,
        confidence: float = 1.0,
        device_id: Optional[str] = None,
        raw_payload: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Process one gesture event and map it to a safe command request.

        This method never directly executes the mapped command.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        if not gesture_type:
            return self._error_result(
                message="gesture_type is required.",
                error_code="missing_gesture_type",
            )

        safe_gesture_type = self._normalize_gesture_type(gesture_type)
        safe_source = self._normalize_source(source)
        safe_confidence = self._normalize_confidence(confidence)

        event = GestureEvent(
            event_id=self._generate_event_id(),
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            gesture_type=safe_gesture_type,
            source=safe_source,
            confidence=safe_confidence,
            device_id=device_id,
            raw_payload=self._sanitize_payload(raw_payload or {}),
            created_at=time.time(),
        )

        with self._lock:
            profile = self._get_or_create_profile_locked(
                user_id=str(user_id),
                workspace_id=str(workspace_id),
            )

            self._gesture_history[event.event_id] = event
            self._trim_history_locked()

            if not profile.enabled:
                return self._error_result(
                    message="Gesture profile is disabled.",
                    error_code="profile_disabled",
                    data={"gesture_event": asdict(event)},
                    metadata={
                        "user_id": str(user_id),
                        "workspace_id": str(workspace_id),
                    },
                )

            rule = self._find_matching_rule_locked(
                profile=profile,
                gesture_type=safe_gesture_type,
                source=safe_source,
            )

        if not rule:
            return self._error_result(
                message="No gesture rule found for this gesture.",
                error_code="no_matching_rule",
                data={"gesture_event": asdict(event)},
                metadata={
                    "gesture_type": safe_gesture_type,
                    "source": safe_source,
                },
            )

        if not rule.enabled:
            return self._error_result(
                message="Matching gesture rule is disabled.",
                error_code="rule_disabled",
                data={
                    "gesture_event": asdict(event),
                    "rule": asdict(rule),
                },
            )

        if safe_confidence < rule.confidence_threshold:
            return self._error_result(
                message="Gesture confidence is below the rule threshold.",
                error_code="low_confidence",
                data={
                    "gesture_event": asdict(event),
                    "rule": asdict(rule),
                },
                metadata={
                    "confidence": safe_confidence,
                    "required_confidence": rule.confidence_threshold,
                },
            )

        cooldown_check = self._check_cooldown(
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            gesture_type=safe_gesture_type,
            source_key=device_id or safe_source,
            cooldown_seconds=rule.cooldown_seconds,
        )
        if not cooldown_check["success"]:
            return cooldown_check

        command = self._build_command_from_rule(event=event, rule=rule)

        if self._is_blocked_command(command.command):
            return self._error_result(
                message="Mapped command is blocked and cannot be prepared.",
                error_code="blocked_command",
                data={
                    "gesture_event": asdict(event),
                    "command": asdict(command),
                },
            )

        if self._requires_security_check(
            operation="process_gesture",
            command=command.command,
            risk=command.risk,
        ):
            approval = self._request_security_approval(
                operation="process_gesture",
                user_id=user_id,
                workspace_id=workspace_id,
                payload={
                    "gesture_event": asdict(event),
                    "command": asdict(command),
                    "rule": asdict(rule),
                },
            )
            if not approval["success"]:
                command.status = "security_denied"
                with self._lock:
                    self._command_history[command.command_id] = command
                    self._trim_history_locked()
                return approval

            command.requires_security = True
            command.metadata["security_approval"] = approval.get("data", {})

        with self._lock:
            self._command_history[command.command_id] = command
            self._last_gesture_at[
                (
                    str(user_id),
                    str(workspace_id),
                    safe_gesture_type,
                    device_id or safe_source,
                )
            ] = time.time()
            self._trim_history_locked()

        audit = self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            action="process_gesture",
            resource_id=command.command_id,
            details={
                "gesture_event": asdict(event),
                "command": asdict(command),
                "rule_id": rule.rule_id,
            },
        )

        event_payload = self._emit_agent_event(
            event_type="gesture.command_prepared",
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "gesture_event": asdict(event),
                "command": asdict(command),
                "rule": asdict(rule),
            },
        )

        verification = self._prepare_verification_payload(
            operation="process_gesture",
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "gesture_event": asdict(event),
                "command": asdict(command),
                "rule": asdict(rule),
            },
        )

        memory = self._prepare_memory_payload(
            user_id=user_id,
            workspace_id=workspace_id,
            memory_type="gesture_usage_context",
            content={
                "gesture_type": safe_gesture_type,
                "source": safe_source,
                "command": command.command,
                "risk": command.risk,
                "confidence": safe_confidence,
            },
        )

        return self._safe_result(
            message="Gesture mapped to safe command request successfully.",
            data={
                "gesture_event": asdict(event),
                "command_request": asdict(command),
                "rule": asdict(rule),
                "verification_payload": verification,
                "memory_payload": memory,
                "audit_event": audit,
                "agent_event": event_payload,
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "command_id": command.command_id,
                "gesture_event_id": event.event_id,
                "direct_execution": False,
            },
        )

    def acknowledge_command(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        command_id: str,
        status: str = "acknowledged",
        result_data: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Mark a prepared gesture command as acknowledged/completed by another
        agent or dashboard/API worker.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        with self._lock:
            command = self._command_history.get(command_id)

            if not command:
                return self._error_result(
                    message="Command request not found.",
                    error_code="command_not_found",
                    metadata={"command_id": command_id},
                )

            if command.user_id != str(user_id) or command.workspace_id != str(workspace_id):
                return self._error_result(
                    message="Command request does not belong to this user/workspace.",
                    error_code="command_scope_mismatch",
                )

            command.status = str(status)
            command.metadata["acknowledged_at"] = time.time()
            command.metadata["result_data"] = result_data or {}
            command.metadata["error"] = error

            command_dict = asdict(command)

        verification = self._prepare_verification_payload(
            operation="acknowledge_command",
            user_id=user_id,
            workspace_id=workspace_id,
            data=command_dict,
        )

        self._emit_agent_event(
            event_type="gesture.command_acknowledged",
            user_id=user_id,
            workspace_id=workspace_id,
            data=command_dict,
        )

        return self._safe_result(
            message="Gesture command acknowledgement recorded.",
            data={
                "command_request": command_dict,
                "verification_payload": verification,
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "command_id": command_id,
            },
        )

    # ------------------------------------------------------------------
    # History and dashboard exports
    # ------------------------------------------------------------------

    def get_history(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        limit: int = 50,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return gesture and command history for one user/workspace.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        safe_limit = max(1, min(int(limit), self.max_history))

        with self._lock:
            gestures = [
                asdict(event)
                for event in self._gesture_history.values()
                if event.user_id == str(user_id)
                and event.workspace_id == str(workspace_id)
            ][-safe_limit:]

            commands = [
                asdict(command)
                for command in self._command_history.values()
                if command.user_id == str(user_id)
                and command.workspace_id == str(workspace_id)
            ][-safe_limit:]

        return self._safe_result(
            message="Gesture history returned.",
            data={
                "gestures": gestures,
                "commands": commands,
                "gesture_count": len(gestures),
                "command_count": len(commands),
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
                "limit": safe_limit,
            },
        )

    def export_workspace_snapshot(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Export a safe dashboard/API-ready snapshot for one workspace.
        """

        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        with self._lock:
            profile = self._profiles.get(self._profile_key(user_id, workspace_id))
            gestures = [
                asdict(event)
                for event in self._gesture_history.values()
                if event.user_id == str(user_id)
                and event.workspace_id == str(workspace_id)
            ]
            commands = [
                asdict(command)
                for command in self._command_history.values()
                if command.user_id == str(user_id)
                and command.workspace_id == str(workspace_id)
            ]

        return self._safe_result(
            message="Gesture workspace snapshot exported.",
            data={
                "profile": self._profile_to_dict(profile) if profile else None,
                "gestures": gestures,
                "commands": commands,
                "stats": {
                    "profile_exists": profile is not None,
                    "rule_count": len(profile.rules) if profile else 0,
                    "gesture_count": len(gestures),
                    "command_count": len(commands),
                },
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    def get_event_log(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Return recent agent events.
        """

        safe_limit = max(1, min(int(limit), self.max_event_log))

        with self._lock:
            events = list(self._event_log)

        if user_id is not None:
            events = [event for event in events if event.get("user_id") == str(user_id)]

        if workspace_id is not None:
            events = [
                event
                for event in events
                if event.get("workspace_id") == str(workspace_id)
            ]

        events = events[-safe_limit:]

        return self._safe_result(
            message="Gesture event log returned.",
            data={
                "events": events,
                "count": len(events),
            },
        )

    def get_audit_log(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Return recent audit events.
        """

        safe_limit = max(1, min(int(limit), self.max_audit_log))

        with self._lock:
            events = list(self._audit_log)

        if user_id is not None:
            events = [event for event in events if event.get("user_id") == str(user_id)]

        if workspace_id is not None:
            events = [
                event
                for event in events
                if event.get("workspace_id") == str(workspace_id)
            ]

        events = events[-safe_limit:]

        return self._safe_result(
            message="Gesture audit log returned.",
            data={
                "audit_events": events,
                "count": len(events),
            },
        )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        **_: Any,
    ) -> Dict[str, Any]:
        """
        Validate SaaS isolation fields.

        Every user-specific gesture operation must include user_id and workspace_id.
        """

        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="user_id is required for GestureControl operations.",
                error_code="missing_user_id",
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="workspace_id is required for GestureControl operations.",
                error_code="missing_workspace_id",
            )

        return self._safe_result(
            message="Task context is valid.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    def _requires_security_check(
        self,
        operation: str,
        command: Optional[str] = None,
        risk: Optional[str] = None,
        **_: Any,
    ) -> bool:
        """
        Decide whether Security Agent approval is needed.
        """

        sensitive_operations = {
            "register_gesture_rule",
            "update_gesture_rule",
            "remove_gesture_rule",
            "process_gesture",
        }

        if operation in {"remove_gesture_rule"}:
            return True

        safe_risk = self._normalize_risk(risk) if risk else CommandRisk.SAFE.value
        if safe_risk in {CommandRisk.MEDIUM.value, CommandRisk.HIGH.value}:
            return True

        if command:
            lowered = str(command).lower()
            if any(keyword in lowered for keyword in SENSITIVE_COMMAND_KEYWORDS):
                return True

        if operation in sensitive_operations and safe_risk != CommandRisk.SAFE.value:
            return True

        return False

    def _request_security_approval(
        self,
        operation: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If Security Agent is not attached, this uses a safe default approval
        for non-blocked command requests. Blocked commands are never approved.
        """

        approval_payload = {
            "operation": operation,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "payload": self._sanitize_payload(payload or {}),
            "agent": self.agent_name,
            "created_at": time.time(),
        }

        command = self._extract_command_from_payload(payload or {})
        if command and self._is_blocked_command(command):
            return self._error_result(
                message="Security policy blocked this gesture command.",
                error_code="security_blocked_command",
                metadata={"approval_payload": approval_payload},
            )

        if self.security_agent:
            try:
                if hasattr(self.security_agent, "approve_action"):
                    result = self.security_agent.approve_action(approval_payload)
                elif hasattr(self.security_agent, "run"):
                    result = self.security_agent.run({
                        "action": "approve_action",
                        "payload": approval_payload,
                    })
                else:
                    result = None

                if isinstance(result, dict):
                    if result.get("success") is False:
                        return self._error_result(
                            message="Security Agent denied the operation.",
                            error=result.get("error"),
                            error_code="security_denied",
                            metadata={"approval_payload": approval_payload},
                        )

                    return self._safe_result(
                        message="Security Agent approved the operation.",
                        data={"approval": result},
                        metadata={"approval_payload": approval_payload},
                    )
            except Exception as exc:
                logger.warning("Security Agent approval failed: %s", exc)
                return self._error_result(
                    message="Security Agent approval failed.",
                    error=str(exc),
                    error_code="security_agent_error",
                    metadata={"approval_payload": approval_payload},
                )

        return self._safe_result(
            message="Security approval passed by safe default policy.",
            data={"approved": True},
            metadata={
                "approval_payload": approval_payload,
                "approval_mode": "safe_default_no_security_agent_attached",
            },
        )

    def _prepare_verification_payload(
        self,
        operation: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.
        """

        payload = {
            "verification_id": f"verify_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "operation": operation,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "data": copy.deepcopy(data or {}),
            "created_at": time.time(),
            "status": "prepared",
        }

        if self.verification_agent:
            try:
                if hasattr(self.verification_agent, "prepare"):
                    self.verification_agent.prepare(payload)
                elif hasattr(self.verification_agent, "run"):
                    self.verification_agent.run({
                        "action": "prepare_verification",
                        "payload": payload,
                    })
            except Exception as exc:
                payload["verification_agent_error"] = str(exc)

        return payload

    def _prepare_memory_payload(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        memory_type: str,
        content: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.
        """

        payload = {
            "memory_id": f"mem_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "memory_type": memory_type,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "content": copy.deepcopy(content),
            "created_at": time.time(),
            "safe_to_store": True,
        }

        if self.memory_agent:
            try:
                if hasattr(self.memory_agent, "prepare_memory"):
                    self.memory_agent.prepare_memory(payload)
                elif hasattr(self.memory_agent, "run"):
                    self.memory_agent.run({
                        "action": "prepare_memory",
                        "payload": payload,
                    })
            except Exception as exc:
                payload["memory_agent_error"] = str(exc)

        return payload

    def _emit_agent_event(
        self,
        event_type: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit an internal agent event for dashboard/API/event bus.
        """

        event = {
            "event_id": f"evt_{uuid.uuid4().hex}",
            "event_type": event_type,
            "agent": self.agent_name,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "data": copy.deepcopy(data or {}),
            "created_at": time.time(),
        }

        with self._lock:
            self._event_log.append(event)
            if len(self._event_log) > self.max_event_log:
                self._event_log = self._event_log[-self.max_event_log:]

        if self.event_bus:
            try:
                if hasattr(self.event_bus, "emit"):
                    self.event_bus.emit(event_type, event)
                elif hasattr(self.event_bus, "publish"):
                    self.event_bus.publish(event)
            except Exception as exc:
                event["event_bus_error"] = str(exc)

        return event

    def _log_audit_event(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        action: str,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log SaaS-safe audit event.
        """

        audit_event = {
            "audit_id": f"audit_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "action": action,
            "resource_id": resource_id,
            "user_id": str(user_id),
            "workspace_id": str(workspace_id),
            "details": self._sanitize_payload(details or {}),
            "created_at": time.time(),
        }

        with self._lock:
            self._audit_log.append(audit_event)
            if len(self._audit_log) > self.max_audit_log:
                self._audit_log = self._audit_log[-self.max_audit_log:]

        if self.audit_logger:
            try:
                if hasattr(self.audit_logger, "log"):
                    self.audit_logger.log(audit_event)
                elif hasattr(self.audit_logger, "write"):
                    self.audit_logger.write(audit_event)
            except Exception as exc:
                audit_event["audit_logger_error"] = str(exc)

        return audit_event

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success response format.
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
        error: Optional[str] = None,
        error_code: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error response format.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {
                "code": error_code or "gesture_control_error",
                "detail": error or message,
            },
            "metadata": metadata or {},
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _profile_key(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> Tuple[str, str]:
        return (str(user_id), str(workspace_id))

    def _coalesce_id(
        self,
        primary: Optional[Union[str, int]],
        fallback: Optional[Union[str, int]],
    ) -> Optional[Union[str, int]]:
        if primary is not None and str(primary).strip() != "":
            return primary
        if fallback is not None and str(fallback).strip() != "":
            return fallback
        return None

    def _generate_event_id(self) -> str:
        return f"gesture_evt_{uuid.uuid4().hex}"

    def _generate_command_id(self) -> str:
        return f"gesture_cmd_{uuid.uuid4().hex}"

    def _generate_rule_id(self) -> str:
        return f"gesture_rule_{uuid.uuid4().hex}"

    def _normalize_source(self, source: Optional[str]) -> str:
        value = str(source or GestureSource.UNKNOWN.value).strip().lower()
        if value not in SUPPORTED_SOURCES:
            return GestureSource.UNKNOWN.value
        return value

    def _normalize_gesture_type(self, gesture_type: Optional[str]) -> str:
        value = str(gesture_type or GestureType.UNKNOWN.value).strip().lower()
        if value not in SUPPORTED_GESTURE_TYPES:
            return GestureType.UNKNOWN.value
        return value

    def _normalize_risk(self, risk: Optional[str]) -> str:
        value = str(risk or CommandRisk.SAFE.value).strip().lower()
        valid = {item.value for item in CommandRisk}
        if value not in valid:
            return CommandRisk.SAFE.value
        return value

    def _normalize_category(self, category: Optional[str]) -> str:
        value = str(category or CommandCategory.UNKNOWN.value).strip().lower()
        valid = {item.value for item in CommandCategory}
        if value not in valid:
            return CommandCategory.UNKNOWN.value
        return value

    def _normalize_confidence(self, confidence: Any) -> float:
        try:
            value = float(confidence)
        except Exception:
            value = self.confidence_threshold
        return max(0.0, min(1.0, value))

    def _normalize_cooldown(self, cooldown_seconds: Any) -> float:
        try:
            value = float(cooldown_seconds)
        except Exception:
            value = DEFAULT_GESTURE_COOLDOWN_SECONDS
        return max(0.0, min(60.0, value))

    def _sanitize_command_name(self, command: str) -> str:
        """
        Convert command names into safe internal command format.
        """

        value = str(command).strip().lower()
        safe_chars = []
        for char in value:
            if char.isalnum() or char in {"_", "-", "."}:
                safe_chars.append(char)
            elif char.isspace():
                safe_chars.append("_")

        cleaned = "".join(safe_chars).strip("_")
        return cleaned or "unknown_command"

    def _is_blocked_command(self, command: Optional[str]) -> bool:
        if not command:
            return False
        lowered = str(command).lower()
        return any(keyword in lowered for keyword in BLOCKED_COMMAND_KEYWORDS)

    def _extract_command_from_payload(self, payload: Dict[str, Any]) -> Optional[str]:
        if not isinstance(payload, dict):
            return None

        if "command" in payload:
            command_value = payload.get("command")
            if isinstance(command_value, dict):
                return command_value.get("command")
            return str(command_value)

        command_request = payload.get("command_request")
        if isinstance(command_request, dict):
            return command_request.get("command")

        return None

    def _sanitize_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact secrets from arbitrary payloads.
        """

        blocked_terms = {
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "private_key",
            "access_token",
            "refresh_token",
            "credential",
            "cookie",
            "session",
        }

        def clean(obj: Any) -> Any:
            if isinstance(obj, dict):
                safe_dict = {}
                for key, value in obj.items():
                    lower_key = str(key).lower()
                    if any(term in lower_key for term in blocked_terms):
                        safe_dict[key] = "[REDACTED]"
                    else:
                        safe_dict[key] = clean(value)
                return safe_dict

            if isinstance(obj, list):
                return [clean(item) for item in obj]

            return obj

        return clean(copy.deepcopy(payload))

    def _make_rule_from_default(
        self,
        user_id: str,
        workspace_id: str,
        gesture_type: str,
        command_config: Dict[str, Any],
    ) -> GestureRule:
        return GestureRule(
            rule_id=self._generate_rule_id(),
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            gesture_type=gesture_type,
            source=None,
            command=self._sanitize_command_name(command_config.get("command", "")),
            category=self._normalize_category(command_config.get("category")),
            risk=self._normalize_risk(command_config.get("risk")),
            enabled=True,
            confidence_threshold=self.confidence_threshold,
            cooldown_seconds=DEFAULT_GESTURE_COOLDOWN_SECONDS,
            payload_template={},
            description=command_config.get("description"),
            created_at=time.time(),
            updated_at=time.time(),
        )

    def _get_or_create_profile_locked(
        self,
        user_id: str,
        workspace_id: str,
    ) -> GestureProfile:
        key = self._profile_key(user_id, workspace_id)
        profile = self._profiles.get(key)

        if profile:
            return profile

        profile = GestureProfile(
            user_id=str(user_id),
            workspace_id=str(workspace_id),
            enabled=True,
            profile_name="default",
        )

        for gesture_type, command_config in DEFAULT_GESTURE_COMMANDS.items():
            rule = self._make_rule_from_default(
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                gesture_type=gesture_type,
                command_config=command_config,
            )
            profile.rules[rule.rule_id] = rule

        self._profiles[key] = profile
        return profile

    def _profile_to_dict(self, profile: Optional[GestureProfile]) -> Dict[str, Any]:
        if not profile:
            return {}

        return {
            "user_id": profile.user_id,
            "workspace_id": profile.workspace_id,
            "enabled": profile.enabled,
            "profile_name": profile.profile_name,
            "rules": {
                rule_id: asdict(rule)
                for rule_id, rule in profile.rules.items()
            },
            "created_at": profile.created_at,
            "updated_at": profile.updated_at,
            "metadata": copy.deepcopy(profile.metadata),
        }

    def _find_matching_rule_locked(
        self,
        profile: GestureProfile,
        gesture_type: str,
        source: str,
    ) -> Optional[GestureRule]:
        """
        Find best matching rule.

        Priority:
            1. Exact gesture + exact source
            2. Exact gesture + no source restriction
        """

        exact_source_match = None
        generic_match = None

        for rule in profile.rules.values():
            if rule.gesture_type != gesture_type:
                continue

            if rule.source == source:
                exact_source_match = rule
                break

            if rule.source is None:
                generic_match = rule

        return exact_source_match or generic_match

    def _build_command_from_rule(
        self,
        event: GestureEvent,
        rule: GestureRule,
    ) -> GestureCommand:
        payload = copy.deepcopy(rule.payload_template)
        payload.update({
            "gesture_event_id": event.event_id,
            "gesture_type": event.gesture_type,
            "source": event.source,
            "confidence": event.confidence,
            "device_id": event.device_id,
            "raw_payload": event.raw_payload,
        })

        requires_security = self._requires_security_check(
            operation="process_gesture",
            command=rule.command,
            risk=rule.risk,
        )

        return GestureCommand(
            command_id=self._generate_command_id(),
            user_id=event.user_id,
            workspace_id=event.workspace_id,
            gesture_event_id=event.event_id,
            gesture_type=event.gesture_type,
            source=event.source,
            command=rule.command,
            category=rule.category,
            risk=rule.risk,
            payload=payload,
            requires_security=requires_security,
            status="prepared",
            created_at=time.time(),
            metadata={
                "rule_id": rule.rule_id,
                "description": rule.description,
                "direct_execution": False,
                "safe_command_request_only": True,
            },
        )

    def _check_cooldown(
        self,
        user_id: str,
        workspace_id: str,
        gesture_type: str,
        source_key: str,
        cooldown_seconds: float,
    ) -> Dict[str, Any]:
        key = (str(user_id), str(workspace_id), str(gesture_type), str(source_key))
        now = time.time()

        with self._lock:
            previous = self._last_gesture_at.get(key)

        if previous is None:
            return self._safe_result(
                message="Gesture cooldown passed.",
                data={"cooldown_passed": True},
            )

        elapsed = now - previous
        if elapsed < cooldown_seconds:
            return self._error_result(
                message="Gesture ignored because cooldown is active.",
                error_code="gesture_cooldown_active",
                metadata={
                    "elapsed_seconds": round(elapsed, 3),
                    "cooldown_seconds": cooldown_seconds,
                    "remaining_seconds": round(cooldown_seconds - elapsed, 3),
                },
            )

        return self._safe_result(
            message="Gesture cooldown passed.",
            data={"cooldown_passed": True},
        )

    def _set_profile_enabled(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        enabled: bool,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        context = context or {}
        user_id = self._coalesce_id(user_id, context.get("user_id"))
        workspace_id = self._coalesce_id(workspace_id, context.get("workspace_id"))

        validation = self._validate_task_context(user_id=user_id, workspace_id=workspace_id)
        if not validation["success"]:
            return validation

        with self._lock:
            profile = self._get_or_create_profile_locked(
                user_id=str(user_id),
                workspace_id=str(workspace_id),
            )
            profile.enabled = bool(enabled)
            profile.updated_at = time.time()
            profile_dict = self._profile_to_dict(profile)

        action = "enable_profile" if enabled else "disable_profile"

        audit = self._log_audit_event(
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            resource_id=profile.profile_name,
            details={"enabled": enabled},
        )

        event = self._emit_agent_event(
            event_type=f"gesture.profile_{'enabled' if enabled else 'disabled'}",
            user_id=user_id,
            workspace_id=workspace_id,
            data=profile_dict,
        )

        verification = self._prepare_verification_payload(
            operation=action,
            user_id=user_id,
            workspace_id=workspace_id,
            data=profile_dict,
        )

        return self._safe_result(
            message=f"Gesture profile {'enabled' if enabled else 'disabled'} successfully.",
            data={
                "profile": profile_dict,
                "verification_payload": verification,
                "audit_event": audit,
                "agent_event": event,
            },
            metadata={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    def _trim_history_locked(self) -> None:
        if len(self._gesture_history) > self.max_history:
            sorted_gestures = sorted(
                self._gesture_history.items(),
                key=lambda item: item[1].created_at,
            )
            self._gesture_history = dict(sorted_gestures[-self.max_history:])

        if len(self._command_history) > self.max_history:
            sorted_commands = sorted(
                self._command_history.items(),
                key=lambda item: item[1].created_at,
            )
            self._command_history = dict(sorted_commands[-self.max_history:])


# -------------------------------------------------------------------------
# Standalone smoke test
# -------------------------------------------------------------------------

if __name__ == "__main__":
    gesture = GestureControl()

    ctx = {
        "user_id": "user_1",
        "workspace_id": "workspace_1",
    }

    profile_result = gesture.create_profile(context=ctx)
    print("CREATE PROFILE:", profile_result)

    rules_result = gesture.list_rules(context=ctx)
    print("RULES:", rules_result)

    command_result = gesture.process_gesture(
        context=ctx,
        gesture_type="hand_wave_right",
        source="hand",
        confidence=0.95,
        device_id="glasses_001",
        raw_payload={
            "x": 120,
            "y": 240,
            "access_token": "should_be_redacted",
        },
    )
    print("PROCESS GESTURE:", command_result)

    history_result = gesture.get_history(context=ctx)
    print("HISTORY:", history_result)

    snapshot_result = gesture.export_workspace_snapshot(context=ctx)
    print("SNAPSHOT:", snapshot_result)

    print("FILE COMPLETE")