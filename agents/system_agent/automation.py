"""
agents/system_agent/automation.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Keyboard, mouse, gesture automation, clicking, typing, scrolling,
    hotkeys, drag actions, and macro execution for the System Agent.

Architecture Compatibility:
    - Master Agent routing
    - BaseAgent compatibility
    - Agent Registry / Agent Loader compatibility
    - Security Agent permission checks
    - Verification Agent payload preparation
    - Memory Agent payload compatibility
    - Dashboard/API structured responses
    - SaaS user/workspace isolation

Safety:
    This module is import-safe and does not execute automation at import time.
    Potentially sensitive automation actions are permission-gated.
    Real execution requires:
        - valid user_id
        - valid workspace_id
        - security approval when required
        - execution enabled in config/context

Optional Dependency:
    pyautogui

Install:
    pip install pyautogui
"""

from __future__ import annotations

import time
import uuid
import logging
import platform
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Callable, Union, Tuple


# ---------------------------------------------------------------------------
# Optional imports / safe fallbacks
# ---------------------------------------------------------------------------

try:
    import pyautogui  # type: ignore
    PYAUTOGUI_AVAILABLE = True
except Exception:  # pragma: no cover
    pyautogui = None  # type: ignore
    PYAUTOGUI_AVAILABLE = False


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:
        """
        Fallback BaseAgent stub.

        This keeps the file safe to import even if the main William/Jarvis
        BaseAgent has not been generated yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            return None


try:
    from core.context import AgentContext  # type: ignore
except Exception:  # pragma: no cover
    AgentContext = Any  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("william.system_agent.automation")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Enums / Data Structures
# ---------------------------------------------------------------------------

class AutomationActionType(str, Enum):
    CLICK = "click"
    DOUBLE_CLICK = "double_click"
    RIGHT_CLICK = "right_click"
    MOVE = "move"
    DRAG = "drag"
    TYPE_TEXT = "type_text"
    PRESS_KEY = "press_key"
    HOTKEY = "hotkey"
    SCROLL = "scroll"
    PAUSE = "pause"
    MACRO = "macro"
    SCREENSHOT = "screenshot"
    POSITION = "position"


class AutomationRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class AutomationConfig:
    """
    Runtime configuration for automation.

    execution_enabled:
        If False, all actions return dry-run style results.

    dry_run_default:
        If True, actions simulate unless execute=True is explicitly passed.

    require_security_approval:
        If True, sensitive actions must go through Security Agent hook.

    fail_safe:
        Passed to pyautogui.FAILSAFE where available.

    pause_between_actions:
        Default delay between macro steps.

    max_macro_steps:
        Hard safety limit for macro length.

    max_text_length:
        Safety limit for typed text.

    max_clicks_per_action:
        Safety limit for repeated click actions.

    max_scroll_amount:
        Safety limit for scroll values.

    max_drag_duration:
        Safety limit for drag duration.
    """

    execution_enabled: bool = False
    dry_run_default: bool = True
    require_security_approval: bool = True
    fail_safe: bool = True
    pause_between_actions: float = 0.15
    max_macro_steps: int = 100
    max_text_length: int = 5000
    max_clicks_per_action: int = 50
    max_scroll_amount: int = 10000
    max_drag_duration: float = 10.0
    allowed_screen_width: Optional[int] = None
    allowed_screen_height: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AutomationTaskContext:
    """
    SaaS-safe task context.

    Every user-specific action should include user_id and workspace_id.
    This prevents automation logs, memory, analytics, and audit records
    from mixing across users/workspaces.
    """

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: Optional[str] = None
    role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    source: str = "system_agent"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AutomationCommand:
    """
    One automation command for macro execution.
    """

    action: str
    x: Optional[int] = None
    y: Optional[int] = None
    x2: Optional[int] = None
    y2: Optional[int] = None
    text: Optional[str] = None
    key: Optional[str] = None
    keys: Optional[List[str]] = None
    button: str = "left"
    clicks: int = 1
    interval: float = 0.05
    duration: float = 0.2
    amount: Optional[int] = None
    pause: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# SystemAutomation
# ---------------------------------------------------------------------------

class SystemAutomation(BaseAgent):
    """
    Production-level keyboard/mouse/gesture automation module.

    This class is designed to be used by:
        - System Agent
        - Master Agent
        - Agent Router
        - Dashboard/API layer
        - Workflow Agent
        - Verification Agent
        - Memory Agent
        - Security Agent

    It does NOT automatically perform real system actions unless execution
    is explicitly enabled and the action passes validation/security checks.
    """

    agent_name = "SystemAutomation"
    agent_type = "system_agent_helper"
    module_path = "agents/system_agent/automation.py"

    def __init__(
        self,
        config: Optional[AutomationConfig] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)

        self.config = config or AutomationConfig()
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter

        self.runtime_id = str(uuid.uuid4())
        self.created_at = self._utc_now()

        self._configure_pyautogui()

    # -----------------------------------------------------------------------
    # Core helpers
    # -----------------------------------------------------------------------

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _configure_pyautogui(self) -> None:
        """
        Configure pyautogui safely if available.
        """
        if PYAUTOGUI_AVAILABLE and pyautogui is not None:
            try:
                pyautogui.FAILSAFE = bool(self.config.fail_safe)
                pyautogui.PAUSE = float(self.config.pause_between_actions)
            except Exception as exc:
                logger.warning("Unable to configure pyautogui: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "module": self.module_path,
                "runtime_id": self.runtime_id,
                "timestamp": self._utc_now(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error) if error else message,
            "metadata": {
                "agent": self.agent_name,
                "module": self.module_path,
                "runtime_id": self.runtime_id,
                "timestamp": self._utc_now(),
                **(metadata or {}),
            },
        }

    def _normalize_context(
        self,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
    ) -> Optional[AutomationTaskContext]:
        """
        Normalize context from dict/object into AutomationTaskContext.
        """
        if context is None:
            return None

        if isinstance(context, AutomationTaskContext):
            return context

        if isinstance(context, dict):
            user_id = context.get("user_id")
            workspace_id = context.get("workspace_id")

            if user_id is None or workspace_id is None:
                return None

            return AutomationTaskContext(
                user_id=user_id,
                workspace_id=workspace_id,
                request_id=str(context.get("request_id") or uuid.uuid4()),
                session_id=context.get("session_id"),
                role=context.get("role"),
                permissions=list(context.get("permissions") or []),
                source=str(context.get("source") or "system_agent"),
                metadata=dict(context.get("metadata") or {}),
            )

        user_id = getattr(context, "user_id", None)
        workspace_id = getattr(context, "workspace_id", None)

        if user_id is None or workspace_id is None:
            return None

        return AutomationTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            request_id=str(getattr(context, "request_id", uuid.uuid4())),
            session_id=getattr(context, "session_id", None),
            role=getattr(context, "role", None),
            permissions=list(getattr(context, "permissions", []) or []),
            source=str(getattr(context, "source", "system_agent")),
            metadata=dict(getattr(context, "metadata", {}) or {}),
        )

    def _validate_task_context(
        self,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
    ) -> Tuple[bool, Optional[AutomationTaskContext], Optional[str]]:
        """
        Validate SaaS user/workspace isolation context.

        Required by William/Jarvis architecture.
        """
        normalized = self._normalize_context(context)

        if normalized is None:
            return False, None, "Missing or invalid task context. user_id and workspace_id are required."

        if normalized.user_id in ("", None):
            return False, None, "Missing user_id."

        if normalized.workspace_id in ("", None):
            return False, None, "Missing workspace_id."

        return True, normalized, None

    def _requires_security_check(
        self,
        action: AutomationActionType,
        risk_level: AutomationRiskLevel = AutomationRiskLevel.MEDIUM,
    ) -> bool:
        """
        Determine whether an action requires Security Agent approval.
        """
        if not self.config.require_security_approval:
            return False

        high_risk_actions = {
            AutomationActionType.CLICK,
            AutomationActionType.DOUBLE_CLICK,
            AutomationActionType.RIGHT_CLICK,
            AutomationActionType.DRAG,
            AutomationActionType.TYPE_TEXT,
            AutomationActionType.PRESS_KEY,
            AutomationActionType.HOTKEY,
            AutomationActionType.MACRO,
        }

        if risk_level == AutomationRiskLevel.HIGH:
            return True

        return action in high_risk_actions

    def _request_security_approval(
        self,
        action: AutomationActionType,
        context: AutomationTaskContext,
        payload: Dict[str, Any],
        risk_level: AutomationRiskLevel = AutomationRiskLevel.MEDIUM,
    ) -> Dict[str, Any]:
        """
        Ask Security Agent for approval if available.

        If no Security Agent is connected:
            - real execution is blocked when approval is required
            - dry-run can continue
        """
        approval_payload = {
            "action": action.value,
            "risk_level": risk_level.value,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "payload": payload,
            "timestamp": self._utc_now(),
            "agent": self.agent_name,
        }

        if not self._requires_security_check(action, risk_level):
            return {
                "approved": True,
                "reason": "Security approval not required for this action.",
                "payload": approval_payload,
            }

        if self.security_agent is None:
            return {
                "approved": False,
                "reason": "Security Agent is not connected. Real automation blocked.",
                "payload": approval_payload,
            }

        try:
            if hasattr(self.security_agent, "approve_action"):
                result = self.security_agent.approve_action(approval_payload)
            elif hasattr(self.security_agent, "validate_action"):
                result = self.security_agent.validate_action(approval_payload)
            elif callable(self.security_agent):
                result = self.security_agent(approval_payload)
            else:
                return {
                    "approved": False,
                    "reason": "Security Agent does not expose an approval method.",
                    "payload": approval_payload,
                }

            if isinstance(result, dict):
                approved = bool(result.get("approved") or result.get("success"))
                return {
                    "approved": approved,
                    "reason": result.get("message") or result.get("reason") or "Security Agent response received.",
                    "payload": approval_payload,
                    "security_result": result,
                }

            return {
                "approved": bool(result),
                "reason": "Security Agent returned boolean-style response.",
                "payload": approval_payload,
            }

        except Exception as exc:
            logger.exception("Security approval failed.")
            return {
                "approved": False,
                "reason": f"Security approval error: {exc}",
                "payload": approval_payload,
            }

    def _prepare_verification_payload(
        self,
        action: AutomationActionType,
        context: AutomationTaskContext,
        result: Dict[str, Any],
        input_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        This does not force verification directly. It prepares the data so the
        Master Agent, Router, or Verification Agent can process it.
        """
        return {
            "verification_type": "system_automation_action",
            "agent": self.agent_name,
            "action": action.value,
            "success": result.get("success", False),
            "message": result.get("message"),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "input_payload": input_payload,
            "result_data": result.get("data", {}),
            "timestamp": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        action: AutomationActionType,
        context: AutomationTaskContext,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This stores useful non-sensitive operational context only.
        """
        return {
            "memory_type": "system_automation_history",
            "agent": self.agent_name,
            "action": action.value,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "summary": result.get("message"),
            "success": result.get("success", False),
            "timestamp": self._utc_now(),
            "metadata": {
                "module": self.module_path,
                "runtime_id": self.runtime_id,
            },
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit event for dashboard/API/Master Agent integrations.
        """
        try:
            if self.event_emitter:
                self.event_emitter(event_name, payload)
                return

            if hasattr(self, "emit_event"):
                try:
                    self.emit_event(event_name, payload)  # type: ignore
                    return
                except Exception:
                    pass

            logger.info("Agent event: %s | %s", event_name, payload)

        except Exception as exc:
            logger.warning("Failed to emit agent event %s: %s", event_name, exc)

    def _log_audit_event(
        self,
        context: AutomationTaskContext,
        action: AutomationActionType,
        payload: Dict[str, Any],
        result: Dict[str, Any],
    ) -> None:
        """
        Log audit event with user/workspace isolation.
        """
        audit_payload = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "module": self.module_path,
            "action": action.value,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "input_payload": self._redact_sensitive_payload(payload),
            "success": result.get("success", False),
            "message": result.get("message"),
            "error": result.get("error"),
            "timestamp": self._utc_now(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_payload)
            else:
                logger.info("Audit event: %s", audit_payload)
        except Exception as exc:
            logger.warning("Audit logging failed: %s", exc)

    def _redact_sensitive_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact sensitive fields before audit/event logging.
        """
        redacted = dict(payload)
        sensitive_keys = {
            "password",
            "secret",
            "token",
            "api_key",
            "access_token",
            "refresh_token",
            "authorization",
        }

        for key in list(redacted.keys()):
            if key.lower() in sensitive_keys:
                redacted[key] = "***REDACTED***"

        if "text" in redacted:
            text = str(redacted["text"])
            redacted["text_preview"] = text[:80]
            redacted["text_length"] = len(text)
            redacted["text"] = "***TEXT_REDACTED_FOR_AUDIT***"

        return redacted

    def _should_execute(self, execute: Optional[bool]) -> bool:
        """
        Decide whether real automation should execute.
        """
        if not self.config.execution_enabled:
            return False

        if execute is None:
            return not self.config.dry_run_default

        return bool(execute)

    def _validate_pyautogui_available(self) -> Optional[Dict[str, Any]]:
        if not PYAUTOGUI_AVAILABLE or pyautogui is None:
            return self._error_result(
                message="pyautogui is not installed or unavailable.",
                error="Install dependency: pip install pyautogui",
                metadata={"dependency": "pyautogui"},
            )
        return None

    def _validate_coordinates(
        self,
        x: Optional[int],
        y: Optional[int],
    ) -> Optional[str]:
        if x is None or y is None:
            return "Both x and y coordinates are required."

        if not isinstance(x, int) or not isinstance(y, int):
            return "Coordinates must be integers."

        if x < 0 or y < 0:
            return "Coordinates cannot be negative."

        if self.config.allowed_screen_width is not None and x > self.config.allowed_screen_width:
            return f"x coordinate exceeds allowed screen width: {self.config.allowed_screen_width}"

        if self.config.allowed_screen_height is not None and y > self.config.allowed_screen_height:
            return f"y coordinate exceeds allowed screen height: {self.config.allowed_screen_height}"

        return None

    def _finalize_action(
        self,
        action: AutomationActionType,
        context: AutomationTaskContext,
        input_payload: Dict[str, Any],
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Attach verification and memory payloads, emit events, and log audit.
        """
        verification_payload = self._prepare_verification_payload(
            action=action,
            context=context,
            result=result,
            input_payload=input_payload,
        )

        memory_payload = self._prepare_memory_payload(
            action=action,
            context=context,
            result=result,
        )

        result.setdefault("metadata", {})
        result["metadata"]["verification_payload"] = verification_payload
        result["metadata"]["memory_payload"] = memory_payload

        self._emit_agent_event(
            event_name="system_automation_action_completed",
            payload={
                "action": action.value,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "request_id": context.request_id,
                "success": result.get("success", False),
                "timestamp": self._utc_now(),
            },
        )

        self._log_audit_event(
            context=context,
            action=action,
            payload=input_payload,
            result=result,
        )

        return result

    def _run_guarded_action(
        self,
        action: AutomationActionType,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
        payload: Dict[str, Any],
        executor: Callable[[], Dict[str, Any]],
        execute: Optional[bool] = None,
        risk_level: AutomationRiskLevel = AutomationRiskLevel.MEDIUM,
    ) -> Dict[str, Any]:
        """
        Shared validation/security/execution wrapper.
        """
        valid, normalized_context, context_error = self._validate_task_context(context)
        if not valid or normalized_context is None:
            return self._error_result(
                message="Automation task context validation failed.",
                error=context_error,
                data={"payload": self._redact_sensitive_payload(payload)},
            )

        real_execution = self._should_execute(execute)

        guarded_payload = {
            **payload,
            "execute": real_execution,
            "dry_run": not real_execution,
            "platform": platform.platform(),
        }

        if real_execution:
            dependency_error = self._validate_pyautogui_available()
            if dependency_error:
                return self._finalize_action(
                    action,
                    normalized_context,
                    guarded_payload,
                    dependency_error,
                )

            approval = self._request_security_approval(
                action=action,
                context=normalized_context,
                payload=guarded_payload,
                risk_level=risk_level,
            )

            if not approval.get("approved"):
                result = self._error_result(
                    message="Automation blocked by security approval layer.",
                    error=approval.get("reason"),
                    data={
                        "action": action.value,
                        "approved": False,
                        "security": approval,
                    },
                )
                return self._finalize_action(
                    action,
                    normalized_context,
                    guarded_payload,
                    result,
                )

        try:
            if not real_execution:
                result = self._safe_result(
                    message=f"Dry-run completed for automation action: {action.value}",
                    data={
                        "action": action.value,
                        "dry_run": True,
                        "would_execute": guarded_payload,
                    },
                )
            else:
                result = executor()

            return self._finalize_action(
                action,
                normalized_context,
                guarded_payload,
                result,
            )

        except Exception as exc:
            logger.exception("Automation action failed: %s", action.value)
            result = self._error_result(
                message=f"Automation action failed: {action.value}",
                error=exc,
                data={"action": action.value},
            )
            return self._finalize_action(
                action,
                normalized_context,
                guarded_payload,
                result,
            )

    # -----------------------------------------------------------------------
    # Public information methods
    # -----------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """
        Health check for dashboard/API.
        """
        return self._safe_result(
            message="SystemAutomation health check completed.",
            data={
                "agent": self.agent_name,
                "module": self.module_path,
                "runtime_id": self.runtime_id,
                "created_at": self.created_at,
                "pyautogui_available": PYAUTOGUI_AVAILABLE,
                "execution_enabled": self.config.execution_enabled,
                "dry_run_default": self.config.dry_run_default,
                "require_security_approval": self.config.require_security_approval,
                "platform": platform.platform(),
            },
        )

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Return automation capabilities for Registry/Master Agent.
        """
        return self._safe_result(
            message="SystemAutomation capabilities loaded.",
            data={
                "actions": [action.value for action in AutomationActionType],
                "supports_mouse": True,
                "supports_keyboard": True,
                "supports_scroll": True,
                "supports_hotkeys": True,
                "supports_macros": True,
                "supports_dry_run": True,
                "requires_context": ["user_id", "workspace_id"],
                "security_gated": True,
                "pyautogui_available": PYAUTOGUI_AVAILABLE,
            },
        )

    def get_screen_size(
        self,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
        execute: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Get screen size.
        """
        payload = {}

        def executor() -> Dict[str, Any]:
            assert pyautogui is not None
            width, height = pyautogui.size()
            return self._safe_result(
                message="Screen size retrieved.",
                data={"width": width, "height": height},
            )

        return self._run_guarded_action(
            action=AutomationActionType.POSITION,
            context=context,
            payload=payload,
            executor=executor,
            execute=execute,
            risk_level=AutomationRiskLevel.LOW,
        )

    def get_mouse_position(
        self,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
        execute: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Get current mouse position.
        """
        payload = {}

        def executor() -> Dict[str, Any]:
            assert pyautogui is not None
            x, y = pyautogui.position()
            return self._safe_result(
                message="Mouse position retrieved.",
                data={"x": x, "y": y},
            )

        return self._run_guarded_action(
            action=AutomationActionType.POSITION,
            context=context,
            payload=payload,
            executor=executor,
            execute=execute,
            risk_level=AutomationRiskLevel.LOW,
        )

    # -----------------------------------------------------------------------
    # Mouse methods
    # -----------------------------------------------------------------------

    def move_to(
        self,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
        x: int,
        y: int,
        duration: float = 0.2,
        execute: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Move mouse to x/y.
        """
        payload = {"x": x, "y": y, "duration": duration}

        coord_error = self._validate_coordinates(x, y)
        if coord_error:
            return self._error_result("Invalid coordinates.", coord_error, data=payload)

        duration = max(0.0, min(float(duration), self.config.max_drag_duration))

        def executor() -> Dict[str, Any]:
            assert pyautogui is not None
            pyautogui.moveTo(x, y, duration=duration)
            return self._safe_result(
                message="Mouse moved successfully.",
                data={"x": x, "y": y, "duration": duration},
            )

        return self._run_guarded_action(
            action=AutomationActionType.MOVE,
            context=context,
            payload=payload,
            executor=executor,
            execute=execute,
            risk_level=AutomationRiskLevel.MEDIUM,
        )

    def click(
        self,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
        x: Optional[int] = None,
        y: Optional[int] = None,
        button: str = "left",
        clicks: int = 1,
        interval: float = 0.05,
        execute: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Click at optional x/y position.

        If x/y are not provided, pyautogui clicks current mouse position.
        """
        button = button.lower().strip()
        payload = {
            "x": x,
            "y": y,
            "button": button,
            "clicks": clicks,
            "interval": interval,
        }

        if button not in {"left", "right", "middle"}:
            return self._error_result("Invalid mouse button.", "Use left, right, or middle.", data=payload)

        if x is not None or y is not None:
            coord_error = self._validate_coordinates(x, y)
            if coord_error:
                return self._error_result("Invalid coordinates.", coord_error, data=payload)

        if clicks < 1 or clicks > self.config.max_clicks_per_action:
            return self._error_result(
                "Invalid click count.",
                f"clicks must be between 1 and {self.config.max_clicks_per_action}.",
                data=payload,
            )

        def executor() -> Dict[str, Any]:
            assert pyautogui is not None
            if x is not None and y is not None:
                pyautogui.click(x=x, y=y, clicks=clicks, interval=interval, button=button)
            else:
                pyautogui.click(clicks=clicks, interval=interval, button=button)

            return self._safe_result(
                message="Mouse click completed.",
                data=payload,
            )

        return self._run_guarded_action(
            action=AutomationActionType.CLICK,
            context=context,
            payload=payload,
            executor=executor,
            execute=execute,
            risk_level=AutomationRiskLevel.HIGH,
        )

    def double_click(
        self,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
        x: Optional[int] = None,
        y: Optional[int] = None,
        button: str = "left",
        interval: float = 0.05,
        execute: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Double click at optional x/y position.
        """
        return self.click(
            context=context,
            x=x,
            y=y,
            button=button,
            clicks=2,
            interval=interval,
            execute=execute,
        )

    def right_click(
        self,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
        x: Optional[int] = None,
        y: Optional[int] = None,
        execute: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Right click at optional x/y position.
        """
        return self.click(
            context=context,
            x=x,
            y=y,
            button="right",
            clicks=1,
            execute=execute,
        )

    def drag_to(
        self,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
        x: int,
        y: int,
        duration: float = 0.5,
        button: str = "left",
        execute: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Drag mouse to x/y.
        """
        button = button.lower().strip()
        payload = {"x": x, "y": y, "duration": duration, "button": button}

        coord_error = self._validate_coordinates(x, y)
        if coord_error:
            return self._error_result("Invalid coordinates.", coord_error, data=payload)

        if button not in {"left", "right", "middle"}:
            return self._error_result("Invalid mouse button.", "Use left, right, or middle.", data=payload)

        duration = max(0.0, min(float(duration), self.config.max_drag_duration))

        def executor() -> Dict[str, Any]:
            assert pyautogui is not None
            pyautogui.dragTo(x=x, y=y, duration=duration, button=button)
            return self._safe_result(
                message="Mouse drag completed.",
                data=payload,
            )

        return self._run_guarded_action(
            action=AutomationActionType.DRAG,
            context=context,
            payload=payload,
            executor=executor,
            execute=execute,
            risk_level=AutomationRiskLevel.HIGH,
        )

    def scroll(
        self,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
        amount: int,
        x: Optional[int] = None,
        y: Optional[int] = None,
        execute: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Scroll vertically.

        Positive amount usually scrolls up.
        Negative amount usually scrolls down.
        """
        payload = {"amount": amount, "x": x, "y": y}

        if not isinstance(amount, int):
            return self._error_result("Invalid scroll amount.", "amount must be integer.", data=payload)

        if abs(amount) > self.config.max_scroll_amount:
            return self._error_result(
                "Scroll amount exceeds safety limit.",
                f"Max allowed absolute amount is {self.config.max_scroll_amount}.",
                data=payload,
            )

        if x is not None or y is not None:
            coord_error = self._validate_coordinates(x, y)
            if coord_error:
                return self._error_result("Invalid coordinates.", coord_error, data=payload)

        def executor() -> Dict[str, Any]:
            assert pyautogui is not None
            if x is not None and y is not None:
                pyautogui.scroll(amount, x=x, y=y)
            else:
                pyautogui.scroll(amount)

            return self._safe_result(
                message="Scroll completed.",
                data=payload,
            )

        return self._run_guarded_action(
            action=AutomationActionType.SCROLL,
            context=context,
            payload=payload,
            executor=executor,
            execute=execute,
            risk_level=AutomationRiskLevel.MEDIUM,
        )

    # -----------------------------------------------------------------------
    # Keyboard methods
    # -----------------------------------------------------------------------

    def type_text(
        self,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
        text: str,
        interval: float = 0.01,
        execute: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Type text safely.

        Audit logs redact actual text and store only preview/length.
        """
        payload = {
            "text": text,
            "text_length": len(text or ""),
            "interval": interval,
        }

        if not isinstance(text, str):
            return self._error_result("Invalid text.", "text must be a string.", data={})

        if len(text) > self.config.max_text_length:
            return self._error_result(
                "Text exceeds safety limit.",
                f"Max text length is {self.config.max_text_length}.",
                data={"text_length": len(text)},
            )

        interval = max(0.0, float(interval))

        def executor() -> Dict[str, Any]:
            assert pyautogui is not None
            pyautogui.write(text, interval=interval)
            return self._safe_result(
                message="Text typing completed.",
                data={
                    "text_length": len(text),
                    "interval": interval,
                },
            )

        return self._run_guarded_action(
            action=AutomationActionType.TYPE_TEXT,
            context=context,
            payload=payload,
            executor=executor,
            execute=execute,
            risk_level=AutomationRiskLevel.HIGH,
        )

    def press_key(
        self,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
        key: str,
        presses: int = 1,
        interval: float = 0.05,
        execute: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Press a keyboard key.
        """
        key = str(key).strip().lower()
        payload = {"key": key, "presses": presses, "interval": interval}

        if not key:
            return self._error_result("Invalid key.", "key cannot be empty.", data=payload)

        if presses < 1 or presses > self.config.max_clicks_per_action:
            return self._error_result(
                "Invalid press count.",
                f"presses must be between 1 and {self.config.max_clicks_per_action}.",
                data=payload,
            )

        def executor() -> Dict[str, Any]:
            assert pyautogui is not None
            pyautogui.press(key, presses=presses, interval=interval)
            return self._safe_result(
                message="Key press completed.",
                data=payload,
            )

        return self._run_guarded_action(
            action=AutomationActionType.PRESS_KEY,
            context=context,
            payload=payload,
            executor=executor,
            execute=execute,
            risk_level=AutomationRiskLevel.HIGH,
        )

    def hotkey(
        self,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
        keys: List[str],
        execute: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Press a keyboard hotkey combination.
        Example:
            hotkey(context, ["ctrl", "c"])
        """
        normalized_keys = [str(k).strip().lower() for k in keys if str(k).strip()]
        payload = {"keys": normalized_keys}

        if not normalized_keys:
            return self._error_result("Invalid hotkey.", "At least one key is required.", data=payload)

        if len(normalized_keys) > 5:
            return self._error_result("Hotkey too long.", "Maximum 5 keys allowed.", data=payload)

        def executor() -> Dict[str, Any]:
            assert pyautogui is not None
            pyautogui.hotkey(*normalized_keys)
            return self._safe_result(
                message="Hotkey completed.",
                data=payload,
            )

        return self._run_guarded_action(
            action=AutomationActionType.HOTKEY,
            context=context,
            payload=payload,
            executor=executor,
            execute=execute,
            risk_level=AutomationRiskLevel.HIGH,
        )

    # -----------------------------------------------------------------------
    # Screenshot method
    # -----------------------------------------------------------------------

    def screenshot(
        self,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
        save_path: Optional[str] = None,
        execute: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Capture screenshot.

        If save_path is provided, screenshot is saved there.
        Otherwise, only an in-memory screenshot object is created and summarized.
        """
        payload = {"save_path": save_path}

        def executor() -> Dict[str, Any]:
            assert pyautogui is not None
            image = pyautogui.screenshot()

            saved = False
            if save_path:
                image.save(save_path)
                saved = True

            return self._safe_result(
                message="Screenshot captured.",
                data={
                    "saved": saved,
                    "save_path": save_path,
                    "image_size": getattr(image, "size", None),
                },
            )

        return self._run_guarded_action(
            action=AutomationActionType.SCREENSHOT,
            context=context,
            payload=payload,
            executor=executor,
            execute=execute,
            risk_level=AutomationRiskLevel.MEDIUM,
        )

    # -----------------------------------------------------------------------
    # Macro execution
    # -----------------------------------------------------------------------

    def run_macro(
        self,
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]],
        commands: List[Union[AutomationCommand, Dict[str, Any]]],
        stop_on_error: bool = True,
        execute: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Run a list of automation commands.

        Supported command actions:
            - click
            - double_click
            - right_click
            - move
            - drag
            - type_text
            - press_key
            - hotkey
            - scroll
            - pause
            - screenshot

        Macro safety:
            - validates context once
            - limits max macro length
            - every command returns structured result
            - can stop on first error
        """
        payload = {
            "command_count": len(commands or []),
            "stop_on_error": stop_on_error,
        }

        if not isinstance(commands, list):
            return self._error_result("Invalid macro.", "commands must be a list.", data=payload)

        if len(commands) > self.config.max_macro_steps:
            return self._error_result(
                "Macro exceeds safety step limit.",
                f"Maximum allowed steps: {self.config.max_macro_steps}",
                data=payload,
            )

        valid, normalized_context, context_error = self._validate_task_context(context)
        if not valid or normalized_context is None:
            return self._error_result(
                message="Automation task context validation failed.",
                error=context_error,
                data=payload,
            )

        real_execution = self._should_execute(execute)

        macro_payload = {
            **payload,
            "execute": real_execution,
            "dry_run": not real_execution,
            "commands": [
                asdict(cmd) if isinstance(cmd, AutomationCommand) else dict(cmd)
                for cmd in commands
            ],
        }

        if real_execution:
            dependency_error = self._validate_pyautogui_available()
            if dependency_error:
                return self._finalize_action(
                    AutomationActionType.MACRO,
                    normalized_context,
                    macro_payload,
                    dependency_error,
                )

            approval = self._request_security_approval(
                action=AutomationActionType.MACRO,
                context=normalized_context,
                payload=macro_payload,
                risk_level=AutomationRiskLevel.HIGH,
            )

            if not approval.get("approved"):
                result = self._error_result(
                    message="Macro blocked by security approval layer.",
                    error=approval.get("reason"),
                    data={"approved": False, "security": approval},
                )
                return self._finalize_action(
                    AutomationActionType.MACRO,
                    normalized_context,
                    macro_payload,
                    result,
                )

        results: List[Dict[str, Any]] = []

        for index, raw_command in enumerate(commands):
            command = self._normalize_command(raw_command)
            command_result = self._execute_macro_command(
                context=normalized_context,
                command=command,
                execute=real_execution,
                index=index,
            )

            results.append(command_result)

            if stop_on_error and not command_result.get("success"):
                break

            pause_value = command.pause
            if pause_value is None:
                pause_value = self.config.pause_between_actions

            if real_execution and pause_value > 0:
                time.sleep(float(pause_value))

        success = all(item.get("success") for item in results)

        result = self._safe_result(
            message="Macro completed successfully." if success else "Macro completed with one or more errors.",
            data={
                "success_count": sum(1 for item in results if item.get("success")),
                "error_count": sum(1 for item in results if not item.get("success")),
                "total_commands": len(commands),
                "results": results,
                "dry_run": not real_execution,
            },
        )

        if not success:
            result["success"] = False
            result["error"] = "One or more macro commands failed."

        return self._finalize_action(
            AutomationActionType.MACRO,
            normalized_context,
            macro_payload,
            result,
        )

    def _normalize_command(
        self,
        command: Union[AutomationCommand, Dict[str, Any]],
    ) -> AutomationCommand:
        if isinstance(command, AutomationCommand):
            return command

        return AutomationCommand(
            action=str(command.get("action", "")).strip(),
            x=command.get("x"),
            y=command.get("y"),
            x2=command.get("x2"),
            y2=command.get("y2"),
            text=command.get("text"),
            key=command.get("key"),
            keys=command.get("keys"),
            button=str(command.get("button", "left")),
            clicks=int(command.get("clicks", 1)),
            interval=float(command.get("interval", 0.05)),
            duration=float(command.get("duration", 0.2)),
            amount=command.get("amount"),
            pause=command.get("pause"),
            metadata=dict(command.get("metadata") or {}),
        )

    def _execute_macro_command(
        self,
        context: AutomationTaskContext,
        command: AutomationCommand,
        execute: bool,
        index: int,
    ) -> Dict[str, Any]:
        """
        Execute one macro command.

        This intentionally calls direct pyautogui only after run_macro has
        already completed macro-level context/security validation.
        """
        action = command.action.strip().lower()

        try:
            if not execute:
                return self._safe_result(
                    message=f"Dry-run macro step {index + 1}: {action}",
                    data={
                        "index": index,
                        "command": asdict(command),
                        "dry_run": True,
                    },
                )

            assert pyautogui is not None

            if action == AutomationActionType.PAUSE.value:
                pause_time = float(command.pause if command.pause is not None else command.duration)
                pause_time = max(0.0, min(pause_time, 60.0))
                time.sleep(pause_time)
                return self._safe_result(
                    message=f"Macro pause completed at step {index + 1}.",
                    data={"index": index, "pause": pause_time},
                )

            if action == AutomationActionType.MOVE.value:
                coord_error = self._validate_coordinates(command.x, command.y)
                if coord_error:
                    return self._error_result("Invalid move command.", coord_error, data=asdict(command))
                pyautogui.moveTo(command.x, command.y, duration=command.duration)
                return self._safe_result("Macro move completed.", data={"index": index, "command": asdict(command)})

            if action == AutomationActionType.CLICK.value:
                if command.x is not None or command.y is not None:
                    coord_error = self._validate_coordinates(command.x, command.y)
                    if coord_error:
                        return self._error_result("Invalid click command.", coord_error, data=asdict(command))
                    pyautogui.click(
                        x=command.x,
                        y=command.y,
                        clicks=command.clicks,
                        interval=command.interval,
                        button=command.button,
                    )
                else:
                    pyautogui.click(
                        clicks=command.clicks,
                        interval=command.interval,
                        button=command.button,
                    )
                return self._safe_result("Macro click completed.", data={"index": index, "command": asdict(command)})

            if action == AutomationActionType.DOUBLE_CLICK.value:
                if command.x is not None and command.y is not None:
                    pyautogui.doubleClick(x=command.x, y=command.y, button=command.button)
                else:
                    pyautogui.doubleClick(button=command.button)
                return self._safe_result("Macro double click completed.", data={"index": index, "command": asdict(command)})

            if action == AutomationActionType.RIGHT_CLICK.value:
                if command.x is not None and command.y is not None:
                    pyautogui.rightClick(x=command.x, y=command.y)
                else:
                    pyautogui.rightClick()
                return self._safe_result("Macro right click completed.", data={"index": index, "command": asdict(command)})

            if action == AutomationActionType.DRAG.value:
                coord_error = self._validate_coordinates(command.x, command.y)
                if coord_error:
                    return self._error_result("Invalid drag command.", coord_error, data=asdict(command))
                pyautogui.dragTo(
                    x=command.x,
                    y=command.y,
                    duration=command.duration,
                    button=command.button,
                )
                return self._safe_result("Macro drag completed.", data={"index": index, "command": asdict(command)})

            if action == AutomationActionType.TYPE_TEXT.value:
                if command.text is None:
                    return self._error_result("Invalid type_text command.", "text is required.", data=asdict(command))
                if len(command.text) > self.config.max_text_length:
                    return self._error_result("Text too long.", "Command text exceeds max_text_length.", data={"index": index})
                pyautogui.write(command.text, interval=command.interval)
                return self._safe_result(
                    "Macro text typing completed.",
                    data={
                        "index": index,
                        "text_length": len(command.text),
                    },
                )

            if action == AutomationActionType.PRESS_KEY.value:
                if not command.key:
                    return self._error_result("Invalid press_key command.", "key is required.", data=asdict(command))
                pyautogui.press(command.key, presses=command.clicks, interval=command.interval)
                return self._safe_result("Macro key press completed.", data={"index": index, "key": command.key})

            if action == AutomationActionType.HOTKEY.value:
                if not command.keys:
                    return self._error_result("Invalid hotkey command.", "keys list is required.", data=asdict(command))
                pyautogui.hotkey(*command.keys)
                return self._safe_result("Macro hotkey completed.", data={"index": index, "keys": command.keys})

            if action == AutomationActionType.SCROLL.value:
                if command.amount is None:
                    return self._error_result("Invalid scroll command.", "amount is required.", data=asdict(command))
                if abs(int(command.amount)) > self.config.max_scroll_amount:
                    return self._error_result("Scroll too large.", "amount exceeds max_scroll_amount.", data=asdict(command))

                if command.x is not None and command.y is not None:
                    pyautogui.scroll(int(command.amount), x=command.x, y=command.y)
                else:
                    pyautogui.scroll(int(command.amount))

                return self._safe_result("Macro scroll completed.", data={"index": index, "amount": command.amount})

            if action == AutomationActionType.SCREENSHOT.value:
                image = pyautogui.screenshot()
                save_path = command.metadata.get("save_path")
                saved = False
                if save_path:
                    image.save(save_path)
                    saved = True
                return self._safe_result(
                    "Macro screenshot completed.",
                    data={
                        "index": index,
                        "saved": saved,
                        "save_path": save_path,
                        "image_size": getattr(image, "size", None),
                    },
                )

            return self._error_result(
                message=f"Unsupported macro action at step {index + 1}.",
                error=f"Unsupported action: {action}",
                data={"index": index, "command": asdict(command)},
            )

        except Exception as exc:
            logger.exception("Macro command failed at index %s", index)
            return self._error_result(
                message=f"Macro command failed at step {index + 1}.",
                error=exc,
                data={"index": index, "command": asdict(command)},
            )

    # -----------------------------------------------------------------------
    # Router-compatible method
    # -----------------------------------------------------------------------

    def handle_task(
        self,
        task: Dict[str, Any],
        context: Optional[Union[AutomationTaskContext, Dict[str, Any], AgentContext]] = None,
    ) -> Dict[str, Any]:
        """
        Master Agent / Router compatible task handler.

        Expected task format:
            {
                "action": "click",
                "params": {...},
                "execute": false
            }
        """
        if not isinstance(task, dict):
            return self._error_result("Invalid task.", "task must be a dict.")

        action = str(task.get("action", "")).strip().lower()
        params = dict(task.get("params") or {})
        execute = task.get("execute")

        if context is None:
            context = task.get("context")

        try:
            if action == AutomationActionType.CLICK.value:
                return self.click(context=context, execute=execute, **params)

            if action == AutomationActionType.DOUBLE_CLICK.value:
                return self.double_click(context=context, execute=execute, **params)

            if action == AutomationActionType.RIGHT_CLICK.value:
                return self.right_click(context=context, execute=execute, **params)

            if action == AutomationActionType.MOVE.value:
                return self.move_to(context=context, execute=execute, **params)

            if action == AutomationActionType.DRAG.value:
                return self.drag_to(context=context, execute=execute, **params)

            if action == AutomationActionType.TYPE_TEXT.value:
                return self.type_text(context=context, execute=execute, **params)

            if action == AutomationActionType.PRESS_KEY.value:
                return self.press_key(context=context, execute=execute, **params)

            if action == AutomationActionType.HOTKEY.value:
                return self.hotkey(context=context, execute=execute, **params)

            if action == AutomationActionType.SCROLL.value:
                return self.scroll(context=context, execute=execute, **params)

            if action == AutomationActionType.SCREENSHOT.value:
                return self.screenshot(context=context, execute=execute, **params)

            if action == AutomationActionType.MACRO.value:
                return self.run_macro(context=context, execute=execute, **params)

            if action == "health_check":
                return self.health_check()

            if action == "capabilities":
                return self.get_capabilities()

            if action == "screen_size":
                return self.get_screen_size(context=context, execute=execute)

            if action == "mouse_position":
                return self.get_mouse_position(context=context, execute=execute)

            return self._error_result(
                message="Unsupported automation task action.",
                error=f"Unsupported action: {action}",
                data={"task": task},
            )

        except TypeError as exc:
            return self._error_result(
                message="Invalid parameters for automation task.",
                error=exc,
                data={"action": action, "params": params},
            )

        except Exception as exc:
            logger.exception("handle_task failed.")
            return self._error_result(
                message="Automation task handling failed.",
                error=exc,
                data={"action": action},
            )


# ---------------------------------------------------------------------------
# Registry helper
# ---------------------------------------------------------------------------

def get_agent() -> SystemAutomation:
    """
    Agent Loader / Registry compatible factory.
    """
    return SystemAutomation()


def get_module_info() -> Dict[str, Any]:
    """
    Static module metadata for Agent Registry / Dashboard.
    """
    return {
        "agent_name": "SystemAutomation",
        "agent_type": "system_agent_helper",
        "module_path": "agents/system_agent/automation.py",
        "class_name": "SystemAutomation",
        "capabilities": [action.value for action in AutomationActionType],
        "requires_user_context": True,
        "requires_workspace_context": True,
        "security_gated": True,
        "safe_to_import": True,
        "pyautogui_available": PYAUTOGUI_AVAILABLE,
        "version": "1.0.0",
    }


__all__ = [
    "AutomationActionType",
    "AutomationRiskLevel",
    "AutomationConfig",
    "AutomationTaskContext",
    "AutomationCommand",
    "SystemAutomation",
    "get_agent",
    "get_module_info",
]


# FILE COMPLETE