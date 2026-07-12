"""
core/planner.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Breaks a user request into ordered task steps with agent intent,
    risk level, dependencies, and expected result.

This file is intentionally import-safe:
    - It can import even if future files are not created yet.
    - It does not execute real system/browser/financial/call/message/destructive actions.
    - It only creates safe structured plans.
    - Every result follows William/Jarvis structured dict format:
      success, message, data, error, metadata.

Main Class:
    Planner
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union, Tuple


# =============================================================================
# Optional CoreConfig import with fallback
# =============================================================================

try:
    from core.config import get_core_config  # type: ignore
except Exception:  # pragma: no cover
    get_core_config = None  # type: ignore


# =============================================================================
# Constants
# =============================================================================

DEFAULT_AGENT_NAMES: List[str] = [
    "master",
    "voice",
    "system",
    "browser",
    "code",
    "memory",
    "security",
    "verification",
    "visual",
    "workflow",
    "hologram",
    "call",
    "business",
    "finance",
    "creator",
]

SENSITIVE_AGENT_NAMES: List[str] = [
    "system",
    "browser",
    "code",
    "call",
    "finance",
    "security",
]

HIGH_RISK_ACTIONS: List[str] = [
    "delete",
    "destroy",
    "send_email",
    "send_message",
    "make_call",
    "transfer_money",
    "purchase",
    "execute_code",
    "run_terminal",
    "browser_submit",
    "modify_file",
    "upload_file",
    "download_file",
    "external_api_write",
    "change_permissions",
    "change_subscription",
]

RISK_LEVELS: List[str] = [
    "low",
    "medium",
    "high",
    "critical",
]

DEFAULT_PLANNER_CONFIDENCE = 0.72


# =============================================================================
# Helper functions
# =============================================================================

def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    """Return readable unique ID."""
    return f"{prefix}_{uuid.uuid4().hex}"


def _normalize_text(value: Any) -> str:
    """Normalize text safely."""
    if value is None:
        return ""
    return str(value).strip()


def _normalize_agent_name(value: Any) -> str:
    """Normalize agent name safely."""
    text = str(value or "").strip().lower()
    return text or "business"


def _safe_lower(value: Any) -> str:
    """Safe lowercase string conversion."""
    return str(value or "").strip().lower()


def _safe_json(value: Any) -> str:
    """Safely convert value to JSON."""
    try:
        return json.dumps(value, default=str, ensure_ascii=False)
    except Exception:
        return str(value)


_KEYWORD_PATTERN_CACHE: Dict[str, "re.Pattern[str]"] = {}


def _keyword_matches(keyword: str, text: str) -> bool:
    """
    Word/phrase-boundary keyword match -- NOT a raw substring check.

    A plain `keyword in text` check false-positives whenever the keyword is
    a substring of an unrelated word: e.g. the routing keyword "click"
    (meant to detect browser actions) matched inside the brand name
    "ClickRonix", silently routing "create a VEO prompt for ClickRonix" to
    a browser_action step instead of the Creator Agent. `\\b` boundaries
    require the keyword to start/end on a real word edge, so "click"
    matches "click here" but not "clickronix", while multi-word phrases
    like "open website" still match as a whole phrase.
    """
    pattern = _KEYWORD_PATTERN_CACHE.get(keyword)
    if pattern is None:
        pattern = re.compile(r"\b" + re.escape(keyword) + r"\b")
        _KEYWORD_PATTERN_CACHE[keyword] = pattern
    return pattern.search(text) is not None


def _dedupe_keep_order(items: List[str]) -> List[str]:
    """Deduplicate list while preserving order."""
    seen = set()
    result: List[str] = []

    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)

    return result


# =============================================================================
# Fallback Config
# =============================================================================

class FallbackPlannerConfig:
    """
    Minimal fallback config.

    Used only when core/config.py is not available.
    """

    def __init__(self) -> None:
        self.routing_config = type(
            "RoutingConfig",
            (),
            {
                "registered_agents": DEFAULT_AGENT_NAMES,
                "sensitive_agents": SENSITIVE_AGENT_NAMES,
                "default_agent": "master",
                "fallback_agent": "business",
                "minimum_router_confidence": 0.55,
                "max_routing_attempts": 3,
            },
        )()

        self.safety_config = type(
            "SafetyConfig",
            (),
            {
                "safe_mode": True,
                "strict_mode": True,
                "require_security_for_sensitive_agents": True,
                "require_security_for_high_risk_actions": True,
                "require_user_confirmation_for_sensitive_actions": True,
                "block_destructive_actions_by_default": True,
                "high_risk_actions": HIGH_RISK_ACTIONS,
            },
        )()

        self.saas_config = type(
            "SaaSConfig",
            (),
            {
                "require_user_id": True,
                "require_workspace_id": True,
                "enforce_workspace_isolation": True,
                "default_workspace_role": "member",
                "default_subscription_plan": "free",
            },
        )()

        self.memory_config = type(
            "MemoryConfig",
            (),
            {
                "enable_memory_agent": True,
                "auto_prepare_memory_payload": True,
                "write_completed_tasks_to_memory": True,
                "memory_scope": "workspace",
            },
        )()

        self.verification_config = type(
            "VerificationConfig",
            (),
            {
                "enable_verification_agent": True,
                "auto_prepare_verification_payload": True,
                "verify_completed_actions": True,
                "verify_sensitive_actions": True,
                "verification_level": "standard",
            },
        )()

        self.logger = logging.getLogger("william.core.planner.fallback")
        if not self.logger.handlers:
            self.logger.addHandler(logging.StreamHandler())
        self.logger.setLevel(logging.INFO)

    def _safe_result(
        self,
        message: str = "Success.",
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": {
                "module": "core.planner",
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str = "Error.",
        error: Optional[Any] = None,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": str(error) if error is not None else "UNKNOWN_ERROR",
            "metadata": {
                "module": "core.planner",
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _validate_task_context(self, context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        context = context or {}

        missing: List[str] = []

        if self.saas_config.require_user_id and not context.get("user_id"):
            missing.append("user_id")

        if self.saas_config.require_workspace_id and not context.get("workspace_id"):
            missing.append("workspace_id")

        if missing:
            return self._error_result(
                message="Task context failed SaaS isolation validation.",
                error="MISSING_REQUIRED_CONTEXT_FIELDS",
                data={
                    "valid": False,
                    "missing": missing,
                },
            )

        return self._safe_result(
            message="Task context validated successfully.",
            data={
                "valid": True,
                "user_id": context.get("user_id"),
                "workspace_id": context.get("workspace_id"),
            },
        )

    def _requires_security_check(
        self,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        agent = _normalize_agent_name(agent_name)
        action_text = _safe_lower(action)

        reasons: List[str] = []

        if agent in SENSITIVE_AGENT_NAMES:
            reasons.append("sensitive_agent")

        if action_text in HIGH_RISK_ACTIONS:
            reasons.append("high_risk_action")

        if any(word in action_text for word in ["delete", "send", "call", "pay", "execute", "modify"]):
            reasons.append("sensitive_action_keyword")

        if getattr(self.safety_config, "safe_mode", True):
            reasons.append("safe_mode_enabled")

        return self._safe_result(
            message="Security check decision generated.",
            data={
                "requires_security_check": len(reasons) > 0,
                "agent_name": agent,
                "action": action_text,
                "reasons": _dedupe_keep_order(reasons),
            },
        )

    def _request_security_approval(
        self,
        agent_name: Optional[str],
        action: Optional[str],
        context: Optional[Dict[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._safe_result(
            message="Security approval payload prepared.",
            data={
                "approval_required": True,
                "agent_name": _normalize_agent_name(agent_name),
                "action": _safe_lower(action),
                "context": context or {},
                "payload_summary": payload or {},
                "target_agent": "security",
                "created_at": _utc_now_iso(),
            },
        )

    def _prepare_verification_payload(
        self,
        task_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._safe_result(
            message="Verification payload prepared.",
            data={
                "verification_required": True,
                "task_id": task_id,
                "agent_name": agent_name,
                "action": action,
                "result_summary": result or {},
                "context": context or {},
                "target_agent": "verification",
                "created_at": _utc_now_iso(),
            },
        )

    def _prepare_memory_payload(
        self,
        task_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        useful_context: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._safe_result(
            message="Memory payload prepared.",
            data={
                "memory_enabled": True,
                "task_id": task_id,
                "agent_name": agent_name,
                "action": action,
                "useful_context": useful_context or {},
                "context": context or {},
                "target_agent": "memory",
                "created_at": _utc_now_iso(),
            },
        )

    def _emit_agent_event(
        self,
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        event = {
            "event_type": event_type,
            "data": data or {},
            "user_id": user_id,
            "workspace_id": workspace_id,
            "created_at": _utc_now_iso(),
        }
        self.logger.info("AGENT_EVENT %s", _safe_json(event))
        return self._safe_result(message="Agent event emitted.", data=event)

    def _log_audit_event(
        self,
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        event = {
            "event_type": event_type,
            "data": data or {},
            "user_id": user_id,
            "workspace_id": workspace_id,
            "created_at": _utc_now_iso(),
        }
        self.logger.info("AUDIT_EVENT %s", _safe_json(event))
        return self._safe_result(message="Audit event logged.", data=event)


# =============================================================================
# Data structures
# =============================================================================

@dataclass
class PlanDependency:
    """Represents dependency relationship between plan steps."""

    dependency_id: str
    dependency_type: str = "step"
    required: bool = True
    description: str = ""


@dataclass
class PlanStep:
    """
    MasterAgent-compatible plan step.

    MasterAgent expects:
        step_id
        agent_name
        action
        instruction
        requires_security
        requires_verification
        save_to_memory
        input_data
        metadata
    """

    step_id: str
    order: int
    agent_name: str
    intent: str
    action: str
    instruction: str
    risk_level: str = "low"
    dependencies: List[str] = field(default_factory=list)
    expected_result: str = ""
    requires_security: bool = False
    requires_verification: bool = True
    save_to_memory: bool = True
    input_data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PlanResult:
    """Serializable plan result."""

    plan_id: str
    request_id: str
    user_id: Optional[Union[str, int]]
    workspace_id: Optional[Union[str, int]]
    goal: str
    summary: str
    risk_level: str
    steps: List[Dict[str, Any]]
    expected_result: str
    created_at: str = field(default_factory=_utc_now_iso)
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Planner
# =============================================================================

class Planner:
    """
    William/Jarvis Planner.

    Responsibilities:
        - Convert user request into ordered executable steps.
        - Detect target agent intent.
        - Assign risk level.
        - Add dependencies between steps.
        - Mark security requirement.
        - Mark verification requirement.
        - Mark memory-save compatibility.
        - Return MasterAgent-compatible structured plan.

    Important:
        This planner does NOT execute the actions.
        It only prepares a safe plan for MasterAgent, Router, Security Agent,
        Verification Agent, Memory Agent, Dashboard/API, and Task Manager.
    """

    def __init__(
        self,
        config: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        default_confidence: float = DEFAULT_PLANNER_CONFIDENCE,
    ) -> None:
        self.config = config or self._load_config()
        self.logger = logger or getattr(self.config, "logger", None) or logging.getLogger("william.core.planner")

        if not self.logger.handlers:
            self.logger.addHandler(logging.StreamHandler())

        self.logger.setLevel(logging.INFO)
        self.default_confidence = default_confidence

        self.agent_keywords = self._build_agent_keywords()
        self.action_keywords = self._build_action_keywords()
        self.risk_keywords = self._build_risk_keywords()

        self._emit_agent_event(
            event_type="planner_initialized",
            data={
                "default_confidence": self.default_confidence,
                "supported_agents": self.get_supported_agents(),
            },
        )

    # -------------------------------------------------------------------------
    # Config loading
    # -------------------------------------------------------------------------

    def _load_config(self) -> Any:
        """Load CoreConfig safely, otherwise fallback."""
        try:
            if get_core_config is not None:
                return get_core_config()
        except Exception:
            pass

        return FallbackPlannerConfig()

    # -------------------------------------------------------------------------
    # Public planning API
    # -------------------------------------------------------------------------

    async def create_plan(
        self,
        request: Any,
        memory_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Main async planner method used by MasterAgent.

        Accepts either:
            - MasterRequest dataclass-like object
            - dict request

        Returns:
            {
                success,
                message,
                data: {
                    plan_id,
                    request_id,
                    steps,
                    summary,
                    risk_level,
                    expected_result
                },
                error,
                metadata
            }
        """
        return self.plan(
            request=request,
            memory_context=memory_context,
        )

    def plan(
        self,
        request: Any,
        memory_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Sync planning method.

        Safe for:
            - MasterAgent
            - CLI testing
            - API services
            - future dashboard preview
        """
        try:
            normalized_request = self._normalize_request(request)
            context = self._extract_context(normalized_request)

            context_validation = self._validate_task_context(context)
            if not context_validation.get("success"):
                return context_validation

            message = normalized_request["message"]
            action = normalized_request["action"]
            preferred_agent = normalized_request.get("preferred_agent")
            input_data = normalized_request.get("input_data", {})

            if not message and not input_data:
                return self._error_result(
                    message="Planner cannot create plan because request message and input_data are empty.",
                    error="EMPTY_REQUEST",
                    data={
                        "request": normalized_request,
                    },
                )

            intent_result = self.detect_intent(
                message=message,
                action=action,
                preferred_agent=preferred_agent,
                input_data=input_data,
                memory_context=memory_context or {},
            )

            if not intent_result.get("success"):
                return intent_result

            intent_data = intent_result["data"]

            steps = self._build_ordered_steps(
                request=normalized_request,
                intent_data=intent_data,
                memory_context=memory_context or {},
            )

            plan_risk = self._calculate_plan_risk(steps)

            expected_result = self._build_expected_result(
                request=normalized_request,
                steps=steps,
                plan_risk=plan_risk,
            )

            plan_id = _new_id("plan")

            plan_result = PlanResult(
                plan_id=plan_id,
                request_id=normalized_request["request_id"],
                user_id=normalized_request.get("user_id"),
                workspace_id=normalized_request.get("workspace_id"),
                goal=message or action,
                summary=self._build_plan_summary(steps, plan_risk),
                risk_level=plan_risk,
                steps=[asdict(step) for step in steps],
                expected_result=expected_result,
                metadata={
                    "planner": "Planner",
                    "confidence": intent_data.get("confidence", self.default_confidence),
                    "primary_agent": intent_data.get("primary_agent"),
                    "secondary_agents": intent_data.get("secondary_agents", []),
                    "memory_used": bool(memory_context),
                    "created_at": _utc_now_iso(),
                },
            )

            self._log_audit_event(
                event_type="planner_plan_created",
                user_id=normalized_request.get("user_id"),
                workspace_id=normalized_request.get("workspace_id"),
                data={
                    "plan_id": plan_id,
                    "request_id": normalized_request["request_id"],
                    "steps_count": len(steps),
                    "risk_level": plan_risk,
                    "primary_agent": intent_data.get("primary_agent"),
                },
            )

            return self._safe_result(
                message="Planner created ordered task plan successfully.",
                data=asdict(plan_result),
                metadata={
                    "plan_id": plan_id,
                    "request_id": normalized_request["request_id"],
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Planner failed to create plan safely.",
                error=exc,
            )

    def detect_intent(
        self,
        message: str,
        action: str = "general_request",
        preferred_agent: Optional[str] = None,
        input_data: Optional[Dict[str, Any]] = None,
        memory_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Detect primary agent, secondary agents, intent, action type, and risk.

        This method is deterministic and does not call external models.
        """
        try:
            message_text = _safe_lower(message)
            action_text = _safe_lower(action)
            combined_text = f"{message_text} {action_text} {_safe_json(input_data or {})}".lower()

            agent_scores = self._score_agents(combined_text)

            if preferred_agent:
                normalized_preferred = _normalize_agent_name(preferred_agent)
                agent_scores[normalized_preferred] = agent_scores.get(normalized_preferred, 0) + 5

            sorted_agents = sorted(
                agent_scores.items(),
                key=lambda item: item[1],
                reverse=True,
            )

            primary_agent = sorted_agents[0][0] if sorted_agents and sorted_agents[0][1] > 0 else "business"
            secondary_agents = [
                agent for agent, score in sorted_agents[1:4]
                if score > 0 and agent != primary_agent
            ]

            intent = self._detect_task_intent(combined_text, primary_agent)
            normalized_action = self._detect_action_type(combined_text, action_text, primary_agent)
            risk_level, risk_reasons = self._detect_risk_level(
                combined_text=combined_text,
                primary_agent=primary_agent,
                action=normalized_action,
            )

            requires_security = self._plan_requires_security(
                agent_name=primary_agent,
                action=normalized_action,
                risk_level=risk_level,
                text=combined_text,
            )

            confidence = self._calculate_intent_confidence(
                agent_scores=agent_scores,
                primary_agent=primary_agent,
                preferred_agent=preferred_agent,
            )

            return self._safe_result(
                message="Planner intent detected successfully.",
                data={
                    "primary_agent": primary_agent,
                    "secondary_agents": secondary_agents,
                    "intent": intent,
                    "action": normalized_action,
                    "risk_level": risk_level,
                    "risk_reasons": risk_reasons,
                    "requires_security": requires_security,
                    "confidence": confidence,
                    "agent_scores": agent_scores,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Planner failed to detect intent.",
                error=exc,
            )

    def preview_plan(
        self,
        message: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        action: str = "general_request",
        preferred_agent: Optional[str] = None,
        input_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Dashboard/API-friendly preview method.

        It returns a plan without executing anything.
        """
        request = {
            "request_id": _new_id("req"),
            "user_id": user_id,
            "workspace_id": workspace_id,
            "message": message,
            "action": action,
            "preferred_agent": preferred_agent,
            "input_data": input_data or {},
            "permissions": {},
            "metadata": {
                "preview": True,
            },
        }

        return self.plan(request=request, memory_context={})

    def get_supported_agents(self) -> List[str]:
        """Return configured agents supported by this planner."""
        try:
            agents = getattr(
                getattr(self.config, "routing_config", None),
                "registered_agents",
                DEFAULT_AGENT_NAMES,
            )
            return list(agents)
        except Exception:
            return list(DEFAULT_AGENT_NAMES)

    # -------------------------------------------------------------------------
    # Step building
    # -------------------------------------------------------------------------

    def _build_ordered_steps(
        self,
        request: Dict[str, Any],
        intent_data: Dict[str, Any],
        memory_context: Dict[str, Any],
    ) -> List[PlanStep]:
        """Build ordered MasterAgent-compatible plan steps."""
        steps: List[PlanStep] = []

        primary_agent = intent_data.get("primary_agent", "business")
        secondary_agents = intent_data.get("secondary_agents", [])
        intent = intent_data.get("intent", "general_assistance")
        action = intent_data.get("action", request.get("action", "general_request"))
        risk_level = intent_data.get("risk_level", "low")
        requires_security = bool(intent_data.get("requires_security", False))

        request_message = request.get("message", "")
        input_data = request.get("input_data", {})

        # Step 1: Main task step
        main_step_id = _new_id("step")
        main_step = PlanStep(
            step_id=main_step_id,
            order=1,
            agent_name=primary_agent,
            intent=intent,
            action=action,
            instruction=self._build_instruction(
                request_message=request_message,
                agent_name=primary_agent,
                intent=intent,
                action=action,
                input_data=input_data,
            ),
            risk_level=risk_level,
            dependencies=[],
            expected_result=self._expected_result_for_agent(primary_agent, intent, action),
            requires_security=requires_security,
            requires_verification=True,
            save_to_memory=True,
            input_data={
                "message": request_message,
                "input_data": input_data,
                "memory_context": memory_context,
                "request_metadata": request.get("metadata", {}),
            },
            metadata={
                "source": "Planner",
                "primary": True,
                "confidence": intent_data.get("confidence", self.default_confidence),
                "risk_reasons": intent_data.get("risk_reasons", []),
                "created_at": _utc_now_iso(),
            },
        )
        steps.append(main_step)

        # Optional supporting steps
        order = 2
        for agent_name in secondary_agents:
            if agent_name in {"security", "verification", "memory", primary_agent}:
                continue

            supporting_action = self._supporting_action_for_agent(agent_name)
            supporting_risk, risk_reasons = self._detect_risk_level(
                combined_text=f"{request_message} {supporting_action}",
                primary_agent=agent_name,
                action=supporting_action,
            )

            supporting_step = PlanStep(
                step_id=_new_id("step"),
                order=order,
                agent_name=agent_name,
                intent=f"support_{agent_name}",
                action=supporting_action,
                instruction=self._build_supporting_instruction(
                    request_message=request_message,
                    agent_name=agent_name,
                    primary_agent=primary_agent,
                ),
                risk_level=supporting_risk,
                dependencies=[main_step_id],
                expected_result=self._expected_result_for_agent(
                    agent_name,
                    f"support_{agent_name}",
                    supporting_action,
                ),
                requires_security=self._plan_requires_security(
                    agent_name=agent_name,
                    action=supporting_action,
                    risk_level=supporting_risk,
                    text=request_message,
                ),
                requires_verification=True,
                save_to_memory=True,
                input_data={
                    "message": request_message,
                    "input_data": input_data,
                    "depends_on": [main_step_id],
                    "primary_agent": primary_agent,
                },
                metadata={
                    "source": "Planner",
                    "primary": False,
                    "supporting_agent": True,
                    "risk_reasons": risk_reasons,
                    "created_at": _utc_now_iso(),
                },
            )

            steps.append(supporting_step)
            order += 1

        # Verification and memory are not always actual plan steps because MasterAgent
        # already prepares verification and memory payloads after each step.
        # This planner keeps compatibility flags instead of forcing extra agent calls.

        return steps

    def _build_instruction(
        self,
        request_message: str,
        agent_name: str,
        intent: str,
        action: str,
        input_data: Dict[str, Any],
    ) -> str:
        """Build clear agent instruction."""
        base = request_message.strip() or "Process the provided input data safely."

        return (
            f"Handle this request as the {agent_name} agent. "
            f"Intent: {intent}. Action: {action}. "
            f"Follow SaaS user/workspace isolation. "
            f"Do not perform real sensitive or destructive actions unless Security Agent approval exists. "
            f"Request: {base}"
        )

    def _build_supporting_instruction(
        self,
        request_message: str,
        agent_name: str,
        primary_agent: str,
    ) -> str:
        """Build instruction for secondary/supporting agent."""
        return (
            f"Support the {primary_agent} agent by handling the {agent_name}-related part "
            f"of the request. Keep output structured, safe, and verification-ready. "
            f"Request: {request_message}"
        )

    # -------------------------------------------------------------------------
    # Intent, action, risk detection
    # -------------------------------------------------------------------------

    def _score_agents(self, combined_text: str) -> Dict[str, int]:
        """Score agents based on deterministic keyword matching."""
        scores: Dict[str, int] = {agent: 0 for agent in self.get_supported_agents()}

        for agent, keywords in self.agent_keywords.items():
            for keyword in keywords:
                if _keyword_matches(keyword, combined_text):
                    scores[agent] = scores.get(agent, 0) + 1

        # Master should not normally become primary unless explicitly requested.
        if _keyword_matches("master agent", combined_text) or _keyword_matches("main brain", combined_text) or _keyword_matches("jarvis", combined_text):
            scores["master"] = scores.get("master", 0) + 3
        else:
            scores["master"] = max(0, scores.get("master", 0) - 2)

        return scores

    def _detect_task_intent(self, combined_text: str, primary_agent: str) -> str:
        """Detect high-level intent."""
        intent_patterns: List[Tuple[str, List[str]]] = [
            ("create", ["create", "generate", "make", "build", "write", "produce"]),
            ("analyze", ["analyze", "check", "review", "audit", "inspect", "diagnose"]),
            ("fix", ["fix", "repair", "solve", "debug", "correct", "resolve"]),
            ("search", ["search", "find", "look up", "research", "browse"]),
            ("automate", ["automate", "workflow", "trigger", "schedule", "process"]),
            ("communicate", ["call", "email", "message", "reply", "send"]),
            ("remember", ["remember", "store", "save memory", "recall", "memory"]),
            ("verify", ["verify", "validate", "confirm", "test"]),
            ("report", ["report", "summary", "status", "dashboard", "analytics"]),
        ]

        for intent, keywords in intent_patterns:
            if any(_keyword_matches(keyword, combined_text) for keyword in keywords):
                return f"{intent}_{primary_agent}"

        return f"general_{primary_agent}"

    def _detect_action_type(
        self,
        combined_text: str,
        action_text: str,
        primary_agent: str,
    ) -> str:
        """Detect action type."""
        if action_text and action_text != "general_request":
            return action_text

        for action, keywords in self.action_keywords.items():
            if any(_keyword_matches(keyword, combined_text) for keyword in keywords):
                return action

        return f"{primary_agent}_assist"

    def _detect_risk_level(
        self,
        combined_text: str,
        primary_agent: str,
        action: str,
    ) -> Tuple[str, List[str]]:
        """Detect risk level and reasons."""
        reasons: List[str] = []
        risk_score = 0

        if primary_agent in SENSITIVE_AGENT_NAMES:
            risk_score += 2
            reasons.append("sensitive_agent")

        if action in HIGH_RISK_ACTIONS:
            risk_score += 3
            reasons.append("high_risk_action")

        for level, keywords in self.risk_keywords.items():
            for keyword in keywords:
                if _keyword_matches(keyword, combined_text):
                    if level == "critical":
                        risk_score += 4
                    elif level == "high":
                        risk_score += 3
                    elif level == "medium":
                        risk_score += 2
                    elif level == "low":
                        risk_score += 1
                    reasons.append(f"{level}_keyword:{keyword}")

        if risk_score >= 6:
            return "critical", _dedupe_keep_order(reasons)

        if risk_score >= 4:
            return "high", _dedupe_keep_order(reasons)

        if risk_score >= 2:
            return "medium", _dedupe_keep_order(reasons)

        return "low", _dedupe_keep_order(reasons)

    def _plan_requires_security(
        self,
        agent_name: str,
        action: str,
        risk_level: str,
        text: str,
    ) -> bool:
        """Decide whether this plan step requires Security Agent."""
        try:
            decision = self._requires_security_check(
                agent_name=agent_name,
                action=action,
                context={},
            )

            if decision.get("data", {}).get("requires_security_check"):
                return True
        except Exception:
            pass

        if risk_level in {"medium", "high", "critical"}:
            return True

        if agent_name in SENSITIVE_AGENT_NAMES:
            return True

        lowered = _safe_lower(text)
        sensitive_words = [
            "delete",
            "remove",
            "send",
            "call",
            "pay",
            "purchase",
            "execute",
            "terminal",
            "password",
            "token",
            "secret",
            "permission",
            "subscription",
        ]

        return any(word in lowered for word in sensitive_words)

    def _calculate_intent_confidence(
        self,
        agent_scores: Dict[str, int],
        primary_agent: str,
        preferred_agent: Optional[str],
    ) -> float:
        """Calculate deterministic planner confidence."""
        primary_score = agent_scores.get(primary_agent, 0)
        total_score = sum(max(score, 0) for score in agent_scores.values())

        if total_score <= 0:
            confidence = 0.55
        else:
            confidence = 0.50 + min(0.40, (primary_score / max(total_score, 1)) * 0.40)

        if preferred_agent:
            confidence += 0.08

        return round(min(0.97, max(0.50, confidence)), 2)

    def _calculate_plan_risk(self, steps: List[PlanStep]) -> str:
        """Calculate overall plan risk from steps."""
        if not steps:
            return "low"

        priority = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        max_risk = max(steps, key=lambda step: priority.get(step.risk_level, 1)).risk_level
        return max_risk if max_risk in RISK_LEVELS else "low"

    # -------------------------------------------------------------------------
    # Expected result and summaries
    # -------------------------------------------------------------------------

    def _expected_result_for_agent(self, agent_name: str, intent: str, action: str) -> str:
        """Generate expected result description."""
        templates = {
            "voice": "Voice-ready response or voice interaction plan.",
            "system": "Safe system-level plan or status output without unauthorized execution.",
            "browser": "Browser/search result plan or safe web-action payload requiring approval if needed.",
            "code": "Code analysis, generated code, debugging output, or safe implementation plan.",
            "memory": "User/workspace-isolated memory recall or memory save payload.",
            "security": "Security decision, approval status, risk explanation, or blocked-action result.",
            "verification": "Verification result confirming output quality, completion, or risk status.",
            "visual": "Visual/design/image/video analysis or creative production plan.",
            "workflow": "Ordered automation workflow plan with triggers, actions, and safety rules.",
            "hologram": "Future hologram/AR interaction plan or safe placeholder result.",
            "call": "Call workflow plan or approval-required call payload.",
            "business": "Business strategy, operational recommendation, or structured advisory output.",
            "finance": "Financial analysis or approval-required finance action payload.",
            "creator": "Creative content, script, campaign, or asset generation output.",
            "master": "Coordinated multi-agent status report and final decision.",
        }

        return templates.get(
            agent_name,
            f"Structured result for intent '{intent}' and action '{action}'.",
        )

    def _build_expected_result(
        self,
        request: Dict[str, Any],
        steps: List[PlanStep],
        plan_risk: str,
    ) -> str:
        """Build overall expected result."""
        if len(steps) == 1:
            return steps[0].expected_result

        agent_names = ", ".join([step.agent_name for step in steps])

        return (
            f"Coordinated multi-step result using agents: {agent_names}. "
            f"Overall risk level: {plan_risk}. "
            f"Each step should return structured JSON, be verification-ready, "
            f"and maintain user/workspace isolation."
        )

    def _build_plan_summary(self, steps: List[PlanStep], plan_risk: str) -> str:
        """Build human-readable plan summary."""
        if not steps:
            return "No executable steps were generated."

        if len(steps) == 1:
            step = steps[0]
            return (
                f"Single-step plan routed to {step.agent_name} agent "
                f"with {step.risk_level} risk."
            )

        return (
            f"{len(steps)} ordered steps generated. "
            f"Primary agent: {steps[0].agent_name}. "
            f"Overall risk: {plan_risk}."
        )

    def _supporting_action_for_agent(self, agent_name: str) -> str:
        """Return support action for secondary agent."""
        mapping = {
            "voice": "prepare_voice_response",
            "system": "prepare_system_status",
            "browser": "prepare_browser_research",
            "code": "prepare_code_support",
            "memory": "prepare_memory_context",
            "security": "prepare_security_review",
            "verification": "prepare_verification_review",
            "visual": "prepare_visual_support",
            "workflow": "prepare_workflow_support",
            "hologram": "prepare_hologram_support",
            "call": "prepare_call_support",
            "business": "prepare_business_support",
            "finance": "prepare_finance_support",
            "creator": "prepare_creator_support",
            "master": "prepare_master_coordination",
        }

        return mapping.get(agent_name, "prepare_agent_support")

    # -------------------------------------------------------------------------
    # Request normalization
    # -------------------------------------------------------------------------

    def _normalize_request(self, request: Any) -> Dict[str, Any]:
        """
        Normalize request from dataclass-like object or dictionary.
        """
        if isinstance(request, dict):
            raw = dict(request)
        else:
            raw = {
                "request_id": getattr(request, "request_id", None),
                "user_id": getattr(request, "user_id", None),
                "workspace_id": getattr(request, "workspace_id", None),
                "message": getattr(request, "message", ""),
                "action": getattr(request, "action", "general_request"),
                "preferred_agent": getattr(request, "preferred_agent", None),
                "input_data": getattr(request, "input_data", {}),
                "permissions": getattr(request, "permissions", {}),
                "metadata": getattr(request, "metadata", {}),
            }

        return {
            "request_id": raw.get("request_id") or _new_id("req"),
            "user_id": raw.get("user_id"),
            "workspace_id": raw.get("workspace_id"),
            "message": _normalize_text(raw.get("message")),
            "action": _normalize_text(raw.get("action") or "general_request"),
            "preferred_agent": raw.get("preferred_agent"),
            "input_data": raw.get("input_data") if isinstance(raw.get("input_data"), dict) else {},
            "permissions": raw.get("permissions") if isinstance(raw.get("permissions"), dict) else {},
            "metadata": raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {},
        }

    def _extract_context(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Extract SaaS context."""
        return {
            "user_id": request.get("user_id"),
            "workspace_id": request.get("workspace_id"),
            "permissions": request.get("permissions", {}),
            "metadata": request.get("metadata", {}),
        }

    # -------------------------------------------------------------------------
    # Keyword maps
    # -------------------------------------------------------------------------

    def _build_agent_keywords(self) -> Dict[str, List[str]]:
        """Build deterministic agent keyword map."""
        return {
            "voice": [
                "voice",
                "speak",
                "speech",
                "audio",
                "wake word",
                "microphone",
                "tts",
                "stt",
                "listen",
            ],
            "system": [
                "system",
                "device",
                "computer",
                "os",
                "terminal",
                "process",
                "restart",
                "shutdown",
                "file system",
                "permission",
            ],
            "browser": [
                "browser",
                "website",
                "web",
                "url",
                "google",
                "search",
                "page",
                "scrape",
                "crawl",
                "open site",
            ],
            "code": [
                "code",
                "python",
                "javascript",
                "typescript",
                "flutter",
                "kotlin",
                "bug",
                "debug",
                "file",
                "function",
                "class",
                "api",
                "backend",
                "frontend",
                "database",
            ],
            "memory": [
                "memory",
                "remember",
                "recall",
                "save this",
                "store",
                "preference",
                "history",
                "context",
            ],
            "security": [
                "security",
                "permission",
                "approval",
                "risk",
                "safe",
                "policy",
                "auth",
                "login",
                "password",
                "token",
            ],
            "verification": [
                "verify",
                "validate",
                "check result",
                "confirm",
                "test",
                "quality",
                "proof",
            ],
            "visual": [
                "image",
                "visual",
                "design",
                "video",
                "picture",
                "photo",
                "ui",
                "ux",
                "logo",
                "thumbnail",
                "screenshot",
            ],
            "workflow": [
                "workflow",
                "automation",
                "automate",
                "trigger",
                "pipeline",
                "task sequence",
                "zap",
                "process",
            ],
            "hologram": [
                "hologram",
                "ar",
                "vr",
                "3d",
                "projection",
                "spatial",
                "mixed reality",
            ],
            "call": [
                "call",
                "phone",
                "dial",
                "voice call",
                "appointment",
                "lead call",
                "contact by phone",
            ],
            "business": [
                "business",
                "strategy",
                "client",
                "sales",
                "marketing",
                "agency",
                "lead",
                "proposal",
                "offer",
                "conversion",
                "customer",
            ],
            "finance": [
                "finance",
                "money",
                "payment",
                "invoice",
                "budget",
                "revenue",
                "profit",
                "subscription",
                "billing",
                "price",
                "cost",
            ],
            "creator": [
                "creator",
                "content",
                "script",
                "ad",
                "copy",
                "campaign",
                "story",
                "caption",
                "post",
                "creative",
                "veo",
                "video prompt",
                "video ad",
                "thumbnail",
                "storyboard",
                "voiceover",
            ],
            "master": [
                "master",
                "jarvis",
                "william",
                "main brain",
                "orchestrate",
                "coordinate",
                "all agents",
            ],
        }

    def _build_action_keywords(self) -> Dict[str, List[str]]:
        """Build action keyword map."""
        return {
            "create_file": ["create file", "new file", "full final file", "generate file"],
            "analyze_code": ["analyze code", "check code", "review code", "debug"],
            "write_code": ["write code", "generate code", "build code", "full code"],
            "web_research": ["search web", "research", "look up", "find online"],
            "browser_action": ["open website", "click", "submit form", "browser action"],
            "save_memory": ["remember", "save memory", "store this"],
            "recall_memory": ["recall", "what did i say", "previous"],
            "security_review": ["security review", "permission check", "safe check"],
            "verify_result": ["verify", "validate", "test result", "confirm"],
            "create_workflow": ["workflow", "automation", "automate process"],
            "make_call": ["make call", "dial", "phone call"],
            "send_message": ["send message", "send email", "reply email"],
            "finance_review": ["invoice", "payment", "billing", "budget"],
            "business_strategy": ["business strategy", "marketing plan", "proposal"],
            "create_content": ["script", "ad copy", "content", "caption", "post"],
            "visual_design": ["design", "image", "video", "thumbnail", "logo"],
        }

    def _build_risk_keywords(self) -> Dict[str, List[str]]:
        """Build risk keyword map."""
        return {
            "critical": [
                "transfer money",
                "send payment",
                "delete database",
                "drop table",
                "wipe",
                "destroy",
                "permanently delete",
                "change password",
                "secret key",
                "private key",
                "production credentials",
            ],
            "high": [
                "delete",
                "remove",
                "send email",
                "send message",
                "make call",
                "purchase",
                "payment",
                "execute code",
                "run terminal",
                "submit form",
                "change permission",
                "subscription",
            ],
            "medium": [
                "browser",
                "download",
                "upload",
                "modify file",
                "external api",
                "scrape",
                "login",
                "auth",
                "token",
                "financial",
                "invoice",
            ],
            "low": [
                "analyze",
                "summarize",
                "draft",
                "plan",
                "suggest",
                "explain",
                "outline",
                "preview",
            ],
        }

    # -------------------------------------------------------------------------
    # Compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Validate user/workspace context through CoreConfig if available."""
        if hasattr(self.config, "_validate_task_context"):
            return self.config._validate_task_context(context)

        fallback = FallbackPlannerConfig()
        return fallback._validate_task_context(context)

    def _requires_security_check(
        self,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Check if Security Agent is needed through CoreConfig if available."""
        if hasattr(self.config, "_requires_security_check"):
            return self.config._requires_security_check(
                agent_name=agent_name,
                action=action,
                context=context,
            )

        fallback = FallbackPlannerConfig()
        return fallback._requires_security_check(agent_name, action, context)

    def _request_security_approval(
        self,
        agent_name: Optional[str],
        action: Optional[str],
        context: Optional[Dict[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Security Agent approval payload."""
        if hasattr(self.config, "_request_security_approval"):
            return self.config._request_security_approval(
                agent_name=agent_name,
                action=action,
                context=context,
                payload=payload,
            )

        fallback = FallbackPlannerConfig()
        return fallback._request_security_approval(agent_name, action, context, payload)

    def _prepare_verification_payload(
        self,
        task_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent payload."""
        if hasattr(self.config, "_prepare_verification_payload"):
            return self.config._prepare_verification_payload(
                task_id=task_id,
                agent_name=agent_name,
                action=action,
                result=result,
                context=context,
            )

        fallback = FallbackPlannerConfig()
        return fallback._prepare_verification_payload(
            task_id=task_id,
            agent_name=agent_name,
            action=action,
            result=result,
            context=context,
        )

    def _prepare_memory_payload(
        self,
        task_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        useful_context: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Memory Agent payload."""
        if hasattr(self.config, "_prepare_memory_payload"):
            return self.config._prepare_memory_payload(
                task_id=task_id,
                agent_name=agent_name,
                action=action,
                useful_context=useful_context,
                context=context,
            )

        fallback = FallbackPlannerConfig()
        return fallback._prepare_memory_payload(
            task_id=task_id,
            agent_name=agent_name,
            action=action,
            useful_context=useful_context,
            context=context,
        )

    def _emit_agent_event(
        self,
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """Emit dashboard/API-ready agent event."""
        if hasattr(self.config, "_emit_agent_event"):
            return self.config._emit_agent_event(
                event_type=event_type,
                data=data,
                user_id=user_id,
                workspace_id=workspace_id,
            )

        fallback = FallbackPlannerConfig()
        return fallback._emit_agent_event(event_type, data, user_id, workspace_id)

    def _log_audit_event(
        self,
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """Log audit event."""
        if hasattr(self.config, "_log_audit_event"):
            return self.config._log_audit_event(
                event_type=event_type,
                data=data,
                user_id=user_id,
                workspace_id=workspace_id,
            )

        fallback = FallbackPlannerConfig()
        return fallback._log_audit_event(event_type, data, user_id, workspace_id)

    def _safe_result(
        self,
        message: str = "Success.",
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success result."""
        if hasattr(self.config, "_safe_result"):
            return self.config._safe_result(
                message=message,
                data=data,
                metadata={
                    "caller": "Planner",
                    **(metadata or {}),
                },
            )

        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": {
                "module": "core.planner",
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str = "Error.",
        error: Optional[Any] = None,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""
        if hasattr(self.config, "_error_result"):
            return self.config._error_result(
                message=message,
                error=error,
                data=data,
                metadata={
                    "caller": "Planner",
                    **(metadata or {}),
                },
            )

        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": str(error) if error is not None else "UNKNOWN_ERROR",
            "metadata": {
                "module": "core.planner",
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    # -------------------------------------------------------------------------
    # Health
    # -------------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """Return Planner health status."""
        return self._safe_result(
            message="Planner health check completed.",
            data={
                "healthy": True,
                "supported_agents": self.get_supported_agents(),
                "default_confidence": self.default_confidence,
                "keyword_maps": {
                    "agent_keywords": len(self.agent_keywords),
                    "action_keywords": len(self.action_keywords),
                    "risk_keywords": len(self.risk_keywords),
                },
                "timestamp": _utc_now_iso(),
            },
        )


# =============================================================================
# Module-level helpers
# =============================================================================

_default_planner: Optional[Planner] = None


def get_planner(
    config: Optional[Any] = None,
    reload_planner: bool = False,
) -> Planner:
    """
    Return singleton-style Planner instance.

    Safe for:
        - MasterAgent
        - FastAPI dependency injection
        - Dashboard preview
        - CLI tools
    """
    global _default_planner

    if _default_planner is None or reload_planner:
        _default_planner = Planner(config=config)

    return _default_planner


def create_plan_sync(
    message: str,
    user_id: Union[str, int],
    workspace_id: Union[str, int],
    action: str = "general_request",
    preferred_agent: Optional[str] = None,
    input_data: Optional[Dict[str, Any]] = None,
    memory_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Convenience sync helper for planning."""
    planner = get_planner()

    request = {
        "request_id": _new_id("req"),
        "user_id": user_id,
        "workspace_id": workspace_id,
        "message": message,
        "action": action,
        "preferred_agent": preferred_agent,
        "input_data": input_data or {},
        "permissions": {},
        "metadata": {},
    }

    return planner.plan(
        request=request,
        memory_context=memory_context or {},
    )


__all__ = [
    "Planner",
    "PlanStep",
    "PlanResult",
    "PlanDependency",
    "get_planner",
    "create_plan_sync",
]


if __name__ == "__main__":
    planner = get_planner(reload_planner=True)

    print(
        json.dumps(
            planner.health_check(),
            indent=2,
            default=str,
        )
    )

    demo = create_plan_sync(
        message="Create a full final Python file for my SaaS dashboard and make it safe.",
        user_id="demo_user",
        workspace_id="demo_workspace",
        preferred_agent="code",
        input_data={
            "demo": True,
        },
    )

    print(json.dumps(demo, indent=2, default=str))


# =============================================================================
# Completion Tracking
# =============================================================================
# Agent/Module: Core Master Control Files
# File Completed: planner.py
# Completion: 40.0%
# Completed Files: ['context.py', 'config.py', 'master_agent.py', 'planner.py']
# Remaining Files: ['router.py', 'task_manager.py', 'response_builder.py', 'safety_bridge.py', 'verification_bridge.py', 'memory_bridge.py']
# Next Recommended File: core/router.py
# FILE COMPLETE