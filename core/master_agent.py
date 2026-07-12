"""
core/master_agent.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Main Jarvis reporting brain that receives requests, recalls memory,
    plans tasks, routes agents, checks security, verifies results,
    saves memory, and reports final status.

This file is intentionally import-safe:
    - It can import even if planner.py, router.py, task_manager.py,
      safety_bridge.py, verification_bridge.py, memory_bridge.py,
      response_builder.py, BaseAgent, or registry files are not created yet.
    - It does not execute real system/browser/financial/call/message/destructive
      actions directly.
    - Sensitive actions are routed through security approval payloads.
    - Every user/workspace task supports SaaS isolation using user_id and workspace_id.
    - Every result uses structured dict format:
      success, message, data, error, metadata.

Main Class:
    MasterAgent
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union


# =============================================================================
# Optional CoreConfig import with fallback
# =============================================================================

try:
    from core.config import CoreConfig, get_core_config  # type: ignore
except Exception:  # pragma: no cover
    CoreConfig = None  # type: ignore

    def get_core_config(*args: Any, **kwargs: Any) -> Any:
        return FallbackCoreConfig()


# =============================================================================
# Optional BaseAgent import with fallback
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover

    class BaseAgent:
        """
        Safe fallback BaseAgent.

        This fallback allows MasterAgent to import safely before the real
        agents/base_agent.py exists.
        """

        def __init__(
            self,
            agent_name: str = "base",
            config: Optional[Any] = None,
            **kwargs: Any,
        ) -> None:
            self.agent_name = agent_name
            self.config = config
            self.metadata = kwargs

        async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent cannot execute real tasks.",
                "data": {
                    "agent_name": self.agent_name,
                    "task": task,
                },
                "error": "BASE_AGENT_NOT_IMPLEMENTED",
                "metadata": {
                    "module": "core.master_agent",
                    "timestamp": _utc_now_iso(),
                },
            }


# =============================================================================
# Optional future module imports with fallback
# =============================================================================

try:
    from core.planner import Planner  # type: ignore
except Exception:  # pragma: no cover
    Planner = None  # type: ignore

try:
    # core/router.py's class is named Router, not AgentRouter -- this
    # import always raised ImportError, so self.router silently fell
    # back to the bare in-file FallbackRouter for every MasterAgent
    # instance. Router's own docstring/shape (route_task(task, context),
    # resolve_agent() checking both "agent" and "agent_name" keys,
    # _get_agent() duck-typing against anything with .get()/.get_agent())
    # is exactly what this file's _route_step()/_execute_routed_step()
    # already call -- it's the real intended component, just misnamed
    # on import. (agents/agent_router.py's AgentRouter is a different,
    # heavier all-in-one routing+security+execution pipeline meant to be
    # driven directly by main.py/dashboard, not nested inside this
    # file's own separately-staged security/route/execute/verify/memory
    # pipeline -- using it here would either double-execute or bypass
    # this file's own safety_bridge stage.)
    from core.router import Router as AgentRouter  # type: ignore
except Exception:  # pragma: no cover
    AgentRouter = None  # type: ignore

try:
    from core.task_manager import TaskManager  # type: ignore
except Exception:  # pragma: no cover
    TaskManager = None  # type: ignore

try:
    from core.response_builder import ResponseBuilder  # type: ignore
except Exception:  # pragma: no cover
    ResponseBuilder = None  # type: ignore

try:
    from core.safety_bridge import SafetyBridge  # type: ignore
except Exception:  # pragma: no cover
    SafetyBridge = None  # type: ignore

try:
    from core.verification_bridge import VerificationBridge  # type: ignore
except Exception:  # pragma: no cover
    VerificationBridge = None  # type: ignore

try:
    from core.memory_bridge import MemoryBridge  # type: ignore
except Exception:  # pragma: no cover
    MemoryBridge = None  # type: ignore

# Real Verification/Memory Agent instances to inject into the bridges
# above. Unlike SecurityAgent (which SafetyBridge builds for itself
# internally in _init_security_agent), VerificationBridge and
# MemoryBridge only ever take their agent via a constructor argument
# that nothing previously supplied -- verification_agent/memory_agent
# stayed None forever regardless of whether the bridge classes
# themselves imported successfully.
try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore

try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover
    MemoryAgent = None  # type: ignore


# =============================================================================
# Constants
# =============================================================================

MASTER_AGENT_NAME = "master"

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

DEFAULT_MASTER_STAGES: List[str] = [
    "received",
    "context_validated",
    "memory_recalled",
    "planned",
    "security_checked",
    "routed",
    "executed",
    "verified",
    "memory_saved",
    "response_built",
    "completed",
]


# =============================================================================
# Helper functions
# =============================================================================

def _utc_now_iso() -> str:
    """Return current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    """Create readable unique ID."""
    return f"{prefix}_{uuid.uuid4().hex}"


def _safe_json(value: Any) -> str:
    """Safely convert any value to JSON string."""
    try:
        return json.dumps(value, default=str, ensure_ascii=False)
    except Exception:
        return str(value)


def _normalize_text(value: Any) -> str:
    """Normalize request text safely."""
    if value is None:
        return ""
    return str(value).strip()


def _normalize_agent_name(value: Any) -> str:
    """Normalize agent name."""
    text = str(value or "").strip().lower()
    if not text:
        return MASTER_AGENT_NAME
    return text


def _is_awaitable(value: Any) -> bool:
    """Return True if value is awaitable."""
    return inspect.isawaitable(value)


async def _maybe_await(value: Any) -> Any:
    """Await value if it is awaitable."""
    if _is_awaitable(value):
        return await value
    return value


def _method_exists(obj: Any, method_name: str) -> bool:
    """Check method existence safely."""
    return obj is not None and callable(getattr(obj, method_name, None))


# =============================================================================
# Fallback CoreConfig
# =============================================================================

class FallbackCoreConfig:
    """
    Minimal fallback CoreConfig.

    Used only when core/config.py is missing or not importable.
    Keeps master_agent.py import-safe.
    """

    def __init__(self) -> None:
        self.app_name = "William / Jarvis AI SaaS"
        self.app_version = "1.0.0"
        self.environment = "development"
        self.debug = True

        self.routing_config = type(
            "RoutingConfig",
            (),
            {
                "registered_agents": DEFAULT_AGENT_NAMES,
                "sensitive_agents": SENSITIVE_AGENT_NAMES,
                "default_agent": "master",
                "fallback_agent": "master",
                "minimum_router_confidence": 0.55,
                "max_routing_attempts": 3,
                "allow_multi_agent_tasks": True,
                "allow_parallel_agent_execution": False,
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
                "allow_real_browser_actions": False,
                "allow_real_system_actions": False,
                "allow_real_calls": False,
                "allow_real_financial_actions": False,
                "allow_real_messages": False,
                "allow_code_execution": False,
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
                "enforce_user_memory_isolation": True,
                "enforce_user_file_isolation": True,
                "enforce_user_log_isolation": True,
                "enforce_user_task_isolation": True,
                "enable_roles": True,
                "enable_subscriptions": True,
                "enable_agent_permissions": True,
                "enable_dashboard_analytics": True,
                "enable_task_history": True,
                "enable_audit_trail": True,
                "default_workspace_role": "member",
                "default_subscription_plan": "free",
            },
        )()

        self.timeout_config = type(
            "TimeoutConfig",
            (),
            {
                "default_task_timeout_seconds": 60,
                "short_task_timeout_seconds": 15,
                "long_task_timeout_seconds": 300,
                "security_approval_timeout_seconds": 120,
                "verification_timeout_seconds": 60,
                "memory_write_timeout_seconds": 30,
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
                "redact_sensitive_memory_values": True,
                "max_memory_context_items": 20,
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

        self.logger = logging.getLogger("william.core.master.fallback")
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
                "module": "core.master_agent",
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
                "module": "core.master_agent",
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
                data={"valid": False, "missing": missing},
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
        normalized_agent = _normalize_agent_name(agent_name)
        normalized_action = str(action or "").strip().lower()

        reasons: List[str] = []

        if self.safety_config.safe_mode:
            reasons.append("safe_mode_enabled")

        if normalized_agent in self.routing_config.sensitive_agents:
            reasons.append("sensitive_agent")

        if normalized_action in self.safety_config.high_risk_actions:
            reasons.append("high_risk_action")

        return self._safe_result(
            message="Security check decision generated.",
            data={
                "requires_security_check": len(reasons) > 0,
                "agent_name": normalized_agent,
                "action": normalized_action,
                "reasons": reasons,
            },
        )

    def _request_security_approval(
        self,
        agent_name: Optional[str],
        action: Optional[str],
        context: Optional[Dict[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        decision = self._requires_security_check(agent_name, action, context)
        return self._safe_result(
            message="Security approval payload prepared.",
            data={
                "approval_required": decision.get("data", {}).get("requires_security_check", True),
                "agent_name": _normalize_agent_name(agent_name),
                "action": str(action or "").strip().lower(),
                "context": context or {},
                "payload_summary": payload or {},
                "security_reasons": decision.get("data", {}).get("reasons", []),
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
        validation = self._validate_task_context(context or {})
        if not validation.get("success"):
            return validation

        return self._safe_result(
            message="Memory payload prepared.",
            data={
                "memory_enabled": True,
                "task_id": task_id,
                "agent_name": agent_name,
                "action": action,
                "user_id": (context or {}).get("user_id"),
                "workspace_id": (context or {}).get("workspace_id"),
                "useful_context": useful_context or {},
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
# Dataclasses
# =============================================================================

@dataclass
class MasterRequest:
    """
    Normalized request object for MasterAgent.

    user_id and workspace_id are required for user-specific execution.
    """

    request_id: str
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    message: str
    action: str = "general_request"
    preferred_agent: Optional[str] = None
    input_data: Dict[str, Any] = field(default_factory=dict)
    permissions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now_iso)


@dataclass
class MasterPlanStep:
    """Single plan step produced by the Master Agent planner stage."""

    step_id: str
    agent_name: str
    action: str
    instruction: str
    requires_security: bool = False
    requires_verification: bool = True
    save_to_memory: bool = True
    input_data: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MasterExecutionState:
    """Tracks MasterAgent task lifecycle for dashboard/API and audit trail."""

    task_id: str
    request_id: str
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    stage: str = "received"
    status: str = "running"
    stages_completed: List[str] = field(default_factory=list)
    plan: List[Dict[str, Any]] = field(default_factory=list)
    routing: List[Dict[str, Any]] = field(default_factory=list)
    security: List[Dict[str, Any]] = field(default_factory=list)
    execution_results: List[Dict[str, Any]] = field(default_factory=list)
    verification: List[Dict[str, Any]] = field(default_factory=list)
    memory: List[Dict[str, Any]] = field(default_factory=list)
    final_response: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)


# =============================================================================
# Fallback helper modules
# =============================================================================

class FallbackPlanner:
    """
    Safe fallback planner.

    This creates a minimal plan without depending on core/planner.py.
    """

    def __init__(self, config: Any) -> None:
        self.config = config

    async def create_plan(
        self,
        request: MasterRequest,
        memory_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        preferred_agent = _normalize_agent_name(request.preferred_agent or self._guess_agent(request))
        action = request.action or "general_request"

        step = MasterPlanStep(
            step_id=_new_id("step"),
            agent_name=preferred_agent,
            action=action,
            instruction=request.message,
            requires_security=self._step_requires_security(preferred_agent, action),
            requires_verification=True,
            save_to_memory=True,
            input_data={
                "message": request.message,
                "input_data": request.input_data,
                "memory_context": memory_context or {},
            },
            metadata={
                "source": "FallbackPlanner",
                "created_at": _utc_now_iso(),
            },
        )

        return {
            "success": True,
            "message": "Fallback plan created.",
            "data": {
                "plan_id": _new_id("plan"),
                "steps": [asdict(step)],
                "summary": "Single-step safe fallback plan.",
            },
            "error": None,
            "metadata": {
                "module": "core.master_agent",
                "timestamp": _utc_now_iso(),
            },
        }

    def _guess_agent(self, request: MasterRequest) -> str:
        text = f"{request.message} {request.action}".lower()

        if any(word in text for word in ["remember", "memory", "recall", "store"]):
            return "memory"
        if any(word in text for word in ["browser", "website", "search web", "open url"]):
            return "browser"
        if any(word in text for word in ["code", "python", "bug", "file", "script"]):
            return "code"
        if any(word in text for word in ["call", "phone", "dial"]):
            return "call"
        if any(word in text for word in ["invoice", "payment", "finance", "money"]):
            return "finance"
        if any(word in text for word in ["image", "visual", "video", "design"]):
            return "visual"
        if any(word in text for word in ["workflow", "automation", "zap", "process"]):
            return "workflow"

        return "business"

    def _step_requires_security(self, agent_name: str, action: str) -> bool:
        agent_name = _normalize_agent_name(agent_name)
        action = str(action or "").lower()

        if agent_name in SENSITIVE_AGENT_NAMES:
            return True

        if action in HIGH_RISK_ACTIONS:
            return True

        return any(keyword in action for keyword in ["delete", "send", "call", "pay", "execute"])


class FallbackRouter:
    """
    Safe fallback router.

    This only resolves an agent object from the local registry.
    """

    def __init__(self, config: Any, agent_registry: Optional[Dict[str, Any]] = None) -> None:
        self.config = config
        self.agent_registry = agent_registry or {}

    async def route(self, step: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        agent_name = _normalize_agent_name(step.get("agent_name"))
        agent = self.agent_registry.get(agent_name)

        if agent is None:
            agent = FallbackExecutableAgent(agent_name=agent_name, config=self.config)

        return {
            "success": True,
            "message": "Fallback route resolved.",
            "data": {
                "agent_name": agent_name,
                "agent": agent,
                "confidence": 0.60,
                "route_source": "FallbackRouter",
                "context": {
                    "user_id": context.get("user_id"),
                    "workspace_id": context.get("workspace_id"),
                },
            },
            "error": None,
            "metadata": {
                "module": "core.master_agent",
                "timestamp": _utc_now_iso(),
            },
        }


class FallbackTaskManager:
    """
    Safe fallback task manager.

    Tracks task states in memory only.
    """

    def __init__(self) -> None:
        self.tasks: Dict[str, Dict[str, Any]] = {}

    async def create_task(self, state: MasterExecutionState) -> Dict[str, Any]:
        self.tasks[state.task_id] = asdict(state)
        return {
            "success": True,
            "message": "Fallback task created.",
            "data": self.tasks[state.task_id],
            "error": None,
            "metadata": {
                "module": "core.master_agent",
                "timestamp": _utc_now_iso(),
            },
        }

    async def update_task(self, task_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        existing = self.tasks.get(task_id, {})
        existing.update(updates)
        existing["updated_at"] = _utc_now_iso()
        self.tasks[task_id] = existing

        return {
            "success": True,
            "message": "Fallback task updated.",
            "data": existing,
            "error": None,
            "metadata": {
                "module": "core.master_agent",
                "timestamp": _utc_now_iso(),
            },
        }


class FallbackResponseBuilder:
    """Safe fallback response builder."""

    async def build_response(
        self,
        request: MasterRequest,
        state: MasterExecutionState,
    ) -> Dict[str, Any]:
        successful_steps = [
            item for item in state.execution_results
            if item.get("success") is True
        ]

        failed_steps = [
            item for item in state.execution_results
            if item.get("success") is False
        ]

        return {
            "success": len(failed_steps) == 0,
            "message": "Master Agent completed request."
            if len(failed_steps) == 0
            else "Master Agent completed request with errors.",
            "data": {
                "task_id": state.task_id,
                "request_id": state.request_id,
                "user_id": request.user_id,
                "workspace_id": request.workspace_id,
                "status": state.status,
                "stage": state.stage,
                "summary": {
                    "total_steps": len(state.plan),
                    "successful_steps": len(successful_steps),
                    "failed_steps": len(failed_steps),
                    "verified_items": len(state.verification),
                    "memory_items": len(state.memory),
                },
                "results": state.execution_results,
                "verification": state.verification,
                "memory": state.memory,
                "errors": state.errors,
            },
            "error": None if len(failed_steps) == 0 else "ONE_OR_MORE_STEPS_FAILED",
            "metadata": {
                "module": "core.master_agent",
                "timestamp": _utc_now_iso(),
                "response_builder": "FallbackResponseBuilder",
            },
        }


class FallbackMemoryBridge:
    """Safe fallback memory bridge."""

    def __init__(self, config: Any) -> None:
        self.config = config
        self._memory: Dict[str, List[Dict[str, Any]]] = {}

    async def recall(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        query: str,
        limit: int = 10,
    ) -> Dict[str, Any]:
        key = f"{user_id}:{workspace_id}"
        items = self._memory.get(key, [])[-limit:]

        return {
            "success": True,
            "message": "Fallback memory recalled.",
            "data": {
                "items": items,
                "query": query,
                "limit": limit,
                "scope": "workspace",
            },
            "error": None,
            "metadata": {
                "module": "core.master_agent",
                "timestamp": _utc_now_iso(),
                "bridge": "FallbackMemoryBridge",
            },
        }

    async def save(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        user_id = payload.get("user_id")
        workspace_id = payload.get("workspace_id")
        key = f"{user_id}:{workspace_id}"

        self._memory.setdefault(key, []).append(payload)

        return {
            "success": True,
            "message": "Fallback memory saved.",
            "data": {
                "saved": True,
                "key": key,
                "count": len(self._memory[key]),
            },
            "error": None,
            "metadata": {
                "module": "core.master_agent",
                "timestamp": _utc_now_iso(),
                "bridge": "FallbackMemoryBridge",
            },
        }


class FallbackSafetyBridge:
    """Safe fallback safety bridge."""

    def __init__(self, config: Any) -> None:
        self.config = config

    async def check(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        approval_required = bool(payload.get("approval_required", True))
        reasons = payload.get("security_reasons", [])

        approved = not approval_required

        return {
            "success": True,
            "message": "Fallback safety check completed.",
            "data": {
                "approved": approved,
                "approval_required": approval_required,
                "blocked": approval_required,
                "reasons": reasons,
                "note": (
                    "Fallback safety bridge blocks actions requiring approval "
                    "until real Security Agent is connected."
                )
                if approval_required
                else "No approval required.",
            },
            "error": None if approved else "SECURITY_APPROVAL_REQUIRED",
            "metadata": {
                "module": "core.master_agent",
                "timestamp": _utc_now_iso(),
                "bridge": "FallbackSafetyBridge",
            },
        }


class FallbackVerificationBridge:
    """Safe fallback verification bridge."""

    def __init__(self, config: Any) -> None:
        self.config = config

    async def verify(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        result_summary = payload.get("result_summary", {})
        success = bool(result_summary.get("success", False))

        return {
            "success": True,
            "message": "Fallback verification completed.",
            "data": {
                "verified": success,
                "verification_level": payload.get("verification_level", "standard"),
                "notes": "Fallback verification checks structured success only.",
                "payload": payload,
            },
            "error": None,
            "metadata": {
                "module": "core.master_agent",
                "timestamp": _utc_now_iso(),
                "bridge": "FallbackVerificationBridge",
            },
        }


class FallbackExecutableAgent(BaseAgent):
    """
    Safe fallback executable agent.

    This does not perform real external actions.
    It only confirms that routing pipeline works.
    """

    def __init__(self, agent_name: str, config: Any) -> None:
        super().__init__(agent_name=agent_name, config=config)

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "message": f"Fallback {self.agent_name} agent received task safely.",
            "data": {
                "agent_name": self.agent_name,
                "simulated": True,
                "task": task,
                "note": (
                    "Real agent is not connected yet. This fallback keeps "
                    "MasterAgent import-safe and testable."
                ),
            },
            "error": None,
            "metadata": {
                "module": "core.master_agent",
                "timestamp": _utc_now_iso(),
                "agent_type": "FallbackExecutableAgent",
            },
        }


# =============================================================================
# MasterAgent
# =============================================================================

class MasterAgent(BaseAgent):
    """
    Main Jarvis reporting brain.

    MasterAgent pipeline:
        1. Receive request.
        2. Validate user_id/workspace_id context.
        3. Recall memory.
        4. Create plan.
        5. Check security.
        6. Route to agent.
        7. Execute safe agent call.
        8. Prepare verification payload.
        9. Save useful memory.
        10. Build final response.
        11. Log audit and dashboard-ready events.

    This class is designed for:
        - FastAPI/dashboard integration.
        - Agent Registry compatibility.
        - Agent Loader compatibility.
        - Agent Router compatibility.
        - Security Agent bridge compatibility.
        - Memory Agent bridge compatibility.
        - Verification Agent bridge compatibility.
        - SaaS multi-user/multi-workspace isolation.
    """

    def __init__(
        self,
        config: Optional[Any] = None,
        agent_registry: Optional[Dict[str, Any]] = None,
        planner: Optional[Any] = None,
        router: Optional[Any] = None,
        task_manager: Optional[Any] = None,
        response_builder: Optional[Any] = None,
        safety_bridge: Optional[Any] = None,
        verification_bridge: Optional[Any] = None,
        memory_bridge: Optional[Any] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        self.config = config or get_core_config()
        self.agent_registry: Dict[str, Any] = agent_registry or {}

        super().__init__(
            agent_name=MASTER_AGENT_NAME,
            config=self.config,
            **kwargs,
        )

        self.logger = logger or getattr(self.config, "logger", None) or logging.getLogger("william.core.master")
        if not self.logger.handlers:
            self.logger.addHandler(logging.StreamHandler())
        self.logger.setLevel(logging.INFO)

        self.planner = planner or self._build_planner()
        self.router = router or self._build_router()
        self.task_manager = task_manager or self._build_task_manager()
        self.response_builder = response_builder or self._build_response_builder()
        self.safety_bridge = safety_bridge or self._build_safety_bridge()
        self.verification_bridge = verification_bridge or self._build_verification_bridge()
        self.memory_bridge = memory_bridge or self._build_memory_bridge()

        self.active_tasks: Dict[str, MasterExecutionState] = {}

        self._emit_agent_event(
            event_type="master_agent_initialized",
            data={
                "registered_agents": list(self.agent_registry.keys()),
                "fallback_modules_enabled": self._fallback_status(),
            },
        )

    # -------------------------------------------------------------------------
    # Builders
    # -------------------------------------------------------------------------

    def _build_planner(self) -> Any:
        if Planner is not None:
            try:
                return Planner(config=self.config)
            except TypeError:
                return Planner()
            except Exception:
                return FallbackPlanner(config=self.config)
        return FallbackPlanner(config=self.config)

    def _build_router(self) -> Any:
        if AgentRouter is not None:
            try:
                # core.router.Router's own RouterConfig dataclass has a
                # different shape than CoreConfig -- let it use its own
                # defaults rather than pass a config object it doesn't
                # understand (same reasoning as the safety/verification/
                # memory bridges below). Its registry duck-types against
                # anything with .get()/.get_agent(), and self.agent_registry
                # is a plain dict, so a direct .get() lookup works as-is.
                return AgentRouter(registry=self.agent_registry)
            except TypeError:
                try:
                    return AgentRouter(self.agent_registry)
                except Exception:
                    return FallbackRouter(config=self.config, agent_registry=self.agent_registry)
            except Exception:
                return FallbackRouter(config=self.config, agent_registry=self.agent_registry)
        return FallbackRouter(config=self.config, agent_registry=self.agent_registry)

    def _build_task_manager(self) -> Any:
        if TaskManager is not None:
            try:
                return TaskManager(config=self.config)
            except TypeError:
                return TaskManager()
            except Exception:
                return FallbackTaskManager()
        return FallbackTaskManager()

    def _build_response_builder(self) -> Any:
        if ResponseBuilder is not None:
            try:
                return ResponseBuilder(config=self.config)
            except TypeError:
                return ResponseBuilder()
            except Exception:
                return FallbackResponseBuilder()
        return FallbackResponseBuilder()

    def _build_safety_bridge(self) -> Any:
        if SafetyBridge is not None:
            try:
                return SafetyBridge(config=self.config)
            except TypeError:
                return SafetyBridge()
            except Exception:
                return FallbackSafetyBridge(config=self.config)
        return FallbackSafetyBridge(config=self.config)

    def _build_verification_bridge(self) -> Any:
        if VerificationBridge is not None:
            # VerificationBridge's own `config` param expects a
            # VerificationConfig, not CoreConfig -- unlike SafetyBridge,
            # passing config=self.config here doesn't raise (the
            # constructor accepts it as a plain Optional[Any] slot), it
            # just silently stores the wrong-shaped object, so this can't
            # rely on a TypeError fallback the way _build_safety_bridge
            # does. Let it build its own default config, and inject the
            # real agent explicitly since nothing else ever did.
            try:
                real_agent = VerificationAgent() if VerificationAgent is not None else None
            except Exception:
                real_agent = None
            try:
                return VerificationBridge(verification_agent=real_agent)
            except TypeError:
                return VerificationBridge()
            except Exception:
                return FallbackVerificationBridge(config=self.config)
        return FallbackVerificationBridge(config=self.config)

    def _build_memory_bridge(self) -> Any:
        if MemoryBridge is not None:
            # Same reasoning as _build_verification_bridge: MemoryBridge's
            # `config` expects a MemoryBridgeConfig, and memory_agent is
            # never supplied unless explicitly passed here.
            try:
                real_agent = MemoryAgent() if MemoryAgent is not None else None
            except Exception:
                real_agent = None
            try:
                return MemoryBridge(memory_agent=real_agent)
            except TypeError:
                return MemoryBridge()
            except Exception:
                return FallbackMemoryBridge(config=self.config)
        return FallbackMemoryBridge(config=self.config)

    def _fallback_status(self) -> Dict[str, bool]:
        """Return which fallback modules are currently active."""
        return {
            "planner": isinstance(self.planner, FallbackPlanner),
            "router": isinstance(self.router, FallbackRouter),
            "task_manager": isinstance(self.task_manager, FallbackTaskManager),
            "response_builder": isinstance(self.response_builder, FallbackResponseBuilder),
            "safety_bridge": isinstance(self.safety_bridge, FallbackSafetyBridge),
            "verification_bridge": isinstance(self.verification_bridge, FallbackVerificationBridge),
            "memory_bridge": isinstance(self.memory_bridge, FallbackMemoryBridge),
        }

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    async def handle_request(
        self,
        message: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        action: str = "general_request",
        preferred_agent: Optional[str] = None,
        input_data: Optional[Dict[str, Any]] = None,
        permissions: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Main async request handler.

        This is the primary method for dashboard/API use.
        """
        request = MasterRequest(
            request_id=_new_id("req"),
            user_id=user_id,
            workspace_id=workspace_id,
            message=_normalize_text(message),
            action=action or "general_request",
            preferred_agent=preferred_agent,
            input_data=input_data or {},
            permissions=permissions or {},
            metadata=metadata or {},
        )

        return await self.process_request(request)

    def handle_request_sync(
        self,
        message: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        action: str = "general_request",
        preferred_agent: Optional[str] = None,
        input_data: Optional[Dict[str, Any]] = None,
        permissions: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Sync wrapper for environments that are not async-aware.

        FastAPI should prefer handle_request().
        CLI/simple tests can use this method.
        """
        coro = self.handle_request(
            message=message,
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            preferred_agent=preferred_agent,
            input_data=input_data,
            permissions=permissions,
            metadata=metadata,
        )

        try:
            return asyncio.run(coro)
        except RuntimeError:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(coro)

    async def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible execute method.

        Expected task shape:
            {
                "message": "...",
                "user_id": 1,
                "workspace_id": 1,
                "action": "general_request",
                "preferred_agent": "business",
                "input_data": {},
                "permissions": {},
                "metadata": {}
            }
        """
        task = task or {}

        return await self.handle_request(
            message=task.get("message", ""),
            user_id=task.get("user_id"),
            workspace_id=task.get("workspace_id"),
            action=task.get("action", "general_request"),
            preferred_agent=task.get("preferred_agent"),
            input_data=task.get("input_data", {}),
            permissions=task.get("permissions", {}),
            metadata=task.get("metadata", {}),
        )

    async def process_request(self, request: MasterRequest) -> Dict[str, Any]:
        """
        Full MasterAgent orchestration pipeline.
        """
        task_id = _new_id("task")

        state = MasterExecutionState(
            task_id=task_id,
            request_id=request.request_id,
            user_id=request.user_id,
            workspace_id=request.workspace_id,
        )

        self.active_tasks[task_id] = state

        try:
            await self._create_or_update_task(state)
            self._set_stage(state, "received")

            self._emit_agent_event(
                event_type="master_request_received",
                user_id=request.user_id,
                workspace_id=request.workspace_id,
                data={
                    "task_id": task_id,
                    "request_id": request.request_id,
                    "action": request.action,
                    "preferred_agent": request.preferred_agent,
                },
            )

            context_validation = self._validate_task_context(
                {
                    "user_id": request.user_id,
                    "workspace_id": request.workspace_id,
                    "permissions": request.permissions,
                    "metadata": request.metadata,
                }
            )

            if not context_validation.get("success"):
                self._append_error(state, "context_validation_failed", context_validation)
                state.status = "failed"
                self._set_stage(state, "failed")
                await self._create_or_update_task(state)
                return self._error_result(
                    message="Master Agent blocked request because SaaS context is invalid.",
                    error=context_validation.get("error"),
                    data={
                        "task_id": task_id,
                        "context_validation": context_validation,
                    },
                )

            self._set_stage(state, "context_validated")

            memory_context = await self._recall_memory(request, state)
            self._set_stage(state, "memory_recalled")

            plan_result = await self._create_plan(request, memory_context, state)
            if not plan_result.get("success"):
                self._append_error(state, "planning_failed", plan_result)
                state.status = "failed"
                self._set_stage(state, "failed")
                await self._create_or_update_task(state)
                return self._error_result(
                    message="Master Agent could not create a safe execution plan.",
                    error=plan_result.get("error"),
                    data={
                        "task_id": task_id,
                        "planning_result": plan_result,
                    },
                )

            plan_steps = plan_result.get("data", {}).get("steps", [])
            state.plan = plan_steps
            self._set_stage(state, "planned")

            for step in plan_steps:
                step_result = await self._process_step(request, state, step)
                state.execution_results.append(step_result)

                if not step_result.get("success"):
                    self._append_error(state, "step_failed", step_result)

                    strict_mode = bool(getattr(getattr(self.config, "safety_config", None), "strict_mode", True))
                    if strict_mode:
                        break

            self._set_stage(state, "executed")

            state.status = "completed" if len(state.errors) == 0 else "completed_with_errors"

            final_response = await self._build_final_response(request, state)
            state.final_response = final_response
            self._set_stage(state, "response_built")

            await self._create_or_update_task(state)

            self._log_audit_event(
                event_type="master_request_completed",
                user_id=request.user_id,
                workspace_id=request.workspace_id,
                data={
                    "task_id": task_id,
                    "request_id": request.request_id,
                    "status": state.status,
                    "errors_count": len(state.errors),
                    "steps_count": len(state.plan),
                },
            )

            self._set_stage(state, "completed")

            return final_response

        except Exception as exc:
            self._append_error(
                state,
                "master_pipeline_exception",
                {
                    "success": False,
                    "message": "Master pipeline exception.",
                    "error": str(exc),
                },
            )
            state.status = "failed"
            self._set_stage(state, "failed")
            await self._create_or_update_task(state)

            self._log_audit_event(
                event_type="master_request_failed",
                user_id=request.user_id,
                workspace_id=request.workspace_id,
                data={
                    "task_id": task_id,
                    "request_id": request.request_id,
                    "error": str(exc),
                },
            )

            return self._error_result(
                message="Master Agent failed while processing request.",
                error=exc,
                data={
                    "task_id": task_id,
                    "request_id": request.request_id,
                    "state": asdict(state),
                },
            )

    # -------------------------------------------------------------------------
    # Pipeline stages
    # -------------------------------------------------------------------------

    async def _recall_memory(
        self,
        request: MasterRequest,
        state: MasterExecutionState,
    ) -> Dict[str, Any]:
        """Recall useful user/workspace memory before planning."""
        try:
            if not _method_exists(self.memory_bridge, "recall"):
                result = self._safe_result(
                    message="Memory bridge has no recall method.",
                    data={"items": [], "bridge_available": False},
                )
                state.memory.append(result)
                return result

            result = await _maybe_await(
                self.memory_bridge.recall(
                    user_id=request.user_id,
                    workspace_id=request.workspace_id,
                    query=request.message,
                    limit=self._get_memory_limit(),
                )
            )

            normalized = self._normalize_result(result, "Memory recall completed.")
            state.memory.append(normalized)

            self._emit_agent_event(
                event_type="master_memory_recalled",
                user_id=request.user_id,
                workspace_id=request.workspace_id,
                data={
                    "task_id": state.task_id,
                    "success": normalized.get("success"),
                    "items_count": len(normalized.get("data", {}).get("items", [])),
                },
            )

            await self._create_or_update_task(state)
            return normalized

        except Exception as exc:
            result = self._error_result(
                message="Memory recall failed safely.",
                error=exc,
            )
            state.memory.append(result)
            return result

    async def _create_plan(
        self,
        request: MasterRequest,
        memory_context: Dict[str, Any],
        state: MasterExecutionState,
    ) -> Dict[str, Any]:
        """Create safe plan using real Planner or fallback planner."""
        try:
            if _method_exists(self.planner, "create_plan"):
                result = await _maybe_await(
                    self.planner.create_plan(
                        request=request,
                        memory_context=memory_context,
                    )
                )
            elif _method_exists(self.planner, "plan"):
                result = await _maybe_await(
                    self.planner.plan(
                        request=asdict(request),
                        memory_context=memory_context,
                    )
                )
            else:
                fallback = FallbackPlanner(config=self.config)
                result = await fallback.create_plan(request, memory_context)

            normalized = self._normalize_result(result, "Plan created.")

            self._emit_agent_event(
                event_type="master_plan_created",
                user_id=request.user_id,
                workspace_id=request.workspace_id,
                data={
                    "task_id": state.task_id,
                    "success": normalized.get("success"),
                    "steps_count": len(normalized.get("data", {}).get("steps", [])),
                },
            )

            await self._create_or_update_task(state)
            return normalized

        except Exception as exc:
            return self._error_result(
                message="Planning failed safely.",
                error=exc,
            )

    async def _process_step(
        self,
        request: MasterRequest,
        state: MasterExecutionState,
        step: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Process one plan step:
            - security check
            - route
            - execute
            - verify
            - save memory
        """
        step_id = step.get("step_id") or _new_id("step")
        agent_name = _normalize_agent_name(step.get("agent_name"))
        action = str(step.get("action") or request.action or "general_request").strip().lower()

        context = {
            "user_id": request.user_id,
            "workspace_id": request.workspace_id,
            "role": request.metadata.get("role"),
            "subscription_plan": request.metadata.get("subscription_plan"),
            "permissions": request.permissions,
            "request_id": request.request_id,
            "task_id": state.task_id,
            "step_id": step_id,
        }

        security_result = await self._check_step_security(
            request=request,
            state=state,
            step=step,
            agent_name=agent_name,
            action=action,
            context=context,
        )

        state.security.append(security_result)
        self._set_stage(state, "security_checked")

        if not security_result.get("success"):
            return self._error_result(
                message="Step blocked by security validation.",
                error=security_result.get("error"),
                data={
                    "step_id": step_id,
                    "agent_name": agent_name,
                    "action": action,
                    "security": security_result,
                },
            )

        security_data = security_result.get("data", {})
        if security_data.get("blocked") is True:
            return self._error_result(
                message="Step requires Security Agent approval before execution.",
                error="SECURITY_APPROVAL_REQUIRED",
                data={
                    "step_id": step_id,
                    "agent_name": agent_name,
                    "action": action,
                    "security": security_result,
                },
            )

        route_result = await self._route_step(request, state, step, context)
        state.routing.append(route_result)
        self._set_stage(state, "routed")

        if not route_result.get("success"):
            return self._error_result(
                message="Step routing failed.",
                error=route_result.get("error"),
                data={
                    "step_id": step_id,
                    "agent_name": agent_name,
                    "action": action,
                    "route": route_result,
                },
            )

        execution_result = await self._execute_routed_step(
            request=request,
            state=state,
            step=step,
            route_result=route_result,
            context=context,
        )

        verification_result = await self._verify_step_result(
            request=request,
            state=state,
            step=step,
            agent_name=agent_name,
            action=action,
            execution_result=execution_result,
            context=context,
        )
        state.verification.append(verification_result)
        self._set_stage(state, "verified")

        memory_result = await self._save_step_memory(
            request=request,
            state=state,
            step=step,
            agent_name=agent_name,
            action=action,
            execution_result=execution_result,
            context=context,
        )
        state.memory.append(memory_result)
        self._set_stage(state, "memory_saved")

        merged_result = {
            "success": bool(execution_result.get("success")),
            "message": execution_result.get("message", "Step executed."),
            "data": {
                "step_id": step_id,
                "agent_name": agent_name,
                "action": action,
                "execution": execution_result,
                "verification": verification_result,
                "memory": memory_result,
            },
            "error": execution_result.get("error"),
            "metadata": {
                "module": "core.master_agent",
                "timestamp": _utc_now_iso(),
                "task_id": state.task_id,
                "request_id": request.request_id,
            },
        }

        await self._create_or_update_task(state)
        return merged_result

    async def _check_step_security(
        self,
        request: MasterRequest,
        state: MasterExecutionState,
        step: Dict[str, Any],
        agent_name: str,
        action: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Prepare and process security approval payload."""
        try:
            decision = self._requires_security_check(
                agent_name=agent_name,
                action=action,
                context=context,
            )

            requires_security = bool(
                step.get("requires_security", False)
                or decision.get("data", {}).get("requires_security_check", False)
            )

            if not requires_security:
                return self._safe_result(
                    message="Security check passed. No approval required.",
                    data={
                        "approved": True,
                        "blocked": False,
                        "approval_required": False,
                        "agent_name": agent_name,
                        "action": action,
                        "decision": decision,
                    },
                )

            approval_payload = self._request_security_approval(
                agent_name=agent_name,
                action=action,
                context=context,
                payload={
                    "request": asdict(request),
                    "step": step,
                },
            )

            if not approval_payload.get("success"):
                return approval_payload

            if _method_exists(self.safety_bridge, "inspect_task"):
                # The real core.safety_bridge.SafetyBridge exposes
                # inspect_task(action, payload, context, ...), not
                # check()/request_approval() -- neither of those names
                # exist on it, so this always fell through to a brand
                # new, disconnected FallbackSafetyBridge(config=self.config)
                # instead of the properly-wired self.safety_bridge (with
                # its real SecurityAgent), even after that agent was
                # correctly injected elsewhere.
                inspection = await _maybe_await(
                    self.safety_bridge.inspect_task(
                        action=action,
                        payload=approval_payload.get("data", {}),
                        context=context,
                        force_security_check=True,
                    )
                )
                safety_result = self._interpret_safety_inspection(inspection)
            elif _method_exists(self.safety_bridge, "check"):
                safety_result = await _maybe_await(
                    self.safety_bridge.check(approval_payload.get("data", {}))
                )
            elif _method_exists(self.safety_bridge, "request_approval"):
                safety_result = await _maybe_await(
                    self.safety_bridge.request_approval(approval_payload.get("data", {}))
                )
            else:
                fallback = FallbackSafetyBridge(config=self.config)
                safety_result = await fallback.check(approval_payload.get("data", {}))

            normalized = self._normalize_result(safety_result, "Security check completed.")

            self._log_audit_event(
                event_type="master_step_security_checked",
                user_id=request.user_id,
                workspace_id=request.workspace_id,
                data={
                    "task_id": state.task_id,
                    "step_id": step.get("step_id"),
                    "agent_name": agent_name,
                    "action": action,
                    "success": normalized.get("success"),
                    "blocked": normalized.get("data", {}).get("blocked"),
                    "approved": normalized.get("data", {}).get("approved"),
                },
            )

            return normalized

        except Exception as exc:
            return self._error_result(
                message="Security check failed safely.",
                error=exc,
                data={
                    "agent_name": agent_name,
                    "action": action,
                },
            )

    def _interpret_safety_inspection(self, inspection: Dict[str, Any]) -> Dict[str, Any]:
        """
        Translate core.safety_bridge.SafetyBridge.inspect_task()'s
        decision-based result (decision: allow/require_approval/block/
        review/error) into the approved/blocked/approval_required shape
        _process_step() actually reads. inspect_task() returns
        success=True even for a require_approval decision (it succeeded
        at *inspecting*, independent of whether the action is allowed to
        proceed) -- callers must key off "decision", not "success". Only
        "allow" is treated as safe to proceed; every other decision
        (including "review" and inspection errors) blocks, since no real
        interactive approval flow exists yet to resolve them.
        """
        data = inspection.get("data", {}) if isinstance(inspection, dict) else {}
        decision = data.get("decision")

        approved = decision == "allow"
        blocked = not approved

        return {
            "success": bool(inspection.get("success", False)) if approved else False,
            "message": inspection.get("message", "Security inspection completed."),
            "data": {
                "approved": approved,
                "blocked": blocked,
                "approval_required": decision == "require_approval",
                "decision": decision,
                "risk_level": data.get("risk_level"),
                "reasons": data.get("reasons"),
                "inspection": data,
            },
            "error": None if approved else (inspection.get("error") or "SECURITY_APPROVAL_REQUIRED"),
            "metadata": inspection.get("metadata", {}),
        }

    async def _route_step(
        self,
        request: MasterRequest,
        state: MasterExecutionState,
        step: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Route step to selected agent."""
        try:
            if _method_exists(self.router, "route"):
                result = await _maybe_await(
                    self.router.route(
                        step=step,
                        context=context,
                    )
                )
            elif _method_exists(self.router, "route_task"):
                result = await _maybe_await(
                    self.router.route_task(
                        task=step,
                        context=context,
                    )
                )
            else:
                fallback = FallbackRouter(
                    config=self.config,
                    agent_registry=self.agent_registry,
                )
                result = await fallback.route(step, context)

            normalized = self._normalize_result(result, "Step routed.")

            route_data = normalized.get("data", {})
            route_data.pop("agent", None)

            self._emit_agent_event(
                event_type="master_step_routed",
                user_id=request.user_id,
                workspace_id=request.workspace_id,
                data={
                    "task_id": state.task_id,
                    "step_id": step.get("step_id"),
                    "agent_name": route_data.get("agent_name"),
                    "confidence": route_data.get("confidence"),
                    "route_source": route_data.get("route_source"),
                },
            )

            return normalized

        except Exception as exc:
            return self._error_result(
                message="Routing failed safely.",
                error=exc,
            )

    async def _execute_routed_step(
        self,
        request: MasterRequest,
        state: MasterExecutionState,
        step: Dict[str, Any],
        route_result: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute routed step safely."""
        try:
            route_data = route_result.get("data", {})
            agent = route_data.get("agent")
            agent_name = _normalize_agent_name(route_data.get("agent_name") or step.get("agent_name"))

            if agent is None:
                agent = self.agent_registry.get(agent_name)

            if agent is None:
                agent = FallbackExecutableAgent(agent_name=agent_name, config=self.config)

            task_payload = {
                "task_id": state.task_id,
                "request_id": request.request_id,
                "step_id": step.get("step_id"),
                "user_id": request.user_id,
                "workspace_id": request.workspace_id,
                "agent_name": agent_name,
                "action": step.get("action"),
                "instruction": step.get("instruction"),
                "input_data": step.get("input_data", {}),
                "context": context,
                "metadata": {
                    "source": "MasterAgent",
                    "created_at": _utc_now_iso(),
                },
            }

            timeout_seconds = self._get_task_timeout(step)

            # A live smoke test invoking every real specialized agent through
            # this dispatch confirmed each one implements a different real
            # entrypoint (run_task/handle_task/arun/run/execute) and that
            # several agents' inherited BaseAgent.execute_task() pipeline
            # crashes outright due to incompatible internal hook overrides
            # (_emit_agent_event/_log_audit_event/_error_result signature
            # drift written for that agent's own convention only). Rather
            # than special-case every agent's quirks here, delegate to the
            # shared adapter (agents/agent_execution_adapter.py), which tries
            # each real entrypoint in the confirmed-safe preference order and
            # degrades a signature/method mismatch to a structured error
            # instead of raising.
            if callable(agent) and not any(
                _method_exists(agent, name)
                for name in ("run_task", "handle_task", "arun", "run", "execute", "execute_task")
            ):
                result = await asyncio.wait_for(
                    _maybe_await(agent(task_payload)),
                    timeout=timeout_seconds,
                )
            elif agent is not None:
                from agents.agent_execution_adapter import call_agent

                result = await asyncio.wait_for(
                    call_agent(agent, task_payload, agent_name=agent_name),
                    timeout=timeout_seconds,
                )
            else:
                return self._error_result(
                    message="Resolved agent is not executable.",
                    error="AGENT_NOT_EXECUTABLE",
                    data={
                        "agent_name": agent_name,
                        "step": step,
                    },
                )

            normalized = self._normalize_result(result, "Agent step executed.")

            self._emit_agent_event(
                event_type="master_step_executed",
                user_id=request.user_id,
                workspace_id=request.workspace_id,
                data={
                    "task_id": state.task_id,
                    "step_id": step.get("step_id"),
                    "agent_name": agent_name,
                    "success": normalized.get("success"),
                    "error": normalized.get("error"),
                },
            )

            return normalized

        except asyncio.TimeoutError:
            return self._error_result(
                message="Agent execution timed out.",
                error="AGENT_EXECUTION_TIMEOUT",
                data={
                    "step": step,
                    "timeout_seconds": self._get_task_timeout(step),
                },
            )
        except Exception as exc:
            return self._error_result(
                message="Agent execution failed safely.",
                error=exc,
                data={
                    "step": step,
                },
            )

    async def _verify_step_result(
        self,
        request: MasterRequest,
        state: MasterExecutionState,
        step: Dict[str, Any],
        agent_name: str,
        action: str,
        execution_result: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Prepare and send verification payload."""
        try:
            if step.get("requires_verification", True) is False:
                return self._safe_result(
                    message="Verification skipped for this step.",
                    data={
                        "verified": None,
                        "skipped": True,
                        "step_id": step.get("step_id"),
                    },
                )

            verification_payload = self._prepare_verification_payload(
                task_id=state.task_id,
                agent_name=agent_name,
                action=action,
                result=execution_result,
                context=context,
            )

            if not verification_payload.get("success"):
                return verification_payload

            if _method_exists(self.verification_bridge, "verify"):
                result = await _maybe_await(
                    self.verification_bridge.verify(verification_payload.get("data", {}))
                )
            else:
                fallback = FallbackVerificationBridge(config=self.config)
                result = await fallback.verify(verification_payload.get("data", {}))

            normalized = self._normalize_result(result, "Verification completed.")

            self._emit_agent_event(
                event_type="master_step_verified",
                user_id=request.user_id,
                workspace_id=request.workspace_id,
                data={
                    "task_id": state.task_id,
                    "step_id": step.get("step_id"),
                    "agent_name": agent_name,
                    "verified": normalized.get("data", {}).get("verified"),
                },
            )

            return normalized

        except Exception as exc:
            return self._error_result(
                message="Verification failed safely.",
                error=exc,
            )

    async def _save_step_memory(
        self,
        request: MasterRequest,
        state: MasterExecutionState,
        step: Dict[str, Any],
        agent_name: str,
        action: str,
        execution_result: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Prepare and save useful memory payload."""
        try:
            if step.get("save_to_memory", True) is False:
                return self._safe_result(
                    message="Memory save skipped for this step.",
                    data={
                        "saved": None,
                        "skipped": True,
                        "step_id": step.get("step_id"),
                    },
                )

            useful_context = {
                "request_message": request.message,
                "action": action,
                "agent_name": agent_name,
                "step_instruction": step.get("instruction"),
                "execution_success": execution_result.get("success"),
                "execution_message": execution_result.get("message"),
                "execution_data": execution_result.get("data"),
            }

            memory_payload = self._prepare_memory_payload(
                task_id=state.task_id,
                agent_name=agent_name,
                action=action,
                useful_context=useful_context,
                context=context,
            )

            if not memory_payload.get("success"):
                return memory_payload

            if _method_exists(self.memory_bridge, "save"):
                result = await _maybe_await(
                    self.memory_bridge.save(memory_payload.get("data", {}))
                )
            else:
                fallback = FallbackMemoryBridge(config=self.config)
                result = await fallback.save(memory_payload.get("data", {}))

            normalized = self._normalize_result(result, "Memory saved.")

            self._emit_agent_event(
                event_type="master_step_memory_saved",
                user_id=request.user_id,
                workspace_id=request.workspace_id,
                data={
                    "task_id": state.task_id,
                    "step_id": step.get("step_id"),
                    "agent_name": agent_name,
                    "saved": normalized.get("data", {}).get("saved"),
                },
            )

            return normalized

        except Exception as exc:
            return self._error_result(
                message="Memory save failed safely.",
                error=exc,
            )

    async def _build_final_response(
        self,
        request: MasterRequest,
        state: MasterExecutionState,
    ) -> Dict[str, Any]:
        """Build final dashboard/API-ready response."""
        try:
            if _method_exists(self.response_builder, "build_response"):
                result = await _maybe_await(
                    self.response_builder.build_response(
                        request=request,
                        state=state,
                    )
                )
            elif _method_exists(self.response_builder, "build"):
                result = await _maybe_await(
                    self.response_builder.build(
                        request=asdict(request),
                        state=asdict(state),
                    )
                )
            else:
                fallback = FallbackResponseBuilder()
                result = await fallback.build_response(request, state)

            return self._normalize_result(result, "Final response built.")

        except Exception as exc:
            return self._error_result(
                message="Failed to build final response.",
                error=exc,
                data={
                    "task_id": state.task_id,
                    "request_id": request.request_id,
                    "state": asdict(state),
                },
            )

    # -------------------------------------------------------------------------
    # Agent registry methods
    # -------------------------------------------------------------------------

    def register_agent(self, agent_name: str, agent: Any) -> Dict[str, Any]:
        """Register or replace an agent in MasterAgent local registry."""
        try:
            normalized_name = _normalize_agent_name(agent_name)

            if not normalized_name:
                return self._error_result(
                    message="Agent name is required.",
                    error="MISSING_AGENT_NAME",
                )

            self.agent_registry[normalized_name] = agent

            if isinstance(self.router, FallbackRouter):
                self.router.agent_registry = self.agent_registry

            self._emit_agent_event(
                event_type="master_agent_registered",
                data={
                    "agent_name": normalized_name,
                    "agent_type": type(agent).__name__,
                },
            )

            return self._safe_result(
                message="Agent registered successfully.",
                data={
                    "agent_name": normalized_name,
                    "agent_type": type(agent).__name__,
                    "registered_agents": list(self.agent_registry.keys()),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to register agent.",
                error=exc,
            )

    def unregister_agent(self, agent_name: str) -> Dict[str, Any]:
        """Unregister an agent from local registry."""
        try:
            normalized_name = _normalize_agent_name(agent_name)

            existed = normalized_name in self.agent_registry
            self.agent_registry.pop(normalized_name, None)

            if isinstance(self.router, FallbackRouter):
                self.router.agent_registry = self.agent_registry

            self._emit_agent_event(
                event_type="master_agent_unregistered",
                data={
                    "agent_name": normalized_name,
                    "existed": existed,
                },
            )

            return self._safe_result(
                message="Agent unregistered successfully.",
                data={
                    "agent_name": normalized_name,
                    "existed": existed,
                    "registered_agents": list(self.agent_registry.keys()),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to unregister agent.",
                error=exc,
            )

    def list_agents(self) -> Dict[str, Any]:
        """List registered runtime agents plus configured system agents."""
        configured_agents = list(
            getattr(
                getattr(self.config, "routing_config", None),
                "registered_agents",
                DEFAULT_AGENT_NAMES,
            )
        )

        return self._safe_result(
            message="Agents listed successfully.",
            data={
                "runtime_registered_agents": list(self.agent_registry.keys()),
                "configured_agents": configured_agents,
                "sensitive_agents": list(
                    getattr(
                        getattr(self.config, "routing_config", None),
                        "sensitive_agents",
                        SENSITIVE_AGENT_NAMES,
                    )
                ),
            },
        )

    # -------------------------------------------------------------------------
    # Status and dashboard methods
    # -------------------------------------------------------------------------

    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Return current task status for dashboard/API."""
        state = self.active_tasks.get(task_id)

        if not state:
            return self._error_result(
                message="Task not found.",
                error="TASK_NOT_FOUND",
                data={"task_id": task_id},
            )

        return self._safe_result(
            message="Task status returned.",
            data=asdict(state),
        )

    def list_active_tasks(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """List active tasks, optionally filtered by user/workspace."""
        tasks: List[Dict[str, Any]] = []

        for state in self.active_tasks.values():
            if user_id is not None and str(state.user_id) != str(user_id):
                continue
            if workspace_id is not None and str(state.workspace_id) != str(workspace_id):
                continue
            tasks.append(asdict(state))

        return self._safe_result(
            message="Active tasks listed.",
            data={
                "tasks": tasks,
                "count": len(tasks),
                "filters": {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """Return MasterAgent health status."""
        return self._safe_result(
            message="Master Agent health check completed.",
            data={
                "healthy": True,
                "agent_name": MASTER_AGENT_NAME,
                "active_tasks": len(self.active_tasks),
                "registered_runtime_agents": list(self.agent_registry.keys()),
                "fallback_status": self._fallback_status(),
                "config_available": self.config is not None,
                "timestamp": _utc_now_iso(),
            },
        )

    # -------------------------------------------------------------------------
    # Internal state helpers
    # -------------------------------------------------------------------------

    def _set_stage(self, state: MasterExecutionState, stage: str) -> None:
        """Set task stage and update lifecycle."""
        state.stage = stage
        state.updated_at = _utc_now_iso()

        if stage not in state.stages_completed:
            state.stages_completed.append(stage)

    def _append_error(
        self,
        state: MasterExecutionState,
        error_type: str,
        payload: Dict[str, Any],
    ) -> None:
        """Append structured error to state."""
        state.errors.append(
            {
                "error_type": error_type,
                "payload": payload,
                "created_at": _utc_now_iso(),
            }
        )
        state.updated_at = _utc_now_iso()

    async def _create_or_update_task(self, state: MasterExecutionState) -> Dict[str, Any]:
        """Create/update task in task manager if available."""
        self.active_tasks[state.task_id] = state

        try:
            if state.task_id not in getattr(self.task_manager, "tasks", {}):
                if _method_exists(self.task_manager, "create_task"):
                    return self._normalize_result(
                        await _maybe_await(self.task_manager.create_task(state)),
                        "Task created.",
                    )

            if _method_exists(self.task_manager, "update_task"):
                return self._normalize_result(
                    await _maybe_await(
                        self.task_manager.update_task(
                            state.task_id,
                            asdict(state),
                        )
                    ),
                    "Task updated.",
                )

            return self._safe_result(
                message="Task state updated in MasterAgent memory.",
                data=asdict(state),
            )

        except Exception as exc:
            return self._error_result(
                message="Task manager update failed safely.",
                error=exc,
                data=asdict(state),
            )

    # -------------------------------------------------------------------------
    # Compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Delegate SaaS context validation to CoreConfig when available."""
        if _method_exists(self.config, "_validate_task_context"):
            return self.config._validate_task_context(context)

        fallback = FallbackCoreConfig()
        return fallback._validate_task_context(context)

    def _requires_security_check(
        self,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Delegate security decision to CoreConfig when available."""
        if _method_exists(self.config, "_requires_security_check"):
            return self.config._requires_security_check(
                agent_name=agent_name,
                action=action,
                context=context,
            )

        fallback = FallbackCoreConfig()
        return fallback._requires_security_check(agent_name, action, context)

    def _request_security_approval(
        self,
        agent_name: Optional[str],
        action: Optional[str],
        context: Optional[Dict[str, Any]] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Delegate security approval payload preparation to CoreConfig."""
        if _method_exists(self.config, "_request_security_approval"):
            return self.config._request_security_approval(
                agent_name=agent_name,
                action=action,
                context=context,
                payload=payload,
            )

        fallback = FallbackCoreConfig()
        return fallback._request_security_approval(agent_name, action, context, payload)

    def _prepare_verification_payload(
        self,
        task_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        action: Optional[str] = None,
        result: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Delegate verification payload preparation to CoreConfig."""
        if _method_exists(self.config, "_prepare_verification_payload"):
            return self.config._prepare_verification_payload(
                task_id=task_id,
                agent_name=agent_name,
                action=action,
                result=result,
                context=context,
            )

        fallback = FallbackCoreConfig()
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
        """Delegate memory payload preparation to CoreConfig."""
        if _method_exists(self.config, "_prepare_memory_payload"):
            return self.config._prepare_memory_payload(
                task_id=task_id,
                agent_name=agent_name,
                action=action,
                useful_context=useful_context,
                context=context,
            )

        fallback = FallbackCoreConfig()
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
        if _method_exists(self.config, "_emit_agent_event"):
            return self.config._emit_agent_event(
                event_type=event_type,
                data=data,
                user_id=user_id,
                workspace_id=workspace_id,
            )

        fallback = FallbackCoreConfig()
        return fallback._emit_agent_event(event_type, data, user_id, workspace_id)

    def _log_audit_event(
        self,
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """Log dashboard/API-ready audit event."""
        if _method_exists(self.config, "_log_audit_event"):
            return self.config._log_audit_event(
                event_type=event_type,
                data=data,
                user_id=user_id,
                workspace_id=workspace_id,
            )

        fallback = FallbackCoreConfig()
        return fallback._log_audit_event(event_type, data, user_id, workspace_id)

    def _safe_result(
        self,
        message: str = "Success.",
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success result."""
        if _method_exists(self.config, "_safe_result"):
            return self.config._safe_result(
                message=message,
                data=data,
                metadata={
                    "caller": "MasterAgent",
                    **(metadata or {}),
                },
            )

        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": {
                "module": "core.master_agent",
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
        if _method_exists(self.config, "_error_result"):
            return self.config._error_result(
                message=message,
                error=error,
                data=data,
                metadata={
                    "caller": "MasterAgent",
                    **(metadata or {}),
                },
            )

        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": str(error) if error is not None else "UNKNOWN_ERROR",
            "metadata": {
                "module": "core.master_agent",
                "timestamp": _utc_now_iso(),
                **(metadata or {}),
            },
        }

    # -------------------------------------------------------------------------
    # Utility helpers
    # -------------------------------------------------------------------------

    def _normalize_result(
        self,
        result: Any,
        default_message: str = "Operation completed.",
    ) -> Dict[str, Any]:
        """Normalize any output into William/Jarvis structured result."""
        if isinstance(result, dict):
            return {
                "success": bool(result.get("success", False)),
                "message": result.get("message", default_message),
                "data": result.get("data", {}),
                "error": result.get("error"),
                "metadata": {
                    "module": "core.master_agent",
                    "timestamp": _utc_now_iso(),
                    **(result.get("metadata", {}) if isinstance(result.get("metadata"), dict) else {}),
                },
            }

        return {
            "success": True,
            "message": default_message,
            "data": {
                "value": result,
            },
            "error": None,
            "metadata": {
                "module": "core.master_agent",
                "timestamp": _utc_now_iso(),
                "normalized": True,
            },
        }

    def _get_memory_limit(self) -> int:
        """Return memory recall limit."""
        return int(
            getattr(
                getattr(self.config, "memory_config", None),
                "max_memory_context_items",
                20,
            )
        )

    def _get_task_timeout(self, step: Dict[str, Any]) -> int:
        """Return timeout for step execution."""
        explicit_timeout = step.get("timeout_seconds")
        if explicit_timeout:
            try:
                return max(1, int(explicit_timeout))
            except Exception:
                pass

        action = str(step.get("action") or "").lower()

        timeout_config = getattr(self.config, "timeout_config", None)

        if any(word in action for word in ["long", "analyze", "generate", "workflow"]):
            return int(getattr(timeout_config, "long_task_timeout_seconds", 300))

        if any(word in action for word in ["quick", "status", "ping", "health"]):
            return int(getattr(timeout_config, "short_task_timeout_seconds", 15))

        return int(getattr(timeout_config, "default_task_timeout_seconds", 60))


# =============================================================================
# Module-level singleton helpers
# =============================================================================

_default_master_agent: Optional[MasterAgent] = None


def get_master_agent(
    config: Optional[Any] = None,
    agent_registry: Optional[Dict[str, Any]] = None,
    reload_agent: bool = False,
) -> MasterAgent:
    """
    Return singleton-style MasterAgent instance.

    Safe for:
        - FastAPI dependency injection
        - Dashboard controllers
        - CLI tools
        - Agent Loader
        - Agent Registry
    """
    global _default_master_agent

    if _default_master_agent is None or reload_agent:
        _default_master_agent = MasterAgent(
            config=config,
            agent_registry=agent_registry,
        )

    return _default_master_agent


async def handle_master_request(
    message: str,
    user_id: Union[str, int],
    workspace_id: Union[str, int],
    action: str = "general_request",
    preferred_agent: Optional[str] = None,
    input_data: Optional[Dict[str, Any]] = None,
    permissions: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Convenience async function for external callers.
    """
    master = get_master_agent()
    return await master.handle_request(
        message=message,
        user_id=user_id,
        workspace_id=workspace_id,
        action=action,
        preferred_agent=preferred_agent,
        input_data=input_data,
        permissions=permissions,
        metadata=metadata,
    )


def handle_master_request_sync(
    message: str,
    user_id: Union[str, int],
    workspace_id: Union[str, int],
    action: str = "general_request",
    preferred_agent: Optional[str] = None,
    input_data: Optional[Dict[str, Any]] = None,
    permissions: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Convenience sync function for CLI/simple tests.
    """
    master = get_master_agent()
    return master.handle_request_sync(
        message=message,
        user_id=user_id,
        workspace_id=workspace_id,
        action=action,
        preferred_agent=preferred_agent,
        input_data=input_data,
        permissions=permissions,
        metadata=metadata,
    )


__all__ = [
    "MasterAgent",
    "MasterRequest",
    "MasterPlanStep",
    "MasterExecutionState",
    "get_master_agent",
    "handle_master_request",
    "handle_master_request_sync",
]


if __name__ == "__main__":
    master_agent = get_master_agent(reload_agent=True)

    print(
        json.dumps(
            master_agent.health_check(),
            indent=2,
            default=str,
        )
    )

    demo_result = master_agent.handle_request_sync(
        message="Analyze this business request and tell me the next safe action.",
        user_id="demo_user",
        workspace_id="demo_workspace",
        action="general_request",
        preferred_agent="business",
        input_data={
            "demo": True,
        },
        metadata={
            "role": "owner",
            "subscription_plan": "free",
        },
    )

    print(json.dumps(demo_result, indent=2, default=str))


# =============================================================================
# Completion Tracking
# =============================================================================
# Agent/Module: Core Master Control Files
# File Completed: master_agent.py
# Completion: 30.0%
# Completed Files: ['context.py', 'config.py', 'master_agent.py']
# Remaining Files: ['planner.py', 'router.py', 'task_manager.py', 'response_builder.py', 'safety_bridge.py', 'verification_bridge.py', 'memory_bridge.py']
# Next Recommended File: core/planner.py
# FILE COMPLETE