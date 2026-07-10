"""
core/router.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Routes planned tasks to the correct registered agent and handles
    multi-agent execution order.

This Router connects:
    - Master Agent: receives planned tasks and returns structured execution results.
    - Agent Registry / Agent Loader: resolves agents by name, capability, or type.
    - Security Agent: checks sensitive/destructive/high-risk actions before execution.
    - Verification Agent: prepares verification payloads for completed actions.
    - Memory Agent: prepares memory-compatible payloads for useful context.
    - Dashboard/API: emits structured events, audit logs, task history, and metadata.
    - SaaS Layer: enforces user_id/workspace_id isolation for every routed task.

Import-safe:
    This file includes safe fallback stubs so it can be imported even before the
    full William/Jarvis system is complete.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
import traceback
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Optional imports with safe fallbacks
# =============================================================================

try:
    from core.context import TaskContext  # type: ignore
except Exception:  # pragma: no cover
    @dataclass
    class TaskContext:
        """
        Fallback TaskContext.

        Real implementation should live in core/context.py.
        This fallback keeps router.py import-safe.
        """
        user_id: Optional[Union[str, int]] = None
        workspace_id: Optional[Union[str, int]] = None
        role: Optional[str] = None
        permissions: List[str] = field(default_factory=list)
        subscription_plan: Optional[str] = None
        request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
        session_id: Optional[str] = None
        metadata: Dict[str, Any] = field(default_factory=dict)

        def to_dict(self) -> Dict[str, Any]:
            return {
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "role": self.role,
                "permissions": list(self.permissions),
                "subscription_plan": self.subscription_plan,
                "request_id": self.request_id,
                "session_id": self.session_id,
                "metadata": dict(self.metadata or {}),
            }


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:
        """
        Fallback BaseAgent.

        Real implementation should live in agents/base_agent.py.
        """

        name: str = "base_agent"
        agent_type: str = "base"
        capabilities: List[str] = []

        async def execute(self, task: Dict[str, Any], context: Optional[Any] = None) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent cannot execute real tasks.",
                "data": None,
                "error": "BaseAgent implementation missing.",
                "metadata": {
                    "agent_name": self.name,
                    "agent_type": self.agent_type,
                },
            }


try:
    from core.registry import AgentRegistry  # type: ignore
except Exception:  # pragma: no cover
    class AgentRegistry:
        """
        Fallback AgentRegistry.

        Real implementation should live in core/registry.py.
        """

        def __init__(self) -> None:
            self._agents: Dict[str, Any] = {}

        def register(self, name: str, agent: Any) -> None:
            self._agents[str(name)] = agent

        def get_agent(self, name: str) -> Optional[Any]:
            return self._agents.get(str(name))

        def get(self, name: str) -> Optional[Any]:
            return self.get_agent(name)

        def all_agents(self) -> Dict[str, Any]:
            return dict(self._agents)

        def find_by_capability(self, capability: str) -> Optional[Any]:
            for agent in self._agents.values():
                if capability in getattr(agent, "capabilities", []):
                    return agent
            return None


# =============================================================================
# Enums and data structures
# =============================================================================

class RouteStrategy(str, Enum):
    """
    Supported routing strategies.
    """

    AUTO = "auto"
    DIRECT = "direct"
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    FALLBACK = "fallback"


class TaskRiskLevel(str, Enum):
    """
    Risk levels used before routing to agents.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TaskStatus(str, Enum):
    """
    Task status values for dashboard/task history compatibility.
    """

    PENDING = "pending"
    ROUTING = "routing"
    SECURITY_CHECK = "security_check"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    PARTIAL = "partial"


@dataclass
class RouteDecision:
    """
    Represents the routing decision for one task.
    """

    task_id: str
    agent_name: Optional[str]
    strategy: RouteStrategy = RouteStrategy.AUTO
    confidence: float = 0.0
    reason: str = ""
    requires_security: bool = False
    risk_level: TaskRiskLevel = TaskRiskLevel.LOW
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "agent_name": self.agent_name,
            "strategy": self.strategy.value,
            "confidence": self.confidence,
            "reason": self.reason,
            "requires_security": self.requires_security,
            "risk_level": self.risk_level.value,
            "metadata": dict(self.metadata or {}),
        }


@dataclass
class RouterConfig:
    """
    Router configuration.

    Designed to be FastAPI/dashboard friendly and safe by default.
    """

    allow_parallel_execution: bool = True
    max_parallel_tasks: int = 5
    require_context_for_user_tasks: bool = True
    strict_workspace_isolation: bool = True
    security_agent_name: str = "security"
    verification_agent_name: str = "verification"
    memory_agent_name: str = "memory"
    default_timeout_seconds: int = 120
    continue_on_task_failure: bool = True
    emit_events: bool = True
    audit_enabled: bool = True
    memory_enabled: bool = True
    verification_enabled: bool = True


# =============================================================================
# Router
# =============================================================================

class Router:
    """
    Routes planned tasks to registered agents and handles multi-agent execution.

    Main public methods:
        - route_task()
        - route_tasks()
        - execute_task()
        - execute_plan()
        - resolve_agent()
        - register_agent()

    Expected task shape:
        {
            "id": "task-id",
            "type": "browser.search",
            "agent": "browser",
            "capability": "web_search",
            "action": "search",
            "input": {...},
            "requires_security": false,
            "risk_level": "low",
            "metadata": {...}
        }

    Expected result shape:
        {
            "success": bool,
            "message": str,
            "data": Any,
            "error": Optional[str],
            "metadata": {...}
        }
    """

    def __init__(
        self,
        registry: Optional[Any] = None,
        config: Optional[RouterConfig] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ) -> None:
        self.registry = registry or AgentRegistry()
        self.config = config or RouterConfig()
        self.event_callback = event_callback
        self.audit_callback = audit_callback

        self._routing_history: List[Dict[str, Any]] = []
        self._task_history: List[Dict[str, Any]] = []

    # =========================================================================
    # Public registration helpers
    # =========================================================================

    def register_agent(self, name: str, agent: Any) -> Dict[str, Any]:
        """
        Register an agent into the registry.

        This supports future plugin-style agents.
        """
        try:
            if not name or not isinstance(name, str):
                return self._error_result(
                    message="Agent registration failed.",
                    error="Agent name must be a non-empty string.",
                    metadata={"operation": "register_agent"},
                )

            if agent is None:
                return self._error_result(
                    message="Agent registration failed.",
                    error="Agent instance cannot be None.",
                    metadata={"agent_name": name},
                )

            if hasattr(self.registry, "register"):
                self.registry.register(name, agent)
            elif hasattr(self.registry, "agents"):
                self.registry.agents[name] = agent
            else:
                setattr(self.registry, name, agent)

            self._emit_agent_event(
                event_type="agent_registered",
                payload={
                    "agent_name": name,
                    "agent_type": getattr(agent, "agent_type", None),
                    "capabilities": getattr(agent, "capabilities", []),
                },
            )

            return self._safe_result(
                message=f"Agent '{name}' registered successfully.",
                data={"agent_name": name},
                metadata={"operation": "register_agent"},
            )

        except Exception as exc:
            return self._error_result(
                message="Agent registration failed.",
                error=str(exc),
                metadata={
                    "agent_name": name,
                    "traceback": traceback.format_exc(),
                },
            )

    def list_agents(self) -> Dict[str, Any]:
        """
        Return registered agents in dashboard-safe structure.
        """
        try:
            agents = self._get_all_agents()
            data = []

            for name, agent in agents.items():
                data.append(
                    {
                        "name": name,
                        "agent_type": getattr(agent, "agent_type", None),
                        "capabilities": list(getattr(agent, "capabilities", []) or []),
                        "class": agent.__class__.__name__,
                    }
                )

            return self._safe_result(
                message="Registered agents loaded successfully.",
                data=data,
                metadata={"count": len(data)},
            )
        except Exception as exc:
            return self._error_result(
                message="Unable to list agents.",
                error=str(exc),
                metadata={"traceback": traceback.format_exc()},
            )

    # =========================================================================
    # Main routing methods
    # =========================================================================

    def route_task(
        self,
        task: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        strategy: RouteStrategy = RouteStrategy.AUTO,
    ) -> Dict[str, Any]:
        """
        Build a routing decision for one task without executing it.
        """
        started_at = time.time()
        task_dict = self._normalize_task(task)
        task_id = task_dict["id"]

        try:
            context_result = self._validate_task_context(task_dict, context)
            if not context_result["success"]:
                return context_result

            agent = self.resolve_agent(task_dict)
            agent_name = self._get_agent_name(agent) if agent else None

            requires_security = self._requires_security_check(task_dict)
            risk_level = self._get_task_risk_level(task_dict)

            if not agent:
                decision = RouteDecision(
                    task_id=task_id,
                    agent_name=None,
                    strategy=strategy,
                    confidence=0.0,
                    reason="No suitable registered agent found.",
                    requires_security=requires_security,
                    risk_level=risk_level,
                    metadata={
                        "task_type": task_dict.get("type"),
                        "capability": task_dict.get("capability"),
                        "requested_agent": task_dict.get("agent"),
                    },
                )

                return self._error_result(
                    message="Route decision failed.",
                    error="No suitable registered agent found.",
                    data={"decision": decision.to_dict()},
                    metadata={
                        "task_id": task_id,
                        "duration_ms": self._duration_ms(started_at),
                    },
                )

            confidence = self._calculate_route_confidence(task_dict, agent)
            decision = RouteDecision(
                task_id=task_id,
                agent_name=agent_name,
                strategy=strategy,
                confidence=confidence,
                reason="Agent resolved successfully.",
                requires_security=requires_security,
                risk_level=risk_level,
                metadata={
                    "task_type": task_dict.get("type"),
                    "capability": task_dict.get("capability"),
                    "requested_agent": task_dict.get("agent"),
                    "resolved_agent_type": getattr(agent, "agent_type", None),
                },
            )

            route_record = {
                "task_id": task_id,
                "decision": decision.to_dict(),
                "timestamp": time.time(),
            }
            self._routing_history.append(route_record)

            self._emit_agent_event(
                event_type="task_routed",
                payload={
                    "task_id": task_id,
                    "decision": decision.to_dict(),
                    "context": self._context_to_dict(context),
                },
            )

            return self._safe_result(
                message="Task routed successfully.",
                data={
                    "decision": decision.to_dict(),
                    "agent": agent,
                },
                metadata={
                    "task_id": task_id,
                    "duration_ms": self._duration_ms(started_at),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Route decision crashed.",
                error=str(exc),
                metadata={
                    "task_id": task_id,
                    "duration_ms": self._duration_ms(started_at),
                    "traceback": traceback.format_exc(),
                },
            )

    def route_tasks(
        self,
        tasks: Sequence[Mapping[str, Any]],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        strategy: RouteStrategy = RouteStrategy.SEQUENTIAL,
    ) -> Dict[str, Any]:
        """
        Build routing decisions for multiple planned tasks.
        """
        started_at = time.time()

        try:
            if not isinstance(tasks, Sequence) or isinstance(tasks, (str, bytes)):
                return self._error_result(
                    message="Route tasks failed.",
                    error="Tasks must be a sequence of task dictionaries.",
                )

            decisions: List[Dict[str, Any]] = []
            errors: List[Dict[str, Any]] = []

            for raw_task in tasks:
                routed = self.route_task(raw_task, context=context, strategy=strategy)

                if routed.get("success"):
                    decision = routed.get("data", {}).get("decision", {})
                    decisions.append(decision)
                else:
                    errors.append(
                        {
                            "task": self._safe_task_preview(raw_task),
                            "error": routed.get("error"),
                            "message": routed.get("message"),
                        }
                    )

            success = len(errors) == 0
            return self._safe_result(
                success=success,
                message=(
                    "All tasks routed successfully."
                    if success
                    else "Some tasks could not be routed."
                ),
                data={
                    "decisions": decisions,
                    "errors": errors,
                },
                error=None if success else "One or more routing errors occurred.",
                metadata={
                    "total_tasks": len(tasks),
                    "routed_count": len(decisions),
                    "error_count": len(errors),
                    "duration_ms": self._duration_ms(started_at),
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Route tasks crashed.",
                error=str(exc),
                metadata={
                    "duration_ms": self._duration_ms(started_at),
                    "traceback": traceback.format_exc(),
                },
            )

    # =========================================================================
    # Main execution methods
    # =========================================================================

    async def execute_task(
        self,
        task: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        strategy: RouteStrategy = RouteStrategy.AUTO,
    ) -> Dict[str, Any]:
        """
        Route and execute one task.

        Security Agent approval is requested before sensitive actions.
        Verification and Memory payloads are prepared after execution.
        """
        started_at = time.time()
        task_dict = self._normalize_task(task)
        task_id = task_dict["id"]

        self._emit_agent_event(
            event_type="task_execution_started",
            payload={
                "task_id": task_id,
                "task": self._safe_task_preview(task_dict),
                "context": self._context_to_dict(context),
            },
        )

        self._log_audit_event(
            action="task_execution_started",
            task=task_dict,
            context=context,
            metadata={"status": TaskStatus.EXECUTING.value},
        )

        try:
            route_result = self.route_task(task_dict, context=context, strategy=strategy)
            if not route_result.get("success"):
                self._record_task_history(
                    task=task_dict,
                    status=TaskStatus.FAILED,
                    result=route_result,
                    context=context,
                )
                return route_result

            decision = route_result.get("data", {}).get("decision", {})
            agent = route_result.get("data", {}).get("agent")

            if not agent:
                result = self._error_result(
                    message="Task execution failed.",
                    error="Resolved agent instance is missing.",
                    metadata={"task_id": task_id, "decision": decision},
                )
                self._record_task_history(task_dict, TaskStatus.FAILED, result, context)
                return result

            if decision.get("requires_security"):
                security_result = await self._request_security_approval(
                    task=task_dict,
                    context=context,
                    decision=decision,
                )

                if not security_result.get("success"):
                    blocked = self._error_result(
                        message="Task blocked by Security Agent.",
                        error=security_result.get("error") or security_result.get("message"),
                        data={
                            "security_result": security_result,
                            "decision": decision,
                        },
                        metadata={
                            "task_id": task_id,
                            "status": TaskStatus.BLOCKED.value,
                        },
                    )
                    self._record_task_history(task_dict, TaskStatus.BLOCKED, blocked, context)
                    return blocked

            raw_result = await self._execute_agent(agent, task_dict, context)
            normalized_result = self._normalize_agent_result(raw_result)

            verification_payload = self._prepare_verification_payload(
                task=task_dict,
                result=normalized_result,
                context=context,
                decision=decision,
            )

            memory_payload = self._prepare_memory_payload(
                task=task_dict,
                result=normalized_result,
                context=context,
                decision=decision,
            )

            final_result = self._safe_result(
                success=bool(normalized_result.get("success")),
                message=normalized_result.get("message", "Task executed."),
                data={
                    "task_result": normalized_result.get("data"),
                    "agent_result": normalized_result,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "decision": decision,
                },
                error=normalized_result.get("error"),
                metadata={
                    "task_id": task_id,
                    "agent_name": decision.get("agent_name"),
                    "status": (
                        TaskStatus.COMPLETED.value
                        if normalized_result.get("success")
                        else TaskStatus.FAILED.value
                    ),
                    "duration_ms": self._duration_ms(started_at),
                    "context": self._context_to_dict(context),
                },
            )

            self._emit_agent_event(
                event_type="task_execution_completed",
                payload={
                    "task_id": task_id,
                    "success": final_result.get("success"),
                    "agent_name": decision.get("agent_name"),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
            )

            self._log_audit_event(
                action="task_execution_completed",
                task=task_dict,
                context=context,
                metadata={
                    "success": final_result.get("success"),
                    "agent_name": decision.get("agent_name"),
                    "duration_ms": self._duration_ms(started_at),
                },
            )

            self._record_task_history(
                task=task_dict,
                status=TaskStatus.COMPLETED if final_result.get("success") else TaskStatus.FAILED,
                result=final_result,
                context=context,
            )

            return final_result

        except Exception as exc:
            result = self._error_result(
                message="Task execution crashed.",
                error=str(exc),
                metadata={
                    "task_id": task_id,
                    "duration_ms": self._duration_ms(started_at),
                    "traceback": traceback.format_exc(),
                },
            )

            self._emit_agent_event(
                event_type="task_execution_crashed",
                payload={
                    "task_id": task_id,
                    "error": str(exc),
                },
            )

            self._log_audit_event(
                action="task_execution_crashed",
                task=task_dict,
                context=context,
                metadata={
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                },
            )

            self._record_task_history(task_dict, TaskStatus.FAILED, result, context)
            return result

    async def execute_plan(
        self,
        plan: Union[Mapping[str, Any], Sequence[Mapping[str, Any]]],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a plan created by Master Agent / Planner.

        Supported plan shapes:
            {
                "id": "plan-id",
                "strategy": "sequential" | "parallel" | "auto",
                "tasks": [...]
            }

        Or directly:
            [task1, task2, task3]
        """
        started_at = time.time()
        plan_id = str(uuid.uuid4())
        strategy = RouteStrategy.SEQUENTIAL
        tasks: List[Mapping[str, Any]] = []

        try:
            if isinstance(plan, Mapping):
                plan_id = str(plan.get("id") or plan.get("plan_id") or plan_id)
                raw_strategy = str(plan.get("strategy") or RouteStrategy.SEQUENTIAL.value).lower()
                strategy = self._parse_strategy(raw_strategy)
                raw_tasks = plan.get("tasks", [])
                if not isinstance(raw_tasks, Sequence) or isinstance(raw_tasks, (str, bytes)):
                    return self._error_result(
                        message="Plan execution failed.",
                        error="Plan tasks must be a list of task dictionaries.",
                        metadata={"plan_id": plan_id},
                    )
                tasks = list(raw_tasks)
            elif isinstance(plan, Sequence) and not isinstance(plan, (str, bytes)):
                tasks = list(plan)
                strategy = RouteStrategy.SEQUENTIAL
            else:
                return self._error_result(
                    message="Plan execution failed.",
                    error="Plan must be a dict or sequence of task dictionaries.",
                )

            if not tasks:
                return self._safe_result(
                    success=True,
                    message="Plan has no tasks to execute.",
                    data={"plan_id": plan_id, "results": []},
                    metadata={"task_count": 0},
                )

            self._emit_agent_event(
                event_type="plan_execution_started",
                payload={
                    "plan_id": plan_id,
                    "strategy": strategy.value,
                    "task_count": len(tasks),
                    "context": self._context_to_dict(context),
                },
            )

            self._log_audit_event(
                action="plan_execution_started",
                task={"id": plan_id, "type": "plan", "tasks_count": len(tasks)},
                context=context,
                metadata={"strategy": strategy.value},
            )

            if strategy == RouteStrategy.PARALLEL and self.config.allow_parallel_execution:
                results = await self._execute_parallel(tasks, context)
            else:
                results = await self._execute_sequential(tasks, context)

            success_count = sum(1 for item in results if item.get("success"))
            failure_count = len(results) - success_count

            status = (
                TaskStatus.COMPLETED.value
                if failure_count == 0
                else TaskStatus.PARTIAL.value
                if success_count > 0
                else TaskStatus.FAILED.value
            )

            final_result = self._safe_result(
                success=failure_count == 0,
                message=(
                    "Plan executed successfully."
                    if failure_count == 0
                    else "Plan executed with one or more failed tasks."
                ),
                data={
                    "plan_id": plan_id,
                    "strategy": strategy.value,
                    "results": results,
                    "summary": {
                        "total_tasks": len(tasks),
                        "success_count": success_count,
                        "failure_count": failure_count,
                        "status": status,
                    },
                },
                error=None if failure_count == 0 else "One or more plan tasks failed.",
                metadata={
                    "plan_id": plan_id,
                    "duration_ms": self._duration_ms(started_at),
                    "context": self._context_to_dict(context),
                },
            )

            self._emit_agent_event(
                event_type="plan_execution_completed",
                payload={
                    "plan_id": plan_id,
                    "success": final_result.get("success"),
                    "summary": final_result["data"]["summary"],
                },
            )

            self._log_audit_event(
                action="plan_execution_completed",
                task={"id": plan_id, "type": "plan"},
                context=context,
                metadata=final_result["data"]["summary"],
            )

            return final_result

        except Exception as exc:
            return self._error_result(
                message="Plan execution crashed.",
                error=str(exc),
                metadata={
                    "plan_id": plan_id,
                    "duration_ms": self._duration_ms(started_at),
                    "traceback": traceback.format_exc(),
                },
            )

    # =========================================================================
    # Agent resolution
    # =========================================================================

    def resolve_agent(self, task: Mapping[str, Any]) -> Optional[Any]:
        """
        Resolve the best registered agent for a task.

        Resolution order:
            1. Explicit agent name.
            2. Capability.
            3. Task type prefix.
            4. Action name.
            5. Fallback capability matching.
        """
        task_dict = self._normalize_task(task)

        explicit_agent = task_dict.get("agent") or task_dict.get("agent_name")
        if explicit_agent:
            agent = self._get_agent(str(explicit_agent))
            if agent:
                return agent

        capability = task_dict.get("capability")
        if capability:
            agent = self._find_agent_by_capability(str(capability))
            if agent:
                return agent

        task_type = str(task_dict.get("type") or "")
        if "." in task_type:
            prefix = task_type.split(".", 1)[0]
            agent = self._get_agent(prefix)
            if agent:
                return agent

            agent = self._find_agent_by_capability(prefix)
            if agent:
                return agent

        action = task_dict.get("action")
        if action:
            agent = self._find_agent_by_capability(str(action))
            if agent:
                return agent

        return self._fallback_agent_match(task_dict)

    # =========================================================================
    # Required compatibility hooks
    # =========================================================================

    def _validate_task_context(
        self,
        task: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation before routing.

        Every user-specific task must include user_id and workspace_id either:
            - inside context
            - inside task
        """
        try:
            task_dict = dict(task)
            context_dict = self._context_to_dict(context)

            user_id = context_dict.get("user_id") or task_dict.get("user_id")
            workspace_id = context_dict.get("workspace_id") or task_dict.get("workspace_id")

            user_specific = bool(
                task_dict.get("user_specific", True)
                or task_dict.get("requires_user_context", True)
                or task_dict.get("user_id")
                or task_dict.get("workspace_id")
                or context_dict.get("user_id")
                or context_dict.get("workspace_id")
            )

            if self.config.require_context_for_user_tasks and user_specific:
                if user_id in (None, "", 0, "0"):
                    return self._error_result(
                        message="Task context validation failed.",
                        error="Missing user_id for user-specific task.",
                        metadata={
                            "task_id": task_dict.get("id"),
                            "required": "user_id",
                        },
                    )

                if workspace_id in (None, "", 0, "0"):
                    return self._error_result(
                        message="Task context validation failed.",
                        error="Missing workspace_id for user-specific task.",
                        metadata={
                            "task_id": task_dict.get("id"),
                            "required": "workspace_id",
                        },
                    )

            if self.config.strict_workspace_isolation:
                task_user_id = task_dict.get("user_id")
                task_workspace_id = task_dict.get("workspace_id")

                if task_user_id and context_dict.get("user_id") and str(task_user_id) != str(context_dict["user_id"]):
                    return self._error_result(
                        message="Task context validation failed.",
                        error="Task user_id does not match context user_id.",
                        metadata={
                            "task_user_id": task_user_id,
                            "context_user_id": context_dict.get("user_id"),
                        },
                    )

                if (
                    task_workspace_id
                    and context_dict.get("workspace_id")
                    and str(task_workspace_id) != str(context_dict["workspace_id"])
                ):
                    return self._error_result(
                        message="Task context validation failed.",
                        error="Task workspace_id does not match context workspace_id.",
                        metadata={
                            "task_workspace_id": task_workspace_id,
                            "context_workspace_id": context_dict.get("workspace_id"),
                        },
                    )

            return self._safe_result(
                message="Task context validated successfully.",
                data={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "user_specific": user_specific,
                },
                metadata={"task_id": task_dict.get("id")},
            )

        except Exception as exc:
            return self._error_result(
                message="Task context validation crashed.",
                error=str(exc),
                metadata={"traceback": traceback.format_exc()},
            )

    def _requires_security_check(self, task: Mapping[str, Any]) -> bool:
        """
        Decide whether task must go through Security Agent.
        """
        if bool(task.get("requires_security")):
            return True

        risk_level = self._get_task_risk_level(task)
        if risk_level in (TaskRiskLevel.HIGH, TaskRiskLevel.CRITICAL):
            return True

        sensitive_keywords = {
            "delete",
            "remove",
            "destroy",
            "payment",
            "finance",
            "transfer",
            "charge",
            "call",
            "message",
            "email_send",
            "send_email",
            "browser_purchase",
            "system_command",
            "shell",
            "terminal",
            "file_write",
            "file_delete",
            "permission_change",
            "security",
            "credential",
            "secret",
            "token",
            "oauth",
        }

        fields_to_scan = [
            str(task.get("type") or "").lower(),
            str(task.get("action") or "").lower(),
            str(task.get("capability") or "").lower(),
            str(task.get("agent") or "").lower(),
        ]

        return any(keyword in field for field in fields_to_scan for keyword in sensitive_keywords)

    async def _request_security_approval(
        self,
        task: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        decision: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent.

        If Security Agent is not registered, high/critical tasks are blocked by default.
        Medium/low tasks may pass with a warning if explicitly allowed by config.
        """
        security_agent = self._get_agent(self.config.security_agent_name)
        risk_level = self._get_task_risk_level(task)

        payload = {
            "id": f"security-{task.get('id', uuid.uuid4())}",
            "type": "security.approval",
            "action": "approve_task",
            "input": {
                "task": self._safe_task_preview(task),
                "decision": dict(decision or {}),
                "risk_level": risk_level.value,
                "context": self._context_to_dict(context),
            },
            "user_id": self._context_to_dict(context).get("user_id") or task.get("user_id"),
            "workspace_id": self._context_to_dict(context).get("workspace_id") or task.get("workspace_id"),
            "requires_security": False,
            "risk_level": "low",
        }

        if not security_agent:
            if risk_level in (TaskRiskLevel.HIGH, TaskRiskLevel.CRITICAL):
                return self._error_result(
                    message="Security approval failed.",
                    error="Security Agent is not registered. High-risk task blocked by default.",
                    metadata={
                        "task_id": task.get("id"),
                        "risk_level": risk_level.value,
                    },
                )

            return self._safe_result(
                message="Security Agent not registered. Low/medium risk task allowed with warning.",
                data={"approved": True, "warning": "security_agent_missing"},
                metadata={
                    "task_id": task.get("id"),
                    "risk_level": risk_level.value,
                },
            )

        try:
            raw_result = await self._execute_agent(security_agent, payload, context)
            result = self._normalize_agent_result(raw_result)

            approved = bool(
                result.get("success")
                and (
                    result.get("data", {}).get("approved") is True
                    or result.get("data", {}).get("allowed") is True
                    or result.get("approved") is True
                )
            )

            if not approved:
                return self._error_result(
                    message="Security Agent rejected the task.",
                    error=result.get("error") or result.get("message") or "Task not approved.",
                    data={"security_agent_result": result},
                    metadata={
                        "task_id": task.get("id"),
                        "risk_level": risk_level.value,
                    },
                )

            return self._safe_result(
                message="Security Agent approved the task.",
                data={"approved": True, "security_agent_result": result},
                metadata={
                    "task_id": task.get("id"),
                    "risk_level": risk_level.value,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Security approval crashed.",
                error=str(exc),
                metadata={
                    "task_id": task.get("id"),
                    "risk_level": risk_level.value,
                    "traceback": traceback.format_exc(),
                },
            )

    def _prepare_verification_payload(
        self,
        task: Mapping[str, Any],
        result: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        decision: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.

        This does not require Verification Agent to exist yet.
        """
        return {
            "id": f"verify-{task.get('id', uuid.uuid4())}",
            "type": "verification.review",
            "action": "verify_task_result",
            "user_id": self._context_to_dict(context).get("user_id") or task.get("user_id"),
            "workspace_id": self._context_to_dict(context).get("workspace_id") or task.get("workspace_id"),
            "input": {
                "task_id": task.get("id"),
                "task_type": task.get("type"),
                "agent_name": dict(decision or {}).get("agent_name"),
                "success": result.get("success"),
                "message": result.get("message"),
                "error": result.get("error"),
                "result_preview": self._safe_data_preview(result.get("data")),
            },
            "metadata": {
                "source": "core.router",
                "created_at": time.time(),
                "decision": dict(decision or {}),
            },
        }

    def _prepare_memory_payload(
        self,
        task: Mapping[str, Any],
        result: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        decision: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Keeps memory scoped to user_id/workspace_id.
        """
        context_dict = self._context_to_dict(context)

        return {
            "id": f"memory-{task.get('id', uuid.uuid4())}",
            "type": "memory.store_candidate",
            "action": "prepare_memory_candidate",
            "user_id": context_dict.get("user_id") or task.get("user_id"),
            "workspace_id": context_dict.get("workspace_id") or task.get("workspace_id"),
            "input": {
                "task_id": task.get("id"),
                "task_type": task.get("type"),
                "agent_name": dict(decision or {}).get("agent_name"),
                "useful_context": {
                    "task_input_preview": self._safe_data_preview(task.get("input")),
                    "result_preview": self._safe_data_preview(result.get("data")),
                    "message": result.get("message"),
                },
            },
            "metadata": {
                "source": "core.router",
                "created_at": time.time(),
                "memory_scope": "workspace",
                "context": context_dict,
            },
        }

    def _emit_agent_event(
        self,
        event_type: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit dashboard/API-compatible router event.

        Safe no-op when callback is not configured.
        """
        if not self.config.emit_events:
            return

        event = {
            "id": str(uuid.uuid4()),
            "event_type": event_type,
            "source": "core.router",
            "payload": dict(payload or {}),
            "timestamp": time.time(),
        }

        try:
            if self.event_callback:
                output = self.event_callback(event)
                if inspect.isawaitable(output):
                    asyncio.create_task(output)
            else:
                logger.debug("Router event: %s", event)
        except Exception:
            logger.exception("Router event callback failed.")

    def _log_audit_event(
        self,
        action: str,
        task: Optional[Mapping[str, Any]] = None,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Write audit log event.

        Safe no-op when callback is not configured.
        """
        if not self.config.audit_enabled:
            return

        audit_event = {
            "id": str(uuid.uuid4()),
            "action": action,
            "source": "core.router",
            "task": self._safe_task_preview(task or {}),
            "context": self._context_to_dict(context),
            "metadata": dict(metadata or {}),
            "timestamp": time.time(),
        }

        try:
            if self.audit_callback:
                output = self.audit_callback(audit_event)
                if inspect.isawaitable(output):
                    asyncio.create_task(output)
            else:
                logger.info("Router audit event: %s", audit_event)
        except Exception:
            logger.exception("Router audit callback failed.")

    def _safe_result(
        self,
        message: str = "Success.",
        data: Any = None,
        error: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        success: bool = True,
    ) -> Dict[str, Any]:
        """
        Standard success result shape.
        """
        return {
            "success": bool(success),
            "message": message,
            "data": data,
            "error": error,
            "metadata": dict(metadata or {}),
        }

    def _error_result(
        self,
        message: str = "Error.",
        error: Optional[str] = None,
        data: Any = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result shape.
        """
        return {
            "success": False,
            "message": message,
            "data": data,
            "error": error or message,
            "metadata": dict(metadata or {}),
        }

    # =========================================================================
    # Internal execution helpers
    # =========================================================================

    async def _execute_sequential(
        self,
        tasks: Sequence[Mapping[str, Any]],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Execute tasks one-by-one in planned order.
        """
        results: List[Dict[str, Any]] = []

        for task in tasks:
            result = await self.execute_task(task, context=context, strategy=RouteStrategy.SEQUENTIAL)
            results.append(result)

            if not result.get("success") and not self.config.continue_on_task_failure:
                break

        return results

    async def _execute_parallel(
        self,
        tasks: Sequence[Mapping[str, Any]],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Execute tasks in parallel with max concurrency.

        Security checks still run per task.
        """
        semaphore = asyncio.Semaphore(max(1, int(self.config.max_parallel_tasks)))

        async def run_one(task: Mapping[str, Any]) -> Dict[str, Any]:
            async with semaphore:
                return await self.execute_task(task, context=context, strategy=RouteStrategy.PARALLEL)

        return list(await asyncio.gather(*(run_one(task) for task in tasks)))

    async def _execute_agent(
        self,
        agent: Any,
        task: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Any:
        """
        Execute an agent using supported public method names.

        Supported methods:
            - execute(task, context)
            - run(task, context)
            - handle(task, context)
            - process(task, context)
            - __call__(task, context)
        """
        methods = ["execute", "run", "handle", "process"]

        for method_name in methods:
            method = getattr(agent, method_name, None)
            if callable(method):
                return await self._call_maybe_async(method, task, context)

        if callable(agent):
            return await self._call_maybe_async(agent, task, context)

        return self._error_result(
            message="Agent execution failed.",
            error=f"Agent '{self._get_agent_name(agent)}' has no executable method.",
            metadata={
                "agent_class": agent.__class__.__name__,
                "supported_methods": methods,
            },
        )

    async def _call_maybe_async(
        self,
        func: Callable[..., Any],
        task: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Any:
        """
        Call sync or async function safely.

        Attempts compatible signatures:
            func(task, context)
            func(task=task, context=context)
            func(task)
        """
        try:
            value = func(task, context)
        except TypeError:
            try:
                value = func(task=task, context=context)
            except TypeError:
                value = func(task)

        if inspect.isawaitable(value):
            return await value

        return value

    # =========================================================================
    # Registry helpers
    # =========================================================================

    def _get_agent(self, name: str) -> Optional[Any]:
        """
        Safely fetch agent from registry.
        """
        if not name:
            return None

        possible_names = [
            name,
            name.lower(),
            name.upper(),
            f"{name}_agent",
            f"{name.lower()}_agent",
        ]

        for candidate in possible_names:
            try:
                if hasattr(self.registry, "get_agent"):
                    agent = self.registry.get_agent(candidate)
                    if agent:
                        return agent

                if hasattr(self.registry, "get"):
                    agent = self.registry.get(candidate)
                    if agent:
                        return agent

                if hasattr(self.registry, "agents"):
                    agent = getattr(self.registry, "agents", {}).get(candidate)
                    if agent:
                        return agent

                if hasattr(self.registry, "_agents"):
                    agent = getattr(self.registry, "_agents", {}).get(candidate)
                    if agent:
                        return agent

            except Exception:
                logger.debug("Registry lookup failed for candidate: %s", candidate, exc_info=True)

        return None

    def _get_all_agents(self) -> Dict[str, Any]:
        """
        Return all agents from registry in dictionary form.
        """
        try:
            if hasattr(self.registry, "all_agents"):
                agents = self.registry.all_agents()
                if isinstance(agents, Mapping):
                    return dict(agents)

            if hasattr(self.registry, "agents"):
                agents = getattr(self.registry, "agents")
                if isinstance(agents, Mapping):
                    return dict(agents)

            if hasattr(self.registry, "_agents"):
                agents = getattr(self.registry, "_agents")
                if isinstance(agents, Mapping):
                    return dict(agents)

            return {}
        except Exception:
            logger.exception("Unable to load agents from registry.")
            return {}

    def _find_agent_by_capability(self, capability: str) -> Optional[Any]:
        """
        Find agent by capability.
        """
        if not capability:
            return None

        try:
            if hasattr(self.registry, "find_by_capability"):
                agent = self.registry.find_by_capability(capability)
                if agent:
                    return agent
        except Exception:
            logger.debug("Registry find_by_capability failed.", exc_info=True)

        capability_lower = capability.lower()
        for _, agent in self._get_all_agents().items():
            capabilities = [
                str(item).lower()
                for item in (getattr(agent, "capabilities", []) or [])
            ]
            if capability_lower in capabilities:
                return agent

        return None

    def _fallback_agent_match(self, task: Mapping[str, Any]) -> Optional[Any]:
        """
        Last-resort matching using task text fields.
        """
        searchable = " ".join(
            [
                str(task.get("type") or ""),
                str(task.get("action") or ""),
                str(task.get("capability") or ""),
                str(task.get("description") or ""),
            ]
        ).lower()

        if not searchable.strip():
            return None

        for name, agent in self._get_all_agents().items():
            name_lower = str(name).lower()
            agent_type = str(getattr(agent, "agent_type", "") or "").lower()
            capabilities = [
                str(item).lower()
                for item in (getattr(agent, "capabilities", []) or [])
            ]

            if name_lower and name_lower in searchable:
                return agent

            if agent_type and agent_type in searchable:
                return agent

            if any(capability in searchable for capability in capabilities):
                return agent

        return None

    # =========================================================================
    # Normalization helpers
    # =========================================================================

    def _normalize_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Normalize task into safe dictionary.

        Does not mutate original task.
        """
        if not isinstance(task, Mapping):
            return {
                "id": str(uuid.uuid4()),
                "type": "unknown",
                "action": "unknown",
                "input": {"raw_task": task},
                "metadata": {},
            }

        task_dict = dict(task)

        if not task_dict.get("id"):
            task_dict["id"] = str(task_dict.get("task_id") or uuid.uuid4())

        if not task_dict.get("type"):
            task_dict["type"] = str(task_dict.get("action") or "general.task")

        if "input" not in task_dict:
            task_dict["input"] = {}

        if not isinstance(task_dict.get("metadata"), Mapping):
            task_dict["metadata"] = {}

        return task_dict

    def _normalize_agent_result(self, result: Any) -> Dict[str, Any]:
        """
        Normalize any agent output into standard result shape.
        """
        if isinstance(result, Mapping):
            result_dict = dict(result)
            return {
                "success": bool(result_dict.get("success", True)),
                "message": str(result_dict.get("message") or "Agent completed task."),
                "data": result_dict.get("data"),
                "error": result_dict.get("error"),
                "metadata": dict(result_dict.get("metadata") or {}),
            }

        return {
            "success": True,
            "message": "Agent completed task.",
            "data": result,
            "error": None,
            "metadata": {},
        }

    def _context_to_dict(
        self,
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Convert context object or mapping to dict.
        """
        if context is None:
            return {}

        if isinstance(context, Mapping):
            return dict(context)

        if hasattr(context, "to_dict") and callable(getattr(context, "to_dict")):
            try:
                return dict(context.to_dict())
            except Exception:
                logger.debug("context.to_dict() failed.", exc_info=True)

        data: Dict[str, Any] = {}
        for key in [
            "user_id",
            "workspace_id",
            "role",
            "permissions",
            "subscription_plan",
            "request_id",
            "session_id",
            "metadata",
        ]:
            if hasattr(context, key):
                data[key] = getattr(context, key)

        return data

    def _parse_strategy(self, raw_strategy: str) -> RouteStrategy:
        """
        Parse strategy string safely.
        """
        try:
            return RouteStrategy(str(raw_strategy).lower())
        except Exception:
            return RouteStrategy.SEQUENTIAL

    def _get_task_risk_level(self, task: Mapping[str, Any]) -> TaskRiskLevel:
        """
        Resolve task risk level.
        """
        raw = str(task.get("risk_level") or "").lower().strip()
        if raw:
            try:
                return TaskRiskLevel(raw)
            except Exception:
                pass

        action_text = " ".join(
            [
                str(task.get("type") or ""),
                str(task.get("action") or ""),
                str(task.get("capability") or ""),
                str(task.get("agent") or ""),
            ]
        ).lower()

        critical_terms = ["delete_account", "payment_transfer", "credential", "secret", "token"]
        high_terms = ["delete", "financial", "finance", "send_email", "call", "system_command", "shell"]
        medium_terms = ["browser", "file_write", "message", "external_api", "oauth"]

        if any(term in action_text for term in critical_terms):
            return TaskRiskLevel.CRITICAL

        if any(term in action_text for term in high_terms):
            return TaskRiskLevel.HIGH

        if any(term in action_text for term in medium_terms):
            return TaskRiskLevel.MEDIUM

        return TaskRiskLevel.LOW

    def _calculate_route_confidence(self, task: Mapping[str, Any], agent: Any) -> float:
        """
        Calculate basic confidence for routing decision.
        """
        confidence = 0.25

        requested_agent = task.get("agent") or task.get("agent_name")
        agent_name = self._get_agent_name(agent)

        if requested_agent and str(requested_agent).lower() in str(agent_name).lower():
            confidence += 0.35

        capability = task.get("capability")
        capabilities = [
            str(item).lower()
            for item in (getattr(agent, "capabilities", []) or [])
        ]

        if capability and str(capability).lower() in capabilities:
            confidence += 0.30

        task_type = str(task.get("type") or "").lower()
        agent_type = str(getattr(agent, "agent_type", "") or "").lower()

        if agent_type and agent_type in task_type:
            confidence += 0.10

        return min(round(confidence, 2), 1.0)

    def _get_agent_name(self, agent: Any) -> str:
        """
        Return safe agent name.
        """
        return str(
            getattr(agent, "name", None)
            or getattr(agent, "agent_name", None)
            or getattr(agent, "agent_type", None)
            or agent.__class__.__name__
        )

    def _record_task_history(
        self,
        task: Mapping[str, Any],
        status: TaskStatus,
        result: Mapping[str, Any],
        context: Optional[Union[TaskContext, Mapping[str, Any]]] = None,
    ) -> None:
        """
        Store lightweight task history for dashboard/API use.

        Real production system can replace this with DB persistence.
        """
        record = {
            "id": str(uuid.uuid4()),
            "task_id": task.get("id"),
            "task_type": task.get("type"),
            "status": status.value,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "error": result.get("error"),
            "context": self._context_to_dict(context),
            "timestamp": time.time(),
        }

        self._task_history.append(record)

    def _safe_task_preview(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Return task preview without large/sensitive payload.
        """
        task_dict = dict(task or {})
        safe = {
            "id": task_dict.get("id"),
            "type": task_dict.get("type"),
            "agent": task_dict.get("agent") or task_dict.get("agent_name"),
            "capability": task_dict.get("capability"),
            "action": task_dict.get("action"),
            "user_id": task_dict.get("user_id"),
            "workspace_id": task_dict.get("workspace_id"),
            "requires_security": task_dict.get("requires_security"),
            "risk_level": task_dict.get("risk_level"),
            "metadata": task_dict.get("metadata", {}),
        }

        return self._redact_sensitive(safe)

    def _safe_data_preview(self, data: Any, max_chars: int = 1000) -> Any:
        """
        Return short preview of arbitrary data.
        """
        try:
            if data is None:
                return None

            if isinstance(data, (str, int, float, bool)):
                value = data
            elif isinstance(data, Mapping):
                value = self._redact_sensitive(dict(data))
            elif isinstance(data, Sequence) and not isinstance(data, (str, bytes)):
                value = list(data)[:10]
            else:
                value = repr(data)

            text = str(value)
            if len(text) > max_chars:
                return text[:max_chars] + "...[truncated]"

            return value

        except Exception:
            return "[unavailable_preview]"

    def _redact_sensitive(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact sensitive fields before events, logs, audit, memory, verification.
        """
        sensitive_keys = {
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "credential",
            "private_key",
            "access_token",
            "refresh_token",
        }

        redacted: Dict[str, Any] = {}
        for key, value in data.items():
            key_lower = str(key).lower()
            if any(sensitive in key_lower for sensitive in sensitive_keys):
                redacted[key] = "[REDACTED]"
            elif isinstance(value, Mapping):
                redacted[key] = self._redact_sensitive(dict(value))
            else:
                redacted[key] = value

        return redacted

    def _duration_ms(self, started_at: float) -> int:
        """
        Milliseconds since start.
        """
        return int((time.time() - started_at) * 1000)

    # =========================================================================
    # Dashboard/API helper accessors
    # =========================================================================

    def get_routing_history(self, limit: int = 100) -> Dict[str, Any]:
        """
        Return recent routing history.
        """
        return self._safe_result(
            message="Routing history loaded successfully.",
            data=self._routing_history[-abs(int(limit)):],
            metadata={"count": min(len(self._routing_history), abs(int(limit)))},
        )

    def get_task_history(self, limit: int = 100) -> Dict[str, Any]:
        """
        Return recent task execution history.
        """
        return self._safe_result(
            message="Task history loaded successfully.",
            data=self._task_history[-abs(int(limit)):],
            metadata={"count": min(len(self._task_history), abs(int(limit)))},
        )

    def clear_history(self) -> Dict[str, Any]:
        """
        Clear in-memory route/task history.

        Production DB logs should not be cleared here.
        """
        routing_count = len(self._routing_history)
        task_count = len(self._task_history)

        self._routing_history.clear()
        self._task_history.clear()

        return self._safe_result(
            message="Router in-memory history cleared.",
            data={
                "routing_records_cleared": routing_count,
                "task_records_cleared": task_count,
            },
        )


__all__ = [
    "Router",
    "RouterConfig",
    "RouteDecision",
    "RouteStrategy",
    "TaskRiskLevel",
    "TaskStatus",
]