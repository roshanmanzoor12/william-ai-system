"""
agents/agent_router.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Agent-level router that maps intents to agents and supports fallback routing
    and multi-agent chains.

Responsibilities:
    - Route tasks from Master Agent / API / Dashboard to the correct agent.
    - Map user intent to agent keys.
    - Support fallback routing when primary agent fails or is unavailable.
    - Support multi-agent chains for complex workflows.
    - Preserve SaaS user/workspace isolation.
    - Request Security Agent approval for sensitive tasks.
    - Prepare Verification Agent and Memory Agent compatible payloads.
    - Emit events and audit logs for dashboard analytics.
    - Remain import-safe even if future William modules are not created yet.

Global Safety:
    - Never mix user/workspace memory, logs, tasks, files, or analytics.
    - Every user-specific task must include user_id and workspace_id.
    - Sensitive actions must go through Security Agent.
    - No real destructive/system/financial/browser/call/message action is executed
      by this router directly. It only routes to agents after permission checks.
"""

from __future__ import annotations

import logging
import re
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union


# =============================================================================
# Safe fallback imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe before the real BaseAgent exists.
        """

        agent_name: str = "base_agent"
        agent_type: str = "base"

        def __init__(
            self,
            user_id: Optional[Union[str, int]] = None,
            workspace_id: Optional[Union[str, int]] = None,
            config: Optional[Dict[str, Any]] = None,
            **kwargs: Any,
        ) -> None:
            self.user_id = user_id
            self.workspace_id = workspace_id
            self.config = config or {}
            self.extra_context = kwargs

        def run(self, task: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback BaseAgent run completed.",
                "data": {"task": task or {}, "kwargs": kwargs},
                "error": None,
                "metadata": {
                    "fallback_base_agent": True,
                    "timestamp": time.time(),
                },
            }

        def health_check(self) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback BaseAgent health check passed.",
                "data": {},
                "error": None,
                "metadata": {"timestamp": time.time()},
            }


try:
    from agents.agent_loader import AgentLoader  # type: ignore
except Exception:  # pragma: no cover
    class AgentLoader:  # type: ignore
        """
        Fallback AgentLoader stub.

        Keeps AgentRouter import-safe before real AgentLoader is available.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self._agents: Dict[str, Any] = {}

        def get_agent_instance(
            self,
            agent_key: str,
            user_id: Union[str, int],
            workspace_id: Union[str, int],
            role: Optional[str] = None,
            agent_config: Optional[Dict[str, Any]] = None,
            force_new: bool = False,
            **kwargs: Any,
        ) -> Dict[str, Any]:
            agent = BaseAgent(
                user_id=user_id,
                workspace_id=workspace_id,
                config=agent_config or {},
                agent_key=agent_key,
                role=role,
                **kwargs,
            )
            return {
                "success": True,
                "message": "Fallback AgentLoader returned fallback BaseAgent.",
                "data": {
                    "agent": agent,
                    "agent_key": agent_key,
                    "fallback": True,
                },
                "error": None,
                "metadata": {"timestamp": time.time()},
            }


try:
    from agents.registry import AgentRegistry  # type: ignore
except Exception:  # pragma: no cover
    class AgentRegistry:  # type: ignore
        """
        Fallback registry stub.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self._agents: Dict[str, Dict[str, Any]] = {}

        def list_agents(self) -> List[Dict[str, Any]]:
            return list(self._agents.values())

        def get_agent(self, key: str) -> Optional[Dict[str, Any]]:
            return self._agents.get(key)


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.agents.agent_router")
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# =============================================================================
# Enums and data structures
# =============================================================================

class RouteMode(str, Enum):
    """
    Supported routing modes.
    """

    SINGLE = "single"
    FALLBACK = "fallback"
    CHAIN = "chain"
    BROADCAST = "broadcast"


class ChainMode(str, Enum):
    """
    Supported multi-agent chain execution modes.
    """

    SEQUENTIAL = "sequential"
    STOP_ON_FAILURE = "stop_on_failure"
    BEST_EFFORT = "best_effort"


class RouteStatus(str, Enum):
    """
    Route lifecycle states for audit/dashboard.
    """

    CREATED = "created"
    APPROVED = "approved"
    ROUTED = "routed"
    COMPLETED = "completed"
    FAILED = "failed"
    DENIED = "denied"


@dataclass
class RouteMatch:
    """
    Result of intent matching.
    """

    intent: str
    agent_key: str
    confidence: float = 1.0
    reason: str = "direct_match"
    route_mode: RouteMode = RouteMode.SINGLE
    fallback_agents: List[str] = field(default_factory=list)
    chain_agents: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RouteRequest:
    """
    Normalized route request.

    Every user-specific request must include user_id and workspace_id to prevent
    mixing memory, logs, permissions, and analytics across SaaS tenants.
    """

    task: Dict[str, Any]
    user_id: Union[str, int]
    workspace_id: Union[str, int]
    intent: Optional[str] = None
    requested_agent: Optional[str] = None
    role: str = "default"
    route_mode: RouteMode = RouteMode.SINGLE
    chain_agents: List[str] = field(default_factory=list)
    fallback_agents: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    route_id: str = field(default_factory=lambda: str(uuid.uuid4()))


@dataclass
class AgentRoute:
    """
    Intent-to-agent route definition.
    """

    intent: str
    agent_key: str
    patterns: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)
    fallback_agents: List[str] = field(default_factory=list)
    chain_agents: List[str] = field(default_factory=list)
    route_mode: RouteMode = RouteMode.SINGLE
    enabled: bool = True
    priority: int = 100
    requires_security: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentRouterConfig:
    """
    Runtime configuration for AgentRouter.
    """

    default_agent: str = "business"
    fallback_agent: str = "business"
    security_agent_key: str = "security"
    memory_agent_key: str = "memory"
    verification_agent_key: str = "verification"

    default_role: str = "default"
    min_confidence: float = 0.35
    allow_fallback: bool = True
    allow_chain_execution: bool = True
    allow_broadcast: bool = False

    max_chain_length: int = 8
    max_fallback_attempts: int = 3

    audit_enabled: bool = True
    emit_events: bool = True
    verification_enabled: bool = True
    memory_payload_enabled: bool = True

    safe_default_approval_without_security_agent: bool = True
    include_tracebacks: bool = True


# =============================================================================
# Default route map
# =============================================================================

DEFAULT_AGENT_ROUTES: List[AgentRoute] = [
    AgentRoute(
        intent="voice",
        agent_key="voice",
        keywords=["voice", "speak", "listen", "microphone", "wake word", "audio", "tts", "stt"],
        patterns=[r"\bvoice\b", r"\bspeak\b", r"\blisten\b", r"\bwake\s*word\b"],
        fallback_agents=["business"],
        priority=10,
    ),
    AgentRoute(
        intent="system",
        agent_key="system",
        keywords=["system", "device", "os", "file", "folder", "computer", "desktop", "process"],
        patterns=[r"\bsystem\b", r"\bdevice\b", r"\bcomputer\b", r"\bprocess\b"],
        fallback_agents=["security", "business"],
        priority=10,
        requires_security=True,
    ),
    AgentRoute(
        intent="browser",
        agent_key="browser",
        keywords=["browser", "website", "web", "search", "page", "url", "open website"],
        patterns=[r"\bbrowser\b", r"\bwebsite\b", r"\burl\b", r"\bweb\s*search\b"],
        fallback_agents=["business"],
        priority=10,
        requires_security=True,
    ),
    AgentRoute(
        intent="code",
        agent_key="code",
        keywords=["code", "python", "javascript", "debug", "function", "class", "file", "programming"],
        patterns=[r"\bcode\b", r"\bdebug\b", r"\bpython\b", r"\bjavascript\b", r"\bfunction\b"],
        fallback_agents=["verification", "business"],
        priority=10,
    ),
    AgentRoute(
        intent="memory",
        agent_key="memory",
        keywords=["remember", "memory", "recall", "store", "forget", "preference"],
        patterns=[r"\bremember\b", r"\brecall\b", r"\bforget\b", r"\bmemory\b"],
        fallback_agents=["business"],
        priority=10,
        requires_security=True,
    ),
    AgentRoute(
        intent="security",
        agent_key="security",
        keywords=["security", "permission", "approve", "safe", "risk", "auth", "login", "access"],
        patterns=[r"\bsecurity\b", r"\bpermission\b", r"\bauth\b", r"\baccess\b"],
        fallback_agents=[],
        priority=1,
        requires_security=False,
    ),
    AgentRoute(
        intent="verification",
        agent_key="verification",
        keywords=["verify", "check", "validate", "confirm", "test", "qa", "quality"],
        patterns=[r"\bverify\b", r"\bvalidate\b", r"\bconfirm\b", r"\btest\b"],
        fallback_agents=["business"],
        priority=10,
    ),
    AgentRoute(
        intent="visual",
        agent_key="visual",
        keywords=["image", "visual", "screenshot", "design", "photo", "video frame", "ocr"],
        patterns=[r"\bimage\b", r"\bscreenshot\b", r"\bvisual\b", r"\bphoto\b", r"\bocr\b"],
        fallback_agents=["creator", "business"],
        priority=10,
    ),
    AgentRoute(
        intent="workflow",
        agent_key="workflow",
        keywords=["workflow", "automation", "pipeline", "sequence", "zap", "task flow"],
        patterns=[r"\bworkflow\b", r"\bautomation\b", r"\bpipeline\b", r"\bsequence\b"],
        fallback_agents=["business", "code"],
        priority=10,
    ),
    AgentRoute(
        intent="hologram",
        agent_key="hologram",
        keywords=["hologram", "avatar", "3d", "projection", "ar", "vr"],
        patterns=[r"\bhologram\b", r"\bavatar\b", r"\b3d\b", r"\bar\b", r"\bvr\b"],
        fallback_agents=["visual", "creator"],
        priority=20,
    ),
    AgentRoute(
        intent="call",
        agent_key="call",
        keywords=["call", "phone", "dial", "sms", "message", "conversation"],
        patterns=[r"\bcall\b", r"\bphone\b", r"\bdial\b", r"\bsms\b"],
        fallback_agents=["security", "business"],
        priority=10,
        requires_security=True,
    ),
    AgentRoute(
        intent="business",
        agent_key="business",
        keywords=["business", "strategy", "marketing", "client", "lead", "sales", "proposal"],
        patterns=[r"\bbusiness\b", r"\bmarketing\b", r"\blead\b", r"\bsales\b", r"\bproposal\b"],
        fallback_agents=["creator"],
        priority=50,
    ),
    AgentRoute(
        intent="finance",
        agent_key="finance",
        keywords=["finance", "money", "invoice", "budget", "payment", "subscription", "revenue"],
        patterns=[r"\bfinance\b", r"\bbudget\b", r"\binvoice\b", r"\bpayment\b", r"\brevenue\b"],
        fallback_agents=["business", "security"],
        priority=10,
        requires_security=True,
    ),
    AgentRoute(
        intent="creator",
        agent_key="creator",
        keywords=["create", "content", "script", "video", "copy", "design", "creative"],
        patterns=[r"\bcreate\b", r"\bcontent\b", r"\bscript\b", r"\bvideo\b", r"\bcopy\b"],
        fallback_agents=["business", "visual"],
        priority=20,
    ),
]


# =============================================================================
# Agent Router
# =============================================================================

class AgentRouter:
    """
    Production-safe agent router for William/Jarvis.

    The Master Agent can use this router to decide which agent should handle a
    task. The router can route in four ways:

        1. SINGLE:
            One intent maps to one agent.

        2. FALLBACK:
            Try primary agent first. If it fails, try fallback agents.

        3. CHAIN:
            Run multiple agents in sequence and pass prior output forward.

        4. BROADCAST:
            Send the same task to multiple agents. Disabled by default.

    Public methods:
        - route_task()
        - route()
        - detect_intent()
        - register_route()
        - update_route()
        - remove_route()
        - list_routes()
        - health_check()
    """

    def __init__(
        self,
        agent_loader: Optional[Any] = None,
        registry: Optional[Any] = None,
        config: Optional[Union[AgentRouterConfig, Dict[str, Any]]] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        routes: Optional[List[AgentRoute]] = None,
    ) -> None:
        self.registry = registry or AgentRegistry()
        self.agent_loader = agent_loader or AgentLoader(registry=self.registry)

        if isinstance(config, AgentRouterConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = AgentRouterConfig(**{
                key: value
                for key, value in config.items()
                if key in AgentRouterConfig.__dataclass_fields__
            })
        else:
            self.config = AgentRouterConfig()

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger

        self._routes: Dict[str, AgentRoute] = {}
        self._lock = threading.RLock()
        self._route_history: List[Dict[str, Any]] = []

        for route in routes or DEFAULT_AGENT_ROUTES:
            self._routes[self._normalize_intent(route.intent)] = route

        self._emit_agent_event(
            event_type="agent_router.initialized",
            data={
                "route_count": len(self._routes),
                "default_agent": self.config.default_agent,
                "fallback_agent": self.config.fallback_agent,
            },
            user_id=None,
            workspace_id=None,
        )

    # =========================================================================
    # Public routing API
    # =========================================================================

    def route_task(
        self,
        task: Dict[str, Any],
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        intent: Optional[str] = None,
        requested_agent: Optional[str] = None,
        route_mode: Optional[Union[str, RouteMode]] = None,
        chain_agents: Optional[List[str]] = None,
        fallback_agents: Optional[List[str]] = None,
        role: Optional[str] = None,
        agent_config: Optional[Dict[str, Any]] = None,
        execute: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Main routing method used by Master Agent, Dashboard, or API.

        Args:
            task:
                Structured task dictionary.
            user_id:
                SaaS user ID.
            workspace_id:
                SaaS workspace ID.
            intent:
                Optional explicit intent.
            requested_agent:
                Optional explicit agent key.
            route_mode:
                Optional routing mode.
            chain_agents:
                Optional chain agent keys.
            fallback_agents:
                Optional fallback agent keys.
            role:
                Optional user role/context.
            agent_config:
                Optional agent config passed to loader.
            execute:
                If False, only returns route decision without executing.
            metadata:
                Optional route metadata.

        Returns:
            Structured dict result.
        """

        request = RouteRequest(
            task=task or {},
            user_id=user_id,
            workspace_id=workspace_id,
            intent=intent,
            requested_agent=requested_agent,
            role=role or self.config.default_role,
            route_mode=self._normalize_route_mode(route_mode),
            chain_agents=chain_agents or [],
            fallback_agents=fallback_agents or [],
            metadata=metadata or {},
        )

        context_result = self._validate_task_context(
            user_id=request.user_id,
            workspace_id=request.workspace_id,
        )
        if not context_result["success"]:
            return context_result

        if not isinstance(request.task, dict):
            return self._error_result(
                message="Task must be a dictionary.",
                error="invalid_task_type",
                data={"task_type": type(request.task).__name__},
                metadata=self._metadata(user_id, workspace_id, {"route_id": request.route_id}),
            )

        self._record_route_history(
            route_id=request.route_id,
            status=RouteStatus.CREATED,
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "intent": intent,
                "requested_agent": requested_agent,
                "route_mode": request.route_mode.value,
            },
        )

        match_result = self._resolve_route(request)
        if not match_result["success"]:
            return match_result

        match: RouteMatch = match_result["data"]["match"]

        security_result = self._request_security_approval(
            action="route_task",
            user_id=user_id,
            workspace_id=workspace_id,
            payload={
                "route_id": request.route_id,
                "intent": match.intent,
                "agent_key": match.agent_key,
                "route_mode": match.route_mode.value,
                "task_summary": self._summarize_task(request.task),
                "requires_security": self._route_requires_security(match, request.task),
            },
        )
        if not security_result["success"]:
            self._record_route_history(
                route_id=request.route_id,
                status=RouteStatus.DENIED,
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "intent": match.intent,
                    "agent_key": match.agent_key,
                    "error": security_result.get("error"),
                },
            )
            return security_result

        self._record_route_history(
            route_id=request.route_id,
            status=RouteStatus.APPROVED,
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "intent": match.intent,
                "agent_key": match.agent_key,
                "route_mode": match.route_mode.value,
            },
        )

        route_decision = {
            "route_id": request.route_id,
            "intent": match.intent,
            "agent_key": match.agent_key,
            "confidence": match.confidence,
            "reason": match.reason,
            "route_mode": match.route_mode.value,
            "fallback_agents": match.fallback_agents,
            "chain_agents": match.chain_agents,
            "execute": execute,
        }

        if not execute:
            return self._safe_result(
                message="Route decision prepared successfully.",
                data={
                    "route": route_decision,
                    "task": self._safe_serialize(request.task),
                },
                metadata=self._metadata(user_id, workspace_id, {
                    "route_id": request.route_id,
                    "verification_payload": self._prepare_verification_payload(
                        action="route_task_decision",
                        success=True,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        data=route_decision,
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        action="route_task_decision",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        data=route_decision,
                    ),
                }),
            )

        if match.route_mode == RouteMode.CHAIN:
            execution_result = self._execute_chain(
                request=request,
                match=match,
                agent_config=agent_config or {},
            )
        elif match.route_mode == RouteMode.BROADCAST:
            execution_result = self._execute_broadcast(
                request=request,
                match=match,
                agent_config=agent_config or {},
            )
        elif match.route_mode == RouteMode.FALLBACK:
            execution_result = self._execute_with_fallback(
                request=request,
                match=match,
                agent_config=agent_config or {},
            )
        else:
            execution_result = self._execute_single(
                request=request,
                match=match,
                agent_config=agent_config or {},
            )

        final_success = bool(execution_result.get("success"))

        self._record_route_history(
            route_id=request.route_id,
            status=RouteStatus.COMPLETED if final_success else RouteStatus.FAILED,
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "intent": match.intent,
                "agent_key": match.agent_key,
                "route_mode": match.route_mode.value,
                "success": final_success,
                "error": execution_result.get("error"),
            },
        )

        self._emit_agent_event(
            event_type="agent_router.route_completed" if final_success else "agent_router.route_failed",
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "route_id": request.route_id,
                "intent": match.intent,
                "agent_key": match.agent_key,
                "route_mode": match.route_mode.value,
                "success": final_success,
            },
        )

        self._log_audit_event(
            action="agent_route_completed" if final_success else "agent_route_failed",
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "route_id": request.route_id,
                "intent": match.intent,
                "agent_key": match.agent_key,
                "route_mode": match.route_mode.value,
                "success": final_success,
                "error": execution_result.get("error"),
            },
        )

        execution_result.setdefault("metadata", {})
        execution_result["metadata"].update({
            "route_id": request.route_id,
            "route": route_decision,
            "verification_payload": self._prepare_verification_payload(
                action="route_task_execution",
                success=final_success,
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "route": route_decision,
                    "result_summary": self._summarize_result(execution_result),
                },
            ),
            "memory_payload": self._prepare_memory_payload(
                action="route_task_execution",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "route": route_decision,
                    "result_summary": self._summarize_result(execution_result),
                },
            ),
        })

        return execution_result

    def route(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """
        Alias for route_task(), useful for Master Agent compatibility.
        """

        return self.route_task(*args, **kwargs)

    def detect_intent(
        self,
        task: Union[str, Dict[str, Any]],
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        Detect intent from task content without executing any agent.
        """

        task_dict = self._normalize_task_to_dict(task)
        text = self._task_to_searchable_text(task_dict)

        best_match: Optional[RouteMatch] = None

        with self._lock:
            routes = list(self._routes.values())

        for route in sorted(routes, key=lambda item: item.priority):
            if not route.enabled:
                continue

            score, reason = self._score_route(route, text, task_dict)
            if score <= 0:
                continue

            candidate = RouteMatch(
                intent=route.intent,
                agent_key=route.agent_key,
                confidence=score,
                reason=reason,
                route_mode=route.route_mode,
                fallback_agents=list(route.fallback_agents),
                chain_agents=list(route.chain_agents),
                metadata=dict(route.metadata),
            )

            if best_match is None or candidate.confidence > best_match.confidence:
                best_match = candidate

        if best_match is None or best_match.confidence < self.config.min_confidence:
            best_match = RouteMatch(
                intent="default",
                agent_key=self.config.default_agent,
                confidence=0.25,
                reason="default_agent",
                route_mode=RouteMode.FALLBACK if self.config.allow_fallback else RouteMode.SINGLE,
                fallback_agents=[self.config.fallback_agent] if self.config.allow_fallback else [],
            )

        return self._safe_result(
            message="Intent detected successfully.",
            data={
                "intent": best_match.intent,
                "agent_key": best_match.agent_key,
                "confidence": best_match.confidence,
                "reason": best_match.reason,
                "route_mode": best_match.route_mode.value,
                "fallback_agents": best_match.fallback_agents,
                "chain_agents": best_match.chain_agents,
            },
            metadata=self._metadata(user_id, workspace_id),
        )

    def register_route(
        self,
        intent: str,
        agent_key: str,
        patterns: Optional[List[str]] = None,
        keywords: Optional[List[str]] = None,
        fallback_agents: Optional[List[str]] = None,
        chain_agents: Optional[List[str]] = None,
        route_mode: Union[str, RouteMode] = RouteMode.SINGLE,
        enabled: bool = True,
        priority: int = 100,
        requires_security: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Register or replace an intent route.
        """

        normalized_intent = self._normalize_intent(intent)
        normalized_agent_key = self._normalize_agent_key(agent_key)

        if not normalized_intent:
            return self._error_result(
                message="Intent is required.",
                error="missing_intent",
                data={},
                metadata=self._metadata(None, None),
            )

        if not normalized_agent_key:
            return self._error_result(
                message="agent_key is required.",
                error="missing_agent_key",
                data={},
                metadata=self._metadata(None, None),
            )

        route = AgentRoute(
            intent=normalized_intent,
            agent_key=normalized_agent_key,
            patterns=patterns or [],
            keywords=keywords or [],
            fallback_agents=[self._normalize_agent_key(item) for item in (fallback_agents or [])],
            chain_agents=[self._normalize_agent_key(item) for item in (chain_agents or [])],
            route_mode=self._normalize_route_mode(route_mode),
            enabled=enabled,
            priority=priority,
            requires_security=requires_security,
            metadata=metadata or {},
        )

        with self._lock:
            self._routes[normalized_intent] = route

        self._emit_agent_event(
            event_type="agent_router.route_registered",
            data={
                "intent": normalized_intent,
                "agent_key": normalized_agent_key,
                "route_mode": route.route_mode.value,
            },
            user_id=None,
            workspace_id=None,
        )

        return self._safe_result(
            message="Route registered successfully.",
            data={"route": self._route_to_dict(route)},
            metadata=self._metadata(None, None),
        )

    def update_route(
        self,
        intent: str,
        **updates: Any,
    ) -> Dict[str, Any]:
        """
        Update an existing route.
        """

        normalized_intent = self._normalize_intent(intent)

        with self._lock:
            route = self._routes.get(normalized_intent)

            if not route:
                return self._error_result(
                    message="Route not found.",
                    error="route_not_found",
                    data={"intent": normalized_intent},
                    metadata=self._metadata(None, None),
                )

            for key, value in updates.items():
                if key == "route_mode":
                    setattr(route, key, self._normalize_route_mode(value))
                elif hasattr(route, key):
                    setattr(route, key, value)

            self._routes[normalized_intent] = route

        return self._safe_result(
            message="Route updated successfully.",
            data={"route": self._route_to_dict(route)},
            metadata=self._metadata(None, None),
        )

    def remove_route(self, intent: str) -> Dict[str, Any]:
        """
        Remove an intent route.
        """

        normalized_intent = self._normalize_intent(intent)

        with self._lock:
            existed = normalized_intent in self._routes
            if existed:
                del self._routes[normalized_intent]

        return self._safe_result(
            message="Route removed successfully." if existed else "Route did not exist.",
            data={
                "intent": normalized_intent,
                "removed": existed,
            },
            metadata=self._metadata(None, None),
        )

    def list_routes(self) -> Dict[str, Any]:
        """
        List all registered routes.
        """

        with self._lock:
            routes = [self._route_to_dict(route) for route in self._routes.values()]

        return self._safe_result(
            message="Routes listed successfully.",
            data={
                "routes": sorted(routes, key=lambda item: item.get("priority", 100)),
                "count": len(routes),
            },
            metadata=self._metadata(None, None),
        )

    def get_route_history(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Return route history for dashboard analytics.

        If user_id/workspace_id are provided, only matching route records are returned.
        """

        normalized_user = self._normalize_optional_context_id(user_id)
        normalized_workspace = self._normalize_optional_context_id(workspace_id)

        with self._lock:
            records = list(self._route_history)

        if normalized_user is not None:
            records = [item for item in records if item.get("user_id") == normalized_user]

        if normalized_workspace is not None:
            records = [item for item in records if item.get("workspace_id") == normalized_workspace]

        records = records[-max(1, int(limit)):]

        return self._safe_result(
            message="Route history retrieved successfully.",
            data={
                "history": records,
                "count": len(records),
            },
            metadata=self._metadata(user_id, workspace_id),
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Health check for router, routes, loader, and optional agents.
        """

        with self._lock:
            route_count = len(self._routes)
            enabled_count = len([route for route in self._routes.values() if route.enabled])
            history_count = len(self._route_history)

        loader_health = None
        try:
            if hasattr(self.agent_loader, "health_check") and callable(self.agent_loader.health_check):
                loader_health = self.agent_loader.health_check()
        except Exception as exc:
            loader_health = {
                "success": False,
                "message": "AgentLoader health check failed.",
                "error": str(exc),
            }

        return self._safe_result(
            message="AgentRouter health check completed.",
            data={
                "router": {
                    "healthy": True,
                    "route_count": route_count,
                    "enabled_route_count": enabled_count,
                    "history_count": history_count,
                    "default_agent": self.config.default_agent,
                    "fallback_agent": self.config.fallback_agent,
                    "allow_fallback": self.config.allow_fallback,
                    "allow_chain_execution": self.config.allow_chain_execution,
                    "allow_broadcast": self.config.allow_broadcast,
                },
                "agent_loader": self._safe_serialize(loader_health),
            },
            metadata=self._metadata(None, None),
        )

    # =========================================================================
    # Route resolving
    # =========================================================================

    def _resolve_route(self, request: RouteRequest) -> Dict[str, Any]:
        """
        Resolve route from explicit agent, explicit intent, chain config,
        fallback config, or automatic intent detection.
        """

        if request.requested_agent:
            agent_key = self._normalize_agent_key(request.requested_agent)

            route_mode = request.route_mode
            if request.chain_agents:
                route_mode = RouteMode.CHAIN
            elif request.fallback_agents:
                route_mode = RouteMode.FALLBACK

            match = RouteMatch(
                intent=request.intent or "explicit_agent",
                agent_key=agent_key,
                confidence=1.0,
                reason="explicit_requested_agent",
                route_mode=route_mode,
                fallback_agents=[self._normalize_agent_key(item) for item in request.fallback_agents],
                chain_agents=[self._normalize_agent_key(item) for item in request.chain_agents],
            )

            return self._safe_result(
                message="Route resolved from explicit requested_agent.",
                data={"match": match},
                metadata=self._metadata(request.user_id, request.workspace_id, {"route_id": request.route_id}),
            )

        if request.chain_agents:
            clean_chain = [self._normalize_agent_key(item) for item in request.chain_agents if item]
            if not clean_chain:
                return self._error_result(
                    message="chain_agents provided but no valid agent keys found.",
                    error="invalid_chain_agents",
                    data={},
                    metadata=self._metadata(request.user_id, request.workspace_id, {"route_id": request.route_id}),
                )

            if len(clean_chain) > self.config.max_chain_length:
                return self._error_result(
                    message="Chain is longer than allowed maximum.",
                    error="chain_too_long",
                    data={
                        "max_chain_length": self.config.max_chain_length,
                        "provided_chain_length": len(clean_chain),
                    },
                    metadata=self._metadata(request.user_id, request.workspace_id, {"route_id": request.route_id}),
                )

            match = RouteMatch(
                intent=request.intent or "explicit_chain",
                agent_key=clean_chain[0],
                confidence=1.0,
                reason="explicit_chain_agents",
                route_mode=RouteMode.CHAIN,
                fallback_agents=[self._normalize_agent_key(item) for item in request.fallback_agents],
                chain_agents=clean_chain,
            )

            return self._safe_result(
                message="Route resolved from explicit chain_agents.",
                data={"match": match},
                metadata=self._metadata(request.user_id, request.workspace_id, {"route_id": request.route_id}),
            )

        if request.intent:
            normalized_intent = self._normalize_intent(request.intent)

            with self._lock:
                route = self._routes.get(normalized_intent)

            if route and route.enabled:
                route_mode = request.route_mode
                if route.route_mode != RouteMode.SINGLE:
                    route_mode = route.route_mode
                if request.fallback_agents:
                    route_mode = RouteMode.FALLBACK

                match = RouteMatch(
                    intent=route.intent,
                    agent_key=route.agent_key,
                    confidence=1.0,
                    reason="explicit_intent_match",
                    route_mode=route_mode,
                    fallback_agents=[
                        self._normalize_agent_key(item)
                        for item in (request.fallback_agents or route.fallback_agents)
                    ],
                    chain_agents=[
                        self._normalize_agent_key(item)
                        for item in (request.chain_agents or route.chain_agents)
                    ],
                    metadata=dict(route.metadata),
                )

                return self._safe_result(
                    message="Route resolved from explicit intent.",
                    data={"match": match},
                    metadata=self._metadata(request.user_id, request.workspace_id, {"route_id": request.route_id}),
                )

        detection_result = self.detect_intent(
            task=request.task,
            user_id=request.user_id,
            workspace_id=request.workspace_id,
        )
        if not detection_result["success"]:
            return detection_result

        detected = detection_result["data"]

        route_mode = self._normalize_route_mode(detected.get("route_mode"))
        if request.route_mode != RouteMode.SINGLE:
            route_mode = request.route_mode

        if request.fallback_agents:
            route_mode = RouteMode.FALLBACK

        match = RouteMatch(
            intent=detected.get("intent", "default"),
            agent_key=detected.get("agent_key", self.config.default_agent),
            confidence=float(detected.get("confidence", 0.25)),
            reason=detected.get("reason", "auto_detected"),
            route_mode=route_mode,
            fallback_agents=[
                self._normalize_agent_key(item)
                for item in (request.fallback_agents or detected.get("fallback_agents") or [])
            ],
            chain_agents=[
                self._normalize_agent_key(item)
                for item in (request.chain_agents or detected.get("chain_agents") or [])
            ],
        )

        return self._safe_result(
            message="Route resolved from automatic intent detection.",
            data={"match": match},
            metadata=self._metadata(request.user_id, request.workspace_id, {"route_id": request.route_id}),
        )

    # =========================================================================
    # Execution helpers
    # =========================================================================

    def _execute_single(
        self,
        request: RouteRequest,
        match: RouteMatch,
        agent_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute task with one agent.
        """

        agent_result = self._get_agent(
            agent_key=match.agent_key,
            request=request,
            agent_config=agent_config,
        )
        if not agent_result["success"]:
            return agent_result

        agent = agent_result["data"]["agent"]

        return self._run_agent(
            agent=agent,
            agent_key=match.agent_key,
            request=request,
            previous_results=[],
        )

    def _execute_with_fallback(
        self,
        request: RouteRequest,
        match: RouteMatch,
        agent_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute primary agent first, then fallback agents if needed.
        """

        agent_keys = [match.agent_key]
        for key in match.fallback_agents:
            clean_key = self._normalize_agent_key(key)
            if clean_key and clean_key not in agent_keys:
                agent_keys.append(clean_key)

        if self.config.fallback_agent and self.config.fallback_agent not in agent_keys:
            agent_keys.append(self.config.fallback_agent)

        agent_keys = agent_keys[: max(1, self.config.max_fallback_attempts + 1)]

        attempts: List[Dict[str, Any]] = []

        for agent_key in agent_keys:
            agent_result = self._get_agent(
                agent_key=agent_key,
                request=request,
                agent_config=agent_config,
            )

            if not agent_result["success"]:
                attempts.append({
                    "agent_key": agent_key,
                    "success": False,
                    "stage": "load",
                    "message": agent_result.get("message"),
                    "error": agent_result.get("error"),
                })
                continue

            run_result = self._run_agent(
                agent=agent_result["data"]["agent"],
                agent_key=agent_key,
                request=request,
                previous_results=attempts,
            )

            attempts.append({
                "agent_key": agent_key,
                "success": bool(run_result.get("success")),
                "stage": "run",
                "message": run_result.get("message"),
                "error": run_result.get("error"),
                "data": self._safe_serialize(run_result.get("data", {})),
            })

            if run_result.get("success"):
                return self._safe_result(
                    message="Task routed successfully with fallback support.",
                    data={
                        "agent_key": agent_key,
                        "result": run_result,
                        "attempts": attempts,
                        "used_fallback": agent_key != match.agent_key,
                    },
                    metadata=self._metadata(request.user_id, request.workspace_id, {
                        "route_id": request.route_id,
                    }),
                )

        return self._error_result(
            message="All fallback routing attempts failed.",
            error="fallback_route_failed",
            data={
                "primary_agent": match.agent_key,
                "attempts": attempts,
            },
            metadata=self._metadata(request.user_id, request.workspace_id, {
                "route_id": request.route_id,
            }),
        )

    def _execute_chain(
        self,
        request: RouteRequest,
        match: RouteMatch,
        agent_config: Dict[str, Any],
        chain_mode: ChainMode = ChainMode.STOP_ON_FAILURE,
    ) -> Dict[str, Any]:
        """
        Execute a multi-agent chain.

        Each agent receives:
            - original_task
            - current task
            - previous_results
            - route_id
            - chain_index
        """

        if not self.config.allow_chain_execution:
            return self._error_result(
                message="Chain execution is disabled by router config.",
                error="chain_execution_disabled",
                data={"chain_agents": match.chain_agents},
                metadata=self._metadata(request.user_id, request.workspace_id, {
                    "route_id": request.route_id,
                }),
            )

        chain_agents = match.chain_agents or [match.agent_key]
        chain_agents = [self._normalize_agent_key(item) for item in chain_agents if item]

        if len(chain_agents) > self.config.max_chain_length:
            return self._error_result(
                message="Chain exceeds max allowed length.",
                error="chain_too_long",
                data={
                    "max_chain_length": self.config.max_chain_length,
                    "chain_length": len(chain_agents),
                    "chain_agents": chain_agents,
                },
                metadata=self._metadata(request.user_id, request.workspace_id, {
                    "route_id": request.route_id,
                }),
            )

        previous_results: List[Dict[str, Any]] = []
        current_task = dict(request.task)

        for index, agent_key in enumerate(chain_agents):
            agent_result = self._get_agent(
                agent_key=agent_key,
                request=request,
                agent_config=agent_config,
            )

            if not agent_result["success"]:
                failed_result = {
                    "agent_key": agent_key,
                    "chain_index": index,
                    "success": False,
                    "stage": "load",
                    "message": agent_result.get("message"),
                    "error": agent_result.get("error"),
                }
                previous_results.append(failed_result)

                if chain_mode == ChainMode.STOP_ON_FAILURE:
                    return self._error_result(
                        message="Chain stopped because an agent failed to load.",
                        error=agent_result.get("error") or "chain_agent_load_failed",
                        data={
                            "chain_agents": chain_agents,
                            "results": previous_results,
                        },
                        metadata=self._metadata(request.user_id, request.workspace_id, {
                            "route_id": request.route_id,
                        }),
                    )
                continue

            chain_request = RouteRequest(
                task={
                    **current_task,
                    "_chain": {
                        "route_id": request.route_id,
                        "chain_index": index,
                        "chain_agents": chain_agents,
                        "previous_results": self._safe_serialize(previous_results),
                        "original_task": self._safe_serialize(request.task),
                    },
                },
                user_id=request.user_id,
                workspace_id=request.workspace_id,
                intent=request.intent,
                requested_agent=agent_key,
                role=request.role,
                route_mode=RouteMode.SINGLE,
                metadata=request.metadata,
                route_id=request.route_id,
            )

            run_result = self._run_agent(
                agent=agent_result["data"]["agent"],
                agent_key=agent_key,
                request=chain_request,
                previous_results=previous_results,
            )

            chain_record = {
                "agent_key": agent_key,
                "chain_index": index,
                "success": bool(run_result.get("success")),
                "message": run_result.get("message"),
                "error": run_result.get("error"),
                "data": self._safe_serialize(run_result.get("data", {})),
            }
            previous_results.append(chain_record)

            if not run_result.get("success") and chain_mode == ChainMode.STOP_ON_FAILURE:
                return self._error_result(
                    message="Chain stopped because an agent execution failed.",
                    error=run_result.get("error") or "chain_agent_execution_failed",
                    data={
                        "chain_agents": chain_agents,
                        "results": previous_results,
                    },
                    metadata=self._metadata(request.user_id, request.workspace_id, {
                        "route_id": request.route_id,
                    }),
                )

            current_task = self._merge_chain_output_into_task(
                current_task=current_task,
                run_result=run_result,
                agent_key=agent_key,
            )

        all_success = all(item.get("success") for item in previous_results)

        return self._safe_result(
            message="Chain execution completed successfully." if all_success else "Chain execution completed with partial failures.",
            data={
                "chain_agents": chain_agents,
                "results": previous_results,
                "all_success": all_success,
                "final_task_state": self._safe_serialize(current_task),
            },
            metadata=self._metadata(request.user_id, request.workspace_id, {
                "route_id": request.route_id,
            }),
        )

    def _execute_broadcast(
        self,
        request: RouteRequest,
        match: RouteMatch,
        agent_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Broadcast same task to multiple agents.

        Disabled by default because broad execution can become expensive and
        risky. Enable explicitly through config when needed.
        """

        if not self.config.allow_broadcast:
            return self._error_result(
                message="Broadcast routing is disabled by router config.",
                error="broadcast_disabled",
                data={},
                metadata=self._metadata(request.user_id, request.workspace_id, {
                    "route_id": request.route_id,
                }),
            )

        agent_keys = match.chain_agents or [match.agent_key] + match.fallback_agents
        agent_keys = list(dict.fromkeys([self._normalize_agent_key(item) for item in agent_keys if item]))

        results: List[Dict[str, Any]] = []

        for agent_key in agent_keys:
            agent_result = self._get_agent(
                agent_key=agent_key,
                request=request,
                agent_config=agent_config,
            )

            if not agent_result["success"]:
                results.append({
                    "agent_key": agent_key,
                    "success": False,
                    "stage": "load",
                    "message": agent_result.get("message"),
                    "error": agent_result.get("error"),
                })
                continue

            run_result = self._run_agent(
                agent=agent_result["data"]["agent"],
                agent_key=agent_key,
                request=request,
                previous_results=[],
            )

            results.append({
                "agent_key": agent_key,
                "success": bool(run_result.get("success")),
                "stage": "run",
                "message": run_result.get("message"),
                "error": run_result.get("error"),
                "data": self._safe_serialize(run_result.get("data", {})),
            })

        return self._safe_result(
            message="Broadcast route completed.",
            data={
                "agent_keys": agent_keys,
                "results": results,
                "success_count": len([item for item in results if item.get("success")]),
                "failure_count": len([item for item in results if not item.get("success")]),
            },
            metadata=self._metadata(request.user_id, request.workspace_id, {
                "route_id": request.route_id,
            }),
        )

    def _get_agent(
        self,
        agent_key: str,
        request: RouteRequest,
        agent_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Load isolated agent instance through AgentLoader.
        """

        try:
            if hasattr(self.agent_loader, "get_agent_instance"):
                return self.agent_loader.get_agent_instance(
                    agent_key=agent_key,
                    user_id=request.user_id,
                    workspace_id=request.workspace_id,
                    role=request.role,
                    agent_config=agent_config,
                    route_id=request.route_id,
                )

            return self._error_result(
                message="AgentLoader does not expose get_agent_instance().",
                error="invalid_agent_loader",
                data={"agent_key": agent_key},
                metadata=self._metadata(request.user_id, request.workspace_id, {
                    "route_id": request.route_id,
                }),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to get agent instance from AgentLoader.",
                error=str(exc),
                data={"agent_key": agent_key},
                metadata=self._metadata(request.user_id, request.workspace_id, {
                    "route_id": request.route_id,
                    "traceback": traceback.format_exc() if self.config.include_tracebacks else None,
                }),
            )

    def _run_agent(
        self,
        agent: Any,
        agent_key: str,
        request: RouteRequest,
        previous_results: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Execute an agent safely.

        The router supports common agent interfaces:
            - run(task)
            - execute(task)
            - handle(task)
            - process(task)
            - __call__(task)
        """

        previous_results = previous_results or []

        task_payload = {
            **request.task,
            "_routing": {
                "route_id": request.route_id,
                "agent_key": agent_key,
                "intent": request.intent,
                "user_id": self._normalize_context_id(request.user_id),
                "workspace_id": self._normalize_context_id(request.workspace_id),
                "role": request.role,
                "previous_results": self._safe_serialize(previous_results),
                "timestamp": time.time(),
            },
        }

        self._emit_agent_event(
            event_type="agent_router.agent_execution_started",
            user_id=request.user_id,
            workspace_id=request.workspace_id,
            data={
                "route_id": request.route_id,
                "agent_key": agent_key,
            },
        )

        started_at = time.time()

        try:
            runner = self._select_agent_runner(agent)

            if runner is None:
                return self._error_result(
                    message="Agent has no executable method.",
                    error="agent_not_executable",
                    data={
                        "agent_key": agent_key,
                        "agent_class": agent.__class__.__name__,
                    },
                    metadata=self._metadata(request.user_id, request.workspace_id, {
                        "route_id": request.route_id,
                    }),
                )

            raw_result = runner(task_payload)

            duration_ms = round((time.time() - started_at) * 1000, 2)
            normalized_result = self._normalize_agent_result(
                raw_result=raw_result,
                agent_key=agent_key,
                request=request,
                duration_ms=duration_ms,
            )

            self._emit_agent_event(
                event_type="agent_router.agent_execution_completed"
                if normalized_result["success"]
                else "agent_router.agent_execution_failed",
                user_id=request.user_id,
                workspace_id=request.workspace_id,
                data={
                    "route_id": request.route_id,
                    "agent_key": agent_key,
                    "success": normalized_result["success"],
                    "duration_ms": duration_ms,
                    "error": normalized_result.get("error"),
                },
            )

            return normalized_result

        except Exception as exc:
            duration_ms = round((time.time() - started_at) * 1000, 2)

            self._emit_agent_event(
                event_type="agent_router.agent_execution_exception",
                user_id=request.user_id,
                workspace_id=request.workspace_id,
                data={
                    "route_id": request.route_id,
                    "agent_key": agent_key,
                    "error": str(exc),
                    "duration_ms": duration_ms,
                },
            )

            return self._error_result(
                message="Agent execution failed with exception.",
                error=str(exc),
                data={
                    "agent_key": agent_key,
                    "agent_class": agent.__class__.__name__ if agent else None,
                },
                metadata=self._metadata(request.user_id, request.workspace_id, {
                    "route_id": request.route_id,
                    "duration_ms": duration_ms,
                    "traceback": traceback.format_exc() if self.config.include_tracebacks else None,
                }),
            )

    @staticmethod
    def _select_agent_runner(agent: Any) -> Optional[Callable[[Dict[str, Any]], Any]]:
        """
        Select executable method from agent.
        """

        for method_name in ("run", "execute", "handle", "process"):
            method = getattr(agent, method_name, None)
            if callable(method):
                return method

        if callable(agent):
            return agent

        return None

    def _normalize_agent_result(
        self,
        raw_result: Any,
        agent_key: str,
        request: RouteRequest,
        duration_ms: float,
    ) -> Dict[str, Any]:
        """
        Normalize agent output into standard William/Jarvis result format.
        """

        if isinstance(raw_result, dict):
            success = bool(raw_result.get("success", True))
            return {
                "success": success,
                "message": raw_result.get("message") or (
                    "Agent execution completed." if success else "Agent execution failed."
                ),
                "data": raw_result.get("data", raw_result),
                "error": raw_result.get("error"),
                "metadata": {
                    **self._safe_serialize(raw_result.get("metadata", {})),
                    "agent_key": agent_key,
                    "route_id": request.route_id,
                    "duration_ms": duration_ms,
                    "user_id": self._normalize_context_id(request.user_id),
                    "workspace_id": self._normalize_context_id(request.workspace_id),
                    "timestamp": time.time(),
                },
            }

        return self._safe_result(
            message="Agent execution completed.",
            data={
                "agent_key": agent_key,
                "result": self._safe_serialize(raw_result),
            },
            metadata=self._metadata(request.user_id, request.workspace_id, {
                "route_id": request.route_id,
                "duration_ms": duration_ms,
            }),
        )

    # =========================================================================
    # Matching helpers
    # =========================================================================

    def _score_route(
        self,
        route: AgentRoute,
        text: str,
        task: Dict[str, Any],
    ) -> Tuple[float, str]:
        """
        Score how well a route matches task text.
        """

        if not text:
            return 0.0, "empty_text"

        normalized_text = text.lower()
        score = 0.0
        reasons: List[str] = []

        task_intent = task.get("intent") or task.get("type") or task.get("category")
        if task_intent and self._normalize_intent(task_intent) == self._normalize_intent(route.intent):
            score += 1.0
            reasons.append("task_intent_exact")

        requested_agent = task.get("agent") or task.get("agent_key") or task.get("requested_agent")
        if requested_agent and self._normalize_agent_key(requested_agent) == self._normalize_agent_key(route.agent_key):
            score += 1.0
            reasons.append("task_agent_exact")

        keyword_hits = 0
        for keyword in route.keywords:
            clean_keyword = str(keyword).lower().strip()
            if clean_keyword and clean_keyword in normalized_text:
                keyword_hits += 1

        if route.keywords:
            keyword_score = min(0.85, keyword_hits / max(1, len(route.keywords)))
            if keyword_score > 0:
                score += keyword_score
                reasons.append(f"keyword_hits:{keyword_hits}")

        pattern_hits = 0
        for pattern in route.patterns:
            try:
                if re.search(pattern, normalized_text, flags=re.IGNORECASE):
                    pattern_hits += 1
            except re.error:
                continue

        if route.patterns:
            pattern_score = min(0.9, pattern_hits / max(1, len(route.patterns)))
            if pattern_score > 0:
                score += pattern_score
                reasons.append(f"pattern_hits:{pattern_hits}")

        if route.intent in normalized_text:
            score += 0.35
            reasons.append("intent_word_found")

        final_score = min(1.0, score)

        if not reasons:
            return 0.0, "no_match"

        return final_score, ",".join(reasons)

    def _task_to_searchable_text(self, task: Dict[str, Any]) -> str:
        """
        Convert task dict into searchable text for intent matching.
        """

        parts: List[str] = []

        important_keys = [
            "intent",
            "type",
            "category",
            "title",
            "summary",
            "message",
            "prompt",
            "query",
            "command",
            "task",
            "description",
            "content",
            "user_input",
        ]

        for key in important_keys:
            value = task.get(key)
            if value is not None:
                parts.append(str(value))

        if not parts:
            parts.append(str(self._safe_serialize(task)))

        return " ".join(parts)

    @staticmethod
    def _normalize_task_to_dict(task: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Normalize string/dict task input.
        """

        if isinstance(task, dict):
            return task

        return {
            "message": str(task),
            "type": "text",
        }

    # =========================================================================
    # Required compatibility hooks
    # =========================================================================

    def _validate_task_context(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        allow_system_context: bool = False,
    ) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Every user-specific route must include user_id and workspace_id.
        """

        if allow_system_context and (user_id is None or workspace_id is None):
            return self._safe_result(
                message="System context accepted.",
                data={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "system_context": True,
                },
                metadata=self._metadata(user_id, workspace_id),
            )

        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="user_id is required for agent routing.",
                error="missing_user_id",
                data={},
                metadata=self._metadata(user_id, workspace_id),
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="workspace_id is required for workspace-isolated routing.",
                error="missing_workspace_id",
                data={},
                metadata=self._metadata(user_id, workspace_id),
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": self._normalize_context_id(user_id),
                "workspace_id": self._normalize_context_id(workspace_id),
            },
            metadata=self._metadata(user_id, workspace_id),
        )

    def _requires_security_check(self, action: str) -> bool:
        """
        Decide if a router action requires security approval.
        """

        sensitive_actions = {
            "route_task",
            "route_system_task",
            "route_browser_task",
            "route_call_task",
            "route_finance_task",
            "route_memory_task",
            "route_broadcast",
            "route_chain",
        }
        return action in sensitive_actions

    def _request_security_approval(
        self,
        action: str,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval if connected.

        If no Security Agent is connected, safe default behavior is controlled by:
            config.safe_default_approval_without_security_agent
        """

        payload = payload or {}
        requires_security = bool(payload.get("requires_security")) or self._requires_security_check(action)

        if not requires_security:
            return self._safe_result(
                message="Security check not required.",
                data={"approved": True, "action": action},
                metadata=self._metadata(user_id, workspace_id),
            )

        if self.security_agent is None:
            if self.config.safe_default_approval_without_security_agent:
                return self._safe_result(
                    message="Security Agent not connected; safe default approval used.",
                    data={
                        "approved": True,
                        "action": action,
                        "security_agent_connected": False,
                    },
                    metadata=self._metadata(user_id, workspace_id),
                )

            return self._error_result(
                message="Security Agent required but not connected.",
                error="security_agent_missing",
                data={
                    "approved": False,
                    "action": action,
                },
                metadata=self._metadata(user_id, workspace_id),
            )

        try:
            security_payload = {
                "source": "AgentRouter",
                "action": action,
                "user_id": self._normalize_optional_context_id(user_id),
                "workspace_id": self._normalize_optional_context_id(workspace_id),
                "payload": self._safe_serialize(payload),
                "timestamp": time.time(),
            }

            if hasattr(self.security_agent, "approve_action"):
                result = self.security_agent.approve_action(security_payload)
            elif hasattr(self.security_agent, "check_permission"):
                result = self.security_agent.check_permission(security_payload)
            elif hasattr(self.security_agent, "run"):
                result = self.security_agent.run(security_payload)
            else:
                return self._error_result(
                    message="Security Agent has no supported approval method.",
                    error="security_agent_invalid",
                    data={
                        "approved": False,
                        "action": action,
                    },
                    metadata=self._metadata(user_id, workspace_id),
                )

            if isinstance(result, dict):
                approved = bool(
                    result.get("approved")
                    or result.get("success")
                    or result.get("allowed")
                )

                if approved:
                    return self._safe_result(
                        message="Security Agent approved routing action.",
                        data={
                            "approved": True,
                            "action": action,
                            "security_result": self._safe_serialize(result),
                        },
                        metadata=self._metadata(user_id, workspace_id),
                    )

                return self._error_result(
                    message="Security Agent denied routing action.",
                    error=result.get("error") or result.get("message") or "security_denied",
                    data={
                        "approved": False,
                        "action": action,
                        "security_result": self._safe_serialize(result),
                    },
                    metadata=self._metadata(user_id, workspace_id),
                )

            if result is True:
                return self._safe_result(
                    message="Security Agent approved routing action.",
                    data={"approved": True, "action": action},
                    metadata=self._metadata(user_id, workspace_id),
                )

            return self._error_result(
                message="Security Agent denied routing action.",
                error="security_denied",
                data={"approved": False, "action": action},
                metadata=self._metadata(user_id, workspace_id),
            )

        except Exception as exc:
            return self._error_result(
                message="Security approval failed.",
                error=str(exc),
                data={
                    "approved": False,
                    "action": action,
                },
                metadata=self._metadata(user_id, workspace_id, {
                    "traceback": traceback.format_exc() if self.config.include_tracebacks else None,
                }),
            )

    def _prepare_verification_payload(
        self,
        action: str,
        success: bool,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        data: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Prepare Verification Agent compatible payload.
        """

        if not self.config.verification_enabled:
            return None

        return {
            "source": "AgentRouter",
            "action": action,
            "success": success,
            "user_id": self._normalize_optional_context_id(user_id),
            "workspace_id": self._normalize_optional_context_id(workspace_id),
            "data": self._safe_serialize(data or {}),
            "timestamp": time.time(),
        }

    def _prepare_memory_payload(
        self,
        action: str,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        data: Optional[Dict[str, Any]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Prepare Memory Agent compatible payload.

        This payload is safe to forward to Memory Agent later. It avoids raw
        secrets and unserializable objects.
        """

        if not self.config.memory_payload_enabled:
            return None

        return {
            "source": "AgentRouter",
            "memory_type": "agent_route_event",
            "action": action,
            "user_id": self._normalize_optional_context_id(user_id),
            "workspace_id": self._normalize_optional_context_id(workspace_id),
            "content": self._safe_serialize(data or {}),
            "timestamp": time.time(),
        }

    def _emit_agent_event(
        self,
        event_type: str,
        data: Optional[Dict[str, Any]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> None:
        """
        Emit dashboard/API compatible event.
        """

        if not self.config.emit_events:
            return

        event = {
            "event_type": event_type,
            "source": "AgentRouter",
            "user_id": self._normalize_optional_context_id(user_id),
            "workspace_id": self._normalize_optional_context_id(workspace_id),
            "data": self._safe_serialize(data or {}),
            "timestamp": time.time(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                logger.debug("AgentRouter event: %s", event)
        except Exception:
            logger.exception("AgentRouter event emitter failed.")

    def _log_audit_event(
        self,
        action: str,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event for SaaS dashboard/security trail.
        """

        if not self.config.audit_enabled:
            return

        event = {
            "action": action,
            "source": "AgentRouter",
            "user_id": self._normalize_optional_context_id(user_id),
            "workspace_id": self._normalize_optional_context_id(workspace_id),
            "data": self._safe_serialize(data or {}),
            "timestamp": time.time(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(event)
            else:
                logger.info("AgentRouter audit event: %s", event)
        except Exception:
            logger.exception("AgentRouter audit logger failed.")

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
        error: Any,
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
            "error": str(error) if error is not None else "unknown_error",
            "metadata": metadata or {},
        }

    # =========================================================================
    # Utility helpers
    # =========================================================================

    def _route_requires_security(self, match: RouteMatch, task: Dict[str, Any]) -> bool:
        """
        Determine whether selected route/task is sensitive.
        """

        sensitive_agent_keys = {
            self.config.security_agent_key,
            "system",
            "browser",
            "call",
            "finance",
            "memory",
        }

        if match.agent_key in sensitive_agent_keys:
            return True

        with self._lock:
            route = self._routes.get(self._normalize_intent(match.intent))

        if route and route.requires_security:
            return True

        task_text = self._task_to_searchable_text(task).lower()
        sensitive_terms = [
            "delete",
            "remove",
            "send",
            "call",
            "payment",
            "transfer",
            "login",
            "password",
            "token",
            "secret",
            "browser",
            "open",
            "execute",
            "terminal",
            "shell",
            "file system",
        ]

        return any(term in task_text for term in sensitive_terms)

    def _record_route_history(
        self,
        route_id: str,
        status: RouteStatus,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record lightweight route history for dashboard analytics.
        """

        record = {
            "route_id": route_id,
            "status": status.value,
            "user_id": self._normalize_optional_context_id(user_id),
            "workspace_id": self._normalize_optional_context_id(workspace_id),
            "data": self._safe_serialize(data or {}),
            "timestamp": time.time(),
        }

        with self._lock:
            self._route_history.append(record)
            if len(self._route_history) > 5000:
                self._route_history = self._route_history[-5000:]

    @staticmethod
    def _normalize_agent_key(agent_key: Any) -> str:
        """
        Normalize agent key.
        """

        if agent_key is None:
            return ""
        return str(agent_key).strip().lower()

    @staticmethod
    def _normalize_intent(intent: Any) -> str:
        """
        Normalize intent name.
        """

        if intent is None:
            return ""
        return str(intent).strip().lower().replace(" ", "_").replace("-", "_")

    @staticmethod
    def _normalize_context_id(value: Union[str, int]) -> str:
        """
        Normalize required context IDs.
        """

        return str(value).strip()

    @staticmethod
    def _normalize_optional_context_id(value: Optional[Union[str, int]]) -> Optional[str]:
        """
        Normalize optional context IDs.
        """

        if value is None:
            return None
        return str(value).strip()

    @staticmethod
    def _normalize_route_mode(value: Optional[Union[str, RouteMode]]) -> RouteMode:
        """
        Normalize route mode.
        """

        if isinstance(value, RouteMode):
            return value

        if value is None:
            return RouteMode.SINGLE

        try:
            return RouteMode(str(value).strip().lower())
        except Exception:
            return RouteMode.SINGLE

    def _metadata(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build standard metadata.
        """

        metadata = {
            "source": "AgentRouter",
            "user_id": self._normalize_optional_context_id(user_id),
            "workspace_id": self._normalize_optional_context_id(workspace_id),
            "timestamp": time.time(),
        }

        if extra:
            metadata.update(extra)

        return metadata

    def _route_to_dict(self, route: AgentRoute) -> Dict[str, Any]:
        """
        Serialize AgentRoute safely.
        """

        return {
            "intent": route.intent,
            "agent_key": route.agent_key,
            "patterns": list(route.patterns),
            "keywords": list(route.keywords),
            "fallback_agents": list(route.fallback_agents),
            "chain_agents": list(route.chain_agents),
            "route_mode": route.route_mode.value,
            "enabled": route.enabled,
            "priority": route.priority,
            "requires_security": route.requires_security,
            "metadata": self._safe_serialize(route.metadata),
        }

    def _merge_chain_output_into_task(
        self,
        current_task: Dict[str, Any],
        run_result: Dict[str, Any],
        agent_key: str,
    ) -> Dict[str, Any]:
        """
        Merge agent result into task state for the next chain agent.
        """

        merged = dict(current_task)

        chain_outputs = list(merged.get("_chain_outputs", []))
        chain_outputs.append({
            "agent_key": agent_key,
            "success": bool(run_result.get("success")),
            "message": run_result.get("message"),
            "data": self._safe_serialize(run_result.get("data", {})),
            "error": run_result.get("error"),
            "timestamp": time.time(),
        })

        merged["_chain_outputs"] = chain_outputs
        merged["_last_agent_output"] = self._safe_serialize(run_result.get("data", {}))

        return merged

    def _summarize_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create safe short task summary for security/audit logs.
        """

        return {
            "keys": list(task.keys())[:30],
            "intent": task.get("intent"),
            "type": task.get("type"),
            "message_preview": str(
                task.get("message")
                or task.get("prompt")
                or task.get("query")
                or task.get("description")
                or ""
            )[:300],
        }

    def _summarize_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create short result summary for verification/memory payloads.
        """

        return {
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "error": result.get("error"),
            "data_keys": list(result.get("data", {}).keys())[:30]
            if isinstance(result.get("data"), dict)
            else [],
        }

    def _safe_serialize(self, value: Any) -> Any:
        """
        Safely serialize data for logs/API/dashboard.

        Removes obvious secrets and converts objects/classes/callables to safe
        descriptions.
        """

        if value is None:
            return None

        if isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, Enum):
            return value.value

        if isinstance(value, dict):
            return {
                str(k): self._safe_serialize(v)
                for k, v in value.items()
                if not self._looks_sensitive(str(k))
            }

        if isinstance(value, (list, tuple, set)):
            return [self._safe_serialize(item) for item in value]

        if hasattr(value, "__dataclass_fields__"):
            safe_data = {}
            for field_name in value.__dataclass_fields__:
                if not self._looks_sensitive(field_name):
                    safe_data[field_name] = self._safe_serialize(getattr(value, field_name))
            return safe_data

        if callable(value):
            return {
                "callable_name": getattr(value, "__name__", value.__class__.__name__),
                "type": "callable",
            }

        if hasattr(value, "__dict__"):
            safe_data = {}
            for key, item in vars(value).items():
                if not self._looks_sensitive(str(key)):
                    safe_data[str(key)] = self._safe_serialize(item)
            return {
                "object_type": value.__class__.__name__,
                "data": safe_data,
            }

        return str(value)

    @staticmethod
    def _looks_sensitive(key: str) -> bool:
        """
        Avoid logging obvious sensitive fields.
        """

        lowered = key.lower()
        sensitive_terms = {
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "private_key",
            "credential",
            "authorization",
            "cookie",
            "session",
        }
        return any(term in lowered for term in sensitive_terms)


# =============================================================================
# Factory helper
# =============================================================================

def create_agent_router(
    agent_loader: Optional[Any] = None,
    registry: Optional[Any] = None,
    config: Optional[Union[AgentRouterConfig, Dict[str, Any]]] = None,
    security_agent: Optional[Any] = None,
    memory_agent: Optional[Any] = None,
    verification_agent: Optional[Any] = None,
    event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
    audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
    routes: Optional[List[AgentRoute]] = None,
) -> AgentRouter:
    """
    Factory helper for FastAPI/dashboard/bootstrap integration.
    """

    return AgentRouter(
        agent_loader=agent_loader,
        registry=registry,
        config=config,
        security_agent=security_agent,
        memory_agent=memory_agent,
        verification_agent=verification_agent,
        event_emitter=event_emitter,
        audit_logger=audit_logger,
        routes=routes,
    )


__all__ = [
    "AgentRouter",
    "AgentRouterConfig",
    "AgentRoute",
    "RouteRequest",
    "RouteMatch",
    "RouteMode",
    "ChainMode",
    "RouteStatus",
    "DEFAULT_AGENT_ROUTES",
    "create_agent_router",
]


if __name__ == "__main__":
    """
    Lightweight smoke test.

    This only tests safe routing structure and fallback imports.
    It does not execute real system, call, browser, finance, file, or destructive actions.
    """

    logging.basicConfig(level=logging.INFO)

    router = AgentRouter()

    print(router.health_check())

    decision = router.route_task(
        task={
            "message": "Create a marketing script for my agency.",
            "type": "content_request",
        },
        user_id="demo_user",
        workspace_id="demo_workspace",
        execute=False,
    )

    print(decision)

    execution = router.route_task(
        task={
            "message": "Create a simple business proposal outline.",
            "type": "business_request",
        },
        user_id="demo_user",
        workspace_id="demo_workspace",
        execute=True,
    )

    print(execution)