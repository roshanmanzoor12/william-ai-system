"""
agents/agent_loader.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Loads agent classes from the agent registry, instantiates them safely per
    user/workspace, and prevents broken imports or missing future modules from
    crashing the system.

Responsibilities:
    - Load agent classes from registry definitions.
    - Instantiate agent objects with SaaS-safe user_id/workspace_id context.
    - Prevent broken imports from crashing the whole system.
    - Cache loaded classes and optionally cache instances per user/workspace.
    - Provide structured JSON-style results.
    - Stay compatible with BaseAgent, Agent Registry, Agent Router, Master Agent,
      Security Agent, Memory Agent, Verification Agent, Dashboard/API, and future
      plugin-style agents.

Safety Rules:
    - Never mix agents, task context, logs, memory, or analytics between users/workspaces.
    - Sensitive loading or execution preparation can be routed through Security Agent.
    - Completed loader actions can produce Verification Agent payloads.
    - Useful context is compatible with Memory Agent.
    - This file is import-safe even if future William modules do not exist yet.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import threading
import time
import traceback
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union


# =============================================================================
# Safe fallback imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps agent_loader.py import-safe before the real BaseAgent file
        exists or if the import path is temporarily broken.
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

        def health_check(self) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback BaseAgent health check passed.",
                "data": {
                    "agent_name": getattr(self, "agent_name", "unknown"),
                    "agent_type": getattr(self, "agent_type", "unknown"),
                },
                "error": None,
                "metadata": {},
            }


try:
    from agents.registry import AgentRegistry  # type: ignore
except Exception:  # pragma: no cover
    class AgentRegistry:  # type: ignore
        """
        Fallback AgentRegistry stub.

        This allows AgentLoader to work safely before the real registry exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self._agents: Dict[str, Dict[str, Any]] = {}

        def register_agent(
            self,
            key: str,
            module_path: str,
            class_name: str,
            metadata: Optional[Dict[str, Any]] = None,
        ) -> Dict[str, Any]:
            self._agents[key] = {
                "key": key,
                "module_path": module_path,
                "class_name": class_name,
                "metadata": metadata or {},
                "enabled": True,
            }
            return self._agents[key]

        def get_agent(self, key: str) -> Optional[Dict[str, Any]]:
            return self._agents.get(key)

        def list_agents(self) -> List[Dict[str, Any]]:
            return list(self._agents.values())

        def is_agent_registered(self, key: str) -> bool:
            return key in self._agents


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.agents.agent_loader")
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# =============================================================================
# Data structures
# =============================================================================

@dataclass(frozen=True)
class AgentInstanceKey:
    """
    Unique cache key for a loaded agent instance.

    user_id and workspace_id are included to enforce SaaS isolation.
    """

    agent_key: str
    user_id: str
    workspace_id: str
    role: str = "default"

    def as_string(self) -> str:
        return f"{self.user_id}:{self.workspace_id}:{self.role}:{self.agent_key}"


@dataclass
class AgentLoadRecord:
    """
    Tracks loaded class metadata and errors for observability.
    """

    agent_key: str
    module_path: str
    class_name: str
    loaded: bool = False
    loaded_at: Optional[float] = None
    error: Optional[str] = None
    traceback_text: Optional[str] = None
    class_ref: Optional[Type[Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentLoaderConfig:
    """
    Runtime configuration for AgentLoader.
    """

    cache_classes: bool = True
    cache_instances: bool = True
    strict_baseagent_check: bool = False
    allow_fallback_agent: bool = True
    default_role: str = "default"
    max_import_attempts: int = 2
    import_retry_delay_seconds: float = 0.05
    emit_events: bool = True
    audit_enabled: bool = True
    verification_enabled: bool = True
    memory_payload_enabled: bool = True


class SafeFallbackAgent(BaseAgent):
    """
    Safe fallback agent returned when an agent cannot be imported or instantiated.

    This prevents Master Agent / Router / API from crashing when one future agent
    file is missing or broken.
    """

    agent_name = "safe_fallback_agent"
    agent_type = "fallback"

    def __init__(
        self,
        agent_key: str = "unknown",
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        config: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        original_error: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(
            user_id=user_id,
            workspace_id=workspace_id,
            config=config or {},
            **kwargs,
        )
        self.agent_key = agent_key
        self.reason = reason or "Agent could not be loaded safely."
        self.original_error = original_error

    def run(self, task: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        return {
            "success": False,
            "message": "Fallback agent cannot execute the requested task.",
            "data": {
                "agent_key": self.agent_key,
                "reason": self.reason,
                "task_received": bool(task),
            },
            "error": self.original_error,
            "metadata": {
                "agent_type": self.agent_type,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "safe_fallback": True,
                "timestamp": time.time(),
            },
        }

    def health_check(self) -> Dict[str, Any]:
        return {
            "success": False,
            "message": "Fallback agent is active because the real agent failed to load.",
            "data": {
                "agent_key": self.agent_key,
                "reason": self.reason,
            },
            "error": self.original_error,
            "metadata": {
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "safe_fallback": True,
                "timestamp": time.time(),
            },
        }


# =============================================================================
# Agent Loader
# =============================================================================

class AgentLoader:
    """
    Production-safe loader for William/Jarvis agents.

    This class connects the Agent Registry to the Master Agent / Router layer.

    Main usage:
        registry = AgentRegistry()
        loader = AgentLoader(registry=registry)

        result = loader.get_agent_instance(
            agent_key="voice",
            user_id="1",
            workspace_id="main"
        )

        if result["success"]:
            agent = result["data"]["agent"]

    Design notes:
        - Classes are loaded from module_path + class_name.
        - Instances are isolated by user_id + workspace_id + role + agent_key.
        - Broken imports return structured errors or SafeFallbackAgent.
        - Public methods return dict results with:
          success, message, data, error, metadata.
    """

    def __init__(
        self,
        registry: Optional[Any] = None,
        config: Optional[Union[AgentLoaderConfig, Dict[str, Any]]] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        self.registry = registry or AgentRegistry()

        if isinstance(config, AgentLoaderConfig):
            self.config = config
        elif isinstance(config, dict):
            self.config = AgentLoaderConfig(**{
                key: value
                for key, value in config.items()
                if key in AgentLoaderConfig.__dataclass_fields__
            })
        else:
            self.config = AgentLoaderConfig()

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger

        self._class_cache: Dict[str, AgentLoadRecord] = {}
        self._instance_cache: Dict[str, Any] = {}
        self._load_errors: Dict[str, AgentLoadRecord] = {}
        self._lock = threading.RLock()

        self._emit_agent_event(
            event_type="agent_loader.initialized",
            data={
                "cache_classes": self.config.cache_classes,
                "cache_instances": self.config.cache_instances,
                "strict_baseagent_check": self.config.strict_baseagent_check,
            },
            user_id=None,
            workspace_id=None,
        )

    # =========================================================================
    # Public API
    # =========================================================================

    def load_agent_class(
        self,
        agent_key: str,
        force_reload: bool = False,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        Load an agent class by key from registry.

        Args:
            agent_key:
                Registry key for the agent.
            force_reload:
                If true, bypass class cache and import again.
            user_id/workspace_id:
                Optional context for audit/security/observability.

        Returns:
            Structured result containing class_ref if successful.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            allow_system_context=True,
        )
        if not context_result["success"]:
            return context_result

        normalized_key = self._normalize_agent_key(agent_key)
        if not normalized_key:
            return self._error_result(
                message="Invalid agent_key.",
                error="agent_key is required",
                data={"agent_key": agent_key},
                metadata=self._metadata(user_id, workspace_id),
            )

        with self._lock:
            if (
                self.config.cache_classes
                and not force_reload
                and normalized_key in self._class_cache
                and self._class_cache[normalized_key].loaded
            ):
                record = self._class_cache[normalized_key]
                return self._safe_result(
                    message="Agent class loaded from cache.",
                    data={
                        "agent_key": normalized_key,
                        "class_ref": record.class_ref,
                        "module_path": record.module_path,
                        "class_name": record.class_name,
                        "cached": True,
                    },
                    metadata=self._metadata(user_id, workspace_id, {
                        "loaded_at": record.loaded_at,
                    }),
                )

        registry_result = self._get_registry_definition(normalized_key)
        if not registry_result["success"]:
            return registry_result

        definition = registry_result["data"]["definition"]
        module_path = self._extract_definition_value(definition, "module_path")
        class_name = self._extract_definition_value(definition, "class_name")
        definition_metadata = self._extract_definition_value(definition, "metadata", default={}) or {}

        if not module_path or not class_name:
            return self._error_result(
                message="Registry definition is missing module_path or class_name.",
                error="invalid_registry_definition",
                data={
                    "agent_key": normalized_key,
                    "definition": self._safe_serialize(definition),
                },
                metadata=self._metadata(user_id, workspace_id),
            )

        security_result = self._request_security_approval(
            action="load_agent_class",
            user_id=user_id,
            workspace_id=workspace_id,
            payload={
                "agent_key": normalized_key,
                "module_path": module_path,
                "class_name": class_name,
            },
        )
        if not security_result["success"]:
            return security_result

        record = AgentLoadRecord(
            agent_key=normalized_key,
            module_path=str(module_path),
            class_name=str(class_name),
            metadata=dict(definition_metadata),
        )

        try:
            class_ref = self._import_class_with_retries(
                module_path=str(module_path),
                class_name=str(class_name),
            )

            base_check_result = self._validate_agent_class(
                class_ref=class_ref,
                agent_key=normalized_key,
            )
            if not base_check_result["success"]:
                return base_check_result

            record.loaded = True
            record.loaded_at = time.time()
            record.class_ref = class_ref

            with self._lock:
                if self.config.cache_classes:
                    self._class_cache[normalized_key] = record
                self._load_errors.pop(normalized_key, None)

            self._log_audit_event(
                action="agent_class_loaded",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "agent_key": normalized_key,
                    "module_path": module_path,
                    "class_name": class_name,
                },
            )

            self._emit_agent_event(
                event_type="agent_loader.class_loaded",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "agent_key": normalized_key,
                    "module_path": module_path,
                    "class_name": class_name,
                },
            )

            return self._safe_result(
                message="Agent class loaded successfully.",
                data={
                    "agent_key": normalized_key,
                    "class_ref": class_ref,
                    "module_path": module_path,
                    "class_name": class_name,
                    "cached": False,
                },
                metadata=self._metadata(user_id, workspace_id, {
                    "verification_payload": self._prepare_verification_payload(
                        action="load_agent_class",
                        success=True,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        data={
                            "agent_key": normalized_key,
                            "module_path": module_path,
                            "class_name": class_name,
                        },
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        action="load_agent_class",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        data={
                            "agent_key": normalized_key,
                            "module_path": module_path,
                            "class_name": class_name,
                        },
                    ),
                }),
            )

        except Exception as exc:
            record.loaded = False
            record.error = str(exc)
            record.traceback_text = traceback.format_exc()

            with self._lock:
                self._load_errors[normalized_key] = record
                if self.config.cache_classes:
                    self._class_cache[normalized_key] = record

            self._log_audit_event(
                action="agent_class_load_failed",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "agent_key": normalized_key,
                    "module_path": module_path,
                    "class_name": class_name,
                    "error": str(exc),
                },
            )

            self._emit_agent_event(
                event_type="agent_loader.class_load_failed",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "agent_key": normalized_key,
                    "error": str(exc),
                },
            )

            if self.config.allow_fallback_agent:
                return self._safe_result(
                    message="Agent class failed to load; SafeFallbackAgent is available.",
                    data={
                        "agent_key": normalized_key,
                        "class_ref": SafeFallbackAgent,
                        "module_path": module_path,
                        "class_name": class_name,
                        "fallback": True,
                        "original_error": str(exc),
                    },
                    metadata=self._metadata(user_id, workspace_id, {
                        "verification_payload": self._prepare_verification_payload(
                            action="load_agent_class",
                            success=False,
                            user_id=user_id,
                            workspace_id=workspace_id,
                            data={
                                "agent_key": normalized_key,
                                "error": str(exc),
                            },
                        ),
                    }),
                )

            return self._error_result(
                message="Agent class failed to load.",
                error=str(exc),
                data={
                    "agent_key": normalized_key,
                    "module_path": module_path,
                    "class_name": class_name,
                },
                metadata=self._metadata(user_id, workspace_id, {
                    "traceback": record.traceback_text,
                }),
            )

    def create_agent_instance(
        self,
        agent_key: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        role: Optional[str] = None,
        agent_config: Optional[Dict[str, Any]] = None,
        force_new: bool = False,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Create a new agent instance for a specific user/workspace.

        This method does not return a cached instance unless cache_instances is enabled
        and force_new is False.

        Args:
            agent_key:
                Registry key for the agent.
            user_id:
                SaaS user ID.
            workspace_id:
                SaaS workspace ID.
            role:
                Optional role/context key.
            agent_config:
                Optional runtime config passed into the agent.
            force_new:
                If true, bypass instance cache.
            kwargs:
                Extra safe context passed into agent constructor.

        Returns:
            Structured result containing the agent instance.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            allow_system_context=False,
        )
        if not context_result["success"]:
            return context_result

        normalized_key = self._normalize_agent_key(agent_key)
        normalized_user_id = self._normalize_context_id(user_id)
        normalized_workspace_id = self._normalize_context_id(workspace_id)
        normalized_role = role or self.config.default_role

        instance_key = AgentInstanceKey(
            agent_key=normalized_key,
            user_id=normalized_user_id,
            workspace_id=normalized_workspace_id,
            role=normalized_role,
        )
        instance_cache_key = instance_key.as_string()

        with self._lock:
            if (
                self.config.cache_instances
                and not force_new
                and instance_cache_key in self._instance_cache
            ):
                instance = self._instance_cache[instance_cache_key]
                return self._safe_result(
                    message="Agent instance loaded from cache.",
                    data={
                        "agent": instance,
                        "agent_key": normalized_key,
                        "instance_key": instance_cache_key,
                        "cached": True,
                    },
                    metadata=self._metadata(user_id, workspace_id),
                )

        security_result = self._request_security_approval(
            action="create_agent_instance",
            user_id=user_id,
            workspace_id=workspace_id,
            payload={
                "agent_key": normalized_key,
                "role": normalized_role,
            },
        )
        if not security_result["success"]:
            return security_result

        class_result = self.load_agent_class(
            agent_key=normalized_key,
            user_id=user_id,
            workspace_id=workspace_id,
        )

        if not class_result["success"]:
            return class_result

        class_ref = class_result["data"].get("class_ref")
        is_fallback = bool(class_result["data"].get("fallback"))
        original_error = class_result["data"].get("original_error")

        try:
            instance = self._instantiate_agent_safely(
                class_ref=class_ref,
                agent_key=normalized_key,
                user_id=normalized_user_id,
                workspace_id=normalized_workspace_id,
                role=normalized_role,
                agent_config=agent_config or {},
                is_fallback=is_fallback,
                original_error=original_error,
                extra_kwargs=kwargs,
            )

            with self._lock:
                if self.config.cache_instances:
                    self._instance_cache[instance_cache_key] = instance

            self._log_audit_event(
                action="agent_instance_created",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "agent_key": normalized_key,
                    "instance_key": instance_cache_key,
                    "role": normalized_role,
                    "fallback": is_fallback,
                },
            )

            self._emit_agent_event(
                event_type="agent_loader.instance_created",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "agent_key": normalized_key,
                    "instance_key": instance_cache_key,
                    "role": normalized_role,
                    "fallback": is_fallback,
                },
            )

            return self._safe_result(
                message="Agent instance created successfully.",
                data={
                    "agent": instance,
                    "agent_key": normalized_key,
                    "instance_key": instance_cache_key,
                    "cached": False,
                    "fallback": is_fallback,
                },
                metadata=self._metadata(user_id, workspace_id, {
                    "verification_payload": self._prepare_verification_payload(
                        action="create_agent_instance",
                        success=True,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        data={
                            "agent_key": normalized_key,
                            "instance_key": instance_cache_key,
                            "fallback": is_fallback,
                        },
                    ),
                    "memory_payload": self._prepare_memory_payload(
                        action="create_agent_instance",
                        user_id=user_id,
                        workspace_id=workspace_id,
                        data={
                            "agent_key": normalized_key,
                            "role": normalized_role,
                            "fallback": is_fallback,
                        },
                    ),
                }),
            )

        except Exception as exc:
            error_text = str(exc)

            self._log_audit_event(
                action="agent_instance_create_failed",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "agent_key": normalized_key,
                    "instance_key": instance_cache_key,
                    "error": error_text,
                },
            )

            self._emit_agent_event(
                event_type="agent_loader.instance_create_failed",
                user_id=user_id,
                workspace_id=workspace_id,
                data={
                    "agent_key": normalized_key,
                    "instance_key": instance_cache_key,
                    "error": error_text,
                },
            )

            if self.config.allow_fallback_agent:
                fallback_instance = SafeFallbackAgent(
                    agent_key=normalized_key,
                    user_id=normalized_user_id,
                    workspace_id=normalized_workspace_id,
                    config=agent_config or {},
                    reason="Agent instance creation failed.",
                    original_error=error_text,
                )

                with self._lock:
                    if self.config.cache_instances:
                        self._instance_cache[instance_cache_key] = fallback_instance

                return self._safe_result(
                    message="Agent instance failed to create; fallback instance returned.",
                    data={
                        "agent": fallback_instance,
                        "agent_key": normalized_key,
                        "instance_key": instance_cache_key,
                        "cached": False,
                        "fallback": True,
                        "original_error": error_text,
                    },
                    metadata=self._metadata(user_id, workspace_id, {
                        "traceback": traceback.format_exc(),
                    }),
                )

            return self._error_result(
                message="Agent instance creation failed.",
                error=error_text,
                data={
                    "agent_key": normalized_key,
                    "instance_key": instance_cache_key,
                },
                metadata=self._metadata(user_id, workspace_id, {
                    "traceback": traceback.format_exc(),
                }),
            )

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
        """
        Main public method used by Master Agent / Agent Router.

        Gets an existing cached instance or creates a new isolated instance.
        """

        return self.create_agent_instance(
            agent_key=agent_key,
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            agent_config=agent_config,
            force_new=force_new,
            **kwargs,
        )

    def preload_agents(
        self,
        agent_keys: Optional[List[str]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        force_reload: bool = False,
    ) -> Dict[str, Any]:
        """
        Preload agent classes into cache.

        Useful for dashboard startup, health checks, deployment validation,
        and Master Agent warmup.
        """

        if agent_keys is None:
            list_result = self.list_registered_agents()
            if not list_result["success"]:
                return list_result

            agent_keys = [
                item.get("key") or item.get("agent_key") or item.get("name")
                for item in list_result["data"]["agents"]
                if item.get("key") or item.get("agent_key") or item.get("name")
            ]

        loaded: List[str] = []
        failed: List[Dict[str, Any]] = []

        for key in agent_keys:
            result = self.load_agent_class(
                agent_key=str(key),
                force_reload=force_reload,
                user_id=user_id,
                workspace_id=workspace_id,
            )
            if result["success"] and not result["data"].get("fallback"):
                loaded.append(str(key))
            else:
                failed.append({
                    "agent_key": str(key),
                    "message": result.get("message"),
                    "error": result.get("error"),
                    "fallback": result.get("data", {}).get("fallback", False),
                })

        return self._safe_result(
            message="Agent preload completed.",
            data={
                "loaded": loaded,
                "failed": failed,
                "total_requested": len(agent_keys),
                "total_loaded": len(loaded),
                "total_failed": len(failed),
            },
            metadata=self._metadata(user_id, workspace_id),
        )


    def load_all_agents(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        role: Optional[str] = None,
        force_new: bool = False,
        agent_config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create real isolated instances for every registered agent.

        This method exists for main.py/live runtime compatibility. It returns
        only real agent instance names in data["agents"]. It never treats the
        wrapper keys success/message/data/error/metadata as agents.
        """
        list_result = self.list_registered_agents()
        if not list_result.get("success"):
            return list_result

        loaded: Dict[str, Any] = {}
        failed: Dict[str, Any] = {}

        for item in list_result.get("data", {}).get("agents", []):
            key = item.get("agent_key") or item.get("key") or item.get("name")
            if not key:
                continue
            key = str(key).replace("_agent", "").lower()
            if key in {"success", "message", "data", "error", "metadata"}:
                continue

            result = self.get_agent_instance(
                agent_key=key,
                user_id=user_id,
                workspace_id=workspace_id,
                role=role,
                agent_config=agent_config or {},
                force_new=force_new,
            )
            agent = result.get("data", {}).get("agent") if isinstance(result, dict) else None
            if result.get("success") and agent is not None:
                loaded[key] = agent
            else:
                failed[key] = {
                    "message": result.get("message") if isinstance(result, dict) else "Unknown load failure",
                    "error": result.get("error") if isinstance(result, dict) else None,
                }

        return self._safe_result(
            message="All registered agents loaded as isolated instances.",
            data={
                "agents": loaded,
                "loaded_agents": sorted(loaded.keys()),
                "failed_agents": failed,
                "count": len(loaded),
            },
            metadata=self._metadata(user_id, workspace_id),
        )

    def load_agents(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Alias used by main.py."""
        return self.load_all_agents(*args, **kwargs)

    def load_all(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Alias used by main.py."""
        return self.load_all_agents(*args, **kwargs)

    def get_loaded_instances(self) -> Dict[str, Any]:
        """Return currently cached real instances without wrapper keys."""
        agents: Dict[str, Any] = {}
        for cache_key, instance in self._instance_cache.items():
            key = str(cache_key).split(":")[-1].replace("_agent", "").lower()
            if key not in {"success", "message", "data", "error", "metadata"}:
                agents[key] = instance
        return self._safe_result(
            message="Loaded agent instances returned.",
            data={"agents": agents, "loaded_agents": sorted(agents.keys()), "count": len(agents)},
            metadata=self._metadata(None, None),
        )

    def unload_agent_instance(
        self,
        agent_key: str,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
        role: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Remove one user/workspace-specific agent instance from cache.
        """

        context_result = self._validate_task_context(user_id, workspace_id)
        if not context_result["success"]:
            return context_result

        normalized_key = self._normalize_agent_key(agent_key)
        instance_key = AgentInstanceKey(
            agent_key=normalized_key,
            user_id=self._normalize_context_id(user_id),
            workspace_id=self._normalize_context_id(workspace_id),
            role=role or self.config.default_role,
        ).as_string()

        with self._lock:
            existed = instance_key in self._instance_cache
            if existed:
                del self._instance_cache[instance_key]

        self._log_audit_event(
            action="agent_instance_unloaded",
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "agent_key": normalized_key,
                "instance_key": instance_key,
                "existed": existed,
            },
        )

        return self._safe_result(
            message="Agent instance unloaded." if existed else "No matching cached instance found.",
            data={
                "agent_key": normalized_key,
                "instance_key": instance_key,
                "removed": existed,
            },
            metadata=self._metadata(user_id, workspace_id),
        )

    def unload_workspace_instances(
        self,
        user_id: Union[str, int],
        workspace_id: Union[str, int],
    ) -> Dict[str, Any]:
        """
        Remove all cached instances for a specific user/workspace.
        """

        context_result = self._validate_task_context(user_id, workspace_id)
        if not context_result["success"]:
            return context_result

        prefix = f"{self._normalize_context_id(user_id)}:{self._normalize_context_id(workspace_id)}:"
        removed_keys: List[str] = []

        with self._lock:
            for key in list(self._instance_cache.keys()):
                if key.startswith(prefix):
                    removed_keys.append(key)
                    del self._instance_cache[key]

        self._log_audit_event(
            action="workspace_agent_instances_unloaded",
            user_id=user_id,
            workspace_id=workspace_id,
            data={
                "removed_count": len(removed_keys),
                "removed_keys": removed_keys,
            },
        )

        return self._safe_result(
            message="Workspace agent instances unloaded.",
            data={
                "removed_count": len(removed_keys),
                "removed_keys": removed_keys,
            },
            metadata=self._metadata(user_id, workspace_id),
        )

    def clear_class_cache(self) -> Dict[str, Any]:
        """
        Clear loaded class cache.

        Does not clear instance cache.
        """

        with self._lock:
            count = len(self._class_cache)
            self._class_cache.clear()

        return self._safe_result(
            message="Agent class cache cleared.",
            data={"cleared_count": count},
            metadata=self._metadata(None, None),
        )

    def clear_instance_cache(self) -> Dict[str, Any]:
        """
        Clear all cached instances.

        Useful for development, tests, deployment reloads, and emergency reset.
        """

        with self._lock:
            count = len(self._instance_cache)
            self._instance_cache.clear()

        return self._safe_result(
            message="Agent instance cache cleared.",
            data={"cleared_count": count},
            metadata=self._metadata(None, None),
        )

    def clear_all_caches(self) -> Dict[str, Any]:
        """
        Clear class cache, instance cache, and load error cache.
        """

        with self._lock:
            class_count = len(self._class_cache)
            instance_count = len(self._instance_cache)
            error_count = len(self._load_errors)

            self._class_cache.clear()
            self._instance_cache.clear()
            self._load_errors.clear()

        return self._safe_result(
            message="All AgentLoader caches cleared.",
            data={
                "class_cache_cleared": class_count,
                "instance_cache_cleared": instance_count,
                "error_cache_cleared": error_count,
            },
            metadata=self._metadata(None, None),
        )

    def list_registered_agents(self) -> Dict[str, Any]:
        """
        List registered agents from registry safely.
        """

        try:
            if hasattr(self.registry, "list_agents") and callable(self.registry.list_agents):
                agents = self.registry.list_agents()
            elif hasattr(self.registry, "agents"):
                agents = list(getattr(self.registry, "agents", {}).values())
            elif hasattr(self.registry, "_agents"):
                agents = list(getattr(self.registry, "_agents", {}).values())
            else:
                agents = []

            return self._safe_result(
                message="Registered agents listed successfully.",
                data={
                    "agents": [self._safe_serialize(item) for item in agents],
                    "count": len(agents),
                },
                metadata=self._metadata(None, None),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to list registered agents.",
                error=str(exc),
                data={},
                metadata=self._metadata(None, None, {
                    "traceback": traceback.format_exc(),
                }),
            )

    def list_loaded_classes(self) -> Dict[str, Any]:
        """
        List class cache records without exposing raw class objects.
        """

        with self._lock:
            records = []
            for key, record in self._class_cache.items():
                records.append({
                    "agent_key": key,
                    "module_path": record.module_path,
                    "class_name": record.class_name,
                    "loaded": record.loaded,
                    "loaded_at": record.loaded_at,
                    "error": record.error,
                    "metadata": record.metadata,
                })

        return self._safe_result(
            message="Loaded agent classes listed successfully.",
            data={
                "classes": records,
                "count": len(records),
            },
            metadata=self._metadata(None, None),
        )

    def list_cached_instances(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> Dict[str, Any]:
        """
        List cached agent instances.

        If user_id and workspace_id are supplied, only list that workspace's
        instances to preserve isolation.
        """

        with self._lock:
            keys = list(self._instance_cache.keys())

        if user_id is not None and workspace_id is not None:
            prefix = f"{self._normalize_context_id(user_id)}:{self._normalize_context_id(workspace_id)}:"
            keys = [key for key in keys if key.startswith(prefix)]

        sanitized = []
        for key in keys:
            instance = self._instance_cache.get(key)
            sanitized.append({
                "instance_key": key,
                "agent_class": instance.__class__.__name__ if instance else None,
                "agent_name": getattr(instance, "agent_name", None),
                "agent_type": getattr(instance, "agent_type", None),
                "user_id": getattr(instance, "user_id", None),
                "workspace_id": getattr(instance, "workspace_id", None),
                "fallback": isinstance(instance, SafeFallbackAgent),
            })

        return self._safe_result(
            message="Cached agent instances listed successfully.",
            data={
                "instances": sanitized,
                "count": len(sanitized),
            },
            metadata=self._metadata(user_id, workspace_id),
        )

    def get_load_errors(self) -> Dict[str, Any]:
        """
        Return recent import/load errors for dashboard diagnostics.
        """

        with self._lock:
            errors = []
            for key, record in self._load_errors.items():
                errors.append({
                    "agent_key": key,
                    "module_path": record.module_path,
                    "class_name": record.class_name,
                    "error": record.error,
                    "traceback": record.traceback_text,
                    "metadata": record.metadata,
                })

        return self._safe_result(
            message="Agent load errors retrieved successfully.",
            data={
                "errors": errors,
                "count": len(errors),
            },
            metadata=self._metadata(None, None),
        )

    def health_check(
        self,
        include_instances: bool = True,
        include_registry: bool = True,
    ) -> Dict[str, Any]:
        """
        Health check for AgentLoader, class cache, instance cache, and registry.
        """

        health_data: Dict[str, Any] = {
            "loader": {
                "healthy": True,
                "class_cache_count": len(self._class_cache),
                "instance_cache_count": len(self._instance_cache),
                "load_error_count": len(self._load_errors),
                "config": {
                    "cache_classes": self.config.cache_classes,
                    "cache_instances": self.config.cache_instances,
                    "strict_baseagent_check": self.config.strict_baseagent_check,
                    "allow_fallback_agent": self.config.allow_fallback_agent,
                },
            }
        }

        if include_registry:
            registry_result = self.list_registered_agents()
            health_data["registry"] = {
                "healthy": registry_result["success"],
                "count": registry_result.get("data", {}).get("count", 0),
                "error": registry_result.get("error"),
            }

        if include_instances:
            instance_health: List[Dict[str, Any]] = []

            with self._lock:
                cached_items = list(self._instance_cache.items())

            for instance_key, instance in cached_items:
                item = {
                    "instance_key": instance_key,
                    "agent_class": instance.__class__.__name__,
                    "healthy": None,
                    "error": None,
                    "fallback": isinstance(instance, SafeFallbackAgent),
                }

                try:
                    if hasattr(instance, "health_check") and callable(instance.health_check):
                        result = instance.health_check()
                        item["healthy"] = bool(result.get("success", False))
                        item["error"] = result.get("error")
                    else:
                        item["healthy"] = True
                except Exception as exc:
                    item["healthy"] = False
                    item["error"] = str(exc)

                instance_health.append(item)

            health_data["instances"] = instance_health

        return self._safe_result(
            message="AgentLoader health check completed.",
            data=health_data,
            metadata=self._metadata(None, None),
        )

    # =========================================================================
    # Registry helpers
    # =========================================================================

    def _get_registry_definition(self, agent_key: str) -> Dict[str, Any]:
        """
        Safely fetch one agent definition from registry.
        """

        try:
            definition = None

            if hasattr(self.registry, "get_agent") and callable(self.registry.get_agent):
                definition = self.registry.get_agent(agent_key)
            elif hasattr(self.registry, "get") and callable(self.registry.get):
                definition = self.registry.get(agent_key)
            elif hasattr(self.registry, "agents"):
                definition = getattr(self.registry, "agents", {}).get(agent_key)
            elif hasattr(self.registry, "_agents"):
                definition = getattr(self.registry, "_agents", {}).get(agent_key)

            if not definition:
                return self._error_result(
                    message="Agent is not registered.",
                    error="agent_not_registered",
                    data={"agent_key": agent_key},
                    metadata=self._metadata(None, None),
                )

            return self._safe_result(
                message="Registry definition found.",
                data={
                    "agent_key": agent_key,
                    "definition": definition,
                },
                metadata=self._metadata(None, None),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to read agent registry definition.",
                error=str(exc),
                data={"agent_key": agent_key},
                metadata=self._metadata(None, None, {
                    "traceback": traceback.format_exc(),
                }),
            )

    @staticmethod
    def _extract_definition_value(
        definition: Any,
        key: str,
        default: Any = None,
    ) -> Any:
        """
        Extract a value from dict/object registry definitions.
        """

        if isinstance(definition, dict):
            return definition.get(key, default)

        return getattr(definition, key, default)

    # =========================================================================
    # Import / instantiate helpers
    # =========================================================================

    def _import_class_with_retries(
        self,
        module_path: str,
        class_name: str,
    ) -> Type[Any]:
        """
        Import module and class with limited retry support.
        """

        last_error: Optional[Exception] = None

        attempts = max(1, int(self.config.max_import_attempts))
        for attempt in range(1, attempts + 1):
            try:
                module = importlib.import_module(module_path)
                return self._get_class_from_module(module, class_name)

            except Exception as exc:
                last_error = exc
                if attempt < attempts:
                    time.sleep(max(0.0, float(self.config.import_retry_delay_seconds)))

        if last_error:
            raise last_error

        raise ImportError(f"Unable to import {class_name} from {module_path}")

    @staticmethod
    def _get_class_from_module(module: ModuleType, class_name: str) -> Type[Any]:
        """
        Get class by name from imported module.
        """

        class_ref = getattr(module, class_name, None)

        if class_ref is None:
            raise AttributeError(
                f"Class '{class_name}' not found in module '{module.__name__}'."
            )

        if not inspect.isclass(class_ref):
            raise TypeError(
                f"'{class_name}' in module '{module.__name__}' is not a class."
            )

        return class_ref

    def _validate_agent_class(
        self,
        class_ref: Type[Any],
        agent_key: str,
    ) -> Dict[str, Any]:
        """
        Validate loaded class compatibility.

        If strict_baseagent_check is false, non-BaseAgent classes are allowed
        but reported in metadata. This helps during early development when
        some future agents may not yet inherit BaseAgent.
        """

        if not inspect.isclass(class_ref):
            return self._error_result(
                message="Loaded agent reference is not a class.",
                error="invalid_agent_class",
                data={"agent_key": agent_key},
                metadata=self._metadata(None, None),
            )

        is_baseagent_subclass = False
        try:
            is_baseagent_subclass = issubclass(class_ref, BaseAgent)
        except Exception:
            is_baseagent_subclass = False

        if self.config.strict_baseagent_check and not is_baseagent_subclass:
            return self._error_result(
                message="Agent class does not inherit from BaseAgent.",
                error="baseagent_inheritance_required",
                data={
                    "agent_key": agent_key,
                    "class_name": class_ref.__name__,
                },
                metadata=self._metadata(None, None),
            )

        return self._safe_result(
            message="Agent class validation completed.",
            data={
                "agent_key": agent_key,
                "class_name": class_ref.__name__,
                "is_baseagent_subclass": is_baseagent_subclass,
            },
            metadata=self._metadata(None, None),
        )

    def _instantiate_agent_safely(
        self,
        class_ref: Type[Any],
        agent_key: str,
        user_id: str,
        workspace_id: str,
        role: str,
        agent_config: Dict[str, Any],
        is_fallback: bool = False,
        original_error: Optional[str] = None,
        extra_kwargs: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """
        Instantiate an agent while adapting to constructor signatures.

        Supports constructors like:
            Agent(user_id=..., workspace_id=..., config=...)
            Agent(config=...)
            Agent()
        """

        extra_kwargs = extra_kwargs or {}

        if class_ref is SafeFallbackAgent or is_fallback:
            return SafeFallbackAgent(
                agent_key=agent_key,
                user_id=user_id,
                workspace_id=workspace_id,
                config=agent_config,
                reason="Real agent class unavailable.",
                original_error=original_error,
                **extra_kwargs,
            )

        constructor_kwargs = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "config": agent_config,
            "agent_key": agent_key,
            "role": role,
            **extra_kwargs,
        }

        try:
            signature = inspect.signature(class_ref)
            accepted_kwargs = {}

            has_var_kwargs = any(
                param.kind == inspect.Parameter.VAR_KEYWORD
                for param in signature.parameters.values()
            )

            if has_var_kwargs:
                accepted_kwargs = constructor_kwargs
            else:
                for key, value in constructor_kwargs.items():
                    if key in signature.parameters:
                        accepted_kwargs[key] = value

            return class_ref(**accepted_kwargs)

        except TypeError:
            try:
                return class_ref(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    config=agent_config,
                )
            except TypeError:
                try:
                    return class_ref(config=agent_config)
                except TypeError:
                    return class_ref()

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
        Validate SaaS user/workspace context.

        System-level operations such as loading a class may allow missing context.
        User-specific instance creation must always include both user_id and
        workspace_id.
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
                message="user_id is required for user-specific agent operations.",
                error="missing_user_id",
                data={},
                metadata=self._metadata(user_id, workspace_id),
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="workspace_id is required for workspace-isolated agent operations.",
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
        Decide whether a loader action requires Security Agent approval.

        Loading/instantiating agents is considered sensitive because broken,
        malicious, or unauthorized plugins could affect the SaaS environment.
        """

        sensitive_actions = {
            "load_agent_class",
            "create_agent_instance",
            "force_reload_agent",
            "unload_workspace_instances",
            "clear_all_caches",
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
        Request Security Agent approval when available.

        If no Security Agent is connected yet, this returns a safe approval with
        metadata stating that approval was bypassed due to missing dependency.
        """

        payload = payload or {}

        if not self._requires_security_check(action):
            return self._safe_result(
                message="Security check not required.",
                data={"approved": True, "action": action},
                metadata=self._metadata(user_id, workspace_id),
            )

        if self.security_agent is None:
            return self._safe_result(
                message="Security Agent not connected; safe default approval used.",
                data={
                    "approved": True,
                    "action": action,
                    "security_agent_connected": False,
                },
                metadata=self._metadata(user_id, workspace_id),
            )

        try:
            security_payload = {
                "action": action,
                "user_id": user_id,
                "workspace_id": workspace_id,
                "payload": payload,
                "source": "AgentLoader",
                "timestamp": time.time(),
            }

            if hasattr(self.security_agent, "approve_action"):
                result = self.security_agent.approve_action(security_payload)
            elif hasattr(self.security_agent, "check_permission"):
                result = self.security_agent.check_permission(security_payload)
            elif hasattr(self.security_agent, "run"):
                result = self.security_agent.run(security_payload)
            else:
                return self._safe_result(
                    message="Security Agent has no approval method; safe default approval used.",
                    data={
                        "approved": True,
                        "action": action,
                        "security_agent_connected": True,
                        "approval_method_found": False,
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
                        message="Security Agent approved action.",
                        data={
                            "approved": True,
                            "action": action,
                            "security_result": self._safe_serialize(result),
                        },
                        metadata=self._metadata(user_id, workspace_id),
                    )

                return self._error_result(
                    message="Security Agent denied action.",
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
                    message="Security Agent approved action.",
                    data={"approved": True, "action": action},
                    metadata=self._metadata(user_id, workspace_id),
                )

            return self._error_result(
                message="Security Agent denied action.",
                error="security_denied",
                data={"approved": False, "action": action},
                metadata=self._metadata(user_id, workspace_id),
            )

        except Exception as exc:
            return self._error_result(
                message="Security approval check failed.",
                error=str(exc),
                data={
                    "approved": False,
                    "action": action,
                },
                metadata=self._metadata(user_id, workspace_id, {
                    "traceback": traceback.format_exc(),
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

        This does not force-call Verification Agent. It prepares a payload that
        Master Agent / Router / API can forward later.
        """

        if not self.config.verification_enabled:
            return None

        return {
            "source": "AgentLoader",
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

        This is intentionally minimal and does not store secrets or raw objects.
        """

        if not self.config.memory_payload_enabled:
            return None

        return {
            "source": "AgentLoader",
            "memory_type": "agent_loader_event",
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
        Emit dashboard/API compatible agent event.

        If event_emitter is not connected, this quietly logs debug only.
        """

        if not self.config.emit_events:
            return

        event = {
            "event_type": event_type,
            "source": "AgentLoader",
            "user_id": self._normalize_optional_context_id(user_id),
            "workspace_id": self._normalize_optional_context_id(workspace_id),
            "data": self._safe_serialize(data or {}),
            "timestamp": time.time(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                logger.debug("AgentLoader event: %s", event)
        except Exception:
            logger.exception("AgentLoader event emitter failed.")

    def _log_audit_event(
        self,
        action: str,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event for dashboard/security trail.
        """

        if not self.config.audit_enabled:
            return

        event = {
            "action": action,
            "source": "AgentLoader",
            "user_id": self._normalize_optional_context_id(user_id),
            "workspace_id": self._normalize_optional_context_id(workspace_id),
            "data": self._safe_serialize(data or {}),
            "timestamp": time.time(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(event)
            else:
                logger.info("AgentLoader audit event: %s", event)
        except Exception:
            logger.exception("AgentLoader audit logger failed.")

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
        error: Any,
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
            "error": str(error) if error is not None else "unknown_error",
            "metadata": metadata or {},
        }

    # =========================================================================
    # Utility helpers
    # =========================================================================

    @staticmethod
    def _normalize_agent_key(agent_key: Any) -> str:
        """
        Normalize agent key.
        """

        if agent_key is None:
            return ""
        return str(agent_key).strip().lower()

    @staticmethod
    def _normalize_context_id(value: Union[str, int]) -> str:
        """
        Normalize user/workspace IDs to strings.
        """

        return str(value).strip()

    @staticmethod
    def _normalize_optional_context_id(value: Optional[Union[str, int]]) -> Optional[str]:
        """
        Normalize optional user/workspace IDs.
        """

        if value is None:
            return None
        return str(value).strip()

    def _metadata(
        self,
        user_id: Optional[Union[str, int]],
        workspace_id: Optional[Union[str, int]],
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build standard metadata object.
        """

        metadata = {
            "source": "AgentLoader",
            "user_id": self._normalize_optional_context_id(user_id),
            "workspace_id": self._normalize_optional_context_id(workspace_id),
            "timestamp": time.time(),
        }

        if extra:
            metadata.update(extra)

        return metadata

    def _safe_serialize(self, value: Any) -> Any:
        """
        Safely serialize values for logs/results without exposing raw objects.

        This avoids returning unserializable class objects in dashboard/API logs.
        """

        if value is None:
            return None

        if isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, dict):
            return {
                str(k): self._safe_serialize(v)
                for k, v in value.items()
                if not self._looks_sensitive(str(k))
            }

        if isinstance(value, (list, tuple, set)):
            return [self._safe_serialize(item) for item in value]

        if inspect.isclass(value):
            return {
                "class_name": value.__name__,
                "module": getattr(value, "__module__", None),
            }

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
        Prevent obvious sensitive fields from being logged or serialized.
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
# Optional module-level convenience factory
# =============================================================================

def create_agent_loader(
    registry: Optional[Any] = None,
    config: Optional[Union[AgentLoaderConfig, Dict[str, Any]]] = None,
    security_agent: Optional[Any] = None,
    memory_agent: Optional[Any] = None,
    verification_agent: Optional[Any] = None,
    event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
    audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> AgentLoader:
    """
    Factory helper for FastAPI/dashboard/bootstrap integration.
    """

    return AgentLoader(
        registry=registry,
        config=config,
        security_agent=security_agent,
        memory_agent=memory_agent,
        verification_agent=verification_agent,
        event_emitter=event_emitter,
        audit_logger=audit_logger,
    )


__all__ = [
    "AgentLoader",
    "AgentLoaderConfig",
    "AgentLoadRecord",
    "AgentInstanceKey",
    "SafeFallbackAgent",
    "create_agent_loader",
]


if __name__ == "__main__":
    """
    Lightweight local smoke test.

    This does not execute real system, browser, call, financial, or destructive
    actions. It only validates that the loader imports and can return structured
    results.
    """

    logging.basicConfig(level=logging.INFO)

    loader = AgentLoader()
    print(loader.health_check())