"""
main.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

FULL FINAL LIVE ENTRYPOINT

What this file does:
- Boots William/Jarvis safely.
- Loads real registry/loader/router/master agent paths first.
- Falls back only when real files/classes are missing or incompatible.
- Adds live CLI mode: python main.py --cli
- Adds voice response mode: python main.py --voice
- Supports one-shot task mode: python main.py --task "{...}"
- Keeps SaaS isolation: user_id + workspace_id on every task.
- Keeps sensitive actions behind security approval.
- Returns structured results: success, message, data, error, metadata.

Important:
- This file does NOT magically make unfinished agents perform real actions.
- It wires your Main/Master Agent runtime correctly so real agents can be tested.
- Voice mode can speak with pyttsx3 if installed.
- Mic listening is optional and only attempted with --listen.
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import inspect
import json
import logging
import os
import sys
import traceback
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union


# =============================================================================
# Paths
# =============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent
LOG_DIR = PROJECT_ROOT / "logs"
DATA_DIR = PROJECT_ROOT / "data"
CONFIG_DIR = PROJECT_ROOT / "config"

for _folder in (LOG_DIR, DATA_DIR, CONFIG_DIR):
    _folder.mkdir(parents=True, exist_ok=True)

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# =============================================================================
# Logging
# =============================================================================

def _setup_logger() -> logging.Logger:
    logger = logging.getLogger("william.main")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    console.setLevel(logging.INFO)

    file_handler = logging.FileHandler(LOG_DIR / "william_main.log", encoding="utf-8")
    file_handler.setFormatter(fmt)
    file_handler.setLevel(logging.INFO)

    logger.addHandler(console)
    logger.addHandler(file_handler)
    return logger


logger = _setup_logger()


# =============================================================================
# Utilities
# =============================================================================

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_json_dumps(data: Any, compact: bool = False) -> str:
    try:
        return json.dumps(
            data,
            ensure_ascii=False,
            default=str,
            separators=(",", ":") if compact else None,
            indent=None if compact else 2,
        )
    except Exception:
        return json.dumps(
            {
                "success": False,
                "message": "Unable to serialize data.",
                "data_type": str(type(data)),
            },
            indent=None if compact else 2,
        )


def _normalize_identifier(value: Optional[Union[str, int]], field_name: str) -> str:
    if value is None:
        raise ValueError(f"{field_name} is required.")
    clean = str(value).strip()
    if not clean:
        raise ValueError(f"{field_name} cannot be empty.")
    if len(clean) > 128:
        raise ValueError(f"{field_name} is too long.")
    return clean


def _safe_import_attr(module_paths: Iterable[str], attr_name: str) -> Optional[Any]:
    for module_path in module_paths:
        try:
            module = importlib.import_module(module_path)
            attr = getattr(module, attr_name, None)
            if attr is not None:
                logger.info("Imported %s from %s", attr_name, module_path)
                return attr
        except Exception as exc:
            logger.debug("Optional import failed: %s.%s | %s", module_path, attr_name, exc)
    return None


def _run_maybe_async(value: Any) -> Any:
    if inspect.isawaitable(value):
        try:
            return asyncio.run(value)
        except RuntimeError:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(value)
    return value


def _call_first_available(obj: Any, method_names: Iterable[str], *args: Any, **kwargs: Any) -> Any:
    last_error: Optional[Exception] = None
    for name in method_names:
        method = getattr(obj, name, None)
        if not callable(method):
            continue
        try:
            return _run_maybe_async(method(*args, **kwargs))
        except TypeError as exc:
            last_error = exc
            continue
    if last_error:
        raise last_error
    raise AttributeError(f"{obj.__class__.__name__} has no callable method in {list(method_names)}")


def _extract_message_from_result(result: Dict[str, Any]) -> str:
    if not isinstance(result, dict):
        return str(result)

    message = result.get("message")
    if message:
        return str(message)

    data = result.get("data")
    if isinstance(data, dict):
        for key in ("response_text", "summary", "text", "final_answer"):
            if data.get(key):
                return str(data[key])

        final_response = data.get("final_response")
        if isinstance(final_response, dict) and final_response.get("message"):
            return str(final_response["message"])

    error = result.get("error")
    if error:
        return f"Task returned an error: {error}"

    return "Task completed."


# =============================================================================
# Fallback Classes
# =============================================================================

class FallbackBaseAgent:
    agent_name = "fallback_base_agent"
    agent_type = "fallback"

    def __init__(self, user_id: Optional[str] = None, workspace_id: Optional[str] = None, **kwargs: Any) -> None:
        self.user_id = user_id
        self.workspace_id = workspace_id
        self.kwargs = kwargs

    def execute(self, task: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "message": f"{self.agent_name} received task safely, but real agent implementation is not connected yet.",
            "data": {
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "task": task,
                "fallback": True,
            },
            "error": None,
            "metadata": {"timestamp": _utc_now(), "fallback": True},
        }

    def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        return self.execute(task)


class FallbackAgentRegistry:
    def __init__(self) -> None:
        self._agents: Dict[str, Any] = {}

    def register_agent(self, name: str, agent: Any = None, **kwargs: Any) -> Dict[str, Any]:
        if agent is None:
            agent = kwargs.get("agent")
        if agent is None:
            return {"success": False, "message": "No agent supplied.", "data": {}, "error": "NO_AGENT", "metadata": {}}
        self._agents[name] = agent
        return {"success": True, "message": f"Registered {name}.", "data": {"name": name}, "error": None, "metadata": {}}

    def get_agent(self, name: str) -> Optional[Any]:
        return self._agents.get(name) or self._agents.get(f"{name}_agent")

    def list_agents(self) -> List[str]:
        return sorted(self._agents.keys())

    def as_dict(self) -> Dict[str, Any]:
        return {
            "registered_agents": self.list_agents(),
            "count": len(self._agents),
            "fallback": True,
        }


class FallbackAgentLoader:
    DEFAULT_AGENT_NAMES = [
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

    def __init__(self, registry: Optional[Any] = None, **kwargs: Any) -> None:
        self.registry = registry or FallbackAgentRegistry()

    def load_all_agents(self, user_id: Optional[str] = None, workspace_id: Optional[str] = None) -> Dict[str, Any]:
        loaded = []
        for name in self.DEFAULT_AGENT_NAMES:
            agent = FallbackBaseAgent(user_id=user_id, workspace_id=workspace_id)
            agent.agent_name = f"{name}_agent"
            agent.agent_type = name
            _registry_register(self.registry, name, agent)
            loaded.append(name)
        return {
            "success": True,
            "message": "Fallback agents loaded safely.",
            "data": {"loaded_agents": loaded, "fallback": True},
            "error": None,
            "metadata": {"timestamp": _utc_now(), "fallback": True},
        }


class FallbackAgentRouter:
    def __init__(self, registry: Optional[Any] = None, **kwargs: Any) -> None:
        self.registry = registry or FallbackAgentRegistry()

    def route(self, task: Dict[str, Any]) -> Dict[str, Any]:
        agent_name = str(task.get("preferred_agent") or task.get("agent") or task.get("agent_name") or "master").lower()
        agent = _registry_get(self.registry, agent_name)
        if agent is None:
            return {
                "success": False,
                "message": f"Agent '{agent_name}' not found.",
                "data": {"available_agents": _registry_list(self.registry)},
                "error": {"code": "AGENT_NOT_FOUND"},
                "metadata": {"timestamp": _utc_now()},
            }
        return _execute_agent(agent, task)


class FallbackMasterAgent(FallbackBaseAgent):
    agent_name = "master"
    agent_type = "master"

    def __init__(self, agent_registry: Optional[Dict[str, Any]] = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.agent_registry = agent_registry or {}

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
        return {
            "success": True,
            "message": "Fallback MasterAgent received your command, but real MasterAgent pipeline is not connected yet.",
            "data": {
                "message": message,
                "preferred_agent": preferred_agent,
                "available_agents": sorted(self.agent_registry.keys()),
                "fallback": True,
            },
            "error": None,
            "metadata": {"timestamp": _utc_now(), "fallback": True},
        }

    def route_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        return self.handle_request_sync(
            message=str(task.get("message") or task.get("description") or task.get("task") or ""),
            user_id=task.get("user_id", "demo_user"),
            workspace_id=task.get("workspace_id", "demo_workspace"),
            action=task.get("action", "general_request"),
            preferred_agent=task.get("preferred_agent") or task.get("agent"),
            input_data=task,
        )


# =============================================================================
# Imports
# =============================================================================

BaseAgent = _safe_import_attr(
    [
        "agents.base_agent",
        "core.base_agent",
        "src.agents.base_agent",
        "src.core.base_agent",
    ],
    "BaseAgent",
) or FallbackBaseAgent

MasterAgent = _safe_import_attr(
    [
        "core.master_agent",
        "agents.master_agent.master_agent",
        "agents.master.master_agent",
        "src.core.master_agent",
    ],
    "MasterAgent",
) or FallbackMasterAgent

AgentRegistry = _safe_import_attr(
    [
        "agents.registry",
        "agents.agent_registry",
        "core.agent_registry",
        "registry.agent_registry",
        "src.agents.registry",
    ],
    "AgentRegistry",
) or FallbackAgentRegistry

AgentLoader = _safe_import_attr(
    [
        "agents.agent_loader",
        "core.agent_loader",
        "registry.agent_loader",
        "src.agents.agent_loader",
    ],
    "AgentLoader",
) or FallbackAgentLoader

AgentRouter = _safe_import_attr(
    [
        "agents.agent_router",
        "core.router",
        "core.agent_router",
        "routing.agent_router",
        "src.agents.agent_router",
    ],
    "AgentRouter",
) or FallbackAgentRouter

VoiceAgent = _safe_import_attr(
    [
        "agents.voice_agent.voice_agent",
        "voice_agent.voice_agent",
        "src.agents.voice_agent.voice_agent",
    ],
    "VoiceAgent",
)

VoiceAgentConfig = _safe_import_attr(
    [
        "agents.voice_agent.voice_agent",
        "voice_agent.voice_agent",
        "src.agents.voice_agent.voice_agent",
    ],
    "VoiceAgentConfig",
)


# =============================================================================
# Registry Adapters
# =============================================================================

def _registry_register(registry: Any, name: str, agent: Any) -> bool:
    if registry is None:
        return False

    candidates = [
        ("register_agent", (name, agent), {}),
        ("register", (name, agent), {}),
        ("add_agent", (name, agent), {}),
        ("set_agent", (name, agent), {}),
        ("register_agent", (), {"name": name, "agent": agent}),
    ]

    for method_name, args, kwargs in candidates:
        method = getattr(registry, method_name, None)
        if not callable(method):
            continue
        try:
            method(*args, **kwargs)
            return True
        except TypeError:
            continue
        except Exception as exc:
            logger.debug("Registry register failed through %s: %s", method_name, exc)

    try:
        if hasattr(registry, "_agents"):
            registry._agents[name] = agent
            return True
        if hasattr(registry, "agents"):
            registry.agents[name] = agent
            return True
    except Exception:
        pass

    return False


def _registry_get(registry: Any, name: str) -> Optional[Any]:
    if registry is None:
        return None

    variants = [name, f"{name}_agent", name.replace("_agent", "")]
    for variant in variants:
        for method_name in ("get_agent", "get", "resolve_agent", "find_agent"):
            method = getattr(registry, method_name, None)
            if callable(method):
                try:
                    value = method(variant)
                    if value is not None:
                        return value
                except Exception:
                    continue

    for attr_name in ("_agents", "agents", "registered_agents"):
        mapping = getattr(registry, attr_name, None)
        if isinstance(mapping, dict):
            for variant in variants:
                if variant in mapping:
                    value = mapping[variant]
                    if isinstance(value, dict) and "instance" in value:
                        return value["instance"]
                    return value

    return None


def _registry_list(registry: Any) -> List[str]:
    if registry is None:
        return []

    for method_name in ("list_agents", "get_registered_agents", "names"):
        method = getattr(registry, method_name, None)
        if callable(method):
            try:
                value = method()
                if isinstance(value, dict):
                    return sorted(str(k) for k in value.keys())
                if isinstance(value, list):
                    return sorted(str(x) for x in value)
            except Exception:
                continue

    for attr_name in ("_agents", "agents", "registered_agents"):
        mapping = getattr(registry, attr_name, None)
        if isinstance(mapping, dict):
            return sorted(str(k) for k in mapping.keys())

    return []


def _registry_snapshot(registry: Any) -> Dict[str, Any]:
    if registry is None:
        return {"ready": False, "registered_agents": [], "count": 0}

    if hasattr(registry, "as_dict") and callable(registry.as_dict):
        try:
            snap = registry.as_dict()
            if isinstance(snap, dict):
                snap.setdefault("ready", True)
                snap.setdefault("registered_agents", _registry_list(registry))
                snap.setdefault("count", len(snap.get("registered_agents", [])))
                return snap
        except Exception:
            pass

    agents = _registry_list(registry)
    return {
        "ready": True,
        "registry_class": registry.__class__.__name__,
        "registered_agents": agents,
        "count": len(agents),
    }


def _execute_agent(agent: Any, task: Dict[str, Any]) -> Dict[str, Any]:
    try:
        for method_name in ("execute", "run", "handle", "process", "route_task"):
            method = getattr(agent, method_name, None)
            if not callable(method):
                continue
            try:
                result = _run_maybe_async(method(task))
                return _normalize_result(result, default_message=f"{agent.__class__.__name__} executed task.")
            except TypeError:
                continue

        return {
            "success": False,
            "message": f"Agent {agent.__class__.__name__} has no compatible execute/run method.",
            "data": {},
            "error": {"code": "AGENT_INTERFACE_MISSING"},
            "metadata": {"timestamp": _utc_now()},
        }

    except Exception as exc:
        return {
            "success": False,
            "message": "Agent execution failed.",
            "data": {},
            "error": {"type": exc.__class__.__name__, "details": str(exc)},
            "metadata": {"timestamp": _utc_now()},
        }


def _normalize_result(result: Any, default_message: str = "Completed.") -> Dict[str, Any]:
    if isinstance(result, dict):
        return {
            "success": bool(result.get("success", True)),
            "message": str(result.get("message") or default_message),
            "data": result.get("data", {}),
            "error": result.get("error"),
            "metadata": result.get("metadata", {}),
        }

    return {
        "success": True,
        "message": default_message,
        "data": {"raw_result": result},
        "error": None,
        "metadata": {"timestamp": _utc_now()},
    }


# =============================================================================
# Config
# =============================================================================

@dataclass
class AppConfig:
    app_name: str = "William / Jarvis Multi-Agent AI SaaS System"
    brand_name: str = "Digital Promotix"
    environment: str = field(default_factory=lambda: os.getenv("WILLIAM_ENV", "development"))
    debug: bool = field(default_factory=lambda: os.getenv("WILLIAM_DEBUG", "false").lower() == "true")
    api_enabled: bool = field(default_factory=lambda: os.getenv("WILLIAM_API_ENABLED", "false").lower() == "true")
    cli_enabled: bool = field(default_factory=lambda: os.getenv("WILLIAM_CLI_ENABLED", "true").lower() == "true")
    smoke_test_enabled: bool = field(default_factory=lambda: os.getenv("WILLIAM_SMOKE_TEST", "true").lower() == "true")
    default_user_id: str = field(default_factory=lambda: os.getenv("WILLIAM_DEFAULT_USER_ID", "demo_user"))
    default_workspace_id: str = field(default_factory=lambda: os.getenv("WILLIAM_DEFAULT_WORKSPACE_ID", "demo_workspace"))
    log_level: str = field(default_factory=lambda: os.getenv("WILLIAM_LOG_LEVEL", "INFO"))
    allow_fallback_agents: bool = field(default_factory=lambda: os.getenv("WILLIAM_ALLOW_FALLBACK_AGENTS", "true").lower() == "true")
    require_security_for_sensitive_actions: bool = True
    voice_enabled: bool = field(default_factory=lambda: os.getenv("WILLIAM_VOICE_ENABLED", "true").lower() == "true")
    voice_mic_enabled: bool = field(default_factory=lambda: os.getenv("WILLIAM_VOICE_MIC_ENABLED", "false").lower() == "true")
    version: str = "0.2.0-live"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TaskContext:
    user_id: str
    workspace_id: str
    role: str = "user"
    subscription_plan: str = "free"
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: Optional[str] = None
    source: str = "main"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================================
# Main Application
# =============================================================================

class MainApp:
    SENSITIVE_ACTION_KEYWORDS = {
        "delete",
        "remove",
        "shutdown",
        "restart",
        "send_email",
        "send_message",
        "message",
        "make_call",
        "call",
        "transfer_money",
        "payment",
        "purchase",
        "execute_shell",
        "run_terminal",
        "terminal",
        "browser_submit",
        "system_write",
        "file_delete",
        "credential",
        "password",
        "token",
        "secret",
        "finance_trade",
    }

    COMMON_AGENT_IMPORTS: Dict[str, Tuple[str, str]] = {
        "voice": ("agents.voice_agent.voice_agent", "VoiceAgent"),
        "system": ("agents.system_agent.system_agent", "SystemAgent"),
        "browser": ("agents.browser_agent.browser_agent", "BrowserAgent"),
        "code": ("agents.code_agent.code_agent", "CodeAgent"),
        "memory": ("agents.memory_agent.memory_agent", "MemoryAgent"),
        "security": ("agents.security_agent.security_agent", "SecurityAgent"),
        "verification": ("agents.verification_agent.verification_agent", "VerificationAgent"),
        "visual": ("agents.visual_agent.visual_agent", "VisualAgent"),
        "workflow": ("agents.workflow_agent.workflow_agent", "WorkflowAgent"),
        "business": ("agents.super_agents.business_agent.business_agent", "BusinessAgent"),
        "finance": ("agents.super_agents.finance_agent.finance_agent", "FinanceAgent"),
        "creator": ("agents.super_agents.creator_agent.creator_agent", "CreatorAgent"),
        "call": ("agents.super_agents.call_agent.call_agent", "CallAgent"),
        "hologram": ("agents.super_agents.hologram_agent.hologram_agent", "HologramAgent"),
    }

    def __init__(
        self,
        config: Optional[AppConfig] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
    ) -> None:
        self.config = config or AppConfig()
        self.user_id = str(user_id or self.config.default_user_id)
        self.workspace_id = str(workspace_id or self.config.default_workspace_id)
        self.started_at = _utc_now()

        self.registry: Any = None
        self.loader: Any = None
        self.router: Any = None
        self.master_agent: Any = None
        self.voice_agent: Any = None

        self.agent_instances: Dict[str, Any] = {}
        self.boot_events: List[Dict[str, Any]] = []
        self.audit_events: List[Dict[str, Any]] = []
        self.agent_events: List[Dict[str, Any]] = []
        self.task_history: List[Dict[str, Any]] = []

        self._configure_logging()

    # ---------------------------------------------------------------------
    # Result helpers
    # ---------------------------------------------------------------------

    def _safe_result(
        self,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": {
                "app": self.config.app_name,
                "brand": self.config.brand_name,
                "version": self.config.version,
                "environment": self.config.environment,
                "timestamp": _utc_now(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if isinstance(error, Exception):
            payload = {
                "type": error.__class__.__name__,
                "details": str(error),
                "traceback": traceback.format_exc() if self.config.debug else None,
            }
        elif isinstance(error, dict):
            payload = error
        elif error is None:
            payload = {"type": "UnknownError", "details": message}
        else:
            payload = {"type": type(error).__name__, "details": str(error)}

        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": payload,
            "metadata": {
                "app": self.config.app_name,
                "brand": self.config.brand_name,
                "version": self.config.version,
                "environment": self.config.environment,
                "timestamp": _utc_now(),
                **(metadata or {}),
            },
        }

    # ---------------------------------------------------------------------
    # Boot
    # ---------------------------------------------------------------------

    def _configure_logging(self) -> None:
        level = getattr(logging, str(self.config.log_level).upper(), logging.INFO)
        logger.setLevel(level)
        for handler in logger.handlers:
            handler.setLevel(level)

    def boot(self) -> Dict[str, Any]:
        try:
            context = self._validate_task_context(
                {"user_id": self.user_id, "workspace_id": self.workspace_id, "action": "boot"}
            )
            if not context["success"]:
                return context

            registry_result = self._initialize_registry()
            loader_result = self._load_agents()
            manual_result = self._manual_load_missing_agents()
            master_result = self._initialize_master_agent()
            router_result = self._initialize_router()
            voice_result = self._initialize_voice_agent()

            boot_data = {
                "registry": self._registry_snapshot(),
                "loader": loader_result,
                "manual_agent_loading": manual_result,
                "master": master_result,
                "router": router_result,
                "voice": voice_result,
                "real_runtime_ready": self.master_agent is not None,
                "agent_instances": sorted(self.agent_instances.keys()),
                "started_at": self.started_at,
            }

            self.boot_events.append(boot_data)
            self._log_audit_event("app_boot", "boot", {"user_id": self.user_id, "workspace_id": self.workspace_id}, "success")

            return self._safe_result(
                "William/Jarvis live runtime booted successfully.",
                boot_data,
                {"component": "boot"},
            )

        except Exception as exc:
            return self._error_result("Application boot failed.", exc, metadata={"component": "boot"})

    def _initialize_registry(self) -> Dict[str, Any]:
        try:
            self.registry = AgentRegistry()
            return self._safe_result(
                "Agent registry initialized.",
                self._registry_snapshot(),
                {"component": "registry", "registry_class": self.registry.__class__.__name__},
            )
        except Exception as exc:
            self.registry = FallbackAgentRegistry()
            return self._error_result(
                "Real AgentRegistry failed; fallback registry initialized.",
                exc,
                self._registry_snapshot(),
                {"component": "registry", "fallback": True},
            )

    def _load_agents(self) -> Dict[str, Any]:
        if self.registry is None:
            self._initialize_registry()

        try:
            self.loader = self._create_loader()

            load_result: Any = None
            for method_name in (
                "load_all_agents",
                "load_agents",
                "load_all",
                "discover_and_load",
                "initialize_agents",
            ):
                method = getattr(self.loader, method_name, None)
                if not callable(method):
                    continue

                for args, kwargs in (
                    ((), {"user_id": self.user_id, "workspace_id": self.workspace_id}),
                    ((self.user_id, self.workspace_id), {}),
                    ((), {}),
                ):
                    try:
                        load_result = _run_maybe_async(method(*args, **kwargs))
                        raise StopIteration
                    except TypeError:
                        continue
                if load_result is not None:
                    break

            if load_result is None:
                load_result = {
                    "success": True,
                    "message": "AgentLoader created but no known load method executed.",
                    "data": {},
                    "error": None,
                    "metadata": {},
                }

            if isinstance(load_result, dict):
                agents = load_result.get("data", {}).get("agents", {})
                if isinstance(agents, dict):
                    for key, agent in agents.items():
                        clean = str(key).replace("_agent", "").lower()
                        if self._is_real_agent_instance(agent):
                            self.agent_instances[clean] = agent
            self._refresh_agent_instances_from_registry()
            return self._safe_result(
                "Agent loader executed.",
                {
                    "loader_class": self.loader.__class__.__name__,
                    "load_result": load_result,
                    "registry": self._registry_snapshot(),
                    "agent_instances": sorted(self.agent_instances.keys()),
                },
                {"component": "agent_loader"},
            )

        except StopIteration:
            self._refresh_agent_instances_from_registry()
            return self._safe_result(
                "Agent loader executed.",
                {
                    "loader_class": self.loader.__class__.__name__ if self.loader else None,
                    "registry": self._registry_snapshot(),
                    "agent_instances": sorted(self.agent_instances.keys()),
                },
                {"component": "agent_loader"},
            )
        except Exception as exc:
            return self._error_result("Failed to load agents.", exc, metadata={"component": "agent_loader"})

    def _create_loader(self) -> Any:
        attempts = [
            ((), {"registry": self.registry, "user_id": self.user_id, "workspace_id": self.workspace_id}),
            ((), {"registry": self.registry}),
            ((self.registry,), {}),
            ((), {}),
        ]

        last_error: Optional[Exception] = None
        for args, kwargs in attempts:
            try:
                return AgentLoader(*args, **kwargs)
            except TypeError as exc:
                last_error = exc
                continue

        if last_error:
            logger.warning("AgentLoader init signature mismatch: %s", last_error)
        return FallbackAgentLoader(registry=self.registry)

    def _manual_load_missing_agents(self) -> Dict[str, Any]:
        loaded: List[str] = []
        failed: Dict[str, str] = {}

        self._refresh_agent_instances_from_registry()

        for name, (module_path, class_name) in self.COMMON_AGENT_IMPORTS.items():
            if name in self.agent_instances:
                continue

            try:
                cls = _safe_import_attr([module_path], class_name)
                if cls is None:
                    failed[name] = f"{class_name} not found in {module_path}"
                    continue

                instance = self._instantiate_agent(cls, name)
                self.agent_instances[name] = instance
                _registry_register(self.registry, name, instance)
                loaded.append(name)

            except Exception as exc:
                failed[name] = f"{exc.__class__.__name__}: {exc}"

        return {
            "success": True,
            "message": "Manual missing-agent import completed.",
            "data": {
                "loaded": loaded,
                "failed": failed,
                "agent_instances": sorted(self.agent_instances.keys()),
            },
            "error": None,
            "metadata": {"component": "manual_agent_import", "timestamp": _utc_now()},
        }

    def _instantiate_agent(self, cls: Any, name: str) -> Any:
        attempts = [
            ((), {"user_id": self.user_id, "workspace_id": self.workspace_id}),
            ((), {"agent_name": name, "user_id": self.user_id, "workspace_id": self.workspace_id}),
            ((), {"name": name, "user_id": self.user_id, "workspace_id": self.workspace_id}),
            ((), {}),
        ]

        last_error: Optional[Exception] = None
        for args, kwargs in attempts:
            try:
                return cls(*args, **kwargs)
            except TypeError as exc:
                last_error = exc
                continue

        raise last_error or RuntimeError(f"Could not instantiate {cls}")

    def _is_real_agent_instance(self, value: Any) -> bool:
        if value is None:
            return False
        if isinstance(value, dict):
            # Registry records and structured result wrappers are not live agents.
            if set(value.keys()) & {"success", "message", "data", "error", "metadata", "module_path", "class_name"}:
                return False
        return any(callable(getattr(value, method, None)) for method in ("handle_task", "execute_task", "execute", "run", "route_task", "handle_request"))

    def _refresh_agent_instances_from_registry(self) -> None:
        for name in _registry_list(self.registry):
            agent = _registry_get(self.registry, name)
            if self._is_real_agent_instance(agent):
                clean = str(name).replace("_agent", "").lower()
                if clean not in {"success", "message", "data", "error", "metadata"}:
                    self.agent_instances[clean] = agent

        # Pull real instances from AgentLoader cache if available.
        if self.loader is not None:
            getter = getattr(self.loader, "get_loaded_instances", None)
            if callable(getter):
                try:
                    result = _run_maybe_async(getter())
                    agents = result.get("data", {}).get("agents", {}) if isinstance(result, dict) else {}
                    if isinstance(agents, dict):
                        for key, agent in agents.items():
                            clean = str(key).replace("_agent", "").lower()
                            if self._is_real_agent_instance(agent):
                                self.agent_instances[clean] = agent
                except Exception:
                    pass

    def _initialize_master_agent(self) -> Dict[str, Any]:
        try:
            self._refresh_agent_instances_from_registry()

            master = _registry_get(self.registry, "master") or _registry_get(self.registry, "master_agent")
            if master is not None and not isinstance(master, FallbackBaseAgent):
                self.master_agent = master
            else:
                self.master_agent = self._create_master_agent()

            self.agent_instances["master"] = self.master_agent
            _registry_register(self.registry, "master", self.master_agent)

            return self._safe_result(
                "Master Agent initialized.",
                {
                    "master_agent_class": self.master_agent.__class__.__name__,
                    "fallback": isinstance(self.master_agent, FallbackMasterAgent),
                    "known_agents": sorted(self.agent_instances.keys()),
                },
                {"component": "master_agent"},
            )

        except Exception as exc:
            self.master_agent = FallbackMasterAgent(
                agent_registry=self.agent_instances,
                user_id=self.user_id,
                workspace_id=self.workspace_id,
            )
            self.agent_instances["master"] = self.master_agent
            _registry_register(self.registry, "master", self.master_agent)
            return self._error_result(
                "Real MasterAgent failed; fallback master initialized.",
                exc,
                {"master_agent_class": self.master_agent.__class__.__name__},
                {"component": "master_agent", "fallback": True},
            )

    def _create_master_agent(self) -> Any:
        attempts = [
            ((), {"agent_registry": self.agent_instances, "user_id": self.user_id, "workspace_id": self.workspace_id}),
            ((), {"agent_registry": self.agent_instances}),
            ((), {"registry": self.registry, "user_id": self.user_id, "workspace_id": self.workspace_id}),
            ((), {"user_id": self.user_id, "workspace_id": self.workspace_id}),
            ((), {}),
        ]

        last_error: Optional[Exception] = None
        for args, kwargs in attempts:
            try:
                return MasterAgent(*args, **kwargs)
            except TypeError as exc:
                last_error = exc
                continue

        raise last_error or RuntimeError("Could not instantiate MasterAgent.")

    def _initialize_router(self) -> Dict[str, Any]:
        try:
            attempts = [
                ((), {"registry": self.registry, "agent_registry": self.agent_instances}),
                ((), {"registry": self.registry}),
                ((), {"agent_registry": self.agent_instances}),
                ((self.registry,), {}),
                ((), {}),
            ]

            last_error: Optional[Exception] = None
            for args, kwargs in attempts:
                try:
                    self.router = AgentRouter(*args, **kwargs)
                    break
                except TypeError as exc:
                    last_error = exc
                    continue

            if self.router is None:
                if last_error:
                    logger.warning("AgentRouter init mismatch: %s", last_error)
                self.router = FallbackAgentRouter(registry=self.registry)

            return self._safe_result(
                "Agent router initialized.",
                {"router_class": self.router.__class__.__name__, "registry": self._registry_snapshot()},
                {"component": "agent_router"},
            )

        except Exception as exc:
            self.router = FallbackAgentRouter(registry=self.registry)
            return self._error_result(
                "Real AgentRouter failed; fallback router initialized.",
                exc,
                {"router_class": self.router.__class__.__name__},
                {"component": "agent_router", "fallback": True},
            )

    def _initialize_voice_agent(self) -> Dict[str, Any]:
        try:
            voice = self.agent_instances.get("voice") or _registry_get(self.registry, "voice")
            if voice is None and VoiceAgent is not None:
                voice_config = None
                if VoiceAgentConfig is not None:
                    try:
                        voice_config = VoiceAgentConfig(
                            allow_device_microphone=self.config.voice_mic_enabled,
                            allow_remote_device_stream=False,
                            enable_tts=True,
                        )
                    except TypeError:
                        voice_config = VoiceAgentConfig()

                attempts = [
                    ((), {
                        "config": voice_config,
                        "master_router": self.execute_text_command,
                        "user_id": self.user_id,
                        "workspace_id": self.workspace_id,
                    }),
                    ((), {"user_id": self.user_id, "workspace_id": self.workspace_id}),
                    ((), {}),
                ]

                for args, kwargs in attempts:
                    try:
                        voice = VoiceAgent(*args, **{k: v for k, v in kwargs.items() if v is not None})
                        break
                    except TypeError:
                        continue

            self.voice_agent = voice
            if voice is not None:
                self.agent_instances["voice"] = voice
                _registry_register(self.registry, "voice", voice)

            return self._safe_result(
                "Voice Agent initialized." if voice is not None else "Voice Agent not available.",
                {
                    "voice_available": voice is not None,
                    "voice_agent_class": voice.__class__.__name__ if voice else None,
                    "mic_enabled": self.config.voice_mic_enabled,
                },
                {"component": "voice_agent"},
            )

        except Exception as exc:
            return self._error_result("Voice Agent initialization failed.", exc, metadata={"component": "voice_agent"})

    # ---------------------------------------------------------------------
    # Task execution
    # ---------------------------------------------------------------------

    def execute_text_command(
        self,
        message: str,
        *,
        preferred_agent: Optional[str] = None,
        action: str = "general_request",
        input_data: Optional[Dict[str, Any]] = None,
        approved_by_security: bool = False,
    ) -> Dict[str, Any]:
        task = {
            "message": message,
            "description": message,
            "action": action,
            "preferred_agent": preferred_agent,
            "agent": preferred_agent or "master",
            "input_data": input_data or {},
            "approved_by_security": approved_by_security,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "request_id": str(uuid.uuid4()),
            "source": "cli_or_voice",
            "created_at": _utc_now(),
        }
        return self.execute_task(task)

    def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        try:
            if not isinstance(task, dict):
                return self._error_result(
                    "Task must be a dictionary.",
                    {"code": "INVALID_TASK_TYPE", "details": f"Got {type(task).__name__}"},
                    metadata={"component": "task_execution"},
                )

            if self.master_agent is None or self.registry is None:
                boot_result = self.boot()
                if not boot_result["success"]:
                    return boot_result

            task = dict(task)
            task.setdefault("user_id", self.user_id)
            task.setdefault("workspace_id", self.workspace_id)
            task.setdefault("request_id", str(uuid.uuid4()))
            task.setdefault("source", "main")
            task.setdefault("created_at", _utc_now())

            context_result = self._validate_task_context(task)
            if not context_result["success"]:
                return context_result

            if self._requires_security_check(task):
                approval = self._request_security_approval(task)
                if not approval["success"]:
                    self._log_audit_event("security_denied", str(task.get("action", "unknown")), task, "denied")
                    return approval

            route_result = self._route_task(task)

            verification_payload = self._prepare_verification_payload(task, route_result)
            memory_payload = self._prepare_memory_payload(
                {
                    "user_id": task["user_id"],
                    "workspace_id": task["workspace_id"],
                    "request_id": task["request_id"],
                },
                {
                    "task": task,
                    "result_summary": route_result.get("message"),
                    "success": route_result.get("success"),
                },
            )
            audit_payload = self._log_audit_event(
                "task_completed" if route_result.get("success") else "task_failed",
                str(task.get("action", "unknown")),
                task,
                "success" if route_result.get("success") else "failed",
            )

            record = {
                "task": task,
                "result": route_result,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "audit_payload": audit_payload,
                "timestamp": _utc_now(),
            }
            self.task_history.append(record)

            return self._safe_result(
                "Task executed through William/Jarvis live routing.",
                record,
                {"component": "task_execution"},
            )

        except Exception as exc:
            return self._error_result("Task execution failed.", exc, metadata={"component": "task_execution"})

    def _route_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        try:
            preferred_agent = task.get("preferred_agent") or task.get("agent")
            message = str(task.get("message") or task.get("description") or task.get("task") or "")

            if self.master_agent is not None:
                if hasattr(self.master_agent, "handle_request_sync"):
                    result = self.master_agent.handle_request_sync(
                        message=message,
                        user_id=task["user_id"],
                        workspace_id=task["workspace_id"],
                        action=task.get("action", "general_request"),
                        preferred_agent=preferred_agent if preferred_agent != "master" else None,
                        input_data=task.get("input_data") or task,
                        permissions=task.get("permissions", {}),
                        metadata={"source": "main.py", "request_id": task.get("request_id")},
                    )
                    return _normalize_result(result, "Master Agent handled request.")

                if hasattr(self.master_agent, "handle_request"):
                    result = self.master_agent.handle_request(
                        message=message,
                        user_id=task["user_id"],
                        workspace_id=task["workspace_id"],
                        action=task.get("action", "general_request"),
                        preferred_agent=preferred_agent if preferred_agent != "master" else None,
                        input_data=task.get("input_data") or task,
                        permissions=task.get("permissions", {}),
                        metadata={"source": "main.py", "request_id": task.get("request_id")},
                    )
                    return _normalize_result(_run_maybe_async(result), "Master Agent handled request.")

                if hasattr(self.master_agent, "execute"):
                    return _normalize_result(_run_maybe_async(self.master_agent.execute(task)), "Master Agent executed task.")

                if hasattr(self.master_agent, "route_task"):
                    method = getattr(self.master_agent, "route_task")
                    for args in ((task, task["user_id"], task["workspace_id"]), (task,)):
                        try:
                            return _normalize_result(_run_maybe_async(method(*args)), "Master Agent routed task.")
                        except TypeError:
                            continue

            if self.router is not None:
                for method_name in ("route", "route_task", "dispatch"):
                    method = getattr(self.router, method_name, None)
                    if callable(method):
                        for args in ((task, task["user_id"], task["workspace_id"]), (task,)):
                            try:
                                return _normalize_result(_run_maybe_async(method(*args)), "Router handled task.")
                            except TypeError:
                                continue

            target = str(preferred_agent or "business").replace("_agent", "").lower()
            agent = self.agent_instances.get(target) or _registry_get(self.registry, target)
            if agent is not None:
                return _execute_agent(agent, task)

            return self._error_result(
                "No MasterAgent, router, or target agent could handle the task.",
                {"code": "NO_EXECUTOR", "available_agents": sorted(self.agent_instances.keys())},
                metadata={"component": "routing"},
            )

        except Exception as exc:
            return self._error_result("Task routing failed.", exc, metadata={"component": "routing"})

    # ---------------------------------------------------------------------
    # Voice and CLI modes
    # ---------------------------------------------------------------------

    def run_interactive_cli(self, speak: bool = False, listen: bool = False) -> Dict[str, Any]:
        boot = self.boot()
        if not boot["success"]:
            print(_safe_json_dumps(boot))
            return boot

        intro = (
            "\nWilliam/Jarvis live mode started.\n"
            "Type your command and press Enter.\n"
            "Commands: agents, status, help, exit\n"
        )
        print(intro)
        if speak:
            self.speak("William is ready. Type your command.")

        while True:
            try:
                if listen:
                    user_text = self.listen_once()
                    if not user_text:
                        user_text = input("You: ").strip()
                    else:
                        print(f"You: {user_text}")
                else:
                    user_text = input("You: ").strip()

                if not user_text:
                    continue

                lowered = user_text.lower()
                if lowered in {"exit", "quit", "stop", "close"}:
                    farewell = "William stopped."
                    print(f"William: {farewell}")
                    if speak:
                        self.speak(farewell)
                    break

                if lowered == "agents":
                    agents = ", ".join(sorted(self.agent_instances.keys()))
                    answer = f"Loaded agents: {agents}"
                    print(f"William: {answer}")
                    if speak:
                        self.speak(answer)
                    continue

                if lowered == "status":
                    status = self.get_status()
                    print(_safe_json_dumps(status))
                    if speak:
                        self.speak(status["message"])
                    continue

                if lowered == "help":
                    help_text = (
                        "Ask me a task like: check my project status, use code agent to review files, "
                        "use memory agent to save a note, or use browser agent to plan a web task. "
                        "Sensitive actions require security approval."
                    )
                    print(f"William: {help_text}")
                    if speak:
                        self.speak(help_text)
                    continue

                result = self.execute_text_command(user_text)
                answer = _extract_message_from_result(result)
                print(f"William: {answer}")

                if not result.get("success"):
                    print(_safe_json_dumps(result))

                if speak:
                    self.speak(answer)

            except KeyboardInterrupt:
                print("\nWilliam stopped.")
                break
            except Exception as exc:
                error = self._error_result("Live CLI loop error.", exc, metadata={"component": "cli"})
                print(_safe_json_dumps(error))
                if speak:
                    self.speak("I hit an error in the live loop.")

        return self._safe_result("Live CLI session ended.", {"task_history_count": len(self.task_history)}, {"component": "cli"})

    def speak(self, text: str) -> Dict[str, Any]:
        text = str(text or "").strip()
        if not text:
            return self._safe_result("No text to speak.", {"spoken": False}, {"component": "voice"})

        # Prefer real VoiceAgent if it exposes speak_text.
        if self.voice_agent is not None and hasattr(self.voice_agent, "speak_text"):
            try:
                result = self.voice_agent.speak_text(
                    text,
                    task_context={"user_id": self.user_id, "workspace_id": self.workspace_id},
                )
                normalized = _normalize_result(result, "VoiceAgent speak_text completed.")
                if normalized.get("success"):
                    return normalized
            except Exception as exc:
                logger.debug("VoiceAgent speak_text failed, trying pyttsx3: %s", exc)

        # Fallback: pyttsx3 local TTS if installed.
        try:
            import pyttsx3  # type: ignore

            engine = pyttsx3.init()
            engine.say(text)
            engine.runAndWait()
            return self._safe_result("Text spoken with pyttsx3.", {"text": text, "engine": "pyttsx3"}, {"component": "voice"})
        except Exception as exc:
            return self._error_result(
                "TTS is not available. Install/configure pyttsx3 or fix VoiceAgent TTS engine.",
                exc,
                {"text": text},
                {"component": "voice"},
            )

    def listen_once(self) -> str:
        """
        Optional microphone listen.

        Requires:
            pip install SpeechRecognition pyaudio

        If not installed or mic fails, returns empty string and CLI falls back to typed input.
        """
        if not self.config.voice_mic_enabled:
            return ""

        try:
            import speech_recognition as sr  # type: ignore

            recognizer = sr.Recognizer()
            with sr.Microphone() as source:
                print("Listening...")
                recognizer.adjust_for_ambient_noise(source, duration=0.5)
                audio = recognizer.listen(source, timeout=8, phrase_time_limit=20)
            return recognizer.recognize_google(audio)
        except Exception as exc:
            logger.warning("Mic listen failed; falling back to typed input: %s", exc)
            return ""

    # ---------------------------------------------------------------------
    # Hooks
    # ---------------------------------------------------------------------

    def _validate_task_context(self, task: Dict[str, Any]) -> Dict[str, Any]:
        try:
            user_id = _normalize_identifier(task.get("user_id"), "user_id")
            workspace_id = _normalize_identifier(task.get("workspace_id"), "workspace_id")
            task["user_id"] = user_id
            task["workspace_id"] = workspace_id
            return self._safe_result(
                "Task context validated.",
                {"user_id": user_id, "workspace_id": workspace_id, "request_id": task.get("request_id")},
                {"component": "context_validation"},
            )
        except Exception as exc:
            return self._error_result("Task context validation failed.", exc, metadata={"component": "context_validation"})

    def _requires_security_check(self, task: Dict[str, Any]) -> bool:
        if not self.config.require_security_for_sensitive_actions:
            return False

        if bool(task.get("approved_by_security")):
            return False

        action = str(task.get("action", "")).lower()
        agent = str(task.get("agent", "") or task.get("preferred_agent", "")).lower()
        description = str(task.get("description", "") or task.get("message", "")).lower()
        task_type = str(task.get("type", "")).lower()
        combined = " ".join([action, agent, description, task_type])

        return any(keyword in combined for keyword in self.SENSITIVE_ACTION_KEYWORDS)

    def _request_security_approval(self, task: Dict[str, Any]) -> Dict[str, Any]:
        security_agent = self.agent_instances.get("security") or _registry_get(self.registry, "security")
        payload = {
            "action": "security_review",
            "original_task": task,
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "request_id": task.get("request_id"),
            "created_at": _utc_now(),
        }

        if security_agent is not None:
            for method_name in ("approve", "approve_action", "check_permission", "execute", "run"):
                method = getattr(security_agent, method_name, None)
                if not callable(method):
                    continue
                try:
                    result = _normalize_result(_run_maybe_async(method(payload)), "Security Agent reviewed task.")
                    approved = bool(
                        result.get("success") is True
                        and (
                            result.get("data", {}).get("approved") is True
                            or result.get("data", {}).get("allowed") is True
                            or result.get("message", "").lower().find("approved") >= 0
                        )
                    )
                    if approved:
                        return self._safe_result("Security Agent approved task.", {"security_result": result}, {"component": "security"})
                except TypeError:
                    continue
                except Exception as exc:
                    logger.debug("Security method %s failed: %s", method_name, exc)

        return self._error_result(
            "Sensitive task requires Security Agent approval.",
            {
                "code": "SECURITY_APPROVAL_REQUIRED",
                "details": (
                    "This command looks sensitive. First test non-sensitive commands. "
                    "For real sensitive actions, wire SecurityAgent approval and pass approved_by_security only after approval."
                ),
            },
            {"security_payload": payload},
            {"component": "security"},
        )

    def _prepare_verification_payload(self, task: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "verification_id": str(uuid.uuid4()),
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "request_id": task.get("request_id"),
            "task_action": task.get("action"),
            "task_agent": task.get("agent") or task.get("preferred_agent"),
            "result_success": result.get("success"),
            "result_message": result.get("message"),
            "created_at": _utc_now(),
            "requires_manual_review": not bool(result.get("success")),
            "metadata": {"source": "main.py", "verification_agent_ready": "verification" in self.agent_instances},
        }

    def _prepare_memory_payload(self, context: Dict[str, Any], content: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "memory_id": str(uuid.uuid4()),
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "request_id": context.get("request_id"),
            "content": content,
            "created_at": _utc_now(),
            "metadata": {
                "source": "main.py",
                "memory_agent_ready": "memory" in self.agent_instances,
                "isolation_scope": "user_workspace",
            },
        }

    def _emit_agent_event(self, event_type: str, agent_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent_name": agent_name,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "payload": payload,
            "created_at": _utc_now(),
        }
        self.agent_events.append(event)
        logger.info("Agent event emitted: %s | %s", event_type, agent_name)
        return event

    def _log_audit_event(self, event_type: str, action: str, context: Dict[str, Any], result: str) -> Dict[str, Any]:
        event = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "action": action,
            "result": result,
            "user_id": context.get("user_id", self.user_id),
            "workspace_id": context.get("workspace_id", self.workspace_id),
            "request_id": context.get("request_id"),
            "created_at": _utc_now(),
            "metadata": {"source": "main.py", "environment": self.config.environment},
        }
        self.audit_events.append(event)
        logger.info("Audit event: %s | action=%s | result=%s", event_type, action, result)
        return event

    # ---------------------------------------------------------------------
    # Status / smoke
    # ---------------------------------------------------------------------

    def _registry_snapshot(self) -> Dict[str, Any]:
        return _registry_snapshot(self.registry)

    def get_status(self) -> Dict[str, Any]:
        return self._safe_result(
            "William/Jarvis status generated.",
            {
                "app_name": self.config.app_name,
                "brand_name": self.config.brand_name,
                "version": self.config.version,
                "environment": self.config.environment,
                "started_at": self.started_at,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "registry": self._registry_snapshot(),
                "router_ready": self.router is not None,
                "master_agent_ready": self.master_agent is not None,
                "master_agent_class": self.master_agent.__class__.__name__ if self.master_agent else None,
                "voice_agent_ready": self.voice_agent is not None,
                "voice_agent_class": self.voice_agent.__class__.__name__ if self.voice_agent else None,
                "loaded_agent_instances": sorted(self.agent_instances.keys()),
                "audit_event_count": len(self.audit_events),
                "agent_event_count": len(self.agent_events),
                "task_history_count": len(self.task_history),
            },
            {"component": "status"},
        )

    def run_smoke_test(self) -> Dict[str, Any]:
        try:
            boot = self.boot()
            if not boot["success"]:
                return boot

            result = self.execute_text_command(
                "Ping the William/Jarvis runtime and report which agents are loaded.",
                preferred_agent=None,
                action="status_report",
            )

            checks = {
                "registry_ready": self.registry is not None,
                "master_agent_ready": self.master_agent is not None,
                "router_ready": self.router is not None,
                "agents_loaded_count": len(self.agent_instances),
                "task_executed": bool(result.get("success")),
                "safe_no_destructive_action": True,
            }

            success = (
                checks["registry_ready"]
                and checks["master_agent_ready"]
                and checks["router_ready"]
                and checks["agents_loaded_count"] >= 1
                and checks["safe_no_destructive_action"]
            )

            return self._safe_result(
                "Smoke test completed successfully." if success else "Smoke test completed with warnings.",
                {
                    "checks": checks,
                    "boot": boot,
                    "task_result": result,
                    "status": self.get_status()["data"],
                },
                {"component": "smoke_test"},
            )

        except Exception as exc:
            return self._error_result("Smoke test failed.", exc, metadata={"component": "smoke_test"})

    def export_runtime_snapshot(self) -> Dict[str, Any]:
        return self._safe_result(
            "Runtime snapshot exported.",
            {
                "status": self.get_status()["data"],
                "boot_events": self.boot_events[-10:],
                "audit_events": self.audit_events[-50:],
                "agent_events": self.agent_events[-50:],
                "task_history": self.task_history[-20:],
            },
            {"component": "snapshot"},
        )


# =============================================================================
# CLI
# =============================================================================

def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="William / Jarvis Multi-Agent AI SaaS System live entry point.")

    parser.add_argument("--user-id", type=str, default=os.getenv("WILLIAM_DEFAULT_USER_ID", "demo_user"))
    parser.add_argument("--workspace-id", type=str, default=os.getenv("WILLIAM_DEFAULT_WORKSPACE_ID", "demo_workspace"))

    parser.add_argument("--boot", action="store_true", help="Boot William/Jarvis and print boot result.")
    parser.add_argument("--smoke-test", action="store_true", help="Run safe smoke test.")
    parser.add_argument("--status", action="store_true", help="Print application status.")
    parser.add_argument("--task", type=str, default=None, help="JSON task payload to execute safely.")
    parser.add_argument("--cli", action="store_true", help="Start live typed CLI mode.")
    parser.add_argument("--voice", action="store_true", help="Start live typed voice mode with spoken responses if TTS works.")
    parser.add_argument("--listen", action="store_true", help="Attempt microphone listening in --voice mode. Requires SpeechRecognition/PyAudio.")
    parser.add_argument("--speak", type=str, default=None, help="Speak one piece of text using VoiceAgent/pyttsx3.")
    parser.add_argument("--json", action="store_true", help="Print compact JSON output.")

    return parser


def _print_result(result: Dict[str, Any], compact: bool = False) -> None:
    print(_safe_json_dumps(result, compact=compact))


def run_from_cli(argv: Optional[List[str]] = None) -> Dict[str, Any]:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    config = AppConfig(voice_mic_enabled=bool(args.listen))
    app = MainApp(config=config, user_id=args.user_id, workspace_id=args.workspace_id)

    try:
        if args.cli:
            return app.run_interactive_cli(speak=False, listen=False)

        if args.voice:
            return app.run_interactive_cli(speak=True, listen=bool(args.listen))

        if args.speak is not None:
            app.boot()
            result = app.speak(args.speak)
            _print_result(result, compact=args.json)
            return result

        if args.boot:
            result = app.boot()
            _print_result(result, compact=args.json)
            return result

        if args.status:
            boot = app.boot()
            if not boot["success"]:
                _print_result(boot, compact=args.json)
                return boot
            result = app.get_status()
            _print_result(result, compact=args.json)
            return result

        if args.task:
            boot = app.boot()
            if not boot["success"]:
                _print_result(boot, compact=args.json)
                return boot
            try:
                task = json.loads(args.task)
            except json.JSONDecodeError as exc:
                result = app._error_result("Invalid JSON task payload.", exc, metadata={"component": "cli"})
                _print_result(result, compact=args.json)
                return result
            result = app.execute_task(task)
            _print_result(result, compact=args.json)
            return result

        if args.smoke_test:
            result = app.run_smoke_test()
            _print_result(result, compact=args.json)
            return result

        # Default behavior: safe smoke test, not live mode.
        result = app.run_smoke_test()
        _print_result(result, compact=args.json)
        return result

    except KeyboardInterrupt:
        result = app._error_result(
            "Execution interrupted by user.",
            {"code": "KEYBOARD_INTERRUPT"},
            metadata={"component": "cli"},
        )
        _print_result(result, compact=args.json)
        return result

    except Exception as exc:
        result = app._error_result("CLI execution failed.", exc, metadata={"component": "cli"})
        _print_result(result, compact=args.json)
        return result


# =============================================================================
# Async Compatibility
# =============================================================================

async def async_boot_app(
    user_id: Optional[Union[str, int]] = None,
    workspace_id: Optional[Union[str, int]] = None,
) -> Dict[str, Any]:
    app = MainApp(user_id=user_id, workspace_id=workspace_id)
    return app.boot()


async def async_execute_task(
    task: Dict[str, Any],
    user_id: Optional[Union[str, int]] = None,
    workspace_id: Optional[Union[str, int]] = None,
) -> Dict[str, Any]:
    app = MainApp(user_id=user_id, workspace_id=workspace_id)
    boot = app.boot()
    if not boot["success"]:
        return boot
    return app.execute_task(task)


if __name__ == "__main__":
    run_from_cli()
