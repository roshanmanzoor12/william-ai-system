"""
William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

File: agents/system_agent/system_agent.py
Agent/Module: System Agent
Purpose:
    Main system controller for apps, files, OS commands, device settings,
    and automation with permission checks.

This file is designed to be:
    - Import-safe even when the full William/Jarvis project is not complete yet.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      and Master Agent routing.
    - Safe by default: destructive/system-level operations require permission
      approval through Security Agent style hooks.
    - SaaS-aware: every user/workspace action validates user_id/workspace_id.
    - Dashboard/API ready: structured JSON/dict results, metadata, audit events,
      memory payloads, verification payloads, and task history metadata.

Important:
    This SystemAgent does not blindly execute destructive commands.
    It prepares safe execution paths, enforces permission gates, and returns
    structured results for MasterAgent, SecurityAgent, VerificationAgent,
    MemoryAgent, dashboard/API, or a future queue worker.
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import enum
import json
import logging
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
    Union,
)


# ---------------------------------------------------------------------------
# Optional / safe imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early project stages
    class BaseAgent:  # type: ignore
        """
        Lightweight fallback BaseAgent so this file can import before the
        final William/Jarvis BaseAgent exists.

        The real BaseAgent should provide richer lifecycle, registry, routing,
        telemetry, memory, and event behavior. This fallback intentionally keeps
        only minimal structure.
        """

        agent_name: str = "base_agent"
        agent_type: str = "base"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_id = kwargs.get("agent_id", str(uuid.uuid4()))
            self.logger = logging.getLogger(self.__class__.__name__)

        async def handle_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent.handle_task is not implemented.")


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore


try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover
    MemoryAgent = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("william.system_agent")
if not LOGGER.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
        )
    )
    LOGGER.addHandler(handler)
LOGGER.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Enums and data structures
# ---------------------------------------------------------------------------

class SystemAction(str, enum.Enum):
    """
    Supported high-level System Agent actions.

    These names are intentionally stable for MasterAgent/Router/API usage.
    """

    GET_SYSTEM_INFO = "get_system_info"
    OPEN_APP = "open_app"
    CLOSE_APP = "close_app"
    LIST_FILES = "list_files"
    READ_FILE = "read_file"
    WRITE_FILE = "write_file"
    DELETE_FILE = "delete_file"
    COPY_FILE = "copy_file"
    MOVE_FILE = "move_file"
    CREATE_FOLDER = "create_folder"
    RUN_COMMAND = "run_command"
    GET_DEVICE_STATUS = "get_device_status"
    SET_DEVICE_SETTING = "set_device_setting"
    CREATE_AUTOMATION = "create_automation"
    RUN_AUTOMATION = "run_automation"
    STOP_AUTOMATION = "stop_automation"
    HEALTH_CHECK = "health_check"


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PermissionDecision(str, enum.Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"


@dataclasses.dataclass(frozen=True)
class SystemAgentConfig:
    """
    Runtime safety/configuration for SystemAgent.

    root_workspace_dir:
        Base directory for user/workspace file operations. Files outside this
        directory are blocked unless explicitly allowed and approved.

    allow_real_execution:
        If False, OS commands/app actions are returned as safe dry-runs.
        In production, set this through environment/config only after Security
        Agent approval controls are connected.

    allow_file_writes:
        Enables write/copy/move/delete folder/file operations inside approved
        workspace paths.

    max_command_timeout_seconds:
        Upper timeout for shell commands.

    max_file_read_bytes:
        Prevents reading huge files into memory.

    audit_enabled:
        Enables local in-memory audit events, and allows future dashboard/API
        forwarding.
    """

    root_workspace_dir: Path = Path("workspace_data")
    allow_real_execution: bool = False
    allow_file_writes: bool = True
    allow_destructive_actions: bool = False
    max_command_timeout_seconds: int = 30
    max_file_read_bytes: int = 512_000
    audit_enabled: bool = True
    strict_workspace_paths: bool = True
    allowed_command_prefixes: Tuple[str, ...] = (
        "python",
        "python3",
        "pip",
        "pip3",
        "node",
        "npm",
        "pnpm",
        "yarn",
        "git",
        "ls",
        "dir",
        "pwd",
        "whoami",
        "echo",
    )
    blocked_command_patterns: Tuple[str, ...] = (
        r"\brm\s+-rf\b",
        r"\bdel\s+/[fsq]\b",
        r"\bformat\b",
        r"\bshutdown\b",
        r"\breboot\b",
        r"\bmkfs\b",
        r"\bdd\s+if=",
        r":\(\)\s*\{\s*:\|:&\s*\};:",
        r"\breg\s+delete\b",
        r"\bnet\s+user\b",
        r"\bchmod\s+777\b",
        r"\bchown\s+-R\b",
        r"\bcurl\b.*\|\s*(sh|bash)",
        r"\bwget\b.*\|\s*(sh|bash)",
    )


@dataclasses.dataclass
class TaskContext:
    """
    Normalized context for all user/workspace-specific executions.
    """

    user_id: str
    workspace_id: str
    request_id: str
    actor: str = "user"
    role: Optional[str] = None
    subscription: Optional[str] = None
    permissions: Optional[Mapping[str, Any]] = None
    metadata: Optional[Mapping[str, Any]] = None


@dataclasses.dataclass
class PermissionRequest:
    """
    Payload sent to or prepared for SecurityAgent approval.
    """

    action: str
    risk_level: RiskLevel
    user_id: str
    workspace_id: str
    reason: str
    resource: Optional[str] = None
    command: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclasses.dataclass
class AutomationRecord:
    """
    In-memory automation definition.

    Future versions can persist this in DB with user/workspace isolation.
    """

    automation_id: str
    user_id: str
    workspace_id: str
    name: str
    action: str
    payload: Dict[str, Any]
    enabled: bool = True
    created_at: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_run_at: Optional[str] = None


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _coerce_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value)


def _safe_json(data: Any) -> Any:
    """
    Make result metadata JSON-serializable.
    """

    try:
        json.dumps(data)
        return data
    except Exception:
        if dataclasses.is_dataclass(data):
            return dataclasses.asdict(data)
        if isinstance(data, Path):
            return str(data)
        if isinstance(data, Mapping):
            return {str(k): _safe_json(v) for k, v in data.items()}
        if isinstance(data, (list, tuple, set)):
            return [_safe_json(v) for v in data]
        return str(data)


def _looks_like_path_traversal(path_text: str) -> bool:
    return ".." in Path(path_text).parts


def _normalize_action(action: Any) -> str:
    if isinstance(action, SystemAction):
        return action.value
    return str(action or "").strip().lower()


def _first_command_token(command: str) -> str:
    with contextlib.suppress(Exception):
        parts = shlex.split(command, posix=os.name != "nt")
        if parts:
            return Path(parts[0]).name.lower()
    return command.strip().split(" ")[0].strip().lower()


def _is_windows() -> bool:
    return platform.system().lower() == "windows"


def _is_macos() -> bool:
    return platform.system().lower() == "darwin"


def _is_linux() -> bool:
    return platform.system().lower() == "linux"


# ---------------------------------------------------------------------------
# SystemAgent
# ---------------------------------------------------------------------------

class SystemAgent(BaseAgent):
    """
    Main System Agent controller.

    Public responsibilities:
        - Validate user/workspace task context.
        - Route system-level actions from MasterAgent/AgentRouter.
        - Protect sensitive actions through SecurityAgent-style checks.
        - Safely manage workspace files.
        - Prepare app/OS/device automation operations.
        - Emit audit, memory, verification, and dashboard-compatible events.

    Integration points:
        MasterAgent:
            Calls handle_task() with a structured task.
        SecurityAgent:
            Used by _request_security_approval() when available.
        VerificationAgent:
            Receives or can consume _prepare_verification_payload().
        MemoryAgent:
            Receives or can consume _prepare_memory_payload().
        Dashboard/API:
            Can consume structured results and emitted audit events.
        Registry/Loader:
            Uses class metadata and get_capabilities().
    """

    agent_name = "system_agent"
    agent_type = "system"
    version = "1.0.0"

    def __init__(
        self,
        config: Optional[SystemAgentConfig] = None,
        security_agent: Any = None,
        memory_agent: Any = None,
        verification_agent: Any = None,
        event_sink: Optional[Callable[[Dict[str, Any]], Any]] = None,
        audit_sink: Optional[Callable[[Dict[str, Any]], Any]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)

        self.config = config or self._config_from_env()
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_sink = event_sink
        self.audit_sink = audit_sink

        self._audit_events: List[Dict[str, Any]] = []
        self._automation_records: Dict[str, AutomationRecord] = {}
        self._task_history: List[Dict[str, Any]] = []

        self.config.root_workspace_dir.mkdir(parents=True, exist_ok=True)

        self.logger = LOGGER
        self.logger.info("SystemAgent initialized | root=%s | real_execution=%s",
                         self.config.root_workspace_dir,
                         self.config.allow_real_execution)

    # ------------------------------------------------------------------
    # Metadata / registry compatibility
    # ------------------------------------------------------------------

    @classmethod
    def get_agent_metadata(cls) -> Dict[str, Any]:
        return {
            "agent_name": cls.agent_name,
            "agent_type": cls.agent_type,
            "version": cls.version,
            "description": (
                "Main system controller for apps, files, OS commands, "
                "device settings, and automation with permission checks."
            ),
            "safe_import": True,
            "requires_context": ["user_id", "workspace_id"],
            "compatible_with": [
                "BaseAgent",
                "AgentRegistry",
                "AgentLoader",
                "AgentRouter",
                "MasterAgent",
                "SecurityAgent",
                "MemoryAgent",
                "VerificationAgent",
                "Dashboard/API",
            ],
        }

    @classmethod
    def get_capabilities(cls) -> Dict[str, Any]:
        return {
            "actions": [action.value for action in SystemAction],
            "supports_user_workspace_isolation": True,
            "supports_security_approval": True,
            "supports_audit_logs": True,
            "supports_memory_payload": True,
            "supports_verification_payload": True,
            "supports_dry_run": True,
            "file_operations": [
                "list_files",
                "read_file",
                "write_file",
                "delete_file",
                "copy_file",
                "move_file",
                "create_folder",
            ],
            "system_operations": [
                "get_system_info",
                "open_app",
                "close_app",
                "run_command",
                "get_device_status",
                "set_device_setting",
            ],
            "automation_operations": [
                "create_automation",
                "run_automation",
                "stop_automation",
            ],
        }

    @staticmethod
    def _config_from_env() -> SystemAgentConfig:
        root = Path(os.getenv("WILLIAM_WORKSPACE_ROOT", "workspace_data"))
        allow_real = os.getenv("WILLIAM_SYSTEM_ALLOW_REAL_EXECUTION", "false").lower() in {
            "1", "true", "yes", "on"
        }
        allow_writes = os.getenv("WILLIAM_SYSTEM_ALLOW_FILE_WRITES", "true").lower() in {
            "1", "true", "yes", "on"
        }
        allow_destructive = os.getenv("WILLIAM_SYSTEM_ALLOW_DESTRUCTIVE", "false").lower() in {
            "1", "true", "yes", "on"
        }

        timeout_raw = os.getenv("WILLIAM_SYSTEM_COMMAND_TIMEOUT", "30")
        read_bytes_raw = os.getenv("WILLIAM_SYSTEM_MAX_FILE_READ_BYTES", "512000")

        with contextlib.suppress(Exception):
            timeout = int(timeout_raw)
        if "timeout" not in locals():
            timeout = 30

        with contextlib.suppress(Exception):
            max_read = int(read_bytes_raw)
        if "max_read" not in locals():
            max_read = 512_000

        return SystemAgentConfig(
            root_workspace_dir=root,
            allow_real_execution=allow_real,
            allow_file_writes=allow_writes,
            allow_destructive_actions=allow_destructive,
            max_command_timeout_seconds=max(1, min(timeout, 300)),
            max_file_read_bytes=max(1024, min(max_read, 25_000_000)),
        )

    # ------------------------------------------------------------------
    # Main routing
    # ------------------------------------------------------------------

    async def handle_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Main entrypoint for MasterAgent / AgentRouter.

        Expected task shape:
            {
                "action": "read_file",
                "user_id": "user_123",
                "workspace_id": "workspace_456",
                "payload": {...},
                "metadata": {...}
            }

        Returns:
            Structured dict with success, message, data, error, metadata.
        """

        started_at = time.time()
        request_id = _coerce_str(task.get("request_id"), str(uuid.uuid4()))
        action = _normalize_action(task.get("action"))

        context_result = self._validate_task_context(task, request_id=request_id)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]["context"]

        await self._emit_agent_event(
            "system_task_started",
            context=context,
            metadata={
                "action": action,
                "request_id": request_id,
                "payload_keys": list((task.get("payload") or {}).keys()),
            },
        )

        try:
            result = await self._dispatch_action(action, task, context)
        except Exception as exc:
            result = self._error_result(
                message="SystemAgent task failed.",
                error=exc,
                context=context,
                metadata={"action": action, "request_id": request_id},
            )

        duration_ms = int((time.time() - started_at) * 1000)

        result.setdefault("metadata", {})
        result["metadata"].update(
            {
                "agent": self.agent_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "action": action,
                "request_id": request_id,
                "duration_ms": duration_ms,
                "timestamp": _utc_now(),
            }
        )

        verification_payload = self._prepare_verification_payload(
            context=context,
            action=action,
            result=result,
        )
        memory_payload = self._prepare_memory_payload(
            context=context,
            action=action,
            result=result,
        )

        result["metadata"]["verification_payload"] = verification_payload
        result["metadata"]["memory_payload"] = memory_payload

        self._task_history.append(
            {
                "request_id": request_id,
                "action": action,
                "success": bool(result.get("success")),
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "duration_ms": duration_ms,
                "created_at": _utc_now(),
            }
        )

        await self._log_audit_event(
            event_type="system_task_completed",
            context=context,
            action=action,
            success=bool(result.get("success")),
            metadata={
                "request_id": request_id,
                "duration_ms": duration_ms,
                "message": result.get("message"),
                "error": result.get("error"),
            },
        )

        await self._emit_agent_event(
            "system_task_completed",
            context=context,
            metadata={
                "action": action,
                "request_id": request_id,
                "success": bool(result.get("success")),
                "duration_ms": duration_ms,
            },
        )

        return result

    async def _dispatch_action(
        self,
        action: str,
        task: Mapping[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        payload = dict(task.get("payload") or {})

        dispatch: Dict[str, Callable[[Dict[str, Any], TaskContext], Awaitable[Dict[str, Any]]]] = {
            SystemAction.HEALTH_CHECK.value: self.health_check,
            SystemAction.GET_SYSTEM_INFO.value: self.get_system_info,
            SystemAction.OPEN_APP.value: self.open_app,
            SystemAction.CLOSE_APP.value: self.close_app,
            SystemAction.LIST_FILES.value: self.list_files,
            SystemAction.READ_FILE.value: self.read_file,
            SystemAction.WRITE_FILE.value: self.write_file,
            SystemAction.DELETE_FILE.value: self.delete_file,
            SystemAction.COPY_FILE.value: self.copy_file,
            SystemAction.MOVE_FILE.value: self.move_file,
            SystemAction.CREATE_FOLDER.value: self.create_folder,
            SystemAction.RUN_COMMAND.value: self.run_command,
            SystemAction.GET_DEVICE_STATUS.value: self.get_device_status,
            SystemAction.SET_DEVICE_SETTING.value: self.set_device_setting,
            SystemAction.CREATE_AUTOMATION.value: self.create_automation,
            SystemAction.RUN_AUTOMATION.value: self.run_automation,
            SystemAction.STOP_AUTOMATION.value: self.stop_automation,
        }

        handler = dispatch.get(action)
        if handler is None:
            return self._error_result(
                message=f"Unsupported SystemAgent action: {action}",
                error="unsupported_action",
                context=context,
                metadata={"allowed_actions": list(dispatch.keys())},
            )

        if self._requires_security_check(action=action, payload=payload):
            approval = await self._request_security_approval(
                PermissionRequest(
                    action=action,
                    risk_level=self._classify_risk(action, payload),
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    reason=f"SystemAgent action requires permission check: {action}",
                    resource=_coerce_str(payload.get("path") or payload.get("target") or ""),
                    command=_coerce_str(payload.get("command") or ""),
                    metadata={"payload": self._redact_sensitive_payload(payload)},
                )
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied or required before execution.",
                    error=approval.get("reason") or "security_approval_required",
                    context=context,
                    metadata={
                        "action": action,
                        "security": approval,
                    },
                )

        return await handler(payload, context)

    # ------------------------------------------------------------------
    # Context and safety hooks required by prompt
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        task: Mapping[str, Any],
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.

        Required for every user-specific operation.
        """

        user_id = _coerce_str(task.get("user_id") or task.get("tenant_user_id")).strip()
        workspace_id = _coerce_str(task.get("workspace_id") or task.get("tenant_workspace_id")).strip()

        if not user_id:
            return self._error_result(
                message="Missing required user_id.",
                error="missing_user_id",
                metadata={"request_id": request_id},
            )
        if not workspace_id:
            return self._error_result(
                message="Missing required workspace_id.",
                error="missing_workspace_id",
                metadata={"request_id": request_id},
            )

        if not re.match(r"^[a-zA-Z0-9_\-:.@]+$", user_id):
            return self._error_result(
                message="Invalid user_id format.",
                error="invalid_user_id",
                metadata={"request_id": request_id},
            )

        if not re.match(r"^[a-zA-Z0-9_\-:.@]+$", workspace_id):
            return self._error_result(
                message="Invalid workspace_id format.",
                error="invalid_workspace_id",
                metadata={"request_id": request_id},
            )

        context = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            request_id=request_id or str(uuid.uuid4()),
            actor=_coerce_str(task.get("actor"), "user"),
            role=task.get("role"),
            subscription=task.get("subscription"),
            permissions=task.get("permissions") or {},
            metadata=task.get("metadata") or {},
        )

        # Deliberately NOT built via self._safe_result(): that helper routes
        # data through _safe_json() for JSON-safety, which -- since TaskContext
        # is a dataclass -- silently converts this live `context` object into
        # a plain dict via dataclasses.asdict(). Callers (handle_task) need the
        # real TaskContext instance back (context.user_id attribute access,
        # _dispatch_action's TaskContext-typed parameter), not a JSON-safe copy.
        return {
            "success": True,
            "message": "Task context validated.",
            "data": {"context": context},
            "error": None,
            "metadata": {"request_id": context.request_id},
        }

    def _requires_security_check(self, action: str, payload: Optional[Mapping[str, Any]] = None) -> bool:
        """
        Decide if SecurityAgent approval is required.

        Sensitive actions are gated even in dry-run mode so dashboard/API can
        display permission state correctly.
        """

        payload = payload or {}

        high_risk_actions = {
            SystemAction.OPEN_APP.value,
            SystemAction.CLOSE_APP.value,
            SystemAction.WRITE_FILE.value,
            SystemAction.DELETE_FILE.value,
            SystemAction.COPY_FILE.value,
            SystemAction.MOVE_FILE.value,
            SystemAction.CREATE_FOLDER.value,
            SystemAction.RUN_COMMAND.value,
            SystemAction.SET_DEVICE_SETTING.value,
            SystemAction.CREATE_AUTOMATION.value,
            SystemAction.RUN_AUTOMATION.value,
            SystemAction.STOP_AUTOMATION.value,
        }

        if action in high_risk_actions:
            return True

        command = _coerce_str(payload.get("command"))
        if command and self._is_command_blocked(command):
            return True

        return False

    async def _request_security_approval(self, permission_request: PermissionRequest) -> Dict[str, Any]:
        """
        Ask SecurityAgent for approval if available.

        If no SecurityAgent is connected:
            - Low-risk operations are allowed.
            - Medium/high/critical operations require explicit permission flags.
        """

        request_payload = dataclasses.asdict(permission_request)

        if self.security_agent is not None:
            for method_name in ("approve_action", "check_permission", "handle_permission_request"):
                method = getattr(self.security_agent, method_name, None)
                if callable(method):
                    try:
                        response = method(request_payload)
                        if asyncio.iscoroutine(response):
                            response = await response
                        return self._normalize_security_response(response)
                    except Exception as exc:
                        return {
                            "approved": False,
                            "reason": f"SecurityAgent approval failed: {exc}",
                            "source": "security_agent_error",
                        }

        risk = permission_request.risk_level
        permissions = permission_request.metadata or {}
        payload = permissions.get("payload") or {}

        explicit_approval = bool(
            payload.get("approved")
            or payload.get("security_approved")
            or payload.get("allow_sensitive_action")
        )

        if risk == RiskLevel.LOW:
            return {
                "approved": True,
                "reason": "Low-risk action approved by fallback permission policy.",
                "source": "fallback_policy",
                "risk_level": risk.value,
            }

        if explicit_approval:
            return {
                "approved": True,
                "reason": "Explicit task-level security approval flag provided.",
                "source": "task_payload",
                "risk_level": risk.value,
            }

        return {
            "approved": False,
            "reason": (
                f"{risk.value} risk action requires SecurityAgent approval "
                "or explicit security_approved flag."
            ),
            "source": "fallback_policy",
            "risk_level": risk.value,
        }

    def _prepare_verification_payload(
        self,
        context: TaskContext,
        action: str,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Build VerificationAgent-compatible payload for completed actions.
        """

        return {
            "verification_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "data_summary": self._summarize_data(result.get("data")),
            "error": result.get("error"),
            "created_at": _utc_now(),
            "checks": {
                "context_validated": True,
                "workspace_isolated": True,
                "structured_result": True,
                "security_gate_checked": self._requires_security_check(action, {}),
            },
        }

    def _prepare_memory_payload(
        self,
        context: TaskContext,
        action: str,
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Build MemoryAgent-compatible payload.

        This intentionally avoids storing sensitive content like full file bodies
        or command output unless future MemoryAgent policy explicitly allows it.
        """

        return {
            "memory_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "action": action,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "created_at": _utc_now(),
            "safe_to_store": True,
            "sensitivity": "low",
            "summary": {
                "action": action,
                "status": "success" if result.get("success") else "failed",
                "error": result.get("error"),
            },
        }

    async def _emit_agent_event(
        self,
        event_type: str,
        context: Optional[TaskContext] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit event for Dashboard/API, MasterAgent telemetry, or future event bus.
        """

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "timestamp": _utc_now(),
            "metadata": _safe_json(dict(metadata or {})),
        }

        if context is not None:
            event.update(
                {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                }
            )

        if self.event_sink:
            try:
                response = self.event_sink(event)
                if asyncio.iscoroutine(response):
                    await response
            except Exception as exc:
                self.logger.warning("Event sink failed: %s", exc)

    async def _log_audit_event(
        self,
        event_type: str,
        context: TaskContext,
        action: str,
        success: bool,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Store/forward audit logs with user/workspace isolation.
        """

        if not self.config.audit_enabled:
            return

        event = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "action": action,
            "success": success,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "timestamp": _utc_now(),
            "metadata": _safe_json(dict(metadata or {})),
        }

        self._audit_events.append(event)

        if self.audit_sink:
            try:
                response = self.audit_sink(event)
                if asyncio.iscoroutine(response):
                    await response
            except Exception as exc:
                self.logger.warning("Audit sink failed: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": message,
            "data": _safe_json(dict(data or {})),
            "error": None,
            "metadata": _safe_json(dict(metadata or {})),
        }

    def _error_result(
        self,
        message: str,
        error: Any,
        context: Optional[TaskContext] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        error_text = str(error)
        payload: Dict[str, Any] = {
            "success": False,
            "message": message,
            "data": {},
            "error": error_text,
            "metadata": _safe_json(dict(metadata or {})),
        }
        if context is not None:
            payload["metadata"].update(
                {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                }
            )
        return payload

    # ------------------------------------------------------------------
    # Core actions
    # ------------------------------------------------------------------

    async def health_check(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        return self._safe_result(
            message="SystemAgent is healthy.",
            data={
                "agent": self.agent_name,
                "version": self.version,
                "root_workspace_dir": str(self.config.root_workspace_dir.resolve()),
                "allow_real_execution": self.config.allow_real_execution,
                "allow_file_writes": self.config.allow_file_writes,
                "allow_destructive_actions": self.config.allow_destructive_actions,
                "platform": platform.platform(),
                "python": sys.version,
            },
            metadata={"context": dataclasses.asdict(context)},
        )

    async def get_system_info(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        """
        Return safe system information for dashboard display.

        Does not include secrets, environment variable values, or private paths
        outside configured workspace root.
        """

        disk = shutil.disk_usage(str(self.config.root_workspace_dir.resolve()))
        data = {
            "platform": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "python_version": platform.python_version(),
            },
            "workspace": {
                "root": str(self.config.root_workspace_dir.resolve()),
                "exists": self.config.root_workspace_dir.exists(),
            },
            "disk_workspace_root": {
                "total": disk.total,
                "used": disk.used,
                "free": disk.free,
            },
            "process": {
                "pid": os.getpid(),
                "cwd": str(Path.cwd()),
            },
            "security": {
                "real_execution_enabled": self.config.allow_real_execution,
                "file_writes_enabled": self.config.allow_file_writes,
                "destructive_actions_enabled": self.config.allow_destructive_actions,
                "strict_workspace_paths": self.config.strict_workspace_paths,
            },
        }
        return self._safe_result("System information retrieved.", data=data)

    async def open_app(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        """
        Open an application by app name/path.

        Safe default:
            If allow_real_execution is False, returns a dry-run result.
        """

        app = _coerce_str(payload.get("app") or payload.get("name") or payload.get("path")).strip()
        args = payload.get("args") or []

        if not app:
            return self._error_result("Missing app name/path.", "missing_app", context)

        command = self._build_open_app_command(app, args=args)
        if command is None:
            return self._error_result(
                "Could not build app open command for this platform.",
                "unsupported_platform_or_app",
                context,
                metadata={"app": app},
            )

        if not self.config.allow_real_execution:
            return self._safe_result(
                "App open prepared as dry-run. Real execution is disabled.",
                data={"app": app, "command": command, "dry_run": True},
            )

        return await self._execute_subprocess_command(
            command=command,
            context=context,
            shell=isinstance(command, str),
            timeout=payload.get("timeout"),
            action=SystemAction.OPEN_APP.value,
        )

    async def close_app(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        """
        Close an application/process.

        This is high-risk. Real execution requires SecurityAgent approval and
        allow_real_execution=True.
        """

        app = _coerce_str(payload.get("app") or payload.get("name") or payload.get("process")).strip()
        if not app:
            return self._error_result("Missing app/process name.", "missing_app", context)

        command = self._build_close_app_command(app)
        if command is None:
            return self._error_result(
                "Could not build app close command for this platform.",
                "unsupported_platform_or_app",
                context,
                metadata={"app": app},
            )

        if not self.config.allow_real_execution:
            return self._safe_result(
                "App close prepared as dry-run. Real execution is disabled.",
                data={"app": app, "command": command, "dry_run": True},
            )

        return await self._execute_subprocess_command(
            command=command,
            context=context,
            shell=isinstance(command, str),
            timeout=payload.get("timeout"),
            action=SystemAction.CLOSE_APP.value,
        )

    async def list_files(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        folder = _coerce_str(payload.get("path") or ".")
        recursive = bool(payload.get("recursive", False))
        include_hidden = bool(payload.get("include_hidden", False))
        limit = int(payload.get("limit") or 200)

        resolved = self._resolve_workspace_path(context, folder, must_exist=True)
        if not resolved["success"]:
            return resolved

        path = Path(resolved["data"]["path"])
        if not path.is_dir():
            return self._error_result("Path is not a folder.", "not_a_folder", context, {"path": str(path)})

        items: List[Dict[str, Any]] = []
        iterator: Iterable[Path] = path.rglob("*") if recursive else path.iterdir()

        for item in iterator:
            if len(items) >= limit:
                break
            if not include_hidden and item.name.startswith("."):
                continue
            with contextlib.suppress(OSError):
                stat = item.stat()
                items.append(
                    {
                        "name": item.name,
                        "path": str(item),
                        "relative_path": str(item.relative_to(self._workspace_root_for_context(context))),
                        "type": "folder" if item.is_dir() else "file",
                        "size": stat.st_size,
                        "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                    }
                )

        return self._safe_result(
            "Files listed successfully.",
            data={
                "path": str(path),
                "recursive": recursive,
                "count": len(items),
                "limit": limit,
                "items": items,
            },
        )

    async def read_file(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        file_path = _coerce_str(payload.get("path"))
        encoding = _coerce_str(payload.get("encoding"), "utf-8")
        as_bytes = bool(payload.get("as_bytes", False))

        if not file_path:
            return self._error_result("Missing file path.", "missing_path", context)

        resolved = self._resolve_workspace_path(context, file_path, must_exist=True)
        if not resolved["success"]:
            return resolved

        path = Path(resolved["data"]["path"])
        if not path.is_file():
            return self._error_result("Path is not a file.", "not_a_file", context, {"path": str(path)})

        size = path.stat().st_size
        if size > self.config.max_file_read_bytes:
            return self._error_result(
                "File is too large to read safely.",
                "file_too_large",
                context,
                {
                    "path": str(path),
                    "size": size,
                    "max_file_read_bytes": self.config.max_file_read_bytes,
                },
            )

        try:
            if as_bytes:
                content = path.read_bytes()
                data: Dict[str, Any] = {
                    "path": str(path),
                    "size": size,
                    "content_base16": content.hex(),
                    "encoding": "base16",
                    "as_bytes": True,
                }
            else:
                content_text = path.read_text(encoding=encoding, errors="replace")
                data = {
                    "path": str(path),
                    "size": size,
                    "content": content_text,
                    "encoding": encoding,
                    "as_bytes": False,
                }
            return self._safe_result("File read successfully.", data=data)
        except Exception as exc:
            return self._error_result("Failed to read file.", exc, context, {"path": str(path)})

    async def write_file(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        file_path = _coerce_str(payload.get("path"))
        content = payload.get("content", "")
        encoding = _coerce_str(payload.get("encoding"), "utf-8")
        append = bool(payload.get("append", False))
        create_parents = bool(payload.get("create_parents", True))

        if not file_path:
            return self._error_result("Missing file path.", "missing_path", context)

        if not self.config.allow_file_writes:
            return self._error_result(
                "File writes are disabled by SystemAgent configuration.",
                "file_writes_disabled",
                context,
            )

        resolved = self._resolve_workspace_path(context, file_path, must_exist=False)
        if not resolved["success"]:
            return resolved

        path = Path(resolved["data"]["path"])

        if create_parents:
            path.parent.mkdir(parents=True, exist_ok=True)

        try:
            if append:
                with path.open("a", encoding=encoding) as handle:
                    handle.write(str(content))
            else:
                path.write_text(str(content), encoding=encoding)
            stat = path.stat()
            return self._safe_result(
                "File written successfully.",
                data={
                    "path": str(path),
                    "append": append,
                    "size": stat.st_size,
                    "modified_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                },
            )
        except Exception as exc:
            return self._error_result("Failed to write file.", exc, context, {"path": str(path)})

    async def delete_file(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        target = _coerce_str(payload.get("path"))
        recursive = bool(payload.get("recursive", False))

        if not target:
            return self._error_result("Missing file/folder path.", "missing_path", context)

        if not self.config.allow_file_writes or not self.config.allow_destructive_actions:
            return self._error_result(
                "Delete is disabled unless file writes and destructive actions are enabled.",
                "delete_disabled",
                context,
            )

        resolved = self._resolve_workspace_path(context, target, must_exist=True)
        if not resolved["success"]:
            return resolved

        path = Path(resolved["data"]["path"])

        try:
            if path.is_dir():
                if not recursive:
                    return self._error_result(
                        "Target is a folder. Set recursive=true to delete folders.",
                        "recursive_required",
                        context,
                        {"path": str(path)},
                    )
                shutil.rmtree(path)
            else:
                path.unlink()
            return self._safe_result("File/folder deleted successfully.", data={"path": str(path)})
        except Exception as exc:
            return self._error_result("Failed to delete file/folder.", exc, context, {"path": str(path)})

    async def copy_file(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        source = _coerce_str(payload.get("source") or payload.get("from"))
        destination = _coerce_str(payload.get("destination") or payload.get("to"))

        if not source or not destination:
            return self._error_result(
                "Missing source or destination.",
                "missing_source_or_destination",
                context,
            )

        if not self.config.allow_file_writes:
            return self._error_result("File writes are disabled.", "file_writes_disabled", context)

        src_resolved = self._resolve_workspace_path(context, source, must_exist=True)
        if not src_resolved["success"]:
            return src_resolved
        dst_resolved = self._resolve_workspace_path(context, destination, must_exist=False)
        if not dst_resolved["success"]:
            return dst_resolved

        src = Path(src_resolved["data"]["path"])
        dst = Path(dst_resolved["data"]["path"])
        dst.parent.mkdir(parents=True, exist_ok=True)

        try:
            if src.is_dir():
                shutil.copytree(src, dst, dirs_exist_ok=bool(payload.get("dirs_exist_ok", True)))
            else:
                shutil.copy2(src, dst)
            return self._safe_result(
                "Copy completed successfully.",
                data={"source": str(src), "destination": str(dst)},
            )
        except Exception as exc:
            return self._error_result("Failed to copy.", exc, context, {"source": str(src), "destination": str(dst)})

    async def move_file(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        source = _coerce_str(payload.get("source") or payload.get("from"))
        destination = _coerce_str(payload.get("destination") or payload.get("to"))

        if not source or not destination:
            return self._error_result(
                "Missing source or destination.",
                "missing_source_or_destination",
                context,
            )

        if not self.config.allow_file_writes:
            return self._error_result("File writes are disabled.", "file_writes_disabled", context)

        src_resolved = self._resolve_workspace_path(context, source, must_exist=True)
        if not src_resolved["success"]:
            return src_resolved
        dst_resolved = self._resolve_workspace_path(context, destination, must_exist=False)
        if not dst_resolved["success"]:
            return dst_resolved

        src = Path(src_resolved["data"]["path"])
        dst = Path(dst_resolved["data"]["path"])
        dst.parent.mkdir(parents=True, exist_ok=True)

        try:
            shutil.move(str(src), str(dst))
            return self._safe_result(
                "Move completed successfully.",
                data={"source": str(src), "destination": str(dst)},
            )
        except Exception as exc:
            return self._error_result("Failed to move.", exc, context, {"source": str(src), "destination": str(dst)})

    async def create_folder(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        folder = _coerce_str(payload.get("path"))
        exist_ok = bool(payload.get("exist_ok", True))

        if not folder:
            return self._error_result("Missing folder path.", "missing_path", context)

        if not self.config.allow_file_writes:
            return self._error_result("File writes are disabled.", "file_writes_disabled", context)

        resolved = self._resolve_workspace_path(context, folder, must_exist=False)
        if not resolved["success"]:
            return resolved

        path = Path(resolved["data"]["path"])

        try:
            path.mkdir(parents=True, exist_ok=exist_ok)
            return self._safe_result(
                "Folder created successfully.",
                data={"path": str(path), "exist_ok": exist_ok},
            )
        except Exception as exc:
            return self._error_result("Failed to create folder.", exc, context, {"path": str(path)})

    async def run_command(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        """
        Run a command with multiple layers of safety:
            - blocked pattern detection
            - allowed prefix validation
            - workspace cwd restriction
            - SecurityAgent approval
            - config.allow_real_execution gate
            - timeout
        """

        command = _coerce_str(payload.get("command")).strip()
        cwd_text = _coerce_str(payload.get("cwd") or ".")
        timeout = payload.get("timeout")
        shell = bool(payload.get("shell", False))

        if not command:
            return self._error_result("Missing command.", "missing_command", context)

        if self._is_command_blocked(command):
            return self._error_result(
                "Command is blocked by safety policy.",
                "blocked_command",
                context,
                {"command": self._redact_command(command)},
            )

        if not self._is_command_prefix_allowed(command):
            return self._error_result(
                "Command prefix is not allowed by SystemAgent configuration.",
                "command_prefix_not_allowed",
                context,
                {
                    "command": self._redact_command(command),
                    "allowed_prefixes": self.config.allowed_command_prefixes,
                },
            )

        cwd_resolved = self._resolve_workspace_path(context, cwd_text, must_exist=True)
        if not cwd_resolved["success"]:
            return cwd_resolved

        cwd = Path(cwd_resolved["data"]["path"])
        if not cwd.is_dir():
            return self._error_result("cwd must be a folder.", "invalid_cwd", context, {"cwd": str(cwd)})

        if not self.config.allow_real_execution:
            return self._safe_result(
                "Command prepared as dry-run. Real execution is disabled.",
                data={
                    "command": self._redact_command(command),
                    "cwd": str(cwd),
                    "dry_run": True,
                    "shell": shell,
                },
            )

        return await self._execute_subprocess_command(
            command=command,
            context=context,
            cwd=cwd,
            shell=shell,
            timeout=timeout,
            action=SystemAction.RUN_COMMAND.value,
        )

    async def get_device_status(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        """
        Return safe local device/system status.

        Future versions can connect mobile/desktop device sync modules.
        """

        data = {
            "device_id": payload.get("device_id") or platform.node() or "local_device",
            "platform": platform.system(),
            "platform_release": platform.release(),
            "architecture": platform.machine(),
            "hostname": platform.node(),
            "python_version": platform.python_version(),
            "workspace_root_exists": self.config.root_workspace_dir.exists(),
            "real_execution_enabled": self.config.allow_real_execution,
            "timestamp": _utc_now(),
        }

        return self._safe_result("Device status retrieved.", data=data)

    async def set_device_setting(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        """
        Prepare or perform device setting changes.

        This file intentionally does not directly change sensitive OS settings
        unless real execution is explicitly enabled and future permission modules
        handle the setting type.
        """

        setting = _coerce_str(payload.get("setting")).strip()
        value = payload.get("value")
        device_id = payload.get("device_id") or "local_device"

        if not setting:
            return self._error_result("Missing device setting name.", "missing_setting", context)

        supported_safe_settings = {
            "agent_mode",
            "automation_enabled",
            "notification_reading_enabled",
            "desktop_vision_enabled",
            "gesture_control_enabled",
        }

        if setting not in supported_safe_settings:
            return self._error_result(
                "Device setting is not supported by this safe SystemAgent file.",
                "unsupported_device_setting",
                context,
                {
                    "setting": setting,
                    "supported_safe_settings": sorted(supported_safe_settings),
                },
            )

        return self._safe_result(
            "Device setting prepared/updated in SystemAgent control plane.",
            data={
                "device_id": device_id,
                "setting": setting,
                "value": value,
                "applied_to_os": False,
                "note": "OS-level setting changes should be implemented in device_controls.py with SecurityAgent approval.",
            },
        )

    async def create_automation(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        name = _coerce_str(payload.get("name")).strip()
        action = _normalize_action(payload.get("action"))
        automation_payload = dict(payload.get("payload") or {})

        if not name:
            return self._error_result("Missing automation name.", "missing_name", context)

        if action not in {a.value for a in SystemAction}:
            return self._error_result(
                "Automation action is not supported.",
                "unsupported_automation_action",
                context,
                {"action": action},
            )

        automation_id = str(uuid.uuid4())
        record = AutomationRecord(
            automation_id=automation_id,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            name=name,
            action=action,
            payload=automation_payload,
            enabled=bool(payload.get("enabled", True)),
        )
        self._automation_records[automation_id] = record

        return self._safe_result(
            "Automation created successfully.",
            data={"automation": dataclasses.asdict(record)},
        )

    async def run_automation(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        automation_id = _coerce_str(payload.get("automation_id")).strip()
        if not automation_id:
            return self._error_result("Missing automation_id.", "missing_automation_id", context)

        record = self._automation_records.get(automation_id)
        if record is None:
            return self._error_result("Automation not found.", "automation_not_found", context)

        if record.user_id != context.user_id or record.workspace_id != context.workspace_id:
            return self._error_result(
                "Automation belongs to a different user/workspace.",
                "workspace_isolation_violation",
                context,
            )

        if not record.enabled:
            return self._error_result("Automation is disabled.", "automation_disabled", context)

        child_task = {
            "action": record.action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": str(uuid.uuid4()),
            "actor": "automation",
            "payload": {
                **record.payload,
                "security_approved": bool(payload.get("security_approved", False)),
            },
            "metadata": {
                "parent_request_id": context.request_id,
                "automation_id": automation_id,
                "automation_name": record.name,
            },
        }

        result = await self.handle_task(child_task)
        record.last_run_at = _utc_now()

        return self._safe_result(
            "Automation run completed.",
            data={
                "automation_id": automation_id,
                "automation_name": record.name,
                "run_result": result,
                "last_run_at": record.last_run_at,
            },
        )

    async def stop_automation(
        self,
        payload: Dict[str, Any],
        context: TaskContext,
    ) -> Dict[str, Any]:
        automation_id = _coerce_str(payload.get("automation_id")).strip()
        if not automation_id:
            return self._error_result("Missing automation_id.", "missing_automation_id", context)

        record = self._automation_records.get(automation_id)
        if record is None:
            return self._error_result("Automation not found.", "automation_not_found", context)

        if record.user_id != context.user_id or record.workspace_id != context.workspace_id:
            return self._error_result(
                "Automation belongs to a different user/workspace.",
                "workspace_isolation_violation",
                context,
            )

        record.enabled = False
        return self._safe_result(
            "Automation stopped/disabled.",
            data={"automation": dataclasses.asdict(record)},
        )

    # ------------------------------------------------------------------
    # Workspace path isolation
    # ------------------------------------------------------------------

    def _workspace_root_for_context(self, context: TaskContext) -> Path:
        """
        Per-user/per-workspace isolated filesystem root.
        """

        safe_user = re.sub(r"[^a-zA-Z0-9_.@:-]+", "_", context.user_id)
        safe_workspace = re.sub(r"[^a-zA-Z0-9_.@:-]+", "_", context.workspace_id)
        return (self.config.root_workspace_dir / safe_user / safe_workspace).resolve()

    def _resolve_workspace_path(
        self,
        context: TaskContext,
        path_text: str,
        must_exist: bool = False,
    ) -> Dict[str, Any]:
        """
        Resolve and validate a path inside the user's workspace root.
        """

        if not path_text:
            return self._error_result("Missing path.", "missing_path", context)

        if _looks_like_path_traversal(path_text):
            return self._error_result(
                "Path traversal is not allowed.",
                "path_traversal_blocked",
                context,
                {"path": path_text},
            )

        root = self._workspace_root_for_context(context)
        root.mkdir(parents=True, exist_ok=True)

        candidate = Path(path_text)
        if candidate.is_absolute():
            resolved = candidate.resolve()
        else:
            resolved = (root / candidate).resolve()

        if self.config.strict_workspace_paths:
            try:
                resolved.relative_to(root)
            except ValueError:
                return self._error_result(
                    "Path is outside the user/workspace root.",
                    "workspace_path_violation",
                    context,
                    {"path": str(resolved), "workspace_root": str(root)},
                )

        if must_exist and not resolved.exists():
            return self._error_result(
                "Path does not exist.",
                "path_not_found",
                context,
                {"path": str(resolved)},
            )

        return self._safe_result(
            "Workspace path resolved.",
            data={"path": str(resolved), "workspace_root": str(root)},
        )

    # ------------------------------------------------------------------
    # Command/app helpers
    # ------------------------------------------------------------------

    def _build_open_app_command(
        self,
        app: str,
        args: Optional[Sequence[Any]] = None,
    ) -> Optional[Union[str, List[str]]]:
        args = [str(a) for a in (args or [])]

        if _is_windows():
            # Use start through cmd for app aliases/shortcuts.
            return f'start "" {shlex.quote(app)}' + (f" {' '.join(map(shlex.quote, args))}" if args else "")

        if _is_macos():
            if Path(app).exists():
                return ["open", app, *args]
            return ["open", "-a", app, *args]

        if _is_linux():
            # If app is a path or command name, subprocess can execute it.
            return [app, *args]

        return None

    def _build_close_app_command(self, app: str) -> Optional[Union[str, List[str]]]:
        process = Path(app).name

        if _is_windows():
            if not process.lower().endswith(".exe"):
                process_exe = f"{process}.exe"
            else:
                process_exe = process
            return ["taskkill", "/IM", process_exe, "/F"]

        if _is_macos() or _is_linux():
            # pkill is common on macOS/Linux. This remains permission-gated.
            return ["pkill", "-f", process]

        return None

    async def _execute_subprocess_command(
        self,
        command: Union[str, Sequence[str]],
        context: TaskContext,
        cwd: Optional[Path] = None,
        shell: bool = False,
        timeout: Optional[Any] = None,
        action: str = "run_command",
    ) -> Dict[str, Any]:
        timeout_seconds = self._normalize_timeout(timeout)

        try:
            started = time.time()

            if isinstance(command, str):
                popen_command: Union[str, Sequence[str]] = command
            else:
                popen_command = [str(part) for part in command]

            completed = await asyncio.to_thread(
                subprocess.run,
                popen_command,
                cwd=str(cwd) if cwd else None,
                shell=shell,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )

            duration_ms = int((time.time() - started) * 1000)
            stdout = completed.stdout[-20_000:] if completed.stdout else ""
            stderr = completed.stderr[-20_000:] if completed.stderr else ""

            return self._safe_result(
                "Command executed." if completed.returncode == 0 else "Command completed with non-zero exit code.",
                data={
                    "command": self._redact_command(command),
                    "returncode": completed.returncode,
                    "stdout": stdout,
                    "stderr": stderr,
                    "cwd": str(cwd) if cwd else None,
                    "duration_ms": duration_ms,
                    "timeout_seconds": timeout_seconds,
                    "action": action,
                },
                metadata={"non_zero_exit": completed.returncode != 0},
            )
        except subprocess.TimeoutExpired as exc:
            return self._error_result(
                "Command timed out.",
                f"timeout_after_{timeout_seconds}_seconds",
                context,
                {"command": self._redact_command(command), "timeout": timeout_seconds, "detail": str(exc)},
            )
        except Exception as exc:
            return self._error_result(
                "Command execution failed.",
                exc,
                context,
                {"command": self._redact_command(command)},
            )

    def _normalize_timeout(self, timeout: Optional[Any]) -> int:
        with contextlib.suppress(Exception):
            value = int(timeout)
            return max(1, min(value, self.config.max_command_timeout_seconds))
        return self.config.max_command_timeout_seconds

    def _is_command_blocked(self, command: str) -> bool:
        lowered = command.lower()
        return any(re.search(pattern, lowered, flags=re.IGNORECASE) for pattern in self.config.blocked_command_patterns)

    def _is_command_prefix_allowed(self, command: str) -> bool:
        token = _first_command_token(command)
        allowed = {prefix.lower() for prefix in self.config.allowed_command_prefixes}
        return token in allowed

    def _classify_risk(self, action: str, payload: Mapping[str, Any]) -> RiskLevel:
        if action in {
            SystemAction.DELETE_FILE.value,
            SystemAction.MOVE_FILE.value,
            SystemAction.CLOSE_APP.value,
            SystemAction.SET_DEVICE_SETTING.value,
        }:
            return RiskLevel.HIGH

        if action == SystemAction.RUN_COMMAND.value:
            command = _coerce_str(payload.get("command"))
            if self._is_command_blocked(command):
                return RiskLevel.CRITICAL
            if payload.get("shell"):
                return RiskLevel.HIGH
            return RiskLevel.MEDIUM

        if action in {
            SystemAction.WRITE_FILE.value,
            SystemAction.COPY_FILE.value,
            SystemAction.CREATE_FOLDER.value,
            SystemAction.OPEN_APP.value,
            SystemAction.CREATE_AUTOMATION.value,
            SystemAction.RUN_AUTOMATION.value,
            SystemAction.STOP_AUTOMATION.value,
        }:
            return RiskLevel.MEDIUM

        return RiskLevel.LOW

    def _normalize_security_response(self, response: Any) -> Dict[str, Any]:
        if isinstance(response, Mapping):
            if "approved" in response:
                return dict(response)
            if response.get("success") is True and response.get("decision") in {"allow", "approved"}:
                return {"approved": True, "reason": response.get("message", "approved"), "source": "security_agent"}
            if response.get("decision") in {"deny", "denied", "block"}:
                return {"approved": False, "reason": response.get("message", "denied"), "source": "security_agent"}
        if response is True:
            return {"approved": True, "reason": "SecurityAgent returned True.", "source": "security_agent"}
        return {"approved": False, "reason": "SecurityAgent did not approve action.", "source": "security_agent"}

    # ------------------------------------------------------------------
    # Redaction / summary helpers
    # ------------------------------------------------------------------

    def _redact_sensitive_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        redacted: Dict[str, Any] = {}
        sensitive_keys = {
            "password",
            "token",
            "secret",
            "api_key",
            "authorization",
            "cookie",
            "private_key",
            "access_token",
            "refresh_token",
        }

        for key, value in payload.items():
            key_str = str(key)
            if any(s in key_str.lower() for s in sensitive_keys):
                redacted[key_str] = "***REDACTED***"
            elif key_str.lower() in {"content"} and isinstance(value, str) and len(value) > 500:
                redacted[key_str] = value[:500] + "...[truncated]"
            else:
                redacted[key_str] = _safe_json(value)

        return redacted

    def _redact_command(self, command: Union[str, Sequence[str]]) -> Union[str, List[str]]:
        secrets_pattern = re.compile(
            r"(?i)(password|token|secret|api[_-]?key|authorization)=([^\s]+)"
        )

        def redact_text(text: str) -> str:
            return secrets_pattern.sub(r"\1=***REDACTED***", text)

        if isinstance(command, str):
            return redact_text(command)

        return [redact_text(str(part)) for part in command]

    def _summarize_data(self, data: Any) -> Dict[str, Any]:
        if data is None:
            return {"type": "none"}

        if isinstance(data, Mapping):
            keys = list(data.keys())
            summary: Dict[str, Any] = {
                "type": "mapping",
                "keys": keys[:25],
                "key_count": len(keys),
            }
            if "path" in data:
                summary["path"] = data.get("path")
            if "count" in data:
                summary["count"] = data.get("count")
            if "returncode" in data:
                summary["returncode"] = data.get("returncode")
            return summary

        if isinstance(data, list):
            return {"type": "list", "count": len(data)}

        return {"type": type(data).__name__, "value_preview": str(data)[:200]}

    # ------------------------------------------------------------------
    # Local inspection helpers for dashboard/testing
    # ------------------------------------------------------------------

    def get_audit_events(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Return in-memory audit events, optionally filtered.
        """

        events = self._audit_events
        if user_id is not None:
            events = [event for event in events if event.get("user_id") == user_id]
        if workspace_id is not None:
            events = [event for event in events if event.get("workspace_id") == workspace_id]
        return events[-limit:]

    def get_task_history(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Return in-memory task history, optionally filtered.
        """

        history = self._task_history
        if user_id is not None:
            history = [item for item in history if item.get("user_id") == user_id]
        if workspace_id is not None:
            history = [item for item in history if item.get("workspace_id") == workspace_id]
        return history[-limit:]

    def list_automations(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Return automation records with user/workspace filtering.
        """

        records = list(self._automation_records.values())
        if user_id is not None:
            records = [record for record in records if record.user_id == user_id]
        if workspace_id is not None:
            records = [record for record in records if record.workspace_id == workspace_id]
        return [dataclasses.asdict(record) for record in records]


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_system_agent(
    config: Optional[SystemAgentConfig] = None,
    security_agent: Any = None,
    memory_agent: Any = None,
    verification_agent: Any = None,
    event_sink: Optional[Callable[[Dict[str, Any]], Any]] = None,
    audit_sink: Optional[Callable[[Dict[str, Any]], Any]] = None,
) -> SystemAgent:
    """
    Factory used by AgentLoader/Registry or tests.
    """

    return SystemAgent(
        config=config,
        security_agent=security_agent,
        memory_agent=memory_agent,
        verification_agent=verification_agent,
        event_sink=event_sink,
        audit_sink=audit_sink,
    )


# ---------------------------------------------------------------------------
# Simple manual test
# ---------------------------------------------------------------------------

async def _demo() -> None:
    agent = create_system_agent()
    result = await agent.handle_task(
        {
            "action": "health_check",
            "user_id": "demo_user",
            "workspace_id": "demo_workspace",
            "payload": {},
        }
    )
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    asyncio.run(_demo())


"""
FILE COMPLETE

Agent/Module: System Agent
File Completed: system_agent.py
Completion: 5.9%
Completed Files: ['system_agent.py']
Remaining Files: ['app_controller.py', 'file_manager.py', 'os_commands.py', 'device_controls.py', 'automation.py', 'notification_reader.py', 'message_controller.py', 'call_controller.py', 'permission_guard.py', 'app_profiles.py', 'device_sync.py', 'gesture_control.py', 'desktop_vision.py', 'task_recorder.py', 'system_memory.py', 'config.py']
Next Recommended File: agents/system_agent/app_controller.py
"""
