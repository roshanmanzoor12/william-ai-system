"""
agents/workflow_agent/n8n_connector.py

Purpose:
    Connects William / Jarvis Workflow Agent to n8n.

Responsibilities:
    - Connect to n8n using safe API configuration.
    - Create, update, activate, deactivate, delete, and inspect n8n workflows.
    - Manage workflow nodes and connections.
    - Read and manage executions.
    - Enforce SaaS user/workspace context isolation at the connector boundary.
    - Route sensitive operations through Security Agent compatible hooks.
    - Prepare Verification Agent payloads after meaningful actions.
    - Prepare Memory Agent payloads for useful workflow context.
    - Emit structured events/audit logs for dashboard/API/registry usage.
    - Remain import-safe even if the rest of William/Jarvis modules are not present yet.

William / Jarvis Architecture Notes:
    This helper is designed to be used by:
        - Workflow Agent
        - Master Agent / Agent Router
        - Dashboard/API layer
        - Security Agent
        - Verification Agent
        - Memory Agent
        - Future app connectors / workflow builder modules

    It intentionally returns structured dictionaries instead of raising raw exceptions
    from public methods.
"""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import Request, urlopen


# ---------------------------------------------------------------------------
# Optional imports
# ---------------------------------------------------------------------------

try:
    import httpx  # type: ignore
except Exception:  # pragma: no cover - optional dependency fallback
    httpx = None  # type: ignore


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        This keeps the connector import-safe when the full William/Jarvis system
        has not been generated yet.
        """

        agent_name: str = "base_agent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_id = kwargs.get("agent_id", self.__class__.__name__)
            self.logger = logging.getLogger(self.__class__.__name__)


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover - optional security dependency
    SecurityAgent = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Enums and data structures
# ---------------------------------------------------------------------------

class N8NAction(str, Enum):
    """Supported connector actions."""

    HEALTH_CHECK = "health_check"
    LIST_WORKFLOWS = "list_workflows"
    GET_WORKFLOW = "get_workflow"
    CREATE_WORKFLOW = "create_workflow"
    UPDATE_WORKFLOW = "update_workflow"
    DELETE_WORKFLOW = "delete_workflow"
    ACTIVATE_WORKFLOW = "activate_workflow"
    DEACTIVATE_WORKFLOW = "deactivate_workflow"
    EXECUTE_WORKFLOW = "execute_workflow"
    LIST_EXECUTIONS = "list_executions"
    GET_EXECUTION = "get_execution"
    DELETE_EXECUTION = "delete_execution"
    ADD_NODE = "add_node"
    UPDATE_NODE = "update_node"
    REMOVE_NODE = "remove_node"
    CONNECT_NODES = "connect_nodes"
    DISCONNECT_NODES = "disconnect_nodes"


class N8NHttpMethod(str, Enum):
    """HTTP methods used by n8n connector."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"


class N8NNodeConnectionType(str, Enum):
    """Common n8n node connection types."""

    MAIN = "main"
    AI_TOOL = "ai_tool"
    AI_MEMORY = "ai_memory"
    AI_LANGUAGE_MODEL = "ai_languageModel"
    AI_OUTPUT_PARSER = "ai_outputParser"


@dataclass
class N8NConnectorConfig:
    """
    Runtime configuration for n8n.

    Do not hardcode secrets. API key can be provided directly from a secret
    manager, environment variable, or dashboard-injected config.
    """

    base_url: str = field(default_factory=lambda: os.getenv("N8N_BASE_URL", "http://localhost:5678"))
    api_key: Optional[str] = field(default_factory=lambda: os.getenv("N8N_API_KEY"))
    api_prefix: str = field(default_factory=lambda: os.getenv("N8N_API_PREFIX", "/api/v1"))
    timeout_seconds: float = field(default_factory=lambda: float(os.getenv("N8N_TIMEOUT_SECONDS", "30")))
    verify_ssl: bool = field(default_factory=lambda: os.getenv("N8N_VERIFY_SSL", "true").lower() not in {"0", "false", "no"})
    allow_manual_execution: bool = field(default_factory=lambda: os.getenv("N8N_ALLOW_MANUAL_EXECUTION", "false").lower() in {"1", "true", "yes"})
    allow_delete: bool = field(default_factory=lambda: os.getenv("N8N_ALLOW_DELETE", "false").lower() in {"1", "true", "yes"})
    user_agent: str = "William-Jarvis-N8NConnector/1.0"
    max_page_size: int = 100
    default_workflow_active: bool = False
    require_security_for_sensitive_actions: bool = True
    request_id_prefix: str = "william_n8n"

    def normalized_base_url(self) -> str:
        """Return base URL without trailing slash."""
        return self.base_url.rstrip("/")

    def normalized_api_prefix(self) -> str:
        """Return API prefix with leading slash and no trailing slash."""
        prefix = self.api_prefix or "/api/v1"
        if not prefix.startswith("/"):
            prefix = f"/{prefix}"
        return prefix.rstrip("/")


@dataclass
class TaskContext:
    """
    SaaS execution context.

    Every user/workspace scoped workflow action should carry this context to
    avoid mixing workflows, audit records, memory, or verification state between
    tenants.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    subscription_id: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    source: str = "workflow_agent"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, context: Mapping[str, Any]) -> "TaskContext":
        """Build TaskContext from dict-like input."""
        return cls(
            user_id=str(context.get("user_id") or "").strip(),
            workspace_id=str(context.get("workspace_id") or "").strip(),
            role=context.get("role"),
            request_id=context.get("request_id"),
            session_id=context.get("session_id"),
            subscription_id=context.get("subscription_id"),
            permissions=list(context.get("permissions") or []),
            source=str(context.get("source") or "workflow_agent"),
            metadata=dict(context.get("metadata") or {}),
        )


# ---------------------------------------------------------------------------
# Connector
# ---------------------------------------------------------------------------

class N8NConnector(BaseAgent):
    """
    Production-level connector for n8n Workflow API.

    This class is intentionally usable as:
        - a direct helper inside Workflow Agent
        - a registry-loaded agent component
        - a FastAPI dependency/service
        - a dashboard action handler
        - a testing utility with mocked HTTP transport

    Public methods return:
        {
            "success": bool,
            "message": str,
            "data": dict/list/None,
            "error": dict/None,
            "metadata": dict
        }
    """

    agent_name = "workflow_agent.n8n_connector"
    agent_version = "1.0.0"

    SENSITIVE_ACTIONS = {
        N8NAction.CREATE_WORKFLOW,
        N8NAction.UPDATE_WORKFLOW,
        N8NAction.DELETE_WORKFLOW,
        N8NAction.ACTIVATE_WORKFLOW,
        N8NAction.DEACTIVATE_WORKFLOW,
        N8NAction.EXECUTE_WORKFLOW,
        N8NAction.DELETE_EXECUTION,
        N8NAction.ADD_NODE,
        N8NAction.UPDATE_NODE,
        N8NAction.REMOVE_NODE,
        N8NAction.CONNECT_NODES,
        N8NAction.DISCONNECT_NODES,
    }

    DESTRUCTIVE_ACTIONS = {
        N8NAction.DELETE_WORKFLOW,
        N8NAction.DELETE_EXECUTION,
        N8NAction.REMOVE_NODE,
        N8NAction.DISCONNECT_NODES,
    }

    def __init__(
        self,
        config: Optional[Union[N8NConnectorConfig, Mapping[str, Any]]] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        http_client: Optional[Any] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the connector.

        Args:
            config:
                N8NConnectorConfig or dict.
            security_agent:
                Optional Security Agent instance.
            memory_agent:
                Optional Memory Agent instance.
            verification_agent:
                Optional Verification Agent instance.
            event_bus:
                Optional event bus / dashboard publisher.
            audit_logger:
                Optional audit logger.
            http_client:
                Optional injected test client.
            logger_instance:
                Optional logger override.
            **kwargs:
                Future BaseAgent compatibility options.
        """
        super().__init__(**kwargs)

        if isinstance(config, N8NConnectorConfig):
            self.config = config
        elif isinstance(config, Mapping):
            self.config = N8NConnectorConfig(**dict(config))
        else:
            self.config = N8NConnectorConfig()

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self.http_client = http_client
        self.logger = logger_instance or logging.getLogger(self.__class__.__name__)

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(self, context: Union[TaskContext, Mapping[str, Any], None]) -> Tuple[bool, Optional[TaskContext], Optional[str]]:
        """
        Validate user/workspace isolation context.

        Returns:
            (is_valid, normalized_context, error_message)
        """
        if context is None:
            return False, None, "Missing task context. user_id and workspace_id are required."

        if isinstance(context, TaskContext):
            task_context = context
        elif isinstance(context, Mapping):
            task_context = TaskContext.from_mapping(context)
        else:
            return False, None, "Invalid task context type. Expected dict or TaskContext."

        if not task_context.user_id:
            return False, None, "Missing user_id in task context."

        if not task_context.workspace_id:
            return False, None, "Missing workspace_id in task context."

        if not task_context.request_id:
            task_context.request_id = self._new_request_id()

        return True, task_context, None

    def _requires_security_check(self, action: Union[N8NAction, str]) -> bool:
        """Return True when an action needs Security Agent approval."""
        try:
            normalized = N8NAction(action)
        except Exception:
            return True

        if not self.config.require_security_for_sensitive_actions:
            return False

        return normalized in self.SENSITIVE_ACTIONS

    async def _request_security_approval(
        self,
        action: Union[N8NAction, str],
        context: TaskContext,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Ask Security Agent for approval.

        If no Security Agent is wired yet, this method uses safe default behavior:
            - non-sensitive actions are allowed
            - sensitive actions are allowed only if connector is configured not to
              require external approval or if context permissions include
              'workflow:admin' / 'n8n:admin' / action-specific permission.

        This fallback keeps the file importable/testable without bypassing safety.
        """
        action_value = str(action.value if isinstance(action, N8NAction) else action)

        if not self._requires_security_check(action_value):
            return {
                "approved": True,
                "reason": "Security check not required for this action.",
                "source": "n8n_connector",
            }

        permission_names = {
            "workflow:admin",
            "n8n:admin",
            f"n8n:{action_value}",
            f"workflow:{action_value}",
        }

        has_local_permission = bool(set(context.permissions).intersection(permission_names))

        approval_payload = {
            "agent": self.agent_name,
            "action": action_value,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "payload": self._redact_sensitive(dict(payload or {})),
            "timestamp": self._utc_now(),
        }

        if self.security_agent is not None:
            try:
                if hasattr(self.security_agent, "approve_action"):
                    response = self.security_agent.approve_action(approval_payload)
                    if asyncio.iscoroutine(response):
                        response = await response
                    return self._normalize_security_response(response)

                if hasattr(self.security_agent, "request_approval"):
                    response = self.security_agent.request_approval(approval_payload)
                    if asyncio.iscoroutine(response):
                        response = await response
                    return self._normalize_security_response(response)

                if hasattr(self.security_agent, "validate"):
                    response = self.security_agent.validate(approval_payload)
                    if asyncio.iscoroutine(response):
                        response = await response
                    return self._normalize_security_response(response)

            except Exception as exc:
                self.logger.exception("Security approval failed.")
                return {
                    "approved": False,
                    "reason": f"Security Agent error: {exc}",
                    "source": "security_agent",
                }

        if has_local_permission:
            return {
                "approved": True,
                "reason": "Approved by local context permission fallback.",
                "source": "context_permissions",
            }

        return {
            "approved": False,
            "reason": (
                "Sensitive n8n action requires Security Agent approval or one of "
                "these permissions: workflow:admin, n8n:admin, "
                f"n8n:{action_value}, workflow:{action_value}."
            ),
            "source": "fallback_guard",
        }

    def _prepare_verification_payload(
        self,
        action: Union[N8NAction, str],
        context: TaskContext,
        result: Mapping[str, Any],
        target: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent compatible payload.

        Verification Agent can use this to confirm workflow changes, activation
        state, execution status, and audit consistency.
        """
        action_value = str(action.value if isinstance(action, N8NAction) else action)

        return {
            "verification_type": "workflow_n8n_action",
            "agent": self.agent_name,
            "action": action_value,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "target": dict(target or {}),
            "data_summary": self._summarize_for_event(result.get("data")),
            "error": result.get("error"),
            "timestamp": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        action: Union[N8NAction, str],
        context: TaskContext,
        result: Mapping[str, Any],
        memory_type: str = "workflow_n8n_context",
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Only sanitized and useful metadata is included. Secrets and API keys are
        never stored.
        """
        action_value = str(action.value if isinstance(action, N8NAction) else action)

        return {
            "memory_type": memory_type,
            "agent": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "action": action_value,
            "summary": result.get("message"),
            "data": self._summarize_for_event(result.get("data")),
            "timestamp": self._utc_now(),
            "metadata": {
                "source": "n8n_connector",
                "success": bool(result.get("success")),
            },
        }

    def _emit_agent_event(
        self,
        event_name: str,
        context: Optional[TaskContext],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit agent/dashboard event.

        This is best-effort and never breaks the main task.
        """
        event = {
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_version": self.agent_version,
            "user_id": context.user_id if context else None,
            "workspace_id": context.workspace_id if context else None,
            "request_id": context.request_id if context else None,
            "payload": self._redact_sensitive(dict(payload or {})),
            "timestamp": self._utc_now(),
        }

        try:
            if self.event_bus is not None:
                if hasattr(self.event_bus, "emit"):
                    response = self.event_bus.emit(event_name, event)
                    if asyncio.iscoroutine(response):
                        # Fire-and-forget compatibility when called from sync hooks.
                        try:
                            loop = asyncio.get_running_loop()
                            loop.create_task(response)
                        except RuntimeError:
                            asyncio.run(response)
                elif callable(self.event_bus):
                    response = self.event_bus(event)
                    if asyncio.iscoroutine(response):
                        try:
                            loop = asyncio.get_running_loop()
                            loop.create_task(response)
                        except RuntimeError:
                            asyncio.run(response)

            self.logger.debug("Agent event emitted: %s", event)
        except Exception:
            self.logger.exception("Failed to emit agent event.")

    def _log_audit_event(
        self,
        action: Union[N8NAction, str],
        context: Optional[TaskContext],
        success: bool,
        message: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        Audit logs are user/workspace scoped and sanitized.
        """
        action_value = str(action.value if isinstance(action, N8NAction) else action)

        audit_record = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "action": action_value,
            "user_id": context.user_id if context else None,
            "workspace_id": context.workspace_id if context else None,
            "request_id": context.request_id if context else None,
            "success": success,
            "message": message,
            "payload": self._redact_sensitive(dict(payload or {})),
            "timestamp": self._utc_now(),
        }

        try:
            if self.audit_logger is not None:
                if hasattr(self.audit_logger, "log"):
                    response = self.audit_logger.log(audit_record)
                    if asyncio.iscoroutine(response):
                        try:
                            loop = asyncio.get_running_loop()
                            loop.create_task(response)
                        except RuntimeError:
                            asyncio.run(response)
                elif callable(self.audit_logger):
                    response = self.audit_logger(audit_record)
                    if asyncio.iscoroutine(response):
                        try:
                            loop = asyncio.get_running_loop()
                            loop.create_task(response)
                        except RuntimeError:
                            asyncio.run(response)

            self.logger.info("Audit event: %s", audit_record)
        except Exception:
            self.logger.exception("Failed to write audit event.")

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Any = None,
        error: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis structured result."""
        return {
            "success": bool(success),
            "message": str(message),
            "data": data,
            "error": dict(error) if error else None,
            "metadata": {
                "agent": self.agent_name,
                "agent_version": self.agent_version,
                "timestamp": self._utc_now(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        code: str = "n8n_connector_error",
        details: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""
        return self._safe_result(
            success=False,
            message=message,
            data=None,
            error={
                "code": code,
                "details": self._redact_sensitive(details) if isinstance(details, dict) else details,
            },
            metadata=metadata,
        )

    # -----------------------------------------------------------------------
    # Public API: health and workflows
    # -----------------------------------------------------------------------

    async def health_check(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Check n8n API connectivity."""
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        result = await self._run_http_action(
            action=N8NAction.HEALTH_CHECK,
            context=ctx,
            method=N8NHttpMethod.GET,
            path="/workflows",
            query={"limit": 1},
            security_payload={"operation": "health_check"},
        )

        if result["success"]:
            result["message"] = "n8n connection is healthy."
            result["data"] = {
                "reachable": True,
                "base_url": self.config.normalized_base_url(),
                "api_prefix": self.config.normalized_api_prefix(),
            }

        return result

    async def list_workflows(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        limit: int = 50,
        cursor: Optional[str] = None,
        active: Optional[bool] = None,
        tags: Optional[List[str]] = None,
        include_all: bool = False,
    ) -> Dict[str, Any]:
        """
        List workflows visible through n8n API.

        The connector filters result metadata by William user/workspace markers
        when available. n8n itself does not provide tenant isolation, so this
        method performs a safe boundary check.
        """
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        safe_limit = min(max(int(limit or 50), 1), self.config.max_page_size)

        query: Dict[str, Any] = {"limit": safe_limit}
        if cursor:
            query["cursor"] = cursor
        if active is not None:
            query["active"] = "true" if active else "false"
        if tags:
            query["tags"] = ",".join(tags)

        result = await self._run_http_action(
            action=N8NAction.LIST_WORKFLOWS,
            context=ctx,
            method=N8NHttpMethod.GET,
            path="/workflows",
            query=query,
            security_payload={"operation": "list_workflows"},
        )

        if not result["success"]:
            return result

        raw_data = result.get("data")
        filtered = self._filter_workflows_for_context(raw_data, ctx, include_all=include_all)

        return self._safe_result(
            success=True,
            message="n8n workflows retrieved successfully.",
            data=filtered,
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "include_all": include_all,
            },
        )

    async def get_workflow(
        self,
        workflow_id: Union[str, int],
        context: Union[TaskContext, Mapping[str, Any]],
        enforce_context: bool = True,
    ) -> Dict[str, Any]:
        """Get one workflow by n8n workflow ID."""
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        workflow_id_str = self._validate_id(workflow_id, "workflow_id")
        if isinstance(workflow_id_str, dict):
            return workflow_id_str

        result = await self._run_http_action(
            action=N8NAction.GET_WORKFLOW,
            context=ctx,
            method=N8NHttpMethod.GET,
            path=f"/workflows/{workflow_id_str}",
            security_payload={"workflow_id": workflow_id_str},
        )

        if not result["success"]:
            return result

        workflow = result.get("data")
        if enforce_context and isinstance(workflow, Mapping):
            if not self._workflow_belongs_to_context(workflow, ctx):
                return self._error_result(
                    message="Workflow does not belong to this user/workspace context.",
                    code="workflow_context_mismatch",
                    metadata={
                        "request_id": ctx.request_id,
                        "workflow_id": workflow_id_str,
                    },
                )

        return self._safe_result(
            success=True,
            message="n8n workflow retrieved successfully.",
            data=workflow,
            metadata={
                "request_id": ctx.request_id,
                "workflow_id": workflow_id_str,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    async def create_workflow(
        self,
        workflow: Mapping[str, Any],
        context: Union[TaskContext, Mapping[str, Any]],
        activate: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Create a workflow in n8n.

        The workflow payload is enriched with William user/workspace metadata.
        """
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        validation = self._validate_workflow_payload(workflow, creating=True)
        if validation is not None:
            return validation

        prepared = self._prepare_workflow_payload_for_context(
            workflow=workflow,
            context=ctx,
            active=self.config.default_workflow_active if activate is None else bool(activate),
        )

        result = await self._run_http_action(
            action=N8NAction.CREATE_WORKFLOW,
            context=ctx,
            method=N8NHttpMethod.POST,
            path="/workflows",
            body=prepared,
            security_payload={
                "operation": "create_workflow",
                "workflow_name": prepared.get("name"),
                "node_count": len(prepared.get("nodes") or []),
                "active": prepared.get("active"),
            },
        )

        await self._post_action_side_effects(
            action=N8NAction.CREATE_WORKFLOW,
            context=ctx,
            result=result,
            target={"workflow_name": prepared.get("name")},
        )

        if result["success"]:
            result["message"] = "n8n workflow created successfully."

        return result

    async def update_workflow(
        self,
        workflow_id: Union[str, int],
        workflow_updates: Mapping[str, Any],
        context: Union[TaskContext, Mapping[str, Any]],
        patch: bool = False,
        enforce_context: bool = True,
    ) -> Dict[str, Any]:
        """
        Update a workflow.

        Args:
            workflow_id:
                n8n workflow ID.
            workflow_updates:
                Full workflow or partial payload.
            context:
                SaaS context.
            patch:
                Use PATCH when True, PUT when False.
            enforce_context:
                Read workflow first and block update if it belongs to another
                user/workspace.
        """
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        workflow_id_str = self._validate_id(workflow_id, "workflow_id")
        if isinstance(workflow_id_str, dict):
            return workflow_id_str

        if not isinstance(workflow_updates, Mapping):
            return self._error_result("workflow_updates must be a mapping.", "invalid_workflow_updates")

        if enforce_context:
            existing_result = await self.get_workflow(workflow_id_str, ctx, enforce_context=True)
            if not existing_result["success"]:
                return existing_result

        prepared_updates = self._prepare_workflow_payload_for_context(
            workflow=workflow_updates,
            context=ctx,
            active=workflow_updates.get("active") if "active" in workflow_updates else None,
            partial=patch,
        )

        method = N8NHttpMethod.PATCH if patch else N8NHttpMethod.PUT

        result = await self._run_http_action(
            action=N8NAction.UPDATE_WORKFLOW,
            context=ctx,
            method=method,
            path=f"/workflows/{workflow_id_str}",
            body=prepared_updates,
            security_payload={
                "operation": "update_workflow",
                "workflow_id": workflow_id_str,
                "fields": list(workflow_updates.keys()),
            },
        )

        await self._post_action_side_effects(
            action=N8NAction.UPDATE_WORKFLOW,
            context=ctx,
            result=result,
            target={"workflow_id": workflow_id_str},
        )

        if result["success"]:
            result["message"] = "n8n workflow updated successfully."

        return result

    async def activate_workflow(
        self,
        workflow_id: Union[str, int],
        context: Union[TaskContext, Mapping[str, Any]],
        enforce_context: bool = True,
    ) -> Dict[str, Any]:
        """Activate workflow by setting active=True."""
        return await self._set_workflow_active_state(
            workflow_id=workflow_id,
            context=context,
            active=True,
            enforce_context=enforce_context,
        )

    async def deactivate_workflow(
        self,
        workflow_id: Union[str, int],
        context: Union[TaskContext, Mapping[str, Any]],
        enforce_context: bool = True,
    ) -> Dict[str, Any]:
        """Deactivate workflow by setting active=False."""
        return await self._set_workflow_active_state(
            workflow_id=workflow_id,
            context=context,
            active=False,
            enforce_context=enforce_context,
        )

    async def delete_workflow(
        self,
        workflow_id: Union[str, int],
        context: Union[TaskContext, Mapping[str, Any]],
        enforce_context: bool = True,
    ) -> Dict[str, Any]:
        """
        Delete workflow from n8n.

        Deletion is blocked unless config.allow_delete=True and security approval
        passes.
        """
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        if not self.config.allow_delete:
            return self._error_result(
                message="Workflow deletion is disabled by connector configuration.",
                code="delete_disabled",
                metadata={"request_id": ctx.request_id},
            )

        workflow_id_str = self._validate_id(workflow_id, "workflow_id")
        if isinstance(workflow_id_str, dict):
            return workflow_id_str

        if enforce_context:
            existing_result = await self.get_workflow(workflow_id_str, ctx, enforce_context=True)
            if not existing_result["success"]:
                return existing_result

        result = await self._run_http_action(
            action=N8NAction.DELETE_WORKFLOW,
            context=ctx,
            method=N8NHttpMethod.DELETE,
            path=f"/workflows/{workflow_id_str}",
            security_payload={
                "operation": "delete_workflow",
                "workflow_id": workflow_id_str,
                "destructive": True,
            },
        )

        await self._post_action_side_effects(
            action=N8NAction.DELETE_WORKFLOW,
            context=ctx,
            result=result,
            target={"workflow_id": workflow_id_str},
        )

        if result["success"]:
            result["message"] = "n8n workflow deleted successfully."

        return result

    # -----------------------------------------------------------------------
    # Public API: node management
    # -----------------------------------------------------------------------

    async def add_node(
        self,
        workflow_id: Union[str, int],
        node: Mapping[str, Any],
        context: Union[TaskContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Add a node to a workflow and update the workflow in n8n."""
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        workflow_result = await self.get_workflow(workflow_id, ctx, enforce_context=True)
        if not workflow_result["success"]:
            return workflow_result

        validation = self._validate_node_payload(node)
        if validation is not None:
            return validation

        workflow = copy.deepcopy(workflow_result["data"])
        workflow.setdefault("nodes", [])

        existing_names = {str(n.get("name")) for n in workflow.get("nodes", []) if isinstance(n, Mapping)}
        node_to_add = copy.deepcopy(dict(node))

        if not node_to_add.get("id"):
            node_to_add["id"] = str(uuid.uuid4())

        if not node_to_add.get("name"):
            node_to_add["name"] = f"William Node {len(existing_names) + 1}"

        if node_to_add["name"] in existing_names:
            return self._error_result(
                message=f"Node with name '{node_to_add['name']}' already exists in workflow.",
                code="duplicate_node_name",
                metadata={"request_id": ctx.request_id},
            )

        workflow["nodes"].append(node_to_add)

        result = await self.update_workflow(
            workflow_id=workflow_id,
            workflow_updates=self._strip_readonly_workflow_fields(workflow),
            context=ctx,
            patch=False,
            enforce_context=False,
        )

        await self._post_action_side_effects(
            action=N8NAction.ADD_NODE,
            context=ctx,
            result=result,
            target={"workflow_id": str(workflow_id), "node_name": node_to_add.get("name")},
        )

        if result["success"]:
            result["message"] = "Node added to n8n workflow successfully."

        return result

    async def update_node(
        self,
        workflow_id: Union[str, int],
        node_name_or_id: str,
        node_updates: Mapping[str, Any],
        context: Union[TaskContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Update one node by name or ID."""
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        if not node_name_or_id:
            return self._error_result("node_name_or_id is required.", "missing_node_identifier")

        if not isinstance(node_updates, Mapping):
            return self._error_result("node_updates must be a mapping.", "invalid_node_updates")

        workflow_result = await self.get_workflow(workflow_id, ctx, enforce_context=True)
        if not workflow_result["success"]:
            return workflow_result

        workflow = copy.deepcopy(workflow_result["data"])
        nodes = workflow.get("nodes") or []

        found = False
        for index, node in enumerate(nodes):
            if not isinstance(node, Mapping):
                continue
            if str(node.get("id")) == str(node_name_or_id) or str(node.get("name")) == str(node_name_or_id):
                updated_node = copy.deepcopy(dict(node))
                updated_node.update(dict(node_updates))
                nodes[index] = updated_node
                found = True
                break

        if not found:
            return self._error_result(
                message=f"Node '{node_name_or_id}' was not found in workflow.",
                code="node_not_found",
                metadata={"request_id": ctx.request_id},
            )

        workflow["nodes"] = nodes

        result = await self.update_workflow(
            workflow_id=workflow_id,
            workflow_updates=self._strip_readonly_workflow_fields(workflow),
            context=ctx,
            patch=False,
            enforce_context=False,
        )

        await self._post_action_side_effects(
            action=N8NAction.UPDATE_NODE,
            context=ctx,
            result=result,
            target={"workflow_id": str(workflow_id), "node": node_name_or_id},
        )

        if result["success"]:
            result["message"] = "Node updated in n8n workflow successfully."

        return result

    async def remove_node(
        self,
        workflow_id: Union[str, int],
        node_name_or_id: str,
        context: Union[TaskContext, Mapping[str, Any]],
        remove_connections: bool = True,
    ) -> Dict[str, Any]:
        """Remove a node and optionally remove all connections referencing it."""
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        if not node_name_or_id:
            return self._error_result("node_name_or_id is required.", "missing_node_identifier")

        workflow_result = await self.get_workflow(workflow_id, ctx, enforce_context=True)
        if not workflow_result["success"]:
            return workflow_result

        workflow = copy.deepcopy(workflow_result["data"])
        nodes = workflow.get("nodes") or []

        target_node_name: Optional[str] = None
        new_nodes = []

        for node in nodes:
            if not isinstance(node, Mapping):
                new_nodes.append(node)
                continue

            if str(node.get("id")) == str(node_name_or_id) or str(node.get("name")) == str(node_name_or_id):
                target_node_name = str(node.get("name"))
                continue

            new_nodes.append(node)

        if not target_node_name:
            return self._error_result(
                message=f"Node '{node_name_or_id}' was not found in workflow.",
                code="node_not_found",
                metadata={"request_id": ctx.request_id},
            )

        workflow["nodes"] = new_nodes

        if remove_connections:
            workflow["connections"] = self._remove_node_connections(
                connections=workflow.get("connections") or {},
                node_name=target_node_name,
            )

        result = await self.update_workflow(
            workflow_id=workflow_id,
            workflow_updates=self._strip_readonly_workflow_fields(workflow),
            context=ctx,
            patch=False,
            enforce_context=False,
        )

        await self._post_action_side_effects(
            action=N8NAction.REMOVE_NODE,
            context=ctx,
            result=result,
            target={"workflow_id": str(workflow_id), "node": node_name_or_id},
        )

        if result["success"]:
            result["message"] = "Node removed from n8n workflow successfully."

        return result

    async def connect_nodes(
        self,
        workflow_id: Union[str, int],
        source_node_name: str,
        target_node_name: str,
        context: Union[TaskContext, Mapping[str, Any]],
        connection_type: Union[N8NNodeConnectionType, str] = N8NNodeConnectionType.MAIN,
        source_output_index: int = 0,
        target_input_index: int = 0,
    ) -> Dict[str, Any]:
        """
        Connect two nodes in an n8n workflow.

        n8n connection shape:
            connections[source_node][connection_type][source_output_index].append({
                "node": target_node_name,
                "type": connection_type,
                "index": target_input_index
            })
        """
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        if not source_node_name or not target_node_name:
            return self._error_result(
                message="source_node_name and target_node_name are required.",
                code="missing_connection_nodes",
            )

        connection_type_str = str(connection_type.value if isinstance(connection_type, N8NNodeConnectionType) else connection_type)

        workflow_result = await self.get_workflow(workflow_id, ctx, enforce_context=True)
        if not workflow_result["success"]:
            return workflow_result

        workflow = copy.deepcopy(workflow_result["data"])
        node_names = {str(node.get("name")) for node in workflow.get("nodes", []) if isinstance(node, Mapping)}

        if source_node_name not in node_names:
            return self._error_result(f"Source node '{source_node_name}' was not found.", "source_node_not_found")

        if target_node_name not in node_names:
            return self._error_result(f"Target node '{target_node_name}' was not found.", "target_node_not_found")

        connections = copy.deepcopy(workflow.get("connections") or {})
        source_connections = connections.setdefault(source_node_name, {})
        typed_connections = source_connections.setdefault(connection_type_str, [])

        while len(typed_connections) <= source_output_index:
            typed_connections.append([])

        edge = {
            "node": target_node_name,
            "type": connection_type_str,
            "index": int(target_input_index),
        }

        if edge not in typed_connections[source_output_index]:
            typed_connections[source_output_index].append(edge)

        workflow["connections"] = connections

        result = await self.update_workflow(
            workflow_id=workflow_id,
            workflow_updates=self._strip_readonly_workflow_fields(workflow),
            context=ctx,
            patch=False,
            enforce_context=False,
        )

        await self._post_action_side_effects(
            action=N8NAction.CONNECT_NODES,
            context=ctx,
            result=result,
            target={
                "workflow_id": str(workflow_id),
                "source_node": source_node_name,
                "target_node": target_node_name,
                "connection_type": connection_type_str,
            },
        )

        if result["success"]:
            result["message"] = "Nodes connected in n8n workflow successfully."

        return result

    async def disconnect_nodes(
        self,
        workflow_id: Union[str, int],
        source_node_name: str,
        target_node_name: str,
        context: Union[TaskContext, Mapping[str, Any]],
        connection_type: Union[N8NNodeConnectionType, str] = N8NNodeConnectionType.MAIN,
    ) -> Dict[str, Any]:
        """Remove connection edges from source node to target node."""
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        connection_type_str = str(connection_type.value if isinstance(connection_type, N8NNodeConnectionType) else connection_type)

        workflow_result = await self.get_workflow(workflow_id, ctx, enforce_context=True)
        if not workflow_result["success"]:
            return workflow_result

        workflow = copy.deepcopy(workflow_result["data"])
        connections = copy.deepcopy(workflow.get("connections") or {})

        if source_node_name not in connections:
            return self._error_result(
                message=f"No connections found for source node '{source_node_name}'.",
                code="connection_not_found",
            )

        source_connections = connections.get(source_node_name, {})
        typed_connections = source_connections.get(connection_type_str, [])

        removed_count = 0
        for output_index, edge_list in enumerate(typed_connections):
            if not isinstance(edge_list, list):
                continue

            before = len(edge_list)
            typed_connections[output_index] = [
                edge for edge in edge_list
                if not (isinstance(edge, Mapping) and str(edge.get("node")) == target_node_name)
            ]
            removed_count += before - len(typed_connections[output_index])

        if removed_count <= 0:
            return self._error_result(
                message=f"No connection found from '{source_node_name}' to '{target_node_name}'.",
                code="connection_not_found",
            )

        workflow["connections"] = connections

        result = await self.update_workflow(
            workflow_id=workflow_id,
            workflow_updates=self._strip_readonly_workflow_fields(workflow),
            context=ctx,
            patch=False,
            enforce_context=False,
        )

        await self._post_action_side_effects(
            action=N8NAction.DISCONNECT_NODES,
            context=ctx,
            result=result,
            target={
                "workflow_id": str(workflow_id),
                "source_node": source_node_name,
                "target_node": target_node_name,
                "connection_type": connection_type_str,
                "removed_count": removed_count,
            },
        )

        if result["success"]:
            result["message"] = "Nodes disconnected in n8n workflow successfully."

        return result

    # -----------------------------------------------------------------------
    # Public API: executions
    # -----------------------------------------------------------------------

    async def list_executions(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        workflow_id: Optional[Union[str, int]] = None,
        status: Optional[str] = None,
        limit: int = 50,
        cursor: Optional[str] = None,
        include_data: bool = False,
    ) -> Dict[str, Any]:
        """List n8n executions with optional workflow/status filters."""
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        safe_limit = min(max(int(limit or 50), 1), self.config.max_page_size)

        query: Dict[str, Any] = {
            "limit": safe_limit,
            "includeData": "true" if include_data else "false",
        }

        if workflow_id is not None:
            workflow_id_str = self._validate_id(workflow_id, "workflow_id")
            if isinstance(workflow_id_str, dict):
                return workflow_id_str
            query["workflowId"] = workflow_id_str

        if status:
            query["status"] = status

        if cursor:
            query["cursor"] = cursor

        result = await self._run_http_action(
            action=N8NAction.LIST_EXECUTIONS,
            context=ctx,
            method=N8NHttpMethod.GET,
            path="/executions",
            query=query,
            security_payload={"operation": "list_executions", "workflow_id": workflow_id, "status": status},
        )

        if result["success"]:
            result["message"] = "n8n executions retrieved successfully."

        return result

    async def get_execution(
        self,
        execution_id: Union[str, int],
        context: Union[TaskContext, Mapping[str, Any]],
        include_data: bool = True,
    ) -> Dict[str, Any]:
        """Get one n8n execution by ID."""
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        execution_id_str = self._validate_id(execution_id, "execution_id")
        if isinstance(execution_id_str, dict):
            return execution_id_str

        result = await self._run_http_action(
            action=N8NAction.GET_EXECUTION,
            context=ctx,
            method=N8NHttpMethod.GET,
            path=f"/executions/{execution_id_str}",
            query={"includeData": "true" if include_data else "false"},
            security_payload={"execution_id": execution_id_str},
        )

        if result["success"]:
            result["message"] = "n8n execution retrieved successfully."

        return result

    async def delete_execution(
        self,
        execution_id: Union[str, int],
        context: Union[TaskContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Delete an execution record from n8n.

        Blocked unless config.allow_delete=True.
        """
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        if not self.config.allow_delete:
            return self._error_result(
                message="Execution deletion is disabled by connector configuration.",
                code="delete_disabled",
                metadata={"request_id": ctx.request_id},
            )

        execution_id_str = self._validate_id(execution_id, "execution_id")
        if isinstance(execution_id_str, dict):
            return execution_id_str

        result = await self._run_http_action(
            action=N8NAction.DELETE_EXECUTION,
            context=ctx,
            method=N8NHttpMethod.DELETE,
            path=f"/executions/{execution_id_str}",
            security_payload={
                "operation": "delete_execution",
                "execution_id": execution_id_str,
                "destructive": True,
            },
        )

        await self._post_action_side_effects(
            action=N8NAction.DELETE_EXECUTION,
            context=ctx,
            result=result,
            target={"execution_id": execution_id_str},
        )

        if result["success"]:
            result["message"] = "n8n execution deleted successfully."

        return result

    async def execute_workflow(
        self,
        workflow_id: Union[str, int],
        context: Union[TaskContext, Mapping[str, Any]],
        payload: Optional[Mapping[str, Any]] = None,
        enforce_context: bool = True,
    ) -> Dict[str, Any]:
        """
        Execute workflow manually when supported/enabled.

        Important:
            n8n manual execution endpoints can vary by n8n version. This method
            is deliberately guarded by config.allow_manual_execution. For many
            production setups, execution should happen through webhook triggers
            created by workflow_builder/webhook_manager instead.
        """
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        if not self.config.allow_manual_execution:
            return self._error_result(
                message=(
                    "Manual workflow execution is disabled. Use webhook-triggered "
                    "workflow execution or set N8N_ALLOW_MANUAL_EXECUTION=true."
                ),
                code="manual_execution_disabled",
                metadata={"request_id": ctx.request_id},
            )

        workflow_id_str = self._validate_id(workflow_id, "workflow_id")
        if isinstance(workflow_id_str, dict):
            return workflow_id_str

        if enforce_context:
            existing_result = await self.get_workflow(workflow_id_str, ctx, enforce_context=True)
            if not existing_result["success"]:
                return existing_result

        result = await self._run_http_action(
            action=N8NAction.EXECUTE_WORKFLOW,
            context=ctx,
            method=N8NHttpMethod.POST,
            path=f"/workflows/{workflow_id_str}/execute",
            body=dict(payload or {}),
            security_payload={
                "operation": "execute_workflow",
                "workflow_id": workflow_id_str,
                "payload_keys": list((payload or {}).keys()),
            },
        )

        await self._post_action_side_effects(
            action=N8NAction.EXECUTE_WORKFLOW,
            context=ctx,
            result=result,
            target={"workflow_id": workflow_id_str},
        )

        if result["success"]:
            result["message"] = "n8n workflow execution requested successfully."

        return result

    # -----------------------------------------------------------------------
    # Public sync wrappers
    # -----------------------------------------------------------------------

    def health_check_sync(self, context: Union[TaskContext, Mapping[str, Any]]) -> Dict[str, Any]:
        """Synchronous wrapper for health_check."""
        return self._run_sync(self.health_check(context))

    def list_workflows_sync(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        limit: int = 50,
        cursor: Optional[str] = None,
        active: Optional[bool] = None,
        tags: Optional[List[str]] = None,
        include_all: bool = False,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for list_workflows."""
        return self._run_sync(self.list_workflows(context, limit, cursor, active, tags, include_all))

    def get_workflow_sync(
        self,
        workflow_id: Union[str, int],
        context: Union[TaskContext, Mapping[str, Any]],
        enforce_context: bool = True,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for get_workflow."""
        return self._run_sync(self.get_workflow(workflow_id, context, enforce_context))

    def create_workflow_sync(
        self,
        workflow: Mapping[str, Any],
        context: Union[TaskContext, Mapping[str, Any]],
        activate: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for create_workflow."""
        return self._run_sync(self.create_workflow(workflow, context, activate))

    def update_workflow_sync(
        self,
        workflow_id: Union[str, int],
        workflow_updates: Mapping[str, Any],
        context: Union[TaskContext, Mapping[str, Any]],
        patch: bool = False,
        enforce_context: bool = True,
    ) -> Dict[str, Any]:
        """Synchronous wrapper for update_workflow."""
        return self._run_sync(self.update_workflow(workflow_id, workflow_updates, context, patch, enforce_context))

    # -----------------------------------------------------------------------
    # Internal action runners
    # -----------------------------------------------------------------------

    async def _set_workflow_active_state(
        self,
        workflow_id: Union[str, int],
        context: Union[TaskContext, Mapping[str, Any]],
        active: bool,
        enforce_context: bool = True,
    ) -> Dict[str, Any]:
        """Internal activation/deactivation method."""
        ctx_result = self._get_valid_context_or_error(context)
        if isinstance(ctx_result, dict):
            return ctx_result
        ctx = ctx_result

        workflow_id_str = self._validate_id(workflow_id, "workflow_id")
        if isinstance(workflow_id_str, dict):
            return workflow_id_str

        if enforce_context:
            existing_result = await self.get_workflow(workflow_id_str, ctx, enforce_context=True)
            if not existing_result["success"]:
                return existing_result

        action = N8NAction.ACTIVATE_WORKFLOW if active else N8NAction.DEACTIVATE_WORKFLOW

        result = await self._run_http_action(
            action=action,
            context=ctx,
            method=N8NHttpMethod.PATCH,
            path=f"/workflows/{workflow_id_str}",
            body={
                "active": bool(active),
                "settings": self._tenant_settings(ctx),
            },
            security_payload={
                "operation": action.value,
                "workflow_id": workflow_id_str,
                "active": bool(active),
            },
        )

        await self._post_action_side_effects(
            action=action,
            context=ctx,
            result=result,
            target={"workflow_id": workflow_id_str, "active": bool(active)},
        )

        if result["success"]:
            result["message"] = "n8n workflow activated successfully." if active else "n8n workflow deactivated successfully."

        return result

    async def _run_http_action(
        self,
        action: N8NAction,
        context: TaskContext,
        method: N8NHttpMethod,
        path: str,
        query: Optional[Mapping[str, Any]] = None,
        body: Optional[Mapping[str, Any]] = None,
        security_payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Validate security, run HTTP request, return structured result."""
        start_time = time.time()

        self._emit_agent_event(
            event_name=f"n8n.{action.value}.started",
            context=context,
            payload={
                "method": method.value,
                "path": path,
                "query": dict(query or {}),
            },
        )

        if self._requires_security_check(action):
            approval = await self._request_security_approval(
                action=action,
                context=context,
                payload={
                    "method": method.value,
                    "path": path,
                    "query": dict(query or {}),
                    "body": self._redact_sensitive(dict(body or {})),
                    **dict(security_payload or {}),
                },
            )
            if not approval.get("approved"):
                result = self._error_result(
                    message=f"Security approval denied for action '{action.value}'.",
                    code="security_denied",
                    details=approval,
                    metadata={
                        "request_id": context.request_id,
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                    },
                )
                self._log_audit_event(action, context, False, result["message"], approval)
                self._emit_agent_event(f"n8n.{action.value}.denied", context, result)
                return result

        if not self.config.api_key:
            result = self._error_result(
                message="Missing n8n API key. Set N8N_API_KEY or pass it through N8NConnectorConfig.",
                code="missing_n8n_api_key",
                metadata={"request_id": context.request_id},
            )
            self._log_audit_event(action, context, False, result["message"], {"path": path})
            return result

        try:
            response_data, status_code, response_headers = await self._request(
                method=method,
                path=path,
                query=query,
                body=body,
            )

            duration_ms = int((time.time() - start_time) * 1000)

            if 200 <= status_code < 300:
                result = self._safe_result(
                    success=True,
                    message=f"n8n action '{action.value}' completed successfully.",
                    data=response_data,
                    metadata={
                        "request_id": context.request_id,
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                        "http_status": status_code,
                        "duration_ms": duration_ms,
                        "response_headers": self._safe_response_headers(response_headers),
                    },
                )
                self._log_audit_event(action, context, True, result["message"], {"path": path, "status": status_code})
                self._emit_agent_event(f"n8n.{action.value}.completed", context, result)
                return result

            result = self._error_result(
                message=f"n8n API returned HTTP {status_code} for action '{action.value}'.",
                code="n8n_http_error",
                details=response_data,
                metadata={
                    "request_id": context.request_id,
                    "http_status": status_code,
                    "duration_ms": duration_ms,
                },
            )
            self._log_audit_event(action, context, False, result["message"], {"path": path, "status": status_code})
            self._emit_agent_event(f"n8n.{action.value}.failed", context, result)
            return result

        except Exception as exc:
            duration_ms = int((time.time() - start_time) * 1000)
            self.logger.exception("n8n action failed: %s", action.value)
            result = self._error_result(
                message=f"n8n action '{action.value}' failed: {exc}",
                code="n8n_request_exception",
                details={"exception": exc.__class__.__name__},
                metadata={
                    "request_id": context.request_id,
                    "duration_ms": duration_ms,
                },
            )
            self._log_audit_event(action, context, False, result["message"], {"path": path})
            self._emit_agent_event(f"n8n.{action.value}.failed", context, result)
            return result

    async def _request(
        self,
        method: N8NHttpMethod,
        path: str,
        query: Optional[Mapping[str, Any]] = None,
        body: Optional[Mapping[str, Any]] = None,
    ) -> Tuple[Any, int, Mapping[str, Any]]:
        """
        Execute HTTP request.

        Uses:
            1. injected http_client when provided
            2. httpx when installed
            3. urllib fallback
        """
        url = self._build_url(path, query)
        headers = self._headers()

        if self.http_client is not None:
            return await self._request_with_injected_client(method, url, headers, body)

        if httpx is not None:
            return await self._request_with_httpx(method, url, headers, body)

        return await self._request_with_urllib(method, url, headers, body)

    async def _request_with_injected_client(
        self,
        method: N8NHttpMethod,
        url: str,
        headers: Mapping[str, str],
        body: Optional[Mapping[str, Any]],
    ) -> Tuple[Any, int, Mapping[str, Any]]:
        """Request through injected client for tests or custom transports."""
        client = self.http_client

        if hasattr(client, "request"):
            response = client.request(method.value, url, headers=dict(headers), json=dict(body) if body is not None else None)
            if asyncio.iscoroutine(response):
                response = await response

            status_code = int(getattr(response, "status_code", 200))
            response_headers = dict(getattr(response, "headers", {}) or {})

            if hasattr(response, "json"):
                try:
                    data = response.json()
                    if asyncio.iscoroutine(data):
                        data = await data
                except Exception:
                    text = getattr(response, "text", "")
                    data = {"raw": text}
            else:
                data = response

            return data, status_code, response_headers

        if callable(client):
            response = client(method.value, url, dict(headers), dict(body) if body is not None else None)
            if asyncio.iscoroutine(response):
                response = await response

            if isinstance(response, tuple) and len(response) >= 2:
                data = response[0]
                status_code = int(response[1])
                response_headers = response[2] if len(response) >= 3 else {}
                return data, status_code, dict(response_headers or {})

            return response, 200, {}

        raise RuntimeError("Injected http_client must be callable or expose request().")

    async def _request_with_httpx(
        self,
        method: N8NHttpMethod,
        url: str,
        headers: Mapping[str, str],
        body: Optional[Mapping[str, Any]],
    ) -> Tuple[Any, int, Mapping[str, Any]]:
        """Request through httpx async client."""
        async with httpx.AsyncClient(timeout=self.config.timeout_seconds, verify=self.config.verify_ssl) as client:  # type: ignore[union-attr]
            response = await client.request(
                method=method.value,
                url=url,
                headers=dict(headers),
                json=dict(body) if body is not None else None,
            )

            try:
                data = response.json()
            except Exception:
                data = {"raw": response.text}

            return data, int(response.status_code), dict(response.headers)

    async def _request_with_urllib(
        self,
        method: N8NHttpMethod,
        url: str,
        headers: Mapping[str, str],
        body: Optional[Mapping[str, Any]],
    ) -> Tuple[Any, int, Mapping[str, Any]]:
        """Request through urllib fallback in executor-friendly async wrapper."""
        return await asyncio.to_thread(self._request_with_urllib_sync, method, url, headers, body)

    def _request_with_urllib_sync(
        self,
        method: N8NHttpMethod,
        url: str,
        headers: Mapping[str, str],
        body: Optional[Mapping[str, Any]],
    ) -> Tuple[Any, int, Mapping[str, Any]]:
        """Synchronous urllib request implementation."""
        payload: Optional[bytes] = None

        if body is not None:
            payload = json.dumps(dict(body)).encode("utf-8")

        request = Request(
            url=url,
            data=payload,
            headers=dict(headers),
            method=method.value,
        )

        try:
            with urlopen(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read().decode("utf-8")
                status_code = int(response.getcode())
                response_headers = dict(response.headers.items())

                try:
                    data = json.loads(raw) if raw else None
                except Exception:
                    data = {"raw": raw}

                return data, status_code, response_headers

        except HTTPError as exc:
            raw = exc.read().decode("utf-8") if exc.fp else ""
            try:
                data = json.loads(raw) if raw else {"error": str(exc)}
            except Exception:
                data = {"raw": raw, "error": str(exc)}

            return data, int(exc.code), dict(exc.headers.items()) if exc.headers else {}

        except URLError as exc:
            raise RuntimeError(f"Unable to reach n8n API: {exc}") from exc

    # -----------------------------------------------------------------------
    # Side effects
    # -----------------------------------------------------------------------

    async def _post_action_side_effects(
        self,
        action: N8NAction,
        context: TaskContext,
        result: Mapping[str, Any],
        target: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Send Verification and Memory compatible payloads after important actions.

        Best-effort only. This never breaks the main workflow response.
        """
        verification_payload = self._prepare_verification_payload(action, context, result, target)
        memory_payload = self._prepare_memory_payload(action, context, result)

        if self.verification_agent is not None:
            try:
                if hasattr(self.verification_agent, "submit"):
                    response = self.verification_agent.submit(verification_payload)
                    if asyncio.iscoroutine(response):
                        await response
                elif hasattr(self.verification_agent, "verify"):
                    response = self.verification_agent.verify(verification_payload)
                    if asyncio.iscoroutine(response):
                        await response
            except Exception:
                self.logger.exception("Failed to submit verification payload.")

        if self.memory_agent is not None and result.get("success"):
            try:
                if hasattr(self.memory_agent, "store"):
                    response = self.memory_agent.store(memory_payload)
                    if asyncio.iscoroutine(response):
                        await response
                elif hasattr(self.memory_agent, "remember"):
                    response = self.memory_agent.remember(memory_payload)
                    if asyncio.iscoroutine(response):
                        await response
            except Exception:
                self.logger.exception("Failed to submit memory payload.")

    # -----------------------------------------------------------------------
    # Validation and context helpers
    # -----------------------------------------------------------------------

    def _get_valid_context_or_error(
        self,
        context: Union[TaskContext, Mapping[str, Any], None],
    ) -> Union[TaskContext, Dict[str, Any]]:
        """Return TaskContext or structured error."""
        is_valid, task_context, error = self._validate_task_context(context)
        if not is_valid or task_context is None:
            return self._error_result(
                message=error or "Invalid task context.",
                code="invalid_task_context",
            )
        return task_context

    def _validate_id(self, value: Union[str, int], field_name: str) -> Union[str, Dict[str, Any]]:
        """Validate n8n identifier."""
        value_str = str(value or "").strip()
        if not value_str:
            return self._error_result(
                message=f"{field_name} is required.",
                code=f"missing_{field_name}",
            )

        if len(value_str) > 256:
            return self._error_result(
                message=f"{field_name} is too long.",
                code=f"invalid_{field_name}",
            )

        return value_str

    def _validate_workflow_payload(
        self,
        workflow: Mapping[str, Any],
        creating: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Validate workflow payload shape."""
        if not isinstance(workflow, Mapping):
            return self._error_result("workflow must be a mapping/dict.", "invalid_workflow_payload")

        if creating and not str(workflow.get("name") or "").strip():
            return self._error_result("workflow.name is required.", "missing_workflow_name")

        if "nodes" in workflow and not isinstance(workflow.get("nodes"), list):
            return self._error_result("workflow.nodes must be a list.", "invalid_workflow_nodes")

        if "connections" in workflow and not isinstance(workflow.get("connections"), Mapping):
            return self._error_result("workflow.connections must be a mapping.", "invalid_workflow_connections")

        return None

    def _validate_node_payload(self, node: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        """Validate n8n node payload."""
        if not isinstance(node, Mapping):
            return self._error_result("node must be a mapping/dict.", "invalid_node_payload")

        if not str(node.get("type") or "").strip():
            return self._error_result("node.type is required.", "missing_node_type")

        if "parameters" in node and not isinstance(node.get("parameters"), Mapping):
            return self._error_result("node.parameters must be a mapping.", "invalid_node_parameters")

        if "position" in node:
            position = node.get("position")
            if not (
                isinstance(position, list)
                and len(position) == 2
                and all(isinstance(item, (int, float)) for item in position)
            ):
                return self._error_result("node.position must be a [x, y] number list.", "invalid_node_position")

        return None

    # -----------------------------------------------------------------------
    # Workflow context isolation
    # -----------------------------------------------------------------------

    def _prepare_workflow_payload_for_context(
        self,
        workflow: Mapping[str, Any],
        context: TaskContext,
        active: Optional[bool] = None,
        partial: bool = False,
    ) -> Dict[str, Any]:
        """
        Add William/Jarvis tenant metadata to workflow payload.

        n8n does not provide native SaaS workspace isolation for this external
        app. These metadata markers allow William dashboard/services to filter
        and verify ownership.
        """
        prepared = copy.deepcopy(dict(workflow))

        if active is not None:
            prepared["active"] = bool(active)

        if not partial:
            prepared.setdefault("nodes", [])
            prepared.setdefault("connections", {})
            prepared.setdefault("settings", {})

        prepared["settings"] = {
            **dict(prepared.get("settings") or {}),
            **self._tenant_settings(context),
        }

        static_data = dict(prepared.get("staticData") or {})
        static_data["william"] = {
            **dict(static_data.get("william") or {}),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "managed_by": self.agent_name,
            "updated_at": self._utc_now(),
        }
        prepared["staticData"] = static_data

        # Add a safe marker into workflow meta when supported by n8n versions.
        meta = dict(prepared.get("meta") or {})
        meta["william_user_id"] = context.user_id
        meta["william_workspace_id"] = context.workspace_id
        meta["william_managed"] = True
        prepared["meta"] = meta

        return prepared

    def _tenant_settings(self, context: TaskContext) -> Dict[str, Any]:
        """Return tenant settings marker."""
        return {
            "williamUserId": context.user_id,
            "williamWorkspaceId": context.workspace_id,
            "williamManaged": True,
        }

    def _workflow_belongs_to_context(self, workflow: Mapping[str, Any], context: TaskContext) -> bool:
        """
        Check whether workflow contains William user/workspace markers.

        If no William markers exist, deny by default to avoid cross-tenant access.
        """
        settings = dict(workflow.get("settings") or {})
        static_data = dict(workflow.get("staticData") or {})
        william_static = dict(static_data.get("william") or {})
        meta = dict(workflow.get("meta") or {})

        candidates = [
            (
                settings.get("williamUserId"),
                settings.get("williamWorkspaceId"),
            ),
            (
                william_static.get("user_id"),
                william_static.get("workspace_id"),
            ),
            (
                meta.get("william_user_id"),
                meta.get("william_workspace_id"),
            ),
        ]

        for user_id, workspace_id in candidates:
            if str(user_id or "") == context.user_id and str(workspace_id or "") == context.workspace_id:
                return True

        return False

    def _filter_workflows_for_context(
        self,
        raw_data: Any,
        context: TaskContext,
        include_all: bool = False,
    ) -> Any:
        """
        Filter list response to current context.

        include_all is intended for admin dashboards only and still requires the
        caller to intentionally pass it.
        """
        if include_all:
            return raw_data

        if isinstance(raw_data, Mapping):
            data_copy = copy.deepcopy(dict(raw_data))
            workflows = data_copy.get("data")

            if isinstance(workflows, list):
                data_copy["data"] = [
                    workflow for workflow in workflows
                    if isinstance(workflow, Mapping) and self._workflow_belongs_to_context(workflow, context)
                ]
                data_copy["filteredByWilliamContext"] = True
                return data_copy

            if isinstance(workflows, Mapping):
                if self._workflow_belongs_to_context(workflows, context):
                    return data_copy
                data_copy["data"] = None
                data_copy["filteredByWilliamContext"] = True
                return data_copy

        if isinstance(raw_data, list):
            return [
                workflow for workflow in raw_data
                if isinstance(workflow, Mapping) and self._workflow_belongs_to_context(workflow, context)
            ]

        return raw_data

    # -----------------------------------------------------------------------
    # Workflow JSON utilities
    # -----------------------------------------------------------------------

    def _strip_readonly_workflow_fields(self, workflow: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Remove read-only fields that n8n may reject during update.

        Different n8n versions return fields that should not be sent back.
        """
        readonly_fields = {
            "id",
            "createdAt",
            "updatedAt",
            "versionId",
            "shared",
            "ownedBy",
            "homeProject",
            "scopes",
            "usedCredentials",
            "triggerCount",
        }

        cleaned = copy.deepcopy(dict(workflow))
        for field_name in readonly_fields:
            cleaned.pop(field_name, None)

        return cleaned

    def _remove_node_connections(self, connections: Mapping[str, Any], node_name: str) -> Dict[str, Any]:
        """Remove all outgoing/incoming connections involving a node."""
        cleaned = copy.deepcopy(dict(connections or {}))

        cleaned.pop(node_name, None)

        for source_name, source_connections in list(cleaned.items()):
            if not isinstance(source_connections, Mapping):
                continue

            for connection_type, output_groups in list(source_connections.items()):
                if not isinstance(output_groups, list):
                    continue

                for output_index, edges in enumerate(output_groups):
                    if not isinstance(edges, list):
                        continue

                    output_groups[output_index] = [
                        edge for edge in edges
                        if not (isinstance(edge, Mapping) and str(edge.get("node")) == node_name)
                    ]

                source_connections[connection_type] = output_groups

            cleaned[source_name] = dict(source_connections)

        return cleaned

    # -----------------------------------------------------------------------
    # HTTP helpers
    # -----------------------------------------------------------------------

    def _build_url(self, path: str, query: Optional[Mapping[str, Any]] = None) -> str:
        """Build full n8n API URL."""
        clean_path = path if path.startswith("/") else f"/{path}"
        base = f"{self.config.normalized_base_url()}{self.config.normalized_api_prefix()}/"
        url = urljoin(base, clean_path.lstrip("/"))

        if query:
            safe_query = {
                key: value
                for key, value in dict(query).items()
                if value is not None
            }
            if safe_query:
                url = f"{url}?{urlencode(safe_query, doseq=True)}"

        return url

    def _headers(self) -> Dict[str, str]:
        """Build n8n API headers."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": self.config.user_agent,
        }

        if self.config.api_key:
            headers["X-N8N-API-KEY"] = self.config.api_key

        return headers

    def _safe_response_headers(self, headers: Mapping[str, Any]) -> Dict[str, Any]:
        """Return non-sensitive response headers."""
        blocked = {"authorization", "set-cookie", "cookie", "x-n8n-api-key"}
        return {
            key: value
            for key, value in dict(headers or {}).items()
            if str(key).lower() not in blocked
        }

    # -----------------------------------------------------------------------
    # Generic helpers
    # -----------------------------------------------------------------------

    def _new_request_id(self) -> str:
        """Create connector request ID."""
        return f"{self.config.request_id_prefix}_{uuid.uuid4().hex}"

    def _utc_now(self) -> str:
        """UTC timestamp in ISO format."""
        return datetime.now(timezone.utc).isoformat()

    def _normalize_security_response(self, response: Any) -> Dict[str, Any]:
        """Normalize different Security Agent response shapes."""
        if isinstance(response, Mapping):
            approved = bool(
                response.get("approved")
                or response.get("allowed")
                or response.get("success")
                or response.get("is_allowed")
            )
            return {
                "approved": approved,
                "reason": response.get("reason") or response.get("message") or "Security Agent response received.",
                "source": response.get("source") or "security_agent",
                "raw": self._redact_sensitive(dict(response)),
            }

        if isinstance(response, bool):
            return {
                "approved": response,
                "reason": "Boolean Security Agent response.",
                "source": "security_agent",
            }

        return {
            "approved": False,
            "reason": "Unrecognized Security Agent response.",
            "source": "security_agent",
            "raw": str(response),
        }

    def _redact_sensitive(self, value: Any) -> Any:
        """Recursively redact secrets before logs/events/memory."""
        sensitive_keys = {
            "api_key",
            "apikey",
            "x-n8n-api-key",
            "authorization",
            "password",
            "secret",
            "token",
            "access_token",
            "refresh_token",
            "credential",
            "credentials",
            "cookie",
            "set-cookie",
        }

        if isinstance(value, Mapping):
            redacted = {}
            for key, item in value.items():
                key_str = str(key)
                if key_str.lower() in sensitive_keys or any(part in key_str.lower() for part in ["secret", "token", "password", "api_key"]):
                    redacted[key] = "***REDACTED***"
                else:
                    redacted[key] = self._redact_sensitive(item)
            return redacted

        if isinstance(value, list):
            return [self._redact_sensitive(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self._redact_sensitive(item) for item in value)

        return value

    def _summarize_for_event(self, data: Any) -> Any:
        """Create compact safe summary for event/memory payloads."""
        data = self._redact_sensitive(data)

        if data is None:
            return None

        if isinstance(data, Mapping):
            summary: Dict[str, Any] = {}

            for key in [
                "id",
                "name",
                "active",
                "workflowId",
                "executionId",
                "status",
                "startedAt",
                "stoppedAt",
                "finished",
                "mode",
            ]:
                if key in data:
                    summary[key] = data[key]

            if "nodes" in data and isinstance(data["nodes"], list):
                summary["node_count"] = len(data["nodes"])

            if "connections" in data and isinstance(data["connections"], Mapping):
                summary["connection_source_count"] = len(data["connections"])

            if "data" in data and isinstance(data["data"], list):
                summary["items_count"] = len(data["data"])

            if not summary:
                keys = list(data.keys())[:15]
                summary["keys"] = keys

            return summary

        if isinstance(data, list):
            return {
                "items_count": len(data),
                "first_item_summary": self._summarize_for_event(data[0]) if data else None,
            }

        return data

    def _run_sync(self, coroutine: Any) -> Dict[str, Any]:
        """
        Run async method from sync code.

        If an event loop is already running, this cannot block safely. In that
        case, return a helpful error asking caller to use async API.
        """
        try:
            asyncio.get_running_loop()
            return self._error_result(
                message="Cannot use sync wrapper inside a running event loop. Use the async method instead.",
                code="event_loop_already_running",
            )
        except RuntimeError:
            return asyncio.run(coroutine)

    # -----------------------------------------------------------------------
    # Registry / dashboard metadata
    # -----------------------------------------------------------------------

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Return connector capabilities for Agent Registry, Dashboard, or API docs.
        """
        return {
            "agent": self.agent_name,
            "version": self.agent_version,
            "class": self.__class__.__name__,
            "capabilities": [
                "n8n_health_check",
                "n8n_list_workflows",
                "n8n_get_workflow",
                "n8n_create_workflow",
                "n8n_update_workflow",
                "n8n_activate_workflow",
                "n8n_deactivate_workflow",
                "n8n_delete_workflow",
                "n8n_add_node",
                "n8n_update_node",
                "n8n_remove_node",
                "n8n_connect_nodes",
                "n8n_disconnect_nodes",
                "n8n_list_executions",
                "n8n_get_execution",
                "n8n_delete_execution",
                "n8n_execute_workflow_guarded",
            ],
            "safety": {
                "requires_user_workspace_context": True,
                "requires_security_for_sensitive_actions": self.config.require_security_for_sensitive_actions,
                "delete_enabled": self.config.allow_delete,
                "manual_execution_enabled": self.config.allow_manual_execution,
            },
            "config": {
                "base_url_configured": bool(self.config.base_url),
                "api_key_configured": bool(self.config.api_key),
                "api_prefix": self.config.normalized_api_prefix(),
                "timeout_seconds": self.config.timeout_seconds,
                "verify_ssl": self.config.verify_ssl,
            },
        }


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------

def create_n8n_connector(
    config: Optional[Union[N8NConnectorConfig, Mapping[str, Any]]] = None,
    **kwargs: Any,
) -> N8NConnector:
    """
    Factory used by Agent Loader / Registry / FastAPI dependency injection.
    """
    return N8NConnector(config=config, **kwargs)


def get_default_n8n_connector() -> N8NConnector:
    """
    Build connector from environment variables.

    Environment variables:
        N8N_BASE_URL
        N8N_API_KEY
        N8N_API_PREFIX
        N8N_TIMEOUT_SECONDS
        N8N_VERIFY_SSL
        N8N_ALLOW_MANUAL_EXECUTION
        N8N_ALLOW_DELETE
    """
    return N8NConnector()


__all__ = [
    "N8NAction",
    "N8NHttpMethod",
    "N8NNodeConnectionType",
    "N8NConnectorConfig",
    "TaskContext",
    "N8NConnector",
    "create_n8n_connector",
    "get_default_n8n_connector",
]