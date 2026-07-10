"""
agents/workflow_agent/action_router.py

William / Jarvis Multi-Agent AI SaaS System
Workflow Agent - Action Router

Purpose:
    Routes workflow steps to connectors or agents.

This file is responsible for safely routing workflow action steps to:
    - Workflow connectors such as CRM, Sheet, Email, WhatsApp, Webhook, n8n, App connectors
    - Internal William/Jarvis agents such as Browser, Code, Memory, Finance, Business, Creator, etc.
    - Local callable handlers registered at runtime
    - Future plugin-style routes

Production design goals:
    - SaaS user/workspace isolation
    - Security Agent approval before sensitive actions
    - Verification Agent payload preparation after actions
    - Memory Agent payload preparation for useful workflow context
    - Master Agent / Agent Registry compatible structured outputs
    - Import-safe even if other William modules do not exist yet
    - No hardcoded secrets
    - No direct destructive, message, browser, financial, call, or system actions without permission gates

Public class:
    WorkflowActionRouter
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
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


# =============================================================================
# Safe optional imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe when the full William/Jarvis project is
        not yet generated. The real BaseAgent should provide richer event,
        memory, audit, registry, and routing integrations.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)

        async def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None

        async def log_audit(self, *args: Any, **kwargs: Any) -> None:
            return None


try:
    from agents.workflow_agent.n8n_connector import N8NConnector  # type: ignore
except Exception:  # pragma: no cover
    N8NConnector = None  # type: ignore

try:
    from agents.workflow_agent.app_connector import AppConnector  # type: ignore
except Exception:  # pragma: no cover
    AppConnector = None  # type: ignore

try:
    from agents.workflow_agent.webhook_manager import WebhookManager  # type: ignore
except Exception:  # pragma: no cover
    WebhookManager = None  # type: ignore

try:
    from agents.workflow_agent.crm_connector import CRMConnector  # type: ignore
except Exception:  # pragma: no cover
    CRMConnector = None  # type: ignore

try:
    from agents.workflow_agent.sheet_connector import SheetConnector  # type: ignore
except Exception:  # pragma: no cover
    SheetConnector = None  # type: ignore

try:
    from agents.workflow_agent.whatsapp_connector import WhatsAppConnector  # type: ignore
except Exception:  # pragma: no cover
    WhatsAppConnector = None  # type: ignore

try:
    from agents.workflow_agent.email_connector import EmailConnector  # type: ignore
except Exception:  # pragma: no cover
    EmailConnector = None  # type: ignore

try:
    from agents.workflow_agent.notification_engine import NotificationEngine  # type: ignore
except Exception:  # pragma: no cover
    NotificationEngine = None  # type: ignore


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# =============================================================================
# Constants and enums
# =============================================================================

class RouteKind(str, Enum):
    """Supported route categories for workflow actions."""

    CONNECTOR = "connector"
    AGENT = "agent"
    LOCAL_HANDLER = "local_handler"
    WEBHOOK = "webhook"
    N8N = "n8n"
    NOOP = "noop"
    UNKNOWN = "unknown"


class ActionRiskLevel(str, Enum):
    """Action risk levels used by Security Agent gates."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionStatus(str, Enum):
    """Normalized action execution status values."""

    PENDING = "pending"
    ROUTED = "routed"
    APPROVED = "approved"
    BLOCKED = "blocked"
    SKIPPED = "skipped"
    FAILED = "failed"
    COMPLETED = "completed"


SENSITIVE_ACTION_KEYWORDS: Tuple[str, ...] = (
    "send",
    "delete",
    "remove",
    "archive",
    "charge",
    "refund",
    "payment",
    "invoice",
    "transfer",
    "call",
    "sms",
    "whatsapp",
    "email",
    "browser",
    "login",
    "credential",
    "password",
    "secret",
    "token",
    "api_key",
    "webhook",
    "post",
    "put",
    "patch",
    "deploy",
    "system",
    "shell",
    "terminal",
    "finance",
    "bank",
    "crm_update",
    "lead_push",
)

DESTRUCTIVE_ACTION_KEYWORDS: Tuple[str, ...] = (
    "delete",
    "remove",
    "destroy",
    "drop",
    "truncate",
    "purge",
    "revoke",
    "disable",
    "cancel",
)

MESSAGE_ACTION_KEYWORDS: Tuple[str, ...] = (
    "send_email",
    "email.send",
    "send_whatsapp",
    "whatsapp.send",
    "send_sms",
    "sms.send",
    "notify",
    "message",
)

FINANCIAL_ACTION_KEYWORDS: Tuple[str, ...] = (
    "charge",
    "refund",
    "payment",
    "invoice",
    "subscription",
    "billing",
    "transfer",
    "payout",
)

BROWSER_ACTION_KEYWORDS: Tuple[str, ...] = (
    "browser",
    "visit",
    "click",
    "submit_form",
    "login",
    "scrape",
)

SYSTEM_ACTION_KEYWORDS: Tuple[str, ...] = (
    "system",
    "shell",
    "terminal",
    "command",
    "file_write",
    "file_delete",
    "deploy",
)

DEFAULT_TIMEOUT_SECONDS = 60


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class WorkflowActionContext:
    """
    Normalized SaaS execution context.

    user_id and workspace_id are mandatory for user-specific execution.
    request_id, workflow_id, run_id, and step_id make audit and dashboard tracking
    traceable across Master Agent, Workflow Agent, Security Agent, Verification
    Agent, Memory Agent, and dashboard/API systems.
    """

    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    workflow_id: Optional[str] = None
    run_id: Optional[str] = None
    step_id: Optional[str] = None
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    agent_permissions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "WorkflowActionContext":
        user_id = str(value.get("user_id") or "").strip()
        workspace_id = str(value.get("workspace_id") or "").strip()

        permissions_raw = value.get("permissions", [])
        if isinstance(permissions_raw, str):
            permissions = [permissions_raw]
        elif isinstance(permissions_raw, Iterable):
            permissions = [str(item) for item in permissions_raw if item is not None]
        else:
            permissions = []

        agent_permissions_raw = value.get("agent_permissions", {})
        agent_permissions = (
            dict(agent_permissions_raw)
            if isinstance(agent_permissions_raw, Mapping)
            else {}
        )

        metadata_raw = value.get("metadata", {})
        metadata = dict(metadata_raw) if isinstance(metadata_raw, Mapping) else {}

        return cls(
            user_id=user_id,
            workspace_id=workspace_id,
            request_id=str(value.get("request_id") or uuid.uuid4()),
            workflow_id=_optional_str(value.get("workflow_id")),
            run_id=_optional_str(value.get("run_id")),
            step_id=_optional_str(value.get("step_id")),
            role=_optional_str(value.get("role")),
            subscription_plan=_optional_str(value.get("subscription_plan")),
            permissions=permissions,
            agent_permissions=agent_permissions,
            metadata=metadata,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "request_id": self.request_id,
            "workflow_id": self.workflow_id,
            "run_id": self.run_id,
            "step_id": self.step_id,
            "role": self.role,
            "subscription_plan": self.subscription_plan,
            "permissions": list(self.permissions),
            "agent_permissions": dict(self.agent_permissions),
            "metadata": dict(self.metadata),
        }


@dataclass
class RouteTarget:
    """
    A resolved action target.

    target can be:
        - an instantiated connector
        - an instantiated agent
        - a callable function
        - None for noop/unknown routes
    """

    kind: RouteKind
    name: str
    target: Any = None
    method_name: Optional[str] = None
    risk_level: ActionRiskLevel = ActionRiskLevel.LOW
    requires_security: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ActionExecutionRecord:
    """Internal trace record for one routed workflow step."""

    action_id: str
    action_type: str
    route_kind: RouteKind
    target_name: str
    status: ActionStatus
    started_at: str
    finished_at: Optional[str] = None
    duration_ms: Optional[int] = None
    security_required: bool = False
    security_approved: Optional[bool] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Utility helpers
# =============================================================================

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _duration_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


def _optional_str(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _lower_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _safe_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _redact_sensitive(value: Any) -> Any:
    """
    Redact secrets before logs/audit/memory/verification payloads.

    This intentionally handles common nested dict/list shapes without mutating
    the original object.
    """

    sensitive_keys = {
        "password",
        "pass",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "credential",
        "credentials",
        "private_key",
        "client_secret",
    }

    if isinstance(value, Mapping):
        redacted: Dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in sensitive_keys or any(
                marker in key_text.lower()
                for marker in ("secret", "token", "password", "api_key", "credential")
            ):
                redacted[key_text] = "***REDACTED***"
            else:
                redacted[key_text] = _redact_sensitive(item)
        return redacted

    if isinstance(value, list):
        return [_redact_sensitive(item) for item in value]

    if isinstance(value, tuple):
        return tuple(_redact_sensitive(item) for item in value)

    return value


def _contains_keyword(text: str, keywords: Sequence[str]) -> bool:
    clean = _lower_text(text)
    return any(keyword in clean for keyword in keywords)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _method_exists(target: Any, method_name: Optional[str]) -> bool:
    if target is None or not method_name:
        return False
    return callable(getattr(target, method_name, None))


def _normalize_action_step(step: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Normalize common action step shapes from workflow_builder, trigger_engine,
    dashboard/API, or future external workflow JSON formats.
    """

    action = dict(step)

    action_id = (
        action.get("action_id")
        or action.get("id")
        or action.get("step_id")
        or str(uuid.uuid4())
    )
    action["action_id"] = str(action_id)

    action_type = (
        action.get("action_type")
        or action.get("type")
        or action.get("name")
        or action.get("operation")
        or "unknown"
    )
    action["action_type"] = str(action_type)

    action["connector"] = _optional_str(
        action.get("connector")
        or action.get("app")
        or action.get("service")
        or action.get("provider")
    )

    action["agent"] = _optional_str(
        action.get("agent")
        or action.get("target_agent")
        or action.get("agent_name")
    )

    action["method"] = _optional_str(
        action.get("method")
        or action.get("operation")
        or action.get("handler")
        or action.get("function")
    )

    params = (
        action.get("params")
        or action.get("parameters")
        or action.get("payload")
        or action.get("data")
        or {}
    )
    action["params"] = _safe_dict(params)

    action["metadata"] = _safe_dict(action.get("metadata"))

    return action


# =============================================================================
# Main router
# =============================================================================

class WorkflowActionRouter(BaseAgent):
    """
    Routes workflow steps to connectors or agents.

    How this connects to William/Jarvis architecture:
        - Master Agent can call route_action() or route_actions() to execute
          workflow steps.
        - Workflow Agent can use this class as the action execution brain after
          trigger_engine.py starts a workflow and workflow_builder.py creates a
          step plan.
        - Security Agent is consulted by _request_security_approval() before
          sensitive actions.
        - Verification Agent receives payloads prepared by
          _prepare_verification_payload().
        - Memory Agent can store useful non-secret execution context prepared by
          _prepare_memory_payload().
        - Dashboard/API can inspect structured results, audit metadata, timings,
          route details, and errors.
        - Agent Registry / Agent Loader can inject agent instances through
          register_agent() or constructor arguments.
    """

    router_name = "workflow_action_router"
    version = "1.0.0"

    def __init__(
        self,
        *,
        connector_registry: Optional[Mapping[str, Any]] = None,
        agent_registry: Optional[Mapping[str, Any]] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_emitter: Optional[Any] = None,
        default_timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        allow_unregistered_noop: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.router_name, **kwargs)

        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter

        self.default_timeout_seconds = max(1, int(default_timeout_seconds or DEFAULT_TIMEOUT_SECONDS))
        self.allow_unregistered_noop = bool(allow_unregistered_noop)

        self.connector_registry: Dict[str, Any] = {}
        self.agent_registry: Dict[str, Any] = {}
        self.local_handlers: Dict[str, Callable[..., Any]] = {}

        self._execution_history: List[ActionExecutionRecord] = []

        self._install_default_connector_placeholders()

        if connector_registry:
            for name, connector in connector_registry.items():
                self.register_connector(str(name), connector)

        if agent_registry:
            for name, agent in agent_registry.items():
                self.register_agent(str(name), agent)

        self._install_default_local_handlers()

    # -------------------------------------------------------------------------
    # Registry methods
    # -------------------------------------------------------------------------

    def register_connector(self, name: str, connector: Any) -> Dict[str, Any]:
        """Register a connector instance for future workflow action routing."""

        clean_name = self._normalize_route_name(name)
        if not clean_name:
            return self._error_result(
                message="Connector name is required.",
                error="invalid_connector_name",
                metadata={"input_name": name},
            )

        self.connector_registry[clean_name] = connector
        return self._safe_result(
            message=f"Connector registered: {clean_name}",
            data={"connector": clean_name},
        )

    def register_agent(self, name: str, agent: Any) -> Dict[str, Any]:
        """Register an agent instance for future workflow action routing."""

        clean_name = self._normalize_route_name(name)
        if not clean_name:
            return self._error_result(
                message="Agent name is required.",
                error="invalid_agent_name",
                metadata={"input_name": name},
            )

        self.agent_registry[clean_name] = agent
        return self._safe_result(
            message=f"Agent registered: {clean_name}",
            data={"agent": clean_name},
        )

    def register_handler(self, action_type: str, handler: Callable[..., Any]) -> Dict[str, Any]:
        """Register a local callable action handler."""

        clean_type = self._normalize_route_name(action_type)
        if not clean_type:
            return self._error_result(
                message="Action type is required.",
                error="invalid_action_type",
                metadata={"input_action_type": action_type},
            )

        if not callable(handler):
            return self._error_result(
                message="Handler must be callable.",
                error="invalid_handler",
                metadata={"action_type": clean_type},
            )

        self.local_handlers[clean_type] = handler
        return self._safe_result(
            message=f"Local handler registered: {clean_type}",
            data={"action_type": clean_type},
        )

    def list_routes(self) -> Dict[str, Any]:
        """Return currently known connectors, agents, and local handlers."""

        return self._safe_result(
            message="Available workflow action routes.",
            data={
                "connectors": sorted(self.connector_registry.keys()),
                "agents": sorted(self.agent_registry.keys()),
                "local_handlers": sorted(self.local_handlers.keys()),
                "router": self.router_name,
                "version": self.version,
            },
        )

    def get_execution_history(self, limit: int = 100) -> Dict[str, Any]:
        """Return recent in-memory execution records for dashboard/debugging."""

        safe_limit = max(1, min(int(limit or 100), 1000))
        records = self._execution_history[-safe_limit:]
        return self._safe_result(
            message="Workflow action execution history.",
            data={
                "records": [self._record_to_dict(record) for record in records],
                "count": len(records),
            },
        )

    # -------------------------------------------------------------------------
    # Main public execution methods
    # -------------------------------------------------------------------------

    async def route_action(
        self,
        action_step: Mapping[str, Any],
        context: Union[WorkflowActionContext, Mapping[str, Any]],
        *,
        dry_run: bool = False,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Route a single workflow action step to a connector, agent, webhook,
        n8n connector, or local handler.

        Args:
            action_step:
                Workflow step dictionary. Common supported fields:
                    - action_id / id / step_id
                    - action_type / type / operation
                    - connector / app / service / provider
                    - agent / target_agent / agent_name
                    - method / operation / handler / function
                    - params / parameters / payload / data
                    - metadata
                    - requires_security
                    - risk_level

            context:
                SaaS execution context with user_id and workspace_id.

            dry_run:
                If True, performs validation, route resolution, security
                classification, verification payload preparation, and audit event
                preparation without executing the target action.

            timeout_seconds:
                Optional per-action timeout.

        Returns:
            Structured dict:
                {
                    "success": bool,
                    "message": str,
                    "data": dict,
                    "error": Optional[str],
                    "metadata": dict
                }
        """

        started = time.monotonic()
        normalized_action = _normalize_action_step(action_step)
        action_id = normalized_action["action_id"]
        action_type = normalized_action["action_type"]

        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        action_context = context_result["data"]["context"]

        route = self._resolve_route(normalized_action)
        requires_security = self._requires_security_check(normalized_action, route)

        record = ActionExecutionRecord(
            action_id=action_id,
            action_type=action_type,
            route_kind=route.kind,
            target_name=route.name,
            status=ActionStatus.PENDING,
            started_at=_now_iso(),
            security_required=requires_security,
            metadata={
                "dry_run": dry_run,
                "workflow_id": action_context.workflow_id,
                "run_id": action_context.run_id,
                "step_id": action_context.step_id or normalized_action.get("step_id"),
            },
        )

        await self._emit_agent_event(
            event_type="workflow.action.routing_started",
            context=action_context,
            payload={
                "action_id": action_id,
                "action_type": action_type,
                "route_kind": route.kind.value,
                "route_name": route.name,
                "dry_run": dry_run,
            },
        )

        try:
            if route.kind == RouteKind.UNKNOWN:
                record.status = ActionStatus.SKIPPED if self.allow_unregistered_noop else ActionStatus.FAILED
                record.error = None if self.allow_unregistered_noop else "route_not_found"
                record.finished_at = _now_iso()
                record.duration_ms = _duration_ms(started)
                self._remember_record(record)

                if self.allow_unregistered_noop:
                    result = self._safe_result(
                        message="No route found for action; safely skipped as noop.",
                        data={
                            "action_id": action_id,
                            "action_type": action_type,
                            "route": self._route_to_dict(route),
                            "executed": False,
                            "skipped": True,
                        },
                        metadata=self._result_metadata(action_context, normalized_action, route, record),
                    )
                else:
                    result = self._error_result(
                        message="No route found for action.",
                        error="route_not_found",
                        data={
                            "action_id": action_id,
                            "action_type": action_type,
                            "route": self._route_to_dict(route),
                        },
                        metadata=self._result_metadata(action_context, normalized_action, route, record),
                    )

                await self._log_audit_event(
                    event_type="workflow.action.route_missing",
                    context=action_context,
                    payload=result,
                )
                return result

            if requires_security:
                approval = await self._request_security_approval(
                    action_step=normalized_action,
                    context=action_context,
                    route=route,
                    dry_run=dry_run,
                )
                record.security_approved = bool(approval.get("success"))

                if not approval.get("success"):
                    record.status = ActionStatus.BLOCKED
                    record.error = str(approval.get("error") or "security_approval_denied")
                    record.finished_at = _now_iso()
                    record.duration_ms = _duration_ms(started)
                    self._remember_record(record)

                    result = self._error_result(
                        message="Workflow action blocked by Security Agent.",
                        error=record.error,
                        data={
                            "action_id": action_id,
                            "action_type": action_type,
                            "route": self._route_to_dict(route),
                            "security": approval,
                            "executed": False,
                        },
                        metadata=self._result_metadata(action_context, normalized_action, route, record),
                    )

                    await self._log_audit_event(
                        event_type="workflow.action.security_blocked",
                        context=action_context,
                        payload=result,
                    )
                    return result

                record.status = ActionStatus.APPROVED

            if dry_run:
                record.status = ActionStatus.SKIPPED
                record.finished_at = _now_iso()
                record.duration_ms = _duration_ms(started)
                self._remember_record(record)

                verification_payload = self._prepare_verification_payload(
                    action_step=normalized_action,
                    context=action_context,
                    route=route,
                    action_result={
                        "success": True,
                        "message": "Dry run completed. Action was not executed.",
                        "data": {"executed": False, "dry_run": True},
                    },
                )

                memory_payload = self._prepare_memory_payload(
                    action_step=normalized_action,
                    context=action_context,
                    route=route,
                    action_result={
                        "success": True,
                        "message": "Dry run completed. Action was not executed.",
                        "data": {"executed": False, "dry_run": True},
                    },
                )

                result = self._safe_result(
                    message="Dry run completed. Action route is valid but was not executed.",
                    data={
                        "action_id": action_id,
                        "action_type": action_type,
                        "route": self._route_to_dict(route),
                        "executed": False,
                        "dry_run": True,
                        "verification_payload": verification_payload,
                        "memory_payload": memory_payload,
                    },
                    metadata=self._result_metadata(action_context, normalized_action, route, record),
                )

                await self._log_audit_event(
                    event_type="workflow.action.dry_run",
                    context=action_context,
                    payload=result,
                )
                return result

            record.status = ActionStatus.ROUTED
            effective_timeout = max(
                1,
                int(timeout_seconds or normalized_action.get("timeout_seconds") or self.default_timeout_seconds),
            )

            raw_result = await asyncio.wait_for(
                self._execute_route(
                    action_step=normalized_action,
                    context=action_context,
                    route=route,
                ),
                timeout=effective_timeout,
            )

            action_result = self._normalize_target_result(raw_result)

            record.status = (
                ActionStatus.COMPLETED
                if action_result.get("success")
                else ActionStatus.FAILED
            )
            record.error = None if action_result.get("success") else str(action_result.get("error") or "action_failed")
            record.finished_at = _now_iso()
            record.duration_ms = _duration_ms(started)

            verification_payload = self._prepare_verification_payload(
                action_step=normalized_action,
                context=action_context,
                route=route,
                action_result=action_result,
            )

            memory_payload = self._prepare_memory_payload(
                action_step=normalized_action,
                context=action_context,
                route=route,
                action_result=action_result,
            )

            self._remember_record(record)

            result = self._safe_result(
                message=(
                    "Workflow action routed and executed successfully."
                    if action_result.get("success")
                    else "Workflow action routed but execution failed."
                ),
                data={
                    "action_id": action_id,
                    "action_type": action_type,
                    "route": self._route_to_dict(route),
                    "executed": True,
                    "action_result": action_result,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                error=None if action_result.get("success") else action_result.get("error"),
                metadata=self._result_metadata(action_context, normalized_action, route, record),
            )

            await self._log_audit_event(
                event_type=(
                    "workflow.action.completed"
                    if action_result.get("success")
                    else "workflow.action.failed"
                ),
                context=action_context,
                payload=result,
            )

            await self._emit_agent_event(
                event_type=(
                    "workflow.action.completed"
                    if action_result.get("success")
                    else "workflow.action.failed"
                ),
                context=action_context,
                payload={
                    "action_id": action_id,
                    "action_type": action_type,
                    "route_kind": route.kind.value,
                    "route_name": route.name,
                    "success": bool(action_result.get("success")),
                    "duration_ms": record.duration_ms,
                },
            )

            return result

        except asyncio.TimeoutError:
            record.status = ActionStatus.FAILED
            record.error = "action_timeout"
            record.finished_at = _now_iso()
            record.duration_ms = _duration_ms(started)
            self._remember_record(record)

            result = self._error_result(
                message="Workflow action timed out.",
                error="action_timeout",
                data={
                    "action_id": action_id,
                    "action_type": action_type,
                    "route": self._route_to_dict(route),
                    "executed": False,
                },
                metadata=self._result_metadata(action_context, normalized_action, route, record),
            )

            await self._log_audit_event(
                event_type="workflow.action.timeout",
                context=action_context,
                payload=result,
            )
            return result

        except Exception as exc:
            self.logger.exception("Workflow action routing failed.")
            record.status = ActionStatus.FAILED
            record.error = str(exc)
            record.finished_at = _now_iso()
            record.duration_ms = _duration_ms(started)
            self._remember_record(record)

            result = self._error_result(
                message="Workflow action routing failed.",
                error=str(exc),
                data={
                    "action_id": action_id,
                    "action_type": action_type,
                    "route": self._route_to_dict(route),
                    "executed": False,
                },
                metadata=self._result_metadata(action_context, normalized_action, route, record),
            )

            await self._log_audit_event(
                event_type="workflow.action.exception",
                context=action_context,
                payload=result,
            )
            return result

    async def route_actions(
        self,
        action_steps: Sequence[Mapping[str, Any]],
        context: Union[WorkflowActionContext, Mapping[str, Any]],
        *,
        dry_run: bool = False,
        stop_on_error: bool = True,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Route multiple workflow action steps sequentially.

        This is intentionally sequential by default because workflow pipelines
        often depend on previous step output. Parallel execution can be added
        later by workflow_builder/condition_engine metadata.
        """

        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        action_context = context_result["data"]["context"]

        results: List[Dict[str, Any]] = []
        successful = 0
        failed = 0
        skipped = 0

        await self._emit_agent_event(
            event_type="workflow.actions.batch_started",
            context=action_context,
            payload={
                "count": len(action_steps),
                "dry_run": dry_run,
                "stop_on_error": stop_on_error,
            },
        )

        for index, step in enumerate(action_steps):
            step_context = WorkflowActionContext.from_mapping(action_context.to_dict())
            step_context.step_id = _optional_str(step.get("step_id") or step.get("id") or f"step_{index + 1}")

            result = await self.route_action(
                action_step=step,
                context=step_context,
                dry_run=dry_run,
                timeout_seconds=timeout_seconds,
            )

            result.setdefault("metadata", {})
            result["metadata"]["batch_index"] = index
            results.append(result)

            if result.get("success"):
                successful += 1
                result_data = _safe_dict(result.get("data"))
                if result_data.get("skipped"):
                    skipped += 1
            else:
                failed += 1
                if stop_on_error:
                    break

        batch_success = failed == 0
        message = (
            "Workflow action batch completed successfully."
            if batch_success
            else "Workflow action batch completed with errors."
        )

        final = self._safe_result(
            message=message,
            data={
                "results": results,
                "count": len(results),
                "requested_count": len(action_steps),
                "successful": successful,
                "failed": failed,
                "skipped": skipped,
                "stopped_early": stop_on_error and failed > 0 and len(results) < len(action_steps),
            },
            error=None if batch_success else "batch_has_failed_actions",
            metadata={
                "router": self.router_name,
                "version": self.version,
                "context": action_context.to_dict(),
                "dry_run": dry_run,
            },
        )
        final["success"] = batch_success

        await self._emit_agent_event(
            event_type=(
                "workflow.actions.batch_completed"
                if batch_success
                else "workflow.actions.batch_failed"
            ),
            context=action_context,
            payload={
                "successful": successful,
                "failed": failed,
                "skipped": skipped,
                "count": len(results),
            },
        )

        await self._log_audit_event(
            event_type=(
                "workflow.actions.batch_completed"
                if batch_success
                else "workflow.actions.batch_failed"
            ),
            context=action_context,
            payload=final,
        )

        return final

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[WorkflowActionContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.

        This is mandatory for every user-specific workflow action to prevent
        cross-user/cross-workspace data mixing.
        """

        try:
            if isinstance(context, WorkflowActionContext):
                action_context = context
            elif isinstance(context, Mapping):
                action_context = WorkflowActionContext.from_mapping(context)
            else:
                return self._error_result(
                    message="Invalid workflow action context.",
                    error="invalid_context",
                    metadata={"context_type": type(context).__name__},
                )

            if not action_context.user_id:
                return self._error_result(
                    message="user_id is required for workflow action routing.",
                    error="missing_user_id",
                )

            if not action_context.workspace_id:
                return self._error_result(
                    message="workspace_id is required for workflow action routing.",
                    error="missing_workspace_id",
                )

            return self._safe_result(
                message="Workflow action context is valid.",
                data={"context": action_context},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to validate workflow action context.",
                error=str(exc),
            )

    def _requires_security_check(
        self,
        action_step: Mapping[str, Any],
        route: Optional[RouteTarget] = None,
    ) -> bool:
        """
        Decide whether an action needs Security Agent approval.

        Sensitive actions include messaging, financial operations, browser
        automation, system operations, destructive updates, credential-related
        operations, and any step explicitly marked requires_security=True.
        """

        action = _normalize_action_step(action_step)
        if bool(action.get("requires_security")):
            return True

        risk_level = _lower_text(action.get("risk_level"))
        if risk_level in {ActionRiskLevel.HIGH.value, ActionRiskLevel.CRITICAL.value}:
            return True

        if route and route.requires_security:
            return True

        haystack = " ".join(
            str(value)
            for value in (
                action.get("action_type"),
                action.get("connector"),
                action.get("agent"),
                action.get("method"),
                action.get("name"),
                action.get("operation"),
            )
            if value is not None
        )

        params = _safe_dict(action.get("params"))
        metadata = _safe_dict(action.get("metadata"))

        checks = (
            SENSITIVE_ACTION_KEYWORDS,
            DESTRUCTIVE_ACTION_KEYWORDS,
            MESSAGE_ACTION_KEYWORDS,
            FINANCIAL_ACTION_KEYWORDS,
            BROWSER_ACTION_KEYWORDS,
            SYSTEM_ACTION_KEYWORDS,
        )

        if any(_contains_keyword(haystack, keywords) for keywords in checks):
            return True

        explicit_sensitive = params.get("sensitive") or metadata.get("sensitive")
        if bool(explicit_sensitive):
            return True

        return False

    async def _request_security_approval(
        self,
        *,
        action_step: Mapping[str, Any],
        context: WorkflowActionContext,
        route: RouteTarget,
        dry_run: bool = False,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval before sensitive action execution.

        If no Security Agent is attached:
            - Dry runs are allowed.
            - Non-dry sensitive actions are blocked by default unless the action
              explicitly has security_preapproved=True in trusted internal context.

        This conservative default prevents accidental real messaging, browser,
        financial, system, or destructive operations.
        """

        action = _normalize_action_step(action_step)

        security_payload = {
            "request_id": context.request_id,
            "workflow_id": context.workflow_id,
            "run_id": context.run_id,
            "step_id": context.step_id or action.get("step_id"),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "action_id": action.get("action_id"),
            "action_type": action.get("action_type"),
            "connector": action.get("connector"),
            "agent": action.get("agent"),
            "method": action.get("method"),
            "route": self._route_to_dict(route),
            "risk_level": self._estimate_risk_level(action, route).value,
            "dry_run": dry_run,
            "params": _redact_sensitive(action.get("params")),
            "metadata": _redact_sensitive(action.get("metadata")),
            "timestamp": _now_iso(),
        }

        await self._emit_agent_event(
            event_type="workflow.action.security_check_requested",
            context=context,
            payload=security_payload,
        )

        if dry_run:
            return self._safe_result(
                message="Dry run security check passed without executing sensitive action.",
                data={
                    "approved": True,
                    "dry_run": True,
                    "security_payload": security_payload,
                },
            )

        trusted_preapproved = bool(action.get("security_preapproved")) and bool(
            context.metadata.get("trusted_internal_route")
        )
        if trusted_preapproved:
            return self._safe_result(
                message="Sensitive action pre-approved by trusted internal route.",
                data={
                    "approved": True,
                    "preapproved": True,
                    "security_payload": security_payload,
                },
            )

        if self.security_agent is None:
            return self._error_result(
                message="Sensitive workflow action requires Security Agent approval, but no Security Agent is attached.",
                error="security_agent_unavailable",
                data={
                    "approved": False,
                    "security_payload": security_payload,
                },
            )

        try:
            security_methods = (
                "approve_workflow_action",
                "request_approval",
                "validate_action",
                "check_permission",
                "run",
                "execute",
            )

            for method_name in security_methods:
                method = getattr(self.security_agent, method_name, None)
                if callable(method):
                    raw = method(security_payload)
                    response = await _maybe_await(raw)
                    normalized = self._normalize_security_response(response)
                    return normalized

            return self._error_result(
                message="Security Agent does not expose a compatible approval method.",
                error="security_method_unavailable",
                data={
                    "approved": False,
                    "security_payload": security_payload,
                },
            )

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return self._error_result(
                message="Security Agent approval request failed.",
                error=str(exc),
                data={
                    "approved": False,
                    "security_payload": security_payload,
                },
            )

    def _prepare_verification_payload(
        self,
        *,
        action_step: Mapping[str, Any],
        context: WorkflowActionContext,
        route: RouteTarget,
        action_result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can use this to confirm whether workflow side effects
        occurred as expected, such as checking a CRM record, sheet row, email
        draft status, webhook response, or connector state.
        """

        action = _normalize_action_step(action_step)
        result_data = _safe_dict(action_result.get("data"))

        return {
            "verification_type": "workflow_action_result",
            "request_id": context.request_id,
            "workflow_id": context.workflow_id,
            "run_id": context.run_id,
            "step_id": context.step_id or action.get("step_id"),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "action_id": action.get("action_id"),
            "action_type": action.get("action_type"),
            "route": self._route_to_dict(route),
            "expected_outcome": _redact_sensitive(action.get("expected_outcome")),
            "actual_result": _redact_sensitive(
                {
                    "success": action_result.get("success"),
                    "message": action_result.get("message"),
                    "error": action_result.get("error"),
                    "data": result_data,
                }
            ),
            "requires_followup_verification": bool(
                action.get("requires_verification", True)
            ),
            "created_at": _now_iso(),
            "metadata": {
                "router": self.router_name,
                "router_version": self.version,
                "source": "WorkflowActionRouter._prepare_verification_payload",
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        action_step: Mapping[str, Any],
        context: WorkflowActionContext,
        route: RouteTarget,
        action_result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        This payload intentionally redacts sensitive fields and stores only useful
        workflow context. Memory Agent can decide whether to persist it based on
        user/workspace policy.
        """

        action = _normalize_action_step(action_step)

        return {
            "memory_type": "workflow_action_context",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "workflow_id": context.workflow_id,
            "run_id": context.run_id,
            "step_id": context.step_id or action.get("step_id"),
            "action_id": action.get("action_id"),
            "action_type": action.get("action_type"),
            "route_kind": route.kind.value,
            "route_name": route.name,
            "success": bool(action_result.get("success")),
            "summary": {
                "message": action_result.get("message"),
                "error": action_result.get("error"),
            },
            "safe_action_metadata": _redact_sensitive(action.get("metadata")),
            "created_at": _now_iso(),
            "metadata": {
                "router": self.router_name,
                "router_version": self.version,
                "source": "WorkflowActionRouter._prepare_memory_payload",
            },
        }

    async def _emit_agent_event(
        self,
        *,
        event_type: str,
        context: WorkflowActionContext,
        payload: Mapping[str, Any],
    ) -> None:
        """
        Emit an event for dashboard/API, Master Agent, logs, or observability.

        This method is best-effort and must never break workflow execution.
        """

        safe_payload = _redact_sensitive(dict(payload))

        try:
            event = {
                "event_type": event_type,
                "agent": self.router_name,
                "version": self.version,
                "context": context.to_dict(),
                "payload": safe_payload,
                "timestamp": _now_iso(),
            }

            if self.event_emitter is not None:
                if callable(self.event_emitter):
                    await _maybe_await(self.event_emitter(event))
                    return

                emit = getattr(self.event_emitter, "emit", None)
                if callable(emit):
                    await _maybe_await(emit(event))
                    return

            emit_event = getattr(super(), "emit_event", None)
            if callable(emit_event):
                await _maybe_await(emit_event(event))

        except Exception:
            self.logger.debug("Failed to emit workflow action router event.", exc_info=True)

    async def _log_audit_event(
        self,
        *,
        event_type: str,
        context: WorkflowActionContext,
        payload: Mapping[str, Any],
    ) -> None:
        """
        Log an audit event.

        Audit logs are always scoped by user_id and workspace_id to preserve SaaS
        isolation. This method is best-effort and does not interrupt workflow
        execution.
        """

        safe_payload = _redact_sensitive(dict(payload))

        audit_event = {
            "event_type": event_type,
            "agent": self.router_name,
            "version": self.version,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "workflow_id": context.workflow_id,
            "run_id": context.run_id,
            "step_id": context.step_id,
            "payload": safe_payload,
            "timestamp": _now_iso(),
        }

        try:
            if self.audit_logger is not None:
                if callable(self.audit_logger):
                    await _maybe_await(self.audit_logger(audit_event))
                    return

                log = getattr(self.audit_logger, "log", None)
                if callable(log):
                    await _maybe_await(log(audit_event))
                    return

                write = getattr(self.audit_logger, "write", None)
                if callable(write):
                    await _maybe_await(write(audit_event))
                    return

            log_audit = getattr(super(), "log_audit", None)
            if callable(log_audit):
                await _maybe_await(log_audit(audit_event))
                return

            self.logger.info("workflow_action_audit_event=%s", audit_event)

        except Exception:
            self.logger.debug("Failed to log workflow action audit event.", exc_info=True)

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a structured successful result."""

        return {
            "success": error is None,
            "message": message,
            "data": dict(data or {}),
            "error": error,
            "metadata": {
                "router": self.router_name,
                "version": self.version,
                "timestamp": _now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Any,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return a structured failed result."""

        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": str(error) if error is not None else "unknown_error",
            "metadata": {
                "router": self.router_name,
                "version": self.version,
                "timestamp": _now_iso(),
                **dict(metadata or {}),
            },
        }

    # -------------------------------------------------------------------------
    # Route resolution
    # -------------------------------------------------------------------------

    def _resolve_route(self, action_step: Mapping[str, Any]) -> RouteTarget:
        """
        Resolve workflow action step to a target.

        Priority:
            1. Explicit connector
            2. Explicit agent
            3. Webhook/n8n keywords
            4. Local handler by action_type
            5. Connector inferred from action_type prefix
            6. Agent inferred from action_type prefix
            7. Noop / unknown
        """

        action = _normalize_action_step(action_step)
        action_type = self._normalize_route_name(action.get("action_type"))
        connector_name = self._normalize_route_name(action.get("connector"))
        agent_name = self._normalize_route_name(action.get("agent"))
        method_name = action.get("method")

        if connector_name:
            connector = self.connector_registry.get(connector_name)
            if connector is not None:
                return RouteTarget(
                    kind=self._connector_kind(connector_name),
                    name=connector_name,
                    target=connector,
                    method_name=method_name or self._default_method_for_action(action),
                    risk_level=self._estimate_risk_level(action, None),
                    requires_security=False,
                    metadata={"resolution": "explicit_connector"},
                )

        if agent_name:
            agent = self.agent_registry.get(agent_name)
            if agent is not None:
                return RouteTarget(
                    kind=RouteKind.AGENT,
                    name=agent_name,
                    target=agent,
                    method_name=method_name or self._default_method_for_action(action),
                    risk_level=self._estimate_risk_level(action, None),
                    requires_security=False,
                    metadata={"resolution": "explicit_agent"},
                )

        if action_type in self.local_handlers:
            return RouteTarget(
                kind=RouteKind.LOCAL_HANDLER,
                name=action_type,
                target=self.local_handlers[action_type],
                method_name=None,
                risk_level=self._estimate_risk_level(action, None),
                requires_security=False,
                metadata={"resolution": "local_handler"},
            )

        if action_type.startswith("webhook.") or action_type.startswith("webhook_"):
            webhook = self.connector_registry.get("webhook") or self.connector_registry.get("webhook_manager")
            if webhook is not None:
                return RouteTarget(
                    kind=RouteKind.WEBHOOK,
                    name="webhook",
                    target=webhook,
                    method_name=method_name or self._method_after_prefix(action_type, "webhook"),
                    risk_level=self._estimate_risk_level(action, None),
                    requires_security=True,
                    metadata={"resolution": "webhook_prefix"},
                )

        if action_type.startswith("n8n.") or action_type.startswith("n8n_"):
            n8n = self.connector_registry.get("n8n") or self.connector_registry.get("n8n_connector")
            if n8n is not None:
                return RouteTarget(
                    kind=RouteKind.N8N,
                    name="n8n",
                    target=n8n,
                    method_name=method_name or self._method_after_prefix(action_type, "n8n"),
                    risk_level=self._estimate_risk_level(action, None),
                    requires_security=True,
                    metadata={"resolution": "n8n_prefix"},
                )

        prefix = action_type.split(".", 1)[0].split("_", 1)[0] if action_type else ""
        if prefix in self.connector_registry:
            return RouteTarget(
                kind=self._connector_kind(prefix),
                name=prefix,
                target=self.connector_registry[prefix],
                method_name=method_name or self._method_after_prefix(action_type, prefix),
                risk_level=self._estimate_risk_level(action, None),
                requires_security=False,
                metadata={"resolution": "connector_prefix"},
            )

        if prefix in self.agent_registry:
            return RouteTarget(
                kind=RouteKind.AGENT,
                name=prefix,
                target=self.agent_registry[prefix],
                method_name=method_name or self._method_after_prefix(action_type, prefix),
                risk_level=self._estimate_risk_level(action, None),
                requires_security=False,
                metadata={"resolution": "agent_prefix"},
            )

        if action_type in {"noop", "no_op", "skip", "wait"}:
            return RouteTarget(
                kind=RouteKind.NOOP,
                name=action_type,
                target=self.local_handlers.get("noop"),
                method_name=None,
                risk_level=ActionRiskLevel.LOW,
                requires_security=False,
                metadata={"resolution": "noop_action"},
            )

        return RouteTarget(
            kind=RouteKind.UNKNOWN,
            name=action_type or "unknown",
            target=None,
            method_name=method_name,
            risk_level=self._estimate_risk_level(action, None),
            requires_security=self._requires_security_check(action),
            metadata={"resolution": "unresolved"},
        )

    async def _execute_route(
        self,
        *,
        action_step: Mapping[str, Any],
        context: WorkflowActionContext,
        route: RouteTarget,
    ) -> Any:
        """Execute a resolved route."""

        action = _normalize_action_step(action_step)

        if route.kind == RouteKind.NOOP:
            return {
                "success": True,
                "message": "Noop action skipped safely.",
                "data": {
                    "action_id": action.get("action_id"),
                    "action_type": action.get("action_type"),
                    "executed": False,
                    "skipped": True,
                },
            }

        if route.kind == RouteKind.LOCAL_HANDLER:
            handler = route.target
            return await self._call_handler(handler, action, context, route)

        if route.kind in {RouteKind.CONNECTOR, RouteKind.WEBHOOK, RouteKind.N8N, RouteKind.AGENT}:
            return await self._call_target_method(route.target, route.method_name, action, context, route)

        return {
            "success": False,
            "message": "Unsupported route kind.",
            "error": "unsupported_route_kind",
            "data": {"route": self._route_to_dict(route)},
        }

    async def _call_handler(
        self,
        handler: Callable[..., Any],
        action: Mapping[str, Any],
        context: WorkflowActionContext,
        route: RouteTarget,
    ) -> Any:
        """Call a local registered handler with flexible signatures."""

        params = _safe_dict(action.get("params"))

        signature = None
        try:
            signature = inspect.signature(handler)
        except Exception:
            signature = None

        if signature:
            names = set(signature.parameters.keys())

            if {"action_step", "context", "route"}.issubset(names):
                return await _maybe_await(handler(action_step=action, context=context, route=route))

            if {"action", "context", "route"}.issubset(names):
                return await _maybe_await(handler(action=action, context=context, route=route))

            if {"params", "context"}.issubset(names):
                return await _maybe_await(handler(params=params, context=context))

            if "context" in names:
                return await _maybe_await(handler(params, context=context))

        return await _maybe_await(handler(params))

    async def _call_target_method(
        self,
        target: Any,
        method_name: Optional[str],
        action: Mapping[str, Any],
        context: WorkflowActionContext,
        route: RouteTarget,
    ) -> Any:
        """
        Call a connector or agent method.

        Supported target method signatures:
            method(action_step=..., context=...)
            method(params=..., context=...)
            method(payload=..., context=...)
            method(params)
            run(action_step, context)
            execute(action_step, context)
        """

        if target is None:
            return {
                "success": False,
                "message": "Route target is unavailable.",
                "error": "target_unavailable",
                "data": {"route": self._route_to_dict(route)},
            }

        candidate_methods = self._candidate_method_names(method_name, action, route)
        params = _safe_dict(action.get("params"))

        for candidate in candidate_methods:
            method = getattr(target, candidate, None)
            if not callable(method):
                continue

            try:
                return await self._call_method_flexibly(
                    method=method,
                    action=action,
                    params=params,
                    context=context,
                    route=route,
                )
            except TypeError:
                continue

        return {
            "success": False,
            "message": "No compatible method found on route target.",
            "error": "target_method_unavailable",
            "data": {
                "route": self._route_to_dict(route),
                "candidate_methods": candidate_methods,
                "target_type": type(target).__name__,
            },
        }

    async def _call_method_flexibly(
        self,
        *,
        method: Callable[..., Any],
        action: Mapping[str, Any],
        params: Mapping[str, Any],
        context: WorkflowActionContext,
        route: RouteTarget,
    ) -> Any:
        """Call a method using the richest compatible signature."""

        signature = inspect.signature(method)
        names = set(signature.parameters.keys())

        if {"action_step", "context", "route"}.issubset(names):
            return await _maybe_await(method(action_step=action, context=context, route=route))

        if {"action_step", "context"}.issubset(names):
            return await _maybe_await(method(action_step=action, context=context))

        if {"action", "context"}.issubset(names):
            return await _maybe_await(method(action=action, context=context))

        if {"params", "context"}.issubset(names):
            return await _maybe_await(method(params=params, context=context))

        if {"payload", "context"}.issubset(names):
            return await _maybe_await(method(payload=params, context=context))

        if "context" in names and len(names) >= 1:
            return await _maybe_await(method(params, context=context))

        if len(signature.parameters) == 0:
            return await _maybe_await(method())

        try:
            return await _maybe_await(method(params))
        except TypeError:
            return await _maybe_await(method(action, context))

    # -------------------------------------------------------------------------
    # Default handlers and connector placeholders
    # -------------------------------------------------------------------------

    def _install_default_connector_placeholders(self) -> None:
        """
        Register import-safe connector placeholders when concrete connectors exist.

        These are only instantiated if the imported class is available. Missing
        future files never break this router import.
        """

        optional_connector_classes = {
            "n8n": N8NConnector,
            "n8n_connector": N8NConnector,
            "app": AppConnector,
            "app_connector": AppConnector,
            "webhook": WebhookManager,
            "webhook_manager": WebhookManager,
            "crm": CRMConnector,
            "crm_connector": CRMConnector,
            "sheet": SheetConnector,
            "sheet_connector": SheetConnector,
            "whatsapp": WhatsAppConnector,
            "whatsapp_connector": WhatsAppConnector,
            "email": EmailConnector,
            "email_connector": EmailConnector,
            "notification": NotificationEngine,
            "notification_engine": NotificationEngine,
        }

        for name, cls in optional_connector_classes.items():
            if cls is None:
                continue
            try:
                self.connector_registry[name] = cls()
            except Exception:
                self.logger.debug("Could not instantiate optional connector: %s", name, exc_info=True)

    def _install_default_local_handlers(self) -> None:
        """Install safe local handlers."""

        self.local_handlers.setdefault("noop", self._handle_noop)
        self.local_handlers.setdefault("wait", self._handle_wait)
        self.local_handlers.setdefault("transform", self._handle_transform)
        self.local_handlers.setdefault("set_variable", self._handle_set_variable)
        self.local_handlers.setdefault("log", self._handle_log)

    async def _handle_noop(self, params: Mapping[str, Any], context: Optional[WorkflowActionContext] = None) -> Dict[str, Any]:
        return self._safe_result(
            message="Noop handler executed safely.",
            data={"params": _redact_sensitive(dict(params)), "executed": False, "skipped": True},
        )

    async def _handle_wait(self, params: Mapping[str, Any], context: Optional[WorkflowActionContext] = None) -> Dict[str, Any]:
        """
        Safe wait handler.

        To avoid blocking worker processes for too long, this caps waits at 30
        seconds. Longer scheduling should be handled by scheduler.py.
        """

        seconds = params.get("seconds", params.get("delay_seconds", 0))
        try:
            wait_seconds = max(0, min(float(seconds or 0), 30.0))
        except Exception:
            wait_seconds = 0.0

        if wait_seconds > 0:
            await asyncio.sleep(wait_seconds)

        return self._safe_result(
            message="Wait handler completed.",
            data={"waited_seconds": wait_seconds},
        )

    async def _handle_transform(self, params: Mapping[str, Any], context: Optional[WorkflowActionContext] = None) -> Dict[str, Any]:
        """
        Safe transform handler.

        Provides basic built-in transformations without executing untrusted code.
        """

        source = params.get("source", params.get("value"))
        transform_type = _lower_text(params.get("transform") or params.get("operation") or "identity")

        if transform_type == "identity":
            value = source
        elif transform_type == "lower":
            value = str(source or "").lower()
        elif transform_type == "upper":
            value = str(source or "").upper()
        elif transform_type == "title":
            value = str(source or "").title()
        elif transform_type == "strip":
            value = str(source or "").strip()
        elif transform_type == "string":
            value = str(source or "")
        elif transform_type == "bool":
            value = bool(source)
        elif transform_type == "int":
            try:
                value = int(source)
            except Exception:
                value = 0
        elif transform_type == "float":
            try:
                value = float(source)
            except Exception:
                value = 0.0
        else:
            return self._error_result(
                message="Unsupported safe transform operation.",
                error="unsupported_transform",
                data={"transform": transform_type},
            )

        return self._safe_result(
            message="Transform handler completed.",
            data={"value": value, "transform": transform_type},
        )

    async def _handle_set_variable(self, params: Mapping[str, Any], context: Optional[WorkflowActionContext] = None) -> Dict[str, Any]:
        """
        Safe set-variable handler.

        This returns the variable assignment for the workflow runtime to merge.
        It does not mutate global state.
        """

        name = _optional_str(params.get("name") or params.get("key"))
        if not name:
            return self._error_result(
                message="Variable name is required.",
                error="missing_variable_name",
            )

        return self._safe_result(
            message="Variable assignment prepared.",
            data={
                "variable": {
                    "name": name,
                    "value": _redact_sensitive(params.get("value")),
                }
            },
        )

    async def _handle_log(self, params: Mapping[str, Any], context: Optional[WorkflowActionContext] = None) -> Dict[str, Any]:
        """
        Safe log handler.

        Logs only redacted information and keeps user/workspace context attached.
        """

        safe_params = _redact_sensitive(dict(params))
        self.logger.info(
            "workflow_log_action user_id=%s workspace_id=%s payload=%s",
            context.user_id if context else None,
            context.workspace_id if context else None,
            safe_params,
        )
        return self._safe_result(
            message="Log handler completed.",
            data={"logged": True, "payload": safe_params},
        )

    # -------------------------------------------------------------------------
    # Normalization helpers
    # -------------------------------------------------------------------------

    def _normalize_target_result(self, raw_result: Any) -> Dict[str, Any]:
        """Normalize connector/agent/handler outputs into standard result shape."""

        if isinstance(raw_result, Mapping):
            result = dict(raw_result)

            if "success" not in result:
                result["success"] = result.get("error") in (None, "", False)

            result.setdefault("message", "Action target returned a result.")
            result.setdefault("data", {})
            result.setdefault("error", None if result.get("success") else "action_failed")
            result.setdefault("metadata", {})

            if not isinstance(result["data"], Mapping):
                result["data"] = {"value": result["data"]}

            if not isinstance(result["metadata"], Mapping):
                result["metadata"] = {"raw_metadata": result["metadata"]}

            return {
                "success": bool(result["success"]),
                "message": str(result["message"]),
                "data": _redact_sensitive(dict(result["data"])),
                "error": None if result["success"] else str(result.get("error") or "action_failed"),
                "metadata": _redact_sensitive(dict(result["metadata"])),
            }

        return {
            "success": True,
            "message": "Action target completed.",
            "data": {"value": _redact_sensitive(raw_result)},
            "error": None,
            "metadata": {},
        }

    def _normalize_security_response(self, response: Any) -> Dict[str, Any]:
        """Normalize Security Agent response into approval result shape."""

        if isinstance(response, Mapping):
            result = dict(response)
            approved = bool(
                result.get("approved")
                if "approved" in result
                else result.get("success", False)
            )

            if approved:
                return self._safe_result(
                    message=str(result.get("message") or "Security Agent approved workflow action."),
                    data={
                        "approved": True,
                        "security_result": _redact_sensitive(result),
                    },
                )

            return self._error_result(
                message=str(result.get("message") or "Security Agent denied workflow action."),
                error=result.get("error") or "security_approval_denied",
                data={
                    "approved": False,
                    "security_result": _redact_sensitive(result),
                },
            )

        if response is True:
            return self._safe_result(
                message="Security Agent approved workflow action.",
                data={"approved": True},
            )

        return self._error_result(
            message="Security Agent denied workflow action.",
            error="security_approval_denied",
            data={"approved": False, "security_result": _redact_sensitive(response)},
        )

    def _normalize_route_name(self, name: Any) -> str:
        """Normalize route names consistently."""

        text = str(name or "").strip().lower()
        text = text.replace("-", "_").replace(" ", "_")
        return text

    def _connector_kind(self, connector_name: str) -> RouteKind:
        clean = self._normalize_route_name(connector_name)
        if clean in {"webhook", "webhook_manager"}:
            return RouteKind.WEBHOOK
        if clean in {"n8n", "n8n_connector"}:
            return RouteKind.N8N
        return RouteKind.CONNECTOR

    def _estimate_risk_level(
        self,
        action: Mapping[str, Any],
        route: Optional[RouteTarget],
    ) -> ActionRiskLevel:
        """Estimate risk level from action fields and route."""

        explicit = _lower_text(action.get("risk_level"))
        if explicit in {item.value for item in ActionRiskLevel}:
            return ActionRiskLevel(explicit)

        action_type = _lower_text(action.get("action_type"))
        connector = _lower_text(action.get("connector"))
        agent = _lower_text(action.get("agent"))
        method = _lower_text(action.get("method"))
        text = " ".join([action_type, connector, agent, method])

        if _contains_keyword(text, FINANCIAL_ACTION_KEYWORDS):
            return ActionRiskLevel.CRITICAL

        if _contains_keyword(text, SYSTEM_ACTION_KEYWORDS) or _contains_keyword(text, DESTRUCTIVE_ACTION_KEYWORDS):
            return ActionRiskLevel.CRITICAL

        if _contains_keyword(text, MESSAGE_ACTION_KEYWORDS):
            return ActionRiskLevel.HIGH

        if _contains_keyword(text, BROWSER_ACTION_KEYWORDS):
            return ActionRiskLevel.HIGH

        if _contains_keyword(text, SENSITIVE_ACTION_KEYWORDS):
            return ActionRiskLevel.MEDIUM

        if route and route.risk_level:
            return route.risk_level

        return ActionRiskLevel.LOW

    def _default_method_for_action(self, action: Mapping[str, Any]) -> str:
        """Choose a reasonable default method for connector/agent targets."""

        action_type = self._normalize_route_name(action.get("action_type"))

        mapping = {
            "send_email": "send_email",
            "email_send": "send_email",
            "send_whatsapp": "send_message",
            "whatsapp_send": "send_message",
            "crm_create_lead": "create_lead",
            "crm_update_lead": "update_lead",
            "sheet_append_row": "append_row",
            "sheet_update_row": "update_row",
            "webhook_post": "post",
            "webhook_send": "send",
            "n8n_execute": "execute_workflow",
            "notify": "send_notification",
        }

        if action_type in mapping:
            return mapping[action_type]

        if "." in action_type:
            return action_type.split(".", 1)[1]

        return action_type or "execute"

    def _method_after_prefix(self, action_type: str, prefix: str) -> str:
        """Infer method name from action type prefix."""

        clean_action = self._normalize_route_name(action_type)
        clean_prefix = self._normalize_route_name(prefix)

        for marker in (f"{clean_prefix}.", f"{clean_prefix}_"):
            if clean_action.startswith(marker):
                remainder = clean_action[len(marker):].strip("_")
                return remainder or "execute"

        return self._default_method_for_action({"action_type": clean_action})

    def _candidate_method_names(
        self,
        method_name: Optional[str],
        action: Mapping[str, Any],
        route: RouteTarget,
    ) -> List[str]:
        """Build ordered candidate method names for a target."""

        candidates: List[str] = []

        for item in (
            method_name,
            action.get("method"),
            self._default_method_for_action(action),
            "route_action",
            "execute_action",
            "execute_workflow_action",
            "execute",
            "run",
            "handle",
            "__call__",
        ):
            clean = _optional_str(item)
            if clean and clean not in candidates:
                candidates.append(clean)

        return candidates

    def _route_to_dict(self, route: RouteTarget) -> Dict[str, Any]:
        """Serialize route target without leaking object internals."""

        return {
            "kind": route.kind.value,
            "name": route.name,
            "method_name": route.method_name,
            "risk_level": route.risk_level.value,
            "requires_security": route.requires_security,
            "target_type": type(route.target).__name__ if route.target is not None else None,
            "metadata": _redact_sensitive(route.metadata),
        }

    def _record_to_dict(self, record: ActionExecutionRecord) -> Dict[str, Any]:
        """Serialize execution record."""

        return {
            "action_id": record.action_id,
            "action_type": record.action_type,
            "route_kind": record.route_kind.value,
            "target_name": record.target_name,
            "status": record.status.value,
            "started_at": record.started_at,
            "finished_at": record.finished_at,
            "duration_ms": record.duration_ms,
            "security_required": record.security_required,
            "security_approved": record.security_approved,
            "error": record.error,
            "metadata": _redact_sensitive(record.metadata),
        }

    def _result_metadata(
        self,
        context: WorkflowActionContext,
        action: Mapping[str, Any],
        route: RouteTarget,
        record: ActionExecutionRecord,
    ) -> Dict[str, Any]:
        """Build common result metadata."""

        return {
            "request_id": context.request_id,
            "workflow_id": context.workflow_id,
            "run_id": context.run_id,
            "step_id": context.step_id or action.get("step_id"),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "action_id": action.get("action_id"),
            "action_type": action.get("action_type"),
            "route_kind": route.kind.value,
            "route_name": route.name,
            "status": record.status.value,
            "duration_ms": record.duration_ms,
            "security_required": record.security_required,
            "security_approved": record.security_approved,
        }

    def _remember_record(self, record: ActionExecutionRecord) -> None:
        """Keep a bounded local execution history for tests/dashboard debug."""

        self._execution_history.append(record)
        if len(self._execution_history) > 1000:
            self._execution_history = self._execution_history[-1000:]


# =============================================================================
# Convenience factory
# =============================================================================

def create_workflow_action_router(
    *,
    connector_registry: Optional[Mapping[str, Any]] = None,
    agent_registry: Optional[Mapping[str, Any]] = None,
    security_agent: Optional[Any] = None,
    verification_agent: Optional[Any] = None,
    memory_agent: Optional[Any] = None,
    audit_logger: Optional[Any] = None,
    event_emitter: Optional[Any] = None,
    default_timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> WorkflowActionRouter:
    """
    Factory helper for Agent Loader, Registry, FastAPI dependency injection,
    tests, and dashboard runtime bootstrapping.
    """

    return WorkflowActionRouter(
        connector_registry=connector_registry,
        agent_registry=agent_registry,
        security_agent=security_agent,
        verification_agent=verification_agent,
        memory_agent=memory_agent,
        audit_logger=audit_logger,
        event_emitter=event_emitter,
        default_timeout_seconds=default_timeout_seconds,
    )


# =============================================================================
# Minimal manual smoke test
# =============================================================================

async def _smoke_test() -> Dict[str, Any]:
    """
    Lightweight import-safe smoke test.

    Run manually:
        python agents/workflow_agent/action_router.py

    This does not perform real external actions.
    """

    router = WorkflowActionRouter()

    context = {
        "user_id": "test_user",
        "workspace_id": "test_workspace",
        "workflow_id": "wf_test",
        "run_id": "run_test",
        "permissions": ["workflow:run"],
        "metadata": {"trusted_internal_route": True},
    }

    action = {
        "action_id": "act_1",
        "action_type": "transform",
        "params": {
            "source": " digital promotix ",
            "transform": "strip",
        },
    }

    return await router.route_action(action, context)


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    result = asyncio.run(_smoke_test())
    print(result)