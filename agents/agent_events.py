"""
agents/agent_events.py

William / Jarvis Multi-Agent AI SaaS System - Digital Promotix

Purpose:
    Production-ready event bus for agent-to-agent messages, task events,
    errors, completions, audit hooks, dashboard/API listeners, and future
    plugin-style integrations.

This file is designed to be:
    - Import-safe even if other William modules are not created yet
    - SaaS-safe with user_id/workspace_id isolation
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent routing, Security Agent, Memory Agent, Verification Agent,
      Dashboard/API, and future async workers
    - Testable without external dependencies
    - Structured around dict/JSON-style results:
        success, message, data, error, metadata

Architecture Notes:
    Master Agent:
        Uses AgentEvents to emit, route, subscribe to, and inspect agent events.

    Security Agent:
        Sensitive event publishing or system-level broadcasting can be routed
        through security approval hooks before execution.

    Memory Agent:
        Useful events can generate memory-compatible payloads.

    Verification Agent:
        Completed, failed, or sensitive events can generate verification payloads.

    Dashboard/API:
        Can subscribe to user/workspace-safe event streams, task events,
        audit events, health events, and error events.

    Registry / Loader / Router:
        This file exposes clean public methods and avoids hard dependencies
        so it can be imported early during system boot.

Important:
    This module does NOT perform destructive actions.
    This module does NOT send external network calls.
    This module does NOT hardcode secrets.
"""

from __future__ import annotations

import asyncio
import copy
import inspect
import logging
import threading
import time
import traceback
import uuid
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import (
    Any,
    Awaitable,
    Callable,
    Deque,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)


# =============================================================================
# Optional BaseAgent compatibility
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early boot/import safety
    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent stub.

        This exists only so agent_events.py can import before base_agent.py
        is available or fully implemented.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.agents.agent_events")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Enums
# =============================================================================

class AgentEventType(str, Enum):
    """
    Supported event types for William/Jarvis global event infrastructure.
    """

    AGENT_MESSAGE = "agent_message"
    TASK_CREATED = "task_created"
    TASK_STARTED = "task_started"
    TASK_PROGRESS = "task_progress"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    TASK_CANCELLED = "task_cancelled"
    TASK_RETRY = "task_retry"

    SECURITY_CHECK_REQUESTED = "security_check_requested"
    SECURITY_APPROVED = "security_approved"
    SECURITY_DENIED = "security_denied"
    SECURITY_ALERT = "security_alert"

    MEMORY_PAYLOAD_READY = "memory_payload_ready"
    VERIFICATION_PAYLOAD_READY = "verification_payload_ready"

    AUDIT_EVENT = "audit_event"
    ERROR_EVENT = "error_event"
    HEALTH_EVENT = "health_event"
    REGISTRY_EVENT = "registry_event"
    ROUTER_EVENT = "router_event"
    LOADER_EVENT = "loader_event"
    DASHBOARD_EVENT = "dashboard_event"

    WORKFLOW_STARTED = "workflow_started"
    WORKFLOW_STEP = "workflow_step"
    WORKFLOW_COMPLETED = "workflow_completed"
    WORKFLOW_FAILED = "workflow_failed"

    SYSTEM_NOTICE = "system_notice"
    CUSTOM = "custom"


class AgentEventSeverity(str, Enum):
    """
    Event severity levels.
    """

    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AgentEventStatus(str, Enum):
    """
    Event processing status.
    """

    CREATED = "created"
    QUEUED = "queued"
    PUBLISHED = "published"
    DELIVERED = "delivered"
    FAILED = "failed"
    IGNORED = "ignored"


class AgentEventPriority(str, Enum):
    """
    Event priority levels.
    """

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


# =============================================================================
# Type Aliases
# =============================================================================

EventCallback = Callable[[Dict[str, Any]], Union[None, Dict[str, Any], Awaitable[Any]]]
SecurityApprovalCallback = Callable[[Dict[str, Any]], Union[bool, Dict[str, Any], Awaitable[Any]]]


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class EventSubscription:
    """
    Represents a registered event listener/subscriber.

    user_id/workspace_id may be used to scope dashboard or API listeners.
    agent_name may be used to scope an agent listener.
    """

    subscription_id: str
    callback: EventCallback
    event_types: Set[str] = field(default_factory=set)
    user_id: Optional[Union[str, int]] = None
    workspace_id: Optional[Union[str, int]] = None
    agent_name: Optional[str] = None
    include_audit: bool = False
    include_errors: bool = True
    active: bool = True
    created_at: str = field(default_factory=lambda: AgentEvents.utc_now())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentEvent:
    """
    Canonical William/Jarvis event object.
    """

    event_id: str
    event_type: str
    source_agent: str
    message: str
    user_id: Optional[Union[str, int]] = None
    workspace_id: Optional[Union[str, int]] = None
    target_agent: Optional[str] = None
    task_id: Optional[str] = None
    workflow_id: Optional[str] = None
    severity: str = AgentEventSeverity.INFO.value
    priority: str = AgentEventPriority.NORMAL.value
    status: str = AgentEventStatus.CREATED.value
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: AgentEvents.utc_now())
    published_at: Optional[str] = None
    delivered_to: List[str] = field(default_factory=list)


# =============================================================================
# AgentEvents
# =============================================================================

class AgentEvents(BaseAgent):
    """
    Global event bus for William/Jarvis multi-agent architecture.

    Responsibilities:
        - Emit agent-to-agent messages
        - Publish task events
        - Publish error/completion events
        - Support user/workspace isolation
        - Support dashboard/API subscriptions
        - Support audit hooks
        - Prepare Security, Memory, and Verification payloads
        - Maintain an in-memory event history buffer
        - Remain import-safe and test-friendly

    This class intentionally uses an in-memory bus by default.
    Later, it can be extended to Redis, Postgres, Kafka, RabbitMQ,
    NATS, Celery, or FastAPI WebSocket streaming without changing
    the public interface.
    """

    DEFAULT_MAX_HISTORY = 5000
    DEFAULT_MAX_AUDIT_HISTORY = 5000
    DEFAULT_MAX_ERROR_HISTORY = 2000

    SENSITIVE_EVENT_TYPES: Set[str] = {
        AgentEventType.SECURITY_ALERT.value,
        AgentEventType.SECURITY_CHECK_REQUESTED.value,
        AgentEventType.SECURITY_APPROVED.value,
        AgentEventType.SECURITY_DENIED.value,
        AgentEventType.AUDIT_EVENT.value,
    }

    COMPLETION_EVENT_TYPES: Set[str] = {
        AgentEventType.TASK_COMPLETED.value,
        AgentEventType.TASK_FAILED.value,
        AgentEventType.TASK_CANCELLED.value,
        AgentEventType.WORKFLOW_COMPLETED.value,
        AgentEventType.WORKFLOW_FAILED.value,
    }

    ERROR_EVENT_TYPES: Set[str] = {
        AgentEventType.ERROR_EVENT.value,
        AgentEventType.TASK_FAILED.value,
        AgentEventType.WORKFLOW_FAILED.value,
        AgentEventType.SECURITY_ALERT.value,
    }

    MEMORY_RELEVANT_TYPES: Set[str] = {
        AgentEventType.AGENT_MESSAGE.value,
        AgentEventType.TASK_COMPLETED.value,
        AgentEventType.WORKFLOW_COMPLETED.value,
        AgentEventType.MEMORY_PAYLOAD_READY.value,
    }

    def __init__(
        self,
        max_history: int = DEFAULT_MAX_HISTORY,
        max_audit_history: int = DEFAULT_MAX_AUDIT_HISTORY,
        max_error_history: int = DEFAULT_MAX_ERROR_HISTORY,
        enable_audit_log: bool = True,
        enable_memory_payloads: bool = True,
        enable_verification_payloads: bool = True,
        enable_security_gate: bool = True,
        security_approval_callback: Optional[SecurityApprovalCallback] = None,
        agent_name: str = "AgentEvents",
        agent_id: str = "agent_events",
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(agent_name=agent_name, agent_id=agent_id, **kwargs)
        except TypeError:
            try:
                super().__init__()
            except Exception:
                pass

        self.agent_name = agent_name
        self.agent_id = agent_id

        self.max_history = max(100, int(max_history))
        self.max_audit_history = max(100, int(max_audit_history))
        self.max_error_history = max(100, int(max_error_history))

        self.enable_audit_log = bool(enable_audit_log)
        self.enable_memory_payloads = bool(enable_memory_payloads)
        self.enable_verification_payloads = bool(enable_verification_payloads)
        self.enable_security_gate = bool(enable_security_gate)

        self.security_approval_callback = security_approval_callback

        self._lock = threading.RLock()
        self._event_history: Deque[Dict[str, Any]] = deque(maxlen=self.max_history)
        self._audit_history: Deque[Dict[str, Any]] = deque(maxlen=self.max_audit_history)
        self._error_history: Deque[Dict[str, Any]] = deque(maxlen=self.max_error_history)

        self._subscriptions: Dict[str, EventSubscription] = {}
        self._subscriptions_by_event_type: Dict[str, Set[str]] = defaultdict(set)
        self._agent_inboxes: Dict[str, Deque[Dict[str, Any]]] = defaultdict(lambda: deque(maxlen=1000))

        self._stats: Dict[str, Any] = {
            "events_created": 0,
            "events_published": 0,
            "events_failed": 0,
            "callbacks_delivered": 0,
            "callbacks_failed": 0,
            "audit_events": 0,
            "error_events": 0,
            "security_checks": 0,
            "security_denials": 0,
            "memory_payloads_prepared": 0,
            "verification_payloads_prepared": 0,
            "started_at": self.utc_now(),
            "last_event_at": None,
        }

    # =========================================================================
    # Time / IDs
    # =========================================================================

    @staticmethod
    def utc_now() -> str:
        """
        Return current UTC timestamp in ISO 8601 format.
        """
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def new_event_id(prefix: str = "evt") -> str:
        """
        Create a unique event ID.
        """
        return f"{prefix}_{uuid.uuid4().hex}"

    @staticmethod
    def new_subscription_id(prefix: str = "sub") -> str:
        """
        Create a unique subscription ID.
        """
        return f"{prefix}_{uuid.uuid4().hex}"

    # =========================================================================
    # Standard Results
    # =========================================================================

    def _safe_result(
        self,
        success: bool = True,
        message: str = "OK",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard success result.
        """
        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "timestamp": self.utc_now(),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception, Dict[str, Any]]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard error result.
        """
        if isinstance(error, Exception):
            error_payload: Union[str, Dict[str, Any]] = {
                "type": error.__class__.__name__,
                "message": str(error),
                "traceback": traceback.format_exc(),
            }
        elif isinstance(error, dict):
            error_payload = error
        else:
            error_payload = str(error) if error is not None else message

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error_payload,
            "metadata": metadata or {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "timestamp": self.utc_now(),
            },
        }

    # =========================================================================
    # Context Validation / SaaS Isolation
    # =========================================================================

    def _validate_task_context(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        require_user: bool = False,
        require_workspace: bool = False,
    ) -> Dict[str, Any]:
        """
        Validate SaaS-safe task/event context.

        user_id and workspace_id are required when user-specific execution
        is involved. System-level events may omit them only when intentional.
        """

        errors: List[str] = []

        if require_user and self._is_empty(user_id):
            errors.append("user_id is required for this event")

        if require_workspace and self._is_empty(workspace_id):
            errors.append("workspace_id is required for this event")

        if not self._is_empty(user_id) and not self._is_valid_context_value(user_id):
            errors.append("user_id must be a safe string or integer")

        if not self._is_empty(workspace_id) and not self._is_valid_context_value(workspace_id):
            errors.append("workspace_id must be a safe string or integer")

        if errors:
            return self._error_result(
                message="Invalid task/event context",
                error={"errors": errors},
                data={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "require_user": require_user,
                    "require_workspace": require_workspace,
                },
            )

        return self._safe_result(
            message="Task/event context valid",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "require_user": require_user,
                "require_workspace": require_workspace,
            },
        )

    @staticmethod
    def _is_empty(value: Any) -> bool:
        return value is None or value == ""

    @staticmethod
    def _is_valid_context_value(value: Any) -> bool:
        if isinstance(value, int):
            return value >= 0
        if isinstance(value, str):
            if not value.strip():
                return False
            if len(value) > 128:
                return False
            return True
        return False

    def _same_scope(
        self,
        event: Dict[str, Any],
        subscription: EventSubscription,
    ) -> bool:
        """
        Enforce SaaS isolation between event and subscription.
        """

        event_user_id = event.get("user_id")
        event_workspace_id = event.get("workspace_id")

        if subscription.user_id is not None and str(subscription.user_id) != str(event_user_id):
            return False

        if subscription.workspace_id is not None and str(subscription.workspace_id) != str(event_workspace_id):
            return False

        if subscription.agent_name is not None:
            source_agent = event.get("source_agent")
            target_agent = event.get("target_agent")
            if subscription.agent_name not in {source_agent, target_agent}:
                return False

        return True

    # =========================================================================
    # Security Hooks
    # =========================================================================

    def _requires_security_check(self, event_payload: Dict[str, Any]) -> bool:
        """
        Determine if an event requires Security Agent approval.

        This does not call Security Agent directly. It prepares a structured
        approval request or uses a callback when available.
        """

        event_type = str(event_payload.get("event_type", ""))
        severity = str(event_payload.get("severity", "")).lower()
        metadata = event_payload.get("metadata") or {}
        data = event_payload.get("data") or {}

        if event_type in self.SENSITIVE_EVENT_TYPES:
            return True

        if severity in {
            AgentEventSeverity.CRITICAL.value,
            AgentEventSeverity.ERROR.value,
        }:
            return True

        if bool(metadata.get("requires_security_check")):
            return True

        if bool(data.get("requires_security_check")):
            return True

        if bool(metadata.get("sensitive_action")):
            return True

        return False

    def _request_security_approval(self, event_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Request security approval for sensitive events.

        If a security_approval_callback exists, it is used.
        Otherwise, safe default behavior:
            - Allow internal audit/security events to be recorded
            - Deny events explicitly marked dangerous
            - Allow non-destructive events
        """

        self._stats["security_checks"] += 1

        approval_request = {
            "request_id": self.new_event_id("sec"),
            "event_id": event_payload.get("event_id"),
            "event_type": event_payload.get("event_type"),
            "source_agent": event_payload.get("source_agent"),
            "target_agent": event_payload.get("target_agent"),
            "user_id": event_payload.get("user_id"),
            "workspace_id": event_payload.get("workspace_id"),
            "severity": event_payload.get("severity"),
            "data_summary": self._safe_summary(event_payload.get("data")),
            "metadata": {
                "requested_by": self.agent_name,
                "timestamp": self.utc_now(),
            },
        }

        try:
            if self.security_approval_callback:
                callback_result = self.security_approval_callback(approval_request)

                if inspect.isawaitable(callback_result):
                    callback_result = self._run_awaitable_safely(callback_result)

                if isinstance(callback_result, bool):
                    approved = callback_result
                    reason = "Security callback boolean response"

                elif isinstance(callback_result, dict):
                    approved = bool(callback_result.get("approved", callback_result.get("success", False)))
                    reason = str(callback_result.get("reason", callback_result.get("message", "Security callback response")))
                else:
                    approved = False
                    reason = "Security callback returned unsupported response"

                if not approved:
                    self._stats["security_denials"] += 1

                return self._safe_result(
                    success=approved,
                    message="Security approval granted" if approved else "Security approval denied",
                    data={
                        "approved": approved,
                        "reason": reason,
                        "approval_request": approval_request,
                    },
                )

            dangerous = bool(
                event_payload.get("metadata", {}).get("dangerous")
                or event_payload.get("data", {}).get("dangerous")
                or event_payload.get("metadata", {}).get("destructive_action")
                or event_payload.get("data", {}).get("destructive_action")
            )

            if dangerous:
                self._stats["security_denials"] += 1
                return self._error_result(
                    message="Security approval denied by safe default policy",
                    error={
                        "approved": False,
                        "reason": "Event marked dangerous/destructive and no Security Agent callback is configured",
                        "approval_request": approval_request,
                    },
                )

            return self._safe_result(
                message="Security approval granted by safe default policy",
                data={
                    "approved": True,
                    "reason": "Non-destructive event allowed without external Security Agent callback",
                    "approval_request": approval_request,
                },
            )

        except Exception as exc:
            self._stats["security_denials"] += 1
            return self._error_result(
                message="Security approval failed",
                error=exc,
                data={"approval_request": approval_request},
            )

    # =========================================================================
    # Memory / Verification / Audit Hooks
    # =========================================================================

    def _prepare_verification_payload(self, event_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare a Verification Agent-compatible payload.
        """

        payload = {
            "verification_id": self.new_event_id("ver"),
            "source": "AgentEvents",
            "event_id": event_payload.get("event_id"),
            "event_type": event_payload.get("event_type"),
            "source_agent": event_payload.get("source_agent"),
            "target_agent": event_payload.get("target_agent"),
            "task_id": event_payload.get("task_id"),
            "workflow_id": event_payload.get("workflow_id"),
            "user_id": event_payload.get("user_id"),
            "workspace_id": event_payload.get("workspace_id"),
            "status": event_payload.get("status"),
            "severity": event_payload.get("severity"),
            "message": event_payload.get("message"),
            "data": self._safe_copy(event_payload.get("data", {})),
            "error": self._safe_copy(event_payload.get("error")),
            "metadata": {
                "prepared_by": self.agent_name,
                "prepared_at": self.utc_now(),
                "requires_review": event_payload.get("severity") in {
                    AgentEventSeverity.ERROR.value,
                    AgentEventSeverity.CRITICAL.value,
                },
            },
        }

        self._stats["verification_payloads_prepared"] += 1
        return payload

    def _prepare_memory_payload(self, event_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare a Memory Agent-compatible payload.
        """

        payload = {
            "memory_id": self.new_event_id("mem"),
            "source": "AgentEvents",
            "event_id": event_payload.get("event_id"),
            "event_type": event_payload.get("event_type"),
            "source_agent": event_payload.get("source_agent"),
            "target_agent": event_payload.get("target_agent"),
            "user_id": event_payload.get("user_id"),
            "workspace_id": event_payload.get("workspace_id"),
            "task_id": event_payload.get("task_id"),
            "workflow_id": event_payload.get("workflow_id"),
            "content": {
                "message": event_payload.get("message"),
                "data": self._safe_copy(event_payload.get("data", {})),
                "metadata": self._safe_copy(event_payload.get("metadata", {})),
            },
            "metadata": {
                "prepared_by": self.agent_name,
                "prepared_at": self.utc_now(),
                "importance": event_payload.get("metadata", {}).get("memory_importance", "normal"),
                "ttl": event_payload.get("metadata", {}).get("memory_ttl"),
            },
        }

        self._stats["memory_payloads_prepared"] += 1
        return payload

    def _log_audit_event(
        self,
        action: str,
        event_payload: Optional[Dict[str, Any]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log an audit-safe event in memory.

        Later, this can be connected to Postgres, SIEM, external audit storage,
        dashboard compliance pages, or admin activity logs.
        """

        if not self.enable_audit_log:
            return self._safe_result(
                message="Audit logging disabled",
                data={"logged": False},
            )

        audit_payload = {
            "audit_id": self.new_event_id("audit"),
            "action": action,
            "event_id": (event_payload or {}).get("event_id"),
            "event_type": (event_payload or {}).get("event_type"),
            "source_agent": (event_payload or {}).get("source_agent", self.agent_name),
            "target_agent": (event_payload or {}).get("target_agent"),
            "user_id": user_id if user_id is not None else (event_payload or {}).get("user_id"),
            "workspace_id": workspace_id if workspace_id is not None else (event_payload or {}).get("workspace_id"),
            "metadata": metadata or {},
            "created_at": self.utc_now(),
        }

        with self._lock:
            self._audit_history.append(audit_payload)
            self._stats["audit_events"] += 1

        return self._safe_result(
            message="Audit event logged",
            data={"logged": True, "audit_event": audit_payload},
        )

    def _emit_agent_event(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """
        Compatibility hook used by BaseAgent-style files.

        This delegates to publish_event().
        """
        return self.publish_event(*args, **kwargs)

    # =========================================================================
    # Event Creation
    # =========================================================================

    def create_event(
        self,
        event_type: Union[str, AgentEventType],
        source_agent: str,
        message: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        target_agent: Optional[str] = None,
        task_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        severity: Union[str, AgentEventSeverity] = AgentEventSeverity.INFO,
        priority: Union[str, AgentEventPriority] = AgentEventPriority.NORMAL,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any], Exception]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        require_user: bool = False,
        require_workspace: bool = False,
    ) -> Dict[str, Any]:
        """
        Create a canonical event dictionary without publishing it.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_user=require_user,
            require_workspace=require_workspace,
        )
        if not context_result.get("success"):
            return context_result

        try:
            event_type_value = self._enum_value(event_type)
            severity_value = self._enum_value(severity)
            priority_value = self._enum_value(priority)

            event_error: Optional[Dict[str, Any]]
            if isinstance(error, Exception):
                event_error = {
                    "type": error.__class__.__name__,
                    "message": str(error),
                    "traceback": traceback.format_exc(),
                }
            elif isinstance(error, dict):
                event_error = self._safe_copy(error)
            elif isinstance(error, str):
                event_error = {"message": error}
            else:
                event_error = None

            event = AgentEvent(
                event_id=self.new_event_id(),
                event_type=event_type_value,
                source_agent=source_agent or "unknown_agent",
                target_agent=target_agent,
                message=message or "",
                user_id=user_id,
                workspace_id=workspace_id,
                task_id=task_id,
                workflow_id=workflow_id,
                severity=severity_value,
                priority=priority_value,
                data=self._safe_copy(data or {}),
                error=event_error,
                metadata=self._safe_copy(metadata or {}),
            )

            event_dict = asdict(event)

            with self._lock:
                self._stats["events_created"] += 1

            return self._safe_result(
                message="Event created",
                data={"event": event_dict},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to create event",
                error=exc,
            )

    # =========================================================================
    # Publishing
    # =========================================================================

    def publish_event(
        self,
        event_type: Union[str, AgentEventType],
        source_agent: str,
        message: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        target_agent: Optional[str] = None,
        task_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        severity: Union[str, AgentEventSeverity] = AgentEventSeverity.INFO,
        priority: Union[str, AgentEventPriority] = AgentEventPriority.NORMAL,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any], Exception]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        require_user: bool = False,
        require_workspace: bool = False,
        prepare_memory: Optional[bool] = None,
        prepare_verification: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Create and publish an event to all matching subscribers.

        This is the main public method used by agents, router, registry,
        dashboard API, and task/workflow services.
        """

        created = self.create_event(
            event_type=event_type,
            source_agent=source_agent,
            target_agent=target_agent,
            message=message,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            workflow_id=workflow_id,
            severity=severity,
            priority=priority,
            data=data,
            error=error,
            metadata=metadata,
            require_user=require_user,
            require_workspace=require_workspace,
        )

        if not created.get("success"):
            return created

        event_payload = created["data"]["event"]
        return self.publish_existing_event(
            event_payload=event_payload,
            prepare_memory=prepare_memory,
            prepare_verification=prepare_verification,
        )

    def publish_existing_event(
        self,
        event_payload: Dict[str, Any],
        prepare_memory: Optional[bool] = None,
        prepare_verification: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Publish an already-created event dictionary.
        """

        try:
            event_payload = self._normalize_event_payload(event_payload)

            if self.enable_security_gate and self._requires_security_check(event_payload):
                approval = self._request_security_approval(event_payload)
                approved = bool((approval.get("data") or {}).get("approved", approval.get("success", False)))
                if not approved:
                    event_payload["status"] = AgentEventStatus.FAILED.value
                    self._record_error_event(event_payload)
                    self._log_audit_event(
                        action="security_denied_event_publish",
                        event_payload=event_payload,
                        metadata={"approval": approval},
                    )
                    return self._error_result(
                        message="Event publish blocked by security approval",
                        error=approval.get("error") or approval.get("message"),
                        data={"event": event_payload, "approval": approval},
                    )

            event_payload["status"] = AgentEventStatus.PUBLISHED.value
            event_payload["published_at"] = self.utc_now()

            delivered = self._deliver_event(event_payload)

            memory_payload = None
            verification_payload = None

            should_prepare_memory = (
                self.enable_memory_payloads
                if prepare_memory is None
                else bool(prepare_memory)
            )
            should_prepare_verification = (
                self.enable_verification_payloads
                if prepare_verification is None
                else bool(prepare_verification)
            )

            if should_prepare_memory and self._is_memory_relevant(event_payload):
                memory_payload = self._prepare_memory_payload(event_payload)

            if should_prepare_verification and self._is_verification_relevant(event_payload):
                verification_payload = self._prepare_verification_payload(event_payload)

            with self._lock:
                self._event_history.append(self._safe_copy(event_payload))
                self._stats["events_published"] += 1
                self._stats["last_event_at"] = self.utc_now()

                if event_payload.get("event_type") in self.ERROR_EVENT_TYPES or event_payload.get("error"):
                    self._error_history.append(self._safe_copy(event_payload))
                    self._stats["error_events"] += 1

            if self.enable_audit_log:
                self._log_audit_event(
                    action="event_published",
                    event_payload=event_payload,
                    metadata={
                        "delivered_count": len(delivered.get("data", {}).get("delivered_to", [])),
                    },
                )

            return self._safe_result(
                message="Event published",
                data={
                    "event": event_payload,
                    "delivered": delivered.get("data", {}),
                    "memory_payload": memory_payload,
                    "verification_payload": verification_payload,
                },
            )

        except Exception as exc:
            with self._lock:
                self._stats["events_failed"] += 1

            return self._error_result(
                message="Failed to publish event",
                error=exc,
                data={"event": self._safe_copy(event_payload)},
            )

    def _deliver_event(self, event_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Deliver event to matching subscriptions and target agent inbox.
        """

        delivered_to: List[str] = []
        failed_callbacks: List[Dict[str, Any]] = []

        event_type = str(event_payload.get("event_type", ""))

        with self._lock:
            subscription_ids = set(self._subscriptions_by_event_type.get(event_type, set()))
            subscription_ids.update(self._subscriptions_by_event_type.get("*", set()))

            target_agent = event_payload.get("target_agent")
            if target_agent:
                self._agent_inboxes[str(target_agent)].append(self._safe_copy(event_payload))
                delivered_to.append(f"agent_inbox:{target_agent}")

            subscriptions = [
                self._subscriptions[sub_id]
                for sub_id in subscription_ids
                if sub_id in self._subscriptions
            ]

        for subscription in subscriptions:
            if not subscription.active:
                continue

            if not self._subscription_accepts_event(subscription, event_payload):
                continue

            try:
                result = subscription.callback(self._safe_copy(event_payload))
                if inspect.isawaitable(result):
                    result = self._run_awaitable_safely(result)

                delivered_to.append(subscription.subscription_id)

                with self._lock:
                    self._stats["callbacks_delivered"] += 1

            except Exception as exc:
                failed_callbacks.append(
                    {
                        "subscription_id": subscription.subscription_id,
                        "error": {
                            "type": exc.__class__.__name__,
                            "message": str(exc),
                        },
                    }
                )
                with self._lock:
                    self._stats["callbacks_failed"] += 1

        event_payload["delivered_to"] = delivered_to

        return self._safe_result(
            message="Event delivered",
            data={
                "delivered_to": delivered_to,
                "failed_callbacks": failed_callbacks,
                "delivered_count": len(delivered_to),
                "failed_count": len(failed_callbacks),
            },
        )

    def _subscription_accepts_event(
        self,
        subscription: EventSubscription,
        event_payload: Dict[str, Any],
    ) -> bool:
        """
        Check event type, scope, audit, and error filters.
        """

        event_type = str(event_payload.get("event_type", ""))

        if subscription.event_types and "*" not in subscription.event_types:
            if event_type not in subscription.event_types:
                return False

        if event_type == AgentEventType.AUDIT_EVENT.value and not subscription.include_audit:
            return False

        if event_type in self.ERROR_EVENT_TYPES and not subscription.include_errors:
            return False

        if not self._same_scope(event_payload, subscription):
            return False

        return True

    # =========================================================================
    # Subscribe / Unsubscribe
    # =========================================================================

    def subscribe(
        self,
        callback: EventCallback,
        event_types: Optional[Iterable[Union[str, AgentEventType]]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        agent_name: Optional[str] = None,
        include_audit: bool = False,
        include_errors: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Subscribe to event stream.

        event_types:
            None or ["*"] means all events.
        """

        if not callable(callback):
            return self._error_result(
                message="Subscription callback must be callable",
                error="invalid_callback",
            )

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            require_user=False,
            require_workspace=False,
        )
        if not context_result.get("success"):
            return context_result

        normalized_types = {
            self._enum_value(event_type)
            for event_type in (event_types or ["*"])
        }

        subscription = EventSubscription(
            subscription_id=self.new_subscription_id(),
            callback=callback,
            event_types=normalized_types,
            user_id=user_id,
            workspace_id=workspace_id,
            agent_name=agent_name,
            include_audit=include_audit,
            include_errors=include_errors,
            metadata=metadata or {},
        )

        with self._lock:
            self._subscriptions[subscription.subscription_id] = subscription
            for event_type in normalized_types:
                self._subscriptions_by_event_type[event_type].add(subscription.subscription_id)

        self._log_audit_event(
            action="event_subscription_created",
            user_id=user_id,
            workspace_id=workspace_id,
            metadata={
                "subscription_id": subscription.subscription_id,
                "event_types": sorted(normalized_types),
                "agent_name": agent_name,
            },
        )

        return self._safe_result(
            message="Subscription created",
            data={
                "subscription_id": subscription.subscription_id,
                "subscription": self._subscription_to_public_dict(subscription),
            },
        )

    def unsubscribe(self, subscription_id: str) -> Dict[str, Any]:
        """
        Remove a subscription by ID.
        """

        if not subscription_id:
            return self._error_result(
                message="subscription_id is required",
                error="missing_subscription_id",
            )

        with self._lock:
            subscription = self._subscriptions.pop(subscription_id, None)

            if not subscription:
                return self._error_result(
                    message="Subscription not found",
                    error="subscription_not_found",
                    data={"subscription_id": subscription_id},
                )

            for event_type in subscription.event_types:
                self._subscriptions_by_event_type[event_type].discard(subscription_id)

        self._log_audit_event(
            action="event_subscription_removed",
            user_id=subscription.user_id,
            workspace_id=subscription.workspace_id,
            metadata={"subscription_id": subscription_id},
        )

        return self._safe_result(
            message="Subscription removed",
            data={"subscription_id": subscription_id},
        )

    def pause_subscription(self, subscription_id: str) -> Dict[str, Any]:
        """
        Temporarily disable a subscription without deleting it.
        """

        with self._lock:
            subscription = self._subscriptions.get(subscription_id)
            if not subscription:
                return self._error_result(
                    message="Subscription not found",
                    error="subscription_not_found",
                    data={"subscription_id": subscription_id},
                )
            subscription.active = False

        return self._safe_result(
            message="Subscription paused",
            data={"subscription_id": subscription_id},
        )

    def resume_subscription(self, subscription_id: str) -> Dict[str, Any]:
        """
        Re-enable a paused subscription.
        """

        with self._lock:
            subscription = self._subscriptions.get(subscription_id)
            if not subscription:
                return self._error_result(
                    message="Subscription not found",
                    error="subscription_not_found",
                    data={"subscription_id": subscription_id},
                )
            subscription.active = True

        return self._safe_result(
            message="Subscription resumed",
            data={"subscription_id": subscription_id},
        )

    def list_subscriptions(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        agent_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        List subscriptions with optional SaaS-safe filtering.
        """

        with self._lock:
            subscriptions = list(self._subscriptions.values())

        filtered: List[Dict[str, Any]] = []
        for sub in subscriptions:
            if user_id is not None and str(sub.user_id) != str(user_id):
                continue
            if workspace_id is not None and str(sub.workspace_id) != str(workspace_id):
                continue
            if agent_name is not None and sub.agent_name != agent_name:
                continue
            filtered.append(self._subscription_to_public_dict(sub))

        return self._safe_result(
            message="Subscriptions listed",
            data={
                "subscriptions": filtered,
                "count": len(filtered),
            },
        )

    # =========================================================================
    # Agent-to-Agent Messages
    # =========================================================================

    def send_agent_message(
        self,
        source_agent: str,
        target_agent: str,
        message: str,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        data: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        priority: Union[str, AgentEventPriority] = AgentEventPriority.NORMAL,
        metadata: Optional[Dict[str, Any]] = None,
        require_user: bool = True,
        require_workspace: bool = True,
    ) -> Dict[str, Any]:
        """
        Send an isolated agent-to-agent message.
        """

        return self.publish_event(
            event_type=AgentEventType.AGENT_MESSAGE,
            source_agent=source_agent,
            target_agent=target_agent,
            message=message,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            workflow_id=workflow_id,
            priority=priority,
            data=data or {},
            metadata=metadata or {},
            require_user=require_user,
            require_workspace=require_workspace,
        )

    def read_agent_inbox(
        self,
        agent_name: str,
        limit: int = 50,
        pop: bool = False,
    ) -> Dict[str, Any]:
        """
        Read events delivered to a target agent inbox.

        pop=False:
            returns a copy and keeps messages.

        pop=True:
            removes returned messages from inbox.
        """

        if not agent_name:
            return self._error_result(
                message="agent_name is required",
                error="missing_agent_name",
            )

        safe_limit = max(1, min(int(limit), 500))

        with self._lock:
            inbox = self._agent_inboxes[agent_name]

            if pop:
                events: List[Dict[str, Any]] = []
                while inbox and len(events) < safe_limit:
                    events.append(inbox.popleft())
            else:
                events = list(inbox)[-safe_limit:]

        return self._safe_result(
            message="Agent inbox read",
            data={
                "agent_name": agent_name,
                "events": self._safe_copy(events),
                "count": len(events),
                "pop": pop,
            },
        )

    def clear_agent_inbox(self, agent_name: str) -> Dict[str, Any]:
        """
        Clear target agent inbox.
        """

        if not agent_name:
            return self._error_result(
                message="agent_name is required",
                error="missing_agent_name",
            )

        with self._lock:
            count = len(self._agent_inboxes[agent_name])
            self._agent_inboxes[agent_name].clear()

        return self._safe_result(
            message="Agent inbox cleared",
            data={"agent_name": agent_name, "cleared": count},
        )

    # =========================================================================
    # Task Event Helpers
    # =========================================================================

    def task_created(
        self,
        source_agent: str,
        task_id: str,
        message: str = "Task created",
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.publish_event(
            event_type=AgentEventType.TASK_CREATED,
            source_agent=source_agent,
            message=message,
            task_id=task_id,
            user_id=user_id,
            workspace_id=workspace_id,
            data=data or {},
            metadata=metadata or {},
            require_user=True,
            require_workspace=True,
        )

    def task_started(
        self,
        source_agent: str,
        task_id: str,
        message: str = "Task started",
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.publish_event(
            event_type=AgentEventType.TASK_STARTED,
            source_agent=source_agent,
            message=message,
            task_id=task_id,
            user_id=user_id,
            workspace_id=workspace_id,
            data=data or {},
            metadata=metadata or {},
            require_user=True,
            require_workspace=True,
        )

    def task_progress(
        self,
        source_agent: str,
        task_id: str,
        progress: Union[int, float],
        message: str = "Task progress updated",
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        safe_progress = max(0.0, min(float(progress), 100.0))
        payload = data or {}
        payload["progress"] = safe_progress

        return self.publish_event(
            event_type=AgentEventType.TASK_PROGRESS,
            source_agent=source_agent,
            message=message,
            task_id=task_id,
            user_id=user_id,
            workspace_id=workspace_id,
            data=payload,
            metadata=metadata or {},
            require_user=True,
            require_workspace=True,
        )

    def task_completed(
        self,
        source_agent: str,
        task_id: str,
        message: str = "Task completed",
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.publish_event(
            event_type=AgentEventType.TASK_COMPLETED,
            source_agent=source_agent,
            message=message,
            task_id=task_id,
            user_id=user_id,
            workspace_id=workspace_id,
            data=data or {},
            metadata=metadata or {},
            require_user=True,
            require_workspace=True,
            prepare_memory=True,
            prepare_verification=True,
        )

    def task_failed(
        self,
        source_agent: str,
        task_id: str,
        message: str = "Task failed",
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        error: Optional[Union[str, Dict[str, Any], Exception]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.publish_event(
            event_type=AgentEventType.TASK_FAILED,
            source_agent=source_agent,
            message=message,
            task_id=task_id,
            user_id=user_id,
            workspace_id=workspace_id,
            severity=AgentEventSeverity.ERROR,
            error=error,
            data=data or {},
            metadata=metadata or {},
            require_user=True,
            require_workspace=True,
            prepare_verification=True,
        )

    def task_cancelled(
        self,
        source_agent: str,
        task_id: str,
        message: str = "Task cancelled",
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.publish_event(
            event_type=AgentEventType.TASK_CANCELLED,
            source_agent=source_agent,
            message=message,
            task_id=task_id,
            user_id=user_id,
            workspace_id=workspace_id,
            severity=AgentEventSeverity.WARNING,
            data=data or {},
            metadata=metadata or {},
            require_user=True,
            require_workspace=True,
            prepare_verification=True,
        )

    # =========================================================================
    # Workflow Event Helpers
    # =========================================================================

    def workflow_started(
        self,
        source_agent: str,
        workflow_id: str,
        message: str = "Workflow started",
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.publish_event(
            event_type=AgentEventType.WORKFLOW_STARTED,
            source_agent=source_agent,
            message=message,
            workflow_id=workflow_id,
            user_id=user_id,
            workspace_id=workspace_id,
            data=data or {},
            require_user=True,
            require_workspace=True,
        )

    def workflow_step(
        self,
        source_agent: str,
        workflow_id: str,
        step_name: str,
        message: str = "Workflow step updated",
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        payload = data or {}
        payload["step_name"] = step_name

        return self.publish_event(
            event_type=AgentEventType.WORKFLOW_STEP,
            source_agent=source_agent,
            message=message,
            workflow_id=workflow_id,
            user_id=user_id,
            workspace_id=workspace_id,
            data=payload,
            require_user=True,
            require_workspace=True,
        )

    def workflow_completed(
        self,
        source_agent: str,
        workflow_id: str,
        message: str = "Workflow completed",
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.publish_event(
            event_type=AgentEventType.WORKFLOW_COMPLETED,
            source_agent=source_agent,
            message=message,
            workflow_id=workflow_id,
            user_id=user_id,
            workspace_id=workspace_id,
            data=data or {},
            require_user=True,
            require_workspace=True,
            prepare_memory=True,
            prepare_verification=True,
        )

    def workflow_failed(
        self,
        source_agent: str,
        workflow_id: str,
        message: str = "Workflow failed",
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        error: Optional[Union[str, Dict[str, Any], Exception]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.publish_event(
            event_type=AgentEventType.WORKFLOW_FAILED,
            source_agent=source_agent,
            message=message,
            workflow_id=workflow_id,
            user_id=user_id,
            workspace_id=workspace_id,
            severity=AgentEventSeverity.ERROR,
            error=error,
            data=data or {},
            require_user=True,
            require_workspace=True,
            prepare_verification=True,
        )

    # =========================================================================
    # Error / Health / Audit Public Helpers
    # =========================================================================

    def emit_error(
        self,
        source_agent: str,
        message: str,
        error: Optional[Union[str, Dict[str, Any], Exception]] = None,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        task_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        severity: Union[str, AgentEventSeverity] = AgentEventSeverity.ERROR,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Publish a structured error event.
        """

        return self.publish_event(
            event_type=AgentEventType.ERROR_EVENT,
            source_agent=source_agent,
            message=message,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            workflow_id=workflow_id,
            severity=severity,
            error=error,
            data=data or {},
            metadata=metadata or {},
            require_user=False,
            require_workspace=False,
            prepare_verification=True,
        )

    def emit_health(
        self,
        source_agent: str,
        status: str,
        message: str = "Health event",
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Publish agent/system health status.
        """

        payload = data or {}
        payload["health_status"] = status

        severity = AgentEventSeverity.INFO
        if status.lower() in {"degraded", "warning"}:
            severity = AgentEventSeverity.WARNING
        elif status.lower() in {"down", "failed", "critical"}:
            severity = AgentEventSeverity.ERROR

        return self.publish_event(
            event_type=AgentEventType.HEALTH_EVENT,
            source_agent=source_agent,
            message=message,
            user_id=user_id,
            workspace_id=workspace_id,
            severity=severity,
            data=payload,
            require_user=False,
            require_workspace=False,
        )

    def emit_audit(
        self,
        source_agent: str,
        action: str,
        message: str = "Audit event",
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Publish and store an audit event.
        """

        payload = data or {}
        payload["action"] = action

        result = self.publish_event(
            event_type=AgentEventType.AUDIT_EVENT,
            source_agent=source_agent,
            message=message,
            user_id=user_id,
            workspace_id=workspace_id,
            data=payload,
            metadata=metadata or {},
            require_user=False,
            require_workspace=False,
        )

        self._log_audit_event(
            action=action,
            event_payload=(result.get("data") or {}).get("event", {}),
            user_id=user_id,
            workspace_id=workspace_id,
            metadata=metadata or {},
        )

        return result

    def _record_error_event(self, event_payload: Dict[str, Any]) -> None:
        with self._lock:
            self._error_history.append(self._safe_copy(event_payload))
            self._stats["error_events"] += 1
            self._stats["events_failed"] += 1

    # =========================================================================
    # History / Dashboard / API Helpers
    # =========================================================================

    def get_event_history(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        event_type: Optional[Union[str, AgentEventType]] = None,
        source_agent: Optional[str] = None,
        target_agent: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Get event history filtered safely by user/workspace/event type/agent.
        """

        safe_limit = max(1, min(int(limit), self.max_history))
        event_type_value = self._enum_value(event_type) if event_type else None

        with self._lock:
            events = list(self._event_history)

        filtered = self._filter_events(
            events=events,
            user_id=user_id,
            workspace_id=workspace_id,
            event_type=event_type_value,
            source_agent=source_agent,
            target_agent=target_agent,
        )[-safe_limit:]

        return self._safe_result(
            message="Event history fetched",
            data={
                "events": self._safe_copy(filtered),
                "count": len(filtered),
                "limit": safe_limit,
            },
        )

    def get_audit_history(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Get audit history filtered safely by user/workspace.
        """

        safe_limit = max(1, min(int(limit), self.max_audit_history))

        with self._lock:
            audits = list(self._audit_history)

        filtered = []
        for item in audits:
            if user_id is not None and str(item.get("user_id")) != str(user_id):
                continue
            if workspace_id is not None and str(item.get("workspace_id")) != str(workspace_id):
                continue
            filtered.append(item)

        filtered = filtered[-safe_limit:]

        return self._safe_result(
            message="Audit history fetched",
            data={
                "audit_events": self._safe_copy(filtered),
                "count": len(filtered),
                "limit": safe_limit,
            },
        )

    def get_error_history(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        source_agent: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Get error history filtered safely by user/workspace/agent.
        """

        safe_limit = max(1, min(int(limit), self.max_error_history))

        with self._lock:
            errors = list(self._error_history)

        filtered = self._filter_events(
            events=errors,
            user_id=user_id,
            workspace_id=workspace_id,
            source_agent=source_agent,
        )[-safe_limit:]

        return self._safe_result(
            message="Error history fetched",
            data={
                "error_events": self._safe_copy(filtered),
                "count": len(filtered),
                "limit": safe_limit,
            },
        )

    def get_dashboard_snapshot(
        self,
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """
        Return dashboard-friendly snapshot.

        Useful for FastAPI/Flask dashboard endpoints, admin panels,
        live event monitor, and SaaS workspace activity pages.
        """

        events = self.get_event_history(
            user_id=user_id,
            workspace_id=workspace_id,
            limit=limit,
        )
        errors = self.get_error_history(
            user_id=user_id,
            workspace_id=workspace_id,
            limit=limit,
        )
        audits = self.get_audit_history(
            user_id=user_id,
            workspace_id=workspace_id,
            limit=limit,
        )

        return self._safe_result(
            message="Dashboard snapshot fetched",
            data={
                "stats": self.get_stats().get("data", {}),
                "recent_events": events.get("data", {}).get("events", []),
                "recent_errors": errors.get("data", {}).get("error_events", []),
                "recent_audit_events": audits.get("data", {}).get("audit_events", []),
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
        )

    def clear_history(
        self,
        clear_events: bool = True,
        clear_audits: bool = False,
        clear_errors: bool = True,
    ) -> Dict[str, Any]:
        """
        Clear in-memory histories.

        Audit history is not cleared by default.
        """

        with self._lock:
            event_count = len(self._event_history)
            audit_count = len(self._audit_history)
            error_count = len(self._error_history)

            if clear_events:
                self._event_history.clear()
            if clear_audits:
                self._audit_history.clear()
            if clear_errors:
                self._error_history.clear()

        return self._safe_result(
            message="History cleared",
            data={
                "cleared_events": event_count if clear_events else 0,
                "cleared_audits": audit_count if clear_audits else 0,
                "cleared_errors": error_count if clear_errors else 0,
            },
        )

    # =========================================================================
    # Stats / Health
    # =========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """
        Return event bus stats.
        """

        with self._lock:
            stats = self._safe_copy(self._stats)
            stats.update(
                {
                    "history_size": len(self._event_history),
                    "audit_history_size": len(self._audit_history),
                    "error_history_size": len(self._error_history),
                    "subscriptions": len(self._subscriptions),
                    "agent_inboxes": {
                        agent: len(inbox)
                        for agent, inbox in self._agent_inboxes.items()
                    },
                }
            )

        return self._safe_result(
            message="Stats fetched",
            data=stats,
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Health check for AgentEvents.

        Compatible with future agent_health.py and dashboard monitoring.
        """

        stats = self.get_stats().get("data", {})

        status = "healthy"
        issues: List[str] = []

        if stats.get("callbacks_failed", 0) > stats.get("callbacks_delivered", 0) and stats.get("callbacks_failed", 0) > 10:
            status = "degraded"
            issues.append("High callback failure count")

        if stats.get("events_failed", 0) > 100:
            status = "degraded"
            issues.append("High event failure count")

        return self._safe_result(
            message="AgentEvents health check completed",
            data={
                "status": status,
                "issues": issues,
                "stats": stats,
                "timestamp": self.utc_now(),
            },
        )

    # =========================================================================
    # Async Convenience
    # =========================================================================

    async def async_publish_event(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Async wrapper for publish_event.

        Useful for FastAPI, async workers, and future real-time systems.
        """

        return self.publish_event(*args, **kwargs)

    async def async_send_agent_message(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Async wrapper for send_agent_message.
        """

        return self.send_agent_message(*args, **kwargs)

    # =========================================================================
    # Internal Utility
    # =========================================================================

    def _normalize_event_payload(self, event_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ensure event payload contains all required fields.
        """

        if not isinstance(event_payload, dict):
            raise ValueError("event_payload must be a dict")

        normalized = self._safe_copy(event_payload)

        normalized.setdefault("event_id", self.new_event_id())
        normalized.setdefault("event_type", AgentEventType.CUSTOM.value)
        normalized.setdefault("source_agent", "unknown_agent")
        normalized.setdefault("target_agent", None)
        normalized.setdefault("message", "")
        normalized.setdefault("user_id", None)
        normalized.setdefault("workspace_id", None)
        normalized.setdefault("task_id", None)
        normalized.setdefault("workflow_id", None)
        normalized.setdefault("severity", AgentEventSeverity.INFO.value)
        normalized.setdefault("priority", AgentEventPriority.NORMAL.value)
        normalized.setdefault("status", AgentEventStatus.CREATED.value)
        normalized.setdefault("data", {})
        normalized.setdefault("error", None)
        normalized.setdefault("metadata", {})
        normalized.setdefault("created_at", self.utc_now())
        normalized.setdefault("published_at", None)
        normalized.setdefault("delivered_to", [])

        return normalized

    def _filter_events(
        self,
        events: List[Dict[str, Any]],
        user_id: Optional[Union[str, int]] = None,
        workspace_id: Optional[Union[str, int]] = None,
        event_type: Optional[str] = None,
        source_agent: Optional[str] = None,
        target_agent: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Filter events safely.
        """

        filtered: List[Dict[str, Any]] = []

        for event in events:
            if user_id is not None and str(event.get("user_id")) != str(user_id):
                continue
            if workspace_id is not None and str(event.get("workspace_id")) != str(workspace_id):
                continue
            if event_type is not None and event.get("event_type") != event_type:
                continue
            if source_agent is not None and event.get("source_agent") != source_agent:
                continue
            if target_agent is not None and event.get("target_agent") != target_agent:
                continue
            filtered.append(event)

        return filtered

    def _is_memory_relevant(self, event_payload: Dict[str, Any]) -> bool:
        """
        Check if an event should produce a Memory Agent payload.
        """

        event_type = str(event_payload.get("event_type", ""))

        if event_type in self.MEMORY_RELEVANT_TYPES:
            return True

        metadata = event_payload.get("metadata") or {}
        if metadata.get("save_to_memory") is True:
            return True

        return False

    def _is_verification_relevant(self, event_payload: Dict[str, Any]) -> bool:
        """
        Check if an event should produce a Verification Agent payload.
        """

        event_type = str(event_payload.get("event_type", ""))

        if event_type in self.COMPLETION_EVENT_TYPES:
            return True

        if event_type in self.ERROR_EVENT_TYPES:
            return True

        metadata = event_payload.get("metadata") or {}
        if metadata.get("requires_verification") is True:
            return True

        return False

    @staticmethod
    def _enum_value(value: Any) -> str:
        """
        Convert enum or string to string.
        """

        if isinstance(value, Enum):
            return str(value.value)
        if value is None:
            return ""
        return str(value)

    @staticmethod
    def _safe_copy(value: Any) -> Any:
        """
        Safe copy utility.
        """

        try:
            return copy.deepcopy(value)
        except Exception:
            return value

    @staticmethod
    def _safe_summary(value: Any, max_length: int = 500) -> Any:
        """
        Return a small safe summary of a value for security/audit payloads.
        """

        try:
            text = repr(value)
            if len(text) > max_length:
                return text[:max_length] + "...[truncated]"
            return text
        except Exception:
            return "[unrepresentable]"

    def _run_awaitable_safely(self, awaitable: Awaitable[Any]) -> Any:
        """
        Run awaitable from sync context when possible.

        If called inside an already-running event loop, this returns a safe
        dictionary instead of forcing nested loop execution.
        """

        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                return {
                    "success": False,
                    "message": "Awaitable callback cannot be synchronously awaited inside a running event loop",
                    "error": "running_event_loop_detected",
                }
        except RuntimeError:
            pass

        try:
            return asyncio.run(awaitable)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            try:
                asyncio.set_event_loop(loop)
                return loop.run_until_complete(awaitable)
            finally:
                try:
                    loop.close()
                except Exception:
                    pass

    @staticmethod
    def _subscription_to_public_dict(subscription: EventSubscription) -> Dict[str, Any]:
        """
        Return safe subscription information without exposing callback object.
        """

        return {
            "subscription_id": subscription.subscription_id,
            "event_types": sorted(subscription.event_types),
            "user_id": subscription.user_id,
            "workspace_id": subscription.workspace_id,
            "agent_name": subscription.agent_name,
            "include_audit": subscription.include_audit,
            "include_errors": subscription.include_errors,
            "active": subscription.active,
            "created_at": subscription.created_at,
            "metadata": subscription.metadata,
        }


# =============================================================================
# Global singleton helpers
# =============================================================================

_GLOBAL_AGENT_EVENTS: Optional[AgentEvents] = None
_GLOBAL_AGENT_EVENTS_LOCK = threading.RLock()


def get_agent_events() -> AgentEvents:
    """
    Get global AgentEvents singleton.

    Useful for registry, router, dashboard, API routes, workers,
    and future plugin-style agents.
    """

    global _GLOBAL_AGENT_EVENTS

    with _GLOBAL_AGENT_EVENTS_LOCK:
        if _GLOBAL_AGENT_EVENTS is None:
            _GLOBAL_AGENT_EVENTS = AgentEvents()
        return _GLOBAL_AGENT_EVENTS


def set_agent_events(agent_events: AgentEvents) -> Dict[str, Any]:
    """
    Override global AgentEvents singleton.

    Useful for tests, dependency injection, or production app bootstrap.
    """

    global _GLOBAL_AGENT_EVENTS

    if not isinstance(agent_events, AgentEvents):
        return {
            "success": False,
            "message": "agent_events must be an AgentEvents instance",
            "data": {},
            "error": "invalid_agent_events_instance",
            "metadata": {
                "timestamp": AgentEvents.utc_now(),
            },
        }

    with _GLOBAL_AGENT_EVENTS_LOCK:
        _GLOBAL_AGENT_EVENTS = agent_events

    return {
        "success": True,
        "message": "Global AgentEvents instance set",
        "data": {
            "agent_name": agent_events.agent_name,
            "agent_id": agent_events.agent_id,
        },
        "error": None,
        "metadata": {
            "timestamp": AgentEvents.utc_now(),
        },
    }


def emit_agent_event(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """
    Convenience global emit function.
    """

    return get_agent_events().publish_event(*args, **kwargs)


def send_agent_message(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """
    Convenience global agent-to-agent message function.
    """

    return get_agent_events().send_agent_message(*args, **kwargs)


# =============================================================================
# Self-test
# =============================================================================

def _self_test() -> Dict[str, Any]:
    """
    Lightweight self-test.

    Run:
        python agents/agent_events.py
    """

    bus = AgentEvents()
    received: List[Dict[str, Any]] = []

    def listener(event: Dict[str, Any]) -> None:
        received.append(event)

    sub = bus.subscribe(
        callback=listener,
        event_types=[AgentEventType.TASK_COMPLETED],
        user_id=1,
        workspace_id=10,
    )

    if not sub.get("success"):
        return sub

    result = bus.task_completed(
        source_agent="TestAgent",
        task_id="task_123",
        user_id=1,
        workspace_id=10,
        data={"result": "ok"},
    )

    health = bus.health_check()

    return {
        "success": bool(result.get("success")) and len(received) == 1,
        "message": "AgentEvents self-test completed",
        "data": {
            "publish_result": result,
            "received_count": len(received),
            "health": health,
            "stats": bus.get_stats(),
        },
        "error": None,
        "metadata": {
            "timestamp": AgentEvents.utc_now(),
        },
    }


if __name__ == "__main__":
    import json

    print(json.dumps(_self_test(), indent=2, default=str))


"""
Agent/Module: Global Agent Infrastructure Files
File Completed: agent_events.py
Completion: 77.8%
Completed Files: ['base_agent.py', 'registry.py', 'agent_loader.py', 'agent_router.py', 'agent_manifest.py', 'agent_permissions.py', 'agent_events.py']
Remaining Files: ['agent_health.py', 'agent_config.py']
Next Recommended File: agents/agent_health.py
FILE COMPLETE
"""