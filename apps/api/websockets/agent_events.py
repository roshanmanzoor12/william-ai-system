"""
apps/api/websockets/agent_events.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Agent/Module: API Prompt Bible
Purpose: real-time agent status and task events to dashboard

This module is intentionally import-safe:
- It does not require future project files to exist.
- It avoids hardcoded secrets.
- It uses safe environment defaults.
- It enforces user_id and workspace_id isolation for every WebSocket connection/event.
- It provides a fallback in-process event broker for development.
- It exposes helper functions that future agents/routes/workers can import and call.

Core responsibilities:
- Accept dashboard WebSocket connections.
- Authenticate/scope each connection by user_id and workspace_id.
- Broadcast real-time agent status and task events to the correct dashboard room.
- Prevent cross-user/workspace event leakage.
- Support heartbeat/ping/pong.
- Support dashboard event subscriptions.
- Add audit hooks for connection and event publishing.
- Prepare future-compatible hooks for Master Agent, Security Agent, Memory Agent,
  and Verification Agent.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Set, Tuple

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field, ValidationError, field_validator


# =============================================================================
# Optional future integrations
# =============================================================================

try:
    from apps.api.routes.security import audit_log as project_audit_log  # type: ignore
except Exception:
    project_audit_log = None

try:
    from apps.api.routes.security import require_security_approval as project_security_approval  # type: ignore
except Exception:
    project_security_approval = None

try:
    from apps.api.routes.billing import check_usage_limit as project_check_usage_limit  # type: ignore
except Exception:
    project_check_usage_limit = None

try:
    from apps.api.services.verification import prepare_verification_payload as project_prepare_verification  # type: ignore
except Exception:
    project_prepare_verification = None

try:
    from apps.api.services.memory_agent import memory_agent_index as project_memory_agent_index  # type: ignore
except Exception:
    project_memory_agent_index = None

try:
    from apps.api.services.master_agent import notify_master_agent as project_notify_master_agent  # type: ignore
except Exception:
    project_notify_master_agent = None

# Real, JWT-verified auth -- apps/api/routes/auth.py is a core module (not a
# "future" one), so this import should always succeed; the fallback exists
# only for a genuinely broken install. Previously this endpoint built its
# ActorContext straight from caller-supplied user_id/workspace_id/role/plan
# query parameters with no verification at all (the module's own docstring
# demonstrated the exploit: "?user_id=user_1&workspace_id=workspace_1&
# role=admin&plan=pro" -- anyone could claim to be any user, any workspace,
# any role, and receive that workspace's live agent events).
try:
    from apps.api.routes.auth import AUTH_STORE as REAL_AUTH_STORE, TOKEN_SERVICE as REAL_TOKEN_SERVICE  # type: ignore
except Exception as real_auth_import_exc:
    REAL_AUTH_STORE = None
    REAL_TOKEN_SERVICE = None
    logging.getLogger(__name__).warning(
        "Real auth import fallback enabled in apps.api.websockets.agent_events: %s", real_auth_import_exc
    )


# =============================================================================
# Router
# =============================================================================

router = APIRouter(tags=["Agent Events WebSocket"])


# =============================================================================
# Environment safe defaults
# =============================================================================

APP_NAME = os.getenv("WILLIAM_APP_NAME", "William Jarvis")
WEBSOCKET_PATH = os.getenv("WILLIAM_AGENT_EVENTS_WS_PATH", "/ws/agent-events")
MAX_CONNECTIONS_PER_WORKSPACE = int(os.getenv("WILLIAM_AGENT_EVENTS_MAX_CONNECTIONS_PER_WORKSPACE", "50"))
MAX_MESSAGE_BYTES = int(os.getenv("WILLIAM_AGENT_EVENTS_MAX_MESSAGE_BYTES", "65536"))
HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("WILLIAM_AGENT_EVENTS_HEARTBEAT_SECONDS", "30"))
STALE_CONNECTION_SECONDS = int(os.getenv("WILLIAM_AGENT_EVENTS_STALE_SECONDS", "120"))
REQUIRE_ACTIVE_SUBSCRIPTION = os.getenv("WILLIAM_AGENT_EVENTS_REQUIRE_ACTIVE_SUBSCRIPTION", "true").lower() == "true"
ALLOW_VIEWER_AGENT_EVENTS = os.getenv("WILLIAM_AGENT_EVENTS_ALLOW_VIEWER", "true").lower() == "true"
REQUIRE_SECURITY_FOR_BROADCAST = os.getenv("WILLIAM_AGENT_EVENTS_REQUIRE_SECURITY_FOR_BROADCAST", "false").lower() == "true"


# =============================================================================
# Enums
# =============================================================================

class UserRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MANAGER = "manager"
    MEMBER = "member"
    VIEWER = "viewer"


class SubscriptionPlan(str, Enum):
    FREE = "free"
    PRO = "pro"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


class AgentName(str, Enum):
    MASTER = "master"
    VOICE = "voice"
    SYSTEM = "system"
    BROWSER = "browser"
    CODE = "code"
    MEMORY = "memory"
    SECURITY = "security"
    VERIFICATION = "verification"
    VISUAL = "visual"
    WORKFLOW = "workflow"
    HOLOGRAM = "hologram"
    CALL = "call"
    BUSINESS = "business"
    FINANCE = "finance"
    CREATOR = "creator"
    UNKNOWN = "unknown"


class AgentStatus(str, Enum):
    IDLE = "idle"
    THINKING = "thinking"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    FAILED = "failed"
    OFFLINE = "offline"


class TaskStatus(str, Enum):
    QUEUED = "queued"
    STARTED = "started"
    PROGRESS = "progress"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EventType(str, Enum):
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    HEARTBEAT = "heartbeat"
    PING = "ping"
    PONG = "pong"
    ERROR = "error"

    AGENT_STATUS = "agent.status"
    AGENT_MESSAGE = "agent.message"
    AGENT_THOUGHT_SUMMARY = "agent.thought_summary"

    TASK_CREATED = "task.created"
    TASK_STARTED = "task.started"
    TASK_PROGRESS = "task.progress"
    TASK_WAITING_APPROVAL = "task.waiting_approval"
    TASK_COMPLETED = "task.completed"
    TASK_FAILED = "task.failed"
    TASK_CANCELLED = "task.cancelled"

    SECURITY_APPROVAL_REQUIRED = "security.approval_required"
    SECURITY_APPROVED = "security.approved"
    SECURITY_DENIED = "security.denied"

    VERIFICATION_PREPARED = "verification.prepared"
    VERIFICATION_CONFIRMED = "verification.confirmed"
    VERIFICATION_FAILED = "verification.failed"

    MEMORY_UPDATED = "memory.updated"
    WORKFLOW_EVENT = "workflow.event"
    BILLING_EVENT = "billing.event"
    SYSTEM_NOTICE = "system.notice"
    DASHBOARD_NOTIFICATION = "dashboard.notification"


class EventPriority(str, Enum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class AuditStatus(str, Enum):
    SUCCESS = "success"
    DENIED = "denied"
    ERROR = "error"
    PENDING = "pending"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class ActorContext:
    user_id: str
    workspace_id: str
    role: UserRole = UserRole.MEMBER
    plan: SubscriptionPlan = SubscriptionPlan.FREE
    subscription_active: bool = True
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class ConnectionRecord:
    connection_id: str
    user_id: str
    workspace_id: str
    role: UserRole
    plan: SubscriptionPlan
    subscriptions: Set[str]
    connected_at: str
    last_seen_at: str
    ip_address: Optional[str]
    user_agent: Optional[str]

    def visible_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["subscriptions"] = sorted(list(self.subscriptions))
        return data


@dataclass
class AgentEventRecord:
    id: str
    event_type: EventType
    user_id: str
    workspace_id: str
    agent_name: AgentName
    task_id: Optional[str]
    run_id: Optional[str]
    priority: EventPriority
    payload: Dict[str, Any]
    created_at: str
    created_by: Optional[str]
    request_id: Optional[str]

    def visible_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================================
# Pydantic schemas
# =============================================================================

class AgentEventPayload(BaseModel):
    event_type: EventType
    agent_name: AgentName = AgentName.UNKNOWN
    task_id: Optional[str] = Field(default=None, max_length=140)
    run_id: Optional[str] = Field(default=None, max_length=140)
    priority: EventPriority = EventPriority.NORMAL
    payload: Dict[str, Any] = Field(default_factory=dict)
    created_by: Optional[str] = Field(default=None, max_length=140)
    request_id: Optional[str] = Field(default=None, max_length=140)

    @field_validator("payload")
    @classmethod
    def validate_payload_size(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        serialized = json.dumps(value, default=str)
        if len(serialized.encode("utf-8")) > MAX_MESSAGE_BYTES:
            raise ValueError("Event payload is too large.")
        return value


class ClientMessage(BaseModel):
    type: Literal["ping", "subscribe", "unsubscribe", "ack", "client_event"]
    channels: List[str] = Field(default_factory=list, max_length=100)
    event: Optional[AgentEventPayload] = None
    payload: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("channels")
    @classmethod
    def clean_channels(cls, value: List[str]) -> List[str]:
        cleaned: List[str] = []
        seen = set()

        for channel in value:
            item = normalize_channel(channel)
            if item and item not in seen:
                seen.add(item)
                cleaned.append(item)

        return cleaned


class PublishEventRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=140)
    workspace_id: str = Field(..., min_length=1, max_length=140)
    event: AgentEventPayload


class AgentStatusEventRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=140)
    workspace_id: str = Field(..., min_length=1, max_length=140)
    agent_name: AgentName
    status: AgentStatus
    message: Optional[str] = Field(default=None, max_length=1000)
    task_id: Optional[str] = Field(default=None, max_length=140)
    run_id: Optional[str] = Field(default=None, max_length=140)
    progress: Optional[float] = Field(default=None, ge=0, le=100)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TaskEventRequest(BaseModel):
    user_id: str = Field(..., min_length=1, max_length=140)
    workspace_id: str = Field(..., min_length=1, max_length=140)
    task_id: str = Field(..., min_length=1, max_length=140)
    status: TaskStatus
    agent_name: AgentName = AgentName.UNKNOWN
    title: Optional[str] = Field(default=None, max_length=250)
    message: Optional[str] = Field(default=None, max_length=1000)
    progress: Optional[float] = Field(default=None, ge=0, le=100)
    result: Dict[str, Any] = Field(default_factory=dict)
    error: Optional[str] = Field(default=None, max_length=2000)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# Utility helpers
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_id(value: Optional[str], field_name: str) -> str:
    if value is None:
        raise ValueError(f"{field_name} is required.")

    cleaned = str(value).strip()
    if not cleaned:
        raise ValueError(f"{field_name} cannot be empty.")

    if len(cleaned) > 140:
        raise ValueError(f"{field_name} is too long.")

    if not re.match(r"^[a-zA-Z0-9_\-:.@]+$", cleaned):
        raise ValueError(f"{field_name} contains unsafe characters.")

    return cleaned


def normalize_channel(value: str) -> str:
    cleaned = str(value).strip().lower()
    cleaned = re.sub(r"[^a-z0-9_.:\-]", "", cleaned)
    return cleaned[:120]


def parse_role(value: Optional[str]) -> UserRole:
    if not value:
        return UserRole.MEMBER

    normalized = value.strip().lower()
    for role in UserRole:
        if role.value == normalized:
            return role

    return UserRole.MEMBER


def parse_plan(value: Optional[str]) -> SubscriptionPlan:
    if not value:
        return SubscriptionPlan.FREE

    normalized = value.strip().lower()
    for plan in SubscriptionPlan:
        if plan.value == normalized:
            return plan

    return SubscriptionPlan.FREE


def subscription_active_from_value(value: Optional[str]) -> bool:
    if value is None:
        return True

    return str(value).strip().lower() not in {
        "false",
        "0",
        "no",
        "inactive",
        "cancelled",
        "canceled",
    }


def safe_json(data: Any) -> Any:
    try:
        json.dumps(data, default=str)
        return data
    except Exception:
        return {"serialization_warning": "Original value could not be serialized safely."}


def can_connect(role: UserRole) -> bool:
    if role == UserRole.VIEWER:
        return ALLOW_VIEWER_AGENT_EVENTS
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER, UserRole.MEMBER}


def can_publish_client_event(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER, UserRole.MEMBER}


def default_channels_for_user(user_id: str, workspace_id: str) -> Set[str]:
    return {
        "agent.status",
        "agent.message",
        "task.created",
        "task.started",
        "task.progress",
        "task.waiting_approval",
        "task.completed",
        "task.failed",
        "task.cancelled",
        "security.approval_required",
        "security.approved",
        "security.denied",
        "verification.prepared",
        "verification.confirmed",
        "verification.failed",
        "memory.updated",
        "workflow.event",
        "billing.event",
        "system.notice",
        "dashboard.notification",
        f"user:{user_id}",
        f"workspace:{workspace_id}",
    }


def event_channels(event: AgentEventRecord) -> Set[str]:
    channels = {
        event.event_type.value,
        f"user:{event.user_id}",
        f"workspace:{event.workspace_id}",
        f"agent:{event.agent_name.value}",
    }

    if event.task_id:
        channels.add(f"task:{event.task_id}")

    if event.run_id:
        channels.add(f"run:{event.run_id}")

    return channels


async def websocket_actor_from_token(
    websocket: WebSocket,
    token: str,
    request_id: Optional[str],
) -> Optional[ActorContext]:
    """
    Verify a real access token and build an ActorContext from it.

    Mirrors apps/api/routes/auth.py's get_current_auth_context() exactly
    (signature check, revocation check, active-user check, live session
    lookup, live membership lookup) since browsers can't set a custom
    Authorization header on a WebSocket handshake -- the token travels as a
    query parameter instead, but every other verification step is identical
    to the HTTP routes. Returns None on any failure; the caller must close
    the connection without accepting it, never fall back to trusting the
    query parameters themselves.
    """

    if REAL_TOKEN_SERVICE is None or REAL_AUTH_STORE is None:
        return None

    try:
        payload = REAL_TOKEN_SERVICE.verify_token(token, expected_type="access")

        if REAL_AUTH_STORE.is_jti_revoked(payload["jti"]):
            return None

        user = REAL_AUTH_STORE.get_user_by_id(payload["sub"])
        if not user or not user.is_active:
            return None

        session = REAL_AUTH_STORE.touch_session(payload["session_id"])

        if session.user_id != user.user_id or session.workspace_id != payload["workspace_id"]:
            return None

        membership = REAL_AUTH_STORE.get_membership(user.user_id, session.workspace_id)
        if not membership:
            return None

        return ActorContext(
            user_id=user.user_id,
            workspace_id=session.workspace_id,
            role=parse_role(membership.role),
            plan=parse_plan(membership.plan),
            subscription_active=True,
            request_id=request_id or str(uuid.uuid4()),
            ip_address=websocket.client.host if websocket.client else None,
            user_agent=websocket.headers.get("User-Agent"),
        )

    except Exception:
        return None


async def send_safe_json(websocket: WebSocket, data: Dict[str, Any]) -> bool:
    try:
        await websocket.send_json(safe_json(data))
        return True
    except Exception:
        return False


# =============================================================================
# Main component
# =============================================================================

class AgentEvents:
    """
    Required class/component name: AgentEvents

    In-process WebSocket manager and event broker.

    Production upgrade path:
    - Replace in-process event fanout with Redis Pub/Sub, NATS, Kafka, or Postgres LISTEN/NOTIFY.
    - Keep this public API and helper functions stable.
    """

    def __init__(
        self,
        audit_hook: Optional[Callable[..., Any]] = None,
        security_hook: Optional[Callable[..., Any]] = None,
        usage_hook: Optional[Callable[..., Any]] = None,
        verification_hook: Optional[Callable[..., Any]] = None,
        memory_agent_hook: Optional[Callable[..., Any]] = None,
        master_agent_hook: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.audit_hook = audit_hook or project_audit_log
        self.security_hook = security_hook or project_security_approval
        self.usage_hook = usage_hook or project_check_usage_limit
        self.verification_hook = verification_hook or project_prepare_verification
        self.memory_agent_hook = memory_agent_hook or project_memory_agent_index
        self.master_agent_hook = master_agent_hook or project_notify_master_agent

        self._connections: Dict[str, WebSocket] = {}
        self._records: Dict[str, ConnectionRecord] = {}
        self._workspace_index: Dict[Tuple[str, str], Set[str]] = {}
        self._event_history: Dict[Tuple[str, str], List[AgentEventRecord]] = {}
        self._lock = RLock()

    async def audit(
        self,
        actor: ActorContext,
        action: str,
        event_status: AuditStatus,
        target_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        risk_level: Optional[RiskLevel] = None,
    ) -> None:
        payload = {
            "app": APP_NAME,
            "action": action,
            "category": "agent_events",
            "status": event_status.value,
            "target_type": "websocket",
            "target_id": target_id,
            "risk_level": risk_level.value if risk_level else None,
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "role": actor.role.value,
            "plan": actor.plan.value,
            "request_id": actor.request_id,
            "ip_address": actor.ip_address,
            "user_agent": actor.user_agent,
            "details": safe_json(details or {}),
            "created_at": utc_now(),
        }

        if callable(self.audit_hook):
            try:
                result = self.audit_hook(payload)
                if hasattr(result, "__await__"):
                    await result
            except Exception:
                return

    async def require_security(
        self,
        actor: ActorContext,
        action: str,
        risk_level: RiskLevel,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        request_payload = {
            "action": action,
            "risk_level": risk_level.value,
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "role": actor.role.value,
            "plan": actor.plan.value,
            "request_id": actor.request_id,
            "payload": safe_json(payload),
        }

        if callable(self.security_hook):
            try:
                result = self.security_hook(request_payload)
                if hasattr(result, "__await__"):
                    result = await result

                if isinstance(result, dict):
                    if not bool(result.get("approved", False)):
                        return {
                            "approved": False,
                            "reason": "Security Agent denied the event action.",
                            "result": result,
                        }
                    return result
            except Exception as exc:
                return {
                    "approved": False,
                    "reason": f"Security Agent unavailable: {exc}",
                }

        return {
            "approved": True,
            "mode": "fallback",
            "reason": "No external Security Agent hook configured.",
        }

    async def check_usage(self, actor: ActorContext) -> bool:
        if not callable(self.usage_hook):
            return True

        try:
            result = self.usage_hook(
                {
                    "user_id": actor.user_id,
                    "workspace_id": actor.workspace_id,
                    "role": actor.role.value,
                    "plan": actor.plan.value,
                    "request_id": actor.request_id,
                    "metric": "api_calls",
                    "requested_amount": 1,
                }
            )
            if hasattr(result, "__await__"):
                result = await result

            if isinstance(result, dict):
                return bool(result.get("allowed", True))

            return True
        except Exception:
            return True

    async def prepare_verification(
        self,
        actor: ActorContext,
        action: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload = {
            "agent": "Verification Agent",
            "module": "agent_events",
            "action": action,
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "request_id": actor.request_id,
            "result": safe_json(result),
            "prepared_at": utc_now(),
        }

        if callable(self.verification_hook):
            try:
                maybe_result = self.verification_hook(payload)
                if hasattr(maybe_result, "__await__"):
                    maybe_result = await maybe_result
                if isinstance(maybe_result, dict):
                    return maybe_result
            except Exception:
                return payload

        return payload

    async def index_for_memory_agent(
        self,
        actor: ActorContext,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        message = {
            "agent": "Memory Agent",
            "module": "agent_events",
            "event_type": event_type,
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "request_id": actor.request_id,
            "payload": safe_json(payload),
            "created_at": utc_now(),
        }

        if callable(self.memory_agent_hook):
            try:
                result = self.memory_agent_hook(message)
                if hasattr(result, "__await__"):
                    await result
            except Exception:
                return

    async def notify_master_agent(
        self,
        actor: ActorContext,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        message = {
            "agent": "Master Agent",
            "module": "agent_events",
            "event_type": event_type,
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "request_id": actor.request_id,
            "payload": safe_json(payload),
            "created_at": utc_now(),
        }

        if callable(self.master_agent_hook):
            try:
                result = self.master_agent_hook(message)
                if hasattr(result, "__await__"):
                    await result
            except Exception:
                return

    def workspace_connection_count(self, user_id: str, workspace_id: str) -> int:
        with self._lock:
            return len(self._workspace_index.get((user_id, workspace_id), set()))

    async def connect(self, websocket: WebSocket, actor: ActorContext, channels: Optional[Iterable[str]] = None) -> Optional[str]:
        if REQUIRE_ACTIVE_SUBSCRIPTION and not actor.subscription_active:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Subscription inactive.")
            return None

        if not can_connect(actor.role):
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Role cannot access agent events.")
            return None

        if self.workspace_connection_count(actor.user_id, actor.workspace_id) >= MAX_CONNECTIONS_PER_WORKSPACE:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Too many dashboard connections.")
            return None

        usage_allowed = await self.check_usage(actor)
        if not usage_allowed:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Usage limit exceeded.")
            return None

        await websocket.accept()

        connection_id = str(uuid.uuid4())
        subscriptions = default_channels_for_user(actor.user_id, actor.workspace_id)

        if channels:
            for channel in channels:
                normalized = normalize_channel(channel)
                if normalized:
                    subscriptions.add(normalized)

        record = ConnectionRecord(
            connection_id=connection_id,
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            role=actor.role,
            plan=actor.plan,
            subscriptions=subscriptions,
            connected_at=utc_now(),
            last_seen_at=utc_now(),
            ip_address=actor.ip_address,
            user_agent=actor.user_agent,
        )

        with self._lock:
            self._connections[connection_id] = websocket
            self._records[connection_id] = record
            self._workspace_index.setdefault((actor.user_id, actor.workspace_id), set()).add(connection_id)

        await self.audit(
            actor=actor,
            action="agent_events.websocket.connect",
            event_status=AuditStatus.SUCCESS,
            target_id=connection_id,
            details={"connection_id": connection_id, "subscriptions": sorted(list(subscriptions))},
            risk_level=RiskLevel.LOW,
        )

        await send_safe_json(
            websocket,
            {
                "ok": True,
                "event_type": EventType.CONNECTED.value,
                "connection_id": connection_id,
                "user_id": actor.user_id,
                "workspace_id": actor.workspace_id,
                "request_id": actor.request_id,
                "server_time": utc_now(),
                "heartbeat_interval_seconds": HEARTBEAT_INTERVAL_SECONDS,
                "subscriptions": sorted(list(subscriptions)),
            },
        )

        await self.publish(
            actor=actor,
            event=AgentEventPayload(
                event_type=EventType.DASHBOARD_NOTIFICATION,
                agent_name=AgentName.MASTER,
                priority=EventPriority.LOW,
                payload={
                    "message": "Dashboard connected to real-time agent events.",
                    "connection_id": connection_id,
                },
                request_id=actor.request_id,
            ),
            persist=False,
        )

        return connection_id

    async def disconnect(self, connection_id: str, reason: str = "client_disconnected") -> None:
        record: Optional[ConnectionRecord] = None

        with self._lock:
            record = self._records.pop(connection_id, None)
            self._connections.pop(connection_id, None)

            if record:
                key = (record.user_id, record.workspace_id)
                if key in self._workspace_index:
                    self._workspace_index[key].discard(connection_id)
                    if not self._workspace_index[key]:
                        self._workspace_index.pop(key, None)

        if record:
            actor = ActorContext(
                user_id=record.user_id,
                workspace_id=record.workspace_id,
                role=record.role,
                plan=record.plan,
                subscription_active=True,
                request_id=str(uuid.uuid4()),
                ip_address=record.ip_address,
                user_agent=record.user_agent,
            )

            await self.audit(
                actor=actor,
                action="agent_events.websocket.disconnect",
                event_status=AuditStatus.SUCCESS,
                target_id=connection_id,
                details={"connection_id": connection_id, "reason": reason},
                risk_level=RiskLevel.LOW,
            )

    def get_connection_record(self, connection_id: str) -> Optional[ConnectionRecord]:
        with self._lock:
            return self._records.get(connection_id)

    def scoped_connections(self, user_id: str, workspace_id: str) -> List[Tuple[str, WebSocket, ConnectionRecord]]:
        with self._lock:
            ids = list(self._workspace_index.get((user_id, workspace_id), set()))
            results: List[Tuple[str, WebSocket, ConnectionRecord]] = []

            for connection_id in ids:
                websocket = self._connections.get(connection_id)
                record = self._records.get(connection_id)
                if websocket and record:
                    results.append((connection_id, websocket, record))

            return results

    def mark_seen(self, connection_id: str) -> None:
        with self._lock:
            record = self._records.get(connection_id)
            if record:
                record.last_seen_at = utc_now()
                self._records[connection_id] = record

    def subscribe(self, connection_id: str, channels: Iterable[str]) -> List[str]:
        with self._lock:
            record = self._records.get(connection_id)
            if not record:
                return []

            for channel in channels:
                normalized = normalize_channel(channel)
                if normalized:
                    record.subscriptions.add(normalized)

            self._records[connection_id] = record
            return sorted(list(record.subscriptions))

    def unsubscribe(self, connection_id: str, channels: Iterable[str]) -> List[str]:
        protected_prefixes = {"user:", "workspace:"}

        with self._lock:
            record = self._records.get(connection_id)
            if not record:
                return []

            for channel in channels:
                normalized = normalize_channel(channel)
                if not normalized:
                    continue
                if any(normalized.startswith(prefix) for prefix in protected_prefixes):
                    continue
                record.subscriptions.discard(normalized)

            self._records[connection_id] = record
            return sorted(list(record.subscriptions))

    def store_event(self, event: AgentEventRecord) -> None:
        key = (event.user_id, event.workspace_id)

        with self._lock:
            history = self._event_history.setdefault(key, [])
            history.append(event)

            if len(history) > 500:
                self._event_history[key] = history[-500:]

    def recent_events(self, user_id: str, workspace_id: str, limit: int = 50) -> List[AgentEventRecord]:
        with self._lock:
            history = self._event_history.get((user_id, workspace_id), [])
            return list(history[-limit:])

    async def publish(
        self,
        actor: ActorContext,
        event: AgentEventPayload,
        persist: bool = True,
    ) -> AgentEventRecord:
        safe_user_id = normalize_id(actor.user_id, "user_id")
        safe_workspace_id = normalize_id(actor.workspace_id, "workspace_id")

        if REQUIRE_SECURITY_FOR_BROADCAST and event.priority in {EventPriority.HIGH, EventPriority.CRITICAL}:
            security_result = await self.require_security(
                actor=actor,
                action="agent_events.publish_high_priority",
                risk_level=RiskLevel.HIGH if event.priority == EventPriority.HIGH else RiskLevel.CRITICAL,
                payload=event.model_dump(),
            )
            if not bool(security_result.get("approved", False)):
                await self.audit(
                    actor=actor,
                    action="agent_events.publish_denied",
                    event_status=AuditStatus.DENIED,
                    details={"event_type": event.event_type.value, "reason": security_result.get("reason")},
                    risk_level=RiskLevel.HIGH,
                )
                raise PermissionError("Security Agent denied high-priority event broadcast.")

        record = AgentEventRecord(
            id=str(uuid.uuid4()),
            event_type=event.event_type,
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            agent_name=event.agent_name,
            task_id=event.task_id,
            run_id=event.run_id,
            priority=event.priority,
            payload=safe_json(event.payload),
            created_at=utc_now(),
            created_by=event.created_by or actor.user_id,
            request_id=event.request_id or actor.request_id,
        )

        if persist:
            self.store_event(record)

        channels = event_channels(record)
        dead_connections: List[str] = []
        delivered = 0

        for connection_id, websocket, connection_record in self.scoped_connections(safe_user_id, safe_workspace_id):
            if not channels.intersection(connection_record.subscriptions):
                continue

            ok = await send_safe_json(
                websocket,
                {
                    "ok": True,
                    "event": record.visible_dict(),
                    "channels": sorted(list(channels)),
                    "server_time": utc_now(),
                },
            )

            if ok:
                delivered += 1
            else:
                dead_connections.append(connection_id)

        for connection_id in dead_connections:
            await self.disconnect(connection_id, reason="send_failed")

        await self.index_for_memory_agent(
            actor,
            "agent_event_published",
            {
                "event_id": record.id,
                "event_type": record.event_type.value,
                "agent_name": record.agent_name.value,
                "task_id": record.task_id,
                "run_id": record.run_id,
                "delivered": delivered,
            },
        )

        return record

    async def broadcast_system_notice(
        self,
        user_id: str,
        workspace_id: str,
        message: str,
        priority: EventPriority = EventPriority.NORMAL,
        request_id: Optional[str] = None,
    ) -> AgentEventRecord:
        actor = ActorContext(
            user_id=normalize_id(user_id, "user_id"),
            workspace_id=normalize_id(workspace_id, "workspace_id"),
            role=UserRole.ADMIN,
            plan=SubscriptionPlan.PRO,
            subscription_active=True,
            request_id=request_id or str(uuid.uuid4()),
        )

        return await self.publish(
            actor,
            AgentEventPayload(
                event_type=EventType.SYSTEM_NOTICE,
                agent_name=AgentName.MASTER,
                priority=priority,
                payload={"message": message},
                request_id=actor.request_id,
            ),
        )

    async def publish_agent_status(self, request: AgentStatusEventRequest) -> AgentEventRecord:
        actor = ActorContext(
            user_id=normalize_id(request.user_id, "user_id"),
            workspace_id=normalize_id(request.workspace_id, "workspace_id"),
            role=UserRole.ADMIN,
            plan=SubscriptionPlan.PRO,
            subscription_active=True,
            request_id=str(uuid.uuid4()),
        )

        return await self.publish(
            actor,
            AgentEventPayload(
                event_type=EventType.AGENT_STATUS,
                agent_name=request.agent_name,
                task_id=request.task_id,
                run_id=request.run_id,
                priority=EventPriority.NORMAL,
                payload={
                    "status": request.status.value,
                    "message": request.message,
                    "progress": request.progress,
                    "metadata": safe_json(request.metadata),
                },
                request_id=actor.request_id,
            ),
        )

    async def publish_task_event(self, request: TaskEventRequest) -> AgentEventRecord:
        actor = ActorContext(
            user_id=normalize_id(request.user_id, "user_id"),
            workspace_id=normalize_id(request.workspace_id, "workspace_id"),
            role=UserRole.ADMIN,
            plan=SubscriptionPlan.PRO,
            subscription_active=True,
            request_id=str(uuid.uuid4()),
        )

        event_type_map = {
            TaskStatus.QUEUED: EventType.TASK_CREATED,
            TaskStatus.STARTED: EventType.TASK_STARTED,
            TaskStatus.PROGRESS: EventType.TASK_PROGRESS,
            TaskStatus.WAITING_APPROVAL: EventType.TASK_WAITING_APPROVAL,
            TaskStatus.COMPLETED: EventType.TASK_COMPLETED,
            TaskStatus.FAILED: EventType.TASK_FAILED,
            TaskStatus.CANCELLED: EventType.TASK_CANCELLED,
        }

        priority = EventPriority.HIGH if request.status in {TaskStatus.FAILED, TaskStatus.WAITING_APPROVAL} else EventPriority.NORMAL

        event_record = await self.publish(
            actor,
            AgentEventPayload(
                event_type=event_type_map[request.status],
                agent_name=request.agent_name,
                task_id=request.task_id,
                priority=priority,
                payload={
                    "task_id": request.task_id,
                    "status": request.status.value,
                    "title": request.title,
                    "message": request.message,
                    "progress": request.progress,
                    "result": safe_json(request.result),
                    "error": request.error,
                    "metadata": safe_json(request.metadata),
                },
                request_id=actor.request_id,
            ),
        )

        if request.status == TaskStatus.COMPLETED:
            await self.prepare_verification(
                actor,
                "agent_events.task.completed",
                {
                    "task_id": request.task_id,
                    "agent_name": request.agent_name.value,
                    "event_id": event_record.id,
                },
            )

        return event_record

    async def heartbeat_loop(self, connection_id: str) -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL_SECONDS)

            record = self.get_connection_record(connection_id)
            if not record:
                return

            websocket = self._connections.get(connection_id)
            if not websocket:
                await self.disconnect(connection_id, reason="heartbeat_missing_socket")
                return

            ok = await send_safe_json(
                websocket,
                {
                    "ok": True,
                    "event_type": EventType.HEARTBEAT.value,
                    "connection_id": connection_id,
                    "server_time": utc_now(),
                },
            )

            if not ok:
                await self.disconnect(connection_id, reason="heartbeat_failed")
                return


agent_events_service = AgentEvents()


# =============================================================================
# WebSocket route
# =============================================================================

@router.websocket(WEBSOCKET_PATH)
async def agent_events_websocket(
    websocket: WebSocket,
    token: str = Query(..., description="Real, signed access token (same one used for Authorization: Bearer on HTTP routes)"),
    request_id: Optional[str] = Query(default=None),
    channels: Optional[str] = Query(default=None, description="Comma-separated event channels"),
) -> None:
    """
    Dashboard WebSocket endpoint.

    Example:
    ws://localhost:8000/ws/agent-events?token=<real_access_token>

    user_id/workspace_id/role/plan are derived entirely from the verified
    token's live session + membership lookup (see
    websocket_actor_from_token()) -- browsers can't set a custom
    Authorization header during the WebSocket handshake, so the token
    travels as a query parameter instead, but it is verified exactly like
    every HTTP route's Authorization: Bearer token. Never accept
    user_id/workspace_id/role/plan as caller-supplied values here again.

    Isolation rule:
    A connection only receives events for its exact user_id + workspace_id.
    """

    connection_id: Optional[str] = None
    heartbeat_task: Optional[asyncio.Task[Any]] = None

    try:
        actor = await websocket_actor_from_token(
            websocket=websocket,
            token=token,
            request_id=request_id,
        )

        if actor is None:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid or expired token.")
            return

        channel_list = []
        if channels:
            channel_list = [item.strip() for item in channels.split(",") if item.strip()]

        connection_id = await agent_events_service.connect(websocket, actor, channel_list)

        if not connection_id:
            return

        heartbeat_task = asyncio.create_task(agent_events_service.heartbeat_loop(connection_id))

        while True:
            raw_message = await websocket.receive_text()

            if len(raw_message.encode("utf-8")) > MAX_MESSAGE_BYTES:
                await send_safe_json(
                    websocket,
                    {
                        "ok": False,
                        "event_type": EventType.ERROR.value,
                        "error": {
                            "code": "message_too_large",
                            "message": "WebSocket message is too large.",
                        },
                        "server_time": utc_now(),
                    },
                )
                continue

            try:
                parsed = json.loads(raw_message)
                client_message = ClientMessage.model_validate(parsed)
            except (json.JSONDecodeError, ValidationError) as exc:
                await send_safe_json(
                    websocket,
                    {
                        "ok": False,
                        "event_type": EventType.ERROR.value,
                        "error": {
                            "code": "invalid_message",
                            "message": "Invalid WebSocket message format.",
                            "details": str(exc),
                        },
                        "server_time": utc_now(),
                    },
                )
                continue

            agent_events_service.mark_seen(connection_id)

            if client_message.type == "ping":
                await send_safe_json(
                    websocket,
                    {
                        "ok": True,
                        "event_type": EventType.PONG.value,
                        "connection_id": connection_id,
                        "server_time": utc_now(),
                    },
                )
                continue

            if client_message.type == "subscribe":
                subscriptions = agent_events_service.subscribe(connection_id, client_message.channels)
                await send_safe_json(
                    websocket,
                    {
                        "ok": True,
                        "event_type": "subscription.updated",
                        "subscriptions": subscriptions,
                        "server_time": utc_now(),
                    },
                )
                continue

            if client_message.type == "unsubscribe":
                subscriptions = agent_events_service.unsubscribe(connection_id, client_message.channels)
                await send_safe_json(
                    websocket,
                    {
                        "ok": True,
                        "event_type": "subscription.updated",
                        "subscriptions": subscriptions,
                        "server_time": utc_now(),
                    },
                )
                continue

            if client_message.type == "ack":
                await send_safe_json(
                    websocket,
                    {
                        "ok": True,
                        "event_type": "ack.received",
                        "payload": safe_json(client_message.payload),
                        "server_time": utc_now(),
                    },
                )
                continue

            if client_message.type == "client_event":
                if not can_publish_client_event(actor.role):
                    await send_safe_json(
                        websocket,
                        {
                            "ok": False,
                            "event_type": EventType.ERROR.value,
                            "error": {
                                "code": "role_cannot_publish_client_event",
                                "message": "Your role does not allow publishing dashboard events.",
                            },
                            "server_time": utc_now(),
                        },
                    )
                    continue

                if not client_message.event:
                    await send_safe_json(
                        websocket,
                        {
                            "ok": False,
                            "event_type": EventType.ERROR.value,
                            "error": {
                                "code": "missing_event",
                                "message": "client_event messages require an event object.",
                            },
                            "server_time": utc_now(),
                        },
                    )
                    continue

                event_record = await agent_events_service.publish(actor, client_message.event)

                await send_safe_json(
                    websocket,
                    {
                        "ok": True,
                        "event_type": "client_event.published",
                        "event_id": event_record.id,
                        "server_time": utc_now(),
                    },
                )
                continue

    except WebSocketDisconnect:
        if connection_id:
            await agent_events_service.disconnect(connection_id, reason="websocket_disconnect")

    except ValueError as exc:
        try:
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason=str(exc))
        except Exception:
            None

    except Exception as exc:
        if connection_id:
            await agent_events_service.disconnect(connection_id, reason=f"error:{exc}")

        try:
            await websocket.close(code=status.WS_1011_INTERNAL_ERROR, reason="Internal WebSocket error.")
        except Exception:
            None

    finally:
        if heartbeat_task:
            heartbeat_task.cancel()
        if connection_id:
            await agent_events_service.disconnect(connection_id, reason="connection_cleanup")


# =============================================================================
# Helper functions for agents/routes/workers
# =============================================================================

async def publish_agent_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Service-compatible helper for other modules.

    Expected payload:
    {
        "user_id": "...",
        "workspace_id": "...",
        "event_type": "task.progress",
        "agent_name": "master",
        "task_id": "...",
        "run_id": "...",
        "priority": "normal",
        "payload": {...},
        "created_by": "...",
        "request_id": "..."
    }
    """

    user_id = normalize_id(str(payload.get("user_id")), "user_id")
    workspace_id = normalize_id(str(payload.get("workspace_id")), "workspace_id")

    actor = ActorContext(
        user_id=user_id,
        workspace_id=workspace_id,
        role=parse_role(str(payload.get("role") or "admin")),
        plan=parse_plan(str(payload.get("plan") or "pro")),
        subscription_active=True,
        request_id=str(payload.get("request_id") or uuid.uuid4()),
    )

    event_type_value = str(payload.get("event_type") or EventType.DASHBOARD_NOTIFICATION.value)
    agent_name_value = str(payload.get("agent_name") or AgentName.UNKNOWN.value)
    priority_value = str(payload.get("priority") or EventPriority.NORMAL.value)

    event_type = EventType.DASHBOARD_NOTIFICATION
    for item in EventType:
        if item.value == event_type_value:
            event_type = item
            break

    agent_name = AgentName.UNKNOWN
    for item in AgentName:
        if item.value == agent_name_value:
            agent_name = item
            break

    priority = EventPriority.NORMAL
    for item in EventPriority:
        if item.value == priority_value:
            priority = item
            break

    event = AgentEventPayload(
        event_type=event_type,
        agent_name=agent_name,
        task_id=payload.get("task_id"),
        run_id=payload.get("run_id"),
        priority=priority,
        payload=payload.get("payload") if isinstance(payload.get("payload"), dict) else {},
        created_by=payload.get("created_by") or user_id,
        request_id=actor.request_id,
    )

    record = await agent_events_service.publish(actor, event)

    return {
        "ok": True,
        "event_id": record.id,
        "event_type": record.event_type.value,
        "user_id": record.user_id,
        "workspace_id": record.workspace_id,
        "request_id": actor.request_id,
    }


async def publish_agent_status(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Helper for agent status updates.
    """

    request = AgentStatusEventRequest(
        user_id=str(payload.get("user_id")),
        workspace_id=str(payload.get("workspace_id")),
        agent_name=AgentName(str(payload.get("agent_name") or AgentName.UNKNOWN.value)),
        status=AgentStatus(str(payload.get("status") or AgentStatus.IDLE.value)),
        message=payload.get("message"),
        task_id=payload.get("task_id"),
        run_id=payload.get("run_id"),
        progress=payload.get("progress"),
        metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
    )

    record = await agent_events_service.publish_agent_status(request)

    return {
        "ok": True,
        "event_id": record.id,
        "event_type": record.event_type.value,
        "request_id": record.request_id,
    }


async def publish_task_event(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Helper for task lifecycle events.
    """

    request = TaskEventRequest(
        user_id=str(payload.get("user_id")),
        workspace_id=str(payload.get("workspace_id")),
        task_id=str(payload.get("task_id")),
        status=TaskStatus(str(payload.get("status") or TaskStatus.PROGRESS.value)),
        agent_name=AgentName(str(payload.get("agent_name") or AgentName.UNKNOWN.value)),
        title=payload.get("title"),
        message=payload.get("message"),
        progress=payload.get("progress"),
        result=payload.get("result") if isinstance(payload.get("result"), dict) else {},
        error=payload.get("error"),
        metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
    )

    record = await agent_events_service.publish_task_event(request)

    return {
        "ok": True,
        "event_id": record.id,
        "event_type": record.event_type.value,
        "task_id": record.task_id,
        "request_id": record.request_id,
    }


def get_recent_agent_events(user_id: str, workspace_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """
    Synchronous helper for dashboards/tests to inspect recent scoped events.
    """

    safe_user_id = normalize_id(user_id, "user_id")
    safe_workspace_id = normalize_id(workspace_id, "workspace_id")
    safe_limit = max(1, min(int(limit), 500))

    return [
        event.visible_dict()
        for event in agent_events_service.recent_events(safe_user_id, safe_workspace_id, safe_limit)
    ]


__all__ = [
    "router",
    "AgentEvents",
    "ActorContext",
    "ConnectionRecord",
    "AgentEventRecord",
    "AgentEventPayload",
    "ClientMessage",
    "PublishEventRequest",
    "AgentStatusEventRequest",
    "TaskEventRequest",
    "AgentName",
    "AgentStatus",
    "TaskStatus",
    "EventType",
    "EventPriority",
    "publish_agent_event",
    "publish_agent_status",
    "publish_task_event",
    "get_recent_agent_events",
]