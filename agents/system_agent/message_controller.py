"""
agents/system_agent/message_controller.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Read, draft, and send messages across supported channels such as WhatsApp,
    SMS, Gmail, Slack, and future messaging providers.

Safety Rules:
    - Reading messages requires user/workspace validation.
    - Drafting is safe but still audited.
    - Sending messages always requires explicit approval.
    - No real provider action is performed unless a provider is registered and
      the request has passed security approval.
    - All actions are isolated by user_id and workspace_id.
    - Every result is structured for Master Agent, Dashboard/API, Verification
      Agent, Memory Agent, and Audit Logs.

Compatibility:
    - Import-safe even when the full William/Jarvis system is not available.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent, Security Agent, Memory Agent, Verification Agent, and
      dashboard/API integration.
"""

from __future__ import annotations

import copy
import logging
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Protocol, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety

    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent.

        This allows this file to import safely before the full William/Jarvis
        agent framework is created.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("William.SystemAgent.MessageController")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class MessageChannel(str, Enum):
    """Supported messaging channels."""

    WHATSAPP = "whatsapp"
    SMS = "sms"
    GMAIL = "gmail"
    SLACK = "slack"
    EMAIL = "email"
    TEAMS = "teams"
    DISCORD = "discord"
    TELEGRAM = "telegram"
    INTERNAL = "internal"


class MessageDirection(str, Enum):
    """Message direction."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"
    DRAFT = "draft"


class MessageAction(str, Enum):
    """Actions supported by MessageController."""

    READ = "read"
    DRAFT = "draft"
    REQUEST_SEND_APPROVAL = "request_send_approval"
    APPROVE_SEND = "approve_send"
    DENY_SEND = "deny_send"
    SEND = "send"
    LIST_DRAFTS = "list_drafts"
    LIST_PENDING_APPROVALS = "list_pending_approvals"


class ApprovalStatus(str, Enum):
    """Approval status for sensitive message actions."""

    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    FAILED = "failed"


class MessageStatus(str, Enum):
    """Message lifecycle status."""

    RECEIVED = "received"
    READ = "read"
    DRAFTED = "drafted"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    DENIED = "denied"
    SENT = "sent"
    FAILED = "failed"


class SensitivityLevel(str, Enum):
    """Message sensitivity level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Provider Protocol
# ---------------------------------------------------------------------------

class MessageProvider(Protocol):
    """
    Messaging provider interface.

    Real integrations for Gmail, Slack, WhatsApp, SMS, etc. should implement
    this protocol and be registered with MessageController.register_provider().
    """

    provider_name: str

    def read_messages(
        self,
        *,
        user_id: str,
        workspace_id: str,
        channel: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Read messages from provider."""

    def send_message(
        self,
        *,
        user_id: str,
        workspace_id: str,
        channel: str,
        recipient: str,
        subject: Optional[str],
        body: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Send message through provider."""


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class MessageContext:
    """
    SaaS context for message actions.

    Every user-specific operation must include user_id and workspace_id to
    prevent cross-user or cross-workspace data leakage.
    """

    user_id: str
    workspace_id: str
    actor_id: Optional[str] = None
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = "system_agent"
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MessageRecord:
    """Stored message/draft record."""

    message_id: str
    user_id: str
    workspace_id: str
    channel: str
    direction: str
    status: str
    recipient: Optional[str] = None
    sender: Optional[str] = None
    subject: Optional[str] = None
    body: str = ""
    provider_message_id: Optional[str] = None
    sensitivity: str = SensitivityLevel.MEDIUM.value
    created_at: str = field(default_factory=lambda: _utc_now())
    updated_at: str = field(default_factory=lambda: _utc_now())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ApprovalRequest:
    """Approval request for sensitive outbound messaging."""

    approval_id: str
    user_id: str
    workspace_id: str
    action: str
    channel: str
    draft_message_id: str
    status: str = ApprovalStatus.PENDING.value
    reason: str = ""
    requested_by: Optional[str] = None
    approved_by: Optional[str] = None
    denied_by: Optional[str] = None
    created_at: str = field(default_factory=lambda: _utc_now())
    updated_at: str = field(default_factory=lambda: _utc_now())
    expires_at: Optional[str] = None
    security_payload: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditEvent:
    """Audit event record for dashboard/API/security review."""

    event_id: str
    user_id: str
    workspace_id: str
    action: str
    success: bool
    message: str
    created_at: str = field(default_factory=lambda: _utc_now())
    request_id: Optional[str] = None
    actor_id: Optional[str] = None
    channel: Optional[str] = None
    message_id: Optional[str] = None
    approval_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return current UTC time in ISO format."""

    return datetime.now(timezone.utc).isoformat()


def _safe_copy(value: Any) -> Any:
    """Return a defensive copy where possible."""

    try:
        return copy.deepcopy(value)
    except Exception:
        return value


def _normalize_id(value: Any) -> str:
    """Normalize user/workspace IDs."""

    if value is None:
        return ""
    return str(value).strip()


def _truncate_text(text: Optional[str], limit: int = 300) -> str:
    """Safely truncate text for metadata/audit previews."""

    if text is None:
        return ""
    clean = str(text).replace("\n", " ").strip()
    if len(clean) <= limit:
        return clean
    return clean[: limit - 3] + "..."


def _is_non_empty_string(value: Any) -> bool:
    """Check if value is a meaningful string."""

    return isinstance(value, str) and bool(value.strip())


def _dict_without_none(data: Dict[str, Any]) -> Dict[str, Any]:
    """Remove keys where value is None."""

    return {key: value for key, value in data.items() if value is not None}


# ---------------------------------------------------------------------------
# Safe In-Memory Provider
# ---------------------------------------------------------------------------

class InMemoryMessageProvider:
    """
    Safe internal provider.

    This provider does not connect to external services. It is useful for tests,
    local dashboard previews, and future provider adapter development.
    """

    provider_name = "in_memory"

    def __init__(self) -> None:
        self._messages: List[Dict[str, Any]] = []

    def seed_message(self, message: Dict[str, Any]) -> None:
        """Seed a message for testing."""

        self._messages.append(_safe_copy(message))

    def read_messages(
        self,
        *,
        user_id: str,
        workspace_id: str,
        channel: str,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 20,
    ) -> List[Dict[str, Any]]:
        """Read messages from safe in-memory storage."""

        filters = filters or {}
        results: List[Dict[str, Any]] = []

        for message in self._messages:
            if str(message.get("user_id")) != str(user_id):
                continue
            if str(message.get("workspace_id")) != str(workspace_id):
                continue
            if str(message.get("channel")) != str(channel):
                continue

            sender_filter = filters.get("sender")
            if sender_filter and sender_filter not in str(message.get("sender", "")):
                continue

            recipient_filter = filters.get("recipient")
            if recipient_filter and recipient_filter not in str(message.get("recipient", "")):
                continue

            text_query = filters.get("query")
            if text_query:
                haystack = " ".join(
                    [
                        str(message.get("subject", "")),
                        str(message.get("body", "")),
                        str(message.get("sender", "")),
                        str(message.get("recipient", "")),
                    ]
                ).lower()
                if str(text_query).lower() not in haystack:
                    continue

            results.append(_safe_copy(message))

            if len(results) >= max(1, int(limit)):
                break

        return results

    def send_message(
        self,
        *,
        user_id: str,
        workspace_id: str,
        channel: str,
        recipient: str,
        subject: Optional[str],
        body: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Simulate sending a message.

        This is safe because it does not call any external network, device,
        browser, Gmail, Slack, WhatsApp, or SMS API.
        """

        provider_message_id = f"mem_{uuid.uuid4().hex}"

        record = {
            "provider_message_id": provider_message_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "channel": channel,
            "recipient": recipient,
            "subject": subject,
            "body": body,
            "direction": MessageDirection.OUTBOUND.value,
            "status": MessageStatus.SENT.value,
            "created_at": _utc_now(),
            "metadata": metadata or {},
        }

        self._messages.append(record)

        return {
            "success": True,
            "provider": self.provider_name,
            "provider_message_id": provider_message_id,
            "message": "Message sent through safe in-memory provider.",
            "data": record,
        }


# ---------------------------------------------------------------------------
# MessageController
# ---------------------------------------------------------------------------

class MessageController(BaseAgent):
    """
    System Agent helper for safe message operations.

    Responsibilities:
        - Read messages from registered providers.
        - Create outbound drafts.
        - Request approval before sending.
        - Approve or deny pending send requests.
        - Send only after approval.
        - Prepare Verification Agent payloads.
        - Prepare Memory Agent-compatible payloads.
        - Emit agent events and audit logs.
        - Maintain user/workspace isolation.

    Master Agent Connection:
        The Master Agent can route message-related tasks to this controller by
        calling public methods such as read_messages(), draft_message(),
        request_send_approval(), approve_action(), deny_action(), and
        send_message().

    Security Agent Connection:
        Sending is treated as sensitive. _requires_security_check() returns True
        for outbound send operations. _request_security_approval() creates a
        pending approval payload that the Security Agent/dashboard can review.

    Verification Agent Connection:
        Every successful or failed action prepares a verification payload through
        _prepare_verification_payload().

    Memory Agent Connection:
        Useful context can be passed to Memory Agent through
        _prepare_memory_payload(), without mixing users/workspaces.

    Dashboard/API Connection:
        All methods return structured dicts suitable for FastAPI, Flask, WebSocket
        dashboards, audit pages, and task history.
    """

    DEFAULT_APPROVAL_TTL_SECONDS = 60 * 60
    MAX_BODY_LENGTH = 50_000
    MAX_SUBJECT_LENGTH = 500
    DEFAULT_READ_LIMIT = 20
    MAX_READ_LIMIT = 100

    def __init__(
        self,
        *,
        agent_name: str = "SystemMessageController",
        agent_id: str = "system_agent.message_controller",
        providers: Optional[Dict[str, MessageProvider]] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        enable_in_memory_provider: bool = True,
        strict_provider_mode: bool = False,
        default_provider_name: str = "in_memory",
    ) -> None:
        """
        Initialize MessageController.

        Args:
            agent_name:
                Human-readable agent name.
            agent_id:
                Registry/router-friendly agent ID.
            providers:
                Optional provider registry.
            security_approval_callback:
                Optional callback for external Security Agent integration.
            event_callback:
                Optional callback for event bus/dashboard.
            audit_callback:
                Optional callback for persistent audit store.
            enable_in_memory_provider:
                Register safe in-memory provider for tests/local usage.
            strict_provider_mode:
                If True, missing providers fail instead of using in-memory.
            default_provider_name:
                Default provider for channels without explicit mapping.
        """

        super().__init__(agent_name=agent_name, agent_id=agent_id)

        self.agent_name = agent_name
        self.agent_id = agent_id
        self.logger = logging.getLogger(agent_name)

        self.security_approval_callback = security_approval_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.strict_provider_mode = strict_provider_mode
        self.default_provider_name = default_provider_name

        self.providers: Dict[str, MessageProvider] = {}
        self.channel_provider_map: Dict[str, str] = {}

        self._drafts: Dict[str, MessageRecord] = {}
        self._messages: Dict[str, MessageRecord] = {}
        self._approval_requests: Dict[str, ApprovalRequest] = {}
        self._audit_events: List[AuditEvent] = []
        self._task_history: List[Dict[str, Any]] = []

        if enable_in_memory_provider:
            self.register_provider(default_provider_name, InMemoryMessageProvider())

        if providers:
            for name, provider in providers.items():
                self.register_provider(name, provider)

        self._emit_agent_event(
            event_type="message_controller.initialized",
            payload={
                "agent_id": self.agent_id,
                "providers": list(self.providers.keys()),
                "strict_provider_mode": self.strict_provider_mode,
            },
        )

    # -----------------------------------------------------------------------
    # Provider management
    # -----------------------------------------------------------------------

    def register_provider(
        self,
        provider_name: str,
        provider: MessageProvider,
        *,
        channels: Optional[Iterable[Union[str, MessageChannel]]] = None,
    ) -> Dict[str, Any]:
        """
        Register a messaging provider.

        Args:
            provider_name:
                Internal provider key.
            provider:
                Provider object implementing MessageProvider protocol.
            channels:
                Optional channels this provider should handle.

        Returns:
            Structured result.
        """

        if not _is_non_empty_string(provider_name):
            return self._error_result(
                message="Provider name is required.",
                error_code="INVALID_PROVIDER_NAME",
            )

        required_methods = ("read_messages", "send_message")
        for method_name in required_methods:
            if not callable(getattr(provider, method_name, None)):
                return self._error_result(
                    message=f"Provider '{provider_name}' is missing method '{method_name}'.",
                    error_code="INVALID_PROVIDER_INTERFACE",
                    data={"provider_name": provider_name},
                )

        normalized_name = provider_name.strip()
        self.providers[normalized_name] = provider

        mapped_channels: List[str] = []
        if channels:
            for channel in channels:
                normalized_channel = self._normalize_channel(channel)
                self.channel_provider_map[normalized_channel] = normalized_name
                mapped_channels.append(normalized_channel)

        self._emit_agent_event(
            event_type="message_provider.registered",
            payload={
                "provider_name": normalized_name,
                "channels": mapped_channels,
            },
        )

        return self._safe_result(
            message=f"Provider '{normalized_name}' registered successfully.",
            data={
                "provider_name": normalized_name,
                "channels": mapped_channels,
            },
        )

    def map_channel_to_provider(
        self,
        channel: Union[str, MessageChannel],
        provider_name: str,
    ) -> Dict[str, Any]:
        """
        Map a channel to a provider.

        Example:
            map_channel_to_provider("gmail", "gmail_provider")
        """

        normalized_channel = self._normalize_channel(channel)
        normalized_provider = str(provider_name).strip()

        if normalized_provider not in self.providers:
            return self._error_result(
                message=f"Provider '{normalized_provider}' is not registered.",
                error_code="PROVIDER_NOT_REGISTERED",
                data={
                    "channel": normalized_channel,
                    "provider_name": normalized_provider,
                },
            )

        self.channel_provider_map[normalized_channel] = normalized_provider

        return self._safe_result(
            message=f"Channel '{normalized_channel}' mapped to provider '{normalized_provider}'.",
            data={
                "channel": normalized_channel,
                "provider_name": normalized_provider,
            },
        )

    def get_registered_providers(self) -> Dict[str, Any]:
        """Return registered providers and channel mappings."""

        return self._safe_result(
            message="Registered providers fetched successfully.",
            data={
                "providers": list(self.providers.keys()),
                "channel_provider_map": _safe_copy(self.channel_provider_map),
                "default_provider_name": self.default_provider_name,
                "strict_provider_mode": self.strict_provider_mode,
            },
        )

    # -----------------------------------------------------------------------
    # Public message methods
    # -----------------------------------------------------------------------

    def read_messages(
        self,
        *,
        context: Union[MessageContext, Dict[str, Any]],
        channel: Union[str, MessageChannel],
        filters: Optional[Dict[str, Any]] = None,
        limit: int = DEFAULT_READ_LIMIT,
        provider_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Read messages from a registered provider.

        This method validates user/workspace context and never returns messages
        from another user/workspace.
        """

        started_at = time.time()
        action = MessageAction.READ.value

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        normalized_channel = self._normalize_channel(channel)
        normalized_limit = min(max(1, int(limit)), self.MAX_READ_LIMIT)

        provider_result = self._resolve_provider(normalized_channel, provider_name)
        if not provider_result["success"]:
            self._log_audit_event(
                context=ctx,
                action=action,
                success=False,
                message=provider_result["message"],
                channel=normalized_channel,
                metadata={"filters": self._sanitize_filters(filters)},
            )
            return provider_result

        provider = provider_result["data"]["provider"]
        provider_key = provider_result["data"]["provider_name"]

        try:
            raw_messages = provider.read_messages(
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
                channel=normalized_channel,
                filters=filters or {},
                limit=normalized_limit,
            )

            safe_messages: List[Dict[str, Any]] = []

            for raw in raw_messages:
                if str(raw.get("user_id")) != str(ctx.user_id):
                    continue
                if str(raw.get("workspace_id")) != str(ctx.workspace_id):
                    continue

                record = self._message_record_from_provider(
                    raw,
                    ctx=ctx,
                    channel=normalized_channel,
                )
                self._messages[record.message_id] = record
                safe_messages.append(self._public_message_dict(record))

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                action=action,
                success=True,
                message="Messages read successfully.",
                data={
                    "channel": normalized_channel,
                    "provider": provider_key,
                    "count": len(safe_messages),
                },
            )

            memory_payload = self._prepare_memory_payload(
                context=ctx,
                action=action,
                data={
                    "channel": normalized_channel,
                    "message_count": len(safe_messages),
                    "filters": self._sanitize_filters(filters),
                },
            )

            self._log_audit_event(
                context=ctx,
                action=action,
                success=True,
                message="Messages read successfully.",
                channel=normalized_channel,
                metadata={
                    "provider": provider_key,
                    "count": len(safe_messages),
                    "duration_ms": int((time.time() - started_at) * 1000),
                },
            )

            self._record_task_history(
                context=ctx,
                action=action,
                success=True,
                data={
                    "channel": normalized_channel,
                    "provider": provider_key,
                    "count": len(safe_messages),
                },
            )

            return self._safe_result(
                message="Messages read successfully.",
                data={
                    "messages": safe_messages,
                    "count": len(safe_messages),
                    "channel": normalized_channel,
                    "provider": provider_key,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "duration_ms": int((time.time() - started_at) * 1000),
                    "request_id": ctx.request_id,
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to read messages.")
            error = self._error_result(
                message="Failed to read messages.",
                error_code="MESSAGE_READ_FAILED",
                error=str(exc),
                data={
                    "channel": normalized_channel,
                    "provider": provider_key,
                },
                metadata={
                    "request_id": ctx.request_id,
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                },
            )

            self._log_audit_event(
                context=ctx,
                action=action,
                success=False,
                message=error["message"],
                channel=normalized_channel,
                metadata={
                    "error": str(exc),
                    "provider": provider_key,
                },
            )

            return error

    def draft_message(
        self,
        *,
        context: Union[MessageContext, Dict[str, Any]],
        channel: Union[str, MessageChannel],
        recipient: str,
        body: str,
        subject: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        sensitivity: Union[str, SensitivityLevel] = SensitivityLevel.MEDIUM,
    ) -> Dict[str, Any]:
        """
        Create a draft message.

        Drafting does not send anything. It prepares a safe outbound draft that
        can later be submitted for approval.
        """

        started_at = time.time()
        action = MessageAction.DRAFT.value

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        normalized_channel = self._normalize_channel(channel)

        validation = self._validate_message_payload(
            channel=normalized_channel,
            recipient=recipient,
            body=body,
            subject=subject,
        )
        if not validation["success"]:
            self._log_audit_event(
                context=ctx,
                action=action,
                success=False,
                message=validation["message"],
                channel=normalized_channel,
            )
            return validation

        normalized_sensitivity = self._normalize_sensitivity(sensitivity)

        draft_id = f"draft_{uuid.uuid4().hex}"
        record = MessageRecord(
            message_id=draft_id,
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            channel=normalized_channel,
            direction=MessageDirection.DRAFT.value,
            status=MessageStatus.DRAFTED.value,
            recipient=recipient.strip(),
            subject=subject.strip() if subject else None,
            body=body,
            sensitivity=normalized_sensitivity,
            metadata={
                **(metadata or {}),
                "request_id": ctx.request_id,
                "actor_id": ctx.actor_id,
                "source": ctx.source,
            },
        )

        self._drafts[draft_id] = record
        self._messages[draft_id] = record

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action=action,
            success=True,
            message="Message draft created successfully.",
            data={
                "draft_message_id": draft_id,
                "channel": normalized_channel,
                "recipient": recipient.strip(),
                "sensitivity": normalized_sensitivity,
            },
        )

        memory_payload = self._prepare_memory_payload(
            context=ctx,
            action=action,
            data={
                "draft_message_id": draft_id,
                "channel": normalized_channel,
                "recipient": recipient.strip(),
                "subject": subject,
                "body_preview": _truncate_text(body),
            },
        )

        self._log_audit_event(
            context=ctx,
            action=action,
            success=True,
            message="Message draft created successfully.",
            channel=normalized_channel,
            message_id=draft_id,
            metadata={
                "recipient": recipient.strip(),
                "subject": subject,
                "sensitivity": normalized_sensitivity,
                "duration_ms": int((time.time() - started_at) * 1000),
            },
        )

        self._emit_agent_event(
            event_type="message.drafted",
            payload={
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "message_id": draft_id,
                "channel": normalized_channel,
                "recipient": recipient.strip(),
            },
        )

        self._record_task_history(
            context=ctx,
            action=action,
            success=True,
            data={
                "draft_message_id": draft_id,
                "channel": normalized_channel,
                "recipient": recipient.strip(),
            },
        )

        return self._safe_result(
            message="Message draft created successfully.",
            data={
                "draft": self._public_message_dict(record),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "duration_ms": int((time.time() - started_at) * 1000),
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def request_send_approval(
        self,
        *,
        context: Union[MessageContext, Dict[str, Any]],
        draft_message_id: str,
        reason: str = "",
        expires_in_seconds: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval to send a draft.

        This creates a pending approval request that can be reviewed by Security
        Agent, dashboard, admin, or the user.
        """

        started_at = time.time()
        action = MessageAction.REQUEST_SEND_APPROVAL.value

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]

        draft_result = self._get_owned_draft(ctx, draft_message_id)
        if not draft_result["success"]:
            return draft_result

        draft = draft_result["data"]["draft"]

        if self._requires_security_check(action=MessageAction.SEND.value, message=draft):
            security_result = self._request_security_approval(
                context=ctx,
                action=MessageAction.SEND.value,
                message=draft,
                reason=reason,
                metadata=metadata or {},
            )
            if not security_result["success"]:
                self._log_audit_event(
                    context=ctx,
                    action=action,
                    success=False,
                    message=security_result["message"],
                    channel=draft.channel,
                    message_id=draft.message_id,
                    metadata={"reason": reason},
                )
                return security_result
            security_payload = security_result["data"]
        else:
            security_payload = {
                "approval_required": False,
                "status": ApprovalStatus.NOT_REQUIRED.value,
            }

        approval_id = f"approval_{uuid.uuid4().hex}"
        ttl = expires_in_seconds or self.DEFAULT_APPROVAL_TTL_SECONDS
        expires_at = datetime.fromtimestamp(time.time() + ttl, tz=timezone.utc).isoformat()

        approval = ApprovalRequest(
            approval_id=approval_id,
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            action=MessageAction.SEND.value,
            channel=draft.channel,
            draft_message_id=draft.message_id,
            status=ApprovalStatus.PENDING.value,
            reason=reason,
            requested_by=ctx.actor_id or ctx.user_id,
            expires_at=expires_at,
            security_payload=security_payload,
            metadata={
                **(metadata or {}),
                "request_id": ctx.request_id,
                "body_preview": _truncate_text(draft.body),
                "recipient": draft.recipient,
                "subject": draft.subject,
                "sensitivity": draft.sensitivity,
            },
        )

        self._approval_requests[approval_id] = approval

        draft.status = MessageStatus.PENDING_APPROVAL.value
        draft.updated_at = _utc_now()
        self._drafts[draft.message_id] = draft
        self._messages[draft.message_id] = draft

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action=action,
            success=True,
            message="Send approval requested successfully.",
            data={
                "approval_id": approval_id,
                "draft_message_id": draft.message_id,
                "channel": draft.channel,
                "recipient": draft.recipient,
                "status": approval.status,
            },
        )

        memory_payload = self._prepare_memory_payload(
            context=ctx,
            action=action,
            data={
                "approval_id": approval_id,
                "draft_message_id": draft.message_id,
                "channel": draft.channel,
                "recipient": draft.recipient,
                "reason": reason,
            },
        )

        self._log_audit_event(
            context=ctx,
            action=action,
            success=True,
            message="Send approval requested successfully.",
            channel=draft.channel,
            message_id=draft.message_id,
            approval_id=approval_id,
            metadata={
                "reason": reason,
                "expires_at": expires_at,
                "duration_ms": int((time.time() - started_at) * 1000),
            },
        )

        self._emit_agent_event(
            event_type="message.send_approval_requested",
            payload={
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "approval_id": approval_id,
                "draft_message_id": draft.message_id,
                "channel": draft.channel,
                "recipient": draft.recipient,
            },
        )

        self._record_task_history(
            context=ctx,
            action=action,
            success=True,
            data={
                "approval_id": approval_id,
                "draft_message_id": draft.message_id,
            },
        )

        return self._safe_result(
            message="Send approval requested successfully.",
            data={
                "approval": asdict(approval),
                "draft": self._public_message_dict(draft),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "duration_ms": int((time.time() - started_at) * 1000),
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def approve_action(
        self,
        *,
        context: Union[MessageContext, Dict[str, Any]],
        approval_id: str,
        approved_by: Optional[str] = None,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Approve a pending send action.

        Approval does not send by itself unless send_message() is called after.
        """

        return self._set_approval_status(
            context=context,
            approval_id=approval_id,
            status=ApprovalStatus.APPROVED,
            actor=approved_by,
            note=note,
        )

    def deny_action(
        self,
        *,
        context: Union[MessageContext, Dict[str, Any]],
        approval_id: str,
        denied_by: Optional[str] = None,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Deny a pending send action.

        A denied draft cannot be sent using the denied approval ID.
        """

        return self._set_approval_status(
            context=context,
            approval_id=approval_id,
            status=ApprovalStatus.DENIED,
            actor=denied_by,
            note=note,
        )

    def send_message(
        self,
        *,
        context: Union[MessageContext, Dict[str, Any]],
        draft_message_id: str,
        approval_id: str,
        provider_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send an approved draft.

        This method will fail unless:
            - context is valid
            - draft belongs to same user/workspace
            - approval belongs to same user/workspace
            - approval is approved and not expired
            - provider is registered
        """

        started_at = time.time()
        action = MessageAction.SEND.value

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]

        draft_result = self._get_owned_draft(ctx, draft_message_id)
        if not draft_result["success"]:
            return draft_result

        draft = draft_result["data"]["draft"]

        approval_result = self._get_owned_approval(ctx, approval_id)
        if not approval_result["success"]:
            return approval_result

        approval = approval_result["data"]["approval"]

        if approval.draft_message_id != draft.message_id:
            return self._error_result(
                message="Approval request does not match this draft.",
                error_code="APPROVAL_DRAFT_MISMATCH",
                data={
                    "approval_id": approval_id,
                    "draft_message_id": draft_message_id,
                },
            )

        approval_status_result = self._ensure_approval_is_valid(approval)
        if not approval_status_result["success"]:
            self._log_audit_event(
                context=ctx,
                action=action,
                success=False,
                message=approval_status_result["message"],
                channel=draft.channel,
                message_id=draft.message_id,
                approval_id=approval.approval_id,
            )
            return approval_status_result

        provider_result = self._resolve_provider(draft.channel, provider_name)
        if not provider_result["success"]:
            self._log_audit_event(
                context=ctx,
                action=action,
                success=False,
                message=provider_result["message"],
                channel=draft.channel,
                message_id=draft.message_id,
                approval_id=approval.approval_id,
            )
            return provider_result

        provider = provider_result["data"]["provider"]
        provider_key = provider_result["data"]["provider_name"]

        try:
            provider_response = provider.send_message(
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
                channel=draft.channel,
                recipient=draft.recipient or "",
                subject=draft.subject,
                body=draft.body,
                metadata={
                    **draft.metadata,
                    "approval_id": approval.approval_id,
                    "request_id": ctx.request_id,
                },
            )

            if not provider_response.get("success", False):
                draft.status = MessageStatus.FAILED.value
                draft.updated_at = _utc_now()
                self._messages[draft.message_id] = draft
                self._drafts[draft.message_id] = draft

                return self._error_result(
                    message=provider_response.get("message", "Provider failed to send message."),
                    error_code="PROVIDER_SEND_FAILED",
                    data={
                        "provider": provider_key,
                        "provider_response": provider_response,
                    },
                )

            draft.status = MessageStatus.SENT.value
            draft.direction = MessageDirection.OUTBOUND.value
            draft.provider_message_id = provider_response.get("provider_message_id")
            draft.updated_at = _utc_now()
            draft.metadata["provider_response"] = provider_response

            self._messages[draft.message_id] = draft
            self._drafts.pop(draft.message_id, None)

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                action=action,
                success=True,
                message="Message sent successfully.",
                data={
                    "message_id": draft.message_id,
                    "approval_id": approval.approval_id,
                    "provider": provider_key,
                    "provider_message_id": draft.provider_message_id,
                    "channel": draft.channel,
                    "recipient": draft.recipient,
                },
            )

            memory_payload = self._prepare_memory_payload(
                context=ctx,
                action=action,
                data={
                    "message_id": draft.message_id,
                    "channel": draft.channel,
                    "recipient": draft.recipient,
                    "subject": draft.subject,
                    "body_preview": _truncate_text(draft.body),
                },
            )

            self._log_audit_event(
                context=ctx,
                action=action,
                success=True,
                message="Message sent successfully.",
                channel=draft.channel,
                message_id=draft.message_id,
                approval_id=approval.approval_id,
                metadata={
                    "provider": provider_key,
                    "provider_message_id": draft.provider_message_id,
                    "duration_ms": int((time.time() - started_at) * 1000),
                },
            )

            self._emit_agent_event(
                event_type="message.sent",
                payload={
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "message_id": draft.message_id,
                    "approval_id": approval.approval_id,
                    "channel": draft.channel,
                    "recipient": draft.recipient,
                    "provider": provider_key,
                },
            )

            self._record_task_history(
                context=ctx,
                action=action,
                success=True,
                data={
                    "message_id": draft.message_id,
                    "approval_id": approval.approval_id,
                    "provider": provider_key,
                },
            )

            return self._safe_result(
                message="Message sent successfully.",
                data={
                    "message": self._public_message_dict(draft),
                    "provider_response": provider_response,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "duration_ms": int((time.time() - started_at) * 1000),
                    "request_id": ctx.request_id,
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to send message.")

            draft.status = MessageStatus.FAILED.value
            draft.updated_at = _utc_now()
            self._messages[draft.message_id] = draft

            self._log_audit_event(
                context=ctx,
                action=action,
                success=False,
                message="Failed to send message.",
                channel=draft.channel,
                message_id=draft.message_id,
                approval_id=approval.approval_id,
                metadata={
                    "error": str(exc),
                    "provider": provider_key,
                },
            )

            return self._error_result(
                message="Failed to send message.",
                error_code="MESSAGE_SEND_FAILED",
                error=str(exc),
                data={
                    "message_id": draft.message_id,
                    "approval_id": approval.approval_id,
                    "provider": provider_key,
                },
                metadata={
                    "request_id": ctx.request_id,
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                },
            )

    def list_drafts(
        self,
        *,
        context: Union[MessageContext, Dict[str, Any]],
        channel: Optional[Union[str, MessageChannel]] = None,
    ) -> Dict[str, Any]:
        """List drafts for the current user/workspace."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        normalized_channel = self._normalize_channel(channel) if channel else None

        drafts: List[Dict[str, Any]] = []
        for draft in self._drafts.values():
            if draft.user_id != ctx.user_id:
                continue
            if draft.workspace_id != ctx.workspace_id:
                continue
            if normalized_channel and draft.channel != normalized_channel:
                continue
            drafts.append(self._public_message_dict(draft))

        return self._safe_result(
            message="Drafts fetched successfully.",
            data={
                "drafts": drafts,
                "count": len(drafts),
                "channel": normalized_channel,
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def list_pending_approvals(
        self,
        *,
        context: Union[MessageContext, Dict[str, Any]],
        channel: Optional[Union[str, MessageChannel]] = None,
    ) -> Dict[str, Any]:
        """List pending approvals for the current user/workspace."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        normalized_channel = self._normalize_channel(channel) if channel else None

        approvals: List[Dict[str, Any]] = []

        for approval in self._approval_requests.values():
            if approval.user_id != ctx.user_id:
                continue
            if approval.workspace_id != ctx.workspace_id:
                continue
            if approval.status != ApprovalStatus.PENDING.value:
                continue
            if normalized_channel and approval.channel != normalized_channel:
                continue

            self._expire_approval_if_needed(approval)

            if approval.status == ApprovalStatus.PENDING.value:
                approvals.append(asdict(approval))

        return self._safe_result(
            message="Pending approvals fetched successfully.",
            data={
                "approvals": approvals,
                "count": len(approvals),
                "channel": normalized_channel,
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def get_message(
        self,
        *,
        context: Union[MessageContext, Dict[str, Any]],
        message_id: str,
    ) -> Dict[str, Any]:
        """Fetch one owned message/draft by ID."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]

        message = self._messages.get(message_id) or self._drafts.get(message_id)
        if not message:
            return self._error_result(
                message="Message not found.",
                error_code="MESSAGE_NOT_FOUND",
                data={"message_id": message_id},
            )

        if message.user_id != ctx.user_id or message.workspace_id != ctx.workspace_id:
            return self._error_result(
                message="Message does not belong to this user/workspace.",
                error_code="MESSAGE_ACCESS_DENIED",
                data={"message_id": message_id},
            )

        return self._safe_result(
            message="Message fetched successfully.",
            data={"message": self._public_message_dict(message)},
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def get_approval(
        self,
        *,
        context: Union[MessageContext, Dict[str, Any]],
        approval_id: str,
    ) -> Dict[str, Any]:
        """Fetch one owned approval request."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]

        approval_result = self._get_owned_approval(ctx, approval_id)
        if not approval_result["success"]:
            return approval_result

        approval = approval_result["data"]["approval"]
        self._expire_approval_if_needed(approval)

        return self._safe_result(
            message="Approval fetched successfully.",
            data={"approval": asdict(approval)},
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def get_audit_events(
        self,
        *,
        context: Union[MessageContext, Dict[str, Any]],
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Return owned audit events for dashboard/API display."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        normalized_limit = min(max(1, int(limit)), 500)

        events = [
            asdict(event)
            for event in self._audit_events
            if event.user_id == ctx.user_id and event.workspace_id == ctx.workspace_id
        ]

        events = events[-normalized_limit:]

        return self._safe_result(
            message="Audit events fetched successfully.",
            data={
                "events": events,
                "count": len(events),
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def get_task_history(
        self,
        *,
        context: Union[MessageContext, Dict[str, Any]],
        limit: int = 50,
    ) -> Dict[str, Any]:
        """Return task history for the current user/workspace."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]
        normalized_limit = min(max(1, int(limit)), 500)

        history = [
            item
            for item in self._task_history
            if item.get("user_id") == ctx.user_id and item.get("workspace_id") == ctx.workspace_id
        ]

        history = history[-normalized_limit:]

        return self._safe_result(
            message="Task history fetched successfully.",
            data={
                "history": history,
                "count": len(history),
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    # -----------------------------------------------------------------------
    # Compatibility hooks required by prompt
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[MessageContext, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Required:
            - user_id
            - workspace_id

        This protects against mixing messages, drafts, approvals, logs, memory,
        task history, and audit data between users/workspaces.
        """

        if isinstance(context, MessageContext):
            ctx = context
        elif isinstance(context, dict):
            ctx = MessageContext(
                user_id=_normalize_id(context.get("user_id")),
                workspace_id=_normalize_id(context.get("workspace_id")),
                actor_id=_normalize_id(context.get("actor_id")) or None,
                role=context.get("role"),
                subscription_plan=context.get("subscription_plan"),
                request_id=_normalize_id(context.get("request_id")) or str(uuid.uuid4()),
                source=context.get("source", "system_agent"),
                ip_address=context.get("ip_address"),
                user_agent=context.get("user_agent"),
                metadata=context.get("metadata") or {},
            )
        else:
            return self._error_result(
                message="Invalid task context type.",
                error_code="INVALID_CONTEXT_TYPE",
            )

        if not _is_non_empty_string(ctx.user_id):
            return self._error_result(
                message="user_id is required for message operations.",
                error_code="MISSING_USER_ID",
            )

        if not _is_non_empty_string(ctx.workspace_id):
            return self._error_result(
                message="workspace_id is required for message operations.",
                error_code="MISSING_WORKSPACE_ID",
            )

        ctx.user_id = _normalize_id(ctx.user_id)
        ctx.workspace_id = _normalize_id(ctx.workspace_id)
        ctx.actor_id = _normalize_id(ctx.actor_id) or ctx.user_id
        ctx.request_id = _normalize_id(ctx.request_id) or str(uuid.uuid4())

        return self._safe_result(
            message="Task context validated successfully.",
            data={"context": ctx},
        )

    def _requires_security_check(
        self,
        *,
        action: Union[str, MessageAction],
        message: Optional[MessageRecord] = None,
    ) -> bool:
        """
        Decide whether a task requires Security Agent approval.

        Sending messages is always sensitive and requires approval.
        High/critical sensitivity drafts can also be escalated.
        """

        normalized_action = action.value if isinstance(action, MessageAction) else str(action)

        if normalized_action == MessageAction.SEND.value:
            return True

        if message and message.sensitivity in {
            SensitivityLevel.HIGH.value,
            SensitivityLevel.CRITICAL.value,
        }:
            return True

        return False

    def _request_security_approval(
        self,
        *,
        context: MessageContext,
        action: Union[str, MessageAction],
        message: MessageRecord,
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Security Agent approval payload.

        If an external security_approval_callback exists, it is called.
        Otherwise, this method returns a local pending payload safely.
        """

        normalized_action = action.value if isinstance(action, MessageAction) else str(action)

        payload = {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "request_id": context.request_id,
            "action": normalized_action,
            "resource_type": "message",
            "resource_id": message.message_id,
            "channel": message.channel,
            "recipient": message.recipient,
            "subject": message.subject,
            "body_preview": _truncate_text(message.body),
            "sensitivity": message.sensitivity,
            "reason": reason,
            "metadata": metadata or {},
            "created_at": _utc_now(),
        }

        if self.security_approval_callback:
            try:
                response = self.security_approval_callback(payload)
                if not isinstance(response, dict):
                    return self._error_result(
                        message="Security approval callback returned invalid response.",
                        error_code="INVALID_SECURITY_CALLBACK_RESPONSE",
                    )

                if response.get("success") is False:
                    return self._error_result(
                        message=response.get("message", "Security approval rejected."),
                        error_code=response.get("error_code", "SECURITY_APPROVAL_FAILED"),
                        data=response,
                    )

                return self._safe_result(
                    message="Security approval payload processed successfully.",
                    data={
                        "approval_required": True,
                        "status": response.get("status", ApprovalStatus.PENDING.value),
                        "security_response": response,
                        "security_payload": payload,
                    },
                )

            except Exception as exc:
                self.logger.exception("Security approval callback failed.")
                return self._error_result(
                    message="Security approval callback failed.",
                    error_code="SECURITY_CALLBACK_FAILED",
                    error=str(exc),
                    data={"security_payload": payload},
                )

        return self._safe_result(
            message="Security approval required.",
            data={
                "approval_required": True,
                "status": ApprovalStatus.PENDING.value,
                "security_payload": payload,
            },
        )

    def _prepare_verification_payload(
        self,
        *,
        context: MessageContext,
        action: str,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        Verification Agent can use this to confirm if action result matches user
        instruction, permission state, and provider response.
        """

        return {
            "verification_type": "message_action",
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "request_id": context.request_id,
            "action": action,
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "created_at": _utc_now(),
        }

    def _prepare_memory_payload(
        self,
        *,
        context: MessageContext,
        action: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        The payload is scoped to user_id and workspace_id so memory never leaks
        across SaaS tenants.
        """

        return {
            "memory_type": "message_context",
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "request_id": context.request_id,
            "action": action,
            "data": data or {},
            "created_at": _utc_now(),
            "safe_to_store": True,
            "contains_full_message_body": False,
        }

    def _emit_agent_event(
        self,
        *,
        event_type: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit an agent event.

        Compatible with future event bus, WebSocket dashboard, registry hooks,
        and Master Agent task tracing.
        """

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "payload": payload or {},
            "created_at": _utc_now(),
        }

        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception:
                self.logger.exception("Event callback failed.")

        try:
            emit_event = getattr(super(), "emit_event", None)
            if callable(emit_event):
                emit_event(event_type, event)
        except Exception:
            pass

    def _log_audit_event(
        self,
        *,
        context: MessageContext,
        action: str,
        success: bool,
        message: str,
        channel: Optional[str] = None,
        message_id: Optional[str] = None,
        approval_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Store and optionally emit audit event.

        This supports dashboard analytics, security review, task history, and
        compliance logging.
        """

        event = AuditEvent(
            event_id=f"audit_{uuid.uuid4().hex}",
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            action=action,
            success=bool(success),
            message=message,
            request_id=context.request_id,
            actor_id=context.actor_id,
            channel=channel,
            message_id=message_id,
            approval_id=approval_id,
            metadata=metadata or {},
        )

        self._audit_events.append(event)

        event_dict = asdict(event)

        if self.audit_callback:
            try:
                self.audit_callback(event_dict)
            except Exception:
                self.logger.exception("Audit callback failed.")

        return event_dict

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success result."""

        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str,
        error_code: str = "ERROR",
        error: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": {
                "code": error_code,
                "detail": error or message,
            },
            "metadata": metadata or {},
        }

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _normalize_channel(self, channel: Union[str, MessageChannel, None]) -> str:
        """Normalize message channel."""

        if isinstance(channel, MessageChannel):
            return channel.value

        raw = str(channel or "").strip().lower()
        if not raw:
            return MessageChannel.INTERNAL.value

        aliases = {
            "mail": MessageChannel.EMAIL.value,
            "email": MessageChannel.EMAIL.value,
            "gmail": MessageChannel.GMAIL.value,
            "whatsapp": MessageChannel.WHATSAPP.value,
            "wa": MessageChannel.WHATSAPP.value,
            "sms": MessageChannel.SMS.value,
            "text": MessageChannel.SMS.value,
            "slack": MessageChannel.SLACK.value,
            "teams": MessageChannel.TEAMS.value,
            "discord": MessageChannel.DISCORD.value,
            "telegram": MessageChannel.TELEGRAM.value,
            "internal": MessageChannel.INTERNAL.value,
        }

        return aliases.get(raw, raw)

    def _normalize_sensitivity(
        self,
        sensitivity: Union[str, SensitivityLevel],
    ) -> str:
        """Normalize sensitivity level."""

        if isinstance(sensitivity, SensitivityLevel):
            return sensitivity.value

        raw = str(sensitivity or SensitivityLevel.MEDIUM.value).strip().lower()

        valid = {item.value for item in SensitivityLevel}
        if raw not in valid:
            return SensitivityLevel.MEDIUM.value

        return raw

    def _validate_message_payload(
        self,
        *,
        channel: str,
        recipient: str,
        body: str,
        subject: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate outbound message payload."""

        if not _is_non_empty_string(channel):
            return self._error_result(
                message="Message channel is required.",
                error_code="MISSING_CHANNEL",
            )

        if not _is_non_empty_string(recipient):
            return self._error_result(
                message="Message recipient is required.",
                error_code="MISSING_RECIPIENT",
            )

        if not _is_non_empty_string(body):
            return self._error_result(
                message="Message body is required.",
                error_code="MISSING_MESSAGE_BODY",
            )

        if len(body) > self.MAX_BODY_LENGTH:
            return self._error_result(
                message=f"Message body exceeds max length of {self.MAX_BODY_LENGTH}.",
                error_code="MESSAGE_BODY_TOO_LONG",
                data={
                    "max_length": self.MAX_BODY_LENGTH,
                    "actual_length": len(body),
                },
            )

        if subject and len(subject) > self.MAX_SUBJECT_LENGTH:
            return self._error_result(
                message=f"Message subject exceeds max length of {self.MAX_SUBJECT_LENGTH}.",
                error_code="MESSAGE_SUBJECT_TOO_LONG",
                data={
                    "max_length": self.MAX_SUBJECT_LENGTH,
                    "actual_length": len(subject),
                },
            )

        blocked_body_patterns = [
            "password:",
            "private key",
            "secret_key",
            "api_key=",
            "-----BEGIN PRIVATE KEY-----",
        ]

        lower_body = body.lower()
        for pattern in blocked_body_patterns:
            if pattern.lower() in lower_body:
                return self._error_result(
                    message="Message body appears to contain sensitive secret material.",
                    error_code="SENSITIVE_SECRET_DETECTED",
                    data={"matched_pattern": pattern},
                )

        return self._safe_result(
            message="Message payload validated successfully.",
            data={
                "channel": channel,
                "recipient": recipient.strip(),
                "subject": subject.strip() if subject else None,
            },
        )

    def _resolve_provider(
        self,
        channel: str,
        provider_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Resolve provider for a channel."""

        selected_name = None

        if provider_name:
            selected_name = provider_name.strip()
        elif channel in self.channel_provider_map:
            selected_name = self.channel_provider_map[channel]
        elif self.default_provider_name in self.providers:
            selected_name = self.default_provider_name

        if not selected_name:
            return self._error_result(
                message=f"No provider configured for channel '{channel}'.",
                error_code="NO_PROVIDER_CONFIGURED",
                data={"channel": channel},
            )

        provider = self.providers.get(selected_name)
        if not provider:
            return self._error_result(
                message=f"Provider '{selected_name}' is not registered.",
                error_code="PROVIDER_NOT_REGISTERED",
                data={
                    "channel": channel,
                    "provider_name": selected_name,
                },
            )

        if self.strict_provider_mode and selected_name == self.default_provider_name:
            return self._error_result(
                message=(
                    f"Strict provider mode is enabled. Configure a real provider "
                    f"for channel '{channel}'."
                ),
                error_code="STRICT_PROVIDER_REQUIRED",
                data={
                    "channel": channel,
                    "provider_name": selected_name,
                },
            )

        return self._safe_result(
            message="Provider resolved successfully.",
            data={
                "provider_name": selected_name,
                "provider": provider,
                "channel": channel,
            },
        )

    def _message_record_from_provider(
        self,
        raw: Dict[str, Any],
        *,
        ctx: MessageContext,
        channel: str,
    ) -> MessageRecord:
        """Create MessageRecord from provider response."""

        message_id = str(raw.get("message_id") or raw.get("id") or f"msg_{uuid.uuid4().hex}")

        return MessageRecord(
            message_id=message_id,
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            channel=channel,
            direction=str(raw.get("direction") or MessageDirection.INBOUND.value),
            status=str(raw.get("status") or MessageStatus.READ.value),
            recipient=raw.get("recipient"),
            sender=raw.get("sender"),
            subject=raw.get("subject"),
            body=str(raw.get("body") or ""),
            provider_message_id=raw.get("provider_message_id"),
            sensitivity=str(raw.get("sensitivity") or SensitivityLevel.MEDIUM.value),
            created_at=str(raw.get("created_at") or _utc_now()),
            updated_at=str(raw.get("updated_at") or _utc_now()),
            metadata=raw.get("metadata") or {},
        )

    def _public_message_dict(self, message: MessageRecord) -> Dict[str, Any]:
        """
        Return safe message representation.

        Full body is included because the user explicitly requested read/draft
        controller behavior. For audit/memory payloads, only previews are used.
        """

        return {
            "message_id": message.message_id,
            "user_id": message.user_id,
            "workspace_id": message.workspace_id,
            "channel": message.channel,
            "direction": message.direction,
            "status": message.status,
            "recipient": message.recipient,
            "sender": message.sender,
            "subject": message.subject,
            "body": message.body,
            "provider_message_id": message.provider_message_id,
            "sensitivity": message.sensitivity,
            "created_at": message.created_at,
            "updated_at": message.updated_at,
            "metadata": _safe_copy(message.metadata),
        }

    def _sanitize_filters(
        self,
        filters: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Return safe filters for audit metadata."""

        if not filters:
            return {}

        safe = {}
        for key, value in filters.items():
            if key.lower() in {"password", "token", "secret", "api_key"}:
                safe[key] = "***redacted***"
            else:
                safe[key] = _truncate_text(str(value), 120)

        return safe

    def _get_owned_draft(
        self,
        ctx: MessageContext,
        draft_message_id: str,
    ) -> Dict[str, Any]:
        """Fetch draft and enforce user/workspace ownership."""

        if not _is_non_empty_string(draft_message_id):
            return self._error_result(
                message="draft_message_id is required.",
                error_code="MISSING_DRAFT_MESSAGE_ID",
            )

        draft = self._drafts.get(draft_message_id)
        if not draft:
            return self._error_result(
                message="Draft not found.",
                error_code="DRAFT_NOT_FOUND",
                data={"draft_message_id": draft_message_id},
            )

        if draft.user_id != ctx.user_id or draft.workspace_id != ctx.workspace_id:
            return self._error_result(
                message="Draft does not belong to this user/workspace.",
                error_code="DRAFT_ACCESS_DENIED",
                data={"draft_message_id": draft_message_id},
            )

        return self._safe_result(
            message="Draft fetched successfully.",
            data={"draft": draft},
        )

    def _get_owned_approval(
        self,
        ctx: MessageContext,
        approval_id: str,
    ) -> Dict[str, Any]:
        """Fetch approval request and enforce user/workspace ownership."""

        if not _is_non_empty_string(approval_id):
            return self._error_result(
                message="approval_id is required.",
                error_code="MISSING_APPROVAL_ID",
            )

        approval = self._approval_requests.get(approval_id)
        if not approval:
            return self._error_result(
                message="Approval request not found.",
                error_code="APPROVAL_NOT_FOUND",
                data={"approval_id": approval_id},
            )

        if approval.user_id != ctx.user_id or approval.workspace_id != ctx.workspace_id:
            return self._error_result(
                message="Approval request does not belong to this user/workspace.",
                error_code="APPROVAL_ACCESS_DENIED",
                data={"approval_id": approval_id},
            )

        return self._safe_result(
            message="Approval fetched successfully.",
            data={"approval": approval},
        )

    def _set_approval_status(
        self,
        *,
        context: Union[MessageContext, Dict[str, Any]],
        approval_id: str,
        status: ApprovalStatus,
        actor: Optional[str] = None,
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Approve or deny a pending approval request."""

        action = (
            MessageAction.APPROVE_SEND.value
            if status == ApprovalStatus.APPROVED
            else MessageAction.DENY_SEND.value
        )

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]

        approval_result = self._get_owned_approval(ctx, approval_id)
        if not approval_result["success"]:
            return approval_result

        approval = approval_result["data"]["approval"]
        self._expire_approval_if_needed(approval)

        if approval.status == ApprovalStatus.EXPIRED.value:
            return self._error_result(
                message="Approval request has expired.",
                error_code="APPROVAL_EXPIRED",
                data={"approval_id": approval_id},
            )

        if approval.status != ApprovalStatus.PENDING.value:
            return self._error_result(
                message=f"Approval request is already '{approval.status}'.",
                error_code="APPROVAL_NOT_PENDING",
                data={
                    "approval_id": approval_id,
                    "status": approval.status,
                },
            )

        draft = self._drafts.get(approval.draft_message_id)

        approval.status = status.value
        approval.updated_at = _utc_now()
        approval.metadata["note"] = note

        if status == ApprovalStatus.APPROVED:
            approval.approved_by = actor or ctx.actor_id or ctx.user_id
            if draft:
                draft.status = MessageStatus.APPROVED.value
                draft.updated_at = _utc_now()
                self._drafts[draft.message_id] = draft
                self._messages[draft.message_id] = draft
            result_message = "Send action approved successfully."
            event_type = "message.send_approved"
        else:
            approval.denied_by = actor or ctx.actor_id or ctx.user_id
            if draft:
                draft.status = MessageStatus.DENIED.value
                draft.updated_at = _utc_now()
                self._drafts[draft.message_id] = draft
                self._messages[draft.message_id] = draft
            result_message = "Send action denied successfully."
            event_type = "message.send_denied"

        self._approval_requests[approval.approval_id] = approval

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action=action,
            success=True,
            message=result_message,
            data={
                "approval_id": approval.approval_id,
                "draft_message_id": approval.draft_message_id,
                "status": approval.status,
                "note": note,
            },
        )

        memory_payload = self._prepare_memory_payload(
            context=ctx,
            action=action,
            data={
                "approval_id": approval.approval_id,
                "draft_message_id": approval.draft_message_id,
                "status": approval.status,
                "note": note,
            },
        )

        self._log_audit_event(
            context=ctx,
            action=action,
            success=True,
            message=result_message,
            channel=approval.channel,
            message_id=approval.draft_message_id,
            approval_id=approval.approval_id,
            metadata={
                "status": approval.status,
                "actor": actor or ctx.actor_id or ctx.user_id,
                "note": note,
            },
        )

        self._emit_agent_event(
            event_type=event_type,
            payload={
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "approval_id": approval.approval_id,
                "draft_message_id": approval.draft_message_id,
                "status": approval.status,
            },
        )

        self._record_task_history(
            context=ctx,
            action=action,
            success=True,
            data={
                "approval_id": approval.approval_id,
                "draft_message_id": approval.draft_message_id,
                "status": approval.status,
            },
        )

        return self._safe_result(
            message=result_message,
            data={
                "approval": asdict(approval),
                "draft": self._public_message_dict(draft) if draft else None,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "request_id": ctx.request_id,
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
            },
        )

    def _ensure_approval_is_valid(
        self,
        approval: ApprovalRequest,
    ) -> Dict[str, Any]:
        """Validate approval before sending."""

        self._expire_approval_if_needed(approval)

        if approval.status == ApprovalStatus.EXPIRED.value:
            return self._error_result(
                message="Approval request has expired.",
                error_code="APPROVAL_EXPIRED",
                data={"approval_id": approval.approval_id},
            )

        if approval.status == ApprovalStatus.DENIED.value:
            return self._error_result(
                message="Approval request was denied.",
                error_code="APPROVAL_DENIED",
                data={"approval_id": approval.approval_id},
            )

        if approval.status != ApprovalStatus.APPROVED.value:
            return self._error_result(
                message="Message cannot be sent without approved approval request.",
                error_code="APPROVAL_REQUIRED",
                data={
                    "approval_id": approval.approval_id,
                    "status": approval.status,
                },
            )

        return self._safe_result(
            message="Approval is valid.",
            data={"approval_id": approval.approval_id},
        )

    def _expire_approval_if_needed(self, approval: ApprovalRequest) -> None:
        """Expire pending approval when TTL has passed."""

        if approval.status != ApprovalStatus.PENDING.value:
            return

        if not approval.expires_at:
            return

        try:
            expires_at = datetime.fromisoformat(approval.expires_at)
            now = datetime.now(timezone.utc)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)

            if now > expires_at:
                approval.status = ApprovalStatus.EXPIRED.value
                approval.updated_at = _utc_now()
                self._approval_requests[approval.approval_id] = approval

                draft = self._drafts.get(approval.draft_message_id)
                if draft and draft.status == MessageStatus.PENDING_APPROVAL.value:
                    draft.status = MessageStatus.FAILED.value
                    draft.updated_at = _utc_now()
                    draft.metadata["approval_expired"] = True
                    self._drafts[draft.message_id] = draft
                    self._messages[draft.message_id] = draft

        except Exception:
            self.logger.exception("Failed to evaluate approval expiry.")

    def _record_task_history(
        self,
        *,
        context: MessageContext,
        action: str,
        success: bool,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record lightweight task history for dashboard/Master Agent."""

        self._task_history.append(
            {
                "task_id": f"task_{uuid.uuid4().hex}",
                "agent_id": self.agent_id,
                "agent_name": self.agent_name,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "actor_id": context.actor_id,
                "request_id": context.request_id,
                "action": action,
                "success": bool(success),
                "data": data or {},
                "created_at": _utc_now(),
            }
        )

    # -----------------------------------------------------------------------
    # Convenience workflow
    # -----------------------------------------------------------------------

    def draft_and_request_approval(
        self,
        *,
        context: Union[MessageContext, Dict[str, Any]],
        channel: Union[str, MessageChannel],
        recipient: str,
        body: str,
        subject: Optional[str] = None,
        reason: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        sensitivity: Union[str, SensitivityLevel] = SensitivityLevel.MEDIUM,
    ) -> Dict[str, Any]:
        """
        Convenience method:
            1. Create draft.
            2. Request send approval.

        It still does not send the message.
        """

        draft_result = self.draft_message(
            context=context,
            channel=channel,
            recipient=recipient,
            subject=subject,
            body=body,
            metadata=metadata,
            sensitivity=sensitivity,
        )

        if not draft_result["success"]:
            return draft_result

        draft_id = draft_result["data"]["draft"]["message_id"]

        approval_result = self.request_send_approval(
            context=context,
            draft_message_id=draft_id,
            reason=reason,
            metadata=metadata,
        )

        if not approval_result["success"]:
            return approval_result

        return self._safe_result(
            message="Draft created and approval requested successfully.",
            data={
                "draft": draft_result["data"]["draft"],
                "approval": approval_result["data"]["approval"],
                "draft_result": draft_result,
                "approval_result": approval_result,
            },
            metadata=draft_result.get("metadata", {}),
        )


# ---------------------------------------------------------------------------
# Module-level safe factory
# ---------------------------------------------------------------------------

def build_message_controller(**kwargs: Any) -> MessageController:
    """
    Factory for Agent Loader / Registry.

    Example:
        controller = build_message_controller()
    """

    return MessageController(**kwargs)


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    controller = MessageController()

    test_context = {
        "user_id": "user_demo_1",
        "workspace_id": "workspace_demo_1",
        "actor_id": "admin_demo_1",
        "role": "owner",
    }

    draft = controller.draft_message(
        context=test_context,
        channel="gmail",
        recipient="client@example.com",
        subject="Project Update",
        body="Hello, this is a safe draft message from William.",
    )

    print("DRAFT:", draft)

    if draft["success"]:
        approval = controller.request_send_approval(
            context=test_context,
            draft_message_id=draft["data"]["draft"]["message_id"],
            reason="User requested this Gmail message to be prepared for sending.",
        )

        print("APPROVAL REQUEST:", approval)

        if approval["success"]:
            approved = controller.approve_action(
                context=test_context,
                approval_id=approval["data"]["approval"]["approval_id"],
                approved_by="admin_demo_1",
                note="Approved in local smoke test.",
            )

            print("APPROVED:", approved)

            sent = controller.send_message(
                context=test_context,
                draft_message_id=draft["data"]["draft"]["message_id"],
                approval_id=approval["data"]["approval"]["approval_id"],
            )

            print("SENT:", sent)


"""
Agent/Module: System Agent
File Completed: message_controller.py
Completion: 47.1%
Completed Files: ['system_agent.py', 'app_controller.py', 'file_manager.py', 'os_commands.py', 'device_controls.py', 'automation.py', 'notification_reader.py', 'message_controller.py']
Remaining Files: ['call_controller.py', 'permission_guard.py', 'app_profiles.py', 'device_sync.py', 'gesture_control.py', 'desktop_vision.py', 'task_recorder.py', 'system_memory.py', 'config.py']
Next Recommended File: agents/system_agent/call_controller.py
FILE COMPLETE
"""