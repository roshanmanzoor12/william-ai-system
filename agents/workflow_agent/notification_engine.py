"""
agents/workflow_agent/notification_engine.py

William / Jarvis Multi-Agent AI SaaS System - Workflow Agent Notification Engine
Digital Promotix

Purpose:
    Sends alerts over WhatsApp, email, Slack, Discord, mobile, and dashboard channels.

This module is designed to be:
    - Import-safe even when the rest of the William/Jarvis codebase is not available yet.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router, and Master Agent routing.
    - SaaS-safe with strict user_id/workspace_id isolation.
    - Security-aware: outbound/sensitive notifications can require Security Agent approval.
    - Verification-ready: completed actions prepare Verification Agent payloads.
    - Memory-compatible: useful context can be prepared for Memory Agent.
    - Dashboard/API-ready: all public methods return structured dict results.

Important:
    This file does not hardcode secrets.
    Real outbound sends are disabled by default unless:
        1. dry_run=False, and
        2. security approval is granted or not required by policy, and
        3. channel configuration is provided safely at runtime/environment.
"""

from __future__ import annotations

import base64
import dataclasses
import email.utils
import enum
import hashlib
import hmac
import json
import logging
import os
import smtplib
import ssl
import time
import traceback
import uuid
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# =============================================================================
# Import-safe BaseAgent fallback
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early project generation
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the real William/Jarvis BaseAgent
        exists. The real BaseAgent should provide richer lifecycle, routing,
        registry, and telemetry behavior.
        """

        agent_name: str = "base_agent"
        agent_type: str = "generic"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_id = kwargs.get("agent_id", self.agent_name)
            self.logger = logging.getLogger(self.agent_id)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_name, payload)


# =============================================================================
# Logging
# =============================================================================

LOGGER = logging.getLogger(__name__)
if not LOGGER.handlers:
    logging.basicConfig(level=os.getenv("WILLIAM_LOG_LEVEL", "INFO"))


# =============================================================================
# Enums and constants
# =============================================================================

class NotificationChannel(str, enum.Enum):
    """Supported outbound/internal notification channels."""

    WHATSAPP = "whatsapp"
    EMAIL = "email"
    SLACK = "slack"
    DISCORD = "discord"
    MOBILE = "mobile"
    DASHBOARD = "dashboard"


class NotificationPriority(str, enum.Enum):
    """Notification priority levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"
    CRITICAL = "critical"


class NotificationStatus(str, enum.Enum):
    """Normalized delivery status."""

    QUEUED = "queued"
    SENT = "sent"
    SKIPPED = "skipped"
    FAILED = "failed"
    DRY_RUN = "dry_run"
    REQUIRES_APPROVAL = "requires_approval"
    PARTIAL = "partial"


class SecurityDecision(str, enum.Enum):
    """Security approval result."""

    APPROVED = "approved"
    DENIED = "denied"
    NOT_REQUIRED = "not_required"
    UNAVAILABLE = "unavailable"


DEFAULT_ALLOWED_CHANNELS = {
    NotificationChannel.WHATSAPP.value,
    NotificationChannel.EMAIL.value,
    NotificationChannel.SLACK.value,
    NotificationChannel.DISCORD.value,
    NotificationChannel.MOBILE.value,
    NotificationChannel.DASHBOARD.value,
}

EXTERNAL_CHANNELS = {
    NotificationChannel.WHATSAPP.value,
    NotificationChannel.EMAIL.value,
    NotificationChannel.SLACK.value,
    NotificationChannel.DISCORD.value,
    NotificationChannel.MOBILE.value,
}

INTERNAL_CHANNELS = {
    NotificationChannel.DASHBOARD.value,
}

SENSITIVE_PRIORITY_LEVELS = {
    NotificationPriority.URGENT.value,
    NotificationPriority.CRITICAL.value,
}

MAX_TITLE_LENGTH = 180
MAX_MESSAGE_LENGTH = 8000
MAX_RECIPIENTS_PER_CALL = 100
DEFAULT_HTTP_TIMEOUT_SECONDS = 12


# =============================================================================
# Data structures
# =============================================================================

@dataclasses.dataclass(frozen=True)
class NotificationRecipient:
    """
    Normalized recipient for any channel.

    For channel-specific routing:
        - email: address should be an email address.
        - whatsapp: address should be E.164 or provider-specific recipient id.
        - slack: address may be a channel id/name, user id, or webhook target.
        - discord: address may be channel id/name or webhook target.
        - mobile: address may be user/device token.
        - dashboard: address may be user id, role, team, or workspace target.
    """

    address: str
    name: Optional[str] = None
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def safe_dict(self) -> Dict[str, Any]:
        return {
            "address": mask_contact(self.address),
            "name": self.name,
            "metadata": safe_metadata(self.metadata),
        }


@dataclasses.dataclass(frozen=True)
class NotificationPayload:
    """A normalized alert payload routed by the NotificationEngine."""

    user_id: str
    workspace_id: str
    channel: str
    title: str
    message: str
    recipients: Tuple[NotificationRecipient, ...]
    priority: str = NotificationPriority.NORMAL.value
    template_id: Optional[str] = None
    template_data: Dict[str, Any] = dataclasses.field(default_factory=dict)
    action_url: Optional[str] = None
    correlation_id: Optional[str] = None
    workflow_id: Optional[str] = None
    task_id: Optional[str] = None
    event_type: Optional[str] = None
    attachments: Tuple[Dict[str, Any], ...] = dataclasses.field(default_factory=tuple)
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def safe_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "channel": self.channel,
            "title": self.title,
            "message_preview": truncate_text(self.message, 220),
            "recipients": [r.safe_dict() for r in self.recipients],
            "priority": self.priority,
            "template_id": self.template_id,
            "template_data": safe_metadata(self.template_data),
            "action_url": self.action_url,
            "correlation_id": self.correlation_id,
            "workflow_id": self.workflow_id,
            "task_id": self.task_id,
            "event_type": self.event_type,
            "attachments_count": len(self.attachments),
            "metadata": safe_metadata(self.metadata),
        }


@dataclasses.dataclass
class NotificationEngineConfig:
    """
    Runtime configuration.

    Keep secrets out of code. Pass secrets at runtime or through environment variables.
    """

    dry_run_default: bool = True
    require_security_for_external: bool = True
    require_security_for_sensitive_priority: bool = True
    allowed_channels: Sequence[str] = dataclasses.field(
        default_factory=lambda: sorted(DEFAULT_ALLOWED_CHANNELS)
    )
    http_timeout_seconds: int = DEFAULT_HTTP_TIMEOUT_SECONDS
    max_recipients_per_call: int = MAX_RECIPIENTS_PER_CALL
    dashboard_events_enabled: bool = True
    mobile_events_enabled: bool = True

    # Slack/Discord webhook routing can be injected per workspace or via config.
    slack_webhook_url: Optional[str] = None
    discord_webhook_url: Optional[str] = None
    whatsapp_webhook_url: Optional[str] = None
    whatsapp_auth_header: Optional[str] = None

    # Email SMTP config.
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from_email: Optional[str] = None
    smtp_from_name: Optional[str] = "William AI"
    smtp_use_tls: bool = True

    # Optional HMAC signing for internal dashboard/mobile event payloads.
    internal_event_signing_secret: Optional[str] = None

    @classmethod
    def from_env(cls) -> "NotificationEngineConfig":
        """Create config from environment without hardcoding secrets."""
        return cls(
            dry_run_default=parse_bool(os.getenv("WILLIAM_NOTIFICATIONS_DRY_RUN"), True),
            require_security_for_external=parse_bool(
                os.getenv("WILLIAM_NOTIFY_REQUIRE_SECURITY_EXTERNAL"), True
            ),
            require_security_for_sensitive_priority=parse_bool(
                os.getenv("WILLIAM_NOTIFY_REQUIRE_SECURITY_SENSITIVE"), True
            ),
            http_timeout_seconds=parse_int(
                os.getenv("WILLIAM_NOTIFY_HTTP_TIMEOUT"),
                DEFAULT_HTTP_TIMEOUT_SECONDS,
            ),
            max_recipients_per_call=parse_int(
                os.getenv("WILLIAM_NOTIFY_MAX_RECIPIENTS"),
                MAX_RECIPIENTS_PER_CALL,
            ),
            dashboard_events_enabled=parse_bool(
                os.getenv("WILLIAM_DASHBOARD_EVENTS_ENABLED"), True
            ),
            mobile_events_enabled=parse_bool(
                os.getenv("WILLIAM_MOBILE_EVENTS_ENABLED"), True
            ),
            slack_webhook_url=os.getenv("WILLIAM_SLACK_WEBHOOK_URL"),
            discord_webhook_url=os.getenv("WILLIAM_DISCORD_WEBHOOK_URL"),
            whatsapp_webhook_url=os.getenv("WILLIAM_WHATSAPP_WEBHOOK_URL"),
            whatsapp_auth_header=os.getenv("WILLIAM_WHATSAPP_AUTH_HEADER"),
            smtp_host=os.getenv("WILLIAM_SMTP_HOST"),
            smtp_port=parse_int(os.getenv("WILLIAM_SMTP_PORT"), 587),
            smtp_username=os.getenv("WILLIAM_SMTP_USERNAME"),
            smtp_password=os.getenv("WILLIAM_SMTP_PASSWORD"),
            smtp_from_email=os.getenv("WILLIAM_SMTP_FROM_EMAIL"),
            smtp_from_name=os.getenv("WILLIAM_SMTP_FROM_NAME", "William AI"),
            smtp_use_tls=parse_bool(os.getenv("WILLIAM_SMTP_USE_TLS"), True),
            internal_event_signing_secret=os.getenv("WILLIAM_INTERNAL_EVENT_SIGNING_SECRET"),
        )


# =============================================================================
# Utility helpers
# =============================================================================

def utc_now_iso() -> str:
    """Return UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    """Parse bool-ish environment/config values."""
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_int(value: Optional[str], default: int) -> int:
    """Parse integer values safely."""
    try:
        if value is None:
            return default
        return int(value)
    except Exception:
        return default


def truncate_text(value: str, limit: int) -> str:
    """Truncate text safely."""
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 3)] + "..."


def stable_hash(value: str) -> str:
    """Create a stable short hash for audit-safe references."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def mask_contact(value: str) -> str:
    """Mask email/phone/token-like contact details for safe logs."""
    if not value:
        return value
    value = str(value)
    if "@" in value:
        local, _, domain = value.partition("@")
        if len(local) <= 2:
            masked_local = local[:1] + "***"
        else:
            masked_local = local[:2] + "***"
        return f"{masked_local}@{domain}"
    digits = "".join(ch for ch in value if ch.isdigit())
    if len(digits) >= 7:
        return f"***{digits[-4:]}"
    if len(value) <= 4:
        return "***"
    return f"{value[:2]}***{value[-2:]}"


def safe_metadata(metadata: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """
    Sanitize metadata for logs/events by redacting common secret keys.

    This does not mutate the original mapping.
    """
    if not metadata:
        return {}

    secret_terms = {
        "token",
        "secret",
        "password",
        "api_key",
        "apikey",
        "authorization",
        "auth",
        "bearer",
        "cookie",
        "session",
        "private_key",
    }

    safe: Dict[str, Any] = {}
    for key, value in metadata.items():
        key_str = str(key)
        key_lower = key_str.lower()
        if any(term in key_lower for term in secret_terms):
            safe[key_str] = "***REDACTED***"
        elif isinstance(value, Mapping):
            safe[key_str] = safe_metadata(value)
        elif isinstance(value, list):
            safe[key_str] = [
                safe_metadata(item) if isinstance(item, Mapping) else item
                for item in value[:25]
            ]
            if len(value) > 25:
                safe[key_str].append(f"... {len(value) - 25} more items")
        else:
            safe[key_str] = value
    return safe


def normalize_channel(channel: str) -> str:
    """Normalize a channel value."""
    return str(channel or "").strip().lower()


def normalize_priority(priority: str) -> str:
    """Normalize a priority value."""
    value = str(priority or NotificationPriority.NORMAL.value).strip().lower()
    allowed = {item.value for item in NotificationPriority}
    return value if value in allowed else NotificationPriority.NORMAL.value


def normalize_recipients(
    recipients: Union[
        str,
        NotificationRecipient,
        Mapping[str, Any],
        Sequence[Union[str, NotificationRecipient, Mapping[str, Any]]],
    ]
) -> Tuple[NotificationRecipient, ...]:
    """Normalize user-provided recipient formats."""
    if isinstance(recipients, (str, NotificationRecipient, Mapping)):
        raw_items: Sequence[Any] = [recipients]
    else:
        raw_items = list(recipients or [])

    normalized: List[NotificationRecipient] = []
    for item in raw_items:
        if isinstance(item, NotificationRecipient):
            if item.address:
                normalized.append(item)
        elif isinstance(item, str):
            address = item.strip()
            if address:
                normalized.append(NotificationRecipient(address=address))
        elif isinstance(item, Mapping):
            address = str(item.get("address") or item.get("email") or item.get("phone") or item.get("id") or "").strip()
            if address:
                normalized.append(
                    NotificationRecipient(
                        address=address,
                        name=item.get("name"),
                        metadata=dict(item.get("metadata") or {}),
                    )
                )

    # Deduplicate by address while preserving order.
    seen = set()
    deduped: List[NotificationRecipient] = []
    for recipient in normalized:
        key = recipient.address.lower()
        if key not in seen:
            seen.add(key)
            deduped.append(recipient)
    return tuple(deduped)


def validate_email_address(address: str) -> bool:
    """Basic email validation suitable for safety checks."""
    parsed = email.utils.parseaddr(address)[1]
    return bool(parsed and "@" in parsed and "." in parsed.rsplit("@", 1)[-1])


def sign_payload(payload: Mapping[str, Any], secret: str) -> str:
    """Return hex HMAC signature for internal event payloads."""
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


# =============================================================================
# Notification Engine
# =============================================================================

class NotificationEngine(BaseAgent):
    """
    Workflow Agent notification helper.

    Master Agent:
        Can route workflow notification tasks to this class via public methods:
        - send_notification()
        - send_bulk_notifications()
        - send_workflow_alert()
        - send_dashboard_event()
        - send_mobile_event()

    Security Agent:
        Outbound and high-risk alerts pass through _requires_security_check()
        and _request_security_approval() before real sending.

    Memory Agent:
        Useful notification summaries can be prepared using _prepare_memory_payload().

    Verification Agent:
        Every completed notification prepares a verification payload using
        _prepare_verification_payload().

    Dashboard/API:
        All results follow success/message/data/error/metadata structure.
    """

    agent_name = "notification_engine"
    agent_type = "workflow_agent"
    public_methods = (
        "send_notification",
        "send_bulk_notifications",
        "send_workflow_alert",
        "send_dashboard_event",
        "send_mobile_event",
        "get_supported_channels",
        "validate_notification_payload",
    )

    def __init__(
        self,
        config: Optional[NotificationEngineConfig] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_callback: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        memory_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        verification_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.config = config or NotificationEngineConfig.from_env()
        self.security_approval_callback = security_approval_callback
        self.audit_callback = audit_callback
        self.event_callback = event_callback
        self.memory_callback = memory_callback
        self.verification_callback = verification_callback
        self.logger = logger or getattr(self, "logger", LOGGER)
        self._dashboard_event_store: List[Dict[str, Any]] = []
        self._mobile_event_store: List[Dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def get_supported_channels(self) -> Dict[str, Any]:
        """Return channels supported by this engine."""
        channels = sorted({channel.value for channel in NotificationChannel})
        return self._safe_result(
            message="Supported notification channels loaded.",
            data={
                "channels": channels,
                "allowed_channels": sorted(set(self.config.allowed_channels)),
                "external_channels": sorted(EXTERNAL_CHANNELS),
                "internal_channels": sorted(INTERNAL_CHANNELS),
                "dry_run_default": self.config.dry_run_default,
            },
            metadata={"agent": self.agent_name},
        )

    def validate_notification_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
        channel: str,
        title: str,
        message: str,
        recipients: Union[
            str,
            NotificationRecipient,
            Mapping[str, Any],
            Sequence[Union[str, NotificationRecipient, Mapping[str, Any]]],
        ],
        priority: str = NotificationPriority.NORMAL.value,
        template_id: Optional[str] = None,
        template_data: Optional[Mapping[str, Any]] = None,
        action_url: Optional[str] = None,
        correlation_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        task_id: Optional[str] = None,
        event_type: Optional[str] = None,
        attachments: Optional[Sequence[Mapping[str, Any]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Validate a notification request without sending it."""
        try:
            payload = self._build_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                channel=channel,
                title=title,
                message=message,
                recipients=recipients,
                priority=priority,
                template_id=template_id,
                template_data=template_data,
                action_url=action_url,
                correlation_id=correlation_id,
                workflow_id=workflow_id,
                task_id=task_id,
                event_type=event_type,
                attachments=attachments,
                metadata=metadata,
            )
            validation = self._validate_payload(payload)
            if not validation["success"]:
                return validation
            return self._safe_result(
                message="Notification payload is valid.",
                data={"payload": payload.safe_dict()},
                metadata={"agent": self.agent_name},
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to validate notification payload.",
                error=exc,
                metadata={"agent": self.agent_name},
            )

    def send_notification(
        self,
        *,
        user_id: str,
        workspace_id: str,
        channel: str,
        title: str,
        message: str,
        recipients: Union[
            str,
            NotificationRecipient,
            Mapping[str, Any],
            Sequence[Union[str, NotificationRecipient, Mapping[str, Any]]],
        ],
        priority: str = NotificationPriority.NORMAL.value,
        template_id: Optional[str] = None,
        template_data: Optional[Mapping[str, Any]] = None,
        action_url: Optional[str] = None,
        correlation_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        task_id: Optional[str] = None,
        event_type: Optional[str] = None,
        attachments: Optional[Sequence[Mapping[str, Any]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        dry_run: Optional[bool] = None,
        require_approval: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Send or prepare a single notification.

        Real sending only happens when dry_run is False and security checks pass.
        """
        started = time.time()
        correlation_id = correlation_id or self._new_correlation_id()

        try:
            payload = self._build_payload(
                user_id=user_id,
                workspace_id=workspace_id,
                channel=channel,
                title=title,
                message=message,
                recipients=recipients,
                priority=priority,
                template_id=template_id,
                template_data=template_data,
                action_url=action_url,
                correlation_id=correlation_id,
                workflow_id=workflow_id,
                task_id=task_id,
                event_type=event_type,
                attachments=attachments,
                metadata=metadata,
            )

            context_result = self._validate_task_context(
                user_id=payload.user_id,
                workspace_id=payload.workspace_id,
                task_id=payload.task_id,
                workflow_id=payload.workflow_id,
                metadata=payload.metadata,
            )
            if not context_result["success"]:
                return context_result

            validation_result = self._validate_payload(payload)
            if not validation_result["success"]:
                self._log_audit_event(
                    action="notification.validation_failed",
                    user_id=payload.user_id,
                    workspace_id=payload.workspace_id,
                    data={
                        "payload": payload.safe_dict(),
                        "error": validation_result.get("error"),
                    },
                    correlation_id=payload.correlation_id,
                )
                return validation_result

            effective_dry_run = self.config.dry_run_default if dry_run is None else bool(dry_run)

            self._emit_agent_event(
                "notification.requested",
                {
                    "payload": payload.safe_dict(),
                    "dry_run": effective_dry_run,
                    "created_at": utc_now_iso(),
                },
            )

            security_result = self._handle_security(
                payload=payload,
                dry_run=effective_dry_run,
                require_approval=require_approval,
            )
            if not security_result["success"]:
                return security_result

            if security_result["data"].get("status") == NotificationStatus.REQUIRES_APPROVAL.value:
                return security_result

            if effective_dry_run:
                delivery_result = self._dry_run_delivery(payload)
            else:
                delivery_result = self._dispatch(payload)

            duration_ms = int((time.time() - started) * 1000)

            verification_payload = self._prepare_verification_payload(
                payload=payload,
                delivery_result=delivery_result,
                duration_ms=duration_ms,
            )

            memory_payload = self._prepare_memory_payload(
                payload=payload,
                delivery_result=delivery_result,
            )

            self._send_optional_callback(self.verification_callback, verification_payload)
            self._send_optional_callback(self.memory_callback, memory_payload)

            self._log_audit_event(
                action="notification.completed",
                user_id=payload.user_id,
                workspace_id=payload.workspace_id,
                data={
                    "payload": payload.safe_dict(),
                    "delivery": delivery_result.get("data", {}),
                    "status": delivery_result.get("data", {}).get("status"),
                    "duration_ms": duration_ms,
                },
                correlation_id=payload.correlation_id,
            )

            self._emit_agent_event(
                "notification.completed",
                {
                    "payload": payload.safe_dict(),
                    "delivery": delivery_result.get("data", {}),
                    "duration_ms": duration_ms,
                    "verification": verification_payload,
                    "memory": memory_payload,
                },
            )

            return self._safe_result(
                message=delivery_result.get("message", "Notification processed."),
                data={
                    "status": delivery_result.get("data", {}).get("status"),
                    "channel": payload.channel,
                    "correlation_id": payload.correlation_id,
                    "delivery": delivery_result.get("data", {}),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "agent": self.agent_name,
                    "duration_ms": duration_ms,
                    "dry_run": effective_dry_run,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Notification processing failed.",
                error=exc,
                metadata={
                    "agent": self.agent_name,
                    "correlation_id": correlation_id,
                    "duration_ms": int((time.time() - started) * 1000),
                },
            )

    def send_bulk_notifications(
        self,
        notifications: Sequence[Mapping[str, Any]],
        *,
        default_user_id: Optional[str] = None,
        default_workspace_id: Optional[str] = None,
        dry_run: Optional[bool] = None,
        require_approval: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Send multiple notifications safely.

        Each notification remains isolated by its own user_id/workspace_id.
        default_user_id/default_workspace_id may be used only when a specific item
        does not include them.
        """
        started = time.time()

        if not isinstance(notifications, Sequence) or isinstance(notifications, (str, bytes)):
            return self._error_result(
                message="notifications must be a sequence of notification dictionaries.",
                error="invalid_notifications_type",
                metadata={"agent": self.agent_name},
            )

        results: List[Dict[str, Any]] = []
        success_count = 0
        failed_count = 0

        for index, item in enumerate(notifications):
            if not isinstance(item, Mapping):
                failed_count += 1
                results.append(
                    self._error_result(
                        message=f"Notification item {index} is not a dictionary.",
                        error="invalid_notification_item",
                        metadata={"index": index},
                    )
                )
                continue

            item_data = dict(item)
            item_data.setdefault("user_id", default_user_id)
            item_data.setdefault("workspace_id", default_workspace_id)

            result = self.send_notification(
                user_id=str(item_data.get("user_id") or ""),
                workspace_id=str(item_data.get("workspace_id") or ""),
                channel=str(item_data.get("channel") or ""),
                title=str(item_data.get("title") or ""),
                message=str(item_data.get("message") or ""),
                recipients=item_data.get("recipients") or [],
                priority=str(item_data.get("priority") or NotificationPriority.NORMAL.value),
                template_id=item_data.get("template_id"),
                template_data=item_data.get("template_data") or {},
                action_url=item_data.get("action_url"),
                correlation_id=item_data.get("correlation_id"),
                workflow_id=item_data.get("workflow_id"),
                task_id=item_data.get("task_id"),
                event_type=item_data.get("event_type"),
                attachments=item_data.get("attachments") or [],
                metadata=item_data.get("metadata") or {},
                dry_run=dry_run,
                require_approval=require_approval,
            )

            results.append(result)
            if result.get("success"):
                success_count += 1
            else:
                failed_count += 1

        status = (
            NotificationStatus.SENT.value
            if failed_count == 0
            else NotificationStatus.PARTIAL.value
            if success_count > 0
            else NotificationStatus.FAILED.value
        )

        return self._safe_result(
            message=f"Bulk notifications processed: {success_count} succeeded, {failed_count} failed.",
            data={
                "status": status,
                "success_count": success_count,
                "failed_count": failed_count,
                "total": len(notifications),
                "results": results,
            },
            metadata={
                "agent": self.agent_name,
                "duration_ms": int((time.time() - started) * 1000),
            },
        )

    def send_workflow_alert(
        self,
        *,
        user_id: str,
        workspace_id: str,
        workflow_id: str,
        task_id: Optional[str],
        title: str,
        message: str,
        channels: Sequence[str],
        recipients_by_channel: Mapping[str, Any],
        priority: str = NotificationPriority.NORMAL.value,
        event_type: str = "workflow.alert",
        action_url: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        dry_run: Optional[bool] = None,
        require_approval: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Send one workflow alert to multiple channels.

        Example:
            send_workflow_alert(
                user_id="u1",
                workspace_id="w1",
                workflow_id="wf_123",
                task_id="task_456",
                title="Workflow failed",
                message="Step 3 failed.",
                channels=["dashboard", "email"],
                recipients_by_channel={
                    "dashboard": ["u1"],
                    "email": ["owner@example.com"],
                },
            )
        """
        notifications: List[Dict[str, Any]] = []
        for channel in channels:
            normalized = normalize_channel(channel)
            notifications.append(
                {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "channel": normalized,
                    "title": title,
                    "message": message,
                    "recipients": recipients_by_channel.get(normalized) or [],
                    "priority": priority,
                    "workflow_id": workflow_id,
                    "task_id": task_id,
                    "event_type": event_type,
                    "action_url": action_url,
                    "metadata": dict(metadata or {}),
                }
            )

        return self.send_bulk_notifications(
            notifications,
            default_user_id=user_id,
            default_workspace_id=workspace_id,
            dry_run=dry_run,
            require_approval=require_approval,
        )

    def send_dashboard_event(
        self,
        *,
        user_id: str,
        workspace_id: str,
        title: str,
        message: str,
        recipients: Union[str, Sequence[Union[str, Mapping[str, Any], NotificationRecipient]]],
        priority: str = NotificationPriority.NORMAL.value,
        workflow_id: Optional[str] = None,
        task_id: Optional[str] = None,
        event_type: str = "dashboard.notification",
        action_url: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        dry_run: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Convenience method for dashboard notifications."""
        return self.send_notification(
            user_id=user_id,
            workspace_id=workspace_id,
            channel=NotificationChannel.DASHBOARD.value,
            title=title,
            message=message,
            recipients=recipients,
            priority=priority,
            workflow_id=workflow_id,
            task_id=task_id,
            event_type=event_type,
            action_url=action_url,
            metadata=metadata or {},
            dry_run=dry_run,
            require_approval=False,
        )

    def send_mobile_event(
        self,
        *,
        user_id: str,
        workspace_id: str,
        title: str,
        message: str,
        recipients: Union[str, Sequence[Union[str, Mapping[str, Any], NotificationRecipient]]],
        priority: str = NotificationPriority.NORMAL.value,
        workflow_id: Optional[str] = None,
        task_id: Optional[str] = None,
        event_type: str = "mobile.notification",
        action_url: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        dry_run: Optional[bool] = None,
        require_approval: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Convenience method for mobile notifications."""
        return self.send_notification(
            user_id=user_id,
            workspace_id=workspace_id,
            channel=NotificationChannel.MOBILE.value,
            title=title,
            message=message,
            recipients=recipients,
            priority=priority,
            workflow_id=workflow_id,
            task_id=task_id,
            event_type=event_type,
            action_url=action_url,
            metadata=metadata or {},
            dry_run=dry_run,
            require_approval=require_approval,
        )

    # -------------------------------------------------------------------------
    # Context, Security, Verification, Memory, Events, Audit hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS context.

        This is the first isolation boundary. Every user-specific notification must
        include user_id and workspace_id.
        """
        if not user_id or not str(user_id).strip():
            return self._error_result(
                message="Missing user_id. Notification cannot be processed without SaaS user isolation.",
                error="missing_user_id",
                metadata={"task_id": task_id, "workflow_id": workflow_id},
            )

        if not workspace_id or not str(workspace_id).strip():
            return self._error_result(
                message="Missing workspace_id. Notification cannot be processed without workspace isolation.",
                error="missing_workspace_id",
                metadata={"task_id": task_id, "workflow_id": workflow_id},
            )

        if metadata:
            meta_user = metadata.get("user_id")
            meta_workspace = metadata.get("workspace_id")
            if meta_user and str(meta_user) != str(user_id):
                return self._error_result(
                    message="Context mismatch: metadata user_id does not match notification user_id.",
                    error="user_context_mismatch",
                    metadata={"task_id": task_id, "workflow_id": workflow_id},
                )
            if meta_workspace and str(meta_workspace) != str(workspace_id):
                return self._error_result(
                    message="Context mismatch: metadata workspace_id does not match notification workspace_id.",
                    error="workspace_context_mismatch",
                    metadata={"task_id": task_id, "workflow_id": workflow_id},
                )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "task_id": task_id,
                "workflow_id": workflow_id,
            },
            metadata={"agent": self.agent_name},
        )

    def _requires_security_check(
        self,
        payload: NotificationPayload,
        *,
        dry_run: bool,
        require_approval: Optional[bool] = None,
    ) -> bool:
        """
        Decide whether Security Agent approval is required.

        Real external sending usually requires approval.
        Critical/urgent messages may require approval because they can trigger
        customer-facing or incident-facing communications.
        """
        if dry_run:
            return False

        if require_approval is not None:
            return bool(require_approval)

        if payload.channel in EXTERNAL_CHANNELS and self.config.require_security_for_external:
            return True

        if (
            payload.priority in SENSITIVE_PRIORITY_LEVELS
            and self.config.require_security_for_sensitive_priority
        ):
            return True

        if payload.attachments:
            return True

        return False

    def _request_security_approval(self, payload: NotificationPayload) -> Dict[str, Any]:
        """
        Ask Security Agent/callback for approval.

        If no callback exists, this fails closed for real outbound notifications.
        """
        approval_request = {
            "agent": self.agent_name,
            "action": "send_notification",
            "risk_type": "outbound_message",
            "user_id": payload.user_id,
            "workspace_id": payload.workspace_id,
            "channel": payload.channel,
            "priority": payload.priority,
            "recipients": [r.safe_dict() for r in payload.recipients],
            "title": payload.title,
            "message_preview": truncate_text(payload.message, 300),
            "workflow_id": payload.workflow_id,
            "task_id": payload.task_id,
            "correlation_id": payload.correlation_id,
            "metadata": safe_metadata(payload.metadata),
            "created_at": utc_now_iso(),
        }

        self._emit_agent_event("notification.security_approval_requested", approval_request)

        if not self.security_approval_callback:
            return self._safe_result(
                message="Security approval is required but Security Agent callback is unavailable.",
                data={
                    "decision": SecurityDecision.UNAVAILABLE.value,
                    "status": NotificationStatus.REQUIRES_APPROVAL.value,
                    "approval_request": approval_request,
                },
                metadata={"agent": self.agent_name},
            )

        try:
            response = self.security_approval_callback(approval_request)
            decision = str(response.get("decision") or response.get("status") or "").lower()

            if decision in {"approved", "allow", "allowed", "ok"}:
                return self._safe_result(
                    message="Security approval granted.",
                    data={
                        "decision": SecurityDecision.APPROVED.value,
                        "status": "approved",
                        "approval_response": safe_metadata(response),
                    },
                    metadata={"agent": self.agent_name},
                )

            if decision in {"denied", "deny", "blocked", "rejected"}:
                return self._error_result(
                    message="Security approval denied.",
                    error="security_denied",
                    data={
                        "decision": SecurityDecision.DENIED.value,
                        "approval_response": safe_metadata(response),
                    },
                    metadata={"agent": self.agent_name},
                )

            return self._safe_result(
                message="Security approval did not return an approval decision.",
                data={
                    "decision": SecurityDecision.UNAVAILABLE.value,
                    "status": NotificationStatus.REQUIRES_APPROVAL.value,
                    "approval_response": safe_metadata(response),
                },
                metadata={"agent": self.agent_name},
            )

        except Exception as exc:
            return self._error_result(
                message="Security approval request failed.",
                error=exc,
                metadata={"agent": self.agent_name},
            )

    def _prepare_verification_payload(
        self,
        *,
        payload: NotificationPayload,
        delivery_result: Mapping[str, Any],
        duration_ms: int,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can later validate delivery, audit state, webhook response,
        dashboard event creation, or provider message ids.
        """
        delivery_data = delivery_result.get("data", {}) if isinstance(delivery_result, Mapping) else {}

        return {
            "verification_type": "notification_delivery",
            "agent": self.agent_name,
            "user_id": payload.user_id,
            "workspace_id": payload.workspace_id,
            "workflow_id": payload.workflow_id,
            "task_id": payload.task_id,
            "correlation_id": payload.correlation_id,
            "channel": payload.channel,
            "status": delivery_data.get("status"),
            "provider_message_id": delivery_data.get("provider_message_id"),
            "provider_status_code": delivery_data.get("provider_status_code"),
            "recipient_count": len(payload.recipients),
            "priority": payload.priority,
            "duration_ms": duration_ms,
            "safe_payload_hash": stable_hash(json.dumps(payload.safe_dict(), sort_keys=True)),
            "created_at": utc_now_iso(),
            "metadata": {
                "title": payload.title,
                "event_type": payload.event_type,
                "delivery_message": delivery_result.get("message"),
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        payload: NotificationPayload,
        delivery_result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This is a summary only. It avoids storing private recipient details or secrets.
        """
        delivery_data = delivery_result.get("data", {}) if isinstance(delivery_result, Mapping) else {}

        return {
            "memory_type": "workflow_notification",
            "agent": self.agent_name,
            "user_id": payload.user_id,
            "workspace_id": payload.workspace_id,
            "workflow_id": payload.workflow_id,
            "task_id": payload.task_id,
            "correlation_id": payload.correlation_id,
            "summary": f"{payload.channel} notification '{payload.title}' processed with status {delivery_data.get('status')}.",
            "data": {
                "channel": payload.channel,
                "priority": payload.priority,
                "event_type": payload.event_type,
                "recipient_count": len(payload.recipients),
                "status": delivery_data.get("status"),
                "title": payload.title,
                "message_preview": truncate_text(payload.message, 300),
            },
            "created_at": utc_now_iso(),
        }

    def _emit_agent_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Emit event for Master Agent, Agent Registry, Dashboard, or event bus.

        This method is safe even when no event bus exists yet.
        """
        safe_payload = safe_metadata(payload)
        try:
            if self.event_callback:
                self.event_callback(event_name, safe_payload)
            elif hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name, safe_payload)  # type: ignore[misc]
                except Exception:
                    self.logger.debug("BaseAgent emit_event failed.", exc_info=True)
            else:
                self.logger.debug("Agent event: %s %s", event_name, safe_payload)
        except Exception:
            self.logger.warning("Failed to emit agent event: %s", event_name, exc_info=True)

    def _log_audit_event(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        data: Optional[Mapping[str, Any]] = None,
        correlation_id: Optional[str] = None,
    ) -> None:
        """
        Write an audit event.

        Audit events must always include user_id/workspace_id for SaaS isolation.
        """
        event = {
            "audit_id": f"audit_{uuid.uuid4().hex}",
            "agent": self.agent_name,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "correlation_id": correlation_id,
            "data": safe_metadata(dict(data or {})),
            "created_at": utc_now_iso(),
        }

        try:
            if self.audit_callback:
                self.audit_callback(event)
            else:
                self.logger.info("AUDIT %s", json.dumps(event, default=str))
        except Exception:
            self.logger.warning("Audit logging failed for action=%s", action, exc_info=True)

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success result."""
        return {
            "success": True,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": {
                "timestamp": utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Union[str, Exception],
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error result."""
        if isinstance(error, Exception):
            error_payload: Union[str, Dict[str, Any]] = {
                "type": error.__class__.__name__,
                "message": str(error),
            }
            self.logger.debug("Exception detail: %s", traceback.format_exc())
        else:
            error_payload = str(error)

        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": error_payload,
            "metadata": {
                "timestamp": utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    # -------------------------------------------------------------------------
    # Internal build/validation/security
    # -------------------------------------------------------------------------

    def _build_payload(
        self,
        *,
        user_id: str,
        workspace_id: str,
        channel: str,
        title: str,
        message: str,
        recipients: Union[
            str,
            NotificationRecipient,
            Mapping[str, Any],
            Sequence[Union[str, NotificationRecipient, Mapping[str, Any]]],
        ],
        priority: str = NotificationPriority.NORMAL.value,
        template_id: Optional[str] = None,
        template_data: Optional[Mapping[str, Any]] = None,
        action_url: Optional[str] = None,
        correlation_id: Optional[str] = None,
        workflow_id: Optional[str] = None,
        task_id: Optional[str] = None,
        event_type: Optional[str] = None,
        attachments: Optional[Sequence[Mapping[str, Any]]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> NotificationPayload:
        """Build a normalized notification payload."""
        normalized_recipients = normalize_recipients(recipients)
        return NotificationPayload(
            user_id=str(user_id or "").strip(),
            workspace_id=str(workspace_id or "").strip(),
            channel=normalize_channel(channel),
            title=str(title or "").strip(),
            message=str(message or "").strip(),
            recipients=normalized_recipients,
            priority=normalize_priority(priority),
            template_id=template_id,
            template_data=dict(template_data or {}),
            action_url=action_url,
            correlation_id=correlation_id or self._new_correlation_id(),
            workflow_id=workflow_id,
            task_id=task_id,
            event_type=event_type,
            attachments=tuple(dict(item) for item in (attachments or [])),
            metadata=dict(metadata or {}),
        )

    def _validate_payload(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Validate payload after context normalization."""
        allowed_channels = set(self.config.allowed_channels or DEFAULT_ALLOWED_CHANNELS)
        supported_channels = {channel.value for channel in NotificationChannel}

        if payload.channel not in supported_channels:
            return self._error_result(
                message=f"Unsupported notification channel: {payload.channel}",
                error="unsupported_channel",
                data={"supported_channels": sorted(supported_channels)},
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        if payload.channel not in allowed_channels:
            return self._error_result(
                message=f"Notification channel is disabled by configuration: {payload.channel}",
                error="channel_disabled",
                data={"allowed_channels": sorted(allowed_channels)},
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        if not payload.title:
            return self._error_result(
                message="Notification title is required.",
                error="missing_title",
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        if not payload.message:
            return self._error_result(
                message="Notification message is required.",
                error="missing_message",
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        if len(payload.title) > MAX_TITLE_LENGTH:
            return self._error_result(
                message=f"Notification title is too long. Max length is {MAX_TITLE_LENGTH}.",
                error="title_too_long",
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        if len(payload.message) > MAX_MESSAGE_LENGTH:
            return self._error_result(
                message=f"Notification message is too long. Max length is {MAX_MESSAGE_LENGTH}.",
                error="message_too_long",
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        if not payload.recipients:
            return self._error_result(
                message="At least one recipient is required.",
                error="missing_recipients",
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        if len(payload.recipients) > self.config.max_recipients_per_call:
            return self._error_result(
                message=f"Too many recipients. Max allowed is {self.config.max_recipients_per_call}.",
                error="too_many_recipients",
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        if payload.channel == NotificationChannel.EMAIL.value:
            invalid = [r.address for r in payload.recipients if not validate_email_address(r.address)]
            if invalid:
                return self._error_result(
                    message="One or more email recipients are invalid.",
                    error="invalid_email_recipient",
                    data={"invalid_recipients": [mask_contact(item) for item in invalid]},
                    metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
                )

        return self._safe_result(
            message="Notification payload validation passed.",
            data={"payload": payload.safe_dict()},
            metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
        )

    def _handle_security(
        self,
        *,
        payload: NotificationPayload,
        dry_run: bool,
        require_approval: Optional[bool],
    ) -> Dict[str, Any]:
        """Run security decision path."""
        if not self._requires_security_check(
            payload,
            dry_run=dry_run,
            require_approval=require_approval,
        ):
            return self._safe_result(
                message="Security approval not required.",
                data={
                    "decision": SecurityDecision.NOT_REQUIRED.value,
                    "status": "not_required",
                },
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        approval = self._request_security_approval(payload)

        if approval.get("success") and approval.get("data", {}).get("decision") == SecurityDecision.APPROVED.value:
            return approval

        if approval.get("success") and approval.get("data", {}).get("status") == NotificationStatus.REQUIRES_APPROVAL.value:
            self._log_audit_event(
                action="notification.requires_security_approval",
                user_id=payload.user_id,
                workspace_id=payload.workspace_id,
                data={
                    "payload": payload.safe_dict(),
                    "security": approval.get("data", {}),
                },
                correlation_id=payload.correlation_id,
            )
            return approval

        return approval

    # -------------------------------------------------------------------------
    # Dispatch
    # -------------------------------------------------------------------------

    def _dispatch(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Dispatch payload by channel."""
        dispatch_map = {
            NotificationChannel.EMAIL.value: self._send_email,
            NotificationChannel.WHATSAPP.value: self._send_whatsapp,
            NotificationChannel.SLACK.value: self._send_slack,
            NotificationChannel.DISCORD.value: self._send_discord,
            NotificationChannel.MOBILE.value: self._send_mobile,
            NotificationChannel.DASHBOARD.value: self._send_dashboard,
        }

        handler = dispatch_map.get(payload.channel)
        if not handler:
            return self._error_result(
                message=f"No handler registered for channel: {payload.channel}",
                error="handler_missing",
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        return handler(payload)

    def _dry_run_delivery(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Return a realistic delivery result without sending."""
        provider_message_id = f"dry_{payload.channel}_{uuid.uuid4().hex[:16]}"
        return self._safe_result(
            message=f"Dry run completed for {payload.channel} notification.",
            data={
                "status": NotificationStatus.DRY_RUN.value,
                "channel": payload.channel,
                "provider_message_id": provider_message_id,
                "provider_status_code": None,
                "recipients": [r.safe_dict() for r in payload.recipients],
                "payload": payload.safe_dict(),
            },
            metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
        )

    # -------------------------------------------------------------------------
    # Channel handlers
    # -------------------------------------------------------------------------

    def _send_email(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Send email through configured SMTP."""
        if not self.config.smtp_host:
            return self._error_result(
                message="SMTP host is not configured.",
                error="smtp_not_configured",
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        if not self.config.smtp_from_email:
            return self._error_result(
                message="SMTP from email is not configured.",
                error="smtp_from_email_missing",
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        try:
            msg = EmailMessage()
            from_header = email.utils.formataddr(
                (self.config.smtp_from_name or "William AI", self.config.smtp_from_email)
            )
            msg["From"] = from_header
            msg["To"] = ", ".join(r.address for r in payload.recipients)
            msg["Subject"] = payload.title
            msg["X-William-Correlation-ID"] = payload.correlation_id or ""
            msg["X-William-Workspace-ID"] = payload.workspace_id
            msg["X-William-User-ID"] = payload.user_id

            body = payload.message
            if payload.action_url:
                body = f"{body}\n\nAction: {payload.action_url}"

            msg.set_content(body)

            for attachment in payload.attachments:
                self._attach_email_file(msg, attachment)

            if self.config.smtp_use_tls:
                context = ssl.create_default_context()
                with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=30) as server:
                    server.starttls(context=context)
                    if self.config.smtp_username and self.config.smtp_password:
                        server.login(self.config.smtp_username, self.config.smtp_password)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(self.config.smtp_host, self.config.smtp_port, timeout=30) as server:
                    if self.config.smtp_username and self.config.smtp_password:
                        server.login(self.config.smtp_username, self.config.smtp_password)
                    server.send_message(msg)

            return self._safe_result(
                message="Email notification sent.",
                data={
                    "status": NotificationStatus.SENT.value,
                    "channel": payload.channel,
                    "provider_message_id": f"email_{stable_hash((payload.correlation_id or '') + payload.title)}",
                    "provider_status_code": 250,
                    "recipients": [r.safe_dict() for r in payload.recipients],
                },
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        except Exception as exc:
            return self._error_result(
                message="Email notification failed.",
                error=exc,
                data={"status": NotificationStatus.FAILED.value, "channel": payload.channel},
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

    def _send_whatsapp(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Send WhatsApp notification through configured webhook/provider endpoint."""
        if not self.config.whatsapp_webhook_url:
            return self._error_result(
                message="WhatsApp webhook URL is not configured.",
                error="whatsapp_not_configured",
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        body = {
            "user_id": payload.user_id,
            "workspace_id": payload.workspace_id,
            "correlation_id": payload.correlation_id,
            "recipients": [r.address for r in payload.recipients],
            "title": payload.title,
            "message": payload.message,
            "priority": payload.priority,
            "template_id": payload.template_id,
            "template_data": payload.template_data,
            "action_url": payload.action_url,
            "metadata": safe_metadata(payload.metadata),
        }

        headers = {"Content-Type": "application/json"}
        if self.config.whatsapp_auth_header:
            headers["Authorization"] = self.config.whatsapp_auth_header

        return self._post_json_provider(
            url=self.config.whatsapp_webhook_url,
            body=body,
            headers=headers,
            channel=payload.channel,
            correlation_id=payload.correlation_id,
            success_message="WhatsApp notification sent.",
            failure_message="WhatsApp notification failed.",
        )

    def _send_slack(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Send Slack notification through webhook."""
        webhook_url = self._resolve_webhook_url(
            payload=payload,
            metadata_key="slack_webhook_url",
            config_value=self.config.slack_webhook_url,
        )
        if not webhook_url:
            return self._error_result(
                message="Slack webhook URL is not configured.",
                error="slack_not_configured",
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        body = {
            "text": f"*{payload.title}*\n{payload.message}",
            "metadata": {
                "event_type": payload.event_type or "workflow.notification",
                "event_payload": {
                    "user_id": payload.user_id,
                    "workspace_id": payload.workspace_id,
                    "workflow_id": payload.workflow_id,
                    "task_id": payload.task_id,
                    "correlation_id": payload.correlation_id,
                    "priority": payload.priority,
                },
            },
        }

        if payload.action_url:
            body["text"] += f"\n<{payload.action_url}|Open action>"

        return self._post_json_provider(
            url=webhook_url,
            body=body,
            headers={"Content-Type": "application/json"},
            channel=payload.channel,
            correlation_id=payload.correlation_id,
            success_message="Slack notification sent.",
            failure_message="Slack notification failed.",
        )

    def _send_discord(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Send Discord notification through webhook."""
        webhook_url = self._resolve_webhook_url(
            payload=payload,
            metadata_key="discord_webhook_url",
            config_value=self.config.discord_webhook_url,
        )
        if not webhook_url:
            return self._error_result(
                message="Discord webhook URL is not configured.",
                error="discord_not_configured",
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        embed = {
            "title": payload.title,
            "description": payload.message,
            "fields": [
                {"name": "Priority", "value": payload.priority, "inline": True},
                {"name": "Workspace", "value": payload.workspace_id, "inline": True},
            ],
            "timestamp": utc_now_iso(),
        }

        if payload.action_url:
            embed["url"] = payload.action_url

        body = {
            "content": None,
            "embeds": [embed],
            "username": "William AI",
        }

        return self._post_json_provider(
            url=webhook_url,
            body=body,
            headers={"Content-Type": "application/json"},
            channel=payload.channel,
            correlation_id=payload.correlation_id,
            success_message="Discord notification sent.",
            failure_message="Discord notification failed.",
        )

    def _send_mobile(self, payload: NotificationPayload) -> Dict[str, Any]:
        """
        Create a mobile notification event.

        This is provider-neutral. A future mobile push service can consume these
        events and route them to APNs/FCM.
        """
        if not self.config.mobile_events_enabled:
            return self._error_result(
                message="Mobile events are disabled.",
                error="mobile_events_disabled",
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        event = self._build_internal_event(payload=payload, target="mobile")
        self._mobile_event_store.append(event)

        return self._safe_result(
            message="Mobile notification event created.",
            data={
                "status": NotificationStatus.QUEUED.value,
                "channel": payload.channel,
                "provider_message_id": event["event_id"],
                "provider_status_code": None,
                "event": event,
                "recipients": [r.safe_dict() for r in payload.recipients],
            },
            metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
        )

    def _send_dashboard(self, payload: NotificationPayload) -> Dict[str, Any]:
        """
        Create dashboard notification event.

        Dashboard/API layer can consume this from callback/event bus or replace
        _dashboard_event_store with persistent storage later.
        """
        if not self.config.dashboard_events_enabled:
            return self._error_result(
                message="Dashboard events are disabled.",
                error="dashboard_events_disabled",
                metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
            )

        event = self._build_internal_event(payload=payload, target="dashboard")
        self._dashboard_event_store.append(event)

        return self._safe_result(
            message="Dashboard notification event created.",
            data={
                "status": NotificationStatus.QUEUED.value,
                "channel": payload.channel,
                "provider_message_id": event["event_id"],
                "provider_status_code": None,
                "event": event,
                "recipients": [r.safe_dict() for r in payload.recipients],
            },
            metadata={"agent": self.agent_name, "correlation_id": payload.correlation_id},
        )

    # -------------------------------------------------------------------------
    # Provider helpers
    # -------------------------------------------------------------------------

    def _post_json_provider(
        self,
        *,
        url: str,
        body: Mapping[str, Any],
        headers: Mapping[str, str],
        channel: str,
        correlation_id: Optional[str],
        success_message: str,
        failure_message: str,
    ) -> Dict[str, Any]:
        """POST JSON to an external provider using stdlib urllib."""
        try:
            encoded = json.dumps(body, default=str).encode("utf-8")
            request = Request(
                url=url,
                data=encoded,
                headers=dict(headers),
                method="POST",
            )

            with urlopen(request, timeout=self.config.http_timeout_seconds) as response:
                response_body = response.read().decode("utf-8", errors="replace")
                status_code = getattr(response, "status", 200)

            provider_message_id = self._extract_provider_message_id(response_body, correlation_id)

            if 200 <= int(status_code) < 300:
                return self._safe_result(
                    message=success_message,
                    data={
                        "status": NotificationStatus.SENT.value,
                        "channel": channel,
                        "provider_message_id": provider_message_id,
                        "provider_status_code": status_code,
                        "provider_response_preview": truncate_text(response_body, 500),
                    },
                    metadata={"agent": self.agent_name, "correlation_id": correlation_id},
                )

            return self._error_result(
                message=failure_message,
                error="provider_non_success_status",
                data={
                    "status": NotificationStatus.FAILED.value,
                    "channel": channel,
                    "provider_status_code": status_code,
                    "provider_response_preview": truncate_text(response_body, 500),
                },
                metadata={"agent": self.agent_name, "correlation_id": correlation_id},
            )

        except HTTPError as exc:
            response_text = ""
            try:
                response_text = exc.read().decode("utf-8", errors="replace")
            except Exception:
                response_text = str(exc)

            return self._error_result(
                message=failure_message,
                error={
                    "type": "HTTPError",
                    "status_code": exc.code,
                    "reason": exc.reason,
                    "response_preview": truncate_text(response_text, 500),
                },
                data={"status": NotificationStatus.FAILED.value, "channel": channel},
                metadata={"agent": self.agent_name, "correlation_id": correlation_id},
            )

        except URLError as exc:
            return self._error_result(
                message=failure_message,
                error={"type": "URLError", "reason": str(exc.reason)},
                data={"status": NotificationStatus.FAILED.value, "channel": channel},
                metadata={"agent": self.agent_name, "correlation_id": correlation_id},
            )

        except Exception as exc:
            return self._error_result(
                message=failure_message,
                error=exc,
                data={"status": NotificationStatus.FAILED.value, "channel": channel},
                metadata={"agent": self.agent_name, "correlation_id": correlation_id},
            )

    def _attach_email_file(self, msg: EmailMessage, attachment: Mapping[str, Any]) -> None:
        """
        Attach a file to an email message.

        Supported attachment shapes:
            {
                "filename": "report.txt",
                "content": "plain text",
                "mime_type": "text/plain"
            }

            {
                "filename": "report.pdf",
                "content_base64": "...",
                "mime_type": "application/pdf"
            }
        """
        filename = str(attachment.get("filename") or f"attachment_{uuid.uuid4().hex}")
        mime_type = str(attachment.get("mime_type") or "application/octet-stream")

        maintype, _, subtype = mime_type.partition("/")
        if not maintype or not subtype:
            maintype, subtype = "application", "octet-stream"

        if "content_base64" in attachment:
            raw_content = base64.b64decode(str(attachment["content_base64"]))
        elif "content" in attachment:
            content = attachment["content"]
            raw_content = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        else:
            raw_content = b""

        msg.add_attachment(
            raw_content,
            maintype=maintype,
            subtype=subtype,
            filename=filename,
        )

    def _resolve_webhook_url(
        self,
        *,
        payload: NotificationPayload,
        metadata_key: str,
        config_value: Optional[str],
    ) -> Optional[str]:
        """
        Resolve channel webhook from payload metadata first, then config.

        This supports per-workspace routing without hardcoding secrets.
        """
        metadata_value = payload.metadata.get(metadata_key)
        if metadata_value:
            return str(metadata_value)
        return config_value

    def _extract_provider_message_id(
        self,
        response_body: str,
        correlation_id: Optional[str],
    ) -> str:
        """Extract provider message id from JSON response when available."""
        try:
            parsed = json.loads(response_body) if response_body else {}
            for key in ("message_id", "id", "sid", "uuid", "event_id"):
                if key in parsed and parsed[key]:
                    return str(parsed[key])
        except Exception:
            pass
        return f"provider_{stable_hash((response_body or '') + (correlation_id or uuid.uuid4().hex))}"

    def _build_internal_event(self, *, payload: NotificationPayload, target: str) -> Dict[str, Any]:
        """Build dashboard/mobile internal event."""
        event = {
            "event_id": f"{target}_{uuid.uuid4().hex}",
            "target": target,
            "agent": self.agent_name,
            "user_id": payload.user_id,
            "workspace_id": payload.workspace_id,
            "workflow_id": payload.workflow_id,
            "task_id": payload.task_id,
            "correlation_id": payload.correlation_id,
            "event_type": payload.event_type or f"{target}.notification",
            "priority": payload.priority,
            "title": payload.title,
            "message": payload.message,
            "action_url": payload.action_url,
            "recipients": [r.safe_dict() for r in payload.recipients],
            "metadata": safe_metadata(payload.metadata),
            "created_at": utc_now_iso(),
            "read": False,
            "delivered": False,
        }

        if self.config.internal_event_signing_secret:
            event["signature"] = sign_payload(event, self.config.internal_event_signing_secret)

        self._emit_agent_event(f"{target}.notification.created", event)
        return event

    def _send_optional_callback(
        self,
        callback: Optional[Callable[[Dict[str, Any]], Any]],
        payload: Dict[str, Any],
    ) -> None:
        """Safely send callback payload."""
        if not callback:
            return
        try:
            callback(payload)
        except Exception:
            self.logger.warning("Optional callback failed.", exc_info=True)

    def _new_correlation_id(self) -> str:
        """Create correlation id for traceability across Workflow/Master/Security/Verification."""
        return f"notif_{uuid.uuid4().hex}"


# =============================================================================
# Registry-friendly module exports
# =============================================================================

def create_notification_engine(
    config: Optional[NotificationEngineConfig] = None,
    **kwargs: Any,
) -> NotificationEngine:
    """Factory used by future Agent Loader / Agent Registry."""
    return NotificationEngine(config=config, **kwargs)


def get_agent_metadata() -> Dict[str, Any]:
    """Return module metadata for Agent Registry / Agent Loader."""
    return {
        "agent_name": NotificationEngine.agent_name,
        "agent_type": NotificationEngine.agent_type,
        "class_name": "NotificationEngine",
        "module": "agents.workflow_agent.notification_engine",
        "public_methods": list(NotificationEngine.public_methods),
        "supported_channels": [channel.value for channel in NotificationChannel],
        "safe_to_import": True,
        "requires_user_id": True,
        "requires_workspace_id": True,
        "security_aware": True,
        "verification_ready": True,
        "memory_compatible": True,
        "dashboard_ready": True,
    }


__all__ = [
    "NotificationEngine",
    "NotificationEngineConfig",
    "NotificationPayload",
    "NotificationRecipient",
    "NotificationChannel",
    "NotificationPriority",
    "NotificationStatus",
    "SecurityDecision",
    "create_notification_engine",
    "get_agent_metadata",
]


# =============================================================================
# Lightweight manual test
# =============================================================================

if __name__ == "__main__":
    engine = NotificationEngine(
        config=NotificationEngineConfig(dry_run_default=True)
    )

    result = engine.send_notification(
        user_id="demo_user",
        workspace_id="demo_workspace",
        channel="dashboard",
        title="Workflow Alert",
        message="Your workflow notification engine is ready.",
        recipients=["demo_user"],
        priority="normal",
        workflow_id="wf_demo",
        task_id="task_demo",
        dry_run=True,
    )

    print(json.dumps(result, indent=2, default=str))