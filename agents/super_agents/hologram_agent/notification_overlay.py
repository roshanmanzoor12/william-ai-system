"""
agents/super_agents/hologram_agent/notification_overlay.py

Purpose:
    Shows safe notifications and hides private data in public mode.

Project:
    William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Architecture:
    This file belongs to the Hologram Agent module. It prepares notification overlay
    payloads for AR glasses, hologram UI, dashboard previews, or future device bridges.

Core Responsibilities:
    - Create safe notification overlay cards.
    - Hide/mask private data in public mode.
    - Queue, update, dismiss, and list notifications.
    - Enforce user_id/workspace_id SaaS isolation.
    - Route sensitive/private display actions through Security Agent.
    - Prepare Verification Agent payloads after completed display actions.
    - Prepare Memory Agent payloads for useful notification preferences/context.
    - Emit dashboard/API events and audit logs.
    - Remain import-safe even if future William/Jarvis modules are not created yet.

Safety:
    - Does not directly access AR hardware.
    - Does not expose private data in public mode.
    - Does not execute destructive actions.
    - Does not hardcode secrets.
    - Returns structured dict/JSON style results:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": dict | None,
            "metadata": dict
        }
"""

from __future__ import annotations

import asyncio
import copy
import hashlib
import inspect
import json
import logging
import re
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Deque, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ======================================================================================
# Safe optional imports
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe before the real William/Jarvis BaseAgent exists.
        The real BaseAgent should provide shared logging, lifecycle, routing,
        registry, and permission utilities.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "hologram")
            self.logger = logging.getLogger(self.agent_name)


try:
    from agents.super_agents.hologram_agent.ar_overlay import AROverlay  # type: ignore
except Exception:  # pragma: no cover
    AROverlay = None  # type: ignore

try:
    from agents.super_agents.hologram_agent.device_bridge import DeviceBridge  # type: ignore
except Exception:  # pragma: no cover
    DeviceBridge = None  # type: ignore


# ======================================================================================
# Logging
# ======================================================================================

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ======================================================================================
# Constants
# ======================================================================================

DEFAULT_AGENT_NAME = "NotificationOverlay"
DEFAULT_AGENT_MODULE = "hologram_agent"
DEFAULT_AGENT_VERSION = "1.0.0"

MAX_TITLE_LENGTH = 120
MAX_BODY_LENGTH = 1200
MAX_NOTIFICATION_QUEUE_SIZE = 250
MAX_ACTIONS_PER_NOTIFICATION = 5
MAX_METADATA_BYTES = 64_000

PRIVATE_REPLACEMENT = "••••"
PUBLIC_MODE_BODY = "Private notification hidden"
PUBLIC_MODE_TITLE = "Private Notification"

SENSITIVE_FIELD_HINTS = {
    "password",
    "pass",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "cookie",
    "session",
    "credit_card",
    "card_number",
    "cvv",
    "ssn",
    "social_security",
    "bank",
    "iban",
    "routing",
    "account_number",
    "otp",
    "pin",
    "private_key",
    "access_key",
    "refresh_token",
    "email",
    "phone",
    "address",
    "location",
    "contact",
    "message_body",
    "conversation",
}

EMAIL_PATTERN = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PHONE_PATTERN = re.compile(r"(?<!\d)(?:\+?\d[\d\s().-]{6,}\d)(?!\d)")
CARD_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]*?){13,19}(?!\d)")
URL_TOKEN_PATTERN = re.compile(r"(?i)(token|key|secret|auth|session)=([^&\s]+)")


# ======================================================================================
# Utility functions
# ======================================================================================

def _utc_now() -> str:
    """Return current UTC timestamp as ISO string."""

    return datetime.now(timezone.utc).isoformat()


def _duration_ms(start: float) -> int:
    """Return elapsed milliseconds."""

    return int((time.monotonic() - start) * 1000)


def _safe_json_size(value: Any) -> int:
    """Return approximate JSON byte size safely."""

    try:
        return len(json.dumps(value, default=str).encode("utf-8"))
    except Exception:
        return len(str(value).encode("utf-8"))


def _normalize_key(value: str) -> str:
    """Normalize user supplied keys into snake_case."""

    text = str(value or "").strip()
    text = re.sub(r"[\s\-]+", "_", text)
    text = re.sub(r"[^a-zA-Z0-9_]", "", text)
    text = re.sub(r"_+", "_", text)
    return text.lower().strip("_")


def _truncate(value: Any, limit: int = 700) -> Any:
    """Truncate long strings for audit/event safety."""

    if isinstance(value, str) and len(value) > limit:
        return value[: limit - 3] + "..."
    return value


def _hash_text(value: str) -> str:
    """Return stable SHA256 hash."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


async def _maybe_await(value: Union[Any, Awaitable[Any]]) -> Any:
    """Await value if it is awaitable."""

    if inspect.isawaitable(value):
        return await value
    return value


def _coerce_bool(value: Any, default: bool = False) -> bool:
    """Coerce common bool-like values."""

    if value is None:
        return default

    if isinstance(value, bool):
        return value

    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on", "enabled"}:
        return True
    if text in {"0", "false", "no", "n", "off", "disabled"}:
        return False

    return default


def _redact_string(value: str, replacement: str = PRIVATE_REPLACEMENT) -> str:
    """Redact sensitive patterns inside plain text."""

    text = str(value)

    text = EMAIL_PATTERN.sub(replacement, text)
    text = PHONE_PATTERN.sub(replacement, text)
    text = CARD_PATTERN.sub(replacement, text)
    text = URL_TOKEN_PATTERN.sub(lambda m: f"{m.group(1)}={replacement}", text)

    return text


def _is_sensitive_key(key: str) -> bool:
    """Check if a key name suggests private/sensitive data."""

    key_l = str(key or "").lower()
    return any(hint in key_l for hint in SENSITIVE_FIELD_HINTS)


def _redact_mapping(data: Mapping[str, Any], replacement: str = PRIVATE_REPLACEMENT) -> Dict[str, Any]:
    """Recursively redact sensitive mapping data."""

    redacted: Dict[str, Any] = {}

    for key, value in data.items():
        safe_key = str(key)

        if _is_sensitive_key(safe_key):
            redacted[safe_key] = replacement
            continue

        if isinstance(value, Mapping):
            redacted[safe_key] = _redact_mapping(value, replacement=replacement)
        elif isinstance(value, list):
            redacted[safe_key] = [
                _redact_mapping(item, replacement=replacement)
                if isinstance(item, Mapping)
                else _redact_string(str(item), replacement=replacement)
                if isinstance(item, str)
                else _truncate(item)
                for item in value[:100]
            ]
        elif isinstance(value, str):
            redacted[safe_key] = _truncate(_redact_string(value, replacement=replacement))
        else:
            redacted[safe_key] = _truncate(value)

    return redacted


# ======================================================================================
# Enums
# ======================================================================================

class OverlayMode(str, Enum):
    """Privacy mode for overlay rendering."""

    PRIVATE = "private"
    PUBLIC = "public"
    FOCUS = "focus"
    DO_NOT_DISTURB = "do_not_disturb"


class NotificationLevel(str, Enum):
    """Notification severity/importance."""

    INFO = "info"
    SUCCESS = "success"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class NotificationCategory(str, Enum):
    """Notification category."""

    SYSTEM = "system"
    SECURITY = "security"
    WORKFLOW = "workflow"
    MEMORY = "memory"
    FINANCE = "finance"
    CALL = "call"
    EMAIL = "email"
    CHAT = "chat"
    BROWSER = "browser"
    BUSINESS = "business"
    CREATOR = "creator"
    NAVIGATION = "navigation"
    HOLOGRAM = "hologram"
    GENERAL = "general"


class NotificationStatus(str, Enum):
    """Notification lifecycle status."""

    QUEUED = "queued"
    DISPLAYED = "displayed"
    DISMISSED = "dismissed"
    EXPIRED = "expired"
    BLOCKED = "blocked"
    FAILED = "failed"


class NotificationPosition(str, Enum):
    """Suggested AR/hologram screen position."""

    TOP_LEFT = "top_left"
    TOP_CENTER = "top_center"
    TOP_RIGHT = "top_right"
    CENTER = "center"
    BOTTOM_LEFT = "bottom_left"
    BOTTOM_CENTER = "bottom_center"
    BOTTOM_RIGHT = "bottom_right"


class NotificationActionType(str, Enum):
    """Safe action types for overlay buttons."""

    DISMISS = "dismiss"
    OPEN_DETAILS = "open_details"
    REPLY = "reply"
    ACCEPT = "accept"
    DECLINE = "decline"
    SNOOZE = "snooze"
    ROUTE_TO_AGENT = "route_to_agent"


# ======================================================================================
# Dataclasses
# ======================================================================================

@dataclass
class NotificationOverlayConfig:
    """
    Configuration for NotificationOverlay.

    No secrets are stored here. Device credentials and external action permissions
    must be handled through Security Agent and DeviceBridge/AppConnector.
    """

    default_mode: OverlayMode = OverlayMode.PRIVATE
    default_position: NotificationPosition = NotificationPosition.TOP_RIGHT
    default_duration_ms: int = 6000
    critical_duration_ms: int = 15000
    max_queue_size: int = MAX_NOTIFICATION_QUEUE_SIZE
    max_title_length: int = MAX_TITLE_LENGTH
    max_body_length: int = MAX_BODY_LENGTH
    max_metadata_bytes: int = MAX_METADATA_BYTES
    allow_sensitive_in_private_mode: bool = True
    hide_private_in_public_mode: bool = True
    public_mode_show_category_only: bool = True
    do_not_disturb_allows_critical: bool = True
    focus_mode_allows_warning_plus: bool = True
    enable_memory_payload: bool = True
    enable_verification_payload: bool = True
    enable_audit_logs: bool = True
    enable_agent_events: bool = True
    dry_run: bool = False

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["default_mode"] = self.default_mode.value
        data["default_position"] = self.default_position.value
        return data


@dataclass
class NotificationContext:
    """
    SaaS isolation context for notification tasks.

    user_id and workspace_id are mandatory for user/workspace-scoped execution.
    """

    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: Optional[str] = None
    actor_id: Optional[str] = None
    role: Optional[str] = None
    subscription_id: Optional[str] = None
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    agent_permissions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def isolation_key(self) -> str:
        raw = f"{self.user_id}:{self.workspace_id}"
        return _hash_text(raw)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NotificationAction:
    """Safe UI action shown on notification overlay."""

    action_id: str
    label: str
    action_type: NotificationActionType = NotificationActionType.DISMISS
    route: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    requires_security_check: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "label": self.label,
            "action_type": self.action_type.value,
            "route": self.route,
            "payload": _redact_mapping(self.payload),
            "requires_security_check": self.requires_security_check,
        }


@dataclass
class NotificationCard:
    """Internal notification card model."""

    notification_id: str
    user_id: str
    workspace_id: str
    title: str
    body: str
    category: NotificationCategory = NotificationCategory.GENERAL
    level: NotificationLevel = NotificationLevel.INFO
    status: NotificationStatus = NotificationStatus.QUEUED
    position: NotificationPosition = NotificationPosition.TOP_RIGHT
    mode: OverlayMode = OverlayMode.PRIVATE
    duration_ms: int = 6000
    is_private: bool = False
    contains_sensitive_data: bool = False
    source_agent: Optional[str] = None
    source_event: Optional[str] = None
    actions: List[NotificationAction] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    payload: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    expires_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def tenant_key(self) -> str:
        return f"{self.user_id}:{self.workspace_id}:{self.notification_id}"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["category"] = self.category.value
        data["level"] = self.level.value
        data["status"] = self.status.value
        data["position"] = self.position.value
        data["mode"] = self.mode.value
        data["actions"] = [action.to_dict() for action in self.actions]
        data["payload"] = _redact_mapping(self.payload)
        data["metadata"] = _redact_mapping(self.metadata)
        return data


@dataclass
class OverlayRenderResult:
    """Rendered overlay payload ready for dashboard/device bridge."""

    notification_id: str
    render_payload: Dict[str, Any]
    privacy_applied: bool
    blocked: bool = False
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ======================================================================================
# Fallback Device Bridge
# ======================================================================================

class _FallbackDeviceBridge:
    """
    Safe fallback device bridge.

    It does not touch real hardware. It returns simulated results so this file
    remains import-safe and testable.
    """

    bridge_name = "fallback_device_bridge"

    def __init__(self, dry_run: bool = True, logger_: Optional[logging.Logger] = None) -> None:
        self.dry_run = dry_run
        self.logger = logger_ or logger

    async def display_notification(self, **kwargs: Any) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "Notification display simulated by fallback device bridge.",
            "data": {
                "bridge": self.bridge_name,
                "dry_run": True,
                "received_keys": sorted(kwargs.keys()),
            },
            "error": None,
            "metadata": {"simulated": True, "timestamp": _utc_now()},
        }

    async def dismiss_notification(self, **kwargs: Any) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "Notification dismiss simulated by fallback device bridge.",
            "data": {
                "bridge": self.bridge_name,
                "dry_run": True,
                "received_keys": sorted(kwargs.keys()),
            },
            "error": None,
            "metadata": {"simulated": True, "timestamp": _utc_now()},
        }


# ======================================================================================
# NotificationOverlay
# ======================================================================================

class NotificationOverlay(BaseAgent):
    """
    Safe notification overlay manager for the William/Jarvis Hologram Agent.

    Master Agent:
        Can route tasks to this class through `run_task()`.

    Security Agent:
        Sensitive/private notification displays are checked through:
            - _requires_security_check()
            - _request_security_approval()

    Memory Agent:
        Useful user/workspace notification preferences and safety decisions are
        prepared through `_prepare_memory_payload()`.

    Verification Agent:
        Completed notification rendering actions prepare verification evidence
        through `_prepare_verification_payload()`.

    Dashboard/API:
        All public methods return structured dict/JSON responses suitable for
        FastAPI, dashboard cards, audit logs, and task history.

    Device Bridge:
        This class does not directly render to hardware. It can pass a safe
        render payload to a future DeviceBridge when available.
    """

    agent_name = DEFAULT_AGENT_NAME
    agent_module = DEFAULT_AGENT_MODULE
    agent_version = DEFAULT_AGENT_VERSION

    def __init__(
        self,
        config: Optional[Union[NotificationOverlayConfig, Mapping[str, Any]]] = None,
        *,
        device_bridge: Optional[Any] = None,
        ar_overlay: Optional[Any] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[..., Any]] = None,
        audit_logger: Optional[Callable[..., Any]] = None,
        logger_: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.agent_name, agent_type="hologram", **kwargs)

        self.logger = logger_ or getattr(self, "logger", logger) or logger

        if config is None:
            self.config = NotificationOverlayConfig()
        elif isinstance(config, NotificationOverlayConfig):
            self.config = config
        elif isinstance(config, Mapping):
            normalized_config = dict(config)
            if isinstance(normalized_config.get("default_mode"), str):
                normalized_config["default_mode"] = OverlayMode(normalized_config["default_mode"])
            if isinstance(normalized_config.get("default_position"), str):
                normalized_config["default_position"] = NotificationPosition(
                    normalized_config["default_position"]
                )
            self.config = NotificationOverlayConfig(**normalized_config)
        else:
            raise TypeError("config must be NotificationOverlayConfig, mapping, or None")

        self.device_bridge = device_bridge or self._build_optional_bridge(DeviceBridge, "device_bridge")
        self.ar_overlay = ar_overlay or self._build_optional_bridge(AROverlay, "ar_overlay")

        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger

        self._queue: Deque[NotificationCard] = deque(maxlen=self.config.max_queue_size)
        self._notifications: Dict[str, NotificationCard] = {}

    # ----------------------------------------------------------------------------------
    # Public Master Agent / Router interface
    # ----------------------------------------------------------------------------------

    async def run_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Master Agent compatible entrypoint.

        Supported actions:
            - show_notification
            - queue_notification
            - dismiss_notification
            - list_notifications
            - clear_notifications
            - preview_notification
            - set_overlay_mode
        """

        action = str(task.get("action") or "show_notification").strip()
        context = self._context_from_task(task)

        if action == "show_notification":
            return await self.show_notification(
                title=str(task.get("title") or task.get("payload", {}).get("title") or ""),
                body=str(task.get("body") or task.get("payload", {}).get("body") or ""),
                context=context,
                category=task.get("category") or task.get("payload", {}).get("category"),
                level=task.get("level") or task.get("payload", {}).get("level"),
                mode=task.get("mode") or task.get("payload", {}).get("mode"),
                position=task.get("position") or task.get("payload", {}).get("position"),
                is_private=task.get("is_private") or task.get("payload", {}).get("is_private"),
                payload=task.get("payload") if isinstance(task.get("payload"), Mapping) else {},
                actions=task.get("actions") or task.get("payload", {}).get("actions"),
                source_agent=task.get("source_agent"),
                source_event=task.get("source_event"),
                metadata=task.get("metadata") if isinstance(task.get("metadata"), Mapping) else {},
                display=True,
            )

        if action == "queue_notification":
            return await self.show_notification(
                title=str(task.get("title") or task.get("payload", {}).get("title") or ""),
                body=str(task.get("body") or task.get("payload", {}).get("body") or ""),
                context=context,
                category=task.get("category") or task.get("payload", {}).get("category"),
                level=task.get("level") or task.get("payload", {}).get("level"),
                mode=task.get("mode") or task.get("payload", {}).get("mode"),
                position=task.get("position") or task.get("payload", {}).get("position"),
                is_private=task.get("is_private") or task.get("payload", {}).get("is_private"),
                payload=task.get("payload") if isinstance(task.get("payload"), Mapping) else {},
                actions=task.get("actions") or task.get("payload", {}).get("actions"),
                source_agent=task.get("source_agent"),
                source_event=task.get("source_event"),
                metadata=task.get("metadata") if isinstance(task.get("metadata"), Mapping) else {},
                display=False,
            )

        if action == "dismiss_notification":
            return await self.dismiss_notification(
                notification_id=str(task.get("notification_id") or ""),
                context=context,
                reason=str(task.get("reason") or "dismissed_by_user"),
            )

        if action == "list_notifications":
            return self.list_notifications(
                context=context,
                status=task.get("status"),
                include_private=_coerce_bool(task.get("include_private"), default=False),
            )

        if action == "clear_notifications":
            return await self.clear_notifications(
                context=context,
                status=task.get("status"),
            )

        if action == "preview_notification":
            return self.preview_notification(
                title=str(task.get("title") or task.get("payload", {}).get("title") or ""),
                body=str(task.get("body") or task.get("payload", {}).get("body") or ""),
                context=context,
                category=task.get("category") or task.get("payload", {}).get("category"),
                level=task.get("level") or task.get("payload", {}).get("level"),
                mode=task.get("mode") or task.get("payload", {}).get("mode"),
                is_private=task.get("is_private") or task.get("payload", {}).get("is_private"),
                payload=task.get("payload") if isinstance(task.get("payload"), Mapping) else {},
            )

        if action == "set_overlay_mode":
            return await self.set_overlay_mode(
                context=context,
                mode=str(task.get("mode") or ""),
            )

        return self._error_result(
            message=f"Unsupported NotificationOverlay action: {action}",
            code="unsupported_action",
            metadata={"action": action},
        )

    async def show_notification(
        self,
        *,
        title: str,
        body: str,
        context: Union[NotificationContext, Mapping[str, Any]],
        category: Optional[Union[str, NotificationCategory]] = None,
        level: Optional[Union[str, NotificationLevel]] = None,
        mode: Optional[Union[str, OverlayMode]] = None,
        position: Optional[Union[str, NotificationPosition]] = None,
        is_private: Optional[bool] = None,
        payload: Optional[Mapping[str, Any]] = None,
        actions: Optional[Iterable[Union[NotificationAction, Mapping[str, Any]]]] = None,
        source_agent: Optional[str] = None,
        source_event: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        display: bool = True,
    ) -> Dict[str, Any]:
        """
        Create a safe notification overlay card and optionally display it.

        In public mode:
            - private notifications are replaced with generic safe text.
            - sensitive patterns are masked.
            - metadata/payload are redacted.
        """

        started = time.monotonic()

        try:
            ctx = self._ensure_context(context)
            context_result = self._validate_task_context(ctx)
            if not context_result["success"]:
                return context_result

            card = self._build_notification_card(
                title=title,
                body=body,
                context=ctx,
                category=category,
                level=level,
                mode=mode,
                position=position,
                is_private=is_private,
                payload=payload,
                actions=actions,
                source_agent=source_agent,
                source_event=source_event,
                metadata=metadata,
            )

            mode_value = card.mode

            if self._should_block_by_mode(card):
                card.status = NotificationStatus.BLOCKED
                card.updated_at = _utc_now()
                self._store_notification(card, enqueue=False)

                await self._log_audit_event(
                    event_type="notification_overlay.blocked_by_mode",
                    context=ctx,
                    payload=card.to_dict(),
                )

                return self._safe_result(
                    success=False,
                    message="Notification blocked by overlay mode.",
                    data={
                        "notification": card.to_dict(),
                        "mode": mode_value.value,
                    },
                    error={
                        "code": "blocked_by_overlay_mode",
                        "mode": mode_value.value,
                    },
                    metadata=self._base_metadata(ctx, started),
                )

            security_required = self._requires_security_check(
                action="display_private_notification" if card.is_private else "display_notification",
                payload=card.to_dict(),
            )

            if security_required:
                approval = await self._request_security_approval(
                    action="display_private_notification" if card.is_private else "display_notification",
                    context=ctx,
                    payload={
                        "notification_id": card.notification_id,
                        "title": card.title,
                        "category": card.category.value,
                        "level": card.level.value,
                        "mode": card.mode.value,
                        "is_private": card.is_private,
                        "contains_sensitive_data": card.contains_sensitive_data,
                    },
                )

                if not approval.get("approved", False):
                    card.status = NotificationStatus.BLOCKED
                    card.updated_at = _utc_now()
                    self._store_notification(card, enqueue=False)

                    return self._safe_result(
                        success=False,
                        message="Notification blocked by Security Agent.",
                        data={"notification": card.to_dict(), "security_approval": approval},
                        error={"code": "security_blocked", "details": approval},
                        metadata=self._base_metadata(ctx, started),
                    )

            render_result = self._render_notification_payload(card, mode=mode_value)

            if not display:
                self._store_notification(card, enqueue=True)

                await self._emit_agent_event(
                    event_type="notification_overlay.queued",
                    context=ctx,
                    payload={
                        "notification": card.to_dict(),
                        "render": render_result.to_dict(),
                    },
                )

                return self._safe_result(
                    success=True,
                    message="Notification queued successfully.",
                    data={
                        "notification": card.to_dict(),
                        "render": render_result.to_dict(),
                    },
                    metadata=self._base_metadata(ctx, started),
                )

            display_result = await self._display_render_payload(ctx, card, render_result)

            card.status = NotificationStatus.DISPLAYED if display_result.get("success") else NotificationStatus.FAILED
            card.updated_at = _utc_now()
            self._store_notification(card, enqueue=False)

            verification_payload = None
            if self.config.enable_verification_payload:
                verification_payload = self._prepare_verification_payload(
                    context=ctx,
                    notification=card,
                    render_result=render_result,
                    display_result=display_result,
                )

            memory_payload = None
            if self.config.enable_memory_payload:
                memory_payload = self._prepare_memory_payload(
                    context=ctx,
                    notification=card,
                    render_result=render_result,
                    display_result=display_result,
                )

            await self._emit_agent_event(
                event_type="notification_overlay.displayed" if display_result.get("success") else "notification_overlay.failed",
                context=ctx,
                payload={
                    "notification": card.to_dict(),
                    "render": render_result.to_dict(),
                    "display_result": display_result,
                },
            )

            await self._log_audit_event(
                event_type="notification_overlay.displayed" if display_result.get("success") else "notification_overlay.failed",
                context=ctx,
                payload={
                    "notification": card.to_dict(),
                    "render": render_result.to_dict(),
                    "display_result": display_result,
                },
            )

            return self._safe_result(
                success=bool(display_result.get("success")),
                message=display_result.get("message") or "Notification display completed.",
                data={
                    "notification": card.to_dict(),
                    "render": render_result.to_dict(),
                    "display_result": display_result,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                error=display_result.get("error"),
                metadata=self._base_metadata(ctx, started),
            )

        except Exception as exc:
            self.logger.exception("Failed to show notification overlay.")
            return self._error_result(
                message="Failed to show notification overlay.",
                code="notification_overlay_exception",
                exception=exc,
                metadata={"duration_ms": _duration_ms(started)},
            )

    def preview_notification(
        self,
        *,
        title: str,
        body: str,
        context: Union[NotificationContext, Mapping[str, Any]],
        category: Optional[Union[str, NotificationCategory]] = None,
        level: Optional[Union[str, NotificationLevel]] = None,
        mode: Optional[Union[str, OverlayMode]] = None,
        is_private: Optional[bool] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Preview a notification render payload without queueing or displaying it.
        """

        started = time.monotonic()

        try:
            ctx = self._ensure_context(context)
            context_result = self._validate_task_context(ctx)
            if not context_result["success"]:
                return context_result

            card = self._build_notification_card(
                title=title,
                body=body,
                context=ctx,
                category=category,
                level=level,
                mode=mode,
                is_private=is_private,
                payload=payload,
            )

            render_result = self._render_notification_payload(card, mode=card.mode)

            return self._safe_result(
                success=True,
                message="Notification preview generated successfully.",
                data={
                    "notification": card.to_dict(),
                    "render": render_result.to_dict(),
                    "privacy_applied": render_result.privacy_applied,
                },
                metadata=self._base_metadata(ctx, started),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to preview notification.",
                code="notification_preview_failed",
                exception=exc,
                metadata={"duration_ms": _duration_ms(started)},
            )

    async def dismiss_notification(
        self,
        *,
        notification_id: str,
        context: Union[NotificationContext, Mapping[str, Any]],
        reason: str = "dismissed",
    ) -> Dict[str, Any]:
        """Dismiss one notification scoped to user/workspace."""

        started = time.monotonic()

        try:
            ctx = self._ensure_context(context)
            context_result = self._validate_task_context(ctx)
            if not context_result["success"]:
                return context_result

            card = self._get_notification_for_context(notification_id, ctx)
            if card is None:
                return self._error_result(
                    message="Notification not found for this user/workspace.",
                    code="notification_not_found",
                    metadata=self._base_metadata(ctx, started),
                )

            card.status = NotificationStatus.DISMISSED
            card.updated_at = _utc_now()
            card.metadata["dismiss_reason"] = reason

            device_result = await self._dismiss_on_device(ctx, card, reason)

            await self._emit_agent_event(
                event_type="notification_overlay.dismissed",
                context=ctx,
                payload={"notification": card.to_dict(), "device_result": device_result},
            )

            await self._log_audit_event(
                event_type="notification_overlay.dismissed",
                context=ctx,
                payload={"notification": card.to_dict(), "device_result": device_result},
            )

            return self._safe_result(
                success=True,
                message="Notification dismissed successfully.",
                data={
                    "notification": card.to_dict(),
                    "device_result": device_result,
                },
                metadata=self._base_metadata(ctx, started),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to dismiss notification.",
                code="notification_dismiss_failed",
                exception=exc,
                metadata={"duration_ms": _duration_ms(started)},
            )

    def list_notifications(
        self,
        *,
        context: Union[NotificationContext, Mapping[str, Any]],
        status: Optional[Union[str, NotificationStatus]] = None,
        include_private: bool = False,
    ) -> Dict[str, Any]:
        """List notifications for a specific user/workspace only."""

        started = time.monotonic()

        try:
            ctx = self._ensure_context(context)
            context_result = self._validate_task_context(ctx)
            if not context_result["success"]:
                return context_result

            status_filter = self._coerce_status(status) if status else None
            rows: List[Dict[str, Any]] = []

            for card in self._notifications.values():
                if card.user_id != ctx.user_id or card.workspace_id != ctx.workspace_id:
                    continue

                if status_filter and card.status != status_filter:
                    continue

                safe_card = card.to_dict()
                if card.is_private and not include_private:
                    safe_card = self._render_notification_payload(card, mode=OverlayMode.PUBLIC).render_payload

                rows.append(safe_card)

            rows.sort(key=lambda item: str(item.get("created_at", "")), reverse=True)

            return self._safe_result(
                success=True,
                message="Notifications listed successfully.",
                data={
                    "notifications": rows,
                    "count": len(rows),
                    "include_private": include_private,
                    "status": status_filter.value if status_filter else None,
                },
                metadata=self._base_metadata(ctx, started),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to list notifications.",
                code="notification_list_failed",
                exception=exc,
                metadata={"duration_ms": _duration_ms(started)},
            )

    async def clear_notifications(
        self,
        *,
        context: Union[NotificationContext, Mapping[str, Any]],
        status: Optional[Union[str, NotificationStatus]] = None,
    ) -> Dict[str, Any]:
        """Clear notifications for a specific user/workspace only."""

        started = time.monotonic()

        try:
            ctx = self._ensure_context(context)
            context_result = self._validate_task_context(ctx)
            if not context_result["success"]:
                return context_result

            status_filter = self._coerce_status(status) if status else None
            removed_ids: List[str] = []

            for key, card in list(self._notifications.items()):
                if card.user_id != ctx.user_id or card.workspace_id != ctx.workspace_id:
                    continue

                if status_filter and card.status != status_filter:
                    continue

                removed_ids.append(card.notification_id)
                self._notifications.pop(key, None)

            self._queue = deque(
                [
                    item for item in self._queue
                    if not (
                        item.user_id == ctx.user_id
                        and item.workspace_id == ctx.workspace_id
                        and item.notification_id in removed_ids
                    )
                ],
                maxlen=self.config.max_queue_size,
            )

            await self._emit_agent_event(
                event_type="notification_overlay.cleared",
                context=ctx,
                payload={"removed_ids": removed_ids, "status": status_filter.value if status_filter else None},
            )

            await self._log_audit_event(
                event_type="notification_overlay.cleared",
                context=ctx,
                payload={"removed_ids": removed_ids, "status": status_filter.value if status_filter else None},
            )

            return self._safe_result(
                success=True,
                message="Notifications cleared successfully.",
                data={
                    "removed_ids": removed_ids,
                    "removed_count": len(removed_ids),
                },
                metadata=self._base_metadata(ctx, started),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to clear notifications.",
                code="notification_clear_failed",
                exception=exc,
                metadata={"duration_ms": _duration_ms(started)},
            )

    async def set_overlay_mode(
        self,
        *,
        context: Union[NotificationContext, Mapping[str, Any]],
        mode: Union[str, OverlayMode],
    ) -> Dict[str, Any]:
        """
        Set default overlay privacy mode for this instance.

        In production, long-term mode preferences should be stored by
        Hologram Memory / user settings, not only in this instance.
        """

        started = time.monotonic()

        try:
            ctx = self._ensure_context(context)
            context_result = self._validate_task_context(ctx)
            if not context_result["success"]:
                return context_result

            new_mode = self._coerce_mode(mode)

            approval = await self._request_security_approval(
                action="set_overlay_mode",
                context=ctx,
                payload={"new_mode": new_mode.value},
            )

            if not approval.get("approved", False):
                return self._safe_result(
                    success=False,
                    message="Overlay mode change blocked by Security Agent.",
                    data={"security_approval": approval},
                    error={"code": "security_blocked", "details": approval},
                    metadata=self._base_metadata(ctx, started),
                )

            old_mode = self.config.default_mode
            self.config.default_mode = new_mode

            await self._emit_agent_event(
                event_type="notification_overlay.mode_changed",
                context=ctx,
                payload={"old_mode": old_mode.value, "new_mode": new_mode.value},
            )

            await self._log_audit_event(
                event_type="notification_overlay.mode_changed",
                context=ctx,
                payload={"old_mode": old_mode.value, "new_mode": new_mode.value},
            )

            return self._safe_result(
                success=True,
                message="Overlay mode updated successfully.",
                data={
                    "old_mode": old_mode.value,
                    "new_mode": new_mode.value,
                    "memory_payload": {
                        "memory_type": "hologram_overlay_preference",
                        "scope": {
                            "user_id": ctx.user_id,
                            "workspace_id": ctx.workspace_id,
                            "isolation_key": ctx.isolation_key(),
                        },
                        "content": {"default_notification_overlay_mode": new_mode.value},
                        "created_at": _utc_now(),
                    },
                },
                metadata=self._base_metadata(ctx, started),
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to set overlay mode.",
                code="set_overlay_mode_failed",
                exception=exc,
                metadata={"duration_ms": _duration_ms(started)},
            )

    # ----------------------------------------------------------------------------------
    # Build, render, privacy
    # ----------------------------------------------------------------------------------

    def _build_notification_card(
        self,
        *,
        title: str,
        body: str,
        context: NotificationContext,
        category: Optional[Union[str, NotificationCategory]] = None,
        level: Optional[Union[str, NotificationLevel]] = None,
        mode: Optional[Union[str, OverlayMode]] = None,
        position: Optional[Union[str, NotificationPosition]] = None,
        is_private: Optional[bool] = None,
        payload: Optional[Mapping[str, Any]] = None,
        actions: Optional[Iterable[Union[NotificationAction, Mapping[str, Any]]]] = None,
        source_agent: Optional[str] = None,
        source_event: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> NotificationCard:
        """Build validated internal notification card."""

        clean_title = self._clean_text(title, max_length=self.config.max_title_length)
        clean_body = self._clean_text(body, max_length=self.config.max_body_length)

        if not clean_title:
            clean_title = "Notification"

        clean_payload = dict(payload or {})
        clean_metadata = dict(metadata or {})

        if _safe_json_size(clean_metadata) > self.config.max_metadata_bytes:
            clean_metadata = {"metadata_truncated": True}

        notification_category = self._coerce_category(category)
        notification_level = self._coerce_level(level)
        notification_mode = self._coerce_mode(mode or self.config.default_mode)
        notification_position = self._coerce_position(position or self.config.default_position)

        contains_sensitive = self._contains_sensitive_data(
            {
                "title": clean_title,
                "body": clean_body,
                "payload": clean_payload,
                "metadata": clean_metadata,
            }
        )

        private_flag = bool(is_private) or contains_sensitive

        duration_ms = (
            self.config.critical_duration_ms
            if notification_level == NotificationLevel.CRITICAL
            else self.config.default_duration_ms
        )

        parsed_actions = self._parse_actions(actions)

        card = NotificationCard(
            notification_id=str(uuid.uuid4()),
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            title=clean_title,
            body=clean_body,
            category=notification_category,
            level=notification_level,
            status=NotificationStatus.QUEUED,
            position=notification_position,
            mode=notification_mode,
            duration_ms=duration_ms,
            is_private=private_flag,
            contains_sensitive_data=contains_sensitive,
            source_agent=source_agent,
            source_event=source_event,
            actions=parsed_actions,
            tags=self._derive_tags(notification_category, notification_level, private_flag),
            payload=clean_payload,
            metadata={
                **clean_metadata,
                "request_id": context.request_id,
                "task_id": context.task_id,
                "device_id": context.device_id,
                "session_id": context.session_id,
                "isolation_key": context.isolation_key(),
            },
        )

        return card

    def _render_notification_payload(
        self,
        card: NotificationCard,
        *,
        mode: OverlayMode,
    ) -> OverlayRenderResult:
        """
        Render card into safe overlay payload.

        Public mode hides private content and redacts sensitive content.
        """

        privacy_applied = False

        if mode == OverlayMode.PUBLIC and self.config.hide_private_in_public_mode:
            if card.is_private or card.contains_sensitive_data:
                privacy_applied = True

                if self.config.public_mode_show_category_only:
                    safe_title = f"{card.category.value.title()} Notification"
                else:
                    safe_title = PUBLIC_MODE_TITLE

                render_payload = {
                    "notification_id": card.notification_id,
                    "title": safe_title,
                    "body": PUBLIC_MODE_BODY,
                    "category": card.category.value,
                    "level": card.level.value,
                    "status": card.status.value,
                    "position": card.position.value,
                    "mode": mode.value,
                    "duration_ms": card.duration_ms,
                    "is_private": True,
                    "privacy_applied": True,
                    "contains_sensitive_data": True,
                    "actions": [
                        action.to_dict()
                        for action in card.actions
                        if action.action_type in {NotificationActionType.DISMISS, NotificationActionType.OPEN_DETAILS}
                    ],
                    "payload": {},
                    "metadata": {
                        "created_at": card.created_at,
                        "updated_at": card.updated_at,
                        "source_agent": card.source_agent,
                        "hidden_reason": "public_mode",
                    },
                }

                return OverlayRenderResult(
                    notification_id=card.notification_id,
                    render_payload=render_payload,
                    privacy_applied=privacy_applied,
                )

        safe_title = card.title
        safe_body = card.body
        safe_payload = copy.deepcopy(card.payload)
        safe_metadata = copy.deepcopy(card.metadata)

        if mode == OverlayMode.PUBLIC:
            safe_title = _redact_string(safe_title)
            safe_body = _redact_string(safe_body)
            safe_payload = _redact_mapping(safe_payload)
            safe_metadata = _redact_mapping(safe_metadata)
            privacy_applied = card.contains_sensitive_data

        if mode == OverlayMode.FOCUS and card.level in {NotificationLevel.INFO, NotificationLevel.SUCCESS}:
            safe_body = _truncate(safe_body, 160)

        render_payload = {
            "notification_id": card.notification_id,
            "title": safe_title,
            "body": safe_body,
            "category": card.category.value,
            "level": card.level.value,
            "status": card.status.value,
            "position": card.position.value,
            "mode": mode.value,
            "duration_ms": card.duration_ms,
            "is_private": card.is_private,
            "privacy_applied": privacy_applied,
            "contains_sensitive_data": card.contains_sensitive_data,
            "source_agent": card.source_agent,
            "source_event": card.source_event,
            "actions": [action.to_dict() for action in card.actions],
            "tags": list(card.tags),
            "payload": safe_payload if mode != OverlayMode.PUBLIC else _redact_mapping(safe_payload),
            "metadata": safe_metadata if mode != OverlayMode.PUBLIC else _redact_mapping(safe_metadata),
            "created_at": card.created_at,
            "updated_at": card.updated_at,
            "expires_at": card.expires_at,
        }

        return OverlayRenderResult(
            notification_id=card.notification_id,
            render_payload=render_payload,
            privacy_applied=privacy_applied,
        )

    def _should_block_by_mode(self, card: NotificationCard) -> bool:
        """Decide if notification should be blocked by current overlay mode."""

        if card.mode == OverlayMode.DO_NOT_DISTURB:
            if self.config.do_not_disturb_allows_critical:
                return card.level != NotificationLevel.CRITICAL
            return True

        if card.mode == OverlayMode.FOCUS and self.config.focus_mode_allows_warning_plus:
            return card.level not in {
                NotificationLevel.WARNING,
                NotificationLevel.ERROR,
                NotificationLevel.CRITICAL,
            }

        return False

    def _contains_sensitive_data(self, value: Any) -> bool:
        """Detect sensitive text or sensitive keys in nested payload."""

        if isinstance(value, Mapping):
            for key, item in value.items():
                if _is_sensitive_key(str(key)):
                    return True
                if self._contains_sensitive_data(item):
                    return True
            return False

        if isinstance(value, list):
            return any(self._contains_sensitive_data(item) for item in value)

        if isinstance(value, str):
            if EMAIL_PATTERN.search(value):
                return True
            if PHONE_PATTERN.search(value):
                return True
            if CARD_PATTERN.search(value):
                return True
            if URL_TOKEN_PATTERN.search(value):
                return True

        return False

    def _clean_text(self, value: Any, *, max_length: int) -> str:
        """Clean text for AR overlay display."""

        text = str(value or "").strip()
        text = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", text)
        text = re.sub(r"\s+", " ", text)
        return text[:max_length]

    def _parse_actions(
        self,
        actions: Optional[Iterable[Union[NotificationAction, Mapping[str, Any]]]],
    ) -> List[NotificationAction]:
        """Parse safe action configs."""

        parsed: List[NotificationAction] = []

        if not actions:
            return [
                NotificationAction(
                    action_id=str(uuid.uuid4()),
                    label="Dismiss",
                    action_type=NotificationActionType.DISMISS,
                )
            ]

        for action in list(actions)[:MAX_ACTIONS_PER_NOTIFICATION]:
            if isinstance(action, NotificationAction):
                parsed.append(action)
                continue

            if not isinstance(action, Mapping):
                continue

            label = self._clean_text(action.get("label") or "Action", max_length=40)
            action_type = self._coerce_action_type(action.get("action_type") or action.get("type"))
            route = str(action.get("route")).strip() if action.get("route") else None
            payload = dict(action.get("payload") or {})

            parsed.append(
                NotificationAction(
                    action_id=str(action.get("action_id") or uuid.uuid4()),
                    label=label,
                    action_type=action_type,
                    route=route,
                    payload=payload,
                    requires_security_check=_coerce_bool(
                        action.get("requires_security_check"),
                        default=action_type not in {NotificationActionType.DISMISS, NotificationActionType.OPEN_DETAILS},
                    ),
                )
            )

        if not parsed:
            parsed.append(
                NotificationAction(
                    action_id=str(uuid.uuid4()),
                    label="Dismiss",
                    action_type=NotificationActionType.DISMISS,
                )
            )

        return parsed

    def _derive_tags(
        self,
        category: NotificationCategory,
        level: NotificationLevel,
        is_private: bool,
    ) -> List[str]:
        """Derive lightweight tags for filtering/dashboard."""

        tags = [category.value, level.value]

        if is_private:
            tags.append("private")

        if level in {NotificationLevel.ERROR, NotificationLevel.CRITICAL}:
            tags.append("needs_attention")

        return tags

    # ----------------------------------------------------------------------------------
    # Device bridge integration
    # ----------------------------------------------------------------------------------

    async def _display_render_payload(
        self,
        context: NotificationContext,
        card: NotificationCard,
        render_result: OverlayRenderResult,
    ) -> Dict[str, Any]:
        """Send safe render payload to AR overlay/device bridge if available."""

        if self.config.dry_run:
            return self._safe_result(
                success=True,
                message="Notification display simulated in dry-run mode.",
                data={
                    "notification_id": card.notification_id,
                    "dry_run": True,
                    "render_payload": render_result.render_payload,
                },
                metadata=self._connector_metadata(context, card),
            )

        bridge = self.device_bridge or self.ar_overlay

        if hasattr(bridge, "display_notification"):
            return await _maybe_await(
                bridge.display_notification(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    device_id=context.device_id,
                    notification_id=card.notification_id,
                    render_payload=render_result.render_payload,
                    metadata=self._connector_metadata(context, card),
                )
            )

        if hasattr(bridge, "show_overlay"):
            return await _maybe_await(
                bridge.show_overlay(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    overlay_type="notification",
                    payload=render_result.render_payload,
                    metadata=self._connector_metadata(context, card),
                )
            )

        return self._safe_result(
            success=False,
            message="No compatible device bridge display method available.",
            data={"notification_id": card.notification_id},
            error={"code": "unsupported_device_bridge"},
            metadata=self._connector_metadata(context, card),
        )

    async def _dismiss_on_device(
        self,
        context: NotificationContext,
        card: NotificationCard,
        reason: str,
    ) -> Dict[str, Any]:
        """Dismiss notification through device bridge if available."""

        bridge = self.device_bridge or self.ar_overlay

        if hasattr(bridge, "dismiss_notification"):
            return await _maybe_await(
                bridge.dismiss_notification(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    device_id=context.device_id,
                    notification_id=card.notification_id,
                    reason=reason,
                    metadata=self._connector_metadata(context, card),
                )
            )

        return self._safe_result(
            success=True,
            message="Notification dismissed locally. Device bridge dismiss not available.",
            data={
                "notification_id": card.notification_id,
                "local_only": True,
            },
            metadata=self._connector_metadata(context, card),
        )

    # ----------------------------------------------------------------------------------
    # Required compatibility hooks
    # ----------------------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[NotificationContext, Mapping[str, Any], None],
    ) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Required:
            - user_id
            - workspace_id
        """

        try:
            ctx = self._ensure_context(context)
        except Exception as exc:
            return self._error_result(
                message="Invalid task context.",
                code="invalid_task_context",
                exception=exc,
            )

        missing = []
        if not ctx.user_id or not str(ctx.user_id).strip():
            missing.append("user_id")
        if not ctx.workspace_id or not str(ctx.workspace_id).strip():
            missing.append("workspace_id")

        if missing:
            return self._error_result(
                message="Task context missing required SaaS isolation fields.",
                code="missing_context_fields",
                data={"missing_fields": missing},
                metadata={"required_fields": ["user_id", "workspace_id"]},
            )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "request_id": ctx.request_id,
                "device_id": ctx.device_id,
                "session_id": ctx.session_id,
                "isolation_key": ctx.isolation_key(),
            },
            metadata={"timestamp": _utc_now()},
        )

    def _requires_security_check(
        self,
        *,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide whether Security Agent approval is required.

        Private/sensitive overlays require approval because they may expose
        personal data in a real-world visual environment.
        """

        sensitive_actions = {
            "display_private_notification",
            "display_sensitive_notification",
            "set_overlay_mode",
            "route_notification_action",
        }

        if action in sensitive_actions:
            return True

        if payload:
            if bool(payload.get("is_private")) or bool(payload.get("contains_sensitive_data")):
                return True

            if self._contains_sensitive_data(payload):
                return True

            if _safe_json_size(payload) > self.config.max_metadata_bytes:
                return True

        return False

    async def _request_security_approval(
        self,
        *,
        action: str,
        context: NotificationContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent if available.

        If Security Agent is not attached, fallback local policy:
            - approve when user_id/workspace_id exist
            - approve public safe display
            - approve private display only if mode is not public or payload is redacted
        """

        if self.security_agent is not None:
            if hasattr(self.security_agent, "approve_action"):
                result = await _maybe_await(
                    self.security_agent.approve_action(
                        user_id=context.user_id,
                        workspace_id=context.workspace_id,
                        action=action,
                        payload=_redact_mapping(dict(payload)),
                        metadata={
                            "agent": self.agent_name,
                            "request_id": context.request_id,
                            "task_id": context.task_id,
                            "device_id": context.device_id,
                        },
                    )
                )
                return self._normalize_security_result(result)

            if hasattr(self.security_agent, "request_approval"):
                result = await _maybe_await(
                    self.security_agent.request_approval(
                        action=action,
                        context=context.to_dict(),
                        payload=_redact_mapping(dict(payload)),
                    )
                )
                return self._normalize_security_result(result)

        context_ok = bool(context.user_id and context.workspace_id)
        payload_ok = _safe_json_size(payload) <= self.config.max_metadata_bytes

        approved = context_ok and payload_ok

        return {
            "approved": approved,
            "message": "Approved by local fallback security policy."
            if approved
            else "Blocked by local fallback security policy.",
            "policy": "local_fallback",
            "action": action,
            "timestamp": _utc_now(),
        }

    def _prepare_verification_payload(
        self,
        *,
        context: NotificationContext,
        notification: NotificationCard,
        render_result: OverlayRenderResult,
        display_result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        This payload lets Verification Agent confirm that privacy rules were
        applied before public/hologram display.
        """

        return {
            "agent": self.agent_name,
            "agent_module": self.agent_module,
            "agent_version": self.agent_version,
            "verification_type": "notification_overlay_display",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "device_id": context.device_id,
            "notification_id": notification.notification_id,
            "status": notification.status.value,
            "checks": {
                "context_isolated": bool(context.user_id and context.workspace_id),
                "public_mode_privacy_applied": (
                    render_result.privacy_applied
                    if notification.mode == OverlayMode.PUBLIC
                    else True
                ),
                "private_data_detected": notification.contains_sensitive_data,
                "private_notification": notification.is_private,
                "security_checked": True,
                "display_success": bool(display_result.get("success")),
            },
            "evidence": {
                "category": notification.category.value,
                "level": notification.level.value,
                "mode": notification.mode.value,
                "render_payload": render_result.render_payload,
                "display_result": _redact_mapping(dict(display_result)),
            },
            "created_at": _utc_now(),
        }

    def _prepare_memory_payload(
        self,
        *,
        context: NotificationContext,
        notification: NotificationCard,
        render_result: OverlayRenderResult,
        display_result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Useful for learning safe overlay preferences without storing private body
        content unnecessarily.
        """

        return {
            "agent": self.agent_name,
            "memory_type": "hologram_notification_context",
            "scope": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "isolation_key": context.isolation_key(),
            },
            "notification_id": notification.notification_id,
            "content": {
                "category": notification.category.value,
                "level": notification.level.value,
                "mode": notification.mode.value,
                "position": notification.position.value,
                "is_private": notification.is_private,
                "contains_sensitive_data": notification.contains_sensitive_data,
                "privacy_applied": render_result.privacy_applied,
                "display_success": bool(display_result.get("success")),
                "source_agent": notification.source_agent,
                "source_event": notification.source_event,
            },
            "metadata": {
                "request_id": context.request_id,
                "task_id": context.task_id,
                "device_id": context.device_id,
                "created_at": _utc_now(),
            },
        }

    async def _emit_agent_event(
        self,
        *,
        event_type: str,
        context: NotificationContext,
        payload: Mapping[str, Any],
    ) -> None:
        """Emit dashboard/API event. Safe no-op if no emitter exists."""

        if not self.config.enable_agent_events:
            return

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "agent_module": self.agent_module,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "device_id": context.device_id,
            "payload": _redact_mapping(dict(payload)),
            "created_at": _utc_now(),
        }

        try:
            if self.event_emitter:
                await _maybe_await(self.event_emitter(event))
            else:
                self.logger.info("Agent event: %s", json.dumps(event, default=str))
        except Exception:
            self.logger.exception("Failed to emit agent event: %s", event_type)

    async def _log_audit_event(
        self,
        *,
        event_type: str,
        context: NotificationContext,
        payload: Mapping[str, Any],
    ) -> None:
        """Log SaaS-isolated audit event. Safe no-op if disabled."""

        if not self.config.enable_audit_logs:
            return

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "agent_module": self.agent_module,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "device_id": context.device_id,
            "payload": _redact_mapping(dict(payload)),
            "created_at": _utc_now(),
        }

        try:
            if self.audit_logger:
                await _maybe_await(self.audit_logger(audit_event))
            else:
                self.logger.info("Audit event: %s", json.dumps(audit_event, default=str))
        except Exception:
            self.logger.exception("Failed to log audit event: %s", event_type)

    def _safe_result(
        self,
        *,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis structured result."""

        return {
            "success": bool(success),
            "message": str(message),
            "data": dict(data or {}),
            "error": dict(error) if error else None,
            "metadata": {
                "agent": self.agent_name,
                "agent_module": self.agent_module,
                "agent_version": self.agent_version,
                "timestamp": _utc_now(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        code: str,
        exception: Optional[BaseException] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis structured error result."""

        error = {
            "code": code,
            "message": message,
        }

        if exception is not None:
            error["type"] = exception.__class__.__name__
            error["details"] = str(exception)

        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error,
            metadata=metadata or {},
        )

    # ----------------------------------------------------------------------------------
    # Internal storage/helpers
    # ----------------------------------------------------------------------------------

    def _store_notification(self, card: NotificationCard, *, enqueue: bool) -> None:
        """Store notification in SaaS-safe keyed dictionary."""

        self._notifications[card.tenant_key()] = card

        if enqueue:
            self._queue.append(card)

    def _get_notification_for_context(
        self,
        notification_id: str,
        context: NotificationContext,
    ) -> Optional[NotificationCard]:
        """Fetch notification only when it belongs to user/workspace."""

        key = f"{context.user_id}:{context.workspace_id}:{notification_id}"
        return self._notifications.get(key)

    def _build_optional_bridge(self, bridge_cls: Optional[Any], name: str) -> Any:
        """Build optional bridge or fallback."""

        if bridge_cls is None:
            return _FallbackDeviceBridge(dry_run=True, logger_=self.logger)

        try:
            try:
                return bridge_cls()
            except TypeError:
                return bridge_cls(config={}, logger_=self.logger)
        except Exception:
            self.logger.exception("Failed to initialize %s. Using fallback bridge.", name)
            return _FallbackDeviceBridge(dry_run=True, logger_=self.logger)

    def _ensure_context(
        self,
        context: Optional[Union[NotificationContext, Mapping[str, Any]]],
    ) -> NotificationContext:
        """Coerce mapping into NotificationContext."""

        if isinstance(context, NotificationContext):
            return context

        if context is None:
            return NotificationContext(user_id="", workspace_id="")

        if isinstance(context, Mapping):
            return NotificationContext(
                user_id=str(context.get("user_id") or ""),
                workspace_id=str(context.get("workspace_id") or ""),
                request_id=str(context.get("request_id") or uuid.uuid4()),
                task_id=str(context.get("task_id")) if context.get("task_id") else None,
                actor_id=str(context.get("actor_id")) if context.get("actor_id") else None,
                role=str(context.get("role")) if context.get("role") else None,
                subscription_id=str(context.get("subscription_id"))
                if context.get("subscription_id")
                else None,
                device_id=str(context.get("device_id")) if context.get("device_id") else None,
                session_id=str(context.get("session_id")) if context.get("session_id") else None,
                agent_permissions=dict(context.get("agent_permissions") or {}),
                metadata=dict(context.get("metadata") or {}),
            )

        raise TypeError("context must be NotificationContext, mapping, or None")

    def _context_from_task(self, task: Mapping[str, Any]) -> NotificationContext:
        """Build NotificationContext from Master Agent task."""

        context_data = dict(task.get("context") or {})

        for key in (
            "user_id",
            "workspace_id",
            "request_id",
            "task_id",
            "actor_id",
            "role",
            "subscription_id",
            "device_id",
            "session_id",
            "agent_permissions",
            "metadata",
        ):
            if key in task and key not in context_data:
                context_data[key] = task.get(key)

        return self._ensure_context(context_data)

    def _coerce_mode(self, value: Union[str, OverlayMode]) -> OverlayMode:
        """Coerce overlay mode safely."""

        if isinstance(value, OverlayMode):
            return value

        normalized = _normalize_key(str(value or self.config.default_mode.value))
        try:
            return OverlayMode(normalized)
        except Exception:
            return self.config.default_mode

    def _coerce_level(self, value: Optional[Union[str, NotificationLevel]]) -> NotificationLevel:
        """Coerce notification level safely."""

        if isinstance(value, NotificationLevel):
            return value

        normalized = _normalize_key(str(value or NotificationLevel.INFO.value))
        try:
            return NotificationLevel(normalized)
        except Exception:
            return NotificationLevel.INFO

    def _coerce_category(
        self,
        value: Optional[Union[str, NotificationCategory]],
    ) -> NotificationCategory:
        """Coerce notification category safely."""

        if isinstance(value, NotificationCategory):
            return value

        normalized = _normalize_key(str(value or NotificationCategory.GENERAL.value))
        try:
            return NotificationCategory(normalized)
        except Exception:
            return NotificationCategory.GENERAL

    def _coerce_position(
        self,
        value: Optional[Union[str, NotificationPosition]],
    ) -> NotificationPosition:
        """Coerce overlay position safely."""

        if isinstance(value, NotificationPosition):
            return value

        normalized = _normalize_key(str(value or self.config.default_position.value))
        try:
            return NotificationPosition(normalized)
        except Exception:
            return self.config.default_position

    def _coerce_status(
        self,
        value: Optional[Union[str, NotificationStatus]],
    ) -> NotificationStatus:
        """Coerce notification status safely."""

        if isinstance(value, NotificationStatus):
            return value

        normalized = _normalize_key(str(value or NotificationStatus.QUEUED.value))
        try:
            return NotificationStatus(normalized)
        except Exception:
            return NotificationStatus.QUEUED

    def _coerce_action_type(
        self,
        value: Optional[Union[str, NotificationActionType]],
    ) -> NotificationActionType:
        """Coerce action type safely."""

        if isinstance(value, NotificationActionType):
            return value

        normalized = _normalize_key(str(value or NotificationActionType.DISMISS.value))
        try:
            return NotificationActionType(normalized)
        except Exception:
            return NotificationActionType.DISMISS

    def _base_metadata(
        self,
        context: NotificationContext,
        started: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Common result metadata."""

        metadata = {
            "agent": self.agent_name,
            "agent_module": self.agent_module,
            "agent_version": self.agent_version,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "device_id": context.device_id,
            "session_id": context.session_id,
            "timestamp": _utc_now(),
        }

        if started is not None:
            metadata["duration_ms"] = _duration_ms(started)

        return metadata

    def _connector_metadata(
        self,
        context: NotificationContext,
        card: NotificationCard,
    ) -> Dict[str, Any]:
        """Metadata sent to device bridge or AR overlay."""

        return {
            "agent": self.agent_name,
            "agent_module": self.agent_module,
            "agent_version": self.agent_version,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "device_id": context.device_id,
            "session_id": context.session_id,
            "notification_id": card.notification_id,
            "isolation_key": context.isolation_key(),
            "timestamp": _utc_now(),
        }

    def _normalize_security_result(self, result: Any) -> Dict[str, Any]:
        """Normalize Security Agent result."""

        if isinstance(result, Mapping):
            approved = bool(
                result.get("approved")
                if "approved" in result
                else result.get("success", False)
            )
            return {
                "approved": approved,
                "message": str(result.get("message") or result.get("reason") or ""),
                "data": dict(result.get("data") or {}),
                "error": result.get("error"),
                "metadata": dict(result.get("metadata") or {}),
                "timestamp": _utc_now(),
            }

        if isinstance(result, bool):
            return {
                "approved": result,
                "message": "Security Agent returned boolean approval.",
                "timestamp": _utc_now(),
            }

        return {
            "approved": False,
            "message": "Security Agent returned unsupported response format.",
            "raw_type": result.__class__.__name__,
            "timestamp": _utc_now(),
        }

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Agent Registry / Agent Loader compatible manifest.
        """

        return {
            "agent_name": self.agent_name,
            "agent_module": self.agent_module,
            "agent_version": self.agent_version,
            "class_name": self.__class__.__name__,
            "file_path": "agents/super_agents/hologram_agent/notification_overlay.py",
            "capabilities": [
                "safe_notification_overlay",
                "public_mode_redaction",
                "private_data_masking",
                "notification_queue",
                "notification_dismiss",
                "hologram_dashboard_payloads",
                "device_bridge_ready",
                "security_agent_approval",
                "verification_payload",
                "memory_payload",
                "audit_logging",
                "agent_events",
            ],
            "public_methods": [
                "run_task",
                "show_notification",
                "preview_notification",
                "dismiss_notification",
                "list_notifications",
                "clear_notifications",
                "set_overlay_mode",
                "get_agent_manifest",
            ],
            "required_context": ["user_id", "workspace_id"],
            "safe_to_import": True,
            "privacy_modes": [mode.value for mode in OverlayMode],
            "notification_levels": [level.value for level in NotificationLevel],
            "notification_categories": [category.value for category in NotificationCategory],
            "default_mode": self.config.default_mode.value,
        }


# ======================================================================================
# Synchronous convenience wrappers
# ======================================================================================

def show_notification_sync(
    *,
    title: str,
    body: str,
    context: Union[NotificationContext, Mapping[str, Any]],
    config: Optional[Union[NotificationOverlayConfig, Mapping[str, Any]]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Synchronous helper for scripts/tests.

    FastAPI or async workers should call NotificationOverlay.show_notification directly.
    """

    overlay = NotificationOverlay(config=config)
    return asyncio.run(
        overlay.show_notification(
            title=title,
            body=body,
            context=context,
            **kwargs,
        )
    )


__all__ = [
    "NotificationOverlay",
    "NotificationOverlayConfig",
    "NotificationContext",
    "NotificationAction",
    "NotificationCard",
    "OverlayRenderResult",
    "OverlayMode",
    "NotificationLevel",
    "NotificationCategory",
    "NotificationStatus",
    "NotificationPosition",
    "NotificationActionType",
    "show_notification_sync",
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    demo_result = show_notification_sync(
        title="New email from client@example.com",
        body="Client phone +1 888 808 1006 asked for pricing. Token=abc123",
        context={
            "user_id": "demo_user",
            "workspace_id": "demo_workspace",
            "device_id": "demo_glasses",
            "task_id": "demo_task",
        },
        category="email",
        level="info",
        mode="public",
        is_private=True,
        payload={
            "email": "client@example.com",
            "phone": "+1 888 808 1006",
            "summary": "Asked for pricing",
        },
    )

    print(json.dumps(demo_result, indent=2, default=str))