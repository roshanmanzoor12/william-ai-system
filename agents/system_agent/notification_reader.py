"""
agents/system_agent/notification_reader.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Read and summarize notifications with permission and priority filtering.

Architecture Compatibility:
    - Master Agent routing
    - BaseAgent compatibility
    - Agent Registry / Agent Loader compatibility
    - Agent Router / Dashboard API compatibility
    - Security Agent permission checks
    - Verification Agent payload preparation
    - Memory Agent payload compatibility
    - Audit logging
    - SaaS user/workspace isolation

Important:
    This file does NOT directly scrape private OS notifications by default.
    It provides a safe, structured notification reading layer that can receive
    notification payloads from approved platform bridges such as:
        - Android Accessibility/Notification Listener bridge
        - Desktop bridge
        - Browser extension bridge
        - Mobile APK bridge
        - Backend webhook/event bridge

    Any real notification access must be routed through permission checks.
"""

from __future__ import annotations

import re
import uuid
import time
import logging
from enum import Enum
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union, Callable, Tuple


# ---------------------------------------------------------------------------
# Safe optional imports / fallback compatibility
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe even if William/Jarvis BaseAgent
        has not been generated yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
            return None


try:
    from core.context import AgentContext  # type: ignore
except Exception:  # pragma: no cover
    AgentContext = Any  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("william.system_agent.notification_reader")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)

logger.setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class NotificationPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"
    MUTED = "muted"


class NotificationSource(str, Enum):
    ANDROID = "android"
    IOS = "ios"
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    BROWSER = "browser"
    WEBHOOK = "webhook"
    DASHBOARD = "dashboard"
    UNKNOWN = "unknown"


class NotificationCategory(str, Enum):
    SECURITY = "security"
    SYSTEM = "system"
    MESSAGE = "message"
    EMAIL = "email"
    CALL = "call"
    CALENDAR = "calendar"
    PAYMENT = "payment"
    WORKFLOW = "workflow"
    SOCIAL = "social"
    MARKETING = "marketing"
    APP = "app"
    UNKNOWN = "unknown"


class NotificationAction(str, Enum):
    INGEST = "ingest"
    LIST = "list"
    FILTER = "filter"
    SUMMARIZE = "summarize"
    MARK_READ = "mark_read"
    CLEAR = "clear"
    GET_STATS = "get_stats"
    GET_CAPABILITIES = "get_capabilities"
    HEALTH_CHECK = "health_check"


class NotificationRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class NotificationReaderConfig:
    """
    Runtime configuration.

    max_notifications_per_workspace:
        Safety limit for in-memory notification storage per user/workspace.

    default_summary_limit:
        Default number of notifications summarized.

    redact_sensitive_content:
        Redacts obvious tokens/passwords/keys from summaries and logs.

    require_security_approval:
        Requires Security Agent approval for sensitive notification operations.

    allow_raw_content_in_results:
        If False, public results contain cleaned/sanitized content only.

    critical_keywords / high_priority_keywords:
        Keywords used for priority scoring.

    muted_apps:
        App names/packages to mute by default.
    """

    max_notifications_per_workspace: int = 1000
    default_summary_limit: int = 25
    redact_sensitive_content: bool = True
    require_security_approval: bool = True
    allow_raw_content_in_results: bool = False
    store_in_memory: bool = True
    critical_keywords: List[str] = field(default_factory=lambda: [
        "security alert",
        "login attempt",
        "password changed",
        "payment failed",
        "fraud",
        "unauthorized",
        "2fa",
        "verification code",
        "otp",
        "critical",
        "urgent",
        "breach",
        "blocked",
        "suspicious",
    ])
    high_priority_keywords: List[str] = field(default_factory=lambda: [
        "meeting",
        "deadline",
        "missed call",
        "new lead",
        "client",
        "invoice",
        "approval",
        "support",
        "error",
        "failed",
        "assigned",
        "reminder",
    ])
    low_priority_keywords: List[str] = field(default_factory=lambda: [
        "promotion",
        "offer",
        "sale",
        "newsletter",
        "recommended",
        "suggested",
        "digest",
    ])
    muted_apps: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NotificationTaskContext:
    """
    SaaS-safe context.

    Every user-specific action must include user_id and workspace_id.
    """

    user_id: Union[str, int]
    workspace_id: Union[str, int]
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: Optional[str] = None
    role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    source: str = "system_agent"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NotificationItem:
    """
    Normalized notification object.
    """

    notification_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = ""
    body: str = ""
    app_name: str = ""
    package_name: Optional[str] = None
    source: NotificationSource = NotificationSource.UNKNOWN
    category: NotificationCategory = NotificationCategory.UNKNOWN
    priority: NotificationPriority = NotificationPriority.NORMAL
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    read: bool = False
    dismissed: bool = False
    raw: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NotificationFilter:
    """
    Filter structure for listing and summarizing notifications.
    """

    priority: Optional[Union[str, NotificationPriority]] = None
    category: Optional[Union[str, NotificationCategory]] = None
    source: Optional[Union[str, NotificationSource]] = None
    app_name: Optional[str] = None
    package_name: Optional[str] = None
    unread_only: bool = False
    include_dismissed: bool = False
    search: Optional[str] = None
    limit: Optional[int] = None
    since_timestamp: Optional[str] = None
    until_timestamp: Optional[str] = None


# ---------------------------------------------------------------------------
# NotificationReader
# ---------------------------------------------------------------------------

class NotificationReader(BaseAgent):
    """
    Permission-safe notification reader and summarizer.

    This class is designed to be called by:
        - Master Agent
        - System Agent
        - Workflow Agent
        - Dashboard/API
        - Android/Desktop/Browser bridge
        - Verification Agent
        - Memory Agent
        - Security Agent

    It does not directly access private device notifications by itself.
    Platform bridges should ingest approved notification payloads here.
    """

    agent_name = "NotificationReader"
    agent_type = "system_agent_helper"
    module_path = "agents/system_agent/notification_reader.py"

    def __init__(
        self,
        config: Optional[NotificationReaderConfig] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)

        self.config = config or NotificationReaderConfig()
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter

        self.runtime_id = str(uuid.uuid4())
        self.created_at = self._utc_now()

        # Isolated in-memory store:
        # {
        #   "user_id::workspace_id": [NotificationItem, ...]
        # }
        self._notifications: Dict[str, List[NotificationItem]] = {}

    # -----------------------------------------------------------------------
    # Standard hooks
    # -----------------------------------------------------------------------

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "module": self.module_path,
                "runtime_id": self.runtime_id,
                "timestamp": self._utc_now(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error) if error else message,
            "metadata": {
                "agent": self.agent_name,
                "module": self.module_path,
                "runtime_id": self.runtime_id,
                "timestamp": self._utc_now(),
                **(metadata or {}),
            },
        }

    def _normalize_context(
        self,
        context: Optional[Union[NotificationTaskContext, Dict[str, Any], AgentContext]],
    ) -> Optional[NotificationTaskContext]:
        if context is None:
            return None

        if isinstance(context, NotificationTaskContext):
            return context

        if isinstance(context, dict):
            user_id = context.get("user_id")
            workspace_id = context.get("workspace_id")

            if user_id is None or workspace_id is None:
                return None

            return NotificationTaskContext(
                user_id=user_id,
                workspace_id=workspace_id,
                request_id=str(context.get("request_id") or uuid.uuid4()),
                session_id=context.get("session_id"),
                role=context.get("role"),
                permissions=list(context.get("permissions") or []),
                source=str(context.get("source") or "system_agent"),
                metadata=dict(context.get("metadata") or {}),
            )

        user_id = getattr(context, "user_id", None)
        workspace_id = getattr(context, "workspace_id", None)

        if user_id is None or workspace_id is None:
            return None

        return NotificationTaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            request_id=str(getattr(context, "request_id", uuid.uuid4())),
            session_id=getattr(context, "session_id", None),
            role=getattr(context, "role", None),
            permissions=list(getattr(context, "permissions", []) or []),
            source=str(getattr(context, "source", "system_agent")),
            metadata=dict(getattr(context, "metadata", {}) or {}),
        )

    def _validate_task_context(
        self,
        context: Optional[Union[NotificationTaskContext, Dict[str, Any], AgentContext]],
    ) -> Tuple[bool, Optional[NotificationTaskContext], Optional[str]]:
        """
        Validate user/workspace context for SaaS isolation.
        """
        normalized = self._normalize_context(context)

        if normalized is None:
            return False, None, "Missing or invalid context. user_id and workspace_id are required."

        if normalized.user_id in ("", None):
            return False, None, "Missing user_id."

        if normalized.workspace_id in ("", None):
            return False, None, "Missing workspace_id."

        return True, normalized, None

    def _workspace_key(self, context: NotificationTaskContext) -> str:
        """
        Create isolated store key.
        """
        return f"{context.user_id}::{context.workspace_id}"

    def _requires_security_check(
        self,
        action: NotificationAction,
        risk_level: NotificationRiskLevel = NotificationRiskLevel.MEDIUM,
    ) -> bool:
        """
        Decide if an action needs Security Agent approval.
        """
        if not self.config.require_security_approval:
            return False

        sensitive_actions = {
            NotificationAction.INGEST,
            NotificationAction.LIST,
            NotificationAction.SUMMARIZE,
            NotificationAction.CLEAR,
            NotificationAction.MARK_READ,
        }

        if risk_level == NotificationRiskLevel.HIGH:
            return True

        return action in sensitive_actions

    def _request_security_approval(
        self,
        action: NotificationAction,
        context: NotificationTaskContext,
        payload: Dict[str, Any],
        risk_level: NotificationRiskLevel = NotificationRiskLevel.MEDIUM,
    ) -> Dict[str, Any]:
        """
        Security Agent approval layer.

        If Security Agent is not attached, non-destructive dry-safe operations
        may still work depending on configuration, but sensitive access is blocked
        by default when approval is required.
        """
        approval_payload = {
            "action": action.value,
            "risk_level": risk_level.value,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "payload": self._redact_sensitive_payload(payload),
            "timestamp": self._utc_now(),
            "agent": self.agent_name,
        }

        if not self._requires_security_check(action, risk_level):
            return {
                "approved": True,
                "reason": "Security approval not required.",
                "payload": approval_payload,
            }

        if self.security_agent is None:
            # Safe default for production: block sensitive operations if no
            # Security Agent is connected.
            return {
                "approved": False,
                "reason": "Security Agent is not connected.",
                "payload": approval_payload,
            }

        try:
            if hasattr(self.security_agent, "approve_action"):
                result = self.security_agent.approve_action(approval_payload)
            elif hasattr(self.security_agent, "validate_action"):
                result = self.security_agent.validate_action(approval_payload)
            elif callable(self.security_agent):
                result = self.security_agent(approval_payload)
            else:
                return {
                    "approved": False,
                    "reason": "Security Agent does not expose an approval method.",
                    "payload": approval_payload,
                }

            if isinstance(result, dict):
                approved = bool(result.get("approved") or result.get("success"))
                return {
                    "approved": approved,
                    "reason": result.get("message") or result.get("reason") or "Security Agent response received.",
                    "payload": approval_payload,
                    "security_result": result,
                }

            return {
                "approved": bool(result),
                "reason": "Security Agent returned boolean response.",
                "payload": approval_payload,
            }

        except Exception as exc:
            logger.exception("Security approval failed.")
            return {
                "approved": False,
                "reason": f"Security approval error: {exc}",
                "payload": approval_payload,
            }

    def _prepare_verification_payload(
        self,
        action: NotificationAction,
        context: NotificationTaskContext,
        result: Dict[str, Any],
        input_payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent-compatible payload.
        """
        return {
            "verification_type": "notification_reader_action",
            "agent": self.agent_name,
            "action": action.value,
            "success": result.get("success", False),
            "message": result.get("message"),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "input_payload": self._redact_sensitive_payload(input_payload),
            "result_summary": {
                "keys": list((result.get("data") or {}).keys()),
                "success": result.get("success", False),
            },
            "timestamp": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        action: NotificationAction,
        context: NotificationTaskContext,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        Stores only safe summary-level information.
        """
        return {
            "memory_type": "notification_reader_history",
            "agent": self.agent_name,
            "action": action.value,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "summary": result.get("message"),
            "success": result.get("success", False),
            "timestamp": self._utc_now(),
            "metadata": {
                "module": self.module_path,
                "runtime_id": self.runtime_id,
            },
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit event for Dashboard/API/Master Agent.
        """
        try:
            if self.event_emitter:
                self.event_emitter(event_name, payload)
                return

            if hasattr(self, "emit_event"):
                try:
                    self.emit_event(event_name, payload)  # type: ignore
                    return
                except Exception:
                    pass

            logger.info("Agent event: %s | %s", event_name, payload)

        except Exception as exc:
            logger.warning("Failed to emit event %s: %s", event_name, exc)

    def _log_audit_event(
        self,
        context: NotificationTaskContext,
        action: NotificationAction,
        payload: Dict[str, Any],
        result: Dict[str, Any],
    ) -> None:
        """
        Audit logging with user/workspace isolation.
        """
        audit_payload = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "module": self.module_path,
            "action": action.value,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "input_payload": self._redact_sensitive_payload(payload),
            "success": result.get("success", False),
            "message": result.get("message"),
            "error": result.get("error"),
            "timestamp": self._utc_now(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_payload)
            else:
                logger.info("Audit event: %s", audit_payload)
        except Exception as exc:
            logger.warning("Audit logging failed: %s", exc)

    def _finalize_action(
        self,
        action: NotificationAction,
        context: NotificationTaskContext,
        input_payload: Dict[str, Any],
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Add verification/memory payloads, emit event, and audit.
        """
        verification_payload = self._prepare_verification_payload(
            action=action,
            context=context,
            result=result,
            input_payload=input_payload,
        )

        memory_payload = self._prepare_memory_payload(
            action=action,
            context=context,
            result=result,
        )

        result.setdefault("metadata", {})
        result["metadata"]["verification_payload"] = verification_payload
        result["metadata"]["memory_payload"] = memory_payload

        self._emit_agent_event(
            event_name="notification_reader_action_completed",
            payload={
                "action": action.value,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "request_id": context.request_id,
                "success": result.get("success", False),
                "timestamp": self._utc_now(),
            },
        )

        self._log_audit_event(
            context=context,
            action=action,
            payload=input_payload,
            result=result,
        )

        return result

    def _guard_action(
        self,
        action: NotificationAction,
        context: Optional[Union[NotificationTaskContext, Dict[str, Any], AgentContext]],
        payload: Dict[str, Any],
        callback: Callable[[NotificationTaskContext], Dict[str, Any]],
        risk_level: NotificationRiskLevel = NotificationRiskLevel.MEDIUM,
    ) -> Dict[str, Any]:
        """
        Shared context/security wrapper.
        """
        valid, normalized_context, context_error = self._validate_task_context(context)

        if not valid or normalized_context is None:
            return self._error_result(
                message="Notification task context validation failed.",
                error=context_error,
                data={"payload": self._redact_sensitive_payload(payload)},
            )

        approval = self._request_security_approval(
            action=action,
            context=normalized_context,
            payload=payload,
            risk_level=risk_level,
        )

        if not approval.get("approved"):
            result = self._error_result(
                message="Notification action blocked by security approval layer.",
                error=approval.get("reason"),
                data={
                    "action": action.value,
                    "approved": False,
                    "security": approval,
                },
            )
            return self._finalize_action(
                action=action,
                context=normalized_context,
                input_payload=payload,
                result=result,
            )

        try:
            result = callback(normalized_context)
            return self._finalize_action(
                action=action,
                context=normalized_context,
                input_payload=payload,
                result=result,
            )
        except Exception as exc:
            logger.exception("NotificationReader action failed: %s", action.value)
            result = self._error_result(
                message=f"NotificationReader action failed: {action.value}",
                error=exc,
                data={"action": action.value},
            )
            return self._finalize_action(
                action=action,
                context=normalized_context,
                input_payload=payload,
                result=result,
            )

    # -----------------------------------------------------------------------
    # Sanitization / classification
    # -----------------------------------------------------------------------

    def _redact_sensitive_text(self, text: str) -> str:
        """
        Redact common sensitive values from notification text.
        """
        if not self.config.redact_sensitive_content:
            return text

        if not text:
            return ""

        redacted = str(text)

        patterns = [
            r"\b\d{4,8}\b",  # OTP-ish numeric codes
            r"(?i)(password|passcode|otp|token|api key|secret)\s*[:=]\s*[^\s]+",
            r"(?i)(bearer)\s+[a-z0-9\.\-_]+",
            r"(?i)(sk_live_|sk_test_)[a-z0-9\-_]+",
        ]

        for pattern in patterns:
            redacted = re.sub(pattern, "***REDACTED***", redacted)

        return redacted

    def _redact_sensitive_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact sensitive payload fields.
        """
        redacted = dict(payload or {})
        sensitive_keys = {
            "password",
            "secret",
            "token",
            "api_key",
            "access_token",
            "refresh_token",
            "authorization",
            "otp",
            "code",
        }

        for key in list(redacted.keys()):
            if key.lower() in sensitive_keys:
                redacted[key] = "***REDACTED***"

        for key in ["title", "body", "text", "content", "message"]:
            if key in redacted and isinstance(redacted[key], str):
                redacted[key] = self._redact_sensitive_text(redacted[key])

        if "notifications" in redacted and isinstance(redacted["notifications"], list):
            redacted["notifications_count"] = len(redacted["notifications"])
            redacted["notifications"] = "***NOTIFICATION_LIST_REDACTED***"

        return redacted

    def _clean_text(self, value: Any) -> str:
        if value is None:
            return ""
        return re.sub(r"\s+", " ", str(value)).strip()

    def _normalize_source(self, source: Any) -> NotificationSource:
        value = str(source or "").strip().lower()
        for item in NotificationSource:
            if item.value == value:
                return item
        return NotificationSource.UNKNOWN

    def _normalize_category(self, category: Any) -> NotificationCategory:
        value = str(category or "").strip().lower()
        for item in NotificationCategory:
            if item.value == value:
                return item
        return NotificationCategory.UNKNOWN

    def _normalize_priority(self, priority: Any) -> NotificationPriority:
        value = str(priority or "").strip().lower()
        for item in NotificationPriority:
            if item.value == value:
                return item
        return NotificationPriority.NORMAL

    def _detect_category(
        self,
        title: str,
        body: str,
        app_name: str,
        package_name: Optional[str],
    ) -> NotificationCategory:
        text = f"{title} {body} {app_name} {package_name or ''}".lower()

        category_keywords = {
            NotificationCategory.SECURITY: [
                "security", "login", "password", "2fa", "verification", "otp",
                "suspicious", "blocked", "unauthorized", "authenticator",
            ],
            NotificationCategory.MESSAGE: [
                "message", "chat", "whatsapp", "messenger", "telegram", "sms",
            ],
            NotificationCategory.EMAIL: [
                "email", "gmail", "outlook", "mail", "inbox",
            ],
            NotificationCategory.CALL: [
                "call", "missed call", "voicemail", "phone",
            ],
            NotificationCategory.CALENDAR: [
                "calendar", "meeting", "event", "appointment", "reminder",
            ],
            NotificationCategory.PAYMENT: [
                "payment", "invoice", "paid", "card", "bank", "transaction",
                "stripe", "paypal",
            ],
            NotificationCategory.WORKFLOW: [
                "task", "assigned", "workflow", "project", "ticket", "deadline",
            ],
            NotificationCategory.SOCIAL: [
                "like", "comment", "follow", "instagram", "facebook", "linkedin",
                "twitter", "x.com",
            ],
            NotificationCategory.MARKETING: [
                "campaign", "lead", "ads", "analytics", "marketing",
            ],
            NotificationCategory.SYSTEM: [
                "battery", "update", "system", "storage", "backup", "sync",
            ],
        }

        for category, keywords in category_keywords.items():
            if any(keyword in text for keyword in keywords):
                return category

        if app_name:
            return NotificationCategory.APP

        return NotificationCategory.UNKNOWN

    def _score_priority(
        self,
        title: str,
        body: str,
        app_name: str,
        category: NotificationCategory,
        explicit_priority: Optional[Any] = None,
    ) -> NotificationPriority:
        """
        Priority scoring based on explicit value + content.
        """
        if explicit_priority:
            normalized = self._normalize_priority(explicit_priority)
            if normalized != NotificationPriority.NORMAL:
                return normalized

        text = f"{title} {body} {app_name}".lower()

        if app_name.lower() in [item.lower() for item in self.config.muted_apps]:
            return NotificationPriority.MUTED

        if category == NotificationCategory.SECURITY:
            return NotificationPriority.CRITICAL

        if any(keyword.lower() in text for keyword in self.config.critical_keywords):
            return NotificationPriority.CRITICAL

        if any(keyword.lower() in text for keyword in self.config.high_priority_keywords):
            return NotificationPriority.HIGH

        if any(keyword.lower() in text for keyword in self.config.low_priority_keywords):
            return NotificationPriority.LOW

        return NotificationPriority.NORMAL

    def _serialize_notification(
        self,
        notification: NotificationItem,
        include_raw: bool = False,
    ) -> Dict[str, Any]:
        """
        Serialize notification safely for API/Dashboard.
        """
        data = asdict(notification)
        data["source"] = notification.source.value
        data["category"] = notification.category.value
        data["priority"] = notification.priority.value

        data["title"] = self._redact_sensitive_text(data.get("title", ""))
        data["body"] = self._redact_sensitive_text(data.get("body", ""))

        if not include_raw or not self.config.allow_raw_content_in_results:
            data.pop("raw", None)
        else:
            data["raw"] = self._redact_sensitive_payload(data.get("raw", {}))

        return data

    def _normalize_notification(
        self,
        raw_notification: Union[NotificationItem, Dict[str, Any]],
    ) -> NotificationItem:
        """
        Convert bridge/platform notification payload into NotificationItem.
        """
        if isinstance(raw_notification, NotificationItem):
            return raw_notification

        raw = dict(raw_notification or {})

        title = self._clean_text(
            raw.get("title")
            or raw.get("notification_title")
            or raw.get("app_title")
            or ""
        )

        body = self._clean_text(
            raw.get("body")
            or raw.get("text")
            or raw.get("message")
            or raw.get("content")
            or ""
        )

        app_name = self._clean_text(
            raw.get("app_name")
            or raw.get("application")
            or raw.get("app")
            or ""
        )

        package_name = raw.get("package_name") or raw.get("package") or raw.get("bundle_id")

        source = self._normalize_source(raw.get("source"))
        category = self._normalize_category(raw.get("category"))

        if category == NotificationCategory.UNKNOWN:
            category = self._detect_category(
                title=title,
                body=body,
                app_name=app_name,
                package_name=package_name,
            )

        priority = self._score_priority(
            title=title,
            body=body,
            app_name=app_name,
            category=category,
            explicit_priority=raw.get("priority"),
        )

        timestamp = raw.get("timestamp") or raw.get("created_at") or self._utc_now()

        return NotificationItem(
            notification_id=str(raw.get("notification_id") or raw.get("id") or uuid.uuid4()),
            title=title,
            body=body,
            app_name=app_name,
            package_name=package_name,
            source=source,
            category=category,
            priority=priority,
            timestamp=str(timestamp),
            read=bool(raw.get("read", False)),
            dismissed=bool(raw.get("dismissed", False)),
            raw=raw,
            metadata=dict(raw.get("metadata") or {}),
        )

    # -----------------------------------------------------------------------
    # Store management
    # -----------------------------------------------------------------------

    def _get_store(self, context: NotificationTaskContext) -> List[NotificationItem]:
        key = self._workspace_key(context)
        if key not in self._notifications:
            self._notifications[key] = []
        return self._notifications[key]

    def _trim_store(self, context: NotificationTaskContext) -> None:
        store = self._get_store(context)
        max_items = max(1, int(self.config.max_notifications_per_workspace))

        if len(store) > max_items:
            del store[:-max_items]

    def _filter_notifications(
        self,
        notifications: List[NotificationItem],
        notification_filter: Optional[Union[NotificationFilter, Dict[str, Any]]] = None,
    ) -> List[NotificationItem]:
        if notification_filter is None:
            nf = NotificationFilter()
        elif isinstance(notification_filter, NotificationFilter):
            nf = notification_filter
        else:
            nf = NotificationFilter(**dict(notification_filter))

        results = list(notifications)

        if not nf.include_dismissed:
            results = [item for item in results if not item.dismissed]

        if nf.unread_only:
            results = [item for item in results if not item.read]

        if nf.priority:
            priority = self._normalize_priority(nf.priority)
            results = [item for item in results if item.priority == priority]

        if nf.category:
            category = self._normalize_category(nf.category)
            results = [item for item in results if item.category == category]

        if nf.source:
            source = self._normalize_source(nf.source)
            results = [item for item in results if item.source == source]

        if nf.app_name:
            app_name = nf.app_name.lower().strip()
            results = [item for item in results if app_name in item.app_name.lower()]

        if nf.package_name:
            package_name = nf.package_name.lower().strip()
            results = [
                item for item in results
                if item.package_name and package_name in item.package_name.lower()
            ]

        if nf.search:
            search = nf.search.lower().strip()
            results = [
                item for item in results
                if search in f"{item.title} {item.body} {item.app_name} {item.package_name or ''}".lower()
            ]

        if nf.since_timestamp:
            results = [
                item for item in results
                if str(item.timestamp) >= str(nf.since_timestamp)
            ]

        if nf.until_timestamp:
            results = [
                item for item in results
                if str(item.timestamp) <= str(nf.until_timestamp)
            ]

        results.sort(key=lambda item: str(item.timestamp), reverse=True)

        if nf.limit is not None:
            results = results[:max(0, int(nf.limit))]

        return results

    # -----------------------------------------------------------------------
    # Public methods
    # -----------------------------------------------------------------------

    def health_check(self) -> Dict[str, Any]:
        """
        Dashboard/API health check.
        """
        return self._safe_result(
            message="NotificationReader health check completed.",
            data={
                "agent": self.agent_name,
                "module": self.module_path,
                "runtime_id": self.runtime_id,
                "created_at": self.created_at,
                "require_security_approval": self.config.require_security_approval,
                "store_in_memory": self.config.store_in_memory,
                "max_notifications_per_workspace": self.config.max_notifications_per_workspace,
            },
        )

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Capabilities for Agent Registry / Master Agent.
        """
        return self._safe_result(
            message="NotificationReader capabilities loaded.",
            data={
                "actions": [action.value for action in NotificationAction],
                "sources": [source.value for source in NotificationSource],
                "categories": [category.value for category in NotificationCategory],
                "priorities": [priority.value for priority in NotificationPriority],
                "supports_ingest": True,
                "supports_filtering": True,
                "supports_summary": True,
                "supports_priority_scoring": True,
                "supports_user_workspace_isolation": True,
                "security_gated": True,
                "raw_os_access": False,
                "requires_platform_bridge": True,
            },
        )

    def ingest_notification(
        self,
        context: Optional[Union[NotificationTaskContext, Dict[str, Any], AgentContext]],
        notification: Union[NotificationItem, Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Ingest one notification from an approved platform bridge.
        """
        payload = {
            "notification": (
                self._serialize_notification(notification, include_raw=False)
                if isinstance(notification, NotificationItem)
                else self._redact_sensitive_payload(dict(notification or {}))
            )
        }

        def callback(valid_context: NotificationTaskContext) -> Dict[str, Any]:
            item = self._normalize_notification(notification)

            if self.config.store_in_memory:
                store = self._get_store(valid_context)

                # Deduplicate by notification_id.
                existing_ids = {n.notification_id for n in store}
                if item.notification_id not in existing_ids:
                    store.append(item)

                self._trim_store(valid_context)

            return self._safe_result(
                message="Notification ingested successfully.",
                data={
                    "notification": self._serialize_notification(item),
                    "stored": self.config.store_in_memory,
                },
            )

        return self._guard_action(
            action=NotificationAction.INGEST,
            context=context,
            payload=payload,
            callback=callback,
            risk_level=NotificationRiskLevel.MEDIUM,
        )

    def ingest_notifications(
        self,
        context: Optional[Union[NotificationTaskContext, Dict[str, Any], AgentContext]],
        notifications: List[Union[NotificationItem, Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """
        Ingest multiple notifications from an approved platform bridge.
        """
        payload = {
            "notifications_count": len(notifications or []),
        }

        if not isinstance(notifications, list):
            return self._error_result(
                message="Invalid notifications payload.",
                error="notifications must be a list.",
                data=payload,
            )

        def callback(valid_context: NotificationTaskContext) -> Dict[str, Any]:
            normalized_items = [
                self._normalize_notification(item)
                for item in notifications
            ]

            stored_count = 0

            if self.config.store_in_memory:
                store = self._get_store(valid_context)
                existing_ids = {n.notification_id for n in store}

                for item in normalized_items:
                    if item.notification_id not in existing_ids:
                        store.append(item)
                        existing_ids.add(item.notification_id)
                        stored_count += 1

                self._trim_store(valid_context)

            return self._safe_result(
                message="Notifications ingested successfully.",
                data={
                    "received_count": len(normalized_items),
                    "stored_count": stored_count,
                    "stored": self.config.store_in_memory,
                    "priority_breakdown": self._priority_breakdown(normalized_items),
                    "category_breakdown": self._category_breakdown(normalized_items),
                },
            )

        return self._guard_action(
            action=NotificationAction.INGEST,
            context=context,
            payload=payload,
            callback=callback,
            risk_level=NotificationRiskLevel.MEDIUM,
        )

    def list_notifications(
        self,
        context: Optional[Union[NotificationTaskContext, Dict[str, Any], AgentContext]],
        notification_filter: Optional[Union[NotificationFilter, Dict[str, Any]]] = None,
        include_raw: bool = False,
    ) -> Dict[str, Any]:
        """
        List notifications for the current user/workspace only.
        """
        payload = {
            "filter": asdict(notification_filter) if isinstance(notification_filter, NotificationFilter) else dict(notification_filter or {}),
            "include_raw": include_raw,
        }

        def callback(valid_context: NotificationTaskContext) -> Dict[str, Any]:
            store = self._get_store(valid_context)
            filtered = self._filter_notifications(store, notification_filter)

            return self._safe_result(
                message="Notifications listed successfully.",
                data={
                    "count": len(filtered),
                    "notifications": [
                        self._serialize_notification(item, include_raw=include_raw)
                        for item in filtered
                    ],
                },
            )

        return self._guard_action(
            action=NotificationAction.LIST,
            context=context,
            payload=payload,
            callback=callback,
            risk_level=NotificationRiskLevel.MEDIUM,
        )

    def summarize_notifications(
        self,
        context: Optional[Union[NotificationTaskContext, Dict[str, Any], AgentContext]],
        notification_filter: Optional[Union[NotificationFilter, Dict[str, Any]]] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Summarize notifications with priority/category grouping.
        """
        final_limit = limit or self.config.default_summary_limit

        payload = {
            "filter": asdict(notification_filter) if isinstance(notification_filter, NotificationFilter) else dict(notification_filter or {}),
            "limit": final_limit,
        }

        def callback(valid_context: NotificationTaskContext) -> Dict[str, Any]:
            store = self._get_store(valid_context)
            filtered = self._filter_notifications(store, notification_filter)
            limited = filtered[:max(0, int(final_limit))]

            summary = self._build_summary(limited)

            return self._safe_result(
                message="Notification summary generated successfully.",
                data={
                    "total_matching": len(filtered),
                    "summarized_count": len(limited),
                    "summary": summary,
                    "priority_breakdown": self._priority_breakdown(filtered),
                    "category_breakdown": self._category_breakdown(filtered),
                    "top_notifications": [
                        self._serialize_notification(item, include_raw=False)
                        for item in limited[:10]
                    ],
                },
            )

        return self._guard_action(
            action=NotificationAction.SUMMARIZE,
            context=context,
            payload=payload,
            callback=callback,
            risk_level=NotificationRiskLevel.MEDIUM,
        )

    def mark_read(
        self,
        context: Optional[Union[NotificationTaskContext, Dict[str, Any], AgentContext]],
        notification_ids: Optional[List[str]] = None,
        mark_all: bool = False,
    ) -> Dict[str, Any]:
        """
        Mark notifications as read.
        """
        payload = {
            "notification_ids": notification_ids or [],
            "mark_all": mark_all,
        }

        def callback(valid_context: NotificationTaskContext) -> Dict[str, Any]:
            store = self._get_store(valid_context)
            target_ids = set(notification_ids or [])
            changed = 0

            for item in store:
                if mark_all or item.notification_id in target_ids:
                    if not item.read:
                        item.read = True
                        changed += 1

            return self._safe_result(
                message="Notifications marked as read.",
                data={
                    "changed_count": changed,
                    "mark_all": mark_all,
                },
            )

        return self._guard_action(
            action=NotificationAction.MARK_READ,
            context=context,
            payload=payload,
            callback=callback,
            risk_level=NotificationRiskLevel.MEDIUM,
        )

    def clear_notifications(
        self,
        context: Optional[Union[NotificationTaskContext, Dict[str, Any], AgentContext]],
        notification_ids: Optional[List[str]] = None,
        clear_all: bool = False,
    ) -> Dict[str, Any]:
        """
        Clear notifications from the isolated in-memory store.

        This does not clear actual OS/device notifications.
        Actual device clearing must be implemented by a permission-gated
        platform bridge.
        """
        payload = {
            "notification_ids": notification_ids or [],
            "clear_all": clear_all,
        }

        def callback(valid_context: NotificationTaskContext) -> Dict[str, Any]:
            store = self._get_store(valid_context)

            if clear_all:
                removed_count = len(store)
                store.clear()
            else:
                target_ids = set(notification_ids or [])
                before = len(store)
                store[:] = [
                    item for item in store
                    if item.notification_id not in target_ids
                ]
                removed_count = before - len(store)

            return self._safe_result(
                message="Notifications cleared from NotificationReader store.",
                data={
                    "removed_count": removed_count,
                    "clear_all": clear_all,
                    "device_notifications_cleared": False,
                },
            )

        return self._guard_action(
            action=NotificationAction.CLEAR,
            context=context,
            payload=payload,
            callback=callback,
            risk_level=NotificationRiskLevel.HIGH,
        )

    def get_stats(
        self,
        context: Optional[Union[NotificationTaskContext, Dict[str, Any], AgentContext]],
    ) -> Dict[str, Any]:
        """
        Get notification analytics for current user/workspace.
        """
        payload: Dict[str, Any] = {}

        def callback(valid_context: NotificationTaskContext) -> Dict[str, Any]:
            store = self._get_store(valid_context)

            unread = [item for item in store if not item.read]
            dismissed = [item for item in store if item.dismissed]

            return self._safe_result(
                message="Notification stats generated successfully.",
                data={
                    "total": len(store),
                    "unread": len(unread),
                    "read": len(store) - len(unread),
                    "dismissed": len(dismissed),
                    "priority_breakdown": self._priority_breakdown(store),
                    "category_breakdown": self._category_breakdown(store),
                    "source_breakdown": self._source_breakdown(store),
                    "top_apps": self._top_apps(store),
                },
            )

        return self._guard_action(
            action=NotificationAction.GET_STATS,
            context=context,
            payload=payload,
            callback=callback,
            risk_level=NotificationRiskLevel.LOW,
        )

    # -----------------------------------------------------------------------
    # Summary helpers
    # -----------------------------------------------------------------------

    def _priority_breakdown(self, notifications: List[NotificationItem]) -> Dict[str, int]:
        data = {priority.value: 0 for priority in NotificationPriority}
        for item in notifications:
            data[item.priority.value] = data.get(item.priority.value, 0) + 1
        return data

    def _category_breakdown(self, notifications: List[NotificationItem]) -> Dict[str, int]:
        data = {category.value: 0 for category in NotificationCategory}
        for item in notifications:
            data[item.category.value] = data.get(item.category.value, 0) + 1
        return data

    def _source_breakdown(self, notifications: List[NotificationItem]) -> Dict[str, int]:
        data = {source.value: 0 for source in NotificationSource}
        for item in notifications:
            data[item.source.value] = data.get(item.source.value, 0) + 1
        return data

    def _top_apps(self, notifications: List[NotificationItem], limit: int = 10) -> List[Dict[str, Any]]:
        counts: Dict[str, int] = {}

        for item in notifications:
            app = item.app_name or item.package_name or "unknown"
            counts[app] = counts.get(app, 0) + 1

        sorted_apps = sorted(counts.items(), key=lambda pair: pair[1], reverse=True)

        return [
            {"app_name": app, "count": count}
            for app, count in sorted_apps[:limit]
        ]

    def _build_summary(self, notifications: List[NotificationItem]) -> Dict[str, Any]:
        """
        Build simple production-safe summary without external LLM dependency.
        Master Agent can later pass this to a language model for richer summary.
        """
        if not notifications:
            return {
                "headline": "No matching notifications.",
                "critical_items": [],
                "high_priority_items": [],
                "normal_items": [],
                "low_priority_items": [],
                "recommended_focus": [],
            }

        critical = [
            item for item in notifications
            if item.priority == NotificationPriority.CRITICAL
        ]

        high = [
            item for item in notifications
            if item.priority == NotificationPriority.HIGH
        ]

        normal = [
            item for item in notifications
            if item.priority == NotificationPriority.NORMAL
        ]

        low = [
            item for item in notifications
            if item.priority in {NotificationPriority.LOW, NotificationPriority.MUTED}
        ]

        headline_parts: List[str] = []

        if critical:
            headline_parts.append(f"{len(critical)} critical")
        if high:
            headline_parts.append(f"{len(high)} high-priority")
        if normal:
            headline_parts.append(f"{len(normal)} normal")
        if low:
            headline_parts.append(f"{len(low)} low-priority/muted")

        headline = "Notifications summary: " + ", ".join(headline_parts) + "."

        recommended_focus = []
        for item in critical[:5] + high[:5]:
            title = self._redact_sensitive_text(item.title)
            app = item.app_name or "Unknown app"
            recommended_focus.append({
                "notification_id": item.notification_id,
                "priority": item.priority.value,
                "category": item.category.value,
                "app_name": app,
                "title": title,
                "reason": self._priority_reason(item),
            })

        return {
            "headline": headline,
            "critical_items": [
                self._compact_notification(item)
                for item in critical[:10]
            ],
            "high_priority_items": [
                self._compact_notification(item)
                for item in high[:10]
            ],
            "normal_items": [
                self._compact_notification(item)
                for item in normal[:10]
            ],
            "low_priority_items": [
                self._compact_notification(item)
                for item in low[:10]
            ],
            "recommended_focus": recommended_focus,
        }

    def _compact_notification(self, item: NotificationItem) -> Dict[str, Any]:
        return {
            "notification_id": item.notification_id,
            "title": self._redact_sensitive_text(item.title),
            "body_preview": self._redact_sensitive_text(item.body)[:160],
            "app_name": item.app_name,
            "package_name": item.package_name,
            "priority": item.priority.value,
            "category": item.category.value,
            "source": item.source.value,
            "timestamp": item.timestamp,
            "read": item.read,
        }

    def _priority_reason(self, item: NotificationItem) -> str:
        if item.category == NotificationCategory.SECURITY:
            return "Security-related notification."

        text = f"{item.title} {item.body}".lower()

        for keyword in self.config.critical_keywords:
            if keyword.lower() in text:
                return f"Matched critical keyword: {keyword}"

        for keyword in self.config.high_priority_keywords:
            if keyword.lower() in text:
                return f"Matched high-priority keyword: {keyword}"

        return "Priority assigned by notification scoring rules."

    # -----------------------------------------------------------------------
    # Router-compatible task handler
    # -----------------------------------------------------------------------

    def handle_task(
        self,
        task: Dict[str, Any],
        context: Optional[Union[NotificationTaskContext, Dict[str, Any], AgentContext]] = None,
    ) -> Dict[str, Any]:
        """
        Master Agent / Router compatible handler.

        Expected format:
            {
                "action": "summarize",
                "params": {...},
                "context": {
                    "user_id": 1,
                    "workspace_id": 1
                }
            }
        """
        if not isinstance(task, dict):
            return self._error_result("Invalid task.", "task must be a dict.")

        action = str(task.get("action", "")).strip().lower()
        params = dict(task.get("params") or {})

        if context is None:
            context = task.get("context")

        try:
            if action in {"health", "health_check"}:
                return self.health_check()

            if action in {"capabilities", "get_capabilities"}:
                return self.get_capabilities()

            if action in {"ingest", "ingest_notification"}:
                return self.ingest_notification(context=context, **params)

            if action in {"ingest_notifications", "bulk_ingest"}:
                return self.ingest_notifications(context=context, **params)

            if action in {"list", "list_notifications"}:
                return self.list_notifications(context=context, **params)

            if action in {"filter", "filter_notifications"}:
                return self.list_notifications(context=context, **params)

            if action in {"summarize", "summary", "summarize_notifications"}:
                return self.summarize_notifications(context=context, **params)

            if action in {"mark_read", "mark_notifications_read"}:
                return self.mark_read(context=context, **params)

            if action in {"clear", "clear_notifications"}:
                return self.clear_notifications(context=context, **params)

            if action in {"stats", "get_stats"}:
                return self.get_stats(context=context)

            return self._error_result(
                message="Unsupported NotificationReader task action.",
                error=f"Unsupported action: {action}",
                data={"task": self._redact_sensitive_payload(task)},
            )

        except TypeError as exc:
            return self._error_result(
                message="Invalid parameters for NotificationReader task.",
                error=exc,
                data={"action": action, "params": self._redact_sensitive_payload(params)},
            )

        except Exception as exc:
            logger.exception("NotificationReader handle_task failed.")
            return self._error_result(
                message="NotificationReader task handling failed.",
                error=exc,
                data={"action": action},
            )


# ---------------------------------------------------------------------------
# Registry helpers
# ---------------------------------------------------------------------------

def get_agent() -> NotificationReader:
    """
    Agent Loader / Registry compatible factory.
    """
    return NotificationReader()


def get_module_info() -> Dict[str, Any]:
    """
    Static module metadata for Agent Registry / Dashboard.
    """
    return {
        "agent_name": "NotificationReader",
        "agent_type": "system_agent_helper",
        "module_path": "agents/system_agent/notification_reader.py",
        "class_name": "NotificationReader",
        "capabilities": [action.value for action in NotificationAction],
        "sources": [source.value for source in NotificationSource],
        "categories": [category.value for category in NotificationCategory],
        "priorities": [priority.value for priority in NotificationPriority],
        "requires_user_context": True,
        "requires_workspace_context": True,
        "security_gated": True,
        "safe_to_import": True,
        "raw_os_access": False,
        "requires_platform_bridge": True,
        "version": "1.0.0",
    }


__all__ = [
    "NotificationPriority",
    "NotificationSource",
    "NotificationCategory",
    "NotificationAction",
    "NotificationRiskLevel",
    "NotificationReaderConfig",
    "NotificationTaskContext",
    "NotificationItem",
    "NotificationFilter",
    "NotificationReader",
    "get_agent",
    "get_module_info",
]


# FILE COMPLETE