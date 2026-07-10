"""
agents/workflow_agent/whatsapp_connector.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Sends approved WhatsApp internal alerts/templates with permission.

This file is designed for the Workflow Agent module and provides a production-ready,
import-safe WhatsApp connector for internal workflow alerts and approved template
messages. It enforces SaaS user/workspace isolation, permission checks, optional
Security Agent approval, audit logging, Verification Agent payloads, Memory Agent
payloads, and structured JSON-style results.

Architecture Connections:
    - Master Agent:
        Can route workflow messaging tasks to WhatsAppConnector through public methods.
    - Workflow Agent:
        Uses this connector to notify users, teams, admins, or internal operators.
    - Security Agent:
        Sensitive sends are routed through approval checks before delivery.
    - Verification Agent:
        Every completed send prepares a verification payload.
    - Memory Agent:
        Useful non-sensitive context can be prepared for memory storage.
    - Dashboard/API:
        Results are structured for FastAPI/dashboard consumption.
    - Agent Registry / Loader:
        The class is import-safe and includes fallback BaseAgent compatibility.

Safety:
    - No hardcoded secrets.
    - Dry-run mode is enabled by default.
    - Sends only approved templates unless explicitly allowed by configuration.
    - Requires user_id and workspace_id for user/workspace-specific execution.
    - Prevents cross-workspace leakage by requiring context on every operation.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - import-safe fallback
    requests = None  # type: ignore


try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early development/import safety
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        This keeps the file import-safe before the real William/Jarvis BaseAgent
        exists. The real BaseAgent should provide richer logging, permissions,
        lifecycle hooks, and registry metadata.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)


try:
    from agents.workflow_agent.config import WorkflowAgentConfig  # type: ignore
except Exception:  # pragma: no cover
    WorkflowAgentConfig = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "workflow_whatsapp_connector"
DEFAULT_PROVIDER = "meta_whatsapp_cloud"
DEFAULT_API_VERSION = "v20.0"
DEFAULT_BASE_URL = "https://graph.facebook.com"
DEFAULT_TIMEOUT_SECONDS = 20
DEFAULT_TEMPLATE_LANGUAGE = "en_US"
DEFAULT_MAX_MESSAGE_LENGTH = 4096
DEFAULT_RATE_LIMIT_PER_MINUTE = 30

PHONE_RE = re.compile(r"^\+[1-9]\d{7,14}$")
TEMPLATE_NAME_RE = re.compile(r"^[a-z0-9_]{1,512}$")
LANGUAGE_RE = re.compile(r"^[a-z]{2,3}(?:_[A-Z]{2})?$")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class WhatsAppProvider(str, Enum):
    """
    Supported WhatsApp provider identifiers.

    Currently production send support is implemented for the Meta WhatsApp
    Cloud API format. Other providers can be added later without changing the
    public connector API.
    """

    META_WHATSAPP_CLOUD = "meta_whatsapp_cloud"
    MOCK = "mock"


class WhatsAppMessageType(str, Enum):
    """Supported message types."""

    TEXT = "text"
    TEMPLATE = "template"


class WhatsAppPriority(str, Enum):
    """Operational priority for internal alerts."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class WhatsAppPermissionScope(str, Enum):
    """Permission scopes for messaging operations."""

    SEND_INTERNAL_ALERT = "workflow.whatsapp.send_internal_alert"
    SEND_TEMPLATE = "workflow.whatsapp.send_template"
    MANAGE_TEMPLATES = "workflow.whatsapp.manage_templates"
    TEST_CONNECTION = "workflow.whatsapp.test_connection"


class WhatsAppApprovalStatus(str, Enum):
    """Internal template approval status."""

    APPROVED = "approved"
    PENDING = "pending"
    REJECTED = "rejected"
    DISABLED = "disabled"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class WhatsAppContext:
    """
    SaaS execution context.

    Every user/workspace-specific operation must include user_id and workspace_id
    to prevent cross-tenant leakage.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: Optional[str] = None
    agent_id: Optional[str] = DEFAULT_AGENT_NAME
    source: Optional[str] = "workflow_agent"
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class WhatsAppTemplate:
    """
    Approved internal WhatsApp template metadata.

    The connector only sends approved templates by default. This mirrors WhatsApp
    Business template discipline while adding internal William/Jarvis permission
    controls.
    """

    name: str
    language: str = DEFAULT_TEMPLATE_LANGUAGE
    category: str = "internal_alert"
    body_preview: str = ""
    status: WhatsAppApprovalStatus = WhatsAppApprovalStatus.APPROVED
    required_variables: Tuple[str, ...] = field(default_factory=tuple)
    allowed_roles: Tuple[str, ...] = field(default_factory=tuple)
    internal_only: bool = True
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class WhatsAppRecipient:
    """Validated WhatsApp recipient."""

    phone_number: str
    display_name: Optional[str] = None
    user_ref: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class WhatsAppSendRequest:
    """
    Normalized send request used internally by connector methods.
    """

    context: WhatsAppContext
    recipients: Tuple[WhatsAppRecipient, ...]
    message_type: WhatsAppMessageType
    template_name: Optional[str] = None
    language: str = DEFAULT_TEMPLATE_LANGUAGE
    text: Optional[str] = None
    variables: Dict[str, Any] = field(default_factory=dict)
    priority: WhatsAppPriority = WhatsAppPriority.NORMAL
    require_security_approval: bool = True
    idempotency_key: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WhatsAppConnectorConfig:
    """
    Connector configuration.

    No secrets are hardcoded. Values can come from environment variables,
    config objects, or explicit constructor arguments.
    """

    provider: WhatsAppProvider = WhatsAppProvider.META_WHATSAPP_CLOUD
    dry_run: bool = True
    api_version: str = DEFAULT_API_VERSION
    base_url: str = DEFAULT_BASE_URL
    phone_number_id: Optional[str] = None
    access_token: Optional[str] = None
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    default_language: str = DEFAULT_TEMPLATE_LANGUAGE
    max_message_length: int = DEFAULT_MAX_MESSAGE_LENGTH
    rate_limit_per_minute: int = DEFAULT_RATE_LIMIT_PER_MINUTE
    allow_raw_text_messages: bool = True
    allow_unapproved_templates: bool = False
    require_security_for_all_sends: bool = True
    require_security_for_critical: bool = True
    redact_phone_in_logs: bool = True
    user_agent: str = "William-Jarvis-WorkflowAgent/1.0"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "WhatsAppConnectorConfig":
        """
        Build config from environment variables.

        Supported env vars:
            WILLIAM_WHATSAPP_PROVIDER
            WILLIAM_WHATSAPP_DRY_RUN
            WILLIAM_WHATSAPP_API_VERSION
            WILLIAM_WHATSAPP_BASE_URL
            WILLIAM_WHATSAPP_PHONE_NUMBER_ID
            WILLIAM_WHATSAPP_ACCESS_TOKEN
            WILLIAM_WHATSAPP_TIMEOUT_SECONDS
            WILLIAM_WHATSAPP_DEFAULT_LANGUAGE
            WILLIAM_WHATSAPP_RATE_LIMIT_PER_MINUTE
            WILLIAM_WHATSAPP_ALLOW_RAW_TEXT
            WILLIAM_WHATSAPP_ALLOW_UNAPPROVED_TEMPLATES
            WILLIAM_WHATSAPP_REQUIRE_SECURITY_ALL
        """

        provider_value = os.getenv("WILLIAM_WHATSAPP_PROVIDER", WhatsAppProvider.META_WHATSAPP_CLOUD.value)
        try:
            provider = WhatsAppProvider(provider_value)
        except ValueError:
            provider = WhatsAppProvider.META_WHATSAPP_CLOUD

        return cls(
            provider=provider,
            dry_run=parse_bool(os.getenv("WILLIAM_WHATSAPP_DRY_RUN"), default=True),
            api_version=os.getenv("WILLIAM_WHATSAPP_API_VERSION", DEFAULT_API_VERSION),
            base_url=os.getenv("WILLIAM_WHATSAPP_BASE_URL", DEFAULT_BASE_URL),
            phone_number_id=os.getenv("WILLIAM_WHATSAPP_PHONE_NUMBER_ID"),
            access_token=os.getenv("WILLIAM_WHATSAPP_ACCESS_TOKEN"),
            timeout_seconds=parse_int(os.getenv("WILLIAM_WHATSAPP_TIMEOUT_SECONDS"), DEFAULT_TIMEOUT_SECONDS),
            default_language=os.getenv("WILLIAM_WHATSAPP_DEFAULT_LANGUAGE", DEFAULT_TEMPLATE_LANGUAGE),
            rate_limit_per_minute=parse_int(
                os.getenv("WILLIAM_WHATSAPP_RATE_LIMIT_PER_MINUTE"),
                DEFAULT_RATE_LIMIT_PER_MINUTE,
            ),
            allow_raw_text_messages=parse_bool(os.getenv("WILLIAM_WHATSAPP_ALLOW_RAW_TEXT"), default=True),
            allow_unapproved_templates=parse_bool(
                os.getenv("WILLIAM_WHATSAPP_ALLOW_UNAPPROVED_TEMPLATES"),
                default=False,
            ),
            require_security_for_all_sends=parse_bool(
                os.getenv("WILLIAM_WHATSAPP_REQUIRE_SECURITY_ALL"),
                default=True,
            ),
        )


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return current UTC datetime in ISO-8601 format."""

    return datetime.now(timezone.utc).isoformat()


def parse_bool(value: Optional[str], default: bool = False) -> bool:
    """Parse environment-style boolean values safely."""

    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def parse_int(value: Optional[str], default: int) -> int:
    """Parse integer with safe fallback."""

    if value is None:
        return default
    try:
        return int(value)
    except Exception:
        return default


def sha256_text(value: str) -> str:
    """Return SHA-256 hex digest for safe idempotency/log fingerprints."""

    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def safe_json_dumps(value: Any) -> str:
    """Serialize to JSON safely for logging/fingerprints."""

    try:
        return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    except Exception:
        return str(value)


def redact_phone(phone_number: str) -> str:
    """Redact phone number while keeping a tiny useful suffix for support."""

    if not phone_number:
        return ""
    if len(phone_number) <= 5:
        return "***"
    return f"{phone_number[:2]}***{phone_number[-4:]}"


def normalize_phone_number(phone_number: str) -> str:
    """
    Normalize a phone number into E.164-like format.

    This function intentionally does not guess country code. It requires the
    caller to pass a number with '+' and country code.
    """

    cleaned = str(phone_number or "").strip()
    cleaned = cleaned.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    return cleaned


def validate_phone_number(phone_number: str) -> bool:
    """Validate E.164-style WhatsApp phone number."""

    return bool(PHONE_RE.match(normalize_phone_number(phone_number)))


def normalize_template_name(template_name: str) -> str:
    """Normalize WhatsApp template name."""

    return str(template_name or "").strip().lower()


def sanitize_text_message(text: str, max_length: int = DEFAULT_MAX_MESSAGE_LENGTH) -> str:
    """
    Sanitize text for WhatsApp sends.

    Keeps user-provided content but removes null/control characters that can
    break APIs or logs.
    """

    raw = str(text or "")
    raw = raw.replace("\x00", "")
    raw = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", raw)
    raw = raw.strip()
    if len(raw) > max_length:
        raw = raw[:max_length]
    return raw


def result_metadata(context: Optional[WhatsAppContext] = None, **extra: Any) -> Dict[str, Any]:
    """Build common result metadata."""

    metadata: Dict[str, Any] = {
        "timestamp": utc_now_iso(),
        "agent": DEFAULT_AGENT_NAME,
    }
    if context is not None:
        metadata.update(
            {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "request_id": context.request_id,
                "task_id": context.task_id,
                "source": context.source,
            }
        )
    metadata.update(extra)
    return metadata


# ---------------------------------------------------------------------------
# Main connector
# ---------------------------------------------------------------------------

class WhatsAppConnector(BaseAgent):
    """
    Sends approved WhatsApp internal alerts/templates with permission.

    Public methods:
        - send_internal_alert()
        - send_template_message()
        - register_template()
        - approve_template()
        - disable_template()
        - list_templates()
        - test_connection()
        - validate_configuration()

    Security model:
        - Every send requires SaaS context.
        - Every sensitive operation can request Security Agent approval.
        - Dry-run mode is enabled by default.
        - Templates must be approved unless config allows unapproved templates.
    """

    def __init__(
        self,
        config: Optional[WhatsAppConnectorConfig] = None,
        *,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        templates: Optional[Iterable[WhatsAppTemplate]] = None,
        agent_name: str = DEFAULT_AGENT_NAME,
    ) -> None:
        """
        Initialize WhatsApp connector.

        Args:
            config:
                Optional connector configuration. If omitted, environment-based
                configuration is used.
            security_approval_callback:
                Optional callback to call Security Agent or approval service.
            event_callback:
                Optional callback for event bus/dashboard integration.
            audit_callback:
                Optional callback for audit log integration.
            templates:
                Optional initial approved/internal template registry.
            agent_name:
                Agent registry name.
        """

        try:
            super().__init__(agent_name=agent_name)
        except TypeError:
            super().__init__()

        self.agent_name = agent_name
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        self.config = config or self._load_config()
        self.security_approval_callback = security_approval_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback

        self._template_registry: Dict[str, WhatsAppTemplate] = {}
        self._send_timestamps: List[float] = []
        self._idempotency_cache: Dict[str, Dict[str, Any]] = {}

        self._register_builtin_templates()

        if templates:
            for template in templates:
                self._template_registry[self._template_key(template.name, template.language)] = template

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def send_internal_alert(
        self,
        *,
        user_id: str,
        workspace_id: str,
        recipients: Sequence[Union[str, Mapping[str, Any], WhatsAppRecipient]],
        message: str,
        priority: Union[str, WhatsAppPriority] = WhatsAppPriority.NORMAL,
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        require_security_approval: Optional[bool] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send an internal WhatsApp alert as a text message.

        This is intended for internal operational alerts such as:
            - Workflow completed
            - Lead captured
            - CRM update needed
            - Approval required
            - Integration failure

        Args:
            user_id:
                SaaS user ID.
            workspace_id:
                SaaS workspace ID.
            recipients:
                WhatsApp recipients as E.164 strings, dicts, or WhatsAppRecipient.
            message:
                Text message content.
            priority:
                low, normal, high, or critical.
            role:
                Current user's role.
            task_id:
                Related workflow task ID.
            metadata:
                Extra dashboard/audit metadata.
            require_security_approval:
                Override connector-level security requirement.
            idempotency_key:
                Optional key to prevent duplicate sends.

        Returns:
            Structured result dict.
        """

        context = WhatsAppContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            task_id=task_id,
            metadata=metadata or {},
        )

        try:
            normalized_priority = self._normalize_priority(priority)
            normalized_recipients = self._normalize_recipients(recipients)
            sanitized_message = sanitize_text_message(message, self.config.max_message_length)

            request = WhatsAppSendRequest(
                context=context,
                recipients=tuple(normalized_recipients),
                message_type=WhatsAppMessageType.TEXT,
                text=sanitized_message,
                priority=normalized_priority,
                require_security_approval=(
                    self.config.require_security_for_all_sends
                    if require_security_approval is None
                    else bool(require_security_approval)
                ),
                idempotency_key=idempotency_key,
                metadata=metadata or {},
            )

            return self._send(request)

        except Exception as exc:
            return self._error_result(
                "Failed to send WhatsApp internal alert.",
                error=exc,
                context=context,
                code="whatsapp_internal_alert_failed",
            )

    def send_template_message(
        self,
        *,
        user_id: str,
        workspace_id: str,
        recipients: Sequence[Union[str, Mapping[str, Any], WhatsAppRecipient]],
        template_name: str,
        variables: Optional[Dict[str, Any]] = None,
        language: Optional[str] = None,
        priority: Union[str, WhatsAppPriority] = WhatsAppPriority.NORMAL,
        role: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        require_security_approval: Optional[bool] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Send an approved WhatsApp template message.

        Args:
            user_id:
                SaaS user ID.
            workspace_id:
                SaaS workspace ID.
            recipients:
                WhatsApp recipients as E.164 strings, dicts, or WhatsAppRecipient.
            template_name:
                Approved internal WhatsApp template name.
            variables:
                Template variables.
            language:
                Template language. Defaults to connector default language.
            priority:
                low, normal, high, or critical.
            role:
                Current user's role.
            task_id:
                Related workflow task ID.
            metadata:
                Extra dashboard/audit metadata.
            require_security_approval:
                Override connector-level security requirement.
            idempotency_key:
                Optional key to prevent duplicate sends.

        Returns:
            Structured result dict.
        """

        context = WhatsAppContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            task_id=task_id,
            metadata=metadata or {},
        )

        try:
            normalized_language = language or self.config.default_language
            normalized_template = normalize_template_name(template_name)
            normalized_priority = self._normalize_priority(priority)
            normalized_recipients = self._normalize_recipients(recipients)

            request = WhatsAppSendRequest(
                context=context,
                recipients=tuple(normalized_recipients),
                message_type=WhatsAppMessageType.TEMPLATE,
                template_name=normalized_template,
                language=normalized_language,
                variables=variables or {},
                priority=normalized_priority,
                require_security_approval=(
                    self.config.require_security_for_all_sends
                    if require_security_approval is None
                    else bool(require_security_approval)
                ),
                idempotency_key=idempotency_key,
                metadata=metadata or {},
            )

            return self._send(request)

        except Exception as exc:
            return self._error_result(
                "Failed to send WhatsApp template message.",
                error=exc,
                context=context,
                code="whatsapp_template_send_failed",
            )

    def register_template(
        self,
        *,
        user_id: str,
        workspace_id: str,
        template_name: str,
        language: str = DEFAULT_TEMPLATE_LANGUAGE,
        body_preview: str = "",
        required_variables: Optional[Sequence[str]] = None,
        allowed_roles: Optional[Sequence[str]] = None,
        category: str = "internal_alert",
        internal_only: bool = True,
        role: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        status: Union[str, WhatsAppApprovalStatus] = WhatsAppApprovalStatus.PENDING,
    ) -> Dict[str, Any]:
        """
        Register a WhatsApp template in the internal connector registry.

        This does not create a template in Meta. It records whether the William
        system is allowed to use the template after internal approval.

        Returns:
            Structured result dict.
        """

        context = WhatsAppContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            metadata=metadata or {},
        )

        try:
            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            permission = self._check_permission(context, WhatsAppPermissionScope.MANAGE_TEMPLATES)
            if not permission["success"]:
                return permission

            normalized_template = normalize_template_name(template_name)
            if not self._is_valid_template_name(normalized_template):
                return self._error_result(
                    "Invalid WhatsApp template name. Use lowercase letters, numbers, and underscores only.",
                    context=context,
                    code="invalid_template_name",
                    error=None,
                )

            if not LANGUAGE_RE.match(language):
                return self._error_result(
                    "Invalid WhatsApp template language.",
                    context=context,
                    code="invalid_template_language",
                    error=None,
                )

            normalized_status = self._normalize_approval_status(status)

            template = WhatsAppTemplate(
                name=normalized_template,
                language=language,
                category=category,
                body_preview=sanitize_text_message(body_preview, 1024),
                status=normalized_status,
                required_variables=tuple(required_variables or ()),
                allowed_roles=tuple(allowed_roles or ()),
                internal_only=internal_only,
                metadata=metadata or {},
            )

            self._template_registry[self._template_key(template.name, template.language)] = template

            self._log_audit_event(
                event_type="whatsapp_template_registered",
                context=context,
                data={
                    "template_name": template.name,
                    "language": template.language,
                    "status": template.status.value,
                    "category": template.category,
                },
            )

            self._emit_agent_event(
                event_type="workflow.whatsapp.template_registered",
                context=context,
                data={
                    "template_name": template.name,
                    "language": template.language,
                    "status": template.status.value,
                },
            )

            return self._safe_result(
                success=True,
                message="WhatsApp template registered successfully.",
                data={"template": self._template_to_public_dict(template)},
                context=context,
                metadata={"operation": "register_template"},
            )

        except Exception as exc:
            return self._error_result(
                "Failed to register WhatsApp template.",
                error=exc,
                context=context,
                code="whatsapp_template_register_failed",
            )

    def approve_template(
        self,
        *,
        user_id: str,
        workspace_id: str,
        template_name: str,
        language: str = DEFAULT_TEMPLATE_LANGUAGE,
        role: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Mark an internal WhatsApp template as approved.

        This is an internal William/Jarvis approval flag and should usually be
        routed through Security Agent/admin dashboard before use.
        """

        return self._set_template_status(
            user_id=user_id,
            workspace_id=workspace_id,
            template_name=template_name,
            language=language,
            status=WhatsAppApprovalStatus.APPROVED,
            role=role,
            metadata=metadata,
        )

    def disable_template(
        self,
        *,
        user_id: str,
        workspace_id: str,
        template_name: str,
        language: str = DEFAULT_TEMPLATE_LANGUAGE,
        role: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Disable an internal WhatsApp template.
        """

        return self._set_template_status(
            user_id=user_id,
            workspace_id=workspace_id,
            template_name=template_name,
            language=language,
            status=WhatsAppApprovalStatus.DISABLED,
            role=role,
            metadata=metadata,
        )

    def list_templates(
        self,
        *,
        user_id: str,
        workspace_id: str,
        role: Optional[str] = None,
        status: Optional[Union[str, WhatsAppApprovalStatus]] = None,
        language: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        List registered WhatsApp templates available in the connector.
        """

        context = WhatsAppContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            metadata=metadata or {},
        )

        try:
            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            permission = self._check_permission(context, WhatsAppPermissionScope.MANAGE_TEMPLATES)
            if not permission["success"]:
                return permission

            normalized_status: Optional[WhatsAppApprovalStatus] = None
            if status is not None:
                normalized_status = self._normalize_approval_status(status)

            templates: List[Dict[str, Any]] = []
            for template in self._template_registry.values():
                if normalized_status is not None and template.status != normalized_status:
                    continue
                if language is not None and template.language != language:
                    continue
                templates.append(self._template_to_public_dict(template))

            return self._safe_result(
                success=True,
                message="WhatsApp templates retrieved successfully.",
                data={"templates": templates, "count": len(templates)},
                context=context,
                metadata={"operation": "list_templates"},
            )

        except Exception as exc:
            return self._error_result(
                "Failed to list WhatsApp templates.",
                error=exc,
                context=context,
                code="whatsapp_template_list_failed",
            )

    def test_connection(
        self,
        *,
        user_id: str,
        workspace_id: str,
        role: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate local connector configuration and optional provider connectivity.

        In dry-run mode, no external request is made.
        """

        context = WhatsAppContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            metadata=metadata or {},
        )

        try:
            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            permission = self._check_permission(context, WhatsAppPermissionScope.TEST_CONNECTION)
            if not permission["success"]:
                return permission

            config_result = self.validate_configuration(
                user_id=user_id,
                workspace_id=workspace_id,
                role=role,
                metadata=metadata,
            )

            if not config_result["success"]:
                return config_result

            if self.config.dry_run or self.config.provider == WhatsAppProvider.MOCK:
                return self._safe_result(
                    success=True,
                    message="WhatsApp connector configuration is valid. Dry-run mode is active.",
                    data={
                        "provider": self.config.provider.value,
                        "dry_run": self.config.dry_run,
                        "external_request_made": False,
                    },
                    context=context,
                    metadata={"operation": "test_connection"},
                )

            if requests is None:
                return self._error_result(
                    "Python requests package is not installed, so live WhatsApp connection cannot be tested.",
                    context=context,
                    code="requests_not_installed",
                    error=None,
                )

            endpoint = self._meta_phone_number_endpoint()
            response = requests.get(
                endpoint,
                headers=self._meta_headers(),
                timeout=self.config.timeout_seconds,
            )

            response_data = self._safe_response_json(response)
            success = 200 <= response.status_code < 300

            self._log_audit_event(
                event_type="whatsapp_connection_tested",
                context=context,
                data={
                    "provider": self.config.provider.value,
                    "status_code": response.status_code,
                    "success": success,
                },
            )

            if not success:
                return self._error_result(
                    "WhatsApp provider connection test failed.",
                    context=context,
                    code="whatsapp_connection_failed",
                    error=response_data,
                    metadata={"status_code": response.status_code},
                )

            return self._safe_result(
                success=True,
                message="WhatsApp provider connection test succeeded.",
                data={
                    "provider": self.config.provider.value,
                    "status_code": response.status_code,
                    "provider_response": response_data,
                },
                context=context,
                metadata={"operation": "test_connection"},
            )

        except Exception as exc:
            return self._error_result(
                "Failed to test WhatsApp connection.",
                error=exc,
                context=context,
                code="whatsapp_connection_test_failed",
            )

    def validate_configuration(
        self,
        *,
        user_id: str,
        workspace_id: str,
        role: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate connector configuration without sending a message.
        """

        context = WhatsAppContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            metadata=metadata or {},
        )

        issues: List[str] = []

        try:
            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            if self.config.provider == WhatsAppProvider.META_WHATSAPP_CLOUD:
                if not self.config.dry_run:
                    if not self.config.phone_number_id:
                        issues.append("Missing WILLIAM_WHATSAPP_PHONE_NUMBER_ID.")
                    if not self.config.access_token:
                        issues.append("Missing WILLIAM_WHATSAPP_ACCESS_TOKEN.")
                    if requests is None:
                        issues.append("Missing dependency: requests.")

                if self.config.timeout_seconds <= 0:
                    issues.append("timeout_seconds must be greater than zero.")

                if self.config.rate_limit_per_minute <= 0:
                    issues.append("rate_limit_per_minute must be greater than zero.")

                if not LANGUAGE_RE.match(self.config.default_language):
                    issues.append("default_language is invalid.")

            if issues:
                return self._safe_result(
                    success=False,
                    message="WhatsApp connector configuration has issues.",
                    data={"issues": issues},
                    error={"code": "invalid_whatsapp_configuration", "details": issues},
                    context=context,
                    metadata={"operation": "validate_configuration"},
                )

            return self._safe_result(
                success=True,
                message="WhatsApp connector configuration is valid.",
                data={
                    "provider": self.config.provider.value,
                    "dry_run": self.config.dry_run,
                    "default_language": self.config.default_language,
                    "rate_limit_per_minute": self.config.rate_limit_per_minute,
                },
                context=context,
                metadata={"operation": "validate_configuration"},
            )

        except Exception as exc:
            return self._error_result(
                "Failed to validate WhatsApp configuration.",
                error=exc,
                context=context,
                code="whatsapp_configuration_validation_failed",
            )

    def get_registry_metadata(self) -> Dict[str, Any]:
        """
        Return metadata for Agent Registry / Agent Loader discovery.
        """

        return {
            "agent_name": DEFAULT_AGENT_NAME,
            "class_name": self.__class__.__name__,
            "module": "agents.workflow_agent.whatsapp_connector",
            "agent_module": "Workflow Agent",
            "file": "whatsapp_connector.py",
            "purpose": "Sends approved WhatsApp internal alerts/templates with permission.",
            "public_methods": [
                "send_internal_alert",
                "send_template_message",
                "register_template",
                "approve_template",
                "disable_template",
                "list_templates",
                "test_connection",
                "validate_configuration",
            ],
            "permissions": [scope.value for scope in WhatsAppPermissionScope],
            "supports_user_workspace_isolation": True,
            "requires_security_agent": True,
            "supports_verification_payload": True,
            "supports_memory_payload": True,
            "safe_to_import": True,
            "dry_run_default": True,
            "provider": self.config.provider.value,
        }

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(self, context: WhatsAppContext) -> Dict[str, Any]:
        """
        Validate required SaaS isolation context.

        Required by William/Jarvis architecture.
        """

        missing: List[str] = []
        if not getattr(context, "user_id", None):
            missing.append("user_id")
        if not getattr(context, "workspace_id", None):
            missing.append("workspace_id")

        if missing:
            return self._safe_result(
                success=False,
                message="Missing required SaaS execution context.",
                data={"missing": missing},
                error={"code": "missing_task_context", "missing": missing},
                context=context,
                metadata={"operation": "validate_task_context"},
            )

        return self._safe_result(
            success=True,
            message="Task context is valid.",
            data={
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "request_id": context.request_id,
            },
            context=context,
            metadata={"operation": "validate_task_context"},
        )

    def _requires_security_check(self, request: WhatsAppSendRequest) -> bool:
        """
        Determine whether Security Agent approval is required.

        Required by William/Jarvis architecture.
        """

        if request.require_security_approval:
            return True

        if self.config.require_security_for_all_sends:
            return True

        if self.config.require_security_for_critical and request.priority == WhatsAppPriority.CRITICAL:
            return True

        if len(request.recipients) > 1:
            return True

        if request.message_type == WhatsAppMessageType.TEXT and not self.config.allow_raw_text_messages:
            return True

        return False

    def _request_security_approval(self, request: WhatsAppSendRequest) -> Dict[str, Any]:
        """
        Request permission approval from Security Agent or local fallback.

        Required by William/Jarvis architecture.

        If a security_approval_callback is provided, it is called with a safe
        payload. Otherwise, a conservative local approval fallback is used:
            - allow dry-run sends
            - allow only approved templates/raw internal alerts after local checks
        """

        approval_payload = {
            "action": "send_whatsapp_message",
            "permission_scope": (
                WhatsAppPermissionScope.SEND_TEMPLATE.value
                if request.message_type == WhatsAppMessageType.TEMPLATE
                else WhatsAppPermissionScope.SEND_INTERNAL_ALERT.value
            ),
            "risk_level": self._risk_level_for_request(request),
            "user_id": request.context.user_id,
            "workspace_id": request.context.workspace_id,
            "request_id": request.context.request_id,
            "task_id": request.context.task_id,
            "message_type": request.message_type.value,
            "recipient_count": len(request.recipients),
            "recipients": [
                self._recipient_to_log_dict(recipient)
                for recipient in request.recipients
            ],
            "template_name": request.template_name,
            "language": request.language,
            "priority": request.priority.value,
            "dry_run": self.config.dry_run,
            "metadata": self._safe_metadata(request.metadata),
            "timestamp": utc_now_iso(),
        }

        try:
            if self.security_approval_callback:
                response = self.security_approval_callback(approval_payload)
                if not isinstance(response, dict):
                    return {
                        "approved": False,
                        "reason": "Security callback returned invalid response.",
                        "data": {"callback_response": str(response)},
                    }

                approved = bool(response.get("approved") or response.get("success"))
                return {
                    "approved": approved,
                    "reason": response.get("reason") or response.get("message") or "Security callback processed request.",
                    "data": response,
                }

            local_approval = self._local_security_fallback(request)
            return local_approval

        except Exception as exc:
            return {
                "approved": False,
                "reason": "Security approval failed with exception.",
                "error": {
                    "code": "security_approval_exception",
                    "message": str(exc),
                    "type": exc.__class__.__name__,
                },
            }

    def _prepare_verification_payload(
        self,
        request: WhatsAppSendRequest,
        send_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Required by William/Jarvis architecture.
        """

        return {
            "verification_type": "whatsapp_send",
            "agent": DEFAULT_AGENT_NAME,
            "user_id": request.context.user_id,
            "workspace_id": request.context.workspace_id,
            "request_id": request.context.request_id,
            "task_id": request.context.task_id,
            "success": bool(send_result.get("success")),
            "message_type": request.message_type.value,
            "template_name": request.template_name,
            "language": request.language,
            "recipient_count": len(request.recipients),
            "priority": request.priority.value,
            "dry_run": self.config.dry_run,
            "provider": self.config.provider.value,
            "provider_message_ids": self._extract_provider_message_ids(send_result),
            "idempotency_key": request.idempotency_key,
            "timestamp": utc_now_iso(),
            "metadata": {
                "result_message": send_result.get("message"),
                "error": send_result.get("error"),
            },
        }

    def _prepare_memory_payload(
        self,
        request: WhatsAppSendRequest,
        send_result: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Required by William/Jarvis architecture.

        This payload intentionally avoids storing full phone numbers or raw
        sensitive message content.
        """

        return {
            "memory_type": "workflow_whatsapp_activity",
            "agent": DEFAULT_AGENT_NAME,
            "user_id": request.context.user_id,
            "workspace_id": request.context.workspace_id,
            "task_id": request.context.task_id,
            "request_id": request.context.request_id,
            "summary": self._memory_summary(request, send_result),
            "safe_context": {
                "message_type": request.message_type.value,
                "template_name": request.template_name,
                "priority": request.priority.value,
                "recipient_count": len(request.recipients),
                "success": bool(send_result.get("success")),
                "dry_run": self.config.dry_run,
            },
            "timestamp": utc_now_iso(),
        }

    def _emit_agent_event(
        self,
        *,
        event_type: str,
        context: WhatsAppContext,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Emit event for dashboard/API/event bus.

        Required by William/Jarvis architecture.
        """

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": DEFAULT_AGENT_NAME,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "source": context.source,
            "data": data or {},
            "timestamp": utc_now_iso(),
        }

        try:
            if self.event_callback:
                self.event_callback(event)
            else:
                self.logger.debug("Agent event emitted: %s", safe_json_dumps(event))
        except Exception as exc:
            self.logger.warning("Failed to emit WhatsApp connector event: %s", exc)

    def _log_audit_event(
        self,
        *,
        event_type: str,
        context: WhatsAppContext,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        Required by William/Jarvis architecture.
        """

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": DEFAULT_AGENT_NAME,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "source": context.source,
            "ip_address": context.ip_address,
            "user_agent": context.user_agent,
            "data": self._safe_metadata(data or {}),
            "timestamp": utc_now_iso(),
        }

        try:
            if self.audit_callback:
                self.audit_callback(audit_event)
            else:
                self.logger.info("Audit event: %s", safe_json_dumps(audit_event))
        except Exception as exc:
            self.logger.warning("Failed to log WhatsApp connector audit event: %s", exc)

    def _safe_result(
        self,
        *,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
        context: Optional[WhatsAppContext] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return structured JSON-style result.

        Required by William/Jarvis architecture.
        """

        result = {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": result_metadata(context, **(metadata or {})),
        }
        return result

    def _error_result(
        self,
        message: str,
        *,
        error: Optional[Any],
        context: Optional[WhatsAppContext] = None,
        code: str = "whatsapp_connector_error",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return structured error result.

        Required by William/Jarvis architecture.
        """

        if isinstance(error, Exception):
            error_payload: Any = {
                "code": code,
                "type": error.__class__.__name__,
                "message": str(error),
            }
        elif error is None:
            error_payload = {"code": code, "message": message}
        elif isinstance(error, dict):
            error_payload = {"code": code, **error}
        else:
            error_payload = {"code": code, "message": str(error)}

        self.logger.error("%s | error=%s", message, safe_json_dumps(error_payload))

        return self._safe_result(
            success=False,
            message=message,
            data={},
            error=error_payload,
            context=context,
            metadata=metadata or {},
        )

    # -----------------------------------------------------------------------
    # Internal send flow
    # -----------------------------------------------------------------------

    def _send(self, request: WhatsAppSendRequest) -> Dict[str, Any]:
        """
        Core send flow for text/template messages.
        """

        validation = self._validate_send_request(request)
        if not validation["success"]:
            return validation

        idem_result = self._check_idempotency(request)
        if idem_result is not None:
            return idem_result

        rate_limit = self._enforce_rate_limit(request.context)
        if not rate_limit["success"]:
            return rate_limit

        if self._requires_security_check(request):
            approval = self._request_security_approval(request)
            if not approval.get("approved"):
                denied = self._safe_result(
                    success=False,
                    message="WhatsApp send blocked by security approval gate.",
                    data={"approval": approval},
                    error={
                        "code": "security_approval_denied",
                        "reason": approval.get("reason", "Not approved."),
                    },
                    context=request.context,
                    metadata={"operation": "send_whatsapp", "security_checked": True},
                )

                self._log_audit_event(
                    event_type="whatsapp_send_denied",
                    context=request.context,
                    data={
                        "reason": approval.get("reason"),
                        "message_type": request.message_type.value,
                        "template_name": request.template_name,
                        "recipient_count": len(request.recipients),
                    },
                )
                return denied

        self._log_audit_event(
            event_type="whatsapp_send_started",
            context=request.context,
            data={
                "message_type": request.message_type.value,
                "template_name": request.template_name,
                "recipient_count": len(request.recipients),
                "priority": request.priority.value,
                "dry_run": self.config.dry_run,
            },
        )

        if self.config.dry_run or self.config.provider == WhatsAppProvider.MOCK:
            send_result = self._dry_run_send(request)
        else:
            send_result = self._provider_send(request)

        verification_payload = self._prepare_verification_payload(request, send_result)
        memory_payload = self._prepare_memory_payload(request, send_result)

        send_result.setdefault("data", {})
        send_result["data"]["verification_payload"] = verification_payload
        send_result["data"]["memory_payload"] = memory_payload

        self._store_idempotency(request, send_result)

        self._emit_agent_event(
            event_type="workflow.whatsapp.send_completed",
            context=request.context,
            data={
                "success": send_result.get("success"),
                "message_type": request.message_type.value,
                "template_name": request.template_name,
                "recipient_count": len(request.recipients),
                "priority": request.priority.value,
                "dry_run": self.config.dry_run,
            },
        )

        self._log_audit_event(
            event_type="whatsapp_send_completed",
            context=request.context,
            data={
                "success": send_result.get("success"),
                "message_type": request.message_type.value,
                "template_name": request.template_name,
                "recipient_count": len(request.recipients),
                "provider": self.config.provider.value,
                "dry_run": self.config.dry_run,
            },
        )

        return send_result

    def _validate_send_request(self, request: WhatsAppSendRequest) -> Dict[str, Any]:
        """
        Validate send request before permission/security/provider calls.
        """

        context_result = self._validate_task_context(request.context)
        if not context_result["success"]:
            return context_result

        if not request.recipients:
            return self._error_result(
                "At least one WhatsApp recipient is required.",
                context=request.context,
                code="missing_whatsapp_recipients",
                error=None,
            )

        invalid_numbers = [
            recipient.phone_number
            for recipient in request.recipients
            if not validate_phone_number(recipient.phone_number)
        ]
        if invalid_numbers:
            return self._error_result(
                "One or more WhatsApp recipients are invalid. Use E.164 format like +15551234567.",
                context=request.context,
                code="invalid_whatsapp_recipient",
                error={
                    "invalid_recipients": [
                        redact_phone(number) if self.config.redact_phone_in_logs else number
                        for number in invalid_numbers
                    ]
                },
            )

        if request.message_type == WhatsAppMessageType.TEXT:
            permission = self._check_permission(request.context, WhatsAppPermissionScope.SEND_INTERNAL_ALERT)
            if not permission["success"]:
                return permission

            if not self.config.allow_raw_text_messages:
                return self._error_result(
                    "Raw WhatsApp text messages are disabled by connector configuration.",
                    context=request.context,
                    code="raw_text_disabled",
                    error=None,
                )

            if not request.text:
                return self._error_result(
                    "WhatsApp text message cannot be empty.",
                    context=request.context,
                    code="empty_whatsapp_message",
                    error=None,
                )

            if len(request.text) > self.config.max_message_length:
                return self._error_result(
                    "WhatsApp text message exceeds maximum length.",
                    context=request.context,
                    code="whatsapp_message_too_long",
                    error={"max_length": self.config.max_message_length},
                )

        elif request.message_type == WhatsAppMessageType.TEMPLATE:
            permission = self._check_permission(request.context, WhatsAppPermissionScope.SEND_TEMPLATE)
            if not permission["success"]:
                return permission

            if not request.template_name:
                return self._error_result(
                    "WhatsApp template name is required.",
                    context=request.context,
                    code="missing_template_name",
                    error=None,
                )

            template_validation = self._validate_template_use(request)
            if not template_validation["success"]:
                return template_validation

        else:
            return self._error_result(
                "Unsupported WhatsApp message type.",
                context=request.context,
                code="unsupported_whatsapp_message_type",
                error={"message_type": str(request.message_type)},
            )

        config_validation = self._validate_provider_ready(request.context)
        if not config_validation["success"]:
            return config_validation

        return self._safe_result(
            success=True,
            message="WhatsApp send request is valid.",
            data={"request_id": request.context.request_id},
            context=request.context,
            metadata={"operation": "validate_send_request"},
        )

    def _validate_provider_ready(self, context: WhatsAppContext) -> Dict[str, Any]:
        """
        Validate provider readiness for dry-run or live sends.
        """

        if self.config.dry_run or self.config.provider == WhatsAppProvider.MOCK:
            return self._safe_result(
                success=True,
                message="WhatsApp provider ready in dry-run/mock mode.",
                data={"dry_run": True, "provider": self.config.provider.value},
                context=context,
                metadata={"operation": "validate_provider_ready"},
            )

        if self.config.provider == WhatsAppProvider.META_WHATSAPP_CLOUD:
            issues: List[str] = []
            if requests is None:
                issues.append("requests dependency is not installed")
            if not self.config.phone_number_id:
                issues.append("phone_number_id is missing")
            if not self.config.access_token:
                issues.append("access_token is missing")

            if issues:
                return self._safe_result(
                    success=False,
                    message="WhatsApp provider is not ready for live sends.",
                    data={"issues": issues},
                    error={"code": "provider_not_ready", "issues": issues},
                    context=context,
                    metadata={"operation": "validate_provider_ready"},
                )

        return self._safe_result(
            success=True,
            message="WhatsApp provider is ready.",
            data={"provider": self.config.provider.value},
            context=context,
            metadata={"operation": "validate_provider_ready"},
        )

    def _dry_run_send(self, request: WhatsAppSendRequest) -> Dict[str, Any]:
        """
        Simulate WhatsApp send without external API call.
        """

        simulated_messages: List[Dict[str, Any]] = []

        for recipient in request.recipients:
            simulated_id = f"dryrun_{sha256_text(request.context.request_id + recipient.phone_number)[:18]}"
            simulated_messages.append(
                {
                    "recipient": self._recipient_to_log_dict(recipient),
                    "message_id": simulated_id,
                    "status": "simulated",
                }
            )

        return self._safe_result(
            success=True,
            message="WhatsApp message simulated successfully in dry-run mode.",
            data={
                "provider": self.config.provider.value,
                "dry_run": True,
                "message_type": request.message_type.value,
                "template_name": request.template_name,
                "recipient_count": len(request.recipients),
                "messages": simulated_messages,
            },
            context=request.context,
            metadata={"operation": "dry_run_send"},
        )

    def _provider_send(self, request: WhatsAppSendRequest) -> Dict[str, Any]:
        """
        Send request through configured provider.
        """

        if self.config.provider == WhatsAppProvider.META_WHATSAPP_CLOUD:
            return self._send_via_meta_cloud_api(request)

        return self._error_result(
            "Unsupported WhatsApp provider.",
            context=request.context,
            code="unsupported_whatsapp_provider",
            error={"provider": self.config.provider.value},
        )

    def _send_via_meta_cloud_api(self, request: WhatsAppSendRequest) -> Dict[str, Any]:
        """
        Send WhatsApp messages through Meta WhatsApp Cloud API.

        One provider call is made per recipient to keep error handling precise.
        """

        if requests is None:
            return self._error_result(
                "Python requests package is required for live WhatsApp sends.",
                context=request.context,
                code="requests_not_installed",
                error=None,
            )

        endpoint = self._meta_messages_endpoint()
        headers = self._meta_headers()
        provider_results: List[Dict[str, Any]] = []
        failures: List[Dict[str, Any]] = []

        for recipient in request.recipients:
            payload = self._build_meta_payload(request, recipient)

            try:
                response = requests.post(
                    endpoint,
                    headers=headers,
                    json=payload,
                    timeout=self.config.timeout_seconds,
                )

                response_data = self._safe_response_json(response)
                item_success = 200 <= response.status_code < 300

                item_result = {
                    "success": item_success,
                    "status_code": response.status_code,
                    "recipient": self._recipient_to_log_dict(recipient),
                    "provider_response": response_data,
                }

                provider_results.append(item_result)

                if not item_success:
                    failures.append(item_result)

            except Exception as exc:
                item_result = {
                    "success": False,
                    "recipient": self._recipient_to_log_dict(recipient),
                    "error": {
                        "type": exc.__class__.__name__,
                        "message": str(exc),
                    },
                }
                provider_results.append(item_result)
                failures.append(item_result)

        if failures:
            return self._safe_result(
                success=False,
                message="One or more WhatsApp messages failed to send.",
                data={
                    "provider": self.config.provider.value,
                    "dry_run": False,
                    "message_type": request.message_type.value,
                    "template_name": request.template_name,
                    "recipient_count": len(request.recipients),
                    "results": provider_results,
                    "failures": failures,
                },
                error={
                    "code": "whatsapp_provider_send_failed",
                    "failed_count": len(failures),
                },
                context=request.context,
                metadata={"operation": "meta_cloud_send"},
            )

        return self._safe_result(
            success=True,
            message="WhatsApp message sent successfully.",
            data={
                "provider": self.config.provider.value,
                "dry_run": False,
                "message_type": request.message_type.value,
                "template_name": request.template_name,
                "recipient_count": len(request.recipients),
                "results": provider_results,
            },
            context=request.context,
            metadata={"operation": "meta_cloud_send"},
        )

    # -----------------------------------------------------------------------
    # Template handling
    # -----------------------------------------------------------------------

    def _register_builtin_templates(self) -> None:
        """
        Register safe built-in internal templates.

        These are internal William/Jarvis examples and can be replaced or
        extended from dashboard/config later.
        """

        builtins = [
            WhatsAppTemplate(
                name="workflow_alert",
                language=DEFAULT_TEMPLATE_LANGUAGE,
                category="internal_alert",
                body_preview="Workflow alert: {{title}} - {{details}}",
                status=WhatsAppApprovalStatus.APPROVED,
                required_variables=("title", "details"),
                allowed_roles=(),
                internal_only=True,
                metadata={"builtin": True},
            ),
            WhatsAppTemplate(
                name="lead_captured_alert",
                language=DEFAULT_TEMPLATE_LANGUAGE,
                category="internal_alert",
                body_preview="New lead captured: {{lead_name}} - {{service_interest}}",
                status=WhatsAppApprovalStatus.APPROVED,
                required_variables=("lead_name", "service_interest"),
                allowed_roles=(),
                internal_only=True,
                metadata={"builtin": True},
            ),
            WhatsAppTemplate(
                name="approval_required",
                language=DEFAULT_TEMPLATE_LANGUAGE,
                category="internal_approval",
                body_preview="Approval required for {{workflow_name}}.",
                status=WhatsAppApprovalStatus.APPROVED,
                required_variables=("workflow_name",),
                allowed_roles=(),
                internal_only=True,
                metadata={"builtin": True},
            ),
            WhatsAppTemplate(
                name="workflow_failed_alert",
                language=DEFAULT_TEMPLATE_LANGUAGE,
                category="internal_alert",
                body_preview="Workflow failed: {{workflow_name}} - {{error_summary}}",
                status=WhatsAppApprovalStatus.APPROVED,
                required_variables=("workflow_name", "error_summary"),
                allowed_roles=(),
                internal_only=True,
                metadata={"builtin": True},
            ),
        ]

        for template in builtins:
            self._template_registry[self._template_key(template.name, template.language)] = template

    def _validate_template_use(self, request: WhatsAppSendRequest) -> Dict[str, Any]:
        """
        Validate template approval, role restrictions, and required variables.
        """

        assert request.template_name is not None

        template = self._get_template(request.template_name, request.language)
        if template is None:
            if self.config.allow_unapproved_templates:
                return self._safe_result(
                    success=True,
                    message="Template not registered locally, but unapproved templates are allowed by configuration.",
                    data={"template_name": request.template_name},
                    context=request.context,
                    metadata={"operation": "validate_template_use"},
                )

            return self._error_result(
                "WhatsApp template is not registered or approved in connector registry.",
                context=request.context,
                code="template_not_registered",
                error={
                    "template_name": request.template_name,
                    "language": request.language,
                },
            )

        if template.status != WhatsAppApprovalStatus.APPROVED and not self.config.allow_unapproved_templates:
            return self._error_result(
                "WhatsApp template is not approved for sending.",
                context=request.context,
                code="template_not_approved",
                error={
                    "template_name": template.name,
                    "language": template.language,
                    "status": template.status.value,
                },
            )

        if template.allowed_roles:
            role = request.context.role or ""
            if role not in template.allowed_roles:
                return self._error_result(
                    "Current role is not allowed to send this WhatsApp template.",
                    context=request.context,
                    code="template_role_not_allowed",
                    error={
                        "template_name": template.name,
                        "role": role,
                        "allowed_roles": list(template.allowed_roles),
                    },
                )

        missing_variables = [
            variable
            for variable in template.required_variables
            if variable not in request.variables or request.variables.get(variable) in (None, "")
        ]

        if missing_variables:
            return self._error_result(
                "Missing required WhatsApp template variables.",
                context=request.context,
                code="missing_template_variables",
                error={
                    "template_name": template.name,
                    "missing_variables": missing_variables,
                },
            )

        return self._safe_result(
            success=True,
            message="WhatsApp template use is valid.",
            data={"template": self._template_to_public_dict(template)},
            context=request.context,
            metadata={"operation": "validate_template_use"},
        )

    def _set_template_status(
        self,
        *,
        user_id: str,
        workspace_id: str,
        template_name: str,
        language: str,
        status: WhatsAppApprovalStatus,
        role: Optional[str],
        metadata: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Shared helper for approving/disabling templates.
        """

        context = WhatsAppContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            metadata=metadata or {},
        )

        try:
            validation = self._validate_task_context(context)
            if not validation["success"]:
                return validation

            permission = self._check_permission(context, WhatsAppPermissionScope.MANAGE_TEMPLATES)
            if not permission["success"]:
                return permission

            key = self._template_key(template_name, language)
            template = self._template_registry.get(key)
            if template is None:
                return self._error_result(
                    "WhatsApp template not found.",
                    context=context,
                    code="template_not_found",
                    error={"template_name": normalize_template_name(template_name), "language": language},
                )

            updated = WhatsAppTemplate(
                name=template.name,
                language=template.language,
                category=template.category,
                body_preview=template.body_preview,
                status=status,
                required_variables=template.required_variables,
                allowed_roles=template.allowed_roles,
                internal_only=template.internal_only,
                created_at=template.created_at,
                updated_at=utc_now_iso(),
                metadata=template.metadata,
            )

            self._template_registry[key] = updated

            self._log_audit_event(
                event_type="whatsapp_template_status_changed",
                context=context,
                data={
                    "template_name": updated.name,
                    "language": updated.language,
                    "status": updated.status.value,
                },
            )

            self._emit_agent_event(
                event_type="workflow.whatsapp.template_status_changed",
                context=context,
                data={
                    "template_name": updated.name,
                    "language": updated.language,
                    "status": updated.status.value,
                },
            )

            return self._safe_result(
                success=True,
                message=f"WhatsApp template status changed to {status.value}.",
                data={"template": self._template_to_public_dict(updated)},
                context=context,
                metadata={"operation": "set_template_status"},
            )

        except Exception as exc:
            return self._error_result(
                "Failed to update WhatsApp template status.",
                error=exc,
                context=context,
                code="whatsapp_template_status_update_failed",
            )

    def _get_template(self, template_name: str, language: str) -> Optional[WhatsAppTemplate]:
        """Get registered template by name/language."""

        return self._template_registry.get(self._template_key(template_name, language))

    def _template_key(self, template_name: str, language: str) -> str:
        """Build registry key."""

        return f"{normalize_template_name(template_name)}::{language or self.config.default_language}"

    def _template_to_public_dict(self, template: WhatsAppTemplate) -> Dict[str, Any]:
        """Convert template dataclass to safe public dict."""

        data = asdict(template)
        data["status"] = template.status.value
        data["required_variables"] = list(template.required_variables)
        data["allowed_roles"] = list(template.allowed_roles)
        return data

    # -----------------------------------------------------------------------
    # Provider payload helpers
    # -----------------------------------------------------------------------

    def _build_meta_payload(
        self,
        request: WhatsAppSendRequest,
        recipient: WhatsAppRecipient,
    ) -> Dict[str, Any]:
        """
        Build Meta WhatsApp Cloud API message payload.
        """

        if request.message_type == WhatsAppMessageType.TEXT:
            return {
                "messaging_product": "whatsapp",
                "recipient_type": "individual",
                "to": recipient.phone_number.replace("+", ""),
                "type": "text",
                "text": {
                    "preview_url": False,
                    "body": request.text or "",
                },
            }

        if request.message_type == WhatsAppMessageType.TEMPLATE:
            components = self._build_meta_template_components(request.variables)
            payload: Dict[str, Any] = {
                "messaging_product": "whatsapp",
                "recipient_type": "individual",
                "to": recipient.phone_number.replace("+", ""),
                "type": "template",
                "template": {
                    "name": request.template_name,
                    "language": {"code": request.language},
                },
            }

            if components:
                payload["template"]["components"] = components

            return payload

        raise ValueError(f"Unsupported message type: {request.message_type}")

    def _build_meta_template_components(self, variables: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Build simple body parameter components for Meta template variables.

        This connector sends variables as ordered text parameters based on sorted
        key order for deterministic output. A future workflow_templates.py file
        can extend this with rich headers/buttons.
        """

        if not variables:
            return []

        parameters = []
        for key in sorted(variables.keys()):
            value = variables[key]
            parameters.append(
                {
                    "type": "text",
                    "text": str(value),
                    "parameter_name": str(key),
                }
            )

        return [
            {
                "type": "body",
                "parameters": parameters,
            }
        ]

    def _meta_messages_endpoint(self) -> str:
        """Return Meta messages endpoint."""

        return (
            f"{self.config.base_url.rstrip('/')}/"
            f"{self.config.api_version}/"
            f"{self.config.phone_number_id}/messages"
        )

    def _meta_phone_number_endpoint(self) -> str:
        """Return Meta phone number endpoint for connection test."""

        return (
            f"{self.config.base_url.rstrip('/')}/"
            f"{self.config.api_version}/"
            f"{self.config.phone_number_id}"
        )

    def _meta_headers(self) -> Dict[str, str]:
        """Return Meta Cloud API headers."""

        return {
            "Authorization": f"Bearer {self.config.access_token}",
            "Content-Type": "application/json",
            "User-Agent": self.config.user_agent,
        }

    def _safe_response_json(self, response: Any) -> Dict[str, Any]:
        """Read response JSON safely."""

        try:
            return response.json()
        except Exception:
            return {
                "text": getattr(response, "text", ""),
                "status_code": getattr(response, "status_code", None),
            }

    # -----------------------------------------------------------------------
    # Permissions, security, rate limit, idempotency
    # -----------------------------------------------------------------------

    def _check_permission(
        self,
        context: WhatsAppContext,
        scope: WhatsAppPermissionScope,
    ) -> Dict[str, Any]:
        """
        Local permission hook.

        The real Security Agent/permissions system can override this via
        BaseAgent in the future. This fallback allows safe import/testing while
        enforcing context presence and role-aware template restrictions.
        """

        if not context.user_id or not context.workspace_id:
            return self._safe_result(
                success=False,
                message="Permission denied because user/workspace context is missing.",
                data={"scope": scope.value},
                error={"code": "permission_context_missing", "scope": scope.value},
                context=context,
                metadata={"operation": "check_permission"},
            )

        return self._safe_result(
            success=True,
            message="Permission check passed.",
            data={"scope": scope.value, "allowed": True},
            context=context,
            metadata={"operation": "check_permission"},
        )

    def _local_security_fallback(self, request: WhatsAppSendRequest) -> Dict[str, Any]:
        """
        Conservative local fallback when Security Agent callback is not configured.
        """

        if not request.context.user_id or not request.context.workspace_id:
            return {
                "approved": False,
                "reason": "Missing SaaS isolation context.",
            }

        if request.priority == WhatsAppPriority.CRITICAL and not self.config.dry_run:
            return {
                "approved": False,
                "reason": "Critical live WhatsApp sends require configured Security Agent approval callback.",
            }

        if len(request.recipients) > 10 and not self.config.dry_run:
            return {
                "approved": False,
                "reason": "Bulk live WhatsApp sends require configured Security Agent approval callback.",
            }

        if request.message_type == WhatsAppMessageType.TEMPLATE and request.template_name:
            template = self._get_template(request.template_name, request.language)
            if template and template.status == WhatsAppApprovalStatus.APPROVED:
                return {
                    "approved": True,
                    "reason": "Local fallback approved registered internal template.",
                }

        if request.message_type == WhatsAppMessageType.TEXT and self.config.allow_raw_text_messages:
            return {
                "approved": True,
                "reason": "Local fallback approved internal text alert.",
            }

        return {
            "approved": False,
            "reason": "Local fallback could not approve request.",
        }

    def _risk_level_for_request(self, request: WhatsAppSendRequest) -> str:
        """Calculate simple risk level for Security Agent."""

        if request.priority == WhatsAppPriority.CRITICAL:
            return "critical"
        if len(request.recipients) > 10:
            return "high"
        if request.message_type == WhatsAppMessageType.TEXT:
            return "medium"
        return "low"

    def _enforce_rate_limit(self, context: WhatsAppContext) -> Dict[str, Any]:
        """
        Enforce simple in-memory connector rate limit.

        Production deployments can replace this with Redis/workspace-level rate
        limits in notification_engine.py or workflow_monitor.py.
        """

        now = time.time()
        window_start = now - 60
        self._send_timestamps = [ts for ts in self._send_timestamps if ts >= window_start]

        if len(self._send_timestamps) >= self.config.rate_limit_per_minute:
            return self._safe_result(
                success=False,
                message="WhatsApp connector rate limit exceeded.",
                data={
                    "rate_limit_per_minute": self.config.rate_limit_per_minute,
                    "current_window_count": len(self._send_timestamps),
                },
                error={"code": "whatsapp_rate_limit_exceeded"},
                context=context,
                metadata={"operation": "rate_limit"},
            )

        self._send_timestamps.append(now)

        return self._safe_result(
            success=True,
            message="Rate limit check passed.",
            data={
                "rate_limit_per_minute": self.config.rate_limit_per_minute,
                "current_window_count": len(self._send_timestamps),
            },
            context=context,
            metadata={"operation": "rate_limit"},
        )

    def _check_idempotency(self, request: WhatsAppSendRequest) -> Optional[Dict[str, Any]]:
        """
        Return cached result if idempotency key was already used.
        """

        key = request.idempotency_key or self._derive_idempotency_key(request)
        object.__setattr__(request, "idempotency_key", key)

        cached = self._idempotency_cache.get(key)
        if cached is None:
            return None

        cached_copy = dict(cached)
        cached_copy["metadata"] = dict(cached_copy.get("metadata", {}))
        cached_copy["metadata"]["idempotent_replay"] = True
        cached_copy["message"] = "WhatsApp send skipped because idempotency key was already processed."
        return cached_copy

    def _store_idempotency(self, request: WhatsAppSendRequest, result: Dict[str, Any]) -> None:
        """Store idempotency result."""

        key = request.idempotency_key or self._derive_idempotency_key(request)
        self._idempotency_cache[key] = result

        if len(self._idempotency_cache) > 1000:
            oldest_key = next(iter(self._idempotency_cache.keys()))
            self._idempotency_cache.pop(oldest_key, None)

    def _derive_idempotency_key(self, request: WhatsAppSendRequest) -> str:
        """Derive deterministic idempotency key for duplicate prevention."""

        payload = {
            "user_id": request.context.user_id,
            "workspace_id": request.context.workspace_id,
            "task_id": request.context.task_id,
            "request_id": request.context.request_id,
            "message_type": request.message_type.value,
            "template_name": request.template_name,
            "text": request.text,
            "variables": request.variables,
            "recipients": [recipient.phone_number for recipient in request.recipients],
        }
        return sha256_text(safe_json_dumps(payload))

    # -----------------------------------------------------------------------
    # Normalization helpers
    # -----------------------------------------------------------------------

    def _normalize_recipients(
        self,
        recipients: Sequence[Union[str, Mapping[str, Any], WhatsAppRecipient]],
    ) -> List[WhatsAppRecipient]:
        """
        Normalize recipient input.
        """

        normalized: List[WhatsAppRecipient] = []

        for item in recipients:
            if isinstance(item, WhatsAppRecipient):
                normalized.append(
                    WhatsAppRecipient(
                        phone_number=normalize_phone_number(item.phone_number),
                        display_name=item.display_name,
                        user_ref=item.user_ref,
                        metadata=item.metadata,
                    )
                )
                continue

            if isinstance(item, str):
                normalized.append(WhatsAppRecipient(phone_number=normalize_phone_number(item)))
                continue

            if isinstance(item, Mapping):
                phone_number = (
                    item.get("phone_number")
                    or item.get("phone")
                    or item.get("number")
                    or item.get("whatsapp")
                )
                normalized.append(
                    WhatsAppRecipient(
                        phone_number=normalize_phone_number(str(phone_number or "")),
                        display_name=str(item.get("display_name") or item.get("name") or "") or None,
                        user_ref=str(item.get("user_ref") or item.get("user_id") or "") or None,
                        metadata=dict(item.get("metadata") or {}),
                    )
                )
                continue

            raise TypeError(f"Unsupported WhatsApp recipient type: {type(item).__name__}")

        deduped: Dict[str, WhatsAppRecipient] = {}
        for recipient in normalized:
            deduped[recipient.phone_number] = recipient

        return list(deduped.values())

    def _normalize_priority(self, priority: Union[str, WhatsAppPriority]) -> WhatsAppPriority:
        """Normalize priority value."""

        if isinstance(priority, WhatsAppPriority):
            return priority

        try:
            return WhatsAppPriority(str(priority).strip().lower())
        except Exception:
            return WhatsAppPriority.NORMAL

    def _normalize_approval_status(
        self,
        status: Union[str, WhatsAppApprovalStatus],
    ) -> WhatsAppApprovalStatus:
        """Normalize approval status."""

        if isinstance(status, WhatsAppApprovalStatus):
            return status

        try:
            return WhatsAppApprovalStatus(str(status).strip().lower())
        except Exception:
            return WhatsAppApprovalStatus.PENDING

    def _is_valid_template_name(self, template_name: str) -> bool:
        """Validate template name."""

        return bool(TEMPLATE_NAME_RE.match(template_name))

    # -----------------------------------------------------------------------
    # Safe output helpers
    # -----------------------------------------------------------------------

    def _recipient_to_log_dict(self, recipient: WhatsAppRecipient) -> Dict[str, Any]:
        """Convert recipient to safe log dict."""

        phone = recipient.phone_number
        if self.config.redact_phone_in_logs:
            phone = redact_phone(phone)

        return {
            "phone_number": phone,
            "display_name": recipient.display_name,
            "user_ref": recipient.user_ref,
        }

    def _safe_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Redact obvious sensitive values in metadata.
        """

        redacted: Dict[str, Any] = {}
        sensitive_keys = {
            "access_token",
            "token",
            "secret",
            "api_key",
            "password",
            "authorization",
            "phone_number_id",
        }

        for key, value in metadata.items():
            lower_key = str(key).lower()
            if any(sensitive in lower_key for sensitive in sensitive_keys):
                redacted[key] = "***redacted***"
            elif isinstance(value, str) and validate_phone_number(value):
                redacted[key] = redact_phone(value) if self.config.redact_phone_in_logs else value
            elif isinstance(value, dict):
                redacted[key] = self._safe_metadata(value)
            elif isinstance(value, list):
                redacted[key] = [
                    self._safe_metadata(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                redacted[key] = value

        return redacted

    def _extract_provider_message_ids(self, send_result: Dict[str, Any]) -> List[str]:
        """Extract provider message IDs from send result where available."""

        message_ids: List[str] = []
        data = send_result.get("data") or {}

        for item in data.get("messages", []) or []:
            if isinstance(item, dict) and item.get("message_id"):
                message_ids.append(str(item["message_id"]))

        for item in data.get("results", []) or []:
            provider_response = item.get("provider_response") if isinstance(item, dict) else None
            if isinstance(provider_response, dict):
                for message in provider_response.get("messages", []) or []:
                    if isinstance(message, dict) and message.get("id"):
                        message_ids.append(str(message["id"]))

        return message_ids

    def _memory_summary(
        self,
        request: WhatsAppSendRequest,
        send_result: Dict[str, Any],
    ) -> str:
        """Build safe memory summary."""

        status = "succeeded" if send_result.get("success") else "failed"
        if request.message_type == WhatsAppMessageType.TEMPLATE:
            return (
                f"WhatsApp template '{request.template_name}' {status} for "
                f"{len(request.recipients)} recipient(s) in workspace {request.context.workspace_id}."
            )

        return (
            f"WhatsApp internal alert {status} for "
            f"{len(request.recipients)} recipient(s) in workspace {request.context.workspace_id}."
        )

    # -----------------------------------------------------------------------
    # Config loading
    # -----------------------------------------------------------------------

    def _load_config(self) -> WhatsAppConnectorConfig:
        """
        Load config from WorkflowAgentConfig if available, otherwise environment.
        """

        if WorkflowAgentConfig is not None:
            try:
                cfg = WorkflowAgentConfig()  # type: ignore
                whatsapp_cfg = getattr(cfg, "whatsapp", None)

                if isinstance(whatsapp_cfg, WhatsAppConnectorConfig):
                    return whatsapp_cfg

                if isinstance(whatsapp_cfg, dict):
                    base = WhatsAppConnectorConfig.from_env()
                    for key, value in whatsapp_cfg.items():
                        if hasattr(base, key):
                            setattr(base, key, value)
                    return base

            except Exception:
                pass

        return WhatsAppConnectorConfig.from_env()


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def create_whatsapp_connector(
    config: Optional[WhatsAppConnectorConfig] = None,
    **kwargs: Any,
) -> WhatsAppConnector:
    """
    Factory for Agent Loader / Registry / FastAPI dependency injection.
    """

    return WhatsAppConnector(config=config, **kwargs)


# ---------------------------------------------------------------------------
# Module exports
# ---------------------------------------------------------------------------

__all__ = [
    "WhatsAppConnector",
    "WhatsAppConnectorConfig",
    "WhatsAppContext",
    "WhatsAppTemplate",
    "WhatsAppRecipient",
    "WhatsAppSendRequest",
    "WhatsAppProvider",
    "WhatsAppMessageType",
    "WhatsAppPriority",
    "WhatsAppPermissionScope",
    "WhatsAppApprovalStatus",
    "create_whatsapp_connector",
]


# ---------------------------------------------------------------------------
# Lightweight manual test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    connector = WhatsAppConnector(
        config=WhatsAppConnectorConfig(
            provider=WhatsAppProvider.MOCK,
            dry_run=True,
        )
    )

    result = connector.send_internal_alert(
        user_id="test_user",
        workspace_id="test_workspace",
        recipients=["+15551234567"],
        message="Workflow test alert from William/Jarvis.",
        priority="normal",
        metadata={"manual_test": True},
    )

    print(json.dumps(result, indent=2, default=str))