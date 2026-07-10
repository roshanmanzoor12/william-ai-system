"""
agents/workflow_agent/config.py

Workflow Agent configuration for William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    Centralized workflow settings for:
    - n8n integration
    - webhook validation/routing settings
    - retries and idempotency safety
    - approval/security gates
    - anti-spam/rate limiting
    - SaaS user/workspace scoped configuration
    - dashboard/API/registry compatibility

Architecture Notes:
    This module is intentionally import-safe and has no hard dependency on future
    William/Jarvis files. If BaseAgent, registry, event bus, audit logger, or
    security components are not available yet, this file still imports and works
    through local fallbacks.

    The WorkflowConfig class can be used by:
    - Master Agent routing
    - Workflow Agent
    - Security Agent approval flow
    - Verification Agent payload preparation
    - Memory Agent preference/context storage
    - Dashboard/API settings pages
    - Agent Registry and Agent Loader
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import logging
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# =============================================================================
# Safe optional imports / compatibility fallbacks
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for incomplete project state
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        This keeps this file safe to import even before the real William/Jarvis
        BaseAgent is implemented.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())


try:
    from agents.agent_registry import register_agent_module  # type: ignore
except Exception:  # pragma: no cover
    def register_agent_module(*args: Any, **kwargs: Any) -> bool:
        """Fallback registry hook."""
        return False


# =============================================================================
# Logging
# =============================================================================

LOGGER = logging.getLogger("william.workflow_agent.config")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# =============================================================================
# Constants
# =============================================================================

MODULE_NAME = "workflow_agent"
FILE_NAME = "config.py"
AGENT_NAME = "WorkflowConfig"
DEFAULT_VERSION = "1.0.0"

DEFAULT_MAX_RETRY_ATTEMPTS = 3
DEFAULT_RETRY_BASE_DELAY_SECONDS = 2.0
DEFAULT_RETRY_MAX_DELAY_SECONDS = 300.0
DEFAULT_RETRY_BACKOFF_MULTIPLIER = 2.0

DEFAULT_WEBHOOK_TIMEOUT_SECONDS = 20
DEFAULT_WEBHOOK_MAX_PAYLOAD_BYTES = 2_000_000
DEFAULT_N8N_TIMEOUT_SECONDS = 30

DEFAULT_ANTI_SPAM_WINDOW_SECONDS = 60
DEFAULT_ANTI_SPAM_MAX_EVENTS = 20
DEFAULT_IDEMPOTENCY_TTL_SECONDS = 86_400

SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:.@/]{1,160}$")
SAFE_WORKFLOW_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:.@/ ]{1,200}$")
SAFE_URL_SCHEME_PATTERN = re.compile(r"^https://", re.IGNORECASE)


# =============================================================================
# Enums
# =============================================================================

class WorkflowEnvironment(str, Enum):
    """Supported runtime environments."""

    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"
    TEST = "test"


class ApprovalMode(str, Enum):
    """Approval behavior for sensitive workflow actions."""

    NEVER = "never"
    ALWAYS = "always"
    SENSITIVE_ONLY = "sensitive_only"
    USER_OR_SECURITY = "user_or_security"


class RetryMode(str, Enum):
    """Retry policy mode."""

    NONE = "none"
    SAFE_ONLY = "safe_only"
    ALL_NON_DESTRUCTIVE = "all_non_destructive"


class WebhookAuthMode(str, Enum):
    """Webhook authentication method."""

    NONE = "none"
    SHARED_SECRET = "shared_secret"
    HMAC_SHA256 = "hmac_sha256"
    BEARER_TOKEN = "bearer_token"


class ConfigScope(str, Enum):
    """Configuration scope."""

    GLOBAL = "global"
    USER = "user"
    WORKSPACE = "workspace"
    USER_WORKSPACE = "user_workspace"


class SensitiveAction(str, Enum):
    """Sensitive workflow action categories."""

    SEND_EMAIL = "send_email"
    SEND_WHATSAPP = "send_whatsapp"
    SEND_SLACK = "send_slack"
    SEND_DISCORD = "send_discord"
    SEND_SMS = "send_sms"
    MAKE_CALL = "make_call"
    WEBHOOK_OUTBOUND = "webhook_outbound"
    CRM_WRITE = "crm_write"
    SHEET_WRITE = "sheet_write"
    DELETE_RECORD = "delete_record"
    UPDATE_BILLING = "update_billing"
    FINANCIAL_ACTION = "financial_action"
    BROWSER_ACTION = "browser_action"
    SYSTEM_ACTION = "system_action"
    EXTERNAL_APP_WRITE = "external_app_write"
    BULK_MESSAGE = "bulk_message"
    BULK_EXPORT = "bulk_export"


class EventSeverity(str, Enum):
    """Agent event severity."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class TaskContext:
    """
    SaaS-safe execution context.

    Every user-specific workflow operation must include user_id and workspace_id.
    This prevents cross-user/workspace leakage of memory, files, logs, tasks,
    analytics, audit records, or integration settings.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    subscription_tier: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: Optional[str] = None
    workflow_id: Optional[str] = None
    run_id: Optional[str] = None
    source_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class N8nConfig:
    """n8n workflow automation settings."""

    enabled: bool = False
    base_url: Optional[str] = None
    api_key_env: str = "N8N_API_KEY"
    webhook_base_url: Optional[str] = None
    timeout_seconds: int = DEFAULT_N8N_TIMEOUT_SECONDS
    verify_ssl: bool = True
    allow_unverified_ssl_in_dev: bool = False
    default_owner_tag: str = "william-jarvis"
    allowed_workflow_tags: List[str] = field(default_factory=lambda: ["william", "jarvis", "workflow_agent"])
    max_workflows_per_workspace: int = 250
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WebhookConfig:
    """Webhook inbound/outbound safety settings."""

    enabled: bool = True
    auth_mode: WebhookAuthMode = WebhookAuthMode.HMAC_SHA256
    secret_env: str = "WORKFLOW_WEBHOOK_SECRET"
    bearer_token_env: str = "WORKFLOW_WEBHOOK_BEARER_TOKEN"
    timeout_seconds: int = DEFAULT_WEBHOOK_TIMEOUT_SECONDS
    max_payload_bytes: int = DEFAULT_WEBHOOK_MAX_PAYLOAD_BYTES
    require_https: bool = True
    allow_localhost_in_dev: bool = True
    accepted_content_types: List[str] = field(
        default_factory=lambda: [
            "application/json",
            "application/x-www-form-urlencoded",
            "multipart/form-data",
            "text/plain",
        ]
    )
    allowed_event_types: List[str] = field(
        default_factory=lambda: [
            "form.submitted",
            "lead.created",
            "lead.updated",
            "crm.contact.created",
            "crm.deal.updated",
            "sheet.row.created",
            "email.received",
            "workflow.triggered",
            "workflow.completed",
            "workflow.failed",
            "approval.requested",
            "approval.approved",
            "approval.rejected",
        ]
    )
    blocked_event_types: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RetryConfig:
    """Retry behavior for safe failed workflow steps."""

    enabled: bool = True
    mode: RetryMode = RetryMode.SAFE_ONLY
    max_attempts: int = DEFAULT_MAX_RETRY_ATTEMPTS
    base_delay_seconds: float = DEFAULT_RETRY_BASE_DELAY_SECONDS
    max_delay_seconds: float = DEFAULT_RETRY_MAX_DELAY_SECONDS
    backoff_multiplier: float = DEFAULT_RETRY_BACKOFF_MULTIPLIER
    jitter_seconds: float = 0.5
    idempotency_ttl_seconds: int = DEFAULT_IDEMPOTENCY_TTL_SECONDS
    retryable_error_codes: List[str] = field(
        default_factory=lambda: [
            "timeout",
            "rate_limited",
            "temporary_unavailable",
            "connection_error",
            "gateway_timeout",
            "service_unavailable",
        ]
    )
    non_retryable_action_types: List[str] = field(
        default_factory=lambda: [
            SensitiveAction.FINANCIAL_ACTION.value,
            SensitiveAction.UPDATE_BILLING.value,
            SensitiveAction.DELETE_RECORD.value,
            SensitiveAction.MAKE_CALL.value,
        ]
    )
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ApprovalConfig:
    """Security approval gate configuration."""

    mode: ApprovalMode = ApprovalMode.SENSITIVE_ONLY
    require_approval_for_sensitive_actions: bool = True
    require_approval_for_bulk_actions: bool = True
    bulk_threshold: int = 25
    approval_ttl_seconds: int = 3_600
    allowed_auto_approve_roles: List[str] = field(default_factory=lambda: ["owner", "admin"])
    sensitive_actions: List[str] = field(
        default_factory=lambda: [action.value for action in SensitiveAction]
    )
    escalation_agent: str = "security_agent"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AntiSpamConfig:
    """Anti-spam, rate-limit, and duplicate prevention settings."""

    enabled: bool = True
    window_seconds: int = DEFAULT_ANTI_SPAM_WINDOW_SECONDS
    max_events_per_window: int = DEFAULT_ANTI_SPAM_MAX_EVENTS
    max_messages_per_recipient_per_day: int = 5
    max_webhooks_per_source_per_minute: int = 120
    duplicate_fingerprint_ttl_seconds: int = DEFAULT_IDEMPOTENCY_TTL_SECONDS
    block_disposable_email_domains: bool = True
    blocked_domains: List[str] = field(
        default_factory=lambda: [
            "mailinator.com",
            "tempmail.com",
            "10minutemail.com",
            "guerrillamail.com",
            "yopmail.com",
        ]
    )
    blocked_keywords: List[str] = field(
        default_factory=lambda: [
            "viagra",
            "casino",
            "crypto giveaway",
            "free money",
            "adult content",
        ]
    )
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditConfig:
    """Audit logging settings."""

    enabled: bool = True
    log_config_reads: bool = False
    log_config_writes: bool = True
    redact_secrets: bool = True
    retention_days: int = 365
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DashboardConfig:
    """Dashboard/API visibility settings."""

    enabled: bool = True
    expose_safe_settings: bool = True
    expose_secret_names_only: bool = True
    allow_workspace_overrides: bool = True
    allow_user_overrides: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowSettings:
    """
    Full Workflow Agent settings bundle.

    This object is serializable and suitable for API/dashboard responses after
    secret redaction.
    """

    version: str = DEFAULT_VERSION
    environment: WorkflowEnvironment = WorkflowEnvironment.DEVELOPMENT
    enabled: bool = True
    default_timezone: str = "UTC"
    n8n: N8nConfig = field(default_factory=N8nConfig)
    webhooks: WebhookConfig = field(default_factory=WebhookConfig)
    retries: RetryConfig = field(default_factory=RetryConfig)
    approvals: ApprovalConfig = field(default_factory=ApprovalConfig)
    anti_spam: AntiSpamConfig = field(default_factory=AntiSpamConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Utility functions
# =============================================================================

def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""

    return datetime.now(timezone.utc).isoformat()


def safe_deepcopy(value: Any) -> Any:
    """Deep-copy a value with fallback for unusual objects."""

    try:
        return copy.deepcopy(value)
    except Exception:
        return value


def dataclass_to_dict(value: Any) -> Any:
    """Convert dataclasses, enums, lists, and dicts into JSON-safe structures."""

    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {key: dataclass_to_dict(item) for key, item in asdict(value).items()}
    if isinstance(value, Mapping):
        return {str(key): dataclass_to_dict(item) for key, item in value.items()}
    if isinstance(value, list):
        return [dataclass_to_dict(item) for item in value]
    if isinstance(value, tuple):
        return [dataclass_to_dict(item) for item in value]
    return value


def nested_update(base: Dict[str, Any], updates: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge updates into base.

    Only dictionary subtrees are merged. Other values are replaced.
    """

    for key, value in updates.items():
        if isinstance(value, Mapping) and isinstance(base.get(key), dict):
            nested_update(base[key], value)
        else:
            base[key] = safe_deepcopy(value)
    return base


def redact_sensitive_values(payload: Any) -> Any:
    """
    Redact secrets/tokens/password-like values from dictionaries.

    This keeps dashboard/API/audit responses safe.
    """

    sensitive_markers = (
        "secret",
        "token",
        "api_key",
        "apikey",
        "password",
        "private_key",
        "bearer",
        "credential",
    )

    if isinstance(payload, Mapping):
        cleaned: Dict[str, Any] = {}
        for key, value in payload.items():
            lower_key = str(key).lower()
            if any(marker in lower_key for marker in sensitive_markers):
                cleaned[str(key)] = "***REDACTED***" if value else value
            else:
                cleaned[str(key)] = redact_sensitive_values(value)
        return cleaned

    if isinstance(payload, list):
        return [redact_sensitive_values(item) for item in payload]

    return payload


def validate_safe_identifier(value: str, field_name: str) -> Tuple[bool, Optional[str]]:
    """Validate user/workspace/workflow-style identifiers."""

    if not isinstance(value, str) or not value.strip():
        return False, f"{field_name} is required."
    if not SAFE_ID_PATTERN.match(value.strip()):
        return False, f"{field_name} contains unsafe characters or is too long."
    return True, None


def normalize_action_type(action_type: Union[str, SensitiveAction, None]) -> str:
    """Normalize action type to lower snake/string form."""

    if action_type is None:
        return ""
    if isinstance(action_type, SensitiveAction):
        return action_type.value
    return str(action_type).strip().lower()


def create_fingerprint(parts: Iterable[Any]) -> str:
    """Create stable SHA-256 fingerprint from JSON-safe parts."""

    normalized = json.dumps(list(parts), sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# =============================================================================
# WorkflowConfig
# =============================================================================

class WorkflowConfig(BaseAgent):
    """
    Production-ready Workflow Agent configuration manager.

    Responsibilities:
        - Provide default and scoped workflow settings.
        - Validate SaaS user/workspace context.
        - Manage n8n, webhook, retry, approval, and anti-spam config.
        - Prepare structured payloads for Security, Verification, Memory, Audit,
          Dashboard/API, Master Agent routing, and Agent Registry.
        - Avoid secrets in source code and redact sensitive values in outputs.

    Storage:
        This class uses in-memory dictionaries by default for import safety and
        testability. In production, pass config_store/audit_sink/event_sink callables
        to connect it to a database, Redis, event bus, or dashboard backend.
    """

    module_name = MODULE_NAME
    file_name = FILE_NAME
    agent_name = AGENT_NAME
    version = DEFAULT_VERSION

    def __init__(
        self,
        default_settings: Optional[WorkflowSettings] = None,
        config_store: Optional[MutableConfigStore] = None,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        memory_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        verification_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.agent_name, agent_id="workflow_config", **kwargs)

        self.logger = logger or LOGGER
        self.default_settings = default_settings or self._load_default_settings_from_env()
        self.config_store = config_store if config_store is not None else {}
        self.audit_sink = audit_sink
        self.event_sink = event_sink
        self.security_approval_callback = security_approval_callback
        self.memory_sink = memory_sink
        self.verification_sink = verification_sink

        self._rate_limit_state: Dict[str, List[float]] = {}
        self._fingerprint_state: Dict[str, float] = {}

        self._emit_agent_event(
            event_type="workflow_config.initialized",
            severity=EventSeverity.INFO,
            data={
                "environment": self.default_settings.environment.value,
                "version": self.default_settings.version,
            },
        )

        try:
            register_agent_module(
                module_name=self.module_name,
                class_name=self.agent_name,
                file_path=f"agents/workflow_agent/{self.file_name}",
                version=self.version,
                capabilities=[
                    "workflow_config",
                    "n8n_settings",
                    "webhook_settings",
                    "retry_settings",
                    "approval_settings",
                    "anti_spam_settings",
                    "saas_scoped_overrides",
                ],
            )
        except Exception as exc:
            self.logger.debug("Agent registry fallback ignored: %s", exc)

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[TaskContext, Mapping[str, Any], None],
        require_user_workspace: bool = True,
    ) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace context.

        Required by William/Jarvis global rules:
        user-specific execution must never happen without both user_id and
        workspace_id.
        """

        if context is None:
            if require_user_workspace:
                return self._error_result(
                    message="Task context is required.",
                    error="missing_context",
                    metadata={"hook": "_validate_task_context"},
                )
            return self._safe_result(
                message="No task context required for this operation.",
                data={"context": None},
            )

        if isinstance(context, TaskContext):
            ctx = dataclass_to_dict(context)
        elif isinstance(context, Mapping):
            ctx = dict(context)
        else:
            return self._error_result(
                message="Invalid task context type.",
                error="invalid_context_type",
                metadata={"type": type(context).__name__},
            )

        if require_user_workspace:
            user_ok, user_error = validate_safe_identifier(str(ctx.get("user_id", "")), "user_id")
            if not user_ok:
                return self._error_result(
                    message=user_error or "Invalid user_id.",
                    error="invalid_user_id",
                    metadata={"hook": "_validate_task_context"},
                )

            workspace_ok, workspace_error = validate_safe_identifier(
                str(ctx.get("workspace_id", "")),
                "workspace_id",
            )
            if not workspace_ok:
                return self._error_result(
                    message=workspace_error or "Invalid workspace_id.",
                    error="invalid_workspace_id",
                    metadata={"hook": "_validate_task_context"},
                )

        ctx.setdefault("request_id", str(uuid.uuid4()))
        ctx.setdefault("metadata", {})

        return self._safe_result(
            message="Task context validated.",
            data={"context": ctx},
            metadata={"hook": "_validate_task_context"},
        )

    def _requires_security_check(
        self,
        action_type: Union[str, SensitiveAction, None],
        context: Union[TaskContext, Mapping[str, Any], None] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide whether an action requires Security Agent approval.

        Sensitive message sending, destructive writes, financial/system/browser
        operations, bulk actions, and outbound webhooks require approval by
        default.
        """

        settings = self.get_effective_settings(context=context).get("data", {}).get("settings", {})
        approvals = settings.get("approvals", {})
        mode = approvals.get("mode", ApprovalMode.SENSITIVE_ONLY.value)

        normalized = normalize_action_type(action_type)
        payload = payload or {}

        if mode == ApprovalMode.NEVER.value:
            return False

        if mode == ApprovalMode.ALWAYS.value:
            return True

        bulk_threshold = int(approvals.get("bulk_threshold", 25))
        item_count = payload.get("item_count") or payload.get("recipient_count") or payload.get("record_count") or 0

        try:
            item_count_int = int(item_count)
        except Exception:
            item_count_int = 0

        if approvals.get("require_approval_for_bulk_actions", True) and item_count_int >= bulk_threshold:
            return True

        sensitive_actions = set(str(item).lower() for item in approvals.get("sensitive_actions", []))
        if normalized in sensitive_actions:
            return bool(approvals.get("require_approval_for_sensitive_actions", True))

        if normalized.startswith("send_") or normalized.endswith("_write"):
            return True

        return False

    def _request_security_approval(
        self,
        action_type: Union[str, SensitiveAction],
        context: Union[TaskContext, Mapping[str, Any]],
        payload: Optional[Mapping[str, Any]] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Prepare and optionally dispatch a Security Agent approval request.

        The real Security Agent can be connected through security_approval_callback.
        Without that callback, this method safely returns a pending approval
        payload without performing the action.
        """

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]
        normalized = normalize_action_type(action_type)
        approval_id = str(uuid.uuid4())

        approval_payload = {
            "approval_id": approval_id,
            "target_agent": "security_agent",
            "source_agent": self.agent_name,
            "module": self.module_name,
            "action_type": normalized,
            "reason": reason or "Workflow action requires security approval.",
            "context": ctx,
            "payload": redact_sensitive_values(dict(payload or {})),
            "requested_at": utc_now_iso(),
            "status": "pending",
            "ttl_seconds": self.default_settings.approvals.approval_ttl_seconds,
        }

        self._emit_agent_event(
            event_type="workflow.security_approval.requested",
            severity=EventSeverity.WARNING,
            data=approval_payload,
            context=ctx,
        )

        self._log_audit_event(
            action="security_approval_requested",
            context=ctx,
            data=approval_payload,
        )

        if self.security_approval_callback:
            try:
                callback_result = self.security_approval_callback(approval_payload)
                if not isinstance(callback_result, Mapping):
                    return self._error_result(
                        message="Security approval callback returned invalid response.",
                        error="invalid_security_callback_response",
                        data={"approval": approval_payload},
                    )

                merged = dict(approval_payload)
                merged.update(dict(callback_result))

                return self._safe_result(
                    message="Security approval callback completed.",
                    data={"approval": merged},
                    metadata={"security_agent_connected": True},
                )
            except Exception as exc:
                self.logger.exception("Security approval callback failed.")
                return self._error_result(
                    message="Security approval request failed.",
                    error=str(exc),
                    data={"approval": approval_payload},
                )

        return self._safe_result(
            message="Security approval prepared and pending.",
            data={"approval": approval_payload},
            metadata={"security_agent_connected": False},
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: Union[TaskContext, Mapping[str, Any], None] = None,
        result: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload after a completed config action.
        """

        ctx = self._context_or_none(context)
        payload = {
            "verification_id": str(uuid.uuid4()),
            "target_agent": "verification_agent",
            "source_agent": self.agent_name,
            "module": self.module_name,
            "file": self.file_name,
            "action": action,
            "context": ctx,
            "result": redact_sensitive_values(dict(result or {})),
            "data": redact_sensitive_values(dict(data or {})),
            "created_at": utc_now_iso(),
            "checks": [
                "context_isolation",
                "secret_redaction",
                "config_schema_validity",
                "dashboard_safety",
            ],
        }

        if self.verification_sink:
            try:
                self.verification_sink(payload)
            except Exception as exc:
                self.logger.debug("Verification sink failed: %s", exc)

        return payload

    def _prepare_memory_payload(
        self,
        action: str,
        context: Union[TaskContext, Mapping[str, Any], None] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This is useful for remembering safe workflow preferences, mappings,
        integration choices, retry policies, or workspace-level automation
        defaults without leaking between users/workspaces.
        """

        ctx = self._context_or_none(context)
        payload = {
            "memory_id": str(uuid.uuid4()),
            "target_agent": "memory_agent",
            "source_agent": self.agent_name,
            "module": self.module_name,
            "action": action,
            "context": ctx,
            "memory_type": "workflow_config",
            "data": redact_sensitive_values(dict(data or {})),
            "created_at": utc_now_iso(),
            "isolation": {
                "user_id": ctx.get("user_id") if ctx else None,
                "workspace_id": ctx.get("workspace_id") if ctx else None,
            },
        }

        if self.memory_sink:
            try:
                self.memory_sink(payload)
            except Exception as exc:
                self.logger.debug("Memory sink failed: %s", exc)

        return payload

    def _emit_agent_event(
        self,
        event_type: str,
        severity: Union[EventSeverity, str] = EventSeverity.INFO,
        data: Optional[Mapping[str, Any]] = None,
        context: Union[TaskContext, Mapping[str, Any], None] = None,
    ) -> Dict[str, Any]:
        """
        Emit an Agent/Master Agent compatible event.

        Can be wired to an event bus later. Safe fallback logs locally.
        """

        severity_value = severity.value if isinstance(severity, EventSeverity) else str(severity)
        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "severity": severity_value,
            "source_agent": self.agent_name,
            "module": self.module_name,
            "file": self.file_name,
            "context": self._context_or_none(context),
            "data": redact_sensitive_values(dict(data or {})),
            "created_at": utc_now_iso(),
        }

        if self.event_sink:
            try:
                self.event_sink(event)
            except Exception as exc:
                self.logger.debug("Event sink failed: %s", exc)

        log_method = getattr(self.logger, severity_value, self.logger.info)
        try:
            log_method("WorkflowConfig event: %s", event_type)
        except Exception:
            self.logger.info("WorkflowConfig event: %s", event_type)

        return event

    def _log_audit_event(
        self,
        action: str,
        context: Union[TaskContext, Mapping[str, Any], None] = None,
        data: Optional[Mapping[str, Any]] = None,
        success: bool = True,
    ) -> Dict[str, Any]:
        """
        Create SaaS-isolated audit event.

        This supports future dashboard analytics, compliance history, task
        history, and workspace-level admin views.
        """

        settings = self.default_settings
        if not settings.audit.enabled:
            return {
                "success": True,
                "message": "Audit logging disabled.",
                "data": None,
                "error": None,
                "metadata": {"audit_enabled": False},
            }

        ctx = self._context_or_none(context)
        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "action": action,
            "success": success,
            "source_agent": self.agent_name,
            "module": self.module_name,
            "file": self.file_name,
            "context": ctx,
            "data": redact_sensitive_values(dict(data or {})) if settings.audit.redact_secrets else dict(data or {}),
            "created_at": utc_now_iso(),
        }

        if self.audit_sink:
            try:
                self.audit_sink(audit_event)
            except Exception as exc:
                self.logger.debug("Audit sink failed: %s", exc)

        return audit_event

    def _safe_result(
        self,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis success response."""

        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "module": self.module_name,
                "file": self.file_name,
                "timestamp": utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Union[str, Exception],
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis error response."""

        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": str(error),
            "metadata": {
                "agent": self.agent_name,
                "module": self.module_name,
                "file": self.file_name,
                "timestamp": utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    # -------------------------------------------------------------------------
    # Public settings methods
    # -------------------------------------------------------------------------

    def get_default_settings(self, redact: bool = True) -> Dict[str, Any]:
        """Return global default settings."""

        settings = dataclass_to_dict(self.default_settings)
        if redact:
            settings = redact_sensitive_values(settings)

        return self._safe_result(
            message="Default workflow settings loaded.",
            data={"settings": settings},
            metadata={"scope": ConfigScope.GLOBAL.value},
        )

    def get_effective_settings(
        self,
        context: Union[TaskContext, Mapping[str, Any], None] = None,
        redact: bool = True,
    ) -> Dict[str, Any]:
        """
        Return global settings merged with user/workspace scoped overrides.

        Merge order:
            global defaults -> workspace override -> user override
            -> user+workspace override
        """

        try:
            base = dataclass_to_dict(self.default_settings)
            ctx = self._context_or_none(context)

            if ctx:
                workspace_key = self._scope_key(ConfigScope.WORKSPACE, None, ctx.get("workspace_id"))
                user_key = self._scope_key(ConfigScope.USER, ctx.get("user_id"), None)
                user_workspace_key = self._scope_key(
                    ConfigScope.USER_WORKSPACE,
                    ctx.get("user_id"),
                    ctx.get("workspace_id"),
                )

                for key in (workspace_key, user_key, user_workspace_key):
                    override = self.config_store.get(key)
                    if isinstance(override, Mapping):
                        nested_update(base, override)

            settings = redact_sensitive_values(base) if redact else base

            if self.default_settings.audit.log_config_reads:
                self._log_audit_event(
                    action="config_read",
                    context=ctx,
                    data={"scope": "effective"},
                )

            return self._safe_result(
                message="Effective workflow settings loaded.",
                data={"settings": settings},
                metadata={
                    "scope": ConfigScope.USER_WORKSPACE.value if ctx else ConfigScope.GLOBAL.value,
                    "redacted": redact,
                },
            )
        except Exception as exc:
            self.logger.exception("Failed to get effective settings.")
            return self._error_result(
                message="Failed to get effective workflow settings.",
                error=exc,
            )

    def set_scoped_override(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        override: Mapping[str, Any],
        scope: ConfigScope = ConfigScope.USER_WORKSPACE,
        actor: Optional[str] = None,
        require_security_for_sensitive: bool = True,
    ) -> Dict[str, Any]:
        """
        Set a SaaS-scoped workflow config override.

        This does not store secrets directly. Secret values should be stored in
        a vault/environment and referenced by env names.
        """

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]

        if not isinstance(override, Mapping):
            return self._error_result(
                message="Config override must be a dictionary.",
                error="invalid_override",
                metadata={"scope": scope.value},
            )

        sanitized = self._sanitize_override(dict(override))
        validation_result = self.validate_settings_dict(sanitized)
        if not validation_result.get("success"):
            return validation_result

        if require_security_for_sensitive and self._override_touches_sensitive_settings(sanitized):
            approval = self._request_security_approval(
                action_type="workflow_config_update",
                context=ctx,
                payload={"override": sanitized, "scope": scope.value, "actor": actor},
                reason="Workflow configuration update touches sensitive settings.",
            )

            approval_data = approval.get("data", {}).get("approval", {})
            if approval_data.get("status") not in {"approved", "auto_approved"}:
                return self._safe_result(
                    message="Config override requires security approval before applying.",
                    data={"approval": approval_data, "applied": False},
                    metadata={"scope": scope.value},
                )

        key = self._scope_key(scope, ctx.get("user_id"), ctx.get("workspace_id"))
        current = self.config_store.get(key, {})
        merged = nested_update(dict(current), sanitized)
        self.config_store[key] = merged

        audit = self._log_audit_event(
            action="config_override_set",
            context=ctx,
            data={
                "scope": scope.value,
                "actor": actor,
                "override": sanitized,
            },
        )

        verification = self._prepare_verification_payload(
            action="config_override_set",
            context=ctx,
            data={"scope": scope.value, "override": sanitized},
        )

        memory = self._prepare_memory_payload(
            action="workflow_config_preference_updated",
            context=ctx,
            data={"scope": scope.value, "override": sanitized},
        )

        self._emit_agent_event(
            event_type="workflow.config.updated",
            severity=EventSeverity.INFO,
            data={"scope": scope.value, "actor": actor},
            context=ctx,
        )

        return self._safe_result(
            message="Workflow config override saved.",
            data={
                "scope": scope.value,
                "key": key,
                "override": redact_sensitive_values(merged),
                "audit": audit,
                "verification": verification,
                "memory": memory,
            },
        )

    def clear_scoped_override(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        scope: ConfigScope = ConfigScope.USER_WORKSPACE,
        actor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Clear a scoped workflow config override."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]
        key = self._scope_key(scope, ctx.get("user_id"), ctx.get("workspace_id"))

        existed = key in self.config_store
        if existed:
            del self.config_store[key]

        audit = self._log_audit_event(
            action="config_override_cleared",
            context=ctx,
            data={"scope": scope.value, "actor": actor, "existed": existed},
        )

        verification = self._prepare_verification_payload(
            action="config_override_cleared",
            context=ctx,
            data={"scope": scope.value, "existed": existed},
        )

        return self._safe_result(
            message="Workflow config override cleared." if existed else "No override existed for this scope.",
            data={
                "scope": scope.value,
                "key": key,
                "existed": existed,
                "audit": audit,
                "verification": verification,
            },
        )

    def list_scoped_overrides(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        redact: bool = True,
    ) -> Dict[str, Any]:
        """List overrides visible to a user/workspace context."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]
        keys = {
            "workspace": self._scope_key(ConfigScope.WORKSPACE, None, ctx.get("workspace_id")),
            "user": self._scope_key(ConfigScope.USER, ctx.get("user_id"), None),
            "user_workspace": self._scope_key(
                ConfigScope.USER_WORKSPACE,
                ctx.get("user_id"),
                ctx.get("workspace_id"),
            ),
        }

        overrides = {
            label: self.config_store.get(key, {})
            for label, key in keys.items()
        }

        if redact:
            overrides = redact_sensitive_values(overrides)

        return self._safe_result(
            message="Scoped workflow config overrides loaded.",
            data={"overrides": overrides, "keys": keys},
            metadata={"redacted": redact},
        )

    # -------------------------------------------------------------------------
    # Public config domain methods
    # -------------------------------------------------------------------------

    def get_n8n_config(
        self,
        context: Union[TaskContext, Mapping[str, Any], None] = None,
        redact: bool = True,
    ) -> Dict[str, Any]:
        """Return effective n8n config."""

        settings_result = self.get_effective_settings(context=context, redact=redact)
        if not settings_result.get("success"):
            return settings_result

        return self._safe_result(
            message="n8n workflow config loaded.",
            data={"n8n": settings_result["data"]["settings"].get("n8n", {})},
        )

    def get_webhook_config(
        self,
        context: Union[TaskContext, Mapping[str, Any], None] = None,
        redact: bool = True,
    ) -> Dict[str, Any]:
        """Return effective webhook config."""

        settings_result = self.get_effective_settings(context=context, redact=redact)
        if not settings_result.get("success"):
            return settings_result

        return self._safe_result(
            message="Webhook config loaded.",
            data={"webhooks": settings_result["data"]["settings"].get("webhooks", {})},
        )

    def get_retry_config(
        self,
        context: Union[TaskContext, Mapping[str, Any], None] = None,
    ) -> Dict[str, Any]:
        """Return effective retry config."""

        settings_result = self.get_effective_settings(context=context)
        if not settings_result.get("success"):
            return settings_result

        return self._safe_result(
            message="Retry config loaded.",
            data={"retries": settings_result["data"]["settings"].get("retries", {})},
        )

    def get_approval_config(
        self,
        context: Union[TaskContext, Mapping[str, Any], None] = None,
    ) -> Dict[str, Any]:
        """Return effective approval config."""

        settings_result = self.get_effective_settings(context=context)
        if not settings_result.get("success"):
            return settings_result

        return self._safe_result(
            message="Approval config loaded.",
            data={"approvals": settings_result["data"]["settings"].get("approvals", {})},
        )

    def get_anti_spam_config(
        self,
        context: Union[TaskContext, Mapping[str, Any], None] = None,
    ) -> Dict[str, Any]:
        """Return effective anti-spam config."""

        settings_result = self.get_effective_settings(context=context)
        if not settings_result.get("success"):
            return settings_result

        return self._safe_result(
            message="Anti-spam config loaded.",
            data={"anti_spam": settings_result["data"]["settings"].get("anti_spam", {})},
        )

    def update_n8n_config(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        n8n_updates: Mapping[str, Any],
        actor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update scoped n8n config."""

        return self.set_scoped_override(
            context=context,
            override={"n8n": dict(n8n_updates)},
            scope=ConfigScope.USER_WORKSPACE,
            actor=actor,
            require_security_for_sensitive=True,
        )

    def update_webhook_config(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        webhook_updates: Mapping[str, Any],
        actor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update scoped webhook config."""

        return self.set_scoped_override(
            context=context,
            override={"webhooks": dict(webhook_updates)},
            scope=ConfigScope.USER_WORKSPACE,
            actor=actor,
            require_security_for_sensitive=True,
        )

    def update_retry_config(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        retry_updates: Mapping[str, Any],
        actor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update scoped retry config."""

        return self.set_scoped_override(
            context=context,
            override={"retries": dict(retry_updates)},
            scope=ConfigScope.USER_WORKSPACE,
            actor=actor,
            require_security_for_sensitive=False,
        )

    def update_approval_config(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        approval_updates: Mapping[str, Any],
        actor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update scoped approval config."""

        return self.set_scoped_override(
            context=context,
            override={"approvals": dict(approval_updates)},
            scope=ConfigScope.USER_WORKSPACE,
            actor=actor,
            require_security_for_sensitive=True,
        )

    def update_anti_spam_config(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        anti_spam_updates: Mapping[str, Any],
        actor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update scoped anti-spam config."""

        return self.set_scoped_override(
            context=context,
            override={"anti_spam": dict(anti_spam_updates)},
            scope=ConfigScope.USER_WORKSPACE,
            actor=actor,
            require_security_for_sensitive=False,
        )

    # -------------------------------------------------------------------------
    # Validation and safety helpers
    # -------------------------------------------------------------------------

    def validate_settings_dict(self, settings: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate a settings dictionary or partial override.

        This is intentionally permissive for future upgrades but strict on known
        safety-critical fields.
        """

        try:
            allowed_top_keys = {
                "version",
                "environment",
                "enabled",
                "default_timezone",
                "n8n",
                "webhooks",
                "retries",
                "approvals",
                "anti_spam",
                "audit",
                "dashboard",
                "metadata",
            }

            unknown = [key for key in settings.keys() if key not in allowed_top_keys]
            if unknown:
                return self._error_result(
                    message="Settings contain unknown top-level keys.",
                    error="unknown_settings_keys",
                    data={"unknown_keys": unknown},
                )

            if "environment" in settings:
                env_value = settings["environment"]
                if env_value not in {item.value for item in WorkflowEnvironment}:
                    return self._error_result(
                        message="Invalid workflow environment.",
                        error="invalid_environment",
                        data={"environment": env_value},
                    )

            n8n = settings.get("n8n")
            if isinstance(n8n, Mapping):
                url_error = self._validate_url_field(
                    value=n8n.get("base_url"),
                    field_name="n8n.base_url",
                    require_https=bool(n8n.get("require_https", True)),
                    allow_empty=True,
                )
                if url_error:
                    return url_error

                webhook_url_error = self._validate_url_field(
                    value=n8n.get("webhook_base_url"),
                    field_name="n8n.webhook_base_url",
                    require_https=True,
                    allow_empty=True,
                )
                if webhook_url_error:
                    return webhook_url_error

                max_workflows = n8n.get("max_workflows_per_workspace")
                if max_workflows is not None and int(max_workflows) < 1:
                    return self._error_result(
                        message="n8n.max_workflows_per_workspace must be at least 1.",
                        error="invalid_n8n_limit",
                    )

            webhooks = settings.get("webhooks")
            if isinstance(webhooks, Mapping):
                auth_mode = webhooks.get("auth_mode")
                if auth_mode and auth_mode not in {item.value for item in WebhookAuthMode}:
                    return self._error_result(
                        message="Invalid webhook auth mode.",
                        error="invalid_webhook_auth_mode",
                        data={"auth_mode": auth_mode},
                    )

                max_payload = webhooks.get("max_payload_bytes")
                if max_payload is not None and int(max_payload) <= 0:
                    return self._error_result(
                        message="webhooks.max_payload_bytes must be positive.",
                        error="invalid_webhook_payload_limit",
                    )

            retries = settings.get("retries")
            if isinstance(retries, Mapping):
                retry_mode = retries.get("mode")
                if retry_mode and retry_mode not in {item.value for item in RetryMode}:
                    return self._error_result(
                        message="Invalid retry mode.",
                        error="invalid_retry_mode",
                        data={"mode": retry_mode},
                    )

                max_attempts = retries.get("max_attempts")
                if max_attempts is not None and not 0 <= int(max_attempts) <= 20:
                    return self._error_result(
                        message="retries.max_attempts must be between 0 and 20.",
                        error="invalid_retry_attempts",
                    )

            approvals = settings.get("approvals")
            if isinstance(approvals, Mapping):
                approval_mode = approvals.get("mode")
                if approval_mode and approval_mode not in {item.value for item in ApprovalMode}:
                    return self._error_result(
                        message="Invalid approval mode.",
                        error="invalid_approval_mode",
                        data={"mode": approval_mode},
                    )

                bulk_threshold = approvals.get("bulk_threshold")
                if bulk_threshold is not None and int(bulk_threshold) < 1:
                    return self._error_result(
                        message="approvals.bulk_threshold must be at least 1.",
                        error="invalid_bulk_threshold",
                    )

            anti_spam = settings.get("anti_spam")
            if isinstance(anti_spam, Mapping):
                max_events = anti_spam.get("max_events_per_window")
                if max_events is not None and int(max_events) < 1:
                    return self._error_result(
                        message="anti_spam.max_events_per_window must be at least 1.",
                        error="invalid_anti_spam_limit",
                    )

                window = anti_spam.get("window_seconds")
                if window is not None and int(window) < 1:
                    return self._error_result(
                        message="anti_spam.window_seconds must be at least 1.",
                        error="invalid_anti_spam_window",
                    )

            return self._safe_result(
                message="Workflow settings validation passed.",
                data={"valid": True},
            )
        except Exception as exc:
            return self._error_result(
                message="Workflow settings validation failed.",
                error=exc,
            )

    def validate_webhook_request(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        headers: Mapping[str, Any],
        body: Union[str, bytes, Mapping[str, Any], List[Any], None],
        source_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate an inbound webhook request using effective config.

        Supports:
            - content type checks
            - max payload size
            - event type allow/block lists
            - shared secret / bearer token / HMAC SHA-256
            - anti-spam fingerprint checks
        """

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]
        settings = self.get_effective_settings(ctx, redact=False)
        if not settings.get("success"):
            return settings

        webhooks = settings["data"]["settings"].get("webhooks", {})
        if not webhooks.get("enabled", True):
            return self._error_result(
                message="Webhooks are disabled for this context.",
                error="webhooks_disabled",
                metadata={"context": ctx},
            )

        payload_bytes = self._body_to_bytes(body)
        if len(payload_bytes) > int(webhooks.get("max_payload_bytes", DEFAULT_WEBHOOK_MAX_PAYLOAD_BYTES)):
            return self._error_result(
                message="Webhook payload exceeds allowed size.",
                error="payload_too_large",
                data={"size_bytes": len(payload_bytes)},
            )

        content_type = str(headers.get("content-type") or headers.get("Content-Type") or "").split(";")[0].strip()
        accepted = set(webhooks.get("accepted_content_types", []))
        if content_type and accepted and content_type not in accepted:
            return self._error_result(
                message="Webhook content type is not accepted.",
                error="invalid_content_type",
                data={"content_type": content_type, "accepted": sorted(accepted)},
            )

        if source_url:
            url_check = self._validate_url_field(
                value=source_url,
                field_name="source_url",
                require_https=bool(webhooks.get("require_https", True)),
                allow_empty=True,
            )
            if url_check and self.default_settings.environment == WorkflowEnvironment.PRODUCTION:
                return url_check

        parsed_body = self._parse_body(body)
        event_type = ""
        if isinstance(parsed_body, Mapping):
            event_type = str(
                parsed_body.get("event_type")
                or parsed_body.get("type")
                or parsed_body.get("event")
                or ""
            ).strip()

        allowed_events = set(webhooks.get("allowed_event_types", []))
        blocked_events = set(webhooks.get("blocked_event_types", []))

        if event_type in blocked_events:
            return self._error_result(
                message="Webhook event type is blocked.",
                error="blocked_event_type",
                data={"event_type": event_type},
            )

        if allowed_events and event_type and event_type not in allowed_events:
            return self._error_result(
                message="Webhook event type is not allowed.",
                error="event_type_not_allowed",
                data={"event_type": event_type, "allowed_event_types": sorted(allowed_events)},
            )

        auth_result = self._validate_webhook_auth(headers=headers, body_bytes=payload_bytes, webhooks=webhooks)
        if not auth_result.get("success"):
            return auth_result

        spam_result = self.check_anti_spam(
            context=ctx,
            actor_key=f"webhook:{source_url or headers.get('x-forwarded-for') or 'unknown'}",
            payload=parsed_body if isinstance(parsed_body, Mapping) else {"body_hash": hashlib.sha256(payload_bytes).hexdigest()},
            action_type="webhook_inbound",
        )
        if not spam_result.get("success"):
            return spam_result

        self._log_audit_event(
            action="webhook_request_validated",
            context=ctx,
            data={"event_type": event_type, "source_url": source_url},
        )

        return self._safe_result(
            message="Webhook request validated.",
            data={
                "event_type": event_type,
                "payload_size_bytes": len(payload_bytes),
                "auth": auth_result.get("data", {}),
                "anti_spam": spam_result.get("data", {}),
            },
        )

    def validate_outbound_webhook_url(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        url: str,
    ) -> Dict[str, Any]:
        """
        Validate outbound webhook URL and request Security Agent approval if needed.
        """

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]
        settings = self.get_effective_settings(ctx, redact=False)
        if not settings.get("success"):
            return settings

        webhooks = settings["data"]["settings"].get("webhooks", {})
        url_error = self._validate_url_field(
            value=url,
            field_name="outbound_webhook_url",
            require_https=bool(webhooks.get("require_https", True)),
            allow_empty=False,
        )
        if url_error:
            return url_error

        if self._requires_security_check(SensitiveAction.WEBHOOK_OUTBOUND, ctx, {"url": url}):
            approval = self._request_security_approval(
                action_type=SensitiveAction.WEBHOOK_OUTBOUND,
                context=ctx,
                payload={"url": url},
                reason="Outbound webhook requires Security Agent approval.",
            )
            approval_data = approval.get("data", {}).get("approval", {})
            if approval_data.get("status") not in {"approved", "auto_approved"}:
                return self._safe_result(
                    message="Outbound webhook URL is valid but requires approval before use.",
                    data={"url": url, "approval": approval_data, "allowed": False},
                )

        return self._safe_result(
            message="Outbound webhook URL validated.",
            data={"url": url, "allowed": True},
        )

    def should_retry(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        action_type: Union[str, SensitiveAction],
        attempt_number: int,
        error_code: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Determine if a failed workflow step should be retried safely.
        """

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]
        settings = self.get_effective_settings(ctx, redact=False)
        if not settings.get("success"):
            return settings

        retries = settings["data"]["settings"].get("retries", {})
        normalized_action = normalize_action_type(action_type)

        if not retries.get("enabled", True):
            return self._safe_result(
                message="Retries disabled.",
                data={"should_retry": False, "reason": "retries_disabled"},
            )

        mode = retries.get("mode", RetryMode.SAFE_ONLY.value)
        if mode == RetryMode.NONE.value:
            return self._safe_result(
                message="Retry mode is none.",
                data={"should_retry": False, "reason": "retry_mode_none"},
            )

        max_attempts = int(retries.get("max_attempts", DEFAULT_MAX_RETRY_ATTEMPTS))
        if attempt_number >= max_attempts:
            return self._safe_result(
                message="Maximum retry attempts reached.",
                data={"should_retry": False, "reason": "max_attempts_reached"},
            )

        non_retryable = set(str(item).lower() for item in retries.get("non_retryable_action_types", []))
        if normalized_action in non_retryable:
            return self._safe_result(
                message="Action type is not retryable.",
                data={"should_retry": False, "reason": "non_retryable_action_type"},
            )

        if error_code:
            retryable_codes = set(str(item).lower() for item in retries.get("retryable_error_codes", []))
            if str(error_code).lower() not in retryable_codes:
                return self._safe_result(
                    message="Error code is not retryable.",
                    data={"should_retry": False, "reason": "non_retryable_error_code"},
                )

        if idempotency_key:
            duplicate = self.check_idempotency(context=ctx, idempotency_key=idempotency_key)
            if not duplicate.get("success"):
                return duplicate
            if duplicate["data"].get("duplicate"):
                return self._safe_result(
                    message="Duplicate idempotency key detected; retry blocked.",
                    data={"should_retry": False, "reason": "duplicate_idempotency_key"},
                )

        delay = self.calculate_retry_delay(context=ctx, attempt_number=attempt_number)
        delay_seconds = delay.get("data", {}).get("delay_seconds", 0)

        return self._safe_result(
            message="Workflow step can be retried.",
            data={
                "should_retry": True,
                "reason": "retryable",
                "attempt_number": attempt_number,
                "next_attempt_number": attempt_number + 1,
                "delay_seconds": delay_seconds,
            },
        )

    def calculate_retry_delay(
        self,
        context: Union[TaskContext, Mapping[str, Any], None],
        attempt_number: int,
    ) -> Dict[str, Any]:
        """Calculate exponential backoff retry delay."""

        settings = self.get_effective_settings(context=context, redact=False)
        if not settings.get("success"):
            return settings

        retries = settings["data"]["settings"].get("retries", {})
        base = float(retries.get("base_delay_seconds", DEFAULT_RETRY_BASE_DELAY_SECONDS))
        maximum = float(retries.get("max_delay_seconds", DEFAULT_RETRY_MAX_DELAY_SECONDS))
        multiplier = float(retries.get("backoff_multiplier", DEFAULT_RETRY_BACKOFF_MULTIPLIER))
        jitter = float(retries.get("jitter_seconds", 0.5))

        safe_attempt = max(0, int(attempt_number))
        delay = min(maximum, base * (multiplier ** safe_attempt))

        if jitter > 0:
            jitter_seed = int(time.time() * 1000) % 1000
            delay += min(jitter, jitter_seed / 1000.0)

        return self._safe_result(
            message="Retry delay calculated.",
            data={
                "attempt_number": safe_attempt,
                "delay_seconds": round(delay, 3),
                "max_delay_seconds": maximum,
            },
        )

    def check_idempotency(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        idempotency_key: str,
        ttl_seconds: Optional[int] = None,
        mark_seen: bool = True,
    ) -> Dict[str, Any]:
        """
        Check and optionally mark idempotency key.

        Prevents duplicate leads/messages/actions during retries.
        """

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]
        valid, error = validate_safe_identifier(idempotency_key, "idempotency_key")
        if not valid:
            return self._error_result(
                message=error or "Invalid idempotency key.",
                error="invalid_idempotency_key",
            )

        settings = self.get_effective_settings(ctx, redact=False)
        retries = settings.get("data", {}).get("settings", {}).get("retries", {})
        ttl = int(ttl_seconds or retries.get("idempotency_ttl_seconds", DEFAULT_IDEMPOTENCY_TTL_SECONDS))

        scoped_key = self._scoped_runtime_key(ctx, f"idempotency:{idempotency_key}")
        now = time.time()
        self._cleanup_expired_state(self._fingerprint_state, now)

        duplicate = scoped_key in self._fingerprint_state and self._fingerprint_state[scoped_key] > now
        if mark_seen and not duplicate:
            self._fingerprint_state[scoped_key] = now + ttl

        return self._safe_result(
            message="Idempotency checked.",
            data={
                "idempotency_key": idempotency_key,
                "duplicate": duplicate,
                "ttl_seconds": ttl,
                "marked_seen": bool(mark_seen and not duplicate),
            },
        )

    def check_anti_spam(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        actor_key: str,
        payload: Optional[Mapping[str, Any]] = None,
        action_type: Optional[Union[str, SensitiveAction]] = None,
    ) -> Dict[str, Any]:
        """
        Check anti-spam/rate-limit/duplicate fingerprint rules.

        actor_key examples:
            - email:client@example.com
            - whatsapp:+15555555555
            - webhook:1.2.3.4
            - form:landing-page-a
        """

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]
        settings = self.get_effective_settings(ctx, redact=False)
        if not settings.get("success"):
            return settings

        anti_spam = settings["data"]["settings"].get("anti_spam", {})
        if not anti_spam.get("enabled", True):
            return self._safe_result(
                message="Anti-spam disabled.",
                data={"allowed": True, "reason": "anti_spam_disabled"},
            )

        valid_actor, actor_error = validate_safe_identifier(actor_key, "actor_key")
        if not valid_actor:
            actor_key = create_fingerprint([actor_key])[:64]

        now = time.time()
        window = int(anti_spam.get("window_seconds", DEFAULT_ANTI_SPAM_WINDOW_SECONDS))
        max_events = int(anti_spam.get("max_events_per_window", DEFAULT_ANTI_SPAM_MAX_EVENTS))

        scoped_actor_key = self._scoped_runtime_key(ctx, f"rate:{actor_key}")
        events = self._rate_limit_state.setdefault(scoped_actor_key, [])
        cutoff = now - window
        events[:] = [timestamp for timestamp in events if timestamp >= cutoff]

        if len(events) >= max_events:
            self._log_audit_event(
                action="anti_spam_rate_limited",
                context=ctx,
                data={
                    "actor_key": actor_key,
                    "action_type": normalize_action_type(action_type),
                    "events_in_window": len(events),
                    "window_seconds": window,
                },
                success=False,
            )
            return self._error_result(
                message="Anti-spam rate limit exceeded.",
                error="rate_limited",
                data={
                    "allowed": False,
                    "actor_key": actor_key,
                    "events_in_window": len(events),
                    "window_seconds": window,
                    "max_events_per_window": max_events,
                },
            )

        spam_content = self._detect_spam_content(payload or {}, anti_spam)
        if spam_content:
            return self._error_result(
                message="Payload blocked by anti-spam content rules.",
                error="spam_content_detected",
                data={"allowed": False, "matches": spam_content},
            )

        duplicate_ttl = int(
            anti_spam.get("duplicate_fingerprint_ttl_seconds", DEFAULT_IDEMPOTENCY_TTL_SECONDS)
        )
        fingerprint = create_fingerprint(
            [
                ctx.get("user_id"),
                ctx.get("workspace_id"),
                normalize_action_type(action_type),
                payload or {},
            ]
        )
        duplicate_key = self._scoped_runtime_key(ctx, f"fingerprint:{fingerprint}")
        self._cleanup_expired_state(self._fingerprint_state, now)

        if duplicate_key in self._fingerprint_state and self._fingerprint_state[duplicate_key] > now:
            return self._error_result(
                message="Duplicate workflow payload detected.",
                error="duplicate_payload",
                data={
                    "allowed": False,
                    "fingerprint": fingerprint,
                    "ttl_seconds": duplicate_ttl,
                },
            )

        events.append(now)
        self._fingerprint_state[duplicate_key] = now + duplicate_ttl

        return self._safe_result(
            message="Anti-spam check passed.",
            data={
                "allowed": True,
                "actor_key": actor_key,
                "events_in_window": len(events),
                "window_seconds": window,
                "fingerprint": fingerprint,
            },
        )

    def get_dashboard_safe_config(
        self,
        context: Union[TaskContext, Mapping[str, Any], None] = None,
    ) -> Dict[str, Any]:
        """
        Return dashboard/API safe config.

        Secrets are redacted. Env var names may be shown so admins know which
        variables must be configured.
        """

        effective = self.get_effective_settings(context=context, redact=True)
        if not effective.get("success"):
            return effective

        settings = effective["data"]["settings"]
        dashboard = settings.get("dashboard", {})

        if not dashboard.get("enabled", True):
            return self._safe_result(
                message="Dashboard config view is disabled.",
                data={"settings": {}},
            )

        return self._safe_result(
            message="Dashboard-safe workflow config loaded.",
            data={
                "settings": settings,
                "registry": self.get_registry_metadata()["data"],
            },
            metadata={"redacted": True, "dashboard_safe": True},
        )

    def get_registry_metadata(self) -> Dict[str, Any]:
        """
        Return Agent Registry / Agent Loader metadata.
        """

        return self._safe_result(
            message="WorkflowConfig registry metadata loaded.",
            data={
                "module_name": self.module_name,
                "file_name": self.file_name,
                "class_name": self.agent_name,
                "version": self.version,
                "import_path": "agents.workflow_agent.config.WorkflowConfig",
                "agent_type": "workflow_config_helper",
                "capabilities": [
                    "n8n_config",
                    "webhook_config",
                    "retry_config",
                    "approval_config",
                    "anti_spam_config",
                    "security_approval_payloads",
                    "verification_payloads",
                    "memory_payloads",
                    "audit_events",
                    "dashboard_safe_settings",
                    "saas_scoped_overrides",
                ],
                "requires_context": True,
                "requires_user_id": True,
                "requires_workspace_id": True,
                "safe_to_import": True,
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """Simple import/runtime health check."""

        settings = dataclass_to_dict(self.default_settings)
        env = settings.get("environment")
        return self._safe_result(
            message="WorkflowConfig health check passed.",
            data={
                "status": "ok",
                "module": self.module_name,
                "file": self.file_name,
                "class": self.agent_name,
                "version": self.version,
                "environment": env,
                "configured_scoped_overrides": len(self.config_store),
                "runtime_rate_keys": len(self._rate_limit_state),
                "runtime_fingerprint_keys": len(self._fingerprint_state),
            },
        )

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _load_default_settings_from_env(self) -> WorkflowSettings:
        """
        Load safe defaults from environment.

        Secrets are not read into config responses directly. Only env variable
        names are stored for secret resolution by secure connector layers.
        """

        env_raw = os.getenv("WILLIAM_ENV", os.getenv("APP_ENV", "development")).lower().strip()
        try:
            environment = WorkflowEnvironment(env_raw)
        except ValueError:
            environment = WorkflowEnvironment.DEVELOPMENT

        n8n_enabled = os.getenv("WORKFLOW_N8N_ENABLED", "false").lower() in {"1", "true", "yes"}
        webhook_enabled = os.getenv("WORKFLOW_WEBHOOKS_ENABLED", "true").lower() in {"1", "true", "yes"}
        anti_spam_enabled = os.getenv("WORKFLOW_ANTI_SPAM_ENABLED", "true").lower() in {"1", "true", "yes"}

        return WorkflowSettings(
            version=DEFAULT_VERSION,
            environment=environment,
            enabled=os.getenv("WORKFLOW_AGENT_ENABLED", "true").lower() in {"1", "true", "yes"},
            default_timezone=os.getenv("WORKFLOW_DEFAULT_TIMEZONE", "UTC"),
            n8n=N8nConfig(
                enabled=n8n_enabled,
                base_url=os.getenv("N8N_BASE_URL") or None,
                api_key_env=os.getenv("N8N_API_KEY_ENV", "N8N_API_KEY"),
                webhook_base_url=os.getenv("N8N_WEBHOOK_BASE_URL") or None,
                timeout_seconds=int(os.getenv("N8N_TIMEOUT_SECONDS", str(DEFAULT_N8N_TIMEOUT_SECONDS))),
                verify_ssl=os.getenv("N8N_VERIFY_SSL", "true").lower() in {"1", "true", "yes"},
                allow_unverified_ssl_in_dev=os.getenv("N8N_ALLOW_UNVERIFIED_SSL_IN_DEV", "false").lower()
                in {"1", "true", "yes"},
            ),
            webhooks=WebhookConfig(
                enabled=webhook_enabled,
                auth_mode=WebhookAuthMode(
                    os.getenv("WORKFLOW_WEBHOOK_AUTH_MODE", WebhookAuthMode.HMAC_SHA256.value)
                ),
                secret_env=os.getenv("WORKFLOW_WEBHOOK_SECRET_ENV", "WORKFLOW_WEBHOOK_SECRET"),
                bearer_token_env=os.getenv(
                    "WORKFLOW_WEBHOOK_BEARER_TOKEN_ENV",
                    "WORKFLOW_WEBHOOK_BEARER_TOKEN",
                ),
                timeout_seconds=int(
                    os.getenv("WORKFLOW_WEBHOOK_TIMEOUT_SECONDS", str(DEFAULT_WEBHOOK_TIMEOUT_SECONDS))
                ),
                max_payload_bytes=int(
                    os.getenv("WORKFLOW_WEBHOOK_MAX_PAYLOAD_BYTES", str(DEFAULT_WEBHOOK_MAX_PAYLOAD_BYTES))
                ),
                require_https=os.getenv("WORKFLOW_WEBHOOK_REQUIRE_HTTPS", "true").lower()
                in {"1", "true", "yes"},
            ),
            retries=RetryConfig(
                enabled=os.getenv("WORKFLOW_RETRIES_ENABLED", "true").lower() in {"1", "true", "yes"},
                max_attempts=int(os.getenv("WORKFLOW_RETRY_MAX_ATTEMPTS", str(DEFAULT_MAX_RETRY_ATTEMPTS))),
                base_delay_seconds=float(
                    os.getenv("WORKFLOW_RETRY_BASE_DELAY_SECONDS", str(DEFAULT_RETRY_BASE_DELAY_SECONDS))
                ),
                max_delay_seconds=float(
                    os.getenv("WORKFLOW_RETRY_MAX_DELAY_SECONDS", str(DEFAULT_RETRY_MAX_DELAY_SECONDS))
                ),
                backoff_multiplier=float(
                    os.getenv("WORKFLOW_RETRY_BACKOFF_MULTIPLIER", str(DEFAULT_RETRY_BACKOFF_MULTIPLIER))
                ),
            ),
            approvals=ApprovalConfig(
                mode=ApprovalMode(
                    os.getenv("WORKFLOW_APPROVAL_MODE", ApprovalMode.SENSITIVE_ONLY.value)
                ),
                bulk_threshold=int(os.getenv("WORKFLOW_APPROVAL_BULK_THRESHOLD", "25")),
            ),
            anti_spam=AntiSpamConfig(
                enabled=anti_spam_enabled,
                window_seconds=int(
                    os.getenv("WORKFLOW_ANTI_SPAM_WINDOW_SECONDS", str(DEFAULT_ANTI_SPAM_WINDOW_SECONDS))
                ),
                max_events_per_window=int(
                    os.getenv("WORKFLOW_ANTI_SPAM_MAX_EVENTS", str(DEFAULT_ANTI_SPAM_MAX_EVENTS))
                ),
            ),
            audit=AuditConfig(
                enabled=os.getenv("WORKFLOW_AUDIT_ENABLED", "true").lower() in {"1", "true", "yes"},
            ),
            dashboard=DashboardConfig(
                enabled=os.getenv("WORKFLOW_DASHBOARD_CONFIG_ENABLED", "true").lower()
                in {"1", "true", "yes"},
            ),
        )

    def _context_or_none(
        self,
        context: Union[TaskContext, Mapping[str, Any], None],
    ) -> Optional[Dict[str, Any]]:
        """Convert context into safe dictionary, if present."""

        if context is None:
            return None

        if isinstance(context, TaskContext):
            return dataclass_to_dict(context)

        if isinstance(context, Mapping):
            ctx = dict(context)
            ctx.setdefault("request_id", str(uuid.uuid4()))
            ctx.setdefault("metadata", {})
            return ctx

        return None

    def _scope_key(
        self,
        scope: ConfigScope,
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> str:
        """Build isolated config store key."""

        if scope == ConfigScope.GLOBAL:
            return "global"

        if scope == ConfigScope.USER:
            return f"user:{user_id}"

        if scope == ConfigScope.WORKSPACE:
            return f"workspace:{workspace_id}"

        return f"user_workspace:{user_id}:{workspace_id}"

    def _scoped_runtime_key(self, context: Mapping[str, Any], suffix: str) -> str:
        """Create runtime state key isolated by user/workspace."""

        return f"{context.get('user_id')}:{context.get('workspace_id')}:{suffix}"

    def _sanitize_override(self, override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitize override payload.

        Direct secret values are rejected/redacted by removing unsafe direct
        secret fields while allowing env-var reference fields like api_key_env.
        """

        cleaned = safe_deepcopy(override)

        forbidden_direct_secret_keys = {
            "api_key",
            "secret",
            "token",
            "password",
            "bearer_token",
            "private_key",
            "client_secret",
        }

        def walk(node: Any) -> Any:
            if isinstance(node, dict):
                result: Dict[str, Any] = {}
                for key, value in node.items():
                    lower = str(key).lower()
                    if lower in forbidden_direct_secret_keys:
                        continue
                    result[key] = walk(value)
                return result
            if isinstance(node, list):
                return [walk(item) for item in node]
            return node

        return walk(cleaned)

    def _override_touches_sensitive_settings(self, override: Mapping[str, Any]) -> bool:
        """Detect whether config update touches sensitive settings."""

        sensitive_top_keys = {"approvals", "webhooks", "n8n"}
        if any(key in override for key in sensitive_top_keys):
            return True

        flattened = json.dumps(override, sort_keys=True, default=str).lower()
        sensitive_markers = ["auth_mode", "secret_env", "bearer_token_env", "api_key_env", "require_https"]
        return any(marker in flattened for marker in sensitive_markers)

    def _validate_url_field(
        self,
        value: Any,
        field_name: str,
        require_https: bool = True,
        allow_empty: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """Validate URL-style config fields."""

        if value is None or value == "":
            if allow_empty:
                return None
            return self._error_result(
                message=f"{field_name} is required.",
                error="missing_url",
            )

        url = str(value).strip()
        if len(url) > 2048:
            return self._error_result(
                message=f"{field_name} is too long.",
                error="url_too_long",
            )

        if require_https and not SAFE_URL_SCHEME_PATTERN.match(url):
            allow_localhost_dev = (
                self.default_settings.environment != WorkflowEnvironment.PRODUCTION
                and (
                    url.startswith("http://localhost")
                    or url.startswith("http://127.0.0.1")
                    or url.startswith("http://0.0.0.0")
                )
            )
            if not allow_localhost_dev:
                return self._error_result(
                    message=f"{field_name} must use HTTPS.",
                    error="https_required",
                    data={"field": field_name},
                )

        return None

    def _body_to_bytes(
        self,
        body: Union[str, bytes, Mapping[str, Any], List[Any], None],
    ) -> bytes:
        """Convert webhook body to bytes."""

        if body is None:
            return b""
        if isinstance(body, bytes):
            return body
        if isinstance(body, str):
            return body.encode("utf-8")
        return json.dumps(body, sort_keys=True, default=str).encode("utf-8")

    def _parse_body(
        self,
        body: Union[str, bytes, Mapping[str, Any], List[Any], None],
    ) -> Union[Dict[str, Any], List[Any], str, None]:
        """Parse webhook body safely."""

        if body is None:
            return None
        if isinstance(body, Mapping):
            return dict(body)
        if isinstance(body, list):
            return body
        if isinstance(body, bytes):
            text = body.decode("utf-8", errors="replace")
        else:
            text = str(body)

        try:
            parsed = json.loads(text)
            return parsed
        except Exception:
            return text

    def _validate_webhook_auth(
        self,
        headers: Mapping[str, Any],
        body_bytes: bytes,
        webhooks: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Validate webhook auth according to configured mode."""

        mode = webhooks.get("auth_mode", WebhookAuthMode.HMAC_SHA256.value)

        if mode == WebhookAuthMode.NONE.value:
            return self._safe_result(
                message="Webhook auth skipped.",
                data={"auth_mode": mode, "authenticated": True},
            )

        if mode == WebhookAuthMode.BEARER_TOKEN.value:
            token_env = str(webhooks.get("bearer_token_env", "WORKFLOW_WEBHOOK_BEARER_TOKEN"))
            expected = os.getenv(token_env)
            if not expected:
                return self._error_result(
                    message="Webhook bearer token environment variable is not configured.",
                    error="missing_webhook_bearer_token",
                    data={"token_env": token_env},
                )

            authorization = str(headers.get("authorization") or headers.get("Authorization") or "")
            provided = authorization.replace("Bearer ", "", 1).strip()
            if not hmac.compare_digest(provided, expected):
                return self._error_result(
                    message="Invalid webhook bearer token.",
                    error="invalid_bearer_token",
                )

            return self._safe_result(
                message="Webhook bearer auth passed.",
                data={"auth_mode": mode, "authenticated": True},
            )

        secret_env = str(webhooks.get("secret_env", "WORKFLOW_WEBHOOK_SECRET"))
        secret = os.getenv(secret_env)
        if not secret:
            return self._error_result(
                message="Webhook secret environment variable is not configured.",
                error="missing_webhook_secret",
                data={"secret_env": secret_env},
            )

        if mode == WebhookAuthMode.SHARED_SECRET.value:
            provided = str(
                headers.get("x-workflow-secret")
                or headers.get("X-Workflow-Secret")
                or headers.get("x-webhook-secret")
                or ""
            )
            if not hmac.compare_digest(provided, secret):
                return self._error_result(
                    message="Invalid webhook shared secret.",
                    error="invalid_shared_secret",
                )

            return self._safe_result(
                message="Webhook shared secret auth passed.",
                data={"auth_mode": mode, "authenticated": True},
            )

        if mode == WebhookAuthMode.HMAC_SHA256.value:
            provided_signature = str(
                headers.get("x-workflow-signature")
                or headers.get("X-Workflow-Signature")
                or headers.get("x-hub-signature-256")
                or ""
            ).strip()

            if provided_signature.startswith("sha256="):
                provided_signature = provided_signature.split("=", 1)[1]

            expected_signature = hmac.new(
                secret.encode("utf-8"),
                body_bytes,
                hashlib.sha256,
            ).hexdigest()

            if not hmac.compare_digest(provided_signature, expected_signature):
                return self._error_result(
                    message="Invalid webhook HMAC signature.",
                    error="invalid_hmac_signature",
                )

            return self._safe_result(
                message="Webhook HMAC auth passed.",
                data={"auth_mode": mode, "authenticated": True},
            )

        return self._error_result(
            message="Unsupported webhook auth mode.",
            error="unsupported_webhook_auth_mode",
            data={"auth_mode": mode},
        )

    def _detect_spam_content(
        self,
        payload: Mapping[str, Any],
        anti_spam: Mapping[str, Any],
    ) -> List[str]:
        """Detect blocked domains/keywords in payload."""

        matches: List[str] = []
        text = json.dumps(payload, sort_keys=True, default=str).lower()

        for keyword in anti_spam.get("blocked_keywords", []):
            keyword_text = str(keyword).lower().strip()
            if keyword_text and keyword_text in text:
                matches.append(f"keyword:{keyword_text}")

        if anti_spam.get("block_disposable_email_domains", True):
            for domain in anti_spam.get("blocked_domains", []):
                domain_text = str(domain).lower().strip()
                if domain_text and domain_text in text:
                    matches.append(f"domain:{domain_text}")

        return matches

    def _cleanup_expired_state(self, state: Dict[str, float], now: Optional[float] = None) -> None:
        """Cleanup expired runtime keys."""

        current = now if now is not None else time.time()
        expired = [key for key, expires_at in state.items() if expires_at <= current]
        for key in expired:
            state.pop(key, None)


# Type alias after class-safe imports.
MutableConfigStore = Dict[str, Dict[str, Any]]


# =============================================================================
# Module-level convenience factory
# =============================================================================

def create_workflow_config(**kwargs: Any) -> WorkflowConfig:
    """
    Factory used by Agent Loader / Agent Registry / tests.
    """

    return WorkflowConfig(**kwargs)


def get_module_metadata() -> Dict[str, Any]:
    """
    Lightweight metadata without instantiating external integrations.
    """

    return {
        "module_name": MODULE_NAME,
        "file_name": FILE_NAME,
        "class_name": AGENT_NAME,
        "version": DEFAULT_VERSION,
        "import_path": "agents.workflow_agent.config.WorkflowConfig",
        "safe_to_import": True,
        "purpose": "Workflow settings, n8n, webhooks, retries, approvals, anti-spam.",
        "completion": 100.0,
    }


__all__ = [
    "WorkflowConfig",
    "WorkflowSettings",
    "TaskContext",
    "N8nConfig",
    "WebhookConfig",
    "RetryConfig",
    "ApprovalConfig",
    "AntiSpamConfig",
    "AuditConfig",
    "DashboardConfig",
    "WorkflowEnvironment",
    "ApprovalMode",
    "RetryMode",
    "WebhookAuthMode",
    "ConfigScope",
    "SensitiveAction",
    "EventSeverity",
    "create_workflow_config",
    "get_module_metadata",
]