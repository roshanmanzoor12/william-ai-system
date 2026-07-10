"""
agents/workflow_agent/form_pipeline.py

Purpose:
    Handles Form -> Validate -> Sheet -> WhatsApp -> CRM -> Email -> Follow-up.

Project:
    William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Architecture:
    This file belongs to the Workflow Agent module. It coordinates safe form intake
    and routes validated submissions through external business systems such as sheets,
    WhatsApp, CRM, email, and follow-up scheduling.

Safety Rules:
    - Every user/workspace-specific task must include user_id and workspace_id.
    - No memory, logs, tasks, analytics, or audit data may be mixed between users/workspaces.
    - Sensitive actions require Security Agent approval before execution.
    - Every completed action prepares Verification Agent payload.
    - Useful normalized context prepares Memory Agent payload.
    - All outputs use structured dict format:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": Optional[dict],
            "metadata": dict
        }

Compatibility:
    - Import-safe even if other William/Jarvis modules do not exist yet.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent routing, Dashboard/API, Security Agent, Memory Agent,
      and Verification Agent.
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
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ======================================================================================
# Safe optional imports
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the real William/Jarvis BaseAgent
        is available. The real BaseAgent should provide logging, routing,
        registry identity, lifecycle hooks, and shared agent utilities.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "workflow")
            self.logger = logging.getLogger(self.agent_name)


try:
    from agents.workflow_agent.sheet_connector import SheetConnector  # type: ignore
except Exception:  # pragma: no cover
    SheetConnector = None  # type: ignore

try:
    from agents.workflow_agent.whatsapp_connector import WhatsAppConnector  # type: ignore
except Exception:  # pragma: no cover
    WhatsAppConnector = None  # type: ignore

try:
    from agents.workflow_agent.crm_connector import CRMConnector  # type: ignore
except Exception:  # pragma: no cover
    CRMConnector = None  # type: ignore

try:
    from agents.workflow_agent.email_connector import EmailConnector  # type: ignore
except Exception:  # pragma: no cover
    EmailConnector = None  # type: ignore

try:
    from agents.workflow_agent.scheduler import WorkflowScheduler  # type: ignore
except Exception:  # pragma: no cover
    WorkflowScheduler = None  # type: ignore


# ======================================================================================
# Logging
# ======================================================================================

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ======================================================================================
# Constants
# ======================================================================================

DEFAULT_AGENT_NAME = "FormPipeline"
DEFAULT_AGENT_MODULE = "workflow_agent"
DEFAULT_AGENT_VERSION = "1.0.0"

MAX_FIELD_KEY_LENGTH = 120
MAX_FIELD_VALUE_LENGTH = 10_000
MAX_TOTAL_PAYLOAD_BYTES = 256_000
MAX_AUDIT_VALUE_LENGTH = 700

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
}

DEFAULT_REQUIRED_FIELDS = ("name", "phone")
DEFAULT_ALLOWED_CHANNELS = ("sheet", "whatsapp", "crm", "email", "follow_up")


# ======================================================================================
# Enums
# ======================================================================================

class PipelineStep(str, Enum):
    """Supported form pipeline steps."""

    RECEIVE = "receive"
    VALIDATE = "validate"
    SHEET = "sheet"
    WHATSAPP = "whatsapp"
    CRM = "crm"
    EMAIL = "email"
    FOLLOW_UP = "follow_up"
    VERIFY = "verify"
    MEMORY = "memory"
    AUDIT = "audit"


class SubmissionStatus(str, Enum):
    """Lifecycle status for a form submission."""

    RECEIVED = "received"
    VALIDATED = "validated"
    PARTIAL_SUCCESS = "partial_success"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    SECURITY_BLOCKED = "security_blocked"


class ValidationSeverity(str, Enum):
    """Validation issue severity."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


class ConsentStatus(str, Enum):
    """Consent status for contacting a submitted lead."""

    GRANTED = "granted"
    NOT_GRANTED = "not_granted"
    UNKNOWN = "unknown"


class ConnectorAction(str, Enum):
    """Actions performed by external connectors."""

    APPEND_ROW = "append_row"
    SEND_WHATSAPP = "send_whatsapp"
    UPSERT_CRM_LEAD = "upsert_crm_lead"
    SEND_EMAIL = "send_email"
    SCHEDULE_FOLLOW_UP = "schedule_follow_up"


# ======================================================================================
# Dataclasses
# ======================================================================================

@dataclass
class FormValidationIssue:
    """Represents one form validation issue."""

    field: str
    message: str
    severity: ValidationSeverity = ValidationSeverity.ERROR
    code: str = "validation_error"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "message": self.message,
            "severity": self.severity.value,
            "code": self.code,
        }


@dataclass
class FormPipelineConfig:
    """
    Configuration for FormPipeline.

    No secrets are stored here. Connector credentials should be resolved through
    secure connector configuration managed by App Connector / Security Agent.
    """

    pipeline_name: str = "default_form_pipeline"
    required_fields: Tuple[str, ...] = DEFAULT_REQUIRED_FIELDS
    optional_fields: Tuple[str, ...] = (
        "email",
        "service",
        "message",
        "source",
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "page_url",
        "referrer",
        "ip_address",
        "user_agent",
        "consent",
    )
    allowed_channels: Tuple[str, ...] = DEFAULT_ALLOWED_CHANNELS
    default_enabled_channels: Tuple[str, ...] = DEFAULT_ALLOWED_CHANNELS
    phone_default_country_code: str = "+1"
    allow_unknown_fields: bool = True
    reject_suspicious_payloads: bool = True
    require_contact_consent_for_messages: bool = False
    dedupe_window_seconds: int = 3600
    default_follow_up_delay_minutes: int = 15
    max_payload_bytes: int = MAX_TOTAL_PAYLOAD_BYTES
    max_field_value_length: int = MAX_FIELD_VALUE_LENGTH
    enable_memory_payload: bool = True
    enable_verification_payload: bool = True
    enable_audit_logs: bool = True
    enable_agent_events: bool = True
    dry_run: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FormSubmissionContext:
    """
    SaaS isolation context for every form submission.

    user_id and workspace_id are mandatory for user/workspace-scoped execution.
    """

    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: Optional[str] = None
    actor_id: Optional[str] = None
    role: Optional[str] = None
    subscription_id: Optional[str] = None
    agent_permissions: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def isolation_key(self) -> str:
        raw = f"{self.user_id}:{self.workspace_id}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class NormalizedFormSubmission:
    """Normalized and validated form submission."""

    submission_id: str
    user_id: str
    workspace_id: str
    fields: Dict[str, Any]
    raw_fields: Dict[str, Any]
    normalized_phone: Optional[str]
    normalized_email: Optional[str]
    service_interest: Optional[str]
    consent_status: ConsentStatus
    received_at: str
    source: Optional[str] = None
    page_url: Optional[str] = None
    referrer: Optional[str] = None
    utm: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        output = asdict(self)
        output["consent_status"] = self.consent_status.value
        return output


@dataclass
class PipelineStepResult:
    """Result for one pipeline step."""

    step: PipelineStep
    success: bool
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[Dict[str, Any]] = None
    duration_ms: int = 0
    skipped: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step": self.step.value,
            "success": self.success,
            "message": self.message,
            "data": self.data,
            "error": self.error,
            "duration_ms": self.duration_ms,
            "skipped": self.skipped,
        }


@dataclass
class PipelineRunResult:
    """Full pipeline execution result."""

    submission_id: str
    status: SubmissionStatus
    step_results: List[PipelineStepResult]
    verification_payload: Optional[Dict[str, Any]] = None
    memory_payload: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def success(self) -> bool:
        return self.status in {SubmissionStatus.COMPLETED, SubmissionStatus.PARTIAL_SUCCESS}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "submission_id": self.submission_id,
            "status": self.status.value,
            "success": self.success(),
            "step_results": [step.to_dict() for step in self.step_results],
            "verification_payload": self.verification_payload,
            "memory_payload": self.memory_payload,
            "metadata": self.metadata,
        }


# ======================================================================================
# Utility functions
# ======================================================================================

def _utc_now() -> str:
    """Return timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def _duration_ms(start: float) -> int:
    """Return elapsed milliseconds from monotonic start."""

    return int((time.monotonic() - start) * 1000)


def _safe_json_size(value: Any) -> int:
    """Return approximate JSON byte size safely."""

    try:
        return len(json.dumps(value, default=str).encode("utf-8"))
    except Exception:
        return len(str(value).encode("utf-8"))


def _truncate(value: Any, limit: int = MAX_AUDIT_VALUE_LENGTH) -> Any:
    """Truncate long string values for logs/audit payloads."""

    if isinstance(value, str) and len(value) > limit:
        return value[: limit - 3] + "..."
    return value


def _redact_key(key: str, value: Any) -> Any:
    """Redact value when key looks sensitive."""

    key_l = key.lower()
    if any(hint in key_l for hint in SENSITIVE_FIELD_HINTS):
        return "***REDACTED***"
    return value


def _redact_mapping(data: Mapping[str, Any]) -> Dict[str, Any]:
    """Recursively redact sensitive mapping values."""

    redacted: Dict[str, Any] = {}
    for key, value in data.items():
        safe_value = _redact_key(str(key), value)
        if isinstance(safe_value, Mapping):
            redacted[str(key)] = _redact_mapping(safe_value)
        elif isinstance(safe_value, list):
            redacted[str(key)] = [
                _redact_mapping(item) if isinstance(item, Mapping) else _truncate(item)
                for item in safe_value
            ]
        else:
            redacted[str(key)] = _truncate(safe_value)
    return redacted


def _normalize_key(key: str) -> str:
    """Normalize form field keys into snake_case."""

    key = str(key or "").strip()
    key = re.sub(r"[\s\-]+", "_", key)
    key = re.sub(r"[^a-zA-Z0-9_]", "", key)
    key = re.sub(r"_+", "_", key)
    return key.lower().strip("_")


def _normalize_email(value: Any) -> Optional[str]:
    """Normalize and validate an email address."""

    if value is None:
        return None

    email = str(value).strip().lower()
    if not email:
        return None

    if len(email) > 254:
        return None

    pattern = r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+$"
    if not re.match(pattern, email):
        return None

    return email


def _normalize_phone(value: Any, default_country_code: str = "+1") -> Optional[str]:
    """
    Normalize a phone number into a conservative E.164-like format.

    This does not guarantee carrier-level validity. It safely cleans common form
    input into a consistent format for downstream connectors.
    """

    if value is None:
        return None

    raw = str(value).strip()
    if not raw:
        return None

    digits = re.sub(r"\D", "", raw)

    if not digits:
        return None

    if raw.startswith("+"):
        normalized = "+" + digits
    elif len(digits) == 10 and default_country_code:
        normalized = f"{default_country_code}{digits}"
    elif len(digits) == 11 and digits.startswith("1"):
        normalized = f"+{digits}"
    elif default_country_code and not digits.startswith(default_country_code.replace("+", "")):
        normalized = f"{default_country_code}{digits}"
    else:
        normalized = f"+{digits}"

    if len(re.sub(r"\D", "", normalized)) < 7:
        return None

    if len(re.sub(r"\D", "", normalized)) > 15:
        return None

    return normalized


def _parse_bool(value: Any) -> Optional[bool]:
    """Parse common boolean-ish form values."""

    if value is None:
        return None

    if isinstance(value, bool):
        return value

    text = str(value).strip().lower()
    if text in {"true", "yes", "y", "1", "on", "agree", "agreed", "consent", "granted"}:
        return True
    if text in {"false", "no", "n", "0", "off", "deny", "denied", "not_granted"}:
        return False

    return None


def _derive_consent_status(fields: Mapping[str, Any]) -> ConsentStatus:
    """Resolve consent status from common form fields."""

    for key in ("consent", "contact_consent", "marketing_consent", "permission_to_contact"):
        if key in fields:
            parsed = _parse_bool(fields.get(key))
            if parsed is True:
                return ConsentStatus.GRANTED
            if parsed is False:
                return ConsentStatus.NOT_GRANTED

    return ConsentStatus.UNKNOWN


def _hash_submission(fields: Mapping[str, Any], user_id: str, workspace_id: str) -> str:
    """Create deterministic hash for dedupe checks."""

    relevant = {
        "user_id": user_id,
        "workspace_id": workspace_id,
        "phone": fields.get("phone") or fields.get("normalized_phone"),
        "email": fields.get("email"),
        "name": fields.get("name"),
        "service": fields.get("service"),
    }
    raw = json.dumps(relevant, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def _maybe_await(value: Union[Any, Awaitable[Any]]) -> Any:
    """Await value if awaitable, otherwise return value."""

    if inspect.isawaitable(value):
        return await value
    return value


# ======================================================================================
# Fallback connector classes
# ======================================================================================

class _FallbackConnector:
    """
    Safe dry fallback connector.

    This connector does not perform network or destructive operations. It returns
    structured simulated results so the file remains testable before concrete
    connector files are generated.
    """

    connector_name = "fallback_connector"

    def __init__(self, dry_run: bool = True, logger_: Optional[logging.Logger] = None) -> None:
        self.dry_run = dry_run
        self.logger = logger_ or logger

    async def append_row(self, **kwargs: Any) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "Sheet append simulated by fallback connector.",
            "data": {
                "connector": self.connector_name,
                "dry_run": True,
                "operation": "append_row",
                "received_keys": sorted(kwargs.keys()),
            },
            "error": None,
            "metadata": {"simulated": True, "timestamp": _utc_now()},
        }

    async def send_message(self, **kwargs: Any) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "WhatsApp message simulated by fallback connector.",
            "data": {
                "connector": self.connector_name,
                "dry_run": True,
                "operation": "send_message",
                "received_keys": sorted(kwargs.keys()),
            },
            "error": None,
            "metadata": {"simulated": True, "timestamp": _utc_now()},
        }

    async def upsert_lead(self, **kwargs: Any) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "CRM lead upsert simulated by fallback connector.",
            "data": {
                "connector": self.connector_name,
                "dry_run": True,
                "operation": "upsert_lead",
                "received_keys": sorted(kwargs.keys()),
            },
            "error": None,
            "metadata": {"simulated": True, "timestamp": _utc_now()},
        }

    async def send_email(self, **kwargs: Any) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "Email send simulated by fallback connector.",
            "data": {
                "connector": self.connector_name,
                "dry_run": True,
                "operation": "send_email",
                "received_keys": sorted(kwargs.keys()),
            },
            "error": None,
            "metadata": {"simulated": True, "timestamp": _utc_now()},
        }

    async def schedule_follow_up(self, **kwargs: Any) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "Follow-up scheduling simulated by fallback connector.",
            "data": {
                "connector": self.connector_name,
                "dry_run": True,
                "operation": "schedule_follow_up",
                "received_keys": sorted(kwargs.keys()),
            },
            "error": None,
            "metadata": {"simulated": True, "timestamp": _utc_now()},
        }


# ======================================================================================
# FormPipeline
# ======================================================================================

class FormPipeline(BaseAgent):
    """
    Production-ready form pipeline coordinator.

    Main responsibility:
        Receive a form payload, validate and normalize it, then safely route the
        lead through:
            1. Sheet
            2. WhatsApp
            3. CRM
            4. Email
            5. Follow-up scheduler

    Master Agent:
        Can route tasks to this class through `run_task()` or
        `process_form_submission()`.

    Security Agent:
        Sensitive external actions are checked through `_requires_security_check()`
        and `_request_security_approval()`.

    Memory Agent:
        Normalized useful form context is emitted through `_prepare_memory_payload()`.

    Verification Agent:
        Completion evidence is emitted through `_prepare_verification_payload()`.

    Dashboard/API:
        Every public method returns structured JSON-style dicts suitable for
        FastAPI responses, dashboard cards, audit logs, and task history.
    """

    agent_name = DEFAULT_AGENT_NAME
    agent_module = DEFAULT_AGENT_MODULE
    agent_version = DEFAULT_AGENT_VERSION

    def __init__(
        self,
        config: Optional[Union[FormPipelineConfig, Mapping[str, Any]]] = None,
        *,
        sheet_connector: Optional[Any] = None,
        whatsapp_connector: Optional[Any] = None,
        crm_connector: Optional[Any] = None,
        email_connector: Optional[Any] = None,
        scheduler: Optional[Any] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[..., Any]] = None,
        audit_logger: Optional[Callable[..., Any]] = None,
        logger_: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.agent_name, agent_type="workflow", **kwargs)

        self.logger = logger_ or getattr(self, "logger", logger) or logger

        if config is None:
            self.config = FormPipelineConfig()
        elif isinstance(config, FormPipelineConfig):
            self.config = config
        elif isinstance(config, Mapping):
            self.config = FormPipelineConfig(**dict(config))
        else:
            raise TypeError("config must be FormPipelineConfig, mapping, or None")

        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger

        self.sheet_connector = sheet_connector or self._build_optional_connector(
            SheetConnector,
            "sheet_connector",
        )
        self.whatsapp_connector = whatsapp_connector or self._build_optional_connector(
            WhatsAppConnector,
            "whatsapp_connector",
        )
        self.crm_connector = crm_connector or self._build_optional_connector(
            CRMConnector,
            "crm_connector",
        )
        self.email_connector = email_connector or self._build_optional_connector(
            EmailConnector,
            "email_connector",
        )
        self.scheduler = scheduler or self._build_optional_connector(
            WorkflowScheduler,
            "workflow_scheduler",
        )

        self._dedupe_cache: Dict[str, float] = {}

    # ----------------------------------------------------------------------------------
    # Public Master Agent / Router interface
    # ----------------------------------------------------------------------------------

    async def run_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Master Agent compatible task entrypoint.

        Expected task shape:
            {
                "action": "process_form_submission",
                "user_id": "...",
                "workspace_id": "...",
                "payload": {...},
                "channels": ["sheet", "whatsapp", "crm", "email", "follow_up"],
                "metadata": {...}
            }
        """

        action = str(task.get("action") or "process_form_submission").strip()

        if action not in {
            "process_form_submission",
            "validate_form_payload",
            "preview_form_pipeline",
        }:
            return self._error_result(
                message=f"Unsupported FormPipeline action: {action}",
                code="unsupported_action",
                metadata={"action": action, "agent": self.agent_name},
            )

        context = self._context_from_task(task)
        payload = task.get("payload") or task.get("form_payload") or {}
        channels = task.get("channels")

        if action == "validate_form_payload":
            return self.validate_form_payload(payload, context=context)

        if action == "preview_form_pipeline":
            return self.preview_form_pipeline(payload, context=context, channels=channels)

        return await self.process_form_submission(
            payload=payload,
            context=context,
            channels=channels,
            options=dict(task.get("options") or {}),
        )

    def validate_form_payload(
        self,
        payload: Mapping[str, Any],
        *,
        context: Optional[Union[FormSubmissionContext, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Validate and normalize a form payload without executing connector actions.
        """

        started = time.monotonic()

        try:
            ctx = self._ensure_context(context)
            context_result = self._validate_task_context(ctx)
            if not context_result["success"]:
                return context_result

            normalized_fields, raw_fields = self._normalize_payload(payload)
            issues = self._validate_normalized_fields(normalized_fields)

            if issues:
                has_errors = any(issue.severity == ValidationSeverity.ERROR for issue in issues)
                return self._safe_result(
                    success=not has_errors,
                    message="Form payload validation completed with issues."
                    if has_errors
                    else "Form payload validation completed with warnings.",
                    data={
                        "valid": not has_errors,
                        "issues": [issue.to_dict() for issue in issues],
                        "fields": self._safe_public_fields(normalized_fields),
                    },
                    metadata={
                        "duration_ms": _duration_ms(started),
                        "user_id": ctx.user_id,
                        "workspace_id": ctx.workspace_id,
                        "request_id": ctx.request_id,
                    },
                )

            submission = self._build_normalized_submission(ctx, normalized_fields, raw_fields)

            return self._safe_result(
                success=True,
                message="Form payload validated successfully.",
                data={
                    "valid": True,
                    "submission": submission.to_dict(),
                    "safe_fields": self._safe_public_fields(submission.fields),
                },
                metadata={
                    "duration_ms": _duration_ms(started),
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "request_id": ctx.request_id,
                },
            )

        except Exception as exc:
            self.logger.exception("Form payload validation failed.")
            return self._error_result(
                message="Form payload validation failed.",
                code="form_validation_exception",
                exception=exc,
                metadata={"duration_ms": _duration_ms(started)},
            )

    def preview_form_pipeline(
        self,
        payload: Mapping[str, Any],
        *,
        context: Optional[Union[FormSubmissionContext, Mapping[str, Any]]] = None,
        channels: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """
        Preview pipeline actions without executing external connector calls.
        """

        validation = self.validate_form_payload(payload, context=context)
        if not validation.get("success"):
            return validation

        selected_channels = self._resolve_channels(channels)

        plan = []
        for channel in selected_channels:
            plan.append(
                {
                    "channel": channel,
                    "requires_security_check": self._requires_security_check(
                        action=channel,
                        payload=payload,
                    ),
                    "dry_run": True,
                }
            )

        return self._safe_result(
            success=True,
            message="Form pipeline preview generated successfully.",
            data={
                "pipeline_name": self.config.pipeline_name,
                "selected_channels": selected_channels,
                "plan": plan,
                "validated_submission": validation.get("data", {}).get("submission"),
            },
            metadata={
                "agent": self.agent_name,
                "agent_version": self.agent_version,
                "timestamp": _utc_now(),
            },
        )

    async def process_form_submission(
        self,
        payload: Mapping[str, Any],
        *,
        context: Optional[Union[FormSubmissionContext, Mapping[str, Any]]] = None,
        channels: Optional[Iterable[str]] = None,
        options: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute the complete form pipeline.

        Args:
            payload:
                Raw form payload from website, webhook, dashboard, API, chatbot,
                or Workflow Agent trigger.

            context:
                SaaS isolation context. Must include user_id and workspace_id.

            channels:
                Optional subset of:
                    sheet, whatsapp, crm, email, follow_up

            options:
                Optional runtime options:
                    {
                        "dry_run": bool,
                        "skip_dedupe": bool,
                        "follow_up_delay_minutes": int,
                        "email_to": str,
                        "notify_owner": bool
                    }
        """

        started = time.monotonic()
        step_results: List[PipelineStepResult] = []
        options_dict = dict(options or {})
        dry_run = bool(options_dict.get("dry_run", self.config.dry_run))

        try:
            ctx = self._ensure_context(context)
            context_validation = self._validate_task_context(ctx)
            if not context_validation["success"]:
                return context_validation

            await self._emit_agent_event(
                event_type="form_pipeline.started",
                context=ctx,
                payload={
                    "pipeline_name": self.config.pipeline_name,
                    "channels": list(channels or self.config.default_enabled_channels),
                    "dry_run": dry_run,
                },
            )

            receive_step = PipelineStepResult(
                step=PipelineStep.RECEIVE,
                success=True,
                message="Form payload received.",
                data={
                    "payload_size_bytes": _safe_json_size(payload),
                    "safe_payload": _redact_mapping(dict(payload)),
                },
            )
            step_results.append(receive_step)

            normalized_fields, raw_fields = self._normalize_payload(payload)
            validation_started = time.monotonic()
            issues = self._validate_normalized_fields(normalized_fields)

            if issues:
                validation_result = PipelineStepResult(
                    step=PipelineStep.VALIDATE,
                    success=False,
                    message="Form validation failed.",
                    data={"issues": [issue.to_dict() for issue in issues]},
                    error={
                        "code": "validation_failed",
                        "details": [issue.to_dict() for issue in issues],
                    },
                    duration_ms=_duration_ms(validation_started),
                )
                step_results.append(validation_result)

                run_result = PipelineRunResult(
                    submission_id="unavailable",
                    status=SubmissionStatus.REJECTED,
                    step_results=step_results,
                    metadata=self._base_metadata(ctx, started),
                )

                await self._log_audit_event(
                    event_type="form_pipeline.validation_failed",
                    context=ctx,
                    payload=run_result.to_dict(),
                )

                return self._safe_result(
                    success=False,
                    message="Form submission rejected because validation failed.",
                    data=run_result.to_dict(),
                    error={
                        "code": "validation_failed",
                        "details": [issue.to_dict() for issue in issues],
                    },
                    metadata=self._base_metadata(ctx, started),
                )

            submission = self._build_normalized_submission(ctx, normalized_fields, raw_fields)

            validation_step = PipelineStepResult(
                step=PipelineStep.VALIDATE,
                success=True,
                message="Form payload validated and normalized.",
                data={
                    "submission_id": submission.submission_id,
                    "safe_fields": self._safe_public_fields(submission.fields),
                    "consent_status": submission.consent_status.value,
                },
                duration_ms=_duration_ms(validation_started),
            )
            step_results.append(validation_step)

            if not options_dict.get("skip_dedupe", False):
                duplicate_result = self._check_and_store_dedupe(submission)
                if duplicate_result.get("duplicate"):
                    run_result = PipelineRunResult(
                        submission_id=submission.submission_id,
                        status=SubmissionStatus.REJECTED,
                        step_results=step_results,
                        metadata={
                            **self._base_metadata(ctx, started),
                            "duplicate": True,
                            "dedupe_hash": duplicate_result.get("dedupe_hash"),
                        },
                    )
                    return self._safe_result(
                        success=False,
                        message="Duplicate form submission rejected within dedupe window.",
                        data=run_result.to_dict(),
                        error={
                            "code": "duplicate_submission",
                            "details": duplicate_result,
                        },
                        metadata=self._base_metadata(ctx, started),
                    )

            selected_channels = self._resolve_channels(channels)

            if self.config.require_contact_consent_for_messages:
                if submission.consent_status == ConsentStatus.NOT_GRANTED:
                    selected_channels = [
                        channel
                        for channel in selected_channels
                        if channel not in {"whatsapp", "email", "follow_up"}
                    ]

            if "sheet" in selected_channels:
                step_results.append(
                    await self._execute_step_with_security(
                        step=PipelineStep.SHEET,
                        action=ConnectorAction.APPEND_ROW.value,
                        context=ctx,
                        submission=submission,
                        dry_run=dry_run,
                        executor=lambda: self._send_to_sheet(ctx, submission, dry_run=dry_run),
                    )
                )

            if "whatsapp" in selected_channels:
                step_results.append(
                    await self._execute_step_with_security(
                        step=PipelineStep.WHATSAPP,
                        action=ConnectorAction.SEND_WHATSAPP.value,
                        context=ctx,
                        submission=submission,
                        dry_run=dry_run,
                        executor=lambda: self._send_to_whatsapp(ctx, submission, dry_run=dry_run),
                    )
                )

            if "crm" in selected_channels:
                step_results.append(
                    await self._execute_step_with_security(
                        step=PipelineStep.CRM,
                        action=ConnectorAction.UPSERT_CRM_LEAD.value,
                        context=ctx,
                        submission=submission,
                        dry_run=dry_run,
                        executor=lambda: self._send_to_crm(ctx, submission, dry_run=dry_run),
                    )
                )

            if "email" in selected_channels:
                step_results.append(
                    await self._execute_step_with_security(
                        step=PipelineStep.EMAIL,
                        action=ConnectorAction.SEND_EMAIL.value,
                        context=ctx,
                        submission=submission,
                        dry_run=dry_run,
                        executor=lambda: self._send_email(ctx, submission, options_dict, dry_run=dry_run),
                    )
                )

            if "follow_up" in selected_channels:
                step_results.append(
                    await self._execute_step_with_security(
                        step=PipelineStep.FOLLOW_UP,
                        action=ConnectorAction.SCHEDULE_FOLLOW_UP.value,
                        context=ctx,
                        submission=submission,
                        dry_run=dry_run,
                        executor=lambda: self._schedule_follow_up(
                            ctx,
                            submission,
                            options_dict,
                            dry_run=dry_run,
                        ),
                    )
                )

            successful_actions = [
                item for item in step_results
                if item.step not in {PipelineStep.RECEIVE, PipelineStep.VALIDATE}
                and item.success
                and not item.skipped
            ]
            failed_actions = [
                item for item in step_results
                if item.step not in {PipelineStep.RECEIVE, PipelineStep.VALIDATE}
                and not item.success
                and not item.skipped
            ]

            if failed_actions and successful_actions:
                status = SubmissionStatus.PARTIAL_SUCCESS
            elif failed_actions and not successful_actions:
                status = SubmissionStatus.FAILED
            else:
                status = SubmissionStatus.COMPLETED

            verification_payload = None
            if self.config.enable_verification_payload:
                verification_payload = self._prepare_verification_payload(
                    context=ctx,
                    submission=submission,
                    step_results=step_results,
                    status=status,
                )

            memory_payload = None
            if self.config.enable_memory_payload:
                memory_payload = self._prepare_memory_payload(
                    context=ctx,
                    submission=submission,
                    step_results=step_results,
                    status=status,
                )

            run_result = PipelineRunResult(
                submission_id=submission.submission_id,
                status=status,
                step_results=step_results,
                verification_payload=verification_payload,
                memory_payload=memory_payload,
                metadata={
                    **self._base_metadata(ctx, started),
                    "channels": selected_channels,
                    "dry_run": dry_run,
                    "successful_action_count": len(successful_actions),
                    "failed_action_count": len(failed_actions),
                },
            )

            await self._emit_agent_event(
                event_type="form_pipeline.completed",
                context=ctx,
                payload=run_result.to_dict(),
            )

            await self._log_audit_event(
                event_type="form_pipeline.completed",
                context=ctx,
                payload=run_result.to_dict(),
            )

            return self._safe_result(
                success=run_result.success(),
                message=(
                    "Form pipeline completed successfully."
                    if status == SubmissionStatus.COMPLETED
                    else "Form pipeline completed with partial success."
                    if status == SubmissionStatus.PARTIAL_SUCCESS
                    else "Form pipeline failed."
                ),
                data=run_result.to_dict(),
                error=None if run_result.success() else {
                    "code": "pipeline_failed",
                    "failed_steps": [step.to_dict() for step in failed_actions],
                },
                metadata=self._base_metadata(ctx, started),
            )

        except Exception as exc:
            self.logger.exception("Form pipeline execution failed.")
            return self._error_result(
                message="Form pipeline execution failed.",
                code="form_pipeline_exception",
                exception=exc,
                metadata={"duration_ms": _duration_ms(started)},
            )

    # ----------------------------------------------------------------------------------
    # Connector step execution
    # ----------------------------------------------------------------------------------

    async def _execute_step_with_security(
        self,
        *,
        step: PipelineStep,
        action: str,
        context: FormSubmissionContext,
        submission: NormalizedFormSubmission,
        dry_run: bool,
        executor: Callable[[], Awaitable[Dict[str, Any]]],
    ) -> PipelineStepResult:
        """Execute one connector step after optional Security Agent approval."""

        started = time.monotonic()

        try:
            security_required = self._requires_security_check(
                action=action,
                payload=submission.to_dict(),
            )

            if security_required:
                approval = await self._request_security_approval(
                    action=action,
                    context=context,
                    payload={
                        "submission_id": submission.submission_id,
                        "step": step.value,
                        "safe_submission": self._safe_public_fields(submission.fields),
                        "dry_run": dry_run,
                    },
                )

                if not approval.get("approved", False):
                    return PipelineStepResult(
                        step=step,
                        success=False,
                        message=f"{step.value} blocked by Security Agent.",
                        data={"security_approval": approval},
                        error={
                            "code": "security_blocked",
                            "details": approval,
                        },
                        duration_ms=_duration_ms(started),
                    )

            if dry_run:
                return PipelineStepResult(
                    step=step,
                    success=True,
                    message=f"{step.value} simulated successfully in dry-run mode.",
                    data={
                        "dry_run": True,
                        "action": action,
                        "submission_id": submission.submission_id,
                    },
                    duration_ms=_duration_ms(started),
                )

            connector_result = await executor()
            success = bool(connector_result.get("success", False))

            return PipelineStepResult(
                step=step,
                success=success,
                message=str(connector_result.get("message") or f"{step.value} finished."),
                data=dict(connector_result.get("data") or {}),
                error=connector_result.get("error"),
                duration_ms=_duration_ms(started),
            )

        except Exception as exc:
            self.logger.exception("Pipeline step failed: %s", step.value)
            return PipelineStepResult(
                step=step,
                success=False,
                message=f"{step.value} failed.",
                error={
                    "code": f"{step.value}_exception",
                    "type": exc.__class__.__name__,
                    "message": str(exc),
                },
                duration_ms=_duration_ms(started),
            )

    async def _send_to_sheet(
        self,
        context: FormSubmissionContext,
        submission: NormalizedFormSubmission,
        *,
        dry_run: bool,
    ) -> Dict[str, Any]:
        """Append normalized submission to sheet connector."""

        row = self._build_sheet_row(context, submission)

        connector = self.sheet_connector
        if hasattr(connector, "append_form_submission"):
            return await _maybe_await(
                connector.append_form_submission(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    submission=submission.to_dict(),
                    row=row,
                    metadata=self._connector_metadata(context, submission),
                )
            )

        if hasattr(connector, "append_row"):
            return await _maybe_await(
                connector.append_row(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    row=row,
                    metadata=self._connector_metadata(context, submission),
                )
            )

        return self._safe_result(
            success=False,
            message="Sheet connector does not support append_row.",
            data={},
            error={"code": "unsupported_sheet_connector"},
            metadata=self._connector_metadata(context, submission),
        )

    async def _send_to_whatsapp(
        self,
        context: FormSubmissionContext,
        submission: NormalizedFormSubmission,
        *,
        dry_run: bool,
    ) -> Dict[str, Any]:
        """Send WhatsApp notification/message for the submission."""

        if not submission.normalized_phone:
            return self._safe_result(
                success=False,
                message="WhatsApp step skipped because phone number is missing or invalid.",
                data={"submission_id": submission.submission_id},
                error={"code": "missing_phone"},
                metadata=self._connector_metadata(context, submission),
            )

        message = self._build_whatsapp_message(submission)
        connector = self.whatsapp_connector

        if hasattr(connector, "send_form_lead_message"):
            return await _maybe_await(
                connector.send_form_lead_message(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    phone=submission.normalized_phone,
                    message=message,
                    submission=submission.to_dict(),
                    metadata=self._connector_metadata(context, submission),
                )
            )

        if hasattr(connector, "send_message"):
            return await _maybe_await(
                connector.send_message(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    to=submission.normalized_phone,
                    message=message,
                    metadata=self._connector_metadata(context, submission),
                )
            )

        return self._safe_result(
            success=False,
            message="WhatsApp connector does not support send_message.",
            data={},
            error={"code": "unsupported_whatsapp_connector"},
            metadata=self._connector_metadata(context, submission),
        )

    async def _send_to_crm(
        self,
        context: FormSubmissionContext,
        submission: NormalizedFormSubmission,
        *,
        dry_run: bool,
    ) -> Dict[str, Any]:
        """Create or update CRM lead."""

        lead = self._build_crm_lead(context, submission)
        connector = self.crm_connector

        if hasattr(connector, "upsert_form_lead"):
            return await _maybe_await(
                connector.upsert_form_lead(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    lead=lead,
                    submission=submission.to_dict(),
                    metadata=self._connector_metadata(context, submission),
                )
            )

        if hasattr(connector, "upsert_lead"):
            return await _maybe_await(
                connector.upsert_lead(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    lead=lead,
                    metadata=self._connector_metadata(context, submission),
                )
            )

        return self._safe_result(
            success=False,
            message="CRM connector does not support upsert_lead.",
            data={},
            error={"code": "unsupported_crm_connector"},
            metadata=self._connector_metadata(context, submission),
        )

    async def _send_email(
        self,
        context: FormSubmissionContext,
        submission: NormalizedFormSubmission,
        options: Mapping[str, Any],
        *,
        dry_run: bool,
    ) -> Dict[str, Any]:
        """Send email notification or lead confirmation."""

        email_payload = self._build_email_payload(submission, options)
        connector = self.email_connector

        if hasattr(connector, "send_form_notification"):
            return await _maybe_await(
                connector.send_form_notification(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    email_payload=email_payload,
                    submission=submission.to_dict(),
                    metadata=self._connector_metadata(context, submission),
                )
            )

        if hasattr(connector, "send_email"):
            return await _maybe_await(
                connector.send_email(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    **email_payload,
                    metadata=self._connector_metadata(context, submission),
                )
            )

        return self._safe_result(
            success=False,
            message="Email connector does not support send_email.",
            data={},
            error={"code": "unsupported_email_connector"},
            metadata=self._connector_metadata(context, submission),
        )

    async def _schedule_follow_up(
        self,
        context: FormSubmissionContext,
        submission: NormalizedFormSubmission,
        options: Mapping[str, Any],
        *,
        dry_run: bool,
    ) -> Dict[str, Any]:
        """Schedule follow-up task for the lead."""

        delay_minutes = int(
            options.get(
                "follow_up_delay_minutes",
                self.config.default_follow_up_delay_minutes,
            )
        )
        follow_up_at = datetime.now(timezone.utc) + timedelta(minutes=delay_minutes)

        follow_up_payload = {
            "title": f"Follow up with {submission.fields.get('name', 'new lead')}",
            "submission_id": submission.submission_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "lead_name": submission.fields.get("name"),
            "lead_phone": submission.normalized_phone,
            "lead_email": submission.normalized_email,
            "service_interest": submission.service_interest,
            "follow_up_at": follow_up_at.isoformat(),
            "source": submission.source,
            "priority": self._derive_follow_up_priority(submission),
            "notes": self._build_follow_up_notes(submission),
        }

        connector = self.scheduler

        if hasattr(connector, "schedule_form_follow_up"):
            return await _maybe_await(
                connector.schedule_form_follow_up(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    follow_up=follow_up_payload,
                    metadata=self._connector_metadata(context, submission),
                )
            )

        if hasattr(connector, "schedule_follow_up"):
            return await _maybe_await(
                connector.schedule_follow_up(
                    user_id=context.user_id,
                    workspace_id=context.workspace_id,
                    follow_up=follow_up_payload,
                    metadata=self._connector_metadata(context, submission),
                )
            )

        return self._safe_result(
            success=False,
            message="Scheduler connector does not support schedule_follow_up.",
            data={},
            error={"code": "unsupported_scheduler_connector"},
            metadata=self._connector_metadata(context, submission),
        )

    # ----------------------------------------------------------------------------------
    # Payload normalization and validation
    # ----------------------------------------------------------------------------------

    def _normalize_payload(
        self,
        payload: Mapping[str, Any],
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """Normalize raw form payload into safe snake_case fields."""

        if not isinstance(payload, Mapping):
            raise TypeError("payload must be a mapping/dict")

        payload_size = _safe_json_size(payload)
        if payload_size > self.config.max_payload_bytes:
            raise ValueError(
                f"payload size exceeds limit: {payload_size} > {self.config.max_payload_bytes}"
            )

        normalized: Dict[str, Any] = {}
        raw_fields: Dict[str, Any] = {}

        for key, value in payload.items():
            normalized_key = _normalize_key(str(key))

            if not normalized_key:
                continue

            if len(normalized_key) > MAX_FIELD_KEY_LENGTH:
                normalized_key = normalized_key[:MAX_FIELD_KEY_LENGTH]

            safe_value = self._normalize_value(value)

            if isinstance(safe_value, str) and len(safe_value) > self.config.max_field_value_length:
                safe_value = safe_value[: self.config.max_field_value_length]

            normalized[normalized_key] = safe_value
            raw_fields[str(key)] = value

        aliases = {
            "full_name": "name",
            "your_name": "name",
            "first_name": "name",
            "phone_number": "phone",
            "mobile": "phone",
            "mobile_number": "phone",
            "contact": "phone",
            "contact_number": "phone",
            "email_address": "email",
            "service_name": "service",
            "selected_service": "service",
            "interest": "service",
            "service_interest": "service",
            "comments": "message",
            "description": "message",
            "details": "message",
            "website_url": "page_url",
            "landing_page": "page_url",
        }

        for source_key, target_key in aliases.items():
            if source_key in normalized and target_key not in normalized:
                normalized[target_key] = normalized[source_key]

        normalized_email = _normalize_email(normalized.get("email"))
        normalized_phone = _normalize_phone(
            normalized.get("phone"),
            default_country_code=self.config.phone_default_country_code,
        )

        if normalized_email:
            normalized["email"] = normalized_email

        if normalized_phone:
            normalized["phone"] = normalized_phone
            normalized["normalized_phone"] = normalized_phone

        if normalized_email:
            normalized["normalized_email"] = normalized_email

        return normalized, raw_fields

    def _normalize_value(self, value: Any) -> Any:
        """Normalize one field value safely."""

        if value is None:
            return None

        if isinstance(value, (int, float, bool)):
            return value

        if isinstance(value, str):
            cleaned = value.strip()
            cleaned = re.sub(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "", cleaned)
            return cleaned

        if isinstance(value, list):
            return [self._normalize_value(item) for item in value[:100]]

        if isinstance(value, tuple):
            return [self._normalize_value(item) for item in value[:100]]

        if isinstance(value, Mapping):
            nested: Dict[str, Any] = {}
            for key, nested_value in list(value.items())[:100]:
                nested[_normalize_key(str(key))] = self._normalize_value(nested_value)
            return nested

        return str(value).strip()

    def _validate_normalized_fields(
        self,
        fields: Mapping[str, Any],
    ) -> List[FormValidationIssue]:
        """Validate required fields, suspicious content, and contact formats."""

        issues: List[FormValidationIssue] = []

        if not fields:
            return [
                FormValidationIssue(
                    field="payload",
                    message="Form payload is empty.",
                    severity=ValidationSeverity.ERROR,
                    code="empty_payload",
                )
            ]

        for required in self.config.required_fields:
            if required not in fields or fields.get(required) in {None, ""}:
                issues.append(
                    FormValidationIssue(
                        field=required,
                        message=f"Required field is missing: {required}",
                        severity=ValidationSeverity.ERROR,
                        code="missing_required_field",
                    )
                )

        if "phone" in fields and fields.get("phone"):
            if not _normalize_phone(
                fields.get("phone"),
                default_country_code=self.config.phone_default_country_code,
            ):
                issues.append(
                    FormValidationIssue(
                        field="phone",
                        message="Phone number is invalid.",
                        severity=ValidationSeverity.ERROR,
                        code="invalid_phone",
                    )
                )

        if "email" in fields and fields.get("email"):
            if not _normalize_email(fields.get("email")):
                issues.append(
                    FormValidationIssue(
                        field="email",
                        message="Email address is invalid.",
                        severity=ValidationSeverity.WARNING,
                        code="invalid_email",
                    )
                )

        if self.config.reject_suspicious_payloads:
            suspicious = self._detect_suspicious_fields(fields)
            issues.extend(suspicious)

        if not self.config.allow_unknown_fields:
            allowed = set(self.config.required_fields) | set(self.config.optional_fields)
            for key in fields.keys():
                if key not in allowed and not key.startswith("utm_"):
                    issues.append(
                        FormValidationIssue(
                            field=key,
                            message=f"Unknown field is not allowed: {key}",
                            severity=ValidationSeverity.WARNING,
                            code="unknown_field",
                        )
                    )

        return issues

    def _detect_suspicious_fields(
        self,
        fields: Mapping[str, Any],
    ) -> List[FormValidationIssue]:
        """Detect basic spam/injection indicators without blocking normal lead data."""

        issues: List[FormValidationIssue] = []

        honeypot_keys = {"website", "url2", "company_website_hidden", "fax"}
        for key in honeypot_keys:
            if key in fields and str(fields.get(key) or "").strip():
                issues.append(
                    FormValidationIssue(
                        field=key,
                        message="Honeypot field was filled.",
                        severity=ValidationSeverity.ERROR,
                        code="honeypot_triggered",
                    )
                )

        suspicious_patterns = [
            r"<script\b",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"\bUNION\b.+\bSELECT\b",
            r"\bDROP\b.+\bTABLE\b",
        ]

        for key, value in fields.items():
            if not isinstance(value, str):
                continue

            lower_value = value.lower()

            for pattern in suspicious_patterns:
                if re.search(pattern, lower_value, flags=re.IGNORECASE | re.DOTALL):
                    issues.append(
                        FormValidationIssue(
                            field=key,
                            message="Suspicious content detected.",
                            severity=ValidationSeverity.ERROR,
                            code="suspicious_content",
                        )
                    )
                    break

        return issues

    def _build_normalized_submission(
        self,
        context: FormSubmissionContext,
        fields: Mapping[str, Any],
        raw_fields: Mapping[str, Any],
    ) -> NormalizedFormSubmission:
        """Build normalized submission dataclass."""

        submission_id = str(uuid.uuid4())
        utm = {
            key: fields.get(key)
            for key in (
                "utm_source",
                "utm_medium",
                "utm_campaign",
                "utm_term",
                "utm_content",
            )
            if fields.get(key)
        }

        return NormalizedFormSubmission(
            submission_id=submission_id,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            fields=dict(fields),
            raw_fields=dict(raw_fields),
            normalized_phone=_normalize_phone(
                fields.get("phone"),
                default_country_code=self.config.phone_default_country_code,
            ),
            normalized_email=_normalize_email(fields.get("email")),
            service_interest=str(fields.get("service")).strip()
            if fields.get("service")
            else None,
            consent_status=_derive_consent_status(fields),
            received_at=_utc_now(),
            source=str(fields.get("source")).strip() if fields.get("source") else None,
            page_url=str(fields.get("page_url")).strip() if fields.get("page_url") else None,
            referrer=str(fields.get("referrer")).strip() if fields.get("referrer") else None,
            utm=utm,
            metadata={
                "request_id": context.request_id,
                "task_id": context.task_id,
                "isolation_key": context.isolation_key(),
                "payload_hash": _hash_submission(fields, context.user_id, context.workspace_id),
            },
        )

    # ----------------------------------------------------------------------------------
    # Payload builders for connectors
    # ----------------------------------------------------------------------------------

    def _build_sheet_row(
        self,
        context: FormSubmissionContext,
        submission: NormalizedFormSubmission,
    ) -> Dict[str, Any]:
        """Build sheet row structure."""

        fields = submission.fields

        return {
            "submission_id": submission.submission_id,
            "received_at": submission.received_at,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "name": fields.get("name"),
            "phone": submission.normalized_phone,
            "email": submission.normalized_email,
            "service": submission.service_interest,
            "message": fields.get("message"),
            "source": submission.source,
            "page_url": submission.page_url,
            "referrer": submission.referrer,
            "utm_source": submission.utm.get("utm_source"),
            "utm_medium": submission.utm.get("utm_medium"),
            "utm_campaign": submission.utm.get("utm_campaign"),
            "utm_term": submission.utm.get("utm_term"),
            "utm_content": submission.utm.get("utm_content"),
            "consent_status": submission.consent_status.value,
            "status": SubmissionStatus.VALIDATED.value,
            "safe_metadata": json.dumps(_redact_mapping(submission.metadata), default=str),
        }

    def _build_whatsapp_message(self, submission: NormalizedFormSubmission) -> str:
        """Build concise WhatsApp lead notification message."""

        fields = submission.fields
        name = fields.get("name") or "New Lead"
        phone = submission.normalized_phone or fields.get("phone") or "Not provided"
        service = submission.service_interest or "Not specified"
        source = submission.source or submission.page_url or "Website form"
        message = fields.get("message") or "No message provided"

        return (
            "New form lead received:\n"
            f"Name: {name}\n"
            f"Phone: {phone}\n"
            f"Email: {submission.normalized_email or 'Not provided'}\n"
            f"Service: {service}\n"
            f"Source: {source}\n"
            f"Message: {message}\n"
            f"Submission ID: {submission.submission_id}"
        )

    def _build_crm_lead(
        self,
        context: FormSubmissionContext,
        submission: NormalizedFormSubmission,
    ) -> Dict[str, Any]:
        """Build CRM lead payload."""

        fields = submission.fields

        return {
            "external_id": submission.submission_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "name": fields.get("name"),
            "phone": submission.normalized_phone,
            "email": submission.normalized_email,
            "service_interest": submission.service_interest,
            "lead_source": submission.source or "form",
            "page_url": submission.page_url,
            "referrer": submission.referrer,
            "message": fields.get("message"),
            "status": "new",
            "stage": "form_submitted",
            "priority": self._derive_follow_up_priority(submission),
            "consent_status": submission.consent_status.value,
            "utm": submission.utm,
            "custom_fields": self._extract_custom_fields(fields),
            "created_at": submission.received_at,
            "metadata": _redact_mapping(submission.metadata),
        }

    def _build_email_payload(
        self,
        submission: NormalizedFormSubmission,
        options: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Build email payload for owner notification or lead confirmation."""

        fields = submission.fields
        to_email = options.get("email_to") or options.get("notification_email")

        subject = options.get("email_subject") or (
            f"New Lead: {fields.get('name', 'Website Form')} - "
            f"{submission.service_interest or 'Service Interest'}"
        )

        body = (
            "A new form lead has been received.\n\n"
            f"Submission ID: {submission.submission_id}\n"
            f"Received At: {submission.received_at}\n"
            f"Name: {fields.get('name')}\n"
            f"Phone: {submission.normalized_phone or 'Not provided'}\n"
            f"Email: {submission.normalized_email or 'Not provided'}\n"
            f"Service: {submission.service_interest or 'Not specified'}\n"
            f"Source: {submission.source or 'Not specified'}\n"
            f"Page URL: {submission.page_url or 'Not provided'}\n"
            f"Referrer: {submission.referrer or 'Not provided'}\n"
            f"Consent: {submission.consent_status.value}\n\n"
            f"Message:\n{fields.get('message') or 'No message provided'}\n"
        )

        payload: Dict[str, Any] = {
            "to": to_email,
            "subject": subject,
            "body": body,
            "submission_id": submission.submission_id,
        }

        if options.get("cc"):
            payload["cc"] = options.get("cc")

        if options.get("bcc"):
            payload["bcc"] = options.get("bcc")

        if not to_email and submission.normalized_email and options.get("send_confirmation_to_lead"):
            payload["to"] = submission.normalized_email
            payload["subject"] = options.get("lead_confirmation_subject") or "We received your request"
            payload["body"] = (
                f"Hi {fields.get('name', '')},\n\n"
                "Thank you. We received your request and our team will review it shortly.\n\n"
                f"Service: {submission.service_interest or 'Not specified'}\n"
                f"Reference ID: {submission.submission_id}\n\n"
                "Regards,\n"
                "Digital Promotix"
            )

        return payload

    def _extract_custom_fields(self, fields: Mapping[str, Any]) -> Dict[str, Any]:
        """Return fields not part of standard CRM schema."""

        standard = {
            "name",
            "phone",
            "normalized_phone",
            "email",
            "normalized_email",
            "service",
            "message",
            "source",
            "page_url",
            "referrer",
            "consent",
            "contact_consent",
            "marketing_consent",
            "permission_to_contact",
            "utm_source",
            "utm_medium",
            "utm_campaign",
            "utm_term",
            "utm_content",
            "ip_address",
            "user_agent",
        }

        custom = {
            key: value
            for key, value in fields.items()
            if key not in standard
        }

        return _redact_mapping(custom)

    def _derive_follow_up_priority(
        self,
        submission: NormalizedFormSubmission,
    ) -> str:
        """Derive simple lead priority for follow-up."""

        service = (submission.service_interest or "").lower()
        message = str(submission.fields.get("message") or "").lower()

        high_intent_terms = {
            "urgent",
            "asap",
            "today",
            "now",
            "call me",
            "quote",
            "pricing",
            "buy",
            "hire",
            "start",
            "consultation",
        }

        premium_services = {
            "google ads",
            "ppc",
            "seo",
            "ai automation",
            "website",
            "web development",
            "crm",
            "voice agent",
        }

        if any(term in message for term in high_intent_terms):
            return "high"

        if any(term in service for term in premium_services):
            return "medium"

        return "normal"

    def _build_follow_up_notes(
        self,
        submission: NormalizedFormSubmission,
    ) -> str:
        """Build internal follow-up notes."""

        return (
            f"Lead submitted form for service: {submission.service_interest or 'Not specified'}. "
            f"Source: {submission.source or submission.page_url or 'Unknown'}. "
            f"Consent: {submission.consent_status.value}. "
            f"Message: {submission.fields.get('message') or 'No message provided'}"
        )

    # ----------------------------------------------------------------------------------
    # Required compatibility hooks
    # ----------------------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[FormSubmissionContext, Mapping[str, Any], None],
    ) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Required by William/Jarvis architecture:
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
                "isolation_key": ctx.isolation_key(),
            },
            metadata={"agent": self.agent_name, "timestamp": _utc_now()},
        )

    def _requires_security_check(
        self,
        *,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide whether an action requires Security Agent approval.

        External actions are treated as sensitive because they may send messages,
        write records, schedule tasks, or notify humans.
        """

        sensitive_actions = {
            ConnectorAction.APPEND_ROW.value,
            ConnectorAction.SEND_WHATSAPP.value,
            ConnectorAction.UPSERT_CRM_LEAD.value,
            ConnectorAction.SEND_EMAIL.value,
            ConnectorAction.SCHEDULE_FOLLOW_UP.value,
            "sheet",
            "whatsapp",
            "crm",
            "email",
            "follow_up",
        }

        if action in sensitive_actions:
            return True

        if payload:
            payload_size = _safe_json_size(payload)
            if payload_size > self.config.max_payload_bytes:
                return True

        return False

    async def _request_security_approval(
        self,
        *,
        action: str,
        context: FormSubmissionContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent if available.

        If no Security Agent is attached, a safe local policy is applied:
            - allow dry-run/fallback-safe actions
            - require user/workspace context
            - deny obviously invalid payloads
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
        payload_ok = _safe_json_size(payload) <= self.config.max_payload_bytes

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
        context: FormSubmissionContext,
        submission: NormalizedFormSubmission,
        step_results: List[PipelineStepResult],
        status: SubmissionStatus,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        This does not call Verification Agent directly. The payload is returned
        to Master Agent / Router / Dashboard so Verification Agent can inspect
        evidence and confirm the outcome.
        """

        return {
            "agent": self.agent_name,
            "agent_module": self.agent_module,
            "agent_version": self.agent_version,
            "verification_type": "form_pipeline_completion",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "submission_id": submission.submission_id,
            "status": status.value,
            "evidence": {
                "received_at": submission.received_at,
                "validated_fields": self._safe_public_fields(submission.fields),
                "step_results": [step.to_dict() for step in step_results],
                "successful_steps": [
                    step.step.value for step in step_results if step.success and not step.skipped
                ],
                "failed_steps": [
                    step.step.value for step in step_results if not step.success
                ],
            },
            "checks": {
                "context_isolated": bool(context.user_id and context.workspace_id),
                "validation_passed": any(
                    step.step == PipelineStep.VALIDATE and step.success
                    for step in step_results
                ),
                "security_checked": True,
                "external_actions_structured": True,
            },
            "created_at": _utc_now(),
        }

    def _prepare_memory_payload(
        self,
        *,
        context: FormSubmissionContext,
        submission: NormalizedFormSubmission,
        step_results: List[PipelineStepResult],
        status: SubmissionStatus,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Memory Agent can store useful lead context per user/workspace without
        mixing tenants.
        """

        return {
            "agent": self.agent_name,
            "memory_type": "form_lead_context",
            "scope": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "isolation_key": context.isolation_key(),
            },
            "submission_id": submission.submission_id,
            "content": {
                "lead_name": submission.fields.get("name"),
                "lead_phone": submission.normalized_phone,
                "lead_email": submission.normalized_email,
                "service_interest": submission.service_interest,
                "source": submission.source,
                "page_url": submission.page_url,
                "utm": submission.utm,
                "consent_status": submission.consent_status.value,
                "pipeline_status": status.value,
            },
            "metadata": {
                "request_id": context.request_id,
                "task_id": context.task_id,
                "created_at": _utc_now(),
                "successful_steps": [
                    step.step.value for step in step_results if step.success and not step.skipped
                ],
            },
        }

    async def _emit_agent_event(
        self,
        *,
        event_type: str,
        context: FormSubmissionContext,
        payload: Mapping[str, Any],
    ) -> None:
        """
        Emit dashboard/API/observability event.

        Safe no-op if no event emitter is configured.
        """

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
        context: FormSubmissionContext,
        payload: Mapping[str, Any],
    ) -> None:
        """
        Log audit event with user/workspace isolation.

        Safe no-op if audit logging is disabled.
        """

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
        """
        Return structured success/error result.

        Required by William/Jarvis architecture.
        """

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
        """
        Return structured error result.

        Required by William/Jarvis architecture.
        """

        error = {
            "code": code,
            "message": str(message),
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
    # Internal helpers
    # ----------------------------------------------------------------------------------

    def _build_optional_connector(
        self,
        connector_cls: Optional[Any],
        name: str,
    ) -> Any:
        """Build connector if available, otherwise return safe fallback connector."""

        if connector_cls is None:
            return _FallbackConnector(dry_run=True, logger_=self.logger)

        try:
            try:
                return connector_cls()
            except TypeError:
                return connector_cls(config={}, logger_=self.logger)
        except Exception:
            self.logger.exception("Failed to initialize %s. Using fallback connector.", name)
            return _FallbackConnector(dry_run=True, logger_=self.logger)

    def _ensure_context(
        self,
        context: Optional[Union[FormSubmissionContext, Mapping[str, Any]]],
    ) -> FormSubmissionContext:
        """Coerce context into FormSubmissionContext."""

        if isinstance(context, FormSubmissionContext):
            return context

        if context is None:
            return FormSubmissionContext(user_id="", workspace_id="")

        if isinstance(context, Mapping):
            return FormSubmissionContext(
                user_id=str(context.get("user_id") or ""),
                workspace_id=str(context.get("workspace_id") or ""),
                request_id=str(context.get("request_id") or str(uuid.uuid4())),
                task_id=str(context.get("task_id")) if context.get("task_id") else None,
                actor_id=str(context.get("actor_id")) if context.get("actor_id") else None,
                role=str(context.get("role")) if context.get("role") else None,
                subscription_id=str(context.get("subscription_id"))
                if context.get("subscription_id")
                else None,
                agent_permissions=dict(context.get("agent_permissions") or {}),
                metadata=dict(context.get("metadata") or {}),
            )

        raise TypeError("context must be FormSubmissionContext, mapping, or None")

    def _context_from_task(self, task: Mapping[str, Any]) -> FormSubmissionContext:
        """Build FormSubmissionContext from Master Agent task."""

        context_data = dict(task.get("context") or {})
        for key in (
            "user_id",
            "workspace_id",
            "request_id",
            "task_id",
            "actor_id",
            "role",
            "subscription_id",
            "agent_permissions",
            "metadata",
        ):
            if key in task and key not in context_data:
                context_data[key] = task.get(key)

        return self._ensure_context(context_data)

    def _resolve_channels(
        self,
        channels: Optional[Iterable[str]],
    ) -> List[str]:
        """Resolve and validate enabled pipeline channels."""

        selected = list(channels or self.config.default_enabled_channels)
        allowed = set(self.config.allowed_channels)

        resolved: List[str] = []
        for channel in selected:
            normalized = _normalize_key(str(channel))
            if normalized in allowed and normalized not in resolved:
                resolved.append(normalized)

        return resolved

    def _safe_public_fields(
        self,
        fields: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Return safe public field mapping for logs, dashboard, memory, verification."""

        return _redact_mapping(dict(fields))

    def _base_metadata(
        self,
        context: FormSubmissionContext,
        started: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Build common result metadata."""

        metadata = {
            "agent": self.agent_name,
            "agent_module": self.agent_module,
            "agent_version": self.agent_version,
            "pipeline_name": self.config.pipeline_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "timestamp": _utc_now(),
        }

        if started is not None:
            metadata["duration_ms"] = _duration_ms(started)

        return metadata

    def _connector_metadata(
        self,
        context: FormSubmissionContext,
        submission: NormalizedFormSubmission,
    ) -> Dict[str, Any]:
        """Build connector metadata."""

        return {
            "agent": self.agent_name,
            "agent_module": self.agent_module,
            "pipeline_name": self.config.pipeline_name,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "task_id": context.task_id,
            "submission_id": submission.submission_id,
            "isolation_key": context.isolation_key(),
            "timestamp": _utc_now(),
        }

    def _normalize_security_result(self, result: Any) -> Dict[str, Any]:
        """Normalize Security Agent response."""

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

    def _check_and_store_dedupe(
        self,
        submission: NormalizedFormSubmission,
    ) -> Dict[str, Any]:
        """Basic in-memory dedupe check scoped by user/workspace."""

        now = time.time()
        dedupe_hash = _hash_submission(
            submission.fields,
            submission.user_id,
            submission.workspace_id,
        )

        expired = [
            key for key, timestamp in self._dedupe_cache.items()
            if now - timestamp > self.config.dedupe_window_seconds
        ]
        for key in expired:
            self._dedupe_cache.pop(key, None)

        if dedupe_hash in self._dedupe_cache:
            return {
                "duplicate": True,
                "dedupe_hash": dedupe_hash,
                "first_seen_at_epoch": self._dedupe_cache[dedupe_hash],
                "window_seconds": self.config.dedupe_window_seconds,
            }

        self._dedupe_cache[dedupe_hash] = now

        return {
            "duplicate": False,
            "dedupe_hash": dedupe_hash,
            "stored_at_epoch": now,
            "window_seconds": self.config.dedupe_window_seconds,
        }

    def get_agent_manifest(self) -> Dict[str, Any]:
        """
        Agent Registry / Agent Loader compatible manifest.

        This allows the wider William/Jarvis system to discover capabilities,
        public methods, permissions, and routing metadata.
        """

        return {
            "agent_name": self.agent_name,
            "agent_module": self.agent_module,
            "agent_version": self.agent_version,
            "class_name": self.__class__.__name__,
            "file_path": "agents/workflow_agent/form_pipeline.py",
            "capabilities": [
                "form_intake",
                "form_validation",
                "sheet_routing",
                "whatsapp_routing",
                "crm_lead_creation",
                "email_notification",
                "follow_up_scheduling",
                "verification_payload",
                "memory_payload",
                "audit_logging",
            ],
            "public_methods": [
                "run_task",
                "process_form_submission",
                "validate_form_payload",
                "preview_form_pipeline",
                "get_agent_manifest",
            ],
            "required_context": ["user_id", "workspace_id"],
            "sensitive_actions": [
                ConnectorAction.APPEND_ROW.value,
                ConnectorAction.SEND_WHATSAPP.value,
                ConnectorAction.UPSERT_CRM_LEAD.value,
                ConnectorAction.SEND_EMAIL.value,
                ConnectorAction.SCHEDULE_FOLLOW_UP.value,
            ],
            "default_channels": list(self.config.default_enabled_channels),
            "safe_to_import": True,
        }


# ======================================================================================
# Synchronous convenience wrappers
# ======================================================================================

def process_form_submission_sync(
    payload: Mapping[str, Any],
    *,
    context: Union[FormSubmissionContext, Mapping[str, Any]],
    channels: Optional[Iterable[str]] = None,
    options: Optional[Mapping[str, Any]] = None,
    config: Optional[Union[FormPipelineConfig, Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Synchronous helper for scripts/tests.

    FastAPI or async workers should call FormPipeline.process_form_submission directly.
    """

    pipeline = FormPipeline(config=config)
    return asyncio.run(
        pipeline.process_form_submission(
            payload=payload,
            context=context,
            channels=channels,
            options=options,
        )
    )


__all__ = [
    "FormPipeline",
    "FormPipelineConfig",
    "FormSubmissionContext",
    "NormalizedFormSubmission",
    "PipelineStep",
    "SubmissionStatus",
    "ValidationSeverity",
    "ConsentStatus",
    "ConnectorAction",
    "PipelineStepResult",
    "PipelineRunResult",
    "FormValidationIssue",
    "process_form_submission_sync",
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    demo_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "task_id": "demo_task",
    }

    demo_payload = {
        "Full Name": "John Smith",
        "Phone Number": "(888) 808-1006",
        "Email": "john@example.com",
        "Service": "AI Automation",
        "Message": "I need pricing and want to start soon.",
        "Source": "landing_page",
        "Consent": "yes",
    }

    result = process_form_submission_sync(
        demo_payload,
        context=demo_context,
        options={"dry_run": True, "skip_dedupe": True},
    )

    print(json.dumps(result, indent=2, default=str))