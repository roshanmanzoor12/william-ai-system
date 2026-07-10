"""
agents/workflow_agent/trigger_engine.py

Purpose:
    Starts workflows from forms, webhooks, sheets, email, schedule, and manual commands
    for the William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Architecture Role:
    TriggerEngine is the Workflow Agent entry-point helper responsible for normalizing
    external or internal trigger events into safe workflow start requests.

    It does NOT directly execute destructive actions, browser actions, calls, payments,
    messages, or system operations. It prepares workflow execution payloads and forwards
    them to a configured workflow runner, action router, n8n connector, or dashboard/API
    layer when available.

Compatibility:
    - Safe to import even when other William/Jarvis modules are not created yet.
    - Compatible with BaseAgent-style hooks.
    - Compatible with Master Agent routing.
    - Compatible with Security Agent approval flow.
    - Compatible with Memory Agent payload preparation.
    - Compatible with Verification Agent payload preparation.
    - Compatible with SaaS user_id/workspace_id isolation.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
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
    Optional,
    Sequence,
    Tuple,
    Union,
)


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports with safe fallbacks
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        This keeps the file import-safe while the full William/Jarvis BaseAgent
        may not exist yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)


try:
    from agents.workflow_agent.workflow_builder import WorkflowBuilder  # type: ignore
except Exception:  # pragma: no cover
    WorkflowBuilder = None  # type: ignore


try:
    from agents.workflow_agent.n8n_connector import N8NConnector  # type: ignore
except Exception:  # pragma: no cover
    N8NConnector = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Type aliases
# ---------------------------------------------------------------------------

StructuredDict = Dict[str, Any]
HookCallable = Callable[..., Union[StructuredDict, Awaitable[StructuredDict], None]]
WorkflowRunnerCallable = Callable[[StructuredDict], Union[StructuredDict, Awaitable[StructuredDict]]]


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_TRIGGER_VERSION = "1.0.0"

SAFE_TRIGGER_TYPES = {
    "form",
    "webhook",
    "sheet",
    "email",
    "schedule",
    "manual",
}

SENSITIVE_TRIGGER_TYPES = {
    "webhook",
    "email",
    "schedule",
    "manual",
}

HIGH_RISK_KEYWORDS = {
    "send",
    "email",
    "sms",
    "whatsapp",
    "call",
    "delete",
    "archive",
    "payment",
    "charge",
    "refund",
    "browser",
    "system",
    "file_delete",
    "credential",
    "secret",
    "api_key",
    "financial",
    "bank",
    "transfer",
    "publish",
    "post",
    "ad",
    "campaign",
}

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PHONE_CLEAN_REGEX = re.compile(r"[^\d+]")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class TriggerType(str, Enum):
    """Supported workflow trigger types."""

    FORM = "form"
    WEBHOOK = "webhook"
    SHEET = "sheet"
    EMAIL = "email"
    SCHEDULE = "schedule"
    MANUAL = "manual"


class TriggerStatus(str, Enum):
    """Internal trigger processing statuses."""

    RECEIVED = "received"
    VALIDATED = "validated"
    SECURITY_PENDING = "security_pending"
    SECURITY_APPROVED = "security_approved"
    SECURITY_DENIED = "security_denied"
    STARTED = "started"
    FAILED = "failed"
    SKIPPED = "skipped"


class TriggerPriority(str, Enum):
    """Trigger priority for queue/routing integrations."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TriggerContext:
    """
    SaaS isolation context.

    Every workflow start involving user-specific data must include user_id and
    workspace_id. This prevents memory, task history, files, analytics, and logs
    from mixing across tenants.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    permissions: Sequence[str] = field(default_factory=tuple)
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    session_id: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    correlation_id: Optional[str] = None

    def to_dict(self) -> StructuredDict:
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "role": self.role,
            "subscription_plan": self.subscription_plan,
            "permissions": list(self.permissions or []),
            "request_id": self.request_id,
            "session_id": self.session_id,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "correlation_id": self.correlation_id,
        }


@dataclass
class TriggerEvent:
    """
    Normalized trigger event.

    All public start methods normalize their source-specific payload into this
    shape before security checks, audit logging, memory payload preparation,
    verification payload preparation, and workflow routing.
    """

    trigger_type: TriggerType
    workflow_id: Optional[str]
    workflow_name: Optional[str]
    payload: StructuredDict
    context: TriggerContext
    source: str
    priority: TriggerPriority = TriggerPriority.NORMAL
    trigger_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    received_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: StructuredDict = field(default_factory=dict)

    def to_dict(self) -> StructuredDict:
        return {
            "trigger_id": self.trigger_id,
            "trigger_type": self.trigger_type.value,
            "workflow_id": self.workflow_id,
            "workflow_name": self.workflow_name,
            "payload": self.payload,
            "context": self.context.to_dict(),
            "source": self.source,
            "priority": self.priority.value,
            "received_at": self.received_at,
            "metadata": self.metadata,
        }


@dataclass
class TriggerEngineConfig:
    """
    TriggerEngine configuration.

    This file keeps configuration local and safe. Future config.py can pass a
    config object/dict into TriggerEngine without changing public methods.
    """

    enabled: bool = True
    require_security_for_sensitive_triggers: bool = True
    require_security_for_high_risk_payloads: bool = True
    allow_manual_triggers: bool = True
    allow_schedule_triggers: bool = True
    allow_email_triggers: bool = True
    allow_sheet_triggers: bool = True
    allow_webhook_triggers: bool = True
    allow_form_triggers: bool = True
    max_payload_bytes: int = 512_000
    max_metadata_bytes: int = 64_000
    dedupe_ttl_seconds: int = 300
    default_priority: TriggerPriority = TriggerPriority.NORMAL
    strict_context_validation: bool = True
    emit_audit_events: bool = True
    emit_memory_payloads: bool = True
    emit_verification_payloads: bool = True
    dashboard_event_enabled: bool = True
    safe_mode: bool = True

    @classmethod
    def from_dict(cls, data: Optional[Mapping[str, Any]]) -> "TriggerEngineConfig":
        if not data:
            return cls()

        kwargs: Dict[str, Any] = {}
        valid_fields = set(cls.__dataclass_fields__.keys())  # type: ignore[attr-defined]

        for key, value in data.items():
            if key not in valid_fields:
                continue
            if key == "default_priority" and isinstance(value, str):
                try:
                    kwargs[key] = TriggerPriority(value)
                except ValueError:
                    kwargs[key] = TriggerPriority.NORMAL
            else:
                kwargs[key] = value

        return cls(**kwargs)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_json_size(value: Any) -> int:
    try:
        return len(json.dumps(value, default=str).encode("utf-8"))
    except Exception:
        return len(str(value).encode("utf-8"))


def _stable_hash(value: Any) -> str:
    try:
        raw = json.dumps(value, sort_keys=True, default=str)
    except Exception:
        raw = str(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _clean_email(value: Any) -> Optional[str]:
    if value is None:
        return None
    email = str(value).strip().lower()
    if not email:
        return None
    if EMAIL_REGEX.match(email):
        return email
    return None


def _clean_phone(value: Any) -> Optional[str]:
    if value is None:
        return None
    phone = PHONE_CLEAN_REGEX.sub("", str(value).strip())
    if len(phone) < 7:
        return None
    return phone


def _safe_str(value: Any, max_len: int = 5000) -> str:
    text = "" if value is None else str(value)
    if len(text) > max_len:
        return text[:max_len] + "...[truncated]"
    return text


def _merge_dicts(*items: Optional[Mapping[str, Any]]) -> StructuredDict:
    merged: StructuredDict = {}
    for item in items:
        if item:
            merged.update(dict(item))
    return merged


def _contains_high_risk_intent(payload: Mapping[str, Any]) -> bool:
    """
    Conservative risk scanner.

    This does not block by itself. It decides whether the trigger should pass
    through Security Agent approval before workflow start.
    """
    try:
        text = json.dumps(payload, default=str).lower()
    except Exception:
        text = str(payload).lower()

    return any(keyword in text for keyword in HIGH_RISK_KEYWORDS)


def _normalize_permissions(permissions: Optional[Iterable[Any]]) -> Tuple[str, ...]:
    if not permissions:
        return tuple()
    return tuple(str(p).strip() for p in permissions if str(p).strip())


async def _maybe_await(value: Union[Any, Awaitable[Any]]) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


# ---------------------------------------------------------------------------
# TriggerEngine
# ---------------------------------------------------------------------------

class TriggerEngine(BaseAgent):
    """
    Starts workflows from supported trigger sources.

    Public methods:
        - start_from_form()
        - start_from_webhook()
        - start_from_sheet()
        - start_from_email()
        - start_from_schedule()
        - start_from_manual_command()
        - process_trigger()
        - register_workflow_runner()
        - register_event_hook()
        - clear_dedupe_cache()
        - health_check()

    Integration points:
        Master Agent:
            Can route "start workflow" tasks into process_trigger() or one of the
            source-specific start methods.

        Security Agent:
            _requires_security_check() and _request_security_approval() protect
            sensitive/high-risk workflow starts.

        Memory Agent:
            _prepare_memory_payload() creates safe structured context to store.

        Verification Agent:
            _prepare_verification_payload() creates evidence payload after a start.

        Dashboard/API:
            _emit_agent_event() and _log_audit_event() create structured event logs.

        Agent Registry / Loader:
            Class name is stable: TriggerEngine.
    """

    agent_type = "workflow_agent"
    component_name = "trigger_engine"
    version = DEFAULT_TRIGGER_VERSION

    def __init__(
        self,
        config: Optional[Union[TriggerEngineConfig, Mapping[str, Any]]] = None,
        workflow_runner: Optional[WorkflowRunnerCallable] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="TriggerEngine", **kwargs)

        if isinstance(config, TriggerEngineConfig):
            self.config = config
        else:
            self.config = TriggerEngineConfig.from_dict(config)

        self.workflow_runner = workflow_runner
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.audit_logger = audit_logger
        self.event_bus = event_bus
        self.logger = logger_instance or logger

        self._event_hooks: Dict[str, List[HookCallable]] = {}
        self._dedupe_cache: Dict[str, float] = {}
        self._local_audit_events: List[StructuredDict] = []
        self._local_agent_events: List[StructuredDict] = []

    # ------------------------------------------------------------------
    # Public registration methods
    # ------------------------------------------------------------------

    def register_workflow_runner(self, runner: WorkflowRunnerCallable) -> StructuredDict:
        """
        Register a callable that starts the actual workflow execution.

        The runner receives a normalized trigger event dict and should return
        a structured dict. The runner may be sync or async.
        """
        if not callable(runner):
            return self._error_result(
                message="Workflow runner must be callable.",
                error_code="invalid_runner",
            )

        self.workflow_runner = runner
        return self._safe_result(
            message="Workflow runner registered successfully.",
            data={"registered": True},
            metadata={"component": self.component_name},
        )

    def register_event_hook(self, event_name: str, hook: HookCallable) -> StructuredDict:
        """
        Register a hook for engine lifecycle events.

        Examples:
            - trigger.received
            - trigger.validated
            - trigger.security_pending
            - trigger.started
            - trigger.failed
        """
        normalized_event = _safe_str(event_name, 100).strip()
        if not normalized_event:
            return self._error_result(
                message="Event name is required.",
                error_code="missing_event_name",
            )
        if not callable(hook):
            return self._error_result(
                message="Event hook must be callable.",
                error_code="invalid_event_hook",
            )

        self._event_hooks.setdefault(normalized_event, []).append(hook)

        return self._safe_result(
            message="Event hook registered successfully.",
            data={"event_name": normalized_event, "hook_count": len(self._event_hooks[normalized_event])},
        )

    # ------------------------------------------------------------------
    # Source-specific public trigger methods
    # ------------------------------------------------------------------

    async def start_from_form(
        self,
        *,
        user_id: str,
        workspace_id: str,
        form_data: Mapping[str, Any],
        workflow_id: Optional[str] = None,
        workflow_name: Optional[str] = None,
        form_id: Optional[str] = None,
        source: str = "form",
        role: Optional[str] = None,
        permissions: Optional[Iterable[Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        request_info: Optional[Mapping[str, Any]] = None,
    ) -> StructuredDict:
        """
        Start workflow from a submitted form.

        Typical use:
            Landing page form -> Dashboard/API -> TriggerEngine.start_from_form()
            -> Security check if needed -> Workflow runner / Action Router.
        """
        if not self.config.allow_form_triggers:
            return self._error_result("Form triggers are disabled.", "form_triggers_disabled")

        payload = self._normalize_form_payload(form_data, form_id=form_id)

        context = self._build_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            permissions=permissions,
            request_info=request_info,
        )

        event = TriggerEvent(
            trigger_type=TriggerType.FORM,
            workflow_id=workflow_id,
            workflow_name=workflow_name,
            payload=payload,
            context=context,
            source=source,
            priority=self.config.default_priority,
            metadata=_merge_dicts(metadata, {"form_id": form_id}),
        )
        return await self.process_trigger(event)

    async def start_from_webhook(
        self,
        *,
        user_id: str,
        workspace_id: str,
        webhook_payload: Mapping[str, Any],
        workflow_id: Optional[str] = None,
        workflow_name: Optional[str] = None,
        webhook_id: Optional[str] = None,
        provider: Optional[str] = None,
        headers: Optional[Mapping[str, Any]] = None,
        source: str = "webhook",
        role: Optional[str] = None,
        permissions: Optional[Iterable[Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        request_info: Optional[Mapping[str, Any]] = None,
    ) -> StructuredDict:
        """
        Start workflow from a webhook.

        This method stores only sanitized header metadata and never logs secrets.
        Signature verification belongs in webhook_manager.py later, but this
        engine remains safe by redacting sensitive fields.
        """
        if not self.config.allow_webhook_triggers:
            return self._error_result("Webhook triggers are disabled.", "webhook_triggers_disabled")

        payload = self._normalize_webhook_payload(webhook_payload, headers=headers, provider=provider)

        context = self._build_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            permissions=permissions,
            request_info=request_info,
        )

        event = TriggerEvent(
            trigger_type=TriggerType.WEBHOOK,
            workflow_id=workflow_id,
            workflow_name=workflow_name,
            payload=payload,
            context=context,
            source=source,
            priority=TriggerPriority.HIGH if provider else self.config.default_priority,
            metadata=_merge_dicts(metadata, {"webhook_id": webhook_id, "provider": provider}),
        )
        return await self.process_trigger(event)

    async def start_from_sheet(
        self,
        *,
        user_id: str,
        workspace_id: str,
        sheet_data: Mapping[str, Any],
        workflow_id: Optional[str] = None,
        workflow_name: Optional[str] = None,
        sheet_id: Optional[str] = None,
        sheet_name: Optional[str] = None,
        row_number: Optional[int] = None,
        source: str = "sheet",
        role: Optional[str] = None,
        permissions: Optional[Iterable[Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        request_info: Optional[Mapping[str, Any]] = None,
    ) -> StructuredDict:
        """
        Start workflow from a Google Sheet, uploaded sheet, or internal sheet row.

        The future sheet_connector.py can call this after detecting a qualifying row.
        """
        if not self.config.allow_sheet_triggers:
            return self._error_result("Sheet triggers are disabled.", "sheet_triggers_disabled")

        payload = self._normalize_sheet_payload(
            sheet_data,
            sheet_id=sheet_id,
            sheet_name=sheet_name,
            row_number=row_number,
        )

        context = self._build_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            permissions=permissions,
            request_info=request_info,
        )

        event = TriggerEvent(
            trigger_type=TriggerType.SHEET,
            workflow_id=workflow_id,
            workflow_name=workflow_name,
            payload=payload,
            context=context,
            source=source,
            priority=self.config.default_priority,
            metadata=_merge_dicts(
                metadata,
                {"sheet_id": sheet_id, "sheet_name": sheet_name, "row_number": row_number},
            ),
        )
        return await self.process_trigger(event)

    async def start_from_email(
        self,
        *,
        user_id: str,
        workspace_id: str,
        email_data: Mapping[str, Any],
        workflow_id: Optional[str] = None,
        workflow_name: Optional[str] = None,
        mailbox: Optional[str] = None,
        message_id: Optional[str] = None,
        source: str = "email",
        role: Optional[str] = None,
        permissions: Optional[Iterable[Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        request_info: Optional[Mapping[str, Any]] = None,
    ) -> StructuredDict:
        """
        Start workflow from email.

        This does not send email. It only uses an inbound email event to start
        a workflow after validation and security gating.
        """
        if not self.config.allow_email_triggers:
            return self._error_result("Email triggers are disabled.", "email_triggers_disabled")

        payload = self._normalize_email_payload(email_data, mailbox=mailbox, message_id=message_id)

        context = self._build_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            permissions=permissions,
            request_info=request_info,
        )

        event = TriggerEvent(
            trigger_type=TriggerType.EMAIL,
            workflow_id=workflow_id,
            workflow_name=workflow_name,
            payload=payload,
            context=context,
            source=source,
            priority=TriggerPriority.HIGH,
            metadata=_merge_dicts(metadata, {"mailbox": mailbox, "message_id": message_id}),
        )
        return await self.process_trigger(event)

    async def start_from_schedule(
        self,
        *,
        user_id: str,
        workspace_id: str,
        schedule_data: Mapping[str, Any],
        workflow_id: Optional[str] = None,
        workflow_name: Optional[str] = None,
        schedule_id: Optional[str] = None,
        source: str = "schedule",
        role: Optional[str] = None,
        permissions: Optional[Iterable[Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        request_info: Optional[Mapping[str, Any]] = None,
    ) -> StructuredDict:
        """
        Start workflow from schedule.

        The future scheduler.py can call this when a due job is detected.
        """
        if not self.config.allow_schedule_triggers:
            return self._error_result("Schedule triggers are disabled.", "schedule_triggers_disabled")

        payload = self._normalize_schedule_payload(schedule_data, schedule_id=schedule_id)

        context = self._build_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            permissions=permissions,
            request_info=request_info,
        )

        event = TriggerEvent(
            trigger_type=TriggerType.SCHEDULE,
            workflow_id=workflow_id,
            workflow_name=workflow_name,
            payload=payload,
            context=context,
            source=source,
            priority=self.config.default_priority,
            metadata=_merge_dicts(metadata, {"schedule_id": schedule_id}),
        )
        return await self.process_trigger(event)

    async def start_from_manual_command(
        self,
        *,
        user_id: str,
        workspace_id: str,
        command: Union[str, Mapping[str, Any]],
        workflow_id: Optional[str] = None,
        workflow_name: Optional[str] = None,
        source: str = "manual",
        role: Optional[str] = None,
        permissions: Optional[Iterable[Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        request_info: Optional[Mapping[str, Any]] = None,
    ) -> StructuredDict:
        """
        Start workflow from a manual dashboard/API/Master Agent command.

        Manual commands are sensitive because they may be broad. The engine
        applies conservative security gating.
        """
        if not self.config.allow_manual_triggers:
            return self._error_result("Manual triggers are disabled.", "manual_triggers_disabled")

        payload = self._normalize_manual_payload(command)

        context = self._build_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            permissions=permissions,
            request_info=request_info,
        )

        event = TriggerEvent(
            trigger_type=TriggerType.MANUAL,
            workflow_id=workflow_id,
            workflow_name=workflow_name,
            payload=payload,
            context=context,
            source=source,
            priority=TriggerPriority.HIGH,
            metadata=_merge_dicts(metadata, {"manual": True}),
        )
        return await self.process_trigger(event)

    # ------------------------------------------------------------------
    # Main trigger processor
    # ------------------------------------------------------------------

    async def process_trigger(self, event: Union[TriggerEvent, Mapping[str, Any]]) -> StructuredDict:
        """
        Validate, secure, audit, prepare payloads, and start a workflow.

        This is the central method Master Agent, API routes, dashboard services,
        connectors, and schedulers can call.
        """
        started_at = time.time()

        if not self.config.enabled:
            return self._error_result(
                message="TriggerEngine is disabled.",
                error_code="trigger_engine_disabled",
                metadata={"component": self.component_name},
            )

        try:
            normalized_event = self._coerce_event(event)
        except Exception as exc:
            self.logger.exception("Failed to normalize trigger event.")
            return self._error_result(
                message="Invalid trigger event.",
                error_code="invalid_trigger_event",
                error=str(exc),
            )

        await self._emit_agent_event("trigger.received", normalized_event.to_dict())
        self._log_audit_event(
            action="trigger_received",
            event=normalized_event,
            status=TriggerStatus.RECEIVED,
        )

        validation = self._validate_trigger_event(normalized_event)
        if not validation["success"]:
            self._log_audit_event(
                action="trigger_validation_failed",
                event=normalized_event,
                status=TriggerStatus.FAILED,
                details={"validation": validation},
            )
            await self._emit_agent_event("trigger.failed", validation)
            return validation

        dedupe_result = self._check_and_store_dedupe(normalized_event)
        if not dedupe_result["success"]:
            self._log_audit_event(
                action="trigger_deduped",
                event=normalized_event,
                status=TriggerStatus.SKIPPED,
                details=dedupe_result,
            )
            await self._emit_agent_event("trigger.skipped", dedupe_result)
            return dedupe_result

        await self._emit_agent_event("trigger.validated", normalized_event.to_dict())

        security_required = self._requires_security_check(normalized_event)
        security_result: Optional[StructuredDict] = None

        if security_required:
            await self._emit_agent_event("trigger.security_pending", normalized_event.to_dict())
            self._log_audit_event(
                action="security_check_required",
                event=normalized_event,
                status=TriggerStatus.SECURITY_PENDING,
            )

            security_result = await self._request_security_approval(normalized_event)
            if not security_result.get("success"):
                denied = self._error_result(
                    message="Workflow trigger blocked by Security Agent.",
                    error_code="security_denied",
                    data={
                        "trigger_id": normalized_event.trigger_id,
                        "workflow_id": normalized_event.workflow_id,
                        "workflow_name": normalized_event.workflow_name,
                    },
                    metadata={
                        "security_result": security_result,
                        "duration_ms": int((time.time() - started_at) * 1000),
                    },
                )
                self._log_audit_event(
                    action="security_denied",
                    event=normalized_event,
                    status=TriggerStatus.SECURITY_DENIED,
                    details=denied,
                )
                await self._emit_agent_event("trigger.security_denied", denied)
                return denied

            self._log_audit_event(
                action="security_approved",
                event=normalized_event,
                status=TriggerStatus.SECURITY_APPROVED,
                details=security_result,
            )
            await self._emit_agent_event("trigger.security_approved", security_result)

        memory_payload = self._prepare_memory_payload(normalized_event)
        verification_payload = self._prepare_verification_payload(
            normalized_event,
            pre_execution_status=TriggerStatus.VALIDATED,
            security_result=security_result,
        )

        if self.config.emit_memory_payloads:
            await self._send_memory_payload(memory_payload)

        workflow_start_payload = self._build_workflow_start_payload(
            normalized_event,
            memory_payload=memory_payload,
            verification_payload=verification_payload,
            security_result=security_result,
        )

        runner_result = await self._start_workflow(workflow_start_payload)

        success = bool(runner_result.get("success", False))
        duration_ms = int((time.time() - started_at) * 1000)

        if success:
            result = self._safe_result(
                message="Workflow trigger processed and workflow start prepared successfully.",
                data={
                    "trigger": normalized_event.to_dict(),
                    "workflow_start": runner_result.get("data", runner_result),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "component": self.component_name,
                    "duration_ms": duration_ms,
                    "security_required": security_required,
                    "security_result": security_result,
                    "runner_used": self.workflow_runner is not None,
                },
            )
            self._log_audit_event(
                action="workflow_trigger_started",
                event=normalized_event,
                status=TriggerStatus.STARTED,
                details=result,
            )
            await self._emit_agent_event("trigger.started", result)
            return result

        result = self._error_result(
            message="Workflow trigger validated, but workflow start failed.",
            error_code="workflow_start_failed",
            data={
                "trigger": normalized_event.to_dict(),
                "runner_result": runner_result,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "component": self.component_name,
                "duration_ms": duration_ms,
                "security_required": security_required,
                "security_result": security_result,
                "runner_used": self.workflow_runner is not None,
            },
        )
        self._log_audit_event(
            action="workflow_trigger_failed",
            event=normalized_event,
            status=TriggerStatus.FAILED,
            details=result,
        )
        await self._emit_agent_event("trigger.failed", result)
        return result

    # ------------------------------------------------------------------
    # Validation and context hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: Union[TriggerContext, Mapping[str, Any]]) -> StructuredDict:
        """
        Required compatibility hook.

        Validates SaaS user/workspace isolation data.
        """
        try:
            ctx = context if isinstance(context, TriggerContext) else self._context_from_mapping(context)
        except Exception as exc:
            return self._error_result(
                message="Invalid task context.",
                error_code="invalid_task_context",
                error=str(exc),
            )

        missing: List[str] = []
        if not _safe_str(ctx.user_id, 200).strip():
            missing.append("user_id")
        if not _safe_str(ctx.workspace_id, 200).strip():
            missing.append("workspace_id")

        if missing:
            return self._error_result(
                message="Missing required SaaS isolation context fields.",
                error_code="missing_context_fields",
                data={"missing": missing},
            )

        if ctx.user_id == ctx.workspace_id:
            return self._error_result(
                message="user_id and workspace_id must be separate identifiers.",
                error_code="invalid_context_isolation",
            )

        return self._safe_result(
            message="Task context is valid.",
            data={"context": ctx.to_dict()},
        )

    def _validate_trigger_event(self, event: TriggerEvent) -> StructuredDict:
        context_result = self._validate_task_context(event.context)
        if not context_result["success"]:
            return context_result

        if event.trigger_type.value not in SAFE_TRIGGER_TYPES:
            return self._error_result(
                message="Unsupported trigger type.",
                error_code="unsupported_trigger_type",
                data={"trigger_type": event.trigger_type.value},
            )

        if not event.workflow_id and not event.workflow_name:
            return self._error_result(
                message="workflow_id or workflow_name is required to start a workflow.",
                error_code="missing_workflow_identifier",
                data={"trigger_id": event.trigger_id},
            )

        payload_size = _safe_json_size(event.payload)
        metadata_size = _safe_json_size(event.metadata)

        if payload_size > self.config.max_payload_bytes:
            return self._error_result(
                message="Trigger payload is too large.",
                error_code="payload_too_large",
                data={
                    "payload_size_bytes": payload_size,
                    "max_payload_bytes": self.config.max_payload_bytes,
                },
            )

        if metadata_size > self.config.max_metadata_bytes:
            return self._error_result(
                message="Trigger metadata is too large.",
                error_code="metadata_too_large",
                data={
                    "metadata_size_bytes": metadata_size,
                    "max_metadata_bytes": self.config.max_metadata_bytes,
                },
            )

        if not isinstance(event.payload, dict):
            return self._error_result(
                message="Trigger payload must be a dictionary.",
                error_code="invalid_payload_type",
            )

        return self._safe_result(
            message="Trigger event is valid.",
            data={
                "trigger_id": event.trigger_id,
                "trigger_type": event.trigger_type.value,
                "payload_size_bytes": payload_size,
                "metadata_size_bytes": metadata_size,
            },
        )

    # ------------------------------------------------------------------
    # Security hook
    # ------------------------------------------------------------------

    def _requires_security_check(self, event: TriggerEvent) -> bool:
        """
        Required compatibility hook.

        Decides whether Security Agent approval is required before workflow start.
        """
        if not self.config.require_security_for_sensitive_triggers and not self.config.require_security_for_high_risk_payloads:
            return False

        if self.config.require_security_for_sensitive_triggers and event.trigger_type.value in SENSITIVE_TRIGGER_TYPES:
            return True

        if self.config.require_security_for_high_risk_payloads and _contains_high_risk_intent(event.payload):
            return True

        requested_permissions = set(event.context.permissions or [])
        if "workflow:start:any" in requested_permissions:
            return True

        return False

    async def _request_security_approval(self, event: TriggerEvent) -> StructuredDict:
        """
        Required compatibility hook.

        Uses Security Agent/client if available. Otherwise applies safe fallback:
        - Allows low-risk normalized starts.
        - Blocks obvious high-risk payloads in safe mode.
        """
        approval_payload = {
            "action": "workflow_trigger_start",
            "agent": self.agent_type,
            "component": self.component_name,
            "trigger": event.to_dict(),
            "risk": {
                "trigger_type_sensitive": event.trigger_type.value in SENSITIVE_TRIGGER_TYPES,
                "payload_high_risk": _contains_high_risk_intent(event.payload),
                "safe_mode": self.config.safe_mode,
            },
            "requested_at": _utc_now(),
        }

        if self.security_client is not None:
            try:
                if hasattr(self.security_client, "approve"):
                    result = self.security_client.approve(approval_payload)
                    result = await _maybe_await(result)
                    return self._normalize_external_result(result, default_message="Security approval completed.")

                if hasattr(self.security_client, "request_approval"):
                    result = self.security_client.request_approval(approval_payload)
                    result = await _maybe_await(result)
                    return self._normalize_external_result(result, default_message="Security approval completed.")

                if callable(self.security_client):
                    result = self.security_client(approval_payload)
                    result = await _maybe_await(result)
                    return self._normalize_external_result(result, default_message="Security approval completed.")

            except Exception as exc:
                self.logger.exception("Security approval request failed.")
                return self._error_result(
                    message="Security approval request failed.",
                    error_code="security_client_error",
                    error=str(exc),
                    metadata={"approval_payload_hash": _stable_hash(approval_payload)},
                )

        high_risk = _contains_high_risk_intent(event.payload)

        if self.config.safe_mode and high_risk:
            return self._error_result(
                message="Fallback Security Agent blocked high-risk workflow trigger in safe mode.",
                error_code="fallback_security_blocked",
                data={
                    "trigger_id": event.trigger_id,
                    "trigger_type": event.trigger_type.value,
                    "reason": "high_risk_payload_detected",
                },
            )

        return self._safe_result(
            message="Fallback security approval granted.",
            data={
                "approved": True,
                "mode": "fallback",
                "trigger_id": event.trigger_id,
                "trigger_type": event.trigger_type.value,
            },
            metadata={"security_client_available": False},
        )

    # ------------------------------------------------------------------
    # Verification and memory hooks
    # ------------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        event: TriggerEvent,
        *,
        pre_execution_status: TriggerStatus,
        security_result: Optional[Mapping[str, Any]] = None,
    ) -> StructuredDict:
        """
        Required compatibility hook.

        Prepares a Verification Agent payload. This file only starts workflow
        execution; final action verification happens after Action Router / workers.
        """
        return {
            "verification_type": "workflow_trigger_start",
            "agent": self.agent_type,
            "component": self.component_name,
            "trigger_id": event.trigger_id,
            "workflow_id": event.workflow_id,
            "workflow_name": event.workflow_name,
            "trigger_type": event.trigger_type.value,
            "source": event.source,
            "status": pre_execution_status.value,
            "context": event.context.to_dict(),
            "evidence": {
                "payload_hash": _stable_hash(event.payload),
                "metadata_hash": _stable_hash(event.metadata),
                "received_at": event.received_at,
                "prepared_at": _utc_now(),
            },
            "security": {
                "required": self._requires_security_check(event),
                "result": dict(security_result) if security_result else None,
            },
            "next_expected_step": "workflow_runner_or_action_router_execution",
        }

    def _prepare_memory_payload(self, event: TriggerEvent) -> StructuredDict:
        """
        Required compatibility hook.

        Prepares Memory Agent-compatible context. Sensitive raw fields are redacted.
        """
        redacted_payload = self._redact_sensitive_data(event.payload)

        return {
            "memory_type": "workflow_trigger_context",
            "agent": self.agent_type,
            "component": self.component_name,
            "user_id": event.context.user_id,
            "workspace_id": event.context.workspace_id,
            "trigger_id": event.trigger_id,
            "workflow_id": event.workflow_id,
            "workflow_name": event.workflow_name,
            "trigger_type": event.trigger_type.value,
            "source": event.source,
            "priority": event.priority.value,
            "summary": self._summarize_trigger(event, redacted_payload),
            "payload": redacted_payload,
            "metadata": self._redact_sensitive_data(event.metadata),
            "created_at": _utc_now(),
            "isolation": {
                "user_id": event.context.user_id,
                "workspace_id": event.context.workspace_id,
            },
        }

    async def _send_memory_payload(self, memory_payload: Mapping[str, Any]) -> None:
        """
        Best-effort Memory Agent integration.

        Failure to store memory should not fail workflow start.
        """
        if self.memory_client is None:
            return

        try:
            if hasattr(self.memory_client, "store"):
                await _maybe_await(self.memory_client.store(dict(memory_payload)))
            elif hasattr(self.memory_client, "remember"):
                await _maybe_await(self.memory_client.remember(dict(memory_payload)))
            elif callable(self.memory_client):
                await _maybe_await(self.memory_client(dict(memory_payload)))
        except Exception:
            self.logger.exception("Failed to send memory payload.")

    # ------------------------------------------------------------------
    # Event and audit hooks
    # ------------------------------------------------------------------

    async def _emit_agent_event(self, event_name: str, payload: Mapping[str, Any]) -> StructuredDict:
        """
        Required compatibility hook.

        Emits events to:
        - local in-memory event list
        - optional event_bus
        - registered event hooks

        Designed for dashboard analytics, audit streams, registry monitoring,
        and Master Agent observability.
        """
        event = {
            "event_name": event_name,
            "agent": self.agent_type,
            "component": self.component_name,
            "timestamp": _utc_now(),
            "payload": dict(payload),
        }

        self._local_agent_events.append(event)

        if self.config.dashboard_event_enabled and self.event_bus is not None:
            try:
                if hasattr(self.event_bus, "emit"):
                    await _maybe_await(self.event_bus.emit(event_name, event))
                elif hasattr(self.event_bus, "publish"):
                    await _maybe_await(self.event_bus.publish(event_name, event))
                elif callable(self.event_bus):
                    await _maybe_await(self.event_bus(event_name, event))
            except Exception:
                self.logger.exception("Failed to emit event to event_bus.")

        hooks = self._event_hooks.get(event_name, []) + self._event_hooks.get("*", [])
        for hook in hooks:
            try:
                await _maybe_await(hook(event))
            except Exception:
                self.logger.exception("Registered event hook failed for %s.", event_name)

        return self._safe_result(
            message="Agent event emitted.",
            data={"event_name": event_name},
        )

    def _log_audit_event(
        self,
        *,
        action: str,
        event: TriggerEvent,
        status: TriggerStatus,
        details: Optional[Mapping[str, Any]] = None,
    ) -> StructuredDict:
        """
        Required compatibility hook.

        Logs audit-safe event data. Raw payload is not directly logged; only hashes,
        source info, context IDs, and redacted details are included.
        """
        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "action": action,
            "status": status.value,
            "agent": self.agent_type,
            "component": self.component_name,
            "trigger_id": event.trigger_id,
            "trigger_type": event.trigger_type.value,
            "workflow_id": event.workflow_id,
            "workflow_name": event.workflow_name,
            "user_id": event.context.user_id,
            "workspace_id": event.context.workspace_id,
            "source": event.source,
            "payload_hash": _stable_hash(event.payload),
            "metadata_hash": _stable_hash(event.metadata),
            "details": self._redact_sensitive_data(dict(details or {})),
            "timestamp": _utc_now(),
        }

        self._local_audit_events.append(audit_event)

        if self.config.emit_audit_events and self.audit_logger is not None:
            try:
                if hasattr(self.audit_logger, "log"):
                    result = self.audit_logger.log(audit_event)
                    if inspect.isawaitable(result):
                        asyncio.create_task(result)  # best-effort, non-blocking
                elif callable(self.audit_logger):
                    result = self.audit_logger(audit_event)
                    if inspect.isawaitable(result):
                        asyncio.create_task(result)
            except Exception:
                self.logger.exception("Failed to log audit event.")

        return self._safe_result(
            message="Audit event logged.",
            data={"audit_id": audit_event["audit_id"]},
        )

    # ------------------------------------------------------------------
    # Structured result hooks
    # ------------------------------------------------------------------

    def _safe_result(
        self,
        message: str = "Success.",
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> StructuredDict:
        """
        Required compatibility hook.

        Standard success result shape.
        """
        return {
            "success": True,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": {
                "agent": self.agent_type,
                "component": self.component_name,
                "version": self.version,
                "timestamp": _utc_now(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str = "Error.",
        error_code: str = "error",
        error: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> StructuredDict:
        """
        Required compatibility hook.

        Standard error result shape.
        """
        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": {
                "code": error_code,
                "detail": error or message,
            },
            "metadata": {
                "agent": self.agent_type,
                "component": self.component_name,
                "version": self.version,
                "timestamp": _utc_now(),
                **dict(metadata or {}),
            },
        }

    # ------------------------------------------------------------------
    # Workflow start
    # ------------------------------------------------------------------

    async def _start_workflow(self, workflow_start_payload: StructuredDict) -> StructuredDict:
        """
        Starts/prepares workflow execution.

        If a workflow_runner is registered, it is called.
        If not, this returns a safe prepared payload so API/dashboard/router layers
        can enqueue or execute it later.
        """
        if self.workflow_runner is None:
            return self._safe_result(
                message="Workflow start payload prepared. No runner registered, so no execution was performed.",
                data={
                    "mode": "prepared_only",
                    "workflow_start_payload": workflow_start_payload,
                },
                metadata={"runner_registered": False},
            )

        try:
            result = self.workflow_runner(workflow_start_payload)
            result = await _maybe_await(result)
            return self._normalize_external_result(
                result,
                default_message="Workflow runner completed.",
            )
        except Exception as exc:
            self.logger.exception("Workflow runner failed.")
            return self._error_result(
                message="Workflow runner failed.",
                error_code="workflow_runner_exception",
                error=str(exc),
            )

    def _build_workflow_start_payload(
        self,
        event: TriggerEvent,
        *,
        memory_payload: Mapping[str, Any],
        verification_payload: Mapping[str, Any],
        security_result: Optional[Mapping[str, Any]],
    ) -> StructuredDict:
        return {
            "task_type": "workflow_start",
            "agent": self.agent_type,
            "component": self.component_name,
            "trigger": event.to_dict(),
            "workflow": {
                "workflow_id": event.workflow_id,
                "workflow_name": event.workflow_name,
            },
            "context": event.context.to_dict(),
            "payload": event.payload,
            "memory_payload": dict(memory_payload),
            "verification_payload": dict(verification_payload),
            "security_result": dict(security_result) if security_result else None,
            "routing": {
                "preferred_next_component": "action_router",
                "master_agent_compatible": True,
                "registry_compatible": True,
                "dashboard_compatible": True,
            },
            "created_at": _utc_now(),
        }

    # ------------------------------------------------------------------
    # Payload normalizers
    # ------------------------------------------------------------------

    def _normalize_form_payload(self, form_data: Mapping[str, Any], *, form_id: Optional[str]) -> StructuredDict:
        data = dict(form_data or {})
        normalized = {
            "source_type": TriggerType.FORM.value,
            "form_id": form_id,
            "fields": self._redact_sensitive_data(data),
            "contact": {
                "name": _safe_str(data.get("name") or data.get("full_name") or data.get("fullName"), 300).strip() or None,
                "email": _clean_email(data.get("email")),
                "phone": _clean_phone(data.get("phone") or data.get("mobile")),
                "company": _safe_str(data.get("company") or data.get("business_name"), 300).strip() or None,
            },
            "service": _safe_str(data.get("service") or data.get("interest") or data.get("selected_service"), 300).strip() or None,
            "message": _safe_str(data.get("message") or data.get("notes") or data.get("description"), 5000).strip() or None,
            "normalized_at": _utc_now(),
        }
        return normalized

    def _normalize_webhook_payload(
        self,
        webhook_payload: Mapping[str, Any],
        *,
        headers: Optional[Mapping[str, Any]],
        provider: Optional[str],
    ) -> StructuredDict:
        return {
            "source_type": TriggerType.WEBHOOK.value,
            "provider": provider,
            "body": self._redact_sensitive_data(dict(webhook_payload or {})),
            "headers": self._sanitize_headers(headers or {}),
            "normalized_at": _utc_now(),
        }

    def _normalize_sheet_payload(
        self,
        sheet_data: Mapping[str, Any],
        *,
        sheet_id: Optional[str],
        sheet_name: Optional[str],
        row_number: Optional[int],
    ) -> StructuredDict:
        return {
            "source_type": TriggerType.SHEET.value,
            "sheet_id": sheet_id,
            "sheet_name": sheet_name,
            "row_number": row_number,
            "row": self._redact_sensitive_data(dict(sheet_data or {})),
            "row_hash": _stable_hash(sheet_data),
            "normalized_at": _utc_now(),
        }

    def _normalize_email_payload(
        self,
        email_data: Mapping[str, Any],
        *,
        mailbox: Optional[str],
        message_id: Optional[str],
    ) -> StructuredDict:
        data = dict(email_data or {})
        attachments = data.get("attachments") or []

        safe_attachments: List[StructuredDict] = []
        if isinstance(attachments, list):
            for item in attachments[:50]:
                if isinstance(item, Mapping):
                    safe_attachments.append(
                        {
                            "filename": _safe_str(item.get("filename"), 500),
                            "mime_type": _safe_str(item.get("mime_type") or item.get("content_type"), 200),
                            "size_bytes": item.get("size_bytes") or item.get("size"),
                            "attachment_id_hash": _stable_hash(item.get("attachment_id") or item.get("id")),
                        }
                    )
                else:
                    safe_attachments.append({"filename": _safe_str(item, 500)})

        return {
            "source_type": TriggerType.EMAIL.value,
            "mailbox": mailbox,
            "message_id": message_id or _safe_str(data.get("message_id") or data.get("id"), 300) or None,
            "from": _safe_str(data.get("from") or data.get("sender"), 500),
            "to": _safe_str(data.get("to"), 1000),
            "subject": _safe_str(data.get("subject"), 1000),
            "snippet": _safe_str(data.get("snippet") or data.get("preview"), 2000),
            "body": _safe_str(data.get("body") or data.get("text"), 15000),
            "attachments": safe_attachments,
            "labels": list(data.get("labels") or []) if isinstance(data.get("labels") or [], list) else [],
            "normalized_at": _utc_now(),
        }

    def _normalize_schedule_payload(
        self,
        schedule_data: Mapping[str, Any],
        *,
        schedule_id: Optional[str],
    ) -> StructuredDict:
        data = dict(schedule_data or {})
        return {
            "source_type": TriggerType.SCHEDULE.value,
            "schedule_id": schedule_id,
            "name": _safe_str(data.get("name") or data.get("title"), 300),
            "cadence": _safe_str(data.get("cadence") or data.get("rrule") or data.get("cron"), 1000),
            "due_at": _safe_str(data.get("due_at") or data.get("run_at") or data.get("scheduled_for"), 300),
            "timezone": _safe_str(data.get("timezone") or data.get("tz"), 100),
            "input": self._redact_sensitive_data(data.get("input") if isinstance(data.get("input"), Mapping) else data),
            "normalized_at": _utc_now(),
        }

    def _normalize_manual_payload(self, command: Union[str, Mapping[str, Any]]) -> StructuredDict:
        if isinstance(command, Mapping):
            command_data = dict(command)
            return {
                "source_type": TriggerType.MANUAL.value,
                "command_type": "structured",
                "command": self._redact_sensitive_data(command_data),
                "command_text": _safe_str(command_data.get("command") or command_data.get("text"), 5000),
                "normalized_at": _utc_now(),
            }

        return {
            "source_type": TriggerType.MANUAL.value,
            "command_type": "text",
            "command_text": _safe_str(command, 10000),
            "normalized_at": _utc_now(),
        }

    # ------------------------------------------------------------------
    # Context/event coercion
    # ------------------------------------------------------------------

    def _build_context(
        self,
        *,
        user_id: str,
        workspace_id: str,
        role: Optional[str],
        permissions: Optional[Iterable[Any]],
        request_info: Optional[Mapping[str, Any]],
    ) -> TriggerContext:
        info = dict(request_info or {})
        return TriggerContext(
            user_id=_safe_str(user_id, 200).strip(),
            workspace_id=_safe_str(workspace_id, 200).strip(),
            role=role,
            permissions=_normalize_permissions(permissions),
            request_id=_safe_str(info.get("request_id") or str(uuid.uuid4()), 200),
            session_id=info.get("session_id"),
            source_ip=info.get("source_ip") or info.get("ip"),
            user_agent=info.get("user_agent"),
            correlation_id=info.get("correlation_id"),
            subscription_plan=info.get("subscription_plan"),
        )

    def _context_from_mapping(self, data: Mapping[str, Any]) -> TriggerContext:
        return TriggerContext(
            user_id=_safe_str(data.get("user_id"), 200).strip(),
            workspace_id=_safe_str(data.get("workspace_id"), 200).strip(),
            role=data.get("role"),
            subscription_plan=data.get("subscription_plan"),
            permissions=_normalize_permissions(data.get("permissions")),
            request_id=_safe_str(data.get("request_id") or str(uuid.uuid4()), 200),
            session_id=data.get("session_id"),
            source_ip=data.get("source_ip"),
            user_agent=data.get("user_agent"),
            correlation_id=data.get("correlation_id"),
        )

    def _coerce_event(self, event: Union[TriggerEvent, Mapping[str, Any]]) -> TriggerEvent:
        if isinstance(event, TriggerEvent):
            return event

        data = dict(event or {})

        raw_trigger_type = data.get("trigger_type") or data.get("type")
        if isinstance(raw_trigger_type, TriggerType):
            trigger_type = raw_trigger_type
        else:
            trigger_type = TriggerType(_safe_str(raw_trigger_type).strip())

        raw_context = data.get("context") or {}
        context = raw_context if isinstance(raw_context, TriggerContext) else self._context_from_mapping(raw_context)

        raw_priority = data.get("priority") or self.config.default_priority.value
        if isinstance(raw_priority, TriggerPriority):
            priority = raw_priority
        else:
            try:
                priority = TriggerPriority(str(raw_priority))
            except ValueError:
                priority = TriggerPriority.NORMAL

        return TriggerEvent(
            trigger_type=trigger_type,
            workflow_id=data.get("workflow_id"),
            workflow_name=data.get("workflow_name"),
            payload=dict(data.get("payload") or {}),
            context=context,
            source=_safe_str(data.get("source") or trigger_type.value, 300),
            priority=priority,
            trigger_id=_safe_str(data.get("trigger_id") or str(uuid.uuid4()), 200),
            received_at=_safe_str(data.get("received_at") or _utc_now(), 100),
            metadata=dict(data.get("metadata") or {}),
        )

    # ------------------------------------------------------------------
    # Dedupe
    # ------------------------------------------------------------------

    def _check_and_store_dedupe(self, event: TriggerEvent) -> StructuredDict:
        """
        Prevents accidental duplicate starts from repeated webhook/form/sheet events.
        """
        self._purge_dedupe_cache()

        dedupe_key = self._dedupe_key(event)
        now = time.time()

        existing = self._dedupe_cache.get(dedupe_key)
        if existing and now - existing < self.config.dedupe_ttl_seconds:
            return self._error_result(
                message="Duplicate trigger skipped within dedupe window.",
                error_code="duplicate_trigger",
                data={
                    "trigger_id": event.trigger_id,
                    "dedupe_key": dedupe_key,
                    "dedupe_ttl_seconds": self.config.dedupe_ttl_seconds,
                },
            )

        self._dedupe_cache[dedupe_key] = now
        return self._safe_result(
            message="Trigger dedupe check passed.",
            data={"dedupe_key": dedupe_key},
        )

    def _dedupe_key(self, event: TriggerEvent) -> str:
        source_unique = {
            "trigger_type": event.trigger_type.value,
            "workflow_id": event.workflow_id,
            "workflow_name": event.workflow_name,
            "user_id": event.context.user_id,
            "workspace_id": event.context.workspace_id,
            "source": event.source,
            "payload_hash": _stable_hash(event.payload),
        }
        return _stable_hash(source_unique)

    def _purge_dedupe_cache(self) -> None:
        now = time.time()
        expired = [
            key
            for key, created_at in self._dedupe_cache.items()
            if now - created_at >= self.config.dedupe_ttl_seconds
        ]
        for key in expired:
            self._dedupe_cache.pop(key, None)

    def clear_dedupe_cache(self) -> StructuredDict:
        count = len(self._dedupe_cache)
        self._dedupe_cache.clear()
        return self._safe_result(
            message="Dedupe cache cleared.",
            data={"cleared_count": count},
        )

    # ------------------------------------------------------------------
    # Sanitization
    # ------------------------------------------------------------------

    def _sanitize_headers(self, headers: Mapping[str, Any]) -> StructuredDict:
        sensitive_header_parts = {
            "authorization",
            "cookie",
            "set-cookie",
            "token",
            "secret",
            "signature",
            "api-key",
            "apikey",
            "x-api-key",
        }

        sanitized: StructuredDict = {}
        for key, value in headers.items():
            key_str = _safe_str(key, 200)
            lowered = key_str.lower()
            if any(part in lowered for part in sensitive_header_parts):
                sanitized[key_str] = "[REDACTED]"
            else:
                sanitized[key_str] = _safe_str(value, 2000)
        return sanitized

    def _redact_sensitive_data(self, data: Any) -> Any:
        """
        Recursively redact secrets while keeping useful operational context.
        """
        sensitive_key_parts = {
            "password",
            "pass",
            "secret",
            "token",
            "api_key",
            "apikey",
            "access_key",
            "private_key",
            "authorization",
            "cookie",
            "credential",
            "card",
            "cvv",
            "ssn",
            "bank",
            "iban",
            "routing",
        }

        if isinstance(data, Mapping):
            redacted: StructuredDict = {}
            for key, value in data.items():
                key_str = _safe_str(key, 200)
                lowered = key_str.lower()
                if any(part in lowered for part in sensitive_key_parts):
                    redacted[key_str] = "[REDACTED]"
                else:
                    redacted[key_str] = self._redact_sensitive_data(value)
            return redacted

        if isinstance(data, list):
            return [self._redact_sensitive_data(item) for item in data[:500]]

        if isinstance(data, tuple):
            return tuple(self._redact_sensitive_data(item) for item in data[:500])

        if isinstance(data, str):
            if len(data) > 15000:
                return data[:15000] + "...[truncated]"
            return data

        return data

    def _summarize_trigger(self, event: TriggerEvent, redacted_payload: Mapping[str, Any]) -> str:
        workflow_label = event.workflow_name or event.workflow_id or "unknown workflow"
        source_label = event.source or event.trigger_type.value

        detail = ""
        if event.trigger_type == TriggerType.FORM:
            contact = redacted_payload.get("contact") if isinstance(redacted_payload.get("contact"), Mapping) else {}
            service = redacted_payload.get("service")
            detail = f" Form contact={contact.get('email') or contact.get('phone') or contact.get('name') or 'unknown'}, service={service or 'unknown'}."
        elif event.trigger_type == TriggerType.EMAIL:
            detail = f" Email subject={redacted_payload.get('subject') or 'unknown'}."
        elif event.trigger_type == TriggerType.SHEET:
            detail = f" Sheet row={redacted_payload.get('row_number') or 'unknown'}."
        elif event.trigger_type == TriggerType.SCHEDULE:
            detail = f" Schedule={redacted_payload.get('schedule_id') or redacted_payload.get('name') or 'unknown'}."
        elif event.trigger_type == TriggerType.WEBHOOK:
            detail = f" Provider={redacted_payload.get('provider') or 'unknown'}."
        elif event.trigger_type == TriggerType.MANUAL:
            detail = " Manual command trigger."

        return f"{event.trigger_type.value} trigger received from {source_label} for {workflow_label}.{detail}"

    # ------------------------------------------------------------------
    # External result normalization
    # ------------------------------------------------------------------

    def _normalize_external_result(self, result: Any, *, default_message: str) -> StructuredDict:
        if isinstance(result, Mapping):
            result_dict = dict(result)
            if "success" in result_dict:
                return {
                    "success": bool(result_dict.get("success")),
                    "message": _safe_str(result_dict.get("message") or default_message, 2000),
                    "data": dict(result_dict.get("data") or {}),
                    "error": result_dict.get("error"),
                    "metadata": dict(result_dict.get("metadata") or {}),
                }
            return self._safe_result(
                message=default_message,
                data={"external_result": result_dict},
            )

        if result is None:
            return self._safe_result(
                message=default_message,
                data={"external_result": None},
            )

        return self._safe_result(
            message=default_message,
            data={"external_result": result},
        )

    # ------------------------------------------------------------------
    # Health, diagnostics, and test helpers
    # ------------------------------------------------------------------

    def health_check(self) -> StructuredDict:
        """
        Dashboard/API health check.
        """
        return self._safe_result(
            message="TriggerEngine is healthy.",
            data={
                "enabled": self.config.enabled,
                "component": self.component_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "runner_registered": self.workflow_runner is not None,
                "security_client_available": self.security_client is not None,
                "memory_client_available": self.memory_client is not None,
                "verification_client_available": self.verification_client is not None,
                "audit_logger_available": self.audit_logger is not None,
                "event_bus_available": self.event_bus is not None,
                "dedupe_cache_size": len(self._dedupe_cache),
                "local_audit_events": len(self._local_audit_events),
                "local_agent_events": len(self._local_agent_events),
                "supported_trigger_types": sorted(SAFE_TRIGGER_TYPES),
            },
        )

    def get_local_audit_events(self, limit: int = 100) -> StructuredDict:
        """
        Returns recent local audit events for tests/dev dashboard.
        Production can replace this with audit_logger integration.
        """
        safe_limit = max(1, min(int(limit), 1000))
        return self._safe_result(
            message="Local audit events retrieved.",
            data={"events": self._local_audit_events[-safe_limit:]},
        )

    def get_local_agent_events(self, limit: int = 100) -> StructuredDict:
        """
        Returns recent local agent events for tests/dev dashboard.
        """
        safe_limit = max(1, min(int(limit), 1000))
        return self._safe_result(
            message="Local agent events retrieved.",
            data={"events": self._local_agent_events[-safe_limit:]},
        )

    def export_registry_manifest(self) -> StructuredDict:
        """
        Agent Registry / Agent Loader compatible manifest.
        """
        return self._safe_result(
            message="TriggerEngine registry manifest exported.",
            data={
                "class_name": "TriggerEngine",
                "module": "agents.workflow_agent.trigger_engine",
                "agent_type": self.agent_type,
                "component_name": self.component_name,
                "version": self.version,
                "public_methods": [
                    "start_from_form",
                    "start_from_webhook",
                    "start_from_sheet",
                    "start_from_email",
                    "start_from_schedule",
                    "start_from_manual_command",
                    "process_trigger",
                    "register_workflow_runner",
                    "register_event_hook",
                    "clear_dedupe_cache",
                    "health_check",
                ],
                "required_context": ["user_id", "workspace_id"],
                "supported_triggers": sorted(SAFE_TRIGGER_TYPES),
                "security_hook": "_requires_security_check",
                "verification_hook": "_prepare_verification_payload",
                "memory_hook": "_prepare_memory_payload",
                "audit_hook": "_log_audit_event",
                "event_hook": "_emit_agent_event",
                "result_hooks": ["_safe_result", "_error_result"],
            },
        )


# ---------------------------------------------------------------------------
# Convenience sync wrapper for simple tests/scripts
# ---------------------------------------------------------------------------

def run_async(coro: Awaitable[StructuredDict]) -> StructuredDict:
    """
    Convenience helper for local scripts/tests.

    In FastAPI or async services, call TriggerEngine methods with await directly.
    """
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = None  # type: ignore[assignment]

    if loop and loop.is_running():
        raise RuntimeError("run_async() cannot be used inside a running event loop. Use await instead.")

    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Local smoke test helper
# ---------------------------------------------------------------------------

async def _smoke_test() -> StructuredDict:
    """
    Import-safe smoke test helper.

    This function is not executed on import. It can be called manually from tests.
    """
    engine = TriggerEngine(config={"safe_mode": False})

    result = await engine.start_from_form(
        user_id="test_user",
        workspace_id="test_workspace",
        workflow_name="lead_capture_workflow",
        form_id="contact_form",
        form_data={
            "full_name": "Test User",
            "email": "test@example.com",
            "phone": "+1 555 000 0000",
            "service": "Website Development",
            "message": "I need a landing page.",
        },
        request_info={
            "source_ip": "127.0.0.1",
            "user_agent": "smoke-test",
        },
    )

    return result


__all__ = [
    "TriggerEngine",
    "TriggerEngineConfig",
    "TriggerContext",
    "TriggerEvent",
    "TriggerType",
    "TriggerStatus",
    "TriggerPriority",
    "run_async",
]


"""
Where to place it:
    agents/workflow_agent/trigger_engine.py

Required dependencies:
    - Python 3.10+
    - Standard library only for this file.
    - Optional future integrations:
        agents.base_agent.BaseAgent
        agents.workflow_agent.workflow_builder.WorkflowBuilder
        agents.workflow_agent.n8n_connector.N8NConnector

How to test it:
    1. Save this file at:
        agents/workflow_agent/trigger_engine.py

    2. From project root, run:
        python -m py_compile agents/workflow_agent/trigger_engine.py

    3. Optional async smoke test:
        python - <<'PY'
        import asyncio
        from agents.workflow_agent.trigger_engine import TriggerEngine

        async def main():
            engine = TriggerEngine(config={"safe_mode": False})
            result = await engine.start_from_form(
                user_id="user_123",
                workspace_id="workspace_456",
                workflow_name="lead_capture_workflow",
                form_id="website_lead_form",
                form_data={
                    "full_name": "John Doe",
                    "email": "john@example.com",
                    "phone": "+1 555 123 4567",
                    "service": "Landing Page",
                    "message": "Need a high-converting landing page."
                }
            )
            print(result)

        asyncio.run(main())
        PY

Agent/Module: Workflow Agent
File Completed: trigger_engine.py
Completion: 19.0%
Completed Files: ['workflow_agent.py', 'n8n_connector.py', 'workflow_builder.py', 'trigger_engine.py']
Remaining Files: ['action_router.py', 'app_connector.py', 'webhook_manager.py', 'form_pipeline.py', 'crm_connector.py', 'sheet_connector.py', 'whatsapp_connector.py', 'email_connector.py', 'notification_engine.py', 'condition_engine.py', 'scheduler.py', 'workflow_monitor.py', 'retry_handler.py', 'workflow_templates.py', 'workflow_memory.py', 'approval_gate.py', 'config.py']
Next Recommended File: agents/workflow_agent/action_router.py
FILE COMPLETE
"""