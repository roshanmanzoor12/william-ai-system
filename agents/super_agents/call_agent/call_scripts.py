"""
agents/super_agents/call_agent/call_scripts.py

CallScripts for William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    Sales, support, receptionist, voicemail, lead qualification, appointment,
    and objection-handling scripts for the Call Agent module.

Core responsibilities:
    - Provide safe reusable scripts for inbound/outbound calls.
    - Support sales, support, receptionist, voicemail, appointment, and follow-up flows.
    - Handle objections with compliant, non-deceptive responses.
    - Maintain SaaS user/workspace isolation.
    - Prepare payloads for Memory Agent and Verification Agent.
    - Expose structured dict/JSON responses for FastAPI/dashboard use.
    - Stay import-safe even if future William/Jarvis modules are not available yet.

Important safety notes:
    - This file does not place real calls, send messages, modify CRM records,
      or execute destructive actions.
    - Scripts should not impersonate humans deceptively.
    - Sensitive actions must go through Security Agent approval in the execution layer.
"""

from __future__ import annotations

import copy
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union


# =============================================================================
# Safe optional imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """Fallback BaseAgent to keep this file import-safe."""

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

LOGGER = logging.getLogger("william.call_agent.call_scripts")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# =============================================================================
# Constants
# =============================================================================

MODULE_NAME = "call_agent"
FILE_NAME = "call_scripts.py"
CLASS_NAME = "CallScripts"
DEFAULT_VERSION = "1.0.0"

SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:.@/]{1,160}$")
SAFE_SCRIPT_KEY_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:.]{1,160}$")
PLACEHOLDER_PATTERN = re.compile(r"\{([a-zA-Z0-9_\-.]+)\}")

DEFAULT_COMPANY_NAME = "Digital Promotix"
DEFAULT_AGENT_NAME = "Emma"
DEFAULT_OFFER_NAME = "$99.99 one-time 5-page website with logo"
DEFAULT_CALLBACK_CTA = "Would you like to receive a call from our specialist to discuss more in detail?"


# =============================================================================
# Enums
# =============================================================================

class CallScriptType(str, Enum):
    """Supported script categories."""

    SALES_OUTBOUND = "sales_outbound"
    SALES_INBOUND = "sales_inbound"
    SUPPORT_INBOUND = "support_inbound"
    RECEPTIONIST = "receptionist"
    VOICEMAIL = "voicemail"
    APPOINTMENT = "appointment"
    LEAD_QUALIFICATION = "lead_qualification"
    FOLLOW_UP = "follow_up"
    ESCALATION = "escalation"
    CLOSING = "closing"


class CallIntent(str, Enum):
    """Common call intents."""

    NEW_LEAD = "new_lead"
    WEBSITE_OFFER = "website_offer"
    SEO_SERVICE = "seo_service"
    PPC_SERVICE = "ppc_service"
    SOCIAL_MEDIA = "social_media"
    AI_AUTOMATION = "ai_automation"
    SUPPORT_REQUEST = "support_request"
    BILLING_QUESTION = "billing_question"
    APPOINTMENT_BOOKING = "appointment_booking"
    GENERAL_INQUIRY = "general_inquiry"
    COMPLAINT = "complaint"
    UNKNOWN = "unknown"


class ObjectionType(str, Enum):
    """Common sales/support objections."""

    NOT_INTERESTED = "not_interested"
    TOO_EXPENSIVE = "too_expensive"
    SEND_INFO = "send_info"
    ALREADY_HAVE_PROVIDER = "already_have_provider"
    NO_TIME = "no_time"
    CALL_LATER = "call_later"
    NEED_TO_THINK = "need_to_think"
    ASKING_IF_AI = "asking_if_ai"
    TRUST_CONCERN = "trust_concern"
    BAD_EXPERIENCE = "bad_experience"
    REMOVE_ME = "remove_me"
    UNKNOWN = "unknown"


class CallTone(str, Enum):
    """Script tone options."""

    PROFESSIONAL = "professional"
    FRIENDLY = "friendly"
    CONCISE = "concise"
    WARM = "warm"
    FORMAL = "formal"


class CallStage(str, Enum):
    """Conversation stage."""

    OPENING = "opening"
    DISCOVERY = "discovery"
    QUALIFICATION = "qualification"
    VALUE_PITCH = "value_pitch"
    OBJECTION_HANDLING = "objection_handling"
    HANDOFF = "handoff"
    CLOSING = "closing"
    VOICEMAIL = "voicemail"
    FOLLOW_UP = "follow_up"


class EventSeverity(str, Enum):
    """Agent event severity."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class SensitiveAction(str, Enum):
    """Actions that generally require Security Agent approval before execution."""

    PLACE_CALL = "place_call"
    SEND_SMS = "send_sms"
    SEND_EMAIL = "send_email"
    SEND_WHATSAPP = "send_whatsapp"
    UPDATE_CRM = "update_crm"
    BOOK_APPOINTMENT = "book_appointment"
    RECORD_CALL = "record_call"
    TRANSCRIBE_CALL = "transcribe_call"
    EXPORT_LEADS = "export_leads"


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class TaskContext:
    """
    SaaS-safe task context.

    Every user-specific execution must include user_id and workspace_id to avoid
    mixing scripts, preferences, logs, memories, and call data between tenants.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    subscription_tier: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    task_id: Optional[str] = None
    call_id: Optional[str] = None
    lead_id: Optional[str] = None
    source_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScriptSafetyRules:
    """Safety and compliance rules for call scripts."""

    disclose_ai_when_asked: bool = True
    never_claim_to_be_human: bool = True
    avoid_guarantees: bool = True
    avoid_pressure_tactics: bool = True
    respect_do_not_call: bool = True
    collect_minimum_personal_data: bool = True
    allowed_collection_fields: List[str] = field(default_factory=lambda: ["full_name", "phone_number"])
    require_consent_for_recording: bool = True
    require_consent_for_marketing_followup: bool = True
    max_questions_in_a_row: int = 1
    pause_after_question: bool = True


@dataclass
class ScriptPersona:
    """Persona settings used to render scripts."""

    agent_name: str = DEFAULT_AGENT_NAME
    company_name: str = DEFAULT_COMPANY_NAME
    role_name: str = "AI voice assistant"
    tone: CallTone = CallTone.WARM
    speak_style: str = "clear, calm, respectful, and concise"
    disclosure_line: str = "I am an AI voice assistant calling on behalf of {company_name}."
    escalation_line: str = "I can have a specialist follow up with you for the details."


@dataclass
class BusinessOffer:
    """Offer details used in sales scripts."""

    offer_name: str = DEFAULT_OFFER_NAME
    primary_service: str = "website design and development"
    value_points: List[str] = field(
        default_factory=lambda: [
            "a clean 5-page business website",
            "basic logo support",
            "mobile-friendly layout",
            "clear call-to-action sections",
            "simple handoff to a specialist for details",
        ]
    )
    default_cta: str = DEFAULT_CALLBACK_CTA
    disclaimer: str = "Final scope, timeline, and terms are confirmed by the specialist before starting."


@dataclass
class ScriptStep:
    """Single step in a call script."""

    stage: CallStage
    text: str
    purpose: str
    required: bool = True
    wait_for_reply: bool = True
    expected_fields: List[str] = field(default_factory=list)
    safety_notes: List[str] = field(default_factory=list)


@dataclass
class CallScript:
    """Complete reusable call script."""

    key: str
    name: str
    script_type: CallScriptType
    intent: CallIntent
    steps: List[ScriptStep]
    description: str = ""
    tags: List[str] = field(default_factory=list)
    safety_rules: ScriptSafetyRules = field(default_factory=ScriptSafetyRules)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ObjectionResponse:
    """Objection handling response."""

    objection_type: ObjectionType
    short_label: str
    response: str
    follow_up_question: Optional[str] = None
    safety_notes: List[str] = field(default_factory=list)
    recommended_next_stage: CallStage = CallStage.OBJECTION_HANDLING


@dataclass
class RenderOptions:
    """Options for rendering a script."""

    include_stage_labels: bool = True
    include_safety_notes: bool = False
    as_list: bool = True
    max_steps: Optional[int] = None
    tone: Optional[CallTone] = None


# =============================================================================
# Utility functions
# =============================================================================

def utc_now_iso() -> str:
    """Return current UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def dataclass_to_dict(value: Any) -> Any:
    """Convert dataclasses/enums/lists/dicts into JSON-safe structures."""

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


def safe_deepcopy(value: Any) -> Any:
    """Deep-copy with safe fallback."""

    try:
        return copy.deepcopy(value)
    except Exception:
        return value


def redact_sensitive_values(payload: Any) -> Any:
    """Redact sensitive fields before logs/dashboard responses."""

    sensitive_markers = (
        "secret",
        "token",
        "api_key",
        "apikey",
        "password",
        "private_key",
        "credential",
        "authorization",
    )

    if isinstance(payload, Mapping):
        cleaned: Dict[str, Any] = {}
        for key, value in payload.items():
            key_text = str(key)
            if any(marker in key_text.lower() for marker in sensitive_markers):
                cleaned[key_text] = "***REDACTED***" if value else value
            else:
                cleaned[key_text] = redact_sensitive_values(value)
        return cleaned

    if isinstance(payload, list):
        return [redact_sensitive_values(item) for item in payload]

    return payload


def validate_safe_identifier(value: str, field_name: str) -> Tuple[bool, Optional[str]]:
    """Validate safe identifier strings."""

    if not isinstance(value, str) or not value.strip():
        return False, f"{field_name} is required."
    if not SAFE_ID_PATTERN.match(value.strip()):
        return False, f"{field_name} contains unsafe characters or is too long."
    return True, None


def normalize_text(value: Any) -> str:
    """Normalize text for lightweight matching."""

    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def safe_format(template: str, variables: Mapping[str, Any]) -> str:
    """
    Safely format script placeholders.

    Unknown placeholders remain visible as {placeholder} so dashboard editors can
    detect missing values.
    """

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key in variables and variables[key] is not None:
            return str(variables[key])
        return "{" + key + "}"

    return PLACEHOLDER_PATTERN.sub(replace, template)


# =============================================================================
# CallScripts
# =============================================================================

class CallScripts(BaseAgent):
    """
    Production-level script manager for Call Agent.

    Connects to:
        - Master Agent: exposes routing-safe public methods and metadata.
        - Security Agent: prepares approval payloads for sensitive actions.
        - Memory Agent: prepares safe payloads for script preferences/outcomes.
        - Verification Agent: prepares verification payloads after script actions.
        - Dashboard/API: returns structured JSON-safe script data.
        - Agent Registry/Loader: safe metadata and fallback registration.
    """

    module_name = MODULE_NAME
    file_name = FILE_NAME
    agent_name = CLASS_NAME
    version = DEFAULT_VERSION

    def __init__(
        self,
        persona: Optional[ScriptPersona] = None,
        offer: Optional[BusinessOffer] = None,
        scripts: Optional[Mapping[str, CallScript]] = None,
        objection_responses: Optional[Mapping[str, ObjectionResponse]] = None,
        audit_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        memory_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        verification_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.agent_name, agent_id="call_scripts", **kwargs)

        self.logger = logger or LOGGER
        self.persona = persona or ScriptPersona()
        self.offer = offer or BusinessOffer()
        self.audit_sink = audit_sink
        self.event_sink = event_sink
        self.memory_sink = memory_sink
        self.verification_sink = verification_sink
        self.security_approval_callback = security_approval_callback

        self._scripts: Dict[str, CallScript] = dict(scripts or self._build_default_scripts())
        self._objections: Dict[str, ObjectionResponse] = dict(
            objection_responses or self._build_default_objection_responses()
        )
        self._workspace_script_overrides: Dict[str, Dict[str, CallScript]] = {}
        self._workspace_persona_overrides: Dict[str, ScriptPersona] = {}
        self._workspace_offer_overrides: Dict[str, BusinessOffer] = {}

        self._emit_agent_event(
            event_type="call_scripts.initialized",
            severity=EventSeverity.INFO,
            data={"script_count": len(self._scripts), "objection_count": len(self._objections)},
        )

        try:
            register_agent_module(
                module_name=self.module_name,
                class_name=self.agent_name,
                file_path=f"agents/super_agents/call_agent/{self.file_name}",
                version=self.version,
                capabilities=[
                    "sales_scripts",
                    "support_scripts",
                    "reception_scripts",
                    "voicemail_scripts",
                    "lead_qualification_scripts",
                    "objection_handling",
                    "script_rendering",
                    "saas_scoped_script_overrides",
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
        """Validate SaaS context for user/workspace isolation."""

        if context is None:
            if require_user_workspace:
                return self._error_result(
                    message="Task context is required.",
                    error="missing_context",
                    metadata={"hook": "_validate_task_context"},
                )
            return self._safe_result(
                message="No task context required.",
                data={"context": None},
                metadata={"hook": "_validate_task_context"},
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
                )

            workspace_ok, workspace_error = validate_safe_identifier(
                str(ctx.get("workspace_id", "")),
                "workspace_id",
            )
            if not workspace_ok:
                return self._error_result(
                    message=workspace_error or "Invalid workspace_id.",
                    error="invalid_workspace_id",
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
        Return whether a downstream execution action requires Security Agent.

        Rendering scripts is safe. Placing calls, sending messages, updating CRM,
        booking appointments, recording/transcribing calls, and exporting leads
        require security approval in the execution layer.
        """

        action = self._normalize_action(action_type)
        sensitive = {item.value for item in SensitiveAction}

        if action in sensitive:
            return True

        payload = payload or {}
        if payload.get("will_contact_customer") is True:
            return True
        if payload.get("will_update_external_system") is True:
            return True
        if payload.get("contains_bulk_recipients") is True:
            return True

        return False

    def _request_security_approval(
        self,
        action_type: Union[str, SensitiveAction],
        context: Union[TaskContext, Mapping[str, Any]],
        payload: Optional[Mapping[str, Any]] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Prepare Security Agent approval request."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]
        approval = {
            "approval_id": str(uuid.uuid4()),
            "target_agent": "security_agent",
            "source_agent": self.agent_name,
            "module": self.module_name,
            "file": self.file_name,
            "action_type": self._normalize_action(action_type),
            "reason": reason or "Call Agent action requires security approval.",
            "context": ctx,
            "payload": redact_sensitive_values(dict(payload or {})),
            "status": "pending",
            "requested_at": utc_now_iso(),
        }

        self._emit_agent_event(
            event_type="call.security_approval.requested",
            severity=EventSeverity.WARNING,
            data=approval,
            context=ctx,
        )
        self._log_audit_event(
            action="security_approval_requested",
            context=ctx,
            data=approval,
        )

        if self.security_approval_callback:
            try:
                callback_result = self.security_approval_callback(approval)
                if not isinstance(callback_result, Mapping):
                    return self._error_result(
                        message="Security approval callback returned invalid response.",
                        error="invalid_security_callback_response",
                        data={"approval": approval},
                    )
                merged = dict(approval)
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
                    error=exc,
                    data={"approval": approval},
                )

        return self._safe_result(
            message="Security approval prepared and pending.",
            data={"approval": approval},
            metadata={"security_agent_connected": False},
        )

    def _prepare_verification_payload(
        self,
        action: str,
        context: Union[TaskContext, Mapping[str, Any], None] = None,
        result: Optional[Mapping[str, Any]] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent compatible payload."""

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
            "checks": [
                "script_safety",
                "tenant_isolation",
                "minimal_data_collection",
                "no_direct_call_execution",
                "ai_disclosure_when_asked",
            ],
            "created_at": utc_now_iso(),
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
        """Prepare Memory Agent compatible payload."""

        ctx = self._context_or_none(context)
        payload = {
            "memory_id": str(uuid.uuid4()),
            "target_agent": "memory_agent",
            "source_agent": self.agent_name,
            "module": self.module_name,
            "file": self.file_name,
            "memory_type": "call_script_preference",
            "action": action,
            "context": ctx,
            "data": redact_sensitive_values(dict(data or {})),
            "isolation": {
                "user_id": ctx.get("user_id") if ctx else None,
                "workspace_id": ctx.get("workspace_id") if ctx else None,
            },
            "created_at": utc_now_iso(),
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
        """Emit event for Master Agent/dashboard/event bus."""

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

        return event

    def _log_audit_event(
        self,
        action: str,
        context: Union[TaskContext, Mapping[str, Any], None] = None,
        data: Optional[Mapping[str, Any]] = None,
        success: bool = True,
    ) -> Dict[str, Any]:
        """Create audit event for dashboard/task history/compliance."""

        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "action": action,
            "success": success,
            "source_agent": self.agent_name,
            "module": self.module_name,
            "file": self.file_name,
            "context": self._context_or_none(context),
            "data": redact_sensitive_values(dict(data or {})),
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
        """Standard William/Jarvis success result."""

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
        """Standard William/Jarvis error result."""

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
    # Public script methods
    # -------------------------------------------------------------------------

    def list_scripts(
        self,
        context: Union[TaskContext, Mapping[str, Any], None] = None,
        script_type: Optional[Union[str, CallScriptType]] = None,
        intent: Optional[Union[str, CallIntent]] = None,
        include_steps: bool = False,
    ) -> Dict[str, Any]:
        """List available scripts with optional filtering."""

        validation = self._validate_task_context(context, require_user_workspace=context is not None)
        if not validation.get("success"):
            return validation

        ctx = validation.get("data", {}).get("context")
        scripts = self._get_effective_scripts(ctx)

        script_type_value = self._enum_value(script_type)
        intent_value = self._enum_value(intent)

        rows: List[Dict[str, Any]] = []
        for script in scripts.values():
            if script_type_value and script.script_type.value != script_type_value:
                continue
            if intent_value and script.intent.value != intent_value:
                continue

            item = {
                "key": script.key,
                "name": script.name,
                "script_type": script.script_type.value,
                "intent": script.intent.value,
                "description": script.description,
                "tags": list(script.tags),
                "step_count": len(script.steps),
            }
            if include_steps:
                item["steps"] = dataclass_to_dict(script.steps)
            rows.append(item)

        return self._safe_result(
            message="Call scripts listed.",
            data={"scripts": rows, "count": len(rows)},
        )

    def get_script(
        self,
        script_key: str,
        context: Union[TaskContext, Mapping[str, Any], None] = None,
    ) -> Dict[str, Any]:
        """Get a single script by key."""

        key_result = self._validate_script_key(script_key)
        if not key_result.get("success"):
            return key_result

        validation = self._validate_task_context(context, require_user_workspace=context is not None)
        if not validation.get("success"):
            return validation

        ctx = validation.get("data", {}).get("context")
        scripts = self._get_effective_scripts(ctx)
        script = scripts.get(script_key)

        if not script:
            return self._error_result(
                message="Call script not found.",
                error="script_not_found",
                data={"script_key": script_key},
            )

        return self._safe_result(
            message="Call script loaded.",
            data={"script": dataclass_to_dict(script)},
        )

    def render_script(
        self,
        script_key: str,
        context: Union[TaskContext, Mapping[str, Any]],
        variables: Optional[Mapping[str, Any]] = None,
        options: Optional[Union[RenderOptions, Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Render a script with safe personalization.

        This does not execute a call. It only returns script text.
        """

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]

        script_result = self.get_script(script_key, ctx)
        if not script_result.get("success"):
            return script_result

        script = self._dict_to_script(script_result["data"]["script"])
        render_options = self._coerce_render_options(options)
        persona = self._get_effective_persona(ctx)
        offer = self._get_effective_offer(ctx)

        safe_variables = self._build_render_variables(
            context=ctx,
            variables=variables or {},
            persona=persona,
            offer=offer,
        )

        steps = script.steps
        if render_options.max_steps is not None:
            steps = steps[: max(0, int(render_options.max_steps))]

        rendered_steps: List[Dict[str, Any]] = []
        for index, step in enumerate(steps, start=1):
            text = safe_format(step.text, safe_variables)
            item = {
                "index": index,
                "stage": step.stage.value,
                "purpose": step.purpose,
                "text": text,
                "required": step.required,
                "wait_for_reply": step.wait_for_reply,
                "expected_fields": list(step.expected_fields),
            }
            if render_options.include_safety_notes:
                item["safety_notes"] = list(step.safety_notes)
            rendered_steps.append(item)

        rendered_text = self._format_rendered_text(rendered_steps, render_options)

        self._log_audit_event(
            action="script_rendered",
            context=ctx,
            data={"script_key": script_key, "script_type": script.script_type.value},
        )

        verification = self._prepare_verification_payload(
            action="script_rendered",
            context=ctx,
            data={
                "script_key": script_key,
                "script_type": script.script_type.value,
                "intent": script.intent.value,
            },
        )

        memory = self._prepare_memory_payload(
            action="script_used",
            context=ctx,
            data={
                "script_key": script_key,
                "script_type": script.script_type.value,
                "intent": script.intent.value,
            },
        )

        return self._safe_result(
            message="Call script rendered.",
            data={
                "script_key": script.key,
                "name": script.name,
                "script_type": script.script_type.value,
                "intent": script.intent.value,
                "rendered_text": rendered_text,
                "steps": rendered_steps,
                "safety_rules": dataclass_to_dict(script.safety_rules),
                "verification": verification,
                "memory": memory,
            },
        )

    def recommend_script(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        intent: Optional[Union[str, CallIntent]] = None,
        call_direction: str = "outbound",
        customer_message: Optional[str] = None,
        service_hint: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Recommend the best script based on intent, direction, and text."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]
        detected_intent = self.detect_intent(customer_message or service_hint or "", fallback=intent)
        if not detected_intent.get("success"):
            return detected_intent

        intent_value = detected_intent["data"]["intent"]
        direction = normalize_text(call_direction)

        candidates = self._get_effective_scripts(ctx)
        scored: List[Tuple[int, CallScript]] = []

        for script in candidates.values():
            score = 0
            if script.intent.value == intent_value:
                score += 50
            if direction == "outbound" and script.script_type == CallScriptType.SALES_OUTBOUND:
                score += 20
            if direction == "inbound" and script.script_type in {
                CallScriptType.SALES_INBOUND,
                CallScriptType.SUPPORT_INBOUND,
                CallScriptType.RECEPTIONIST,
            }:
                score += 20
            if service_hint and normalize_text(service_hint) in " ".join(script.tags).lower():
                score += 10
            if score > 0:
                scored.append((score, script))

        if not scored:
            fallback_key = "receptionist_general"
            script = candidates.get(fallback_key) or next(iter(candidates.values()))
        else:
            script = sorted(scored, key=lambda pair: pair[0], reverse=True)[0][1]

        return self._safe_result(
            message="Call script recommended.",
            data={
                "script_key": script.key,
                "name": script.name,
                "script_type": script.script_type.value,
                "intent": script.intent.value,
                "detected_intent": intent_value,
            },
        )

    def detect_intent(
        self,
        text: str,
        fallback: Optional[Union[str, CallIntent]] = None,
    ) -> Dict[str, Any]:
        """Detect lightweight call intent from text."""

        normalized = normalize_text(text)
        fallback_value = self._enum_value(fallback) or CallIntent.UNKNOWN.value

        keyword_map = {
            CallIntent.WEBSITE_OFFER.value: ["website", "web design", "landing page", "5-page", "logo"],
            CallIntent.SEO_SERVICE.value: ["seo", "ranking", "google ranking", "organic traffic"],
            CallIntent.PPC_SERVICE.value: ["google ads", "ppc", "paid ads", "meta ads", "facebook ads"],
            CallIntent.SOCIAL_MEDIA.value: ["social media", "instagram", "facebook page", "content"],
            CallIntent.AI_AUTOMATION.value: ["ai", "automation", "chatbot", "voice agent", "workflow"],
            CallIntent.SUPPORT_REQUEST.value: ["support", "issue", "problem", "not working", "help"],
            CallIntent.BILLING_QUESTION.value: ["billing", "invoice", "payment", "charge", "refund"],
            CallIntent.APPOINTMENT_BOOKING.value: ["appointment", "book", "schedule", "meeting", "call back"],
            CallIntent.COMPLAINT.value: ["complaint", "angry", "bad service", "unhappy", "cancel"],
        }

        for intent, keywords in keyword_map.items():
            if any(keyword in normalized for keyword in keywords):
                return self._safe_result(
                    message="Call intent detected.",
                    data={"intent": intent, "confidence": 0.72, "method": "keyword"},
                )

        if fallback_value != CallIntent.UNKNOWN.value:
            return self._safe_result(
                message="Fallback call intent used.",
                data={"intent": fallback_value, "confidence": 0.45, "method": "fallback"},
            )

        return self._safe_result(
            message="Call intent unknown.",
            data={"intent": CallIntent.UNKNOWN.value, "confidence": 0.2, "method": "unknown"},
        )

    # -------------------------------------------------------------------------
    # Objection handling
    # -------------------------------------------------------------------------

    def list_objections(self) -> Dict[str, Any]:
        """List available objection responses."""

        rows = [
            {
                "objection_type": response.objection_type.value,
                "short_label": response.short_label,
                "recommended_next_stage": response.recommended_next_stage.value,
            }
            for response in self._objections.values()
        ]
        return self._safe_result(
            message="Objection responses listed.",
            data={"objections": rows, "count": len(rows)},
        )

    def detect_objection(
        self,
        customer_text: str,
        fallback: Optional[Union[str, ObjectionType]] = None,
    ) -> Dict[str, Any]:
        """Detect objection type from customer text."""

        text = normalize_text(customer_text)
        fallback_value = self._enum_value(fallback) or ObjectionType.UNKNOWN.value

        patterns = {
            ObjectionType.NOT_INTERESTED.value: ["not interested", "no thanks", "don't need", "do not need"],
            ObjectionType.TOO_EXPENSIVE.value: ["expensive", "cost too much", "too much", "price"],
            ObjectionType.SEND_INFO.value: ["send info", "email me", "send details", "send me"],
            ObjectionType.ALREADY_HAVE_PROVIDER.value: ["already have", "we have someone", "agency already", "provider"],
            ObjectionType.NO_TIME.value: ["busy", "no time", "in a meeting", "can't talk"],
            ObjectionType.CALL_LATER.value: ["call later", "call me later", "tomorrow", "next week"],
            ObjectionType.NEED_TO_THINK.value: ["think about", "need to think", "not sure", "maybe"],
            ObjectionType.ASKING_IF_AI.value: ["are you ai", "are you a robot", "real person", "human"],
            ObjectionType.TRUST_CONCERN.value: ["scam", "trust", "legit", "real company"],
            ObjectionType.BAD_EXPERIENCE.value: ["bad experience", "burned before", "didn't work", "wasted money"],
            ObjectionType.REMOVE_ME.value: ["remove me", "don't call", "stop calling", "unsubscribe"],
        }

        for objection, keywords in patterns.items():
            if any(keyword in text for keyword in keywords):
                return self._safe_result(
                    message="Objection detected.",
                    data={"objection_type": objection, "confidence": 0.76, "method": "keyword"},
                )

        return self._safe_result(
            message="Objection unknown.",
            data={
                "objection_type": fallback_value,
                "confidence": 0.35 if fallback_value != ObjectionType.UNKNOWN.value else 0.2,
                "method": "fallback" if fallback_value != ObjectionType.UNKNOWN.value else "unknown",
            },
        )

    def handle_objection(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        customer_text: str,
        objection_type: Optional[Union[str, ObjectionType]] = None,
        variables: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return safe objection-handling response."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]
        detected = self.detect_objection(customer_text, fallback=objection_type)
        objection_value = detected["data"]["objection_type"]

        response = self._objections.get(objection_value) or self._objections.get(ObjectionType.UNKNOWN.value)
        if not response:
            return self._error_result(
                message="No objection response available.",
                error="objection_response_not_found",
                data={"objection_type": objection_value},
            )

        persona = self._get_effective_persona(ctx)
        offer = self._get_effective_offer(ctx)
        render_vars = self._build_render_variables(ctx, variables or {}, persona, offer)

        rendered_response = safe_format(response.response, render_vars)
        rendered_follow_up = safe_format(response.follow_up_question, render_vars) if response.follow_up_question else None

        self._log_audit_event(
            action="objection_handled",
            context=ctx,
            data={"objection_type": objection_value},
        )

        verification = self._prepare_verification_payload(
            action="objection_handled",
            context=ctx,
            data={
                "objection_type": objection_value,
                "safety_notes": response.safety_notes,
                "customer_text_sample": customer_text[:250],
            },
        )

        return self._safe_result(
            message="Objection response prepared.",
            data={
                "objection_type": objection_value,
                "short_label": response.short_label,
                "response": rendered_response,
                "follow_up_question": rendered_follow_up,
                "recommended_next_stage": response.recommended_next_stage.value,
                "safety_notes": response.safety_notes,
                "verification": verification,
            },
        )

    # -------------------------------------------------------------------------
    # Script customization methods
    # -------------------------------------------------------------------------

    def register_script(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        script: Union[CallScript, Mapping[str, Any]],
        actor: Optional[str] = None,
        workspace_scoped: bool = True,
    ) -> Dict[str, Any]:
        """Register or override a script safely."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]

        try:
            script_obj = script if isinstance(script, CallScript) else self._dict_to_script(dict(script))
        except Exception as exc:
            return self._error_result(
                message="Invalid script payload.",
                error=exc,
            )

        key_result = self._validate_script_key(script_obj.key)
        if not key_result.get("success"):
            return key_result

        safety_result = self.validate_script_safety(script_obj)
        if not safety_result.get("success"):
            return safety_result

        if workspace_scoped:
            scope_key = self._workspace_key(ctx)
            self._workspace_script_overrides.setdefault(scope_key, {})[script_obj.key] = script_obj
        else:
            self._scripts[script_obj.key] = script_obj

        audit = self._log_audit_event(
            action="script_registered",
            context=ctx,
            data={
                "script_key": script_obj.key,
                "workspace_scoped": workspace_scoped,
                "actor": actor,
            },
        )

        memory = self._prepare_memory_payload(
            action="custom_call_script_saved",
            context=ctx,
            data={
                "script_key": script_obj.key,
                "script_type": script_obj.script_type.value,
                "intent": script_obj.intent.value,
            },
        )

        verification = self._prepare_verification_payload(
            action="script_registered",
            context=ctx,
            data={"script_key": script_obj.key},
        )

        return self._safe_result(
            message="Call script registered.",
            data={
                "script_key": script_obj.key,
                "workspace_scoped": workspace_scoped,
                "audit": audit,
                "memory": memory,
                "verification": verification,
            },
        )

    def remove_workspace_script_override(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        script_key: str,
        actor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Remove a workspace-specific script override."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        key_result = self._validate_script_key(script_key)
        if not key_result.get("success"):
            return key_result

        ctx = validation["data"]["context"]
        scope_key = self._workspace_key(ctx)
        existed = script_key in self._workspace_script_overrides.get(scope_key, {})

        if existed:
            del self._workspace_script_overrides[scope_key][script_key]

        audit = self._log_audit_event(
            action="workspace_script_override_removed",
            context=ctx,
            data={"script_key": script_key, "actor": actor, "existed": existed},
        )

        return self._safe_result(
            message="Workspace script override removed." if existed else "No workspace override existed.",
            data={"script_key": script_key, "existed": existed, "audit": audit},
        )

    def set_workspace_persona(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        persona: Union[ScriptPersona, Mapping[str, Any]],
        actor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Set workspace-specific call persona."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]

        try:
            persona_obj = persona if isinstance(persona, ScriptPersona) else ScriptPersona(**dict(persona))
        except Exception as exc:
            return self._error_result(
                message="Invalid persona payload.",
                error=exc,
            )

        if persona_obj.agent_name and len(persona_obj.agent_name) > 80:
            return self._error_result(
                message="Persona agent_name is too long.",
                error="invalid_persona_agent_name",
            )

        self._workspace_persona_overrides[self._workspace_key(ctx)] = persona_obj

        audit = self._log_audit_event(
            action="workspace_persona_updated",
            context=ctx,
            data={"actor": actor, "persona": dataclass_to_dict(persona_obj)},
        )

        memory = self._prepare_memory_payload(
            action="call_persona_preference_updated",
            context=ctx,
            data={"persona": dataclass_to_dict(persona_obj)},
        )

        return self._safe_result(
            message="Workspace call persona saved.",
            data={"persona": dataclass_to_dict(persona_obj), "audit": audit, "memory": memory},
        )

    def set_workspace_offer(
        self,
        context: Union[TaskContext, Mapping[str, Any]],
        offer: Union[BusinessOffer, Mapping[str, Any]],
        actor: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Set workspace-specific offer details."""

        validation = self._validate_task_context(context)
        if not validation.get("success"):
            return validation

        ctx = validation["data"]["context"]

        try:
            offer_obj = offer if isinstance(offer, BusinessOffer) else BusinessOffer(**dict(offer))
        except Exception as exc:
            return self._error_result(
                message="Invalid offer payload.",
                error=exc,
            )

        if len(offer_obj.offer_name) > 180:
            return self._error_result(
                message="Offer name is too long.",
                error="invalid_offer_name",
            )

        self._workspace_offer_overrides[self._workspace_key(ctx)] = offer_obj

        audit = self._log_audit_event(
            action="workspace_offer_updated",
            context=ctx,
            data={"actor": actor, "offer": dataclass_to_dict(offer_obj)},
        )

        memory = self._prepare_memory_payload(
            action="call_offer_preference_updated",
            context=ctx,
            data={"offer": dataclass_to_dict(offer_obj)},
        )

        return self._safe_result(
            message="Workspace call offer saved.",
            data={"offer": dataclass_to_dict(offer_obj), "audit": audit, "memory": memory},
        )

    # -------------------------------------------------------------------------
    # Safety validation
    # -------------------------------------------------------------------------

    def validate_script_safety(self, script: Union[CallScript, Mapping[str, Any]]) -> Dict[str, Any]:
        """Validate script against basic safety rules."""

        try:
            script_obj = script if isinstance(script, CallScript) else self._dict_to_script(dict(script))
        except Exception as exc:
            return self._error_result(
                message="Invalid script for safety validation.",
                error=exc,
            )

        issues: List[str] = []
        combined_text = " ".join(step.text for step in script_obj.steps).lower()

        prohibited_phrases = [
            "guaranteed results",
            "guarantee you will",
            "risk-free guaranteed",
            "i am a human",
            "this is not ai",
            "you must buy now",
            "limited to this call only",
        ]

        for phrase in prohibited_phrases:
            if phrase in combined_text:
                issues.append(f"Prohibited or risky phrase detected: {phrase}")

        if script_obj.safety_rules.never_claim_to_be_human and "i am a human" in combined_text:
            issues.append("Script must not claim the AI assistant is human.")

        if script_obj.safety_rules.max_questions_in_a_row <= 1:
            for step in script_obj.steps:
                question_count = step.text.count("?")
                if question_count > 1:
                    issues.append(
                        f"Step in stage '{step.stage.value}' may ask more than one question."
                    )

        if script_obj.script_type == CallScriptType.SALES_OUTBOUND:
            if "specialist" not in combined_text and "call back" not in combined_text:
                issues.append("Outbound sales script should include safe specialist handoff or callback option.")

        if issues:
            return self._error_result(
                message="Script safety validation failed.",
                error="script_safety_issues",
                data={"issues": issues, "script_key": script_obj.key},
            )

        return self._safe_result(
            message="Script safety validation passed.",
            data={"script_key": script_obj.key, "issues": []},
        )

    def get_compliance_guidelines(self) -> Dict[str, Any]:
        """Return built-in call script safety guidelines for dashboard/API."""

        return self._safe_result(
            message="Call script compliance guidelines loaded.",
            data={
                "guidelines": [
                    "Ask one question at a time.",
                    "Wait for the caller to finish before continuing.",
                    "Do not claim the assistant is human.",
                    "Disclose AI identity when asked.",
                    "Do not guarantee results.",
                    "Respect do-not-call or opt-out requests.",
                    "Collect only the minimum required information.",
                    "For Digital Promotix cold calls, collect only full name and phone number unless the user approves more.",
                    "Confirm phone numbers digit-by-digit.",
                    "Escalate complex, legal, financial, billing, or angry-customer issues to a human/specialist.",
                    "Do not place calls, send messages, update CRM, or book appointments directly from this file.",
                ],
                "default_allowed_collection_fields": ["full_name", "phone_number"],
            },
        )

    # -------------------------------------------------------------------------
    # Metadata / health
    # -------------------------------------------------------------------------

    def get_registry_metadata(self) -> Dict[str, Any]:
        """Return Agent Registry / Loader metadata."""

        return self._safe_result(
            message="CallScripts registry metadata loaded.",
            data={
                "module_name": self.module_name,
                "file_name": self.file_name,
                "class_name": self.agent_name,
                "version": self.version,
                "import_path": "agents.super_agents.call_agent.call_scripts.CallScripts",
                "agent_type": "call_agent_helper",
                "safe_to_import": True,
                "requires_context": True,
                "requires_user_id": True,
                "requires_workspace_id": True,
                "capabilities": [
                    "sales_scripts",
                    "support_scripts",
                    "reception_scripts",
                    "voicemail_scripts",
                    "lead_qualification_scripts",
                    "appointment_scripts",
                    "objection_handling",
                    "script_recommendation",
                    "safe_script_rendering",
                    "workspace_persona_overrides",
                    "workspace_offer_overrides",
                ],
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """Return module health status."""

        return self._safe_result(
            message="CallScripts health check passed.",
            data={
                "status": "ok",
                "module": self.module_name,
                "file": self.file_name,
                "class": self.agent_name,
                "version": self.version,
                "script_count": len(self._scripts),
                "objection_count": len(self._objections),
                "workspace_script_override_count": sum(
                    len(value) for value in self._workspace_script_overrides.values()
                ),
            },
        )

    # -------------------------------------------------------------------------
    # Default scripts
    # -------------------------------------------------------------------------

    def _build_default_scripts(self) -> Dict[str, CallScript]:
        """Build default production-safe call scripts."""

        scripts = [
            self._script_sales_outbound_website_offer(),
            self._script_sales_inbound_general(),
            self._script_support_inbound_general(),
            self._script_receptionist_general(),
            self._script_voicemail_general(),
            self._script_appointment_booking(),
            self._script_lead_qualification_basic(),
            self._script_follow_up_general(),
            self._script_escalation_specialist(),
            self._script_closing_callback(),
        ]
        return {script.key: script for script in scripts}

    def _script_sales_outbound_website_offer(self) -> CallScript:
        return CallScript(
            key="sales_outbound_website_offer",
            name="Outbound Website Offer",
            script_type=CallScriptType.SALES_OUTBOUND,
            intent=CallIntent.WEBSITE_OFFER,
            description="Outbound sales script for website offer with specialist callback CTA.",
            tags=["sales", "outbound", "website", "digital_promotix"],
            steps=[
                ScriptStep(
                    stage=CallStage.OPENING,
                    purpose="Open politely and identify company.",
                    text=(
                        "Hi, this is {agent_name} calling on behalf of {company_name}. "
                        "I will be brief. Are you the right person to speak with about your business website?"
                    ),
                    safety_notes=["Ask one question only.", "Do not continue if they opt out."],
                ),
                ScriptStep(
                    stage=CallStage.VALUE_PITCH,
                    purpose="Explain offer clearly.",
                    text=(
                        "Thank you. We are currently offering {offer_name}. "
                        "It is designed for businesses that want a clean online presence without a complicated process."
                    ),
                    wait_for_reply=False,
                    safety_notes=["Avoid guarantees.", "Do not pressure the prospect."],
                ),
                ScriptStep(
                    stage=CallStage.DISCOVERY,
                    purpose="Check basic need.",
                    text="Do you currently have a website for your business?",
                    expected_fields=["has_website"],
                ),
                ScriptStep(
                    stage=CallStage.HANDOFF,
                    purpose="Ask for specialist callback.",
                    text="{default_cta}",
                    expected_fields=["callback_interest"],
                ),
                ScriptStep(
                    stage=CallStage.QUALIFICATION,
                    purpose="Collect minimum required lead data.",
                    text="May I have your full name for the callback?",
                    expected_fields=["full_name"],
                    safety_notes=["Collect only full name and phone number for cold-call flow."],
                ),
                ScriptStep(
                    stage=CallStage.QUALIFICATION,
                    purpose="Collect phone number.",
                    text="What is the best phone number for our specialist to call you on?",
                    expected_fields=["phone_number"],
                    safety_notes=["Confirm phone number digit-by-digit."],
                ),
                ScriptStep(
                    stage=CallStage.CLOSING,
                    purpose="Close respectfully.",
                    text=(
                        "Thank you, {customer_name}. I have noted your callback request. "
                        "A specialist from {company_name} will follow up. Have a great day."
                    ),
                    wait_for_reply=False,
                ),
            ],
        )

    def _script_sales_inbound_general(self) -> CallScript:
        return CallScript(
            key="sales_inbound_general",
            name="Inbound Sales Inquiry",
            script_type=CallScriptType.SALES_INBOUND,
            intent=CallIntent.NEW_LEAD,
            description="Inbound sales script for interested prospects.",
            tags=["sales", "inbound", "lead"],
            steps=[
                ScriptStep(
                    stage=CallStage.OPENING,
                    purpose="Greet caller.",
                    text="Thank you for calling {company_name}. This is {agent_name}. How can I help you today?",
                    expected_fields=["caller_need"],
                ),
                ScriptStep(
                    stage=CallStage.DISCOVERY,
                    purpose="Identify service interest.",
                    text="Which service are you most interested in: website, SEO, ads, social media, or AI automation?",
                    expected_fields=["service_interest"],
                ),
                ScriptStep(
                    stage=CallStage.QUALIFICATION,
                    purpose="Collect caller name.",
                    text="May I have your full name, please?",
                    expected_fields=["full_name"],
                ),
                ScriptStep(
                    stage=CallStage.QUALIFICATION,
                    purpose="Collect callback number.",
                    text="What is the best phone number for our specialist to call you back on?",
                    expected_fields=["phone_number"],
                ),
                ScriptStep(
                    stage=CallStage.CLOSING,
                    purpose="Confirm handoff.",
                    text=(
                        "Perfect. I will pass this to our specialist so they can discuss the details with you. "
                        "{disclaimer}"
                    ),
                    wait_for_reply=False,
                ),
            ],
        )

    def _script_support_inbound_general(self) -> CallScript:
        return CallScript(
            key="support_inbound_general",
            name="Inbound Support Request",
            script_type=CallScriptType.SUPPORT_INBOUND,
            intent=CallIntent.SUPPORT_REQUEST,
            description="Support intake script for existing clients or general support callers.",
            tags=["support", "inbound", "intake"],
            steps=[
                ScriptStep(
                    stage=CallStage.OPENING,
                    purpose="Greet support caller.",
                    text="Thank you for calling {company_name} support. This is {agent_name}. What issue can I help note for the team?",
                    expected_fields=["support_issue"],
                ),
                ScriptStep(
                    stage=CallStage.DISCOVERY,
                    purpose="Clarify issue.",
                    text="When did this issue start?",
                    expected_fields=["issue_start_time"],
                ),
                ScriptStep(
                    stage=CallStage.QUALIFICATION,
                    purpose="Collect caller name.",
                    text="May I have your full name, please?",
                    expected_fields=["full_name"],
                ),
                ScriptStep(
                    stage=CallStage.QUALIFICATION,
                    purpose="Collect callback number.",
                    text="What is the best phone number for the support team to reach you?",
                    expected_fields=["phone_number"],
                ),
                ScriptStep(
                    stage=CallStage.HANDOFF,
                    purpose="Escalate to team.",
                    text="Thank you. I will route this to the support team with your notes.",
                    wait_for_reply=False,
                    safety_notes=["Do not promise exact resolution time unless configured."],
                ),
            ],
        )

    def _script_receptionist_general(self) -> CallScript:
        return CallScript(
            key="receptionist_general",
            name="General Receptionist Intake",
            script_type=CallScriptType.RECEPTIONIST,
            intent=CallIntent.GENERAL_INQUIRY,
            description="Receptionist script for caller intake and routing.",
            tags=["reception", "routing", "inbound"],
            steps=[
                ScriptStep(
                    stage=CallStage.OPENING,
                    purpose="Professional greeting.",
                    text="Thank you for calling {company_name}. This is {agent_name}. How may I direct your call?",
                    expected_fields=["caller_intent"],
                ),
                ScriptStep(
                    stage=CallStage.DISCOVERY,
                    purpose="Determine department.",
                    text="Is your call about sales, support, billing, or an existing project?",
                    expected_fields=["department"],
                ),
                ScriptStep(
                    stage=CallStage.QUALIFICATION,
                    purpose="Collect name.",
                    text="May I have your full name, please?",
                    expected_fields=["full_name"],
                ),
                ScriptStep(
                    stage=CallStage.QUALIFICATION,
                    purpose="Collect callback.",
                    text="What is the best callback number in case the right person is unavailable?",
                    expected_fields=["phone_number"],
                ),
                ScriptStep(
                    stage=CallStage.HANDOFF,
                    purpose="Route call.",
                    text="Thank you. I will route your message to the right team.",
                    wait_for_reply=False,
                ),
            ],
        )

    def _script_voicemail_general(self) -> CallScript:
        return CallScript(
            key="voicemail_general",
            name="General Voicemail",
            script_type=CallScriptType.VOICEMAIL,
            intent=CallIntent.GENERAL_INQUIRY,
            description="Short voicemail message.",
            tags=["voicemail", "missed_call"],
            steps=[
                ScriptStep(
                    stage=CallStage.VOICEMAIL,
                    purpose="Leave concise voicemail.",
                    text=(
                        "Hi, this is {agent_name} calling on behalf of {company_name}. "
                        "We were calling regarding {reason}. Please call us back when convenient. Thank you."
                    ),
                    wait_for_reply=False,
                    safety_notes=["Do not include private details in voicemail unless approved."],
                ),
            ],
        )

    def _script_appointment_booking(self) -> CallScript:
        return CallScript(
            key="appointment_booking_basic",
            name="Appointment Booking Intake",
            script_type=CallScriptType.APPOINTMENT,
            intent=CallIntent.APPOINTMENT_BOOKING,
            description="Appointment booking intake before calendar handoff.",
            tags=["appointment", "booking", "calendar"],
            steps=[
                ScriptStep(
                    stage=CallStage.OPENING,
                    purpose="Confirm booking request.",
                    text="I can help note your appointment request. What would you like to discuss with the specialist?",
                    expected_fields=["meeting_topic"],
                ),
                ScriptStep(
                    stage=CallStage.QUALIFICATION,
                    purpose="Collect name.",
                    text="May I have your full name for the appointment request?",
                    expected_fields=["full_name"],
                ),
                ScriptStep(
                    stage=CallStage.QUALIFICATION,
                    purpose="Collect phone.",
                    text="What is the best phone number for the confirmation?",
                    expected_fields=["phone_number"],
                ),
                ScriptStep(
                    stage=CallStage.DISCOVERY,
                    purpose="Ask preferred time.",
                    text="What day and time usually works best for you?",
                    expected_fields=["preferred_time"],
                ),
                ScriptStep(
                    stage=CallStage.HANDOFF,
                    purpose="Explain confirmation.",
                    text="Thank you. The team will confirm availability before the appointment is finalized.",
                    wait_for_reply=False,
                    safety_notes=["Actual calendar booking should go through Security Agent/appointment_booker."],
                ),
            ],
        )

    def _script_lead_qualification_basic(self) -> CallScript:
        return CallScript(
            key="lead_qualification_basic",
            name="Basic Lead Qualification",
            script_type=CallScriptType.LEAD_QUALIFICATION,
            intent=CallIntent.NEW_LEAD,
            description="Minimal lead qualification for callback.",
            tags=["lead", "qualification"],
            steps=[
                ScriptStep(
                    stage=CallStage.OPENING,
                    purpose="Open qualification.",
                    text="I can quickly note your request for our specialist. Which service are you interested in?",
                    expected_fields=["service_interest"],
                ),
                ScriptStep(
                    stage=CallStage.QUALIFICATION,
                    purpose="Collect name.",
                    text="May I have your full name?",
                    expected_fields=["full_name"],
                ),
                ScriptStep(
                    stage=CallStage.QUALIFICATION,
                    purpose="Collect phone.",
                    text="What phone number should the specialist use to call you?",
                    expected_fields=["phone_number"],
                ),
                ScriptStep(
                    stage=CallStage.CLOSING,
                    purpose="Confirm next step.",
                    text="Thank you. A specialist will review this and follow up with you.",
                    wait_for_reply=False,
                ),
            ],
        )

    def _script_follow_up_general(self) -> CallScript:
        return CallScript(
            key="follow_up_general",
            name="General Follow Up",
            script_type=CallScriptType.FOLLOW_UP,
            intent=CallIntent.GENERAL_INQUIRY,
            description="Follow-up script after previous contact.",
            tags=["follow_up", "callback"],
            steps=[
                ScriptStep(
                    stage=CallStage.OPENING,
                    purpose="Open follow-up.",
                    text=(
                        "Hi, this is {agent_name} from {company_name}. "
                        "I am following up regarding your previous inquiry. Is now a good time?"
                    ),
                    expected_fields=["available_now"],
                ),
                ScriptStep(
                    stage=CallStage.DISCOVERY,
                    purpose="Continue conversation.",
                    text="Would you like our specialist to continue with the details?",
                    expected_fields=["callback_interest"],
                ),
                ScriptStep(
                    stage=CallStage.CLOSING,
                    purpose="Close.",
                    text="Thank you. I will update the team with your response.",
                    wait_for_reply=False,
                ),
            ],
        )

    def _script_escalation_specialist(self) -> CallScript:
        return CallScript(
            key="escalation_specialist",
            name="Specialist Escalation",
            script_type=CallScriptType.ESCALATION,
            intent=CallIntent.GENERAL_INQUIRY,
            description="Escalation script for complex questions or sensitive topics.",
            tags=["escalation", "specialist", "handoff"],
            steps=[
                ScriptStep(
                    stage=CallStage.HANDOFF,
                    purpose="Escalate safely.",
                    text=(
                        "That is a good question. I do not want to give you incomplete information. "
                        "I can have a specialist follow up with you to discuss it properly."
                    ),
                    wait_for_reply=False,
                ),
                ScriptStep(
                    stage=CallStage.QUALIFICATION,
                    purpose="Collect callback details.",
                    text="May I have your full name for the specialist?",
                    expected_fields=["full_name"],
                ),
                ScriptStep(
                    stage=CallStage.QUALIFICATION,
                    purpose="Collect phone number.",
                    text="What is the best phone number for the specialist to call?",
                    expected_fields=["phone_number"],
                ),
            ],
        )

    def _script_closing_callback(self) -> CallScript:
        return CallScript(
            key="closing_callback",
            name="Callback Closing",
            script_type=CallScriptType.CLOSING,
            intent=CallIntent.APPOINTMENT_BOOKING,
            description="Respectful call closing after collecting callback details.",
            tags=["closing", "callback"],
            steps=[
                ScriptStep(
                    stage=CallStage.CLOSING,
                    purpose="Confirm phone number.",
                    text="To confirm, the callback number is {phone_number}. Is that correct?",
                    expected_fields=["phone_confirmed"],
                ),
                ScriptStep(
                    stage=CallStage.CLOSING,
                    purpose="Final thanks.",
                    text="Thank you, {customer_name}. I will pass this to the team. Have a great day.",
                    wait_for_reply=False,
                ),
            ],
        )

    def _build_default_objection_responses(self) -> Dict[str, ObjectionResponse]:
        """Build safe default objection responses."""

        responses = [
            ObjectionResponse(
                objection_type=ObjectionType.NOT_INTERESTED,
                short_label="Not interested",
                response="I understand. I will not take more of your time.",
                follow_up_question="Would you prefer that we do not contact you again?",
                safety_notes=["Respect opt-out immediately."],
                recommended_next_stage=CallStage.CLOSING,
            ),
            ObjectionResponse(
                objection_type=ObjectionType.TOO_EXPENSIVE,
                short_label="Too expensive",
                response=(
                    "I understand. The offer is meant to keep the starting point simple, "
                    "and the specialist can explain what is included before anything moves forward."
                ),
                follow_up_question="Would you like a specialist to explain the exact scope first?",
            ),
            ObjectionResponse(
                objection_type=ObjectionType.SEND_INFO,
                short_label="Send information",
                response="Absolutely. I can note that you would like the details sent over.",
                follow_up_question="What is the best phone number for our specialist to confirm the details?",
                safety_notes=["Sending email/WhatsApp should be handled by approved connector layer."],
            ),
            ObjectionResponse(
                objection_type=ObjectionType.ALREADY_HAVE_PROVIDER,
                short_label="Already has provider",
                response=(
                    "That is completely fine. Many businesses already have someone helping them. "
                    "Our specialist can still share a quick comparison if you ever want a second option."
                ),
                follow_up_question="Would you like a quick callback, or should I leave it for now?",
            ),
            ObjectionResponse(
                objection_type=ObjectionType.NO_TIME,
                short_label="No time",
                response="No problem. I will keep it brief.",
                follow_up_question="Would a quick callback from a specialist at a better time work for you?",
            ),
            ObjectionResponse(
                objection_type=ObjectionType.CALL_LATER,
                short_label="Call later",
                response="Sure, I can note that a later time is better.",
                follow_up_question="What day and time usually works best for a callback?",
            ),
            ObjectionResponse(
                objection_type=ObjectionType.NEED_TO_THINK,
                short_label="Needs to think",
                response="Of course. It is better to review the details properly before deciding.",
                follow_up_question="Would you like a specialist to explain the scope so you can decide comfortably?",
            ),
            ObjectionResponse(
                objection_type=ObjectionType.ASKING_IF_AI,
                short_label="Asking if AI",
                response="{disclosure_line}",
                follow_up_question="Would you like me to connect your request to a human specialist?",
                safety_notes=["Disclose AI identity when asked.", "Never claim to be human."],
            ),
            ObjectionResponse(
                objection_type=ObjectionType.TRUST_CONCERN,
                short_label="Trust concern",
                response=(
                    "I understand your concern. You should only move forward after you are comfortable. "
                    "A specialist can share company details, scope, and next steps clearly."
                ),
                follow_up_question="Would you like a specialist to call and explain everything first?",
                safety_notes=["Do not overclaim credentials."],
            ),
            ObjectionResponse(
                objection_type=ObjectionType.BAD_EXPERIENCE,
                short_label="Bad previous experience",
                response=(
                    "I am sorry to hear that. A lot of businesses feel careful after a bad experience. "
                    "Our specialist can keep the discussion clear and explain the scope before anything is agreed."
                ),
                follow_up_question="Would you like them to call you with the details?",
            ),
            ObjectionResponse(
                objection_type=ObjectionType.REMOVE_ME,
                short_label="Remove me",
                response="I understand. I will note your request not to be contacted again.",
                follow_up_question=None,
                safety_notes=["Respect opt-out.", "Route suppression update through approved CRM/contact system."],
                recommended_next_stage=CallStage.CLOSING,
            ),
            ObjectionResponse(
                objection_type=ObjectionType.UNKNOWN,
                short_label="Unknown objection",
                response="I understand. I do not want to assume. I can have a specialist follow up if that helps.",
                follow_up_question="Would you like a specialist to call you back?",
            ),
        ]

        return {response.objection_type.value: response for response in responses}

    # -------------------------------------------------------------------------
    # Internal conversion/helpers
    # -------------------------------------------------------------------------

    def _validate_script_key(self, script_key: str) -> Dict[str, Any]:
        """Validate script key."""

        if not isinstance(script_key, str) or not script_key.strip():
            return self._error_result(
                message="script_key is required.",
                error="missing_script_key",
            )

        if not SAFE_SCRIPT_KEY_PATTERN.match(script_key.strip()):
            return self._error_result(
                message="script_key contains unsafe characters or is too long.",
                error="invalid_script_key",
                data={"script_key": script_key},
            )

        return self._safe_result(
            message="script_key is valid.",
            data={"script_key": script_key},
        )

    def _get_effective_scripts(self, context: Optional[Mapping[str, Any]]) -> Dict[str, CallScript]:
        """Return default scripts merged with workspace overrides."""

        scripts = dict(self._scripts)
        if context:
            overrides = self._workspace_script_overrides.get(self._workspace_key(context), {})
            scripts.update(overrides)
        return scripts

    def _get_effective_persona(self, context: Optional[Mapping[str, Any]]) -> ScriptPersona:
        """Return persona with workspace override if present."""

        if context:
            return self._workspace_persona_overrides.get(self._workspace_key(context), self.persona)
        return self.persona

    def _get_effective_offer(self, context: Optional[Mapping[str, Any]]) -> BusinessOffer:
        """Return offer with workspace override if present."""

        if context:
            return self._workspace_offer_overrides.get(self._workspace_key(context), self.offer)
        return self.offer

    def _workspace_key(self, context: Mapping[str, Any]) -> str:
        """Build isolated workspace key."""

        return f"{context.get('user_id')}:{context.get('workspace_id')}"

    def _context_or_none(
        self,
        context: Union[TaskContext, Mapping[str, Any], None],
    ) -> Optional[Dict[str, Any]]:
        """Convert context into dictionary."""

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

    def _normalize_action(self, action_type: Union[str, SensitiveAction, None]) -> str:
        """Normalize action type."""

        if action_type is None:
            return ""
        if isinstance(action_type, SensitiveAction):
            return action_type.value
        return str(action_type).strip().lower()

    def _enum_value(self, value: Any) -> Optional[str]:
        """Return enum value or normalized string."""

        if value is None:
            return None
        if isinstance(value, Enum):
            return str(value.value)
        return str(value).strip().lower()

    def _build_render_variables(
        self,
        context: Mapping[str, Any],
        variables: Mapping[str, Any],
        persona: ScriptPersona,
        offer: BusinessOffer,
    ) -> Dict[str, Any]:
        """Build safe variables used in scripts."""

        safe_vars = {
            "agent_name": persona.agent_name,
            "company_name": persona.company_name,
            "role_name": persona.role_name,
            "tone": persona.tone.value,
            "speak_style": persona.speak_style,
            "disclosure_line": safe_format(
                persona.disclosure_line,
                {"company_name": persona.company_name, "agent_name": persona.agent_name},
            ),
            "escalation_line": persona.escalation_line,
            "offer_name": offer.offer_name,
            "primary_service": offer.primary_service,
            "value_points": "; ".join(offer.value_points),
            "default_cta": offer.default_cta,
            "disclaimer": offer.disclaimer,
            "customer_name": variables.get("customer_name") or variables.get("full_name") or "there",
            "phone_number": variables.get("phone_number") or "{phone_number}",
            "reason": variables.get("reason") or "your inquiry",
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
        }

        for key, value in variables.items():
            if key in {"secret", "token", "password", "api_key"}:
                continue
            safe_vars[str(key)] = value

        return safe_vars

    def _format_rendered_text(
        self,
        rendered_steps: Sequence[Mapping[str, Any]],
        options: RenderOptions,
    ) -> str:
        """Format rendered steps into readable text."""

        lines: List[str] = []
        for step in rendered_steps:
            prefix = ""
            if options.include_stage_labels:
                prefix = f"[{str(step.get('stage', '')).upper()}] "
            if options.as_list:
                lines.append(f"{step.get('index')}. {prefix}{step.get('text')}")
            else:
                lines.append(f"{prefix}{step.get('text')}")
        return "\n".join(lines)

    def _coerce_render_options(
        self,
        options: Optional[Union[RenderOptions, Mapping[str, Any]]],
    ) -> RenderOptions:
        """Convert render options."""

        if options is None:
            return RenderOptions()
        if isinstance(options, RenderOptions):
            return options

        raw = dict(options)
        tone = raw.get("tone")
        if tone and not isinstance(tone, CallTone):
            try:
                raw["tone"] = CallTone(str(tone))
            except Exception:
                raw["tone"] = None

        return RenderOptions(**raw)

    def _dict_to_script(self, payload: Mapping[str, Any]) -> CallScript:
        """Convert dictionary into CallScript dataclass."""

        steps_raw = payload.get("steps", [])
        steps: List[ScriptStep] = []

        for item in steps_raw:
            if isinstance(item, ScriptStep):
                steps.append(item)
                continue

            item_dict = dict(item)
            stage_value = item_dict.get("stage", CallStage.DISCOVERY.value)
            item_dict["stage"] = stage_value if isinstance(stage_value, CallStage) else CallStage(str(stage_value))
            steps.append(ScriptStep(**item_dict))

        safety_raw = payload.get("safety_rules", ScriptSafetyRules())
        if isinstance(safety_raw, ScriptSafetyRules):
            safety = safety_raw
        else:
            safety = ScriptSafetyRules(**dict(safety_raw))

        script_type = payload.get("script_type", CallScriptType.RECEPTIONIST.value)
        intent = payload.get("intent", CallIntent.UNKNOWN.value)

        return CallScript(
            key=str(payload["key"]),
            name=str(payload.get("name", payload["key"])),
            script_type=script_type if isinstance(script_type, CallScriptType) else CallScriptType(str(script_type)),
            intent=intent if isinstance(intent, CallIntent) else CallIntent(str(intent)),
            steps=steps,
            description=str(payload.get("description", "")),
            tags=list(payload.get("tags", [])),
            safety_rules=safety,
            metadata=dict(payload.get("metadata", {})),
        )


# =============================================================================
# Module-level factory / metadata
# =============================================================================

def create_call_scripts(**kwargs: Any) -> CallScripts:
    """Factory for Agent Loader / tests."""

    return CallScripts(**kwargs)


def get_module_metadata() -> Dict[str, Any]:
    """Return import-safe module metadata."""

    return {
        "module_name": MODULE_NAME,
        "file_name": FILE_NAME,
        "class_name": CLASS_NAME,
        "version": DEFAULT_VERSION,
        "import_path": "agents.super_agents.call_agent.call_scripts.CallScripts",
        "safe_to_import": True,
        "purpose": "Sales/support/reception scripts and objection handling.",
        "completion": 83.3,
    }


__all__ = [
    "CallScripts",
    "TaskContext",
    "ScriptSafetyRules",
    "ScriptPersona",
    "BusinessOffer",
    "ScriptStep",
    "CallScript",
    "ObjectionResponse",
    "RenderOptions",
    "CallScriptType",
    "CallIntent",
    "ObjectionType",
    "CallTone",
    "CallStage",
    "EventSeverity",
    "SensitiveAction",
    "create_call_scripts",
    "get_module_metadata",
]