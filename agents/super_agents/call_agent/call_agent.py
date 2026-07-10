"""
agents/super_agents/call_agent/call_agent.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Call Agent - Main Call Controller

Purpose:
    Main call controller for receptionist mode, summaries, booking,
    lead qualification, voicemail routing, and safe call workflow handling.

Architecture Compatibility:
    - Safe to import even if other future William/Jarvis files are not created yet.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router, and Master Agent routing.
    - Enforces SaaS user/workspace isolation through user_id and workspace_id.
    - Sensitive actions require Security Agent approval.
    - Completed actions prepare Verification Agent payloads.
    - Useful call context prepares Memory Agent payloads.
    - Emits audit/dashboard-friendly events.
    - Returns structured dict/JSON results with success, message, data, error, metadata.

Safety Design:
    - Does not place, answer, transfer, record, or modify real calls directly.
    - Real-world call actions are represented as controlled intents/payloads.
    - External telephony integrations should be implemented in future files such as:
        call_listener.py, contact_router.py, appointment_booker.py, voicemail_handler.py.
    - This file is the safe controller/orchestrator.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover

    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Keeps this file import-safe while the full William/Jarvis architecture
        is still being generated file by file.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent does not implement run().")


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("William.SuperAgents.CallAgent")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "call_agent"
DEFAULT_AGENT_VERSION = "1.0.0"

MAX_TRANSCRIPT_CHARS = 200_000
MAX_SUMMARY_CHARS = 8_000
MAX_NOTES_CHARS = 20_000
MAX_SCRIPT_CHARS = 30_000
MAX_CALLER_FIELD_CHARS = 500

PHONE_REGEX = re.compile(r"^\+?[0-9\s().\-]{7,25}$")
EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

SENSITIVE_PLACEHOLDER = "[REDACTED]"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class CallAction(str, Enum):
    """Supported Call Agent actions."""

    HANDLE_CALL = "handle_call"
    RECEPTIONIST = "receptionist"
    SUMMARIZE_CALL = "summarize_call"
    QUALIFY_LEAD = "qualify_lead"
    BOOK_APPOINTMENT = "book_appointment"
    HANDLE_VOICEMAIL = "handle_voicemail"
    ROUTE_CONTACT = "route_contact"
    GENERATE_SCRIPT = "generate_script"
    CLASSIFY_INTENT = "classify_intent"
    PREPARE_HANDOFF = "prepare_handoff"
    HEALTH_CHECK = "health_check"


class CallDirection(str, Enum):
    """Call direction."""

    INBOUND = "inbound"
    OUTBOUND = "outbound"
    UNKNOWN = "unknown"


class CallStatus(str, Enum):
    """Internal call processing status."""

    RECEIVED = "received"
    IN_PROGRESS = "in_progress"
    RECEPTIONIST_RESPONSE_READY = "receptionist_response_ready"
    SUMMARY_READY = "summary_ready"
    LEAD_QUALIFIED = "lead_qualified"
    BOOKING_PREPARED = "booking_prepared"
    VOICEMAIL_HANDLED = "voicemail_handled"
    ROUTING_PREPARED = "routing_prepared"
    HANDOFF_PREPARED = "handoff_prepared"
    SECURITY_REQUIRED = "security_required"
    DRY_RUN = "dry_run"
    FAILED = "failed"


class LeadTemperature(str, Enum):
    """Lead temperature classification."""

    HOT = "hot"
    WARM = "warm"
    COLD = "cold"
    UNQUALIFIED = "unqualified"
    UNKNOWN = "unknown"


class CallerIntent(str, Enum):
    """Common caller intents."""

    BOOK_APPOINTMENT = "book_appointment"
    ASK_QUESTION = "ask_question"
    REQUEST_CALLBACK = "request_callback"
    SALES_INQUIRY = "sales_inquiry"
    SUPPORT_REQUEST = "support_request"
    BILLING_REQUEST = "billing_request"
    COMPLAINT = "complaint"
    CANCEL = "cancel"
    EMERGENCY = "emergency"
    SPAM = "spam"
    UNKNOWN = "unknown"


class SecurityLevel(str, Enum):
    """Security sensitivity for call actions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CallerProfile:
    """
    Normalized caller/contact information.

    The Call Agent keeps this structure PII-aware. Raw values may be used for
    routing or booking payloads, but audit and memory payloads should hash or
    minimize sensitive fields.
    """

    name: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[str] = None
    company: Optional[str] = None
    timezone: Optional[str] = None
    source: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> Tuple[bool, Optional[str]]:
        if self.name and len(self.name) > MAX_CALLER_FIELD_CHARS:
            return False, "Caller name is too long."
        if self.company and len(self.company) > MAX_CALLER_FIELD_CHARS:
            return False, "Caller company is too long."
        if self.phone and not PHONE_REGEX.match(self.phone):
            return False, "Caller phone number format is invalid."
        if self.email and not EMAIL_REGEX.match(self.email):
            return False, "Caller email format is invalid."
        return True, None


@dataclass
class CallContext:
    """
    Normalized call context used by the Call Agent controller.
    """

    call_id: str
    direction: CallDirection = CallDirection.UNKNOWN
    caller: CallerProfile = field(default_factory=CallerProfile)
    transcript: str = ""
    notes: str = ""
    summary: Optional[str] = None
    intent: CallerIntent = CallerIntent.UNKNOWN
    language: str = "en"
    service_interest: Optional[str] = None
    urgency: Optional[str] = None
    call_started_at: Optional[str] = None
    call_ended_at: Optional[str] = None
    duration_seconds: Optional[int] = None
    recording_url: Optional[str] = None
    consent: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LeadQualification:
    """
    Structured lead qualification result.

    This is useful for CRM, dashboard analytics, Memory Agent, and Verification
    Agent.
    """

    temperature: LeadTemperature = LeadTemperature.UNKNOWN
    score: int = 0
    qualified: bool = False
    reason: str = ""
    pain_points: List[str] = field(default_factory=list)
    goals: List[str] = field(default_factory=list)
    budget: Optional[str] = None
    timeline: Optional[str] = None
    decision_maker: Optional[bool] = None
    recommended_next_step: str = "review"


@dataclass
class AppointmentRequest:
    """
    Booking intent payload.

    This file does not directly create calendar events. It prepares a safe
    structured payload for appointment_booker.py or Calendar Agent.
    """

    title: str
    requested_time: Optional[str] = None
    timezone: Optional[str] = None
    duration_minutes: int = 30
    attendee_name: Optional[str] = None
    attendee_phone: Optional[str] = None
    attendee_email: Optional[str] = None
    notes: str = ""
    service_interest: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReceptionistResponse:
    """
    Receptionist mode response.

    This supports Voice Agent or Call Listener by returning what to say next,
    what data to collect, and what action to prepare.
    """

    response_text: str
    detected_intent: CallerIntent = CallerIntent.UNKNOWN
    next_question: Optional[str] = None
    should_transfer: bool = False
    should_book: bool = False
    should_take_message: bool = False
    should_end_call: bool = False
    handoff_reason: Optional[str] = None
    required_fields: List[str] = field(default_factory=list)


@dataclass
class CallAgentConfig:
    """
    Runtime configuration for CallAgent.

    dry_run:
        Keeps all sensitive real-world call actions simulated.

    require_approval:
        Requires Security Agent approval before transfer, booking, callback,
        outbound-call, or other sensitive actions.

    allow_booking:
        Allows appointment booking payload preparation.

    allow_transfer:
        Allows transfer handoff payload preparation.

    allow_callback:
        Allows callback payload preparation.

    receptionist_business_name:
        Name used in receptionist responses.

    default_services:
        Services used by lead qualification and receptionist prompts.
    """

    dry_run: bool = True
    require_approval: bool = True
    allow_booking: bool = True
    allow_transfer: bool = True
    allow_callback: bool = True
    allow_recording_reference: bool = False
    receptionist_business_name: str = "Digital Promotix"
    receptionist_agent_name: str = "William"
    default_language: str = "en"
    default_timezone: str = "UTC"
    default_call_duration_minutes: int = 30
    lead_score_hot_threshold: int = 75
    lead_score_warm_threshold: int = 45
    default_services: List[str] = field(
        default_factory=lambda: [
            "web development",
            "SEO",
            "Google Ads",
            "Meta Ads",
            "AI automation",
            "AI voice agent",
            "CRM automation",
            "lead generation",
        ]
    )
    audit_enabled: bool = True
    event_emit_enabled: bool = True
    memory_enabled: bool = True
    verification_enabled: bool = True

    @classmethod
    def from_mapping(cls, config: Optional[Mapping[str, Any]]) -> "CallAgentConfig":
        if not config:
            return cls()

        return cls(
            dry_run=bool(config.get("dry_run", True)),
            require_approval=bool(config.get("require_approval", True)),
            allow_booking=bool(config.get("allow_booking", True)),
            allow_transfer=bool(config.get("allow_transfer", True)),
            allow_callback=bool(config.get("allow_callback", True)),
            allow_recording_reference=bool(config.get("allow_recording_reference", False)),
            receptionist_business_name=str(config.get("receptionist_business_name", "Digital Promotix")),
            receptionist_agent_name=str(config.get("receptionist_agent_name", "William")),
            default_language=str(config.get("default_language", "en")),
            default_timezone=str(config.get("default_timezone", "UTC")),
            default_call_duration_minutes=int(config.get("default_call_duration_minutes", 30)),
            lead_score_hot_threshold=int(config.get("lead_score_hot_threshold", 75)),
            lead_score_warm_threshold=int(config.get("lead_score_warm_threshold", 45)),
            default_services=list(config.get("default_services") or cls().default_services),
            audit_enabled=bool(config.get("audit_enabled", True)),
            event_emit_enabled=bool(config.get("event_emit_enabled", True)),
            memory_enabled=bool(config.get("memory_enabled", True)),
            verification_enabled=bool(config.get("verification_enabled", True)),
        )


# ---------------------------------------------------------------------------
# Call Agent
# ---------------------------------------------------------------------------

class CallAgent(BaseAgent):
    """
    Main Call Agent controller.

    Responsibilities:
        - Handle call tasks routed by Master Agent.
        - Run receptionist mode decisioning.
        - Summarize call transcript/notes.
        - Qualify leads from call context.
        - Prepare booking payloads.
        - Prepare transfer/contact routing payloads.
        - Prepare voicemail handling payloads.
        - Prepare handoff payloads for humans or other agents.
        - Enforce Security Agent approval for sensitive call actions.
        - Prepare Memory Agent and Verification Agent payloads.
        - Emit audit/dashboard events.

    Integration Notes:
        - Voice Agent can use receptionist response text.
        - Workflow Agent can route prepared booking/follow-up actions.
        - Calendar/Appointment Booker can consume appointment payloads.
        - CRM Connector can consume lead qualification output.
        - Security Agent should approve sensitive actions.
        - Verification Agent can verify completed task payloads.
        - Memory Agent can store sanitized caller/call context.
    """

    def __init__(
        self,
        config: Optional[Mapping[str, Any]] = None,
        *,
        security_approval_callback: Optional[Callable[[Mapping[str, Any]], Union[bool, Mapping[str, Any]]]] = None,
        audit_callback: Optional[Callable[[Mapping[str, Any]], None]] = None,
        event_callback: Optional[Callable[[Mapping[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=DEFAULT_AGENT_NAME, **kwargs)

        self.config = CallAgentConfig.from_mapping(config)
        self.security_approval_callback = security_approval_callback
        self.audit_callback = audit_callback
        self.event_callback = event_callback
        self.logger = logger or LOGGER

        self.agent_name = DEFAULT_AGENT_NAME
        self.agent_version = DEFAULT_AGENT_VERSION
        self.agent_type = "super_agent"
        self.module_name = "call_agent"

        self.capabilities = [
            "handle_call",
            "receptionist_mode",
            "call_summary",
            "lead_qualification",
            "appointment_booking_preparation",
            "contact_routing_preparation",
            "voicemail_handling",
            "call_script_generation",
            "handoff_preparation",
            "security_approval",
            "audit_logging",
            "verification_payload",
            "memory_payload",
        ]

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible async entrypoint.

        Master Agent, Agent Router, or Agent Loader can call this method.
        """
        return self.execute(task)

    def execute(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Main Call Agent task router.

        Example:
            {
                "action": "handle_call",
                "user_id": "user_123",
                "workspace_id": "workspace_456",
                "payload": {
                    "caller": {"name": "John", "phone": "+15551234567"},
                    "transcript": "Caller wants a website and asked for price.",
                    "direction": "inbound"
                }
            }
        """
        started_at = self._utc_now_iso()
        correlation_id = self._get_correlation_id(task)

        try:
            context_result = self._validate_task_context(task)
            if not context_result["success"]:
                return context_result

            action = self._parse_action(task.get("action"))
            payload = task.get("payload") or {}

            self._emit_agent_event(
                event_type="call_agent.action_started",
                task=task,
                data={
                    "action": action.value,
                    "correlation_id": correlation_id,
                    "started_at": started_at,
                },
            )

            if action == CallAction.HANDLE_CALL:
                result = self.handle_call(task, payload)
            elif action == CallAction.RECEPTIONIST:
                result = self.receptionist_mode(task, payload)
            elif action == CallAction.SUMMARIZE_CALL:
                result = self.summarize_call(task, payload)
            elif action == CallAction.QUALIFY_LEAD:
                result = self.qualify_lead(task, payload)
            elif action == CallAction.BOOK_APPOINTMENT:
                result = self.prepare_booking(task, payload)
            elif action == CallAction.HANDLE_VOICEMAIL:
                result = self.handle_voicemail(task, payload)
            elif action == CallAction.ROUTE_CONTACT:
                result = self.route_contact(task, payload)
            elif action == CallAction.GENERATE_SCRIPT:
                result = self.generate_call_script(task, payload)
            elif action == CallAction.CLASSIFY_INTENT:
                result = self.classify_intent(task, payload)
            elif action == CallAction.PREPARE_HANDOFF:
                result = self.prepare_handoff(task, payload)
            elif action == CallAction.HEALTH_CHECK:
                result = self.health_check()
            else:
                result = self._error_result(
                    message=f"Unsupported CallAgent action: {action}",
                    error_code="unsupported_action",
                    metadata={"correlation_id": correlation_id},
                )

            self._emit_agent_event(
                event_type="call_agent.action_finished",
                task=task,
                data={
                    "action": action.value,
                    "success": bool(result.get("success")),
                    "correlation_id": correlation_id,
                    "finished_at": self._utc_now_iso(),
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("CallAgent execute failed.")
            result = self._error_result(
                message="Call Agent execution failed.",
                error_code="call_agent_execute_failed",
                exception=exc,
                metadata={
                    "correlation_id": correlation_id,
                    "started_at": started_at,
                    "finished_at": self._utc_now_iso(),
                },
            )
            self._log_audit_event(
                event_type="call_agent.error",
                task=task,
                data=result,
            )
            return result

    def handle_call(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Main call controller pipeline.

        Performs:
            1. Normalize call context.
            2. Classify intent.
            3. Generate receptionist response.
            4. Summarize call.
            5. Qualify lead.
            6. Prepare next action payload.
            7. Prepare verification/memory payloads.
        """
        call_result = self._normalize_call_context(payload)
        if not call_result["success"]:
            return call_result

        call_context: CallContext = call_result["data"]["call_context"]

        intent = self._detect_intent(call_context)
        call_context.intent = intent

        receptionist = self._build_receptionist_response(call_context)
        summary = self._summarize_context(call_context)
        call_context.summary = summary

        qualification = self._qualify_context(call_context)

        next_action = self._determine_next_action(
            call_context=call_context,
            receptionist=receptionist,
            qualification=qualification,
        )

        security_result = self._request_security_approval(
            task=task,
            action=CallAction.HANDLE_CALL,
            call_context=call_context,
            proposed_action=next_action,
        )
        if not security_result["success"]:
            return security_result

        status = self._status_from_next_action(next_action)
        verification_payload = self._prepare_verification_payload(
            task=task,
            action=CallAction.HANDLE_CALL,
            status=status,
            call_context=call_context,
            output={
                "intent": intent.value,
                "next_action": next_action,
                "qualification": dataclasses.asdict(qualification),
            },
        )
        memory_payload = self._prepare_memory_payload(
            task=task,
            action=CallAction.HANDLE_CALL,
            status=status,
            call_context=call_context,
            output={
                "summary": summary,
                "intent": intent.value,
                "qualification": dataclasses.asdict(qualification),
            },
        )

        data = {
            "status": status.value,
            "call_context": self._safe_call_context(call_context),
            "intent": intent.value,
            "receptionist_response": dataclasses.asdict(receptionist),
            "summary": summary,
            "lead_qualification": dataclasses.asdict(qualification),
            "next_action": next_action,
            "verification_payload": verification_payload,
            "memory_payload": memory_payload,
        }

        self._log_audit_event(
            event_type="call_agent.call_handled",
            task=task,
            data=data,
        )

        return self._safe_result(
            message="Call handled successfully.",
            data=data,
            metadata={
                "agent": self.agent_name,
                "version": self.agent_version,
                "correlation_id": self._get_correlation_id(task),
                "dry_run": self.config.dry_run,
                "processed_at": self._utc_now_iso(),
            },
        )

    def receptionist_mode(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Generate receptionist-mode response for a live or simulated call.

        Voice Agent can speak response_text. Call Listener can use next_question
        and required_fields to continue the call flow.
        """
        call_result = self._normalize_call_context(payload)
        if not call_result["success"]:
            return call_result

        call_context: CallContext = call_result["data"]["call_context"]
        call_context.intent = self._detect_intent(call_context)
        response = self._build_receptionist_response(call_context)

        status = CallStatus.RECEPTIONIST_RESPONSE_READY
        verification_payload = self._prepare_verification_payload(
            task=task,
            action=CallAction.RECEPTIONIST,
            status=status,
            call_context=call_context,
            output=dataclasses.asdict(response),
        )
        memory_payload = self._prepare_memory_payload(
            task=task,
            action=CallAction.RECEPTIONIST,
            status=status,
            call_context=call_context,
            output=dataclasses.asdict(response),
        )

        return self._safe_result(
            message="Receptionist response prepared.",
            data={
                "status": status.value,
                "receptionist_response": dataclasses.asdict(response),
                "call_context": self._safe_call_context(call_context),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "correlation_id": self._get_correlation_id(task),
                "dry_run": self.config.dry_run,
            },
        )

    def summarize_call(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Summarize call transcript, notes, and caller context.
        """
        call_result = self._normalize_call_context(payload)
        if not call_result["success"]:
            return call_result

        call_context: CallContext = call_result["data"]["call_context"]
        summary = self._summarize_context(call_context)
        call_context.summary = summary

        status = CallStatus.SUMMARY_READY
        verification_payload = self._prepare_verification_payload(
            task=task,
            action=CallAction.SUMMARIZE_CALL,
            status=status,
            call_context=call_context,
            output={"summary": summary},
        )
        memory_payload = self._prepare_memory_payload(
            task=task,
            action=CallAction.SUMMARIZE_CALL,
            status=status,
            call_context=call_context,
            output={"summary": summary},
        )

        return self._safe_result(
            message="Call summary prepared.",
            data={
                "status": status.value,
                "summary": summary,
                "call_context": self._safe_call_context(call_context),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "correlation_id": self._get_correlation_id(task),
            },
        )

    def qualify_lead(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Qualify a caller as a lead based on transcript, service interest, urgency,
        budget, timeline, and decision-maker signals.
        """
        call_result = self._normalize_call_context(payload)
        if not call_result["success"]:
            return call_result

        call_context: CallContext = call_result["data"]["call_context"]
        call_context.intent = self._detect_intent(call_context)
        qualification = self._qualify_context(call_context)

        status = CallStatus.LEAD_QUALIFIED
        verification_payload = self._prepare_verification_payload(
            task=task,
            action=CallAction.QUALIFY_LEAD,
            status=status,
            call_context=call_context,
            output=dataclasses.asdict(qualification),
        )
        memory_payload = self._prepare_memory_payload(
            task=task,
            action=CallAction.QUALIFY_LEAD,
            status=status,
            call_context=call_context,
            output=dataclasses.asdict(qualification),
        )

        return self._safe_result(
            message="Lead qualification completed.",
            data={
                "status": status.value,
                "lead_qualification": dataclasses.asdict(qualification),
                "call_context": self._safe_call_context(call_context),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "correlation_id": self._get_correlation_id(task),
            },
        )

    def prepare_booking(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Prepare appointment booking payload.

        This does not write to a calendar directly. The output can be passed to
        appointment_booker.py, Calendar Agent, or Workflow Agent.
        """
        if not self.config.allow_booking:
            return self._error_result(
                message="Booking preparation is disabled by configuration.",
                error_code="booking_disabled",
            )

        call_result = self._normalize_call_context(payload)
        if not call_result["success"]:
            return call_result

        call_context: CallContext = call_result["data"]["call_context"]
        appointment = self._build_appointment_request(call_context, payload)

        security_result = self._request_security_approval(
            task=task,
            action=CallAction.BOOK_APPOINTMENT,
            call_context=call_context,
            proposed_action={"type": "book_appointment", "appointment": dataclasses.asdict(appointment)},
        )
        if not security_result["success"]:
            return security_result

        status = CallStatus.BOOKING_PREPARED
        verification_payload = self._prepare_verification_payload(
            task=task,
            action=CallAction.BOOK_APPOINTMENT,
            status=status,
            call_context=call_context,
            output={"appointment": dataclasses.asdict(appointment)},
        )
        memory_payload = self._prepare_memory_payload(
            task=task,
            action=CallAction.BOOK_APPOINTMENT,
            status=status,
            call_context=call_context,
            output={"appointment": dataclasses.asdict(appointment)},
        )

        return self._safe_result(
            message="Appointment booking payload prepared.",
            data={
                "status": status.value,
                "appointment_request": dataclasses.asdict(appointment),
                "call_context": self._safe_call_context(call_context),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "correlation_id": self._get_correlation_id(task),
                "dry_run": self.config.dry_run,
            },
        )

    def handle_voicemail(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Prepare voicemail summary and follow-up action.

        Does not send SMS/email/callback directly. It prepares safe payloads for
        Workflow Agent or Notification Engine.
        """
        call_result = self._normalize_call_context(payload)
        if not call_result["success"]:
            return call_result

        call_context: CallContext = call_result["data"]["call_context"]
        summary = self._summarize_context(call_context)
        intent = self._detect_intent(call_context)
        call_context.intent = intent

        voicemail_payload = {
            "type": "voicemail",
            "call_id": call_context.call_id,
            "caller": self._safe_caller(call_context.caller, include_raw=True),
            "summary": summary,
            "intent": intent.value,
            "recommended_next_step": self._voicemail_next_step(intent),
            "created_at": self._utc_now_iso(),
        }

        security_result = self._request_security_approval(
            task=task,
            action=CallAction.HANDLE_VOICEMAIL,
            call_context=call_context,
            proposed_action=voicemail_payload,
        )
        if not security_result["success"]:
            return security_result

        status = CallStatus.VOICEMAIL_HANDLED
        verification_payload = self._prepare_verification_payload(
            task=task,
            action=CallAction.HANDLE_VOICEMAIL,
            status=status,
            call_context=call_context,
            output=voicemail_payload,
        )
        memory_payload = self._prepare_memory_payload(
            task=task,
            action=CallAction.HANDLE_VOICEMAIL,
            status=status,
            call_context=call_context,
            output=voicemail_payload,
        )

        return self._safe_result(
            message="Voicemail handled successfully.",
            data={
                "status": status.value,
                "voicemail_payload": voicemail_payload,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "correlation_id": self._get_correlation_id(task),
            },
        )

    def route_contact(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Prepare contact routing payload.

        This does not perform a live call transfer. It prepares routing decision
        data for contact_router.py or Workflow Agent.
        """
        if not self.config.allow_transfer:
            return self._error_result(
                message="Contact routing/transfer preparation is disabled by configuration.",
                error_code="routing_disabled",
            )

        call_result = self._normalize_call_context(payload)
        if not call_result["success"]:
            return call_result

        call_context: CallContext = call_result["data"]["call_context"]
        call_context.intent = self._detect_intent(call_context)

        route = self._build_contact_route(call_context, payload)

        security_result = self._request_security_approval(
            task=task,
            action=CallAction.ROUTE_CONTACT,
            call_context=call_context,
            proposed_action=route,
        )
        if not security_result["success"]:
            return security_result

        status = CallStatus.ROUTING_PREPARED
        verification_payload = self._prepare_verification_payload(
            task=task,
            action=CallAction.ROUTE_CONTACT,
            status=status,
            call_context=call_context,
            output=route,
        )
        memory_payload = self._prepare_memory_payload(
            task=task,
            action=CallAction.ROUTE_CONTACT,
            status=status,
            call_context=call_context,
            output=route,
        )

        return self._safe_result(
            message="Contact route prepared.",
            data={
                "status": status.value,
                "route": route,
                "call_context": self._safe_call_context(call_context),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "correlation_id": self._get_correlation_id(task),
                "dry_run": self.config.dry_run,
            },
        )

    def generate_call_script(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Generate a short safe call script for receptionist, qualification, or
        callback use.
        """
        context_result = self._validate_task_context(task)
        if not context_result["success"]:
            return context_result

        mode = str(payload.get("mode") or "receptionist").lower().strip()
        service = str(payload.get("service_interest") or payload.get("service") or "your service").strip()
        business_name = str(payload.get("business_name") or self.config.receptionist_business_name).strip()

        script = self._build_script(mode=mode, service=service, business_name=business_name)
        if len(script) > MAX_SCRIPT_CHARS:
            script = script[:MAX_SCRIPT_CHARS]

        status = CallStatus.RECEPTIONIST_RESPONSE_READY
        verification_payload = self._prepare_verification_payload(
            task=task,
            action=CallAction.GENERATE_SCRIPT,
            status=status,
            call_context=None,
            output={"mode": mode, "service": service, "script_hash": self._hash_value(script)},
        )
        memory_payload = self._prepare_memory_payload(
            task=task,
            action=CallAction.GENERATE_SCRIPT,
            status=status,
            call_context=None,
            output={"mode": mode, "service": service, "script_preview": self._safe_preview(script, 500)},
        )

        return self._safe_result(
            message="Call script generated.",
            data={
                "status": status.value,
                "script": script,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "correlation_id": self._get_correlation_id(task),
            },
        )

    def classify_intent(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Classify caller intent from transcript/notes/context.
        """
        call_result = self._normalize_call_context(payload)
        if not call_result["success"]:
            return call_result

        call_context: CallContext = call_result["data"]["call_context"]
        intent = self._detect_intent(call_context)
        call_context.intent = intent

        return self._safe_result(
            message="Caller intent classified.",
            data={
                "intent": intent.value,
                "call_context": self._safe_call_context(call_context),
            },
            metadata={
                "agent": self.agent_name,
                "correlation_id": self._get_correlation_id(task),
            },
        )

    def prepare_handoff(self, task: Mapping[str, Any], payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Prepare human handoff payload for receptionist/call center/owner review.
        """
        call_result = self._normalize_call_context(payload)
        if not call_result["success"]:
            return call_result

        call_context: CallContext = call_result["data"]["call_context"]
        call_context.intent = self._detect_intent(call_context)
        summary = self._summarize_context(call_context)
        qualification = self._qualify_context(call_context)

        handoff_payload = {
            "handoff_id": f"handoff_{uuid.uuid4().hex}",
            "call_id": call_context.call_id,
            "caller": self._safe_caller(call_context.caller, include_raw=True),
            "intent": call_context.intent.value,
            "summary": summary,
            "lead_qualification": dataclasses.asdict(qualification),
            "recommended_next_step": qualification.recommended_next_step,
            "priority": self._handoff_priority(call_context.intent, qualification),
            "created_at": self._utc_now_iso(),
        }

        security_result = self._request_security_approval(
            task=task,
            action=CallAction.PREPARE_HANDOFF,
            call_context=call_context,
            proposed_action=handoff_payload,
        )
        if not security_result["success"]:
            return security_result

        status = CallStatus.HANDOFF_PREPARED
        verification_payload = self._prepare_verification_payload(
            task=task,
            action=CallAction.PREPARE_HANDOFF,
            status=status,
            call_context=call_context,
            output=handoff_payload,
        )
        memory_payload = self._prepare_memory_payload(
            task=task,
            action=CallAction.PREPARE_HANDOFF,
            status=status,
            call_context=call_context,
            output=handoff_payload,
        )

        return self._safe_result(
            message="Handoff payload prepared.",
            data={
                "status": status.value,
                "handoff_payload": handoff_payload,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "correlation_id": self._get_correlation_id(task),
                "dry_run": self.config.dry_run,
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Dashboard/API health check.
        """
        return self._safe_result(
            message="CallAgent is import-safe and ready.",
            data={
                "agent": self.agent_name,
                "version": self.agent_version,
                "type": self.agent_type,
                "module": self.module_name,
                "dry_run": self.config.dry_run,
                "require_approval": self.config.require_approval,
                "capabilities": self.capabilities,
            },
            metadata={
                "checked_at": self._utc_now_iso(),
            },
        )

    def registry_manifest(self) -> Dict[str, Any]:
        """
        Agent Registry / Agent Loader manifest.
        """
        return {
            "agent_name": self.agent_name,
            "class_name": self.__class__.__name__,
            "module": "agents.super_agents.call_agent.call_agent",
            "version": self.agent_version,
            "type": self.agent_type,
            "capabilities": self.capabilities,
            "actions": [action.value for action in CallAction],
            "requires_user_context": True,
            "requires_workspace_context": True,
            "requires_security_for": [
                CallAction.HANDLE_CALL.value,
                CallAction.BOOK_APPOINTMENT.value,
                CallAction.ROUTE_CONTACT.value,
                CallAction.HANDLE_VOICEMAIL.value,
                CallAction.PREPARE_HANDOFF.value,
            ],
            "safe_import": True,
        }

    # -----------------------------------------------------------------------
    # Core internal logic
    # -----------------------------------------------------------------------

    def _normalize_call_context(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        if not isinstance(payload, Mapping):
            return self._error_result(
                message="Call payload must be a mapping/dict.",
                error_code="invalid_payload_type",
            )

        caller_payload = payload.get("caller") or {}
        if not isinstance(caller_payload, Mapping):
            caller_payload = {}

        caller = CallerProfile(
            name=self._clean_optional_str(caller_payload.get("name") or payload.get("caller_name")),
            phone=self._clean_optional_str(caller_payload.get("phone") or payload.get("phone")),
            email=self._clean_optional_str(caller_payload.get("email") or payload.get("email")),
            company=self._clean_optional_str(caller_payload.get("company") or payload.get("company")),
            timezone=self._clean_optional_str(caller_payload.get("timezone") or payload.get("timezone") or self.config.default_timezone),
            source=self._clean_optional_str(caller_payload.get("source") or payload.get("source")),
            metadata=self._normalize_metadata(caller_payload.get("metadata") or {}),
        )

        valid, error = caller.validate()
        if not valid:
            return self._error_result(
                message=error or "Caller profile is invalid.",
                error_code="invalid_caller_profile",
            )

        transcript = str(payload.get("transcript") or "").strip()
        notes = str(payload.get("notes") or "").strip()

        if len(transcript) > MAX_TRANSCRIPT_CHARS:
            return self._error_result(
                message=f"Transcript exceeds {MAX_TRANSCRIPT_CHARS} characters.",
                error_code="transcript_too_long",
            )

        if len(notes) > MAX_NOTES_CHARS:
            return self._error_result(
                message=f"Notes exceed {MAX_NOTES_CHARS} characters.",
                error_code="notes_too_long",
            )

        direction = self._parse_direction(payload.get("direction"))
        intent = self._parse_intent(payload.get("intent"))
        call_id = str(payload.get("call_id") or f"call_{uuid.uuid4().hex}")

        recording_url = self._clean_optional_str(payload.get("recording_url"))
        if recording_url and not self.config.allow_recording_reference:
            recording_url = None

        duration_seconds = payload.get("duration_seconds")
        if duration_seconds is not None:
            try:
                duration_seconds = int(duration_seconds)
            except Exception:
                duration_seconds = None

        call_context = CallContext(
            call_id=call_id,
            direction=direction,
            caller=caller,
            transcript=transcript,
            notes=notes,
            summary=self._clean_optional_str(payload.get("summary")),
            intent=intent,
            language=str(payload.get("language") or self.config.default_language),
            service_interest=self._clean_optional_str(payload.get("service_interest")),
            urgency=self._clean_optional_str(payload.get("urgency")),
            call_started_at=self._clean_optional_str(payload.get("call_started_at")),
            call_ended_at=self._clean_optional_str(payload.get("call_ended_at")),
            duration_seconds=duration_seconds,
            recording_url=recording_url,
            consent=self._normalize_metadata(payload.get("consent") or {}),
            tags=self._normalize_string_list(payload.get("tags") or []),
            metadata=self._normalize_metadata(payload.get("metadata") or {}),
        )

        return self._safe_result(
            message="Call context normalized.",
            data={"call_context": call_context},
        )

    def _detect_intent(self, call_context: CallContext) -> CallerIntent:
        if call_context.intent != CallerIntent.UNKNOWN:
            return call_context.intent

        text = " ".join(
            [
                call_context.transcript,
                call_context.notes,
                call_context.service_interest or "",
                json.dumps(call_context.metadata, default=str),
            ]
        ).lower()

        if not text.strip():
            return CallerIntent.UNKNOWN

        intent_keywords = [
            (CallerIntent.EMERGENCY, ["emergency", "urgent emergency", "danger", "police", "ambulance"]),
            (CallerIntent.SPAM, ["unsubscribe", "robocall", "spam", "wrong number", "do not call"]),
            (CallerIntent.CANCEL, ["cancel", "stop service", "terminate", "close account"]),
            (CallerIntent.BOOK_APPOINTMENT, ["appointment", "schedule", "book", "meeting", "calendar", "available time"]),
            (CallerIntent.REQUEST_CALLBACK, ["call me back", "callback", "return my call", "speak later"]),
            (CallerIntent.SALES_INQUIRY, ["price", "pricing", "quote", "website", "seo", "ads", "marketing", "automation", "service"]),
            (CallerIntent.SUPPORT_REQUEST, ["support", "help", "issue", "problem", "not working", "broken"]),
            (CallerIntent.BILLING_REQUEST, ["invoice", "payment", "billing", "refund", "charge"]),
            (CallerIntent.COMPLAINT, ["complaint", "angry", "bad service", "not happy", "disappointed"]),
            (CallerIntent.ASK_QUESTION, ["question", "asking", "information", "details", "explain"]),
        ]

        for intent, keywords in intent_keywords:
            if any(keyword in text for keyword in keywords):
                return intent

        return CallerIntent.UNKNOWN

    def _build_receptionist_response(self, call_context: CallContext) -> ReceptionistResponse:
        business = self.config.receptionist_business_name
        caller_name = call_context.caller.name or "there"
        service = call_context.service_interest or self._infer_service_interest(call_context) or "the service"

        if call_context.intent == CallerIntent.EMERGENCY:
            return ReceptionistResponse(
                response_text="I understand this may be urgent. Please contact local emergency services immediately if there is any immediate danger. I can also take your details for the team.",
                detected_intent=call_context.intent,
                should_transfer=True,
                handoff_reason="Emergency or urgent concern detected.",
                required_fields=["name", "phone", "issue"],
            )

        if call_context.intent == CallerIntent.SPAM:
            return ReceptionistResponse(
                response_text="No problem. I will mark this as not interested and end the call now. Thank you.",
                detected_intent=call_context.intent,
                should_end_call=True,
                handoff_reason="Caller appears uninterested or wrong contact.",
            )

        if call_context.intent == CallerIntent.BOOK_APPOINTMENT:
            return ReceptionistResponse(
                response_text=f"Sure, {caller_name}. I can help prepare an appointment request with {business}. What day and time works best for you?",
                detected_intent=call_context.intent,
                next_question="What day and time works best for the appointment?",
                should_book=True,
                required_fields=["name", "phone", "requested_time", "service_interest"],
            )

        if call_context.intent == CallerIntent.REQUEST_CALLBACK:
            return ReceptionistResponse(
                response_text=f"Absolutely. I can take your name, best phone number, and what you would like help with so the right person from {business} can call you back.",
                detected_intent=call_context.intent,
                next_question="What is the best phone number and what should the team help you with?",
                should_transfer=False,
                should_take_message=True,
                required_fields=["name", "phone", "reason"],
            )

        if call_context.intent == CallerIntent.SALES_INQUIRY:
            return ReceptionistResponse(
                response_text=f"Thanks for calling {business}. I can help with that. To guide you properly, what is your main goal with {service}, and have you used a similar service before?",
                detected_intent=call_context.intent,
                next_question=f"What is your main goal with {service}?",
                should_transfer=True,
                handoff_reason="Sales inquiry detected.",
                required_fields=["name", "phone", "service_interest", "goal", "budget"],
            )

        if call_context.intent == CallerIntent.SUPPORT_REQUEST:
            return ReceptionistResponse(
                response_text=f"I can help take the details for support. Please share the issue you are facing, and I will prepare it for the {business} team.",
                detected_intent=call_context.intent,
                next_question="What issue are you facing?",
                should_take_message=True,
                required_fields=["name", "phone", "issue"],
            )

        if call_context.intent == CallerIntent.BILLING_REQUEST:
            return ReceptionistResponse(
                response_text="I can take your billing request details and route them to the right team. Please share your name, phone number, and the billing question.",
                detected_intent=call_context.intent,
                should_take_message=True,
                required_fields=["name", "phone", "billing_issue"],
            )

        if call_context.intent == CallerIntent.COMPLAINT:
            return ReceptionistResponse(
                response_text="I’m sorry to hear that. I can take the details carefully and make sure this is routed for review. Please tell me what happened.",
                detected_intent=call_context.intent,
                next_question="Please tell me what happened.",
                should_take_message=True,
                should_transfer=True,
                handoff_reason="Complaint requires human review.",
                required_fields=["name", "phone", "complaint_details"],
            )

        return ReceptionistResponse(
            response_text=f"Thank you for calling {business}. How can I help you today?",
            detected_intent=CallerIntent.UNKNOWN,
            next_question="How can I help you today?",
            required_fields=["name", "phone", "reason"],
        )

    def _summarize_context(self, call_context: CallContext) -> str:
        if call_context.summary:
            return call_context.summary[:MAX_SUMMARY_CHARS]

        source_text = " ".join([call_context.transcript, call_context.notes]).strip()

        if not source_text:
            caller = call_context.caller.name or "Unknown caller"
            phone = call_context.caller.phone or "No phone provided"
            return f"Call received from {caller}. Phone: {phone}. No transcript or notes were provided."

        cleaned = re.sub(r"\s+", " ", source_text).strip()
        service = call_context.service_interest or self._infer_service_interest(call_context)
        intent = call_context.intent.value if call_context.intent else CallerIntent.UNKNOWN.value

        key_points = self._extract_key_points(cleaned)
        summary_lines = [
            f"Intent: {intent}.",
            f"Service interest: {service or 'Not clearly specified'}.",
            f"Caller: {call_context.caller.name or 'Unknown'}."
        ]

        if call_context.caller.company:
            summary_lines.append(f"Company: {call_context.caller.company}.")

        if call_context.urgency:
            summary_lines.append(f"Urgency: {call_context.urgency}.")

        if key_points:
            summary_lines.append("Key points:")
            summary_lines.extend([f"- {point}" for point in key_points])

        if not key_points:
            summary_lines.append(f"Call notes: {self._safe_preview(cleaned, 900)}")

        summary = "\n".join(summary_lines)
        return summary[:MAX_SUMMARY_CHARS]

    def _qualify_context(self, call_context: CallContext) -> LeadQualification:
        text = " ".join(
            [
                call_context.transcript,
                call_context.notes,
                call_context.service_interest or "",
                call_context.urgency or "",
            ]
        ).lower()

        score = 0
        reasons: List[str] = []
        pain_points: List[str] = []
        goals: List[str] = []

        if call_context.caller.phone:
            score += 10
            reasons.append("Caller phone is available.")
        if call_context.caller.email:
            score += 5
            reasons.append("Caller email is available.")
        if call_context.caller.company:
            score += 10
            reasons.append("Company name is available.")
        if call_context.service_interest or self._infer_service_interest(call_context):
            score += 15
            reasons.append("Service interest detected.")

        high_intent_terms = ["price", "quote", "proposal", "ready", "start", "hire", "book", "schedule", "meeting"]
        if any(term in text for term in high_intent_terms):
            score += 20
            reasons.append("High-intent buying or booking language detected.")

        urgency_terms = ["today", "urgent", "asap", "this week", "quickly", "soon", "immediately"]
        if any(term in text for term in urgency_terms):
            score += 15
            reasons.append("Urgency detected.")

        budget_terms = ["budget", "$", "usd", "dollar", "monthly", "one-time", "price range"]
        budget = None
        if any(term in text for term in budget_terms):
            score += 10
            budget = self._extract_budget(text)
            reasons.append("Budget signal detected.")

        decision_terms = ["owner", "founder", "ceo", "manager", "decision", "my business", "we need"]
        decision_maker = None
        if any(term in text for term in decision_terms):
            score += 10
            decision_maker = True
            reasons.append("Decision-maker signal detected.")

        timeline = self._extract_timeline(text)
        if timeline:
            score += 5
            reasons.append("Timeline signal detected.")

        pain_keywords = {
            "leads": "Needs more leads.",
            "sales": "Wants more sales.",
            "traffic": "Needs more traffic.",
            "wasted": "Concerned about wasted budget.",
            "not working": "Current solution is not working.",
            "slow": "Current process or website may be slow.",
            "ads": "Needs advertising support.",
            "website": "Needs website-related help.",
        }
        for keyword, point in pain_keywords.items():
            if keyword in text and point not in pain_points:
                pain_points.append(point)

        goal_keywords = {
            "grow": "Grow the business.",
            "rank": "Improve search rankings.",
            "leads": "Generate qualified leads.",
            "sales": "Increase sales.",
            "automation": "Automate business process.",
            "appointment": "Schedule an appointment.",
            "website": "Build or improve website.",
        }
        for keyword, goal in goal_keywords.items():
            if keyword in text and goal not in goals:
                goals.append(goal)

        score = max(0, min(100, score))

        if score >= self.config.lead_score_hot_threshold:
            temperature = LeadTemperature.HOT
            qualified = True
            next_step = "transfer_or_book_appointment"
        elif score >= self.config.lead_score_warm_threshold:
            temperature = LeadTemperature.WARM
            qualified = True
            next_step = "schedule_follow_up"
        elif score > 0:
            temperature = LeadTemperature.COLD
            qualified = False
            next_step = "nurture_or_take_message"
        else:
            temperature = LeadTemperature.UNKNOWN
            qualified = False
            next_step = "collect_basic_information"

        if call_context.intent == CallerIntent.SPAM:
            temperature = LeadTemperature.UNQUALIFIED
            qualified = False
            next_step = "end_call"

        return LeadQualification(
            temperature=temperature,
            score=score,
            qualified=qualified,
            reason=" ".join(reasons) if reasons else "Not enough information to qualify the lead.",
            pain_points=pain_points,
            goals=goals,
            budget=budget,
            timeline=timeline,
            decision_maker=decision_maker,
            recommended_next_step=next_step,
        )

    def _determine_next_action(
        self,
        *,
        call_context: CallContext,
        receptionist: ReceptionistResponse,
        qualification: LeadQualification,
    ) -> Dict[str, Any]:
        if receptionist.should_end_call:
            return {
                "type": "end_call",
                "reason": receptionist.handoff_reason or "Caller not interested.",
                "dry_run": self.config.dry_run,
            }

        if receptionist.should_book or call_context.intent == CallerIntent.BOOK_APPOINTMENT:
            return {
                "type": "prepare_booking",
                "allowed": self.config.allow_booking,
                "appointment": dataclasses.asdict(self._build_appointment_request(call_context, {})),
                "dry_run": self.config.dry_run,
            }

        if receptionist.should_transfer or qualification.temperature == LeadTemperature.HOT:
            return {
                "type": "prepare_handoff",
                "allowed": self.config.allow_transfer,
                "reason": receptionist.handoff_reason or "Qualified/high-intent caller.",
                "priority": self._handoff_priority(call_context.intent, qualification),
                "dry_run": self.config.dry_run,
            }

        if receptionist.should_take_message:
            return {
                "type": "take_message",
                "reason": receptionist.handoff_reason or "Caller message required.",
                "dry_run": self.config.dry_run,
            }

        return {
            "type": "continue_conversation",
            "next_question": receptionist.next_question,
            "required_fields": receptionist.required_fields,
            "dry_run": self.config.dry_run,
        }

    def _build_appointment_request(
        self,
        call_context: CallContext,
        payload: Mapping[str, Any],
    ) -> AppointmentRequest:
        requested_time = (
            self._clean_optional_str(payload.get("requested_time"))
            or self._clean_optional_str(call_context.metadata.get("requested_time"))
            or self._extract_requested_time(call_context.transcript + " " + call_context.notes)
        )

        title_service = call_context.service_interest or self._infer_service_interest(call_context) or "Consultation"
        caller_name = call_context.caller.name or "Caller"

        return AppointmentRequest(
            title=f"{title_service.title()} Call with {caller_name}",
            requested_time=requested_time,
            timezone=call_context.caller.timezone or self.config.default_timezone,
            duration_minutes=int(payload.get("duration_minutes") or self.config.default_call_duration_minutes),
            attendee_name=call_context.caller.name,
            attendee_phone=call_context.caller.phone,
            attendee_email=call_context.caller.email,
            notes=call_context.summary or self._summarize_context(call_context),
            service_interest=title_service,
            metadata={
                "call_id": call_context.call_id,
                "intent": call_context.intent.value,
                "source": call_context.caller.source,
            },
        )

    def _build_contact_route(self, call_context: CallContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        requested_department = self._clean_optional_str(payload.get("department"))

        if requested_department:
            department = requested_department
        elif call_context.intent == CallerIntent.BILLING_REQUEST:
            department = "billing"
        elif call_context.intent == CallerIntent.SUPPORT_REQUEST:
            department = "support"
        elif call_context.intent in {CallerIntent.SALES_INQUIRY, CallerIntent.BOOK_APPOINTMENT}:
            department = "sales"
        elif call_context.intent == CallerIntent.COMPLAINT:
            department = "manager"
        elif call_context.intent == CallerIntent.EMERGENCY:
            department = "urgent_review"
        else:
            department = "general"

        return {
            "route_id": f"route_{uuid.uuid4().hex}",
            "call_id": call_context.call_id,
            "department": department,
            "intent": call_context.intent.value,
            "caller": self._safe_caller(call_context.caller, include_raw=True),
            "reason": self._summarize_context(call_context),
            "priority": self._route_priority(call_context.intent),
            "dry_run": self.config.dry_run,
            "created_at": self._utc_now_iso(),
        }

    def _build_script(self, *, mode: str, service: str, business_name: str) -> str:
        if mode == "qualification":
            return (
                f"Hi, thanks for calling {business_name}. I can help with {service}.\n\n"
                "I’ll ask just a few quick questions so the right specialist can guide you:\n"
                "1. What is your main goal with this service?\n"
                "2. What problem are you trying to solve right now?\n"
                "3. Have you used a similar service before?\n"
                "4. Do you have a budget range in mind?\n"
                "5. Is this urgent, or would you prefer to schedule a time to discuss it?\n\n"
                "If the caller is interested or confused, prepare a transfer or appointment request. "
                "If not interested, politely end the call."
            )

        if mode == "callback":
            return (
                f"Hi, this is {self.config.receptionist_agent_name} from {business_name}. "
                f"I’m calling back about your interest in {service}. "
                "Do you have a moment, or should I help schedule a better time?"
            )

        if mode == "voicemail":
            return (
                f"Thank you for calling {business_name}. Sorry we missed your call. "
                "Please leave your name, phone number, and what you need help with. "
                "A team member will review your message and follow up."
            )

        return (
            f"Thank you for calling {business_name}. This is {self.config.receptionist_agent_name}. "
            "How can I help you today?"
        )

    # -----------------------------------------------------------------------
    # Compatibility hooks required by prompt
    # -----------------------------------------------------------------------

    def _validate_task_context(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation.

        Every user-specific task must include:
            - user_id
            - workspace_id
        """
        if not isinstance(task, Mapping):
            return self._error_result(
                message="Task must be a mapping/dict.",
                error_code="invalid_task_type",
            )

        user_id = self._clean_optional_str(task.get("user_id"))
        workspace_id = self._clean_optional_str(task.get("workspace_id"))

        if not user_id:
            return self._error_result(
                message="user_id is required for CallAgent tasks.",
                error_code="missing_user_id",
            )

        if not workspace_id:
            return self._error_result(
                message="workspace_id is required for CallAgent tasks.",
                error_code="missing_workspace_id",
            )

        return self._safe_result(
            message="Task context is valid.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "correlation_id": self._get_correlation_id(task),
            },
        )

    def _requires_security_check(
        self,
        *,
        task: Mapping[str, Any],
        action: CallAction,
        call_context: Optional[CallContext] = None,
        proposed_action: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide if Security Agent approval is required.

        Sensitive actions include:
            - booking preparation
            - transfer/handoff preparation
            - voicemail follow-up preparation
            - callback/contact routing
            - any action with high-risk intent
        """
        if not self.config.require_approval:
            return False

        if task.get("skip_security_check") is True:
            return False

        low_risk_actions = {
            CallAction.SUMMARIZE_CALL,
            CallAction.QUALIFY_LEAD,
            CallAction.CLASSIFY_INTENT,
            CallAction.GENERATE_SCRIPT,
            CallAction.RECEPTIONIST,
            CallAction.HEALTH_CHECK,
        }
        if action in low_risk_actions:
            return False

        if call_context and call_context.intent in {CallerIntent.EMERGENCY, CallerIntent.COMPLAINT, CallerIntent.BILLING_REQUEST}:
            return True

        if proposed_action:
            proposed_type = str(proposed_action.get("type") or "").lower()
            if proposed_type in {"prepare_booking", "book_appointment", "prepare_handoff", "route_contact", "callback"}:
                return True

        return action in {
            CallAction.HANDLE_CALL,
            CallAction.BOOK_APPOINTMENT,
            CallAction.ROUTE_CONTACT,
            CallAction.HANDLE_VOICEMAIL,
            CallAction.PREPARE_HANDOFF,
        }

    def _request_security_approval(
        self,
        *,
        task: Mapping[str, Any],
        action: CallAction,
        call_context: Optional[CallContext] = None,
        proposed_action: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Security Agent approval hook.

        Approval can come from:
            - task["permissions"]["approved"] == True
            - task["security"]["approved"] == True
            - security_approval_callback returning True or a success dict
        """
        if not self._requires_security_check(
            task=task,
            action=action,
            call_context=call_context,
            proposed_action=proposed_action,
        ):
            return self._safe_result(
                message="Security check not required for this CallAgent action.",
                data={"approved": True, "source": "not_required"},
            )

        security_payload = {
            "agent": self.agent_name,
            "action": action.value,
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "task_id": task.get("task_id"),
            "correlation_id": self._get_correlation_id(task),
            "security_level": self._security_level(action, call_context, proposed_action).value,
            "call_id": call_context.call_id if call_context else None,
            "caller_hash": self._caller_hash(call_context.caller) if call_context else None,
            "intent": call_context.intent.value if call_context else None,
            "proposed_action": self._sanitize_dict(proposed_action or {}),
            "requested_at": self._utc_now_iso(),
        }

        permissions = task.get("permissions") or {}
        security = task.get("security") or {}

        if isinstance(permissions, Mapping) and permissions.get("approved") is True:
            return self._safe_result(
                message="Call action approved by task permissions.",
                data={
                    "approved": True,
                    "source": "task.permissions",
                    "approved_by": permissions.get("approved_by"),
                    "security_payload": security_payload,
                },
            )

        if isinstance(security, Mapping) and security.get("approved") is True:
            return self._safe_result(
                message="Call action approved by task security context.",
                data={
                    "approved": True,
                    "source": "task.security",
                    "approved_by": security.get("approved_by"),
                    "security_payload": security_payload,
                },
            )

        if self.security_approval_callback:
            callback_response = self.security_approval_callback(security_payload)

            if callback_response is True:
                return self._safe_result(
                    message="Call action approved by Security Agent callback.",
                    data={
                        "approved": True,
                        "source": "security_callback",
                        "security_payload": security_payload,
                    },
                )

            if isinstance(callback_response, Mapping) and callback_response.get("success") is True:
                return self._safe_result(
                    message="Call action approved by Security Agent callback.",
                    data={
                        "approved": True,
                        "source": "security_callback",
                        "approval_response": self._sanitize_dict(callback_response),
                        "security_payload": security_payload,
                    },
                )

        result = self._error_result(
            message="Call action requires Security Agent approval before proceeding.",
            error_code="security_approval_required",
            data={
                "status": CallStatus.SECURITY_REQUIRED.value,
                "approved": False,
                "security_payload": security_payload,
            },
            metadata={
                "agent": self.agent_name,
                "correlation_id": self._get_correlation_id(task),
            },
        )

        self._log_audit_event(
            event_type="call_agent.security_approval_required",
            task=task,
            data=result,
        )

        return result

    def _prepare_verification_payload(
        self,
        *,
        task: Mapping[str, Any],
        action: CallAction,
        status: CallStatus,
        call_context: Optional[CallContext],
        output: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can use this to confirm that:
            - correct user/workspace context was used,
            - action output was prepared,
            - no raw cross-workspace data leaked,
            - sensitive action had approval path.
        """
        return {
            "verification_type": "call_agent_action",
            "agent": self.agent_name,
            "agent_version": self.agent_version,
            "action": action.value,
            "status": status.value,
            "success": True,
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "task_id": task.get("task_id"),
            "correlation_id": self._get_correlation_id(task),
            "call_id": call_context.call_id if call_context else None,
            "caller_hash": self._caller_hash(call_context.caller) if call_context else None,
            "intent": call_context.intent.value if call_context else None,
            "output_hash": self._hash_value(self._safe_json(output)),
            "dry_run": self.config.dry_run,
            "created_at": self._utc_now_iso(),
        }

    def _prepare_memory_payload(
        self,
        *,
        task: Mapping[str, Any],
        action: CallAction,
        status: CallStatus,
        call_context: Optional[CallContext],
        output: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Keeps useful context, but minimizes sensitive values. Raw transcript is
        not stored by default; only preview/hash/summary are included.
        """
        memory: Dict[str, Any] = {
            "memory_type": "call_agent_context",
            "agent": self.agent_name,
            "agent_version": self.agent_version,
            "action": action.value,
            "status": status.value,
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "task_id": task.get("task_id"),
            "correlation_id": self._get_correlation_id(task),
            "created_at": self._utc_now_iso(),
            "output": self._sanitize_dict(output),
        }

        if call_context:
            memory["call"] = {
                "call_id": call_context.call_id,
                "direction": call_context.direction.value,
                "intent": call_context.intent.value,
                "language": call_context.language,
                "service_interest": call_context.service_interest,
                "urgency": call_context.urgency,
                "summary": call_context.summary or self._summarize_context(call_context),
                "caller_hash": self._caller_hash(call_context.caller),
                "caller_company": call_context.caller.company,
                "source": call_context.caller.source,
                "tags": call_context.tags,
                "transcript_hash": self._hash_value(call_context.transcript),
                "transcript_preview": self._safe_preview(call_context.transcript, 500),
            }

        return memory

    def _emit_agent_event(
        self,
        *,
        event_type: str,
        task: Mapping[str, Any],
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit dashboard/API/agent event.

        Future Workflow Monitor or Notification Engine can consume this shape.
        """
        if not self.config.event_emit_enabled:
            return

        event = {
            "event_id": f"evt_{uuid.uuid4().hex}",
            "event_type": event_type,
            "agent": self.agent_name,
            "agent_version": self.agent_version,
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "task_id": task.get("task_id"),
            "correlation_id": self._get_correlation_id(task),
            "data": self._sanitize_dict(data or {}),
            "created_at": self._utc_now_iso(),
        }

        if self.event_callback:
            try:
                self.event_callback(event)
                return
            except Exception:
                self.logger.exception("CallAgent event callback failed.")

        self.logger.info("Agent event: %s", self._safe_json(event))

    def _log_audit_event(
        self,
        *,
        event_type: str,
        task: Mapping[str, Any],
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Audit logging hook.

        Audit data is user/workspace scoped and PII-minimized.
        """
        if not self.config.audit_enabled:
            return

        audit_event = {
            "audit_id": f"audit_{uuid.uuid4().hex}",
            "event_type": event_type,
            "agent": self.agent_name,
            "agent_version": self.agent_version,
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "task_id": task.get("task_id"),
            "correlation_id": self._get_correlation_id(task),
            "data": self._sanitize_dict(data or {}),
            "created_at": self._utc_now_iso(),
        }

        if self.audit_callback:
            try:
                self.audit_callback(audit_event)
                return
            except Exception:
                self.logger.exception("CallAgent audit callback failed.")

        self.logger.info("Audit event: %s", self._safe_json(audit_event))

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured success result.
        """
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error_code: str = "error",
        *,
        exception: Optional[BaseException] = None,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured error result.
        """
        error: Dict[str, Any] = {
            "code": error_code,
            "message": message,
        }
        if exception is not None:
            error["exception_type"] = exception.__class__.__name__
            error["exception"] = self._safe_str(exception)

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    # -----------------------------------------------------------------------
    # Utility helpers
    # -----------------------------------------------------------------------

    def _parse_action(self, action: Any) -> CallAction:
        if isinstance(action, CallAction):
            return action
        if not action:
            return CallAction.HANDLE_CALL
        try:
            return CallAction(str(action).lower().strip())
        except ValueError as exc:
            raise ValueError(f"Unsupported CallAgent action: {action}") from exc

    def _parse_direction(self, value: Any) -> CallDirection:
        if isinstance(value, CallDirection):
            return value
        try:
            return CallDirection(str(value or "unknown").lower().strip())
        except ValueError:
            return CallDirection.UNKNOWN

    def _parse_intent(self, value: Any) -> CallerIntent:
        if isinstance(value, CallerIntent):
            return value
        try:
            return CallerIntent(str(value or "unknown").lower().strip())
        except ValueError:
            return CallerIntent.UNKNOWN

    def _clean_optional_str(self, value: Any) -> Optional[str]:
        if value is None:
            return None
        clean = re.sub(r"\s+", " ", str(value)).strip()
        if not clean:
            return None
        return clean[:MAX_CALLER_FIELD_CHARS]

    def _normalize_string_list(self, value: Any) -> List[str]:
        if not value:
            return []
        if isinstance(value, str):
            items = [value]
        elif isinstance(value, Iterable):
            items = list(value)
        else:
            return []

        normalized: List[str] = []
        seen = set()
        for item in items:
            clean = str(item).strip()
            if not clean:
                continue
            clean = re.sub(r"[^a-zA-Z0-9_\-:.]", "_", clean)[:100]
            if clean not in seen:
                normalized.append(clean)
                seen.add(clean)
        return normalized

    def _normalize_metadata(self, metadata: Any) -> Dict[str, Any]:
        if not isinstance(metadata, Mapping):
            return {}

        safe: Dict[str, Any] = {}
        for key, value in metadata.items():
            clean_key = str(key).strip()[:100]
            if not clean_key:
                continue

            if isinstance(value, (str, int, float, bool)) or value is None:
                safe[clean_key] = value
            else:
                safe[clean_key] = self._safe_json(value)[:3_000]

        return safe

    def _extract_key_points(self, text: str, limit: int = 6) -> List[str]:
        if not text:
            return []

        sentences = re.split(r"(?<=[.!?])\s+", text)
        useful: List[str] = []

        keywords = [
            "need",
            "want",
            "looking",
            "problem",
            "budget",
            "price",
            "schedule",
            "appointment",
            "urgent",
            "website",
            "seo",
            "ads",
            "automation",
            "call back",
            "quote",
        ]

        for sentence in sentences:
            clean = sentence.strip()
            if not clean:
                continue
            if any(keyword in clean.lower() for keyword in keywords):
                useful.append(self._safe_preview(clean, 220))
            if len(useful) >= limit:
                break

        if not useful and text:
            useful.append(self._safe_preview(text, 220))

        return useful

    def _infer_service_interest(self, call_context: CallContext) -> Optional[str]:
        text = " ".join([call_context.transcript, call_context.notes, call_context.service_interest or ""]).lower()

        services = self.config.default_services
        for service in services:
            if service.lower() in text:
                return service

        service_keywords = {
            "website": "web development",
            "landing page": "web development",
            "google ads": "Google Ads",
            "ppc": "Google Ads",
            "meta ads": "Meta Ads",
            "facebook ads": "Meta Ads",
            "seo": "SEO",
            "ranking": "SEO",
            "automation": "AI automation",
            "voice agent": "AI voice agent",
            "chatbot": "AI automation",
            "crm": "CRM automation",
            "lead": "lead generation",
        }

        for keyword, service in service_keywords.items():
            if keyword in text:
                return service

        return None

    def _extract_budget(self, text: str) -> Optional[str]:
        patterns = [
            r"\$[\d,]+(?:\.\d{1,2})?",
            r"\b\d{2,7}\s?(?:usd|dollars|dollar)\b",
            r"\bbudget\s?(?:is|of|around|about)?\s?\$?\d{2,7}\b",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)
        return None

    def _extract_timeline(self, text: str) -> Optional[str]:
        timeline_terms = [
            "today",
            "tomorrow",
            "this week",
            "next week",
            "this month",
            "next month",
            "asap",
            "soon",
            "immediately",
            "in 30 days",
            "in 60 days",
            "in 90 days",
        ]
        for term in timeline_terms:
            if term in text:
                return term
        return None

    def _extract_requested_time(self, text: str) -> Optional[str]:
        if not text:
            return None

        patterns = [
            r"\b(?:today|tomorrow|next week|this week|monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b[^.]{0,80}",
            r"\b\d{1,2}(?::\d{2})?\s?(?:am|pm)\b",
            r"\b\d{4}-\d{2}-\d{2}(?:[ T]\d{2}:\d{2})?\b",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0).strip()
        return None

    def _voicemail_next_step(self, intent: CallerIntent) -> str:
        if intent == CallerIntent.SALES_INQUIRY:
            return "create_sales_callback_task"
        if intent == CallerIntent.BOOK_APPOINTMENT:
            return "prepare_booking_follow_up"
        if intent == CallerIntent.SUPPORT_REQUEST:
            return "create_support_ticket"
        if intent == CallerIntent.BILLING_REQUEST:
            return "route_to_billing"
        if intent == CallerIntent.COMPLAINT:
            return "manager_review"
        return "review_voicemail"

    def _route_priority(self, intent: CallerIntent) -> str:
        if intent in {CallerIntent.EMERGENCY, CallerIntent.COMPLAINT}:
            return "high"
        if intent in {CallerIntent.SALES_INQUIRY, CallerIntent.BOOK_APPOINTMENT}:
            return "medium"
        return "normal"

    def _handoff_priority(self, intent: CallerIntent, qualification: LeadQualification) -> str:
        if intent in {CallerIntent.EMERGENCY, CallerIntent.COMPLAINT}:
            return "high"
        if qualification.temperature == LeadTemperature.HOT:
            return "high"
        if qualification.temperature == LeadTemperature.WARM:
            return "medium"
        return "normal"

    def _status_from_next_action(self, next_action: Mapping[str, Any]) -> CallStatus:
        action_type = str(next_action.get("type") or "").lower()
        if action_type == "prepare_booking":
            return CallStatus.BOOKING_PREPARED
        if action_type in {"prepare_handoff", "take_message"}:
            return CallStatus.HANDOFF_PREPARED
        if action_type == "end_call":
            return CallStatus.RECEPTIONIST_RESPONSE_READY
        return CallStatus.IN_PROGRESS

    def _security_level(
        self,
        action: CallAction,
        call_context: Optional[CallContext],
        proposed_action: Optional[Mapping[str, Any]],
    ) -> SecurityLevel:
        if call_context and call_context.intent == CallerIntent.EMERGENCY:
            return SecurityLevel.CRITICAL
        if call_context and call_context.intent in {CallerIntent.COMPLAINT, CallerIntent.BILLING_REQUEST}:
            return SecurityLevel.HIGH

        proposed_type = str((proposed_action or {}).get("type") or "").lower()
        if proposed_type in {"prepare_booking", "book_appointment", "route_contact", "callback"}:
            return SecurityLevel.HIGH

        if action in {CallAction.BOOK_APPOINTMENT, CallAction.ROUTE_CONTACT, CallAction.PREPARE_HANDOFF}:
            return SecurityLevel.HIGH

        if action in {CallAction.HANDLE_CALL, CallAction.HANDLE_VOICEMAIL}:
            return SecurityLevel.MEDIUM

        return SecurityLevel.LOW

    def _safe_call_context(self, call_context: CallContext) -> Dict[str, Any]:
        return {
            "call_id": call_context.call_id,
            "direction": call_context.direction.value,
            "caller": self._safe_caller(call_context.caller, include_raw=True),
            "transcript_preview": self._safe_preview(call_context.transcript, 500),
            "transcript_hash": self._hash_value(call_context.transcript),
            "notes_preview": self._safe_preview(call_context.notes, 500),
            "summary": call_context.summary,
            "intent": call_context.intent.value,
            "language": call_context.language,
            "service_interest": call_context.service_interest,
            "urgency": call_context.urgency,
            "call_started_at": call_context.call_started_at,
            "call_ended_at": call_context.call_ended_at,
            "duration_seconds": call_context.duration_seconds,
            "recording_url": call_context.recording_url if self.config.allow_recording_reference else None,
            "tags": call_context.tags,
            "metadata": self._sanitize_dict(call_context.metadata),
        }

    def _safe_caller(self, caller: CallerProfile, *, include_raw: bool = False) -> Dict[str, Any]:
        if include_raw:
            return {
                "name": caller.name,
                "phone": caller.phone,
                "email": caller.email,
                "company": caller.company,
                "timezone": caller.timezone,
                "source": caller.source,
                "metadata": self._sanitize_dict(caller.metadata),
                "hash": self._caller_hash(caller),
            }

        return {
            "name_present": bool(caller.name),
            "phone_present": bool(caller.phone),
            "email_present": bool(caller.email),
            "company": caller.company,
            "timezone": caller.timezone,
            "source": caller.source,
            "hash": self._caller_hash(caller),
        }

    def _caller_hash(self, caller: CallerProfile) -> str:
        raw = "|".join(
            [
                caller.name or "",
                caller.phone or "",
                caller.email or "",
                caller.company or "",
            ]
        )
        return self._hash_value(raw)

    def _sanitize_dict(self, value: Any) -> Any:
        sensitive_keys = {
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "auth",
            "access_token",
            "refresh_token",
            "recording",
            "recording_url",
        }

        if dataclasses.is_dataclass(value):
            value = dataclasses.asdict(value)

        if isinstance(value, Mapping):
            sanitized: Dict[str, Any] = {}
            for key, item in value.items():
                key_str = str(key)
                key_lower = key_str.lower()
                if key_lower in sensitive_keys or any(s in key_lower for s in sensitive_keys):
                    sanitized[key_str] = SENSITIVE_PLACEHOLDER
                else:
                    sanitized[key_str] = self._sanitize_dict(item)
            return sanitized

        if isinstance(value, list):
            return [self._sanitize_dict(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self._sanitize_dict(item) for item in value)

        if isinstance(value, bytes):
            return f"<bytes:{len(value)}>"

        return value

    def _hash_value(self, value: Any) -> str:
        text = str(value or "")
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return f"sha256:{digest}"

    def _safe_json(self, value: Any) -> str:
        try:
            return json.dumps(self._sanitize_dict(value), default=str, ensure_ascii=False, sort_keys=True)
        except Exception:
            return str(value)

    def _safe_str(self, value: Any) -> str:
        return str(value)[:2_000]

    def _safe_preview(self, text: Any, limit: int = 180) -> str:
        clean = re.sub(r"\s+", " ", str(text or "")).strip()
        if len(clean) <= limit:
            return clean
        return clean[: max(0, limit - 3)] + "..."

    def _get_correlation_id(self, task: Mapping[str, Any]) -> str:
        for key in ("correlation_id", "request_id", "run_id", "task_id"):
            value = task.get(key)
            if value:
                return str(value)
        return f"corr_{uuid.uuid4().hex}"

    def _utc_now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def build_call_agent(config: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> CallAgent:
    """
    Factory for Agent Loader / FastAPI dependency injection.
    """
    return CallAgent(config=config, **kwargs)


# ---------------------------------------------------------------------------
# Minimal self-test helper
# ---------------------------------------------------------------------------

def _self_test() -> Dict[str, Any]:
    """
    Lightweight import-safe self-test.

    This does not perform a real call, transfer, or booking.
    """
    agent = CallAgent(config={"dry_run": True, "require_approval": False})
    task = {
        "action": "handle_call",
        "user_id": "test_user",
        "workspace_id": "test_workspace",
        "task_id": "test_call_agent",
        "payload": {
            "direction": "inbound",
            "caller": {
                "name": "John Smith",
                "phone": "+15551234567",
                "company": "Smith Roofing",
                "source": "website_call",
            },
            "service_interest": "web development",
            "transcript": (
                "Hi, I need a new website for my roofing business. "
                "I want to get more leads and I would like to know the price. "
                "Can we schedule a meeting this week?"
            ),
            "notes": "Caller sounded interested and asked about pricing.",
        },
    }
    return agent.execute(task)


if __name__ == "__main__":
    print(json.dumps(_self_test(), indent=2, default=str))