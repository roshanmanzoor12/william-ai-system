"""
agents/super_agents/call_agent/receptionist_mode.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Business greeting, caller intake, routing, and receptionist scripts for the Call Agent.

Responsibilities:
    - Generate safe business greetings
    - Collect caller intake details
    - Detect caller intent
    - Route calls to departments, agents, voicemail, callback, or appointment flows
    - Provide script prompts for AI voice/receptionist conversations
    - Keep SaaS user/workspace isolation
    - Prepare Memory Agent compatible context
    - Prepare Verification Agent payloads
    - Emit dashboard/API/audit friendly events

Important:
    This file does not place, answer, transfer, record, or manipulate real calls directly.
    It only prepares structured receptionist decisions and scripts. Real telephony actions
    must be performed by protected Call Agent / Voice Agent / provider connectors after
    permission checks.
"""

from __future__ import annotations

import copy
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union


# =============================================================================
# Safe Optional Imports / Fallbacks
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        Real William/Jarvis deployment should provide agents.base_agent.BaseAgent.
        This fallback keeps this file importable during staged development.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent.run is not implemented.")


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    SecurityAgent = None  # type: ignore


try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover
    MemoryAgent = None  # type: ignore


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    VerificationAgent = None  # type: ignore


LOGGER = logging.getLogger("William.CallAgent.ReceptionistMode")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# =============================================================================
# Enums / Data Structures
# =============================================================================

class CallIntent(str, Enum):
    """Supported caller intents."""

    SALES = "sales"
    SUPPORT = "support"
    BILLING = "billing"
    APPOINTMENT = "appointment"
    COMPLAINT = "complaint"
    EMERGENCY = "emergency"
    GENERAL = "general"
    EXISTING_CUSTOMER = "existing_customer"
    NEW_LEAD = "new_lead"
    PARTNERSHIP = "partnership"
    HUMAN_AGENT = "human_agent"
    VOICEMAIL = "voicemail"
    UNKNOWN = "unknown"


class CallPriority(str, Enum):
    """Call priority levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class CallRouteType(str, Enum):
    """Receptionist routing decision types."""

    TRANSFER = "transfer"
    CALLBACK = "callback"
    APPOINTMENT = "appointment"
    VOICEMAIL = "voicemail"
    INFO_COLLECT = "info_collect"
    HUMAN_REVIEW = "human_review"
    END_CALL = "end_call"
    SAFE_BLOCK = "safe_block"


class ReceptionistStep(str, Enum):
    """Conversation step identifiers."""

    GREETING = "greeting"
    CONSENT_NOTICE = "consent_notice"
    CALLER_NAME = "caller_name"
    PHONE_CONFIRMATION = "phone_confirmation"
    REASON_FOR_CALL = "reason_for_call"
    INTENT_CONFIRMATION = "intent_confirmation"
    INTAKE_DETAILS = "intake_details"
    ROUTING = "routing"
    CLOSING = "closing"


class RiskLevel(str, Enum):
    """Risk levels for audit/security metadata."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BusinessProfile:
    """
    Business profile used for greeting and routing.

    This can later come from workspace settings/config.py/dashboard.
    """

    business_name: str = "Digital Promotix"
    assistant_name: str = "William"
    greeting_style: str = "professional"
    timezone: str = "UTC"
    business_hours_note: str = "Our team will respond as soon as possible."
    default_language: str = "en"
    consent_notice_enabled: bool = True
    consent_notice: str = (
        "This call may be processed by an AI assistant to help route your request accurately."
    )
    emergency_disclaimer: str = (
        "If this is a medical, fire, safety, or life-threatening emergency, please hang up and call your local emergency number immediately."
    )
    custom_greeting: Optional[str] = None
    custom_closing: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IntakeField:
    """Caller intake field definition."""

    key: str
    question: str
    required: bool = True
    validator: Optional[str] = None
    redact_in_logs: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CallerIntake:
    """Collected caller intake details."""

    caller_name: Optional[str] = None
    phone_number: Optional[str] = None
    email: Optional[str] = None
    company: Optional[str] = None
    reason: Optional[str] = None
    service_interest: Optional[str] = None
    urgency: Optional[str] = None
    budget: Optional[str] = None
    preferred_callback_time: Optional[str] = None
    existing_customer: Optional[bool] = None
    raw_transcript: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RoutingDestination:
    """
    Routing destination.

    destination_ref should be an internal symbolic reference, not a hardcoded secret
    or private number. Real phone/email destinations should be resolved by a protected
    Contact Router or Call Agent config after security/permission checks.
    """

    route_name: str
    route_type: Union[str, CallRouteType]
    destination_ref: Optional[str] = None
    department: Optional[str] = None
    allowed_intents: List[str] = field(default_factory=list)
    priority: int = 100
    business_hours_only: bool = False
    requires_security_approval: bool = False
    script_key: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReceptionistScript:
    """Reusable script template."""

    key: str
    text: str
    intent: Optional[str] = None
    step: Optional[str] = None
    variables: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReceptionistDecision:
    """Final receptionist decision."""

    intent: str
    priority: str
    route_type: str
    route_name: str
    script: str
    next_step: str
    collected_intake: Dict[str, Any]
    missing_fields: List[str] = field(default_factory=list)
    confidence: float = 0.0
    reason: str = ""
    requires_security_approval: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Receptionist Mode
# =============================================================================

class ReceptionistMode(BaseAgent):
    """
    Call Agent receptionist mode.

    Master Agent / Agent Router can call:
        - await run(task)

    Public methods:
        - generate_greeting()
        - build_intake_questions()
        - parse_caller_intake()
        - detect_intent()
        - route_caller()
        - generate_script()
        - process_receptionist_turn()

    This class does not perform real transfers or outbound actions. It produces
    safe structured decisions for downstream protected modules:
        - contact_router.py
        - appointment_booker.py
        - voicemail_handler.py
        - call_summarizer.py
        - lead_qualifier.py
    """

    AGENT_NAME = "ReceptionistMode"
    AGENT_TYPE = "call_agent.receptionist_mode"
    VERSION = "1.0.0"

    DEFAULT_INTAKE_FIELDS: List[IntakeField] = [
        IntakeField(
            key="caller_name",
            question="May I have your full name, please?",
            required=True,
            validator="name",
        ),
        IntakeField(
            key="phone_number",
            question="What is the best phone number for our team to reach you?",
            required=True,
            validator="phone",
            redact_in_logs=True,
        ),
        IntakeField(
            key="reason",
            question="How can I help you today?",
            required=True,
            validator="text",
        ),
        IntakeField(
            key="service_interest",
            question="Which service or department is your call about?",
            required=False,
            validator="text",
        ),
        IntakeField(
            key="urgency",
            question="Is this urgent, or is a normal callback okay?",
            required=False,
            validator="text",
        ),
    ]

    DEFAULT_SCRIPTS: Dict[str, ReceptionistScript] = {
        "greeting": ReceptionistScript(
            key="greeting",
            step=ReceptionistStep.GREETING.value,
            text=(
                "Thank you for calling {business_name}. "
                "This is {assistant_name}, the virtual receptionist. "
                "How may I help you today?"
            ),
            variables=["business_name", "assistant_name"],
        ),
        "consent_notice": ReceptionistScript(
            key="consent_notice",
            step=ReceptionistStep.CONSENT_NOTICE.value,
            text="{consent_notice}",
            variables=["consent_notice"],
        ),
        "name_request": ReceptionistScript(
            key="name_request",
            step=ReceptionistStep.CALLER_NAME.value,
            text="May I have your full name, please?",
        ),
        "phone_request": ReceptionistScript(
            key="phone_request",
            step=ReceptionistStep.PHONE_CONFIRMATION.value,
            text="What is the best phone number for our team to reach you?",
        ),
        "phone_confirm": ReceptionistScript(
            key="phone_confirm",
            step=ReceptionistStep.PHONE_CONFIRMATION.value,
            text="Just to confirm, I have your phone number as {phone_number}. Is that correct?",
            variables=["phone_number"],
        ),
        "reason_request": ReceptionistScript(
            key="reason_request",
            step=ReceptionistStep.REASON_FOR_CALL.value,
            text="How can I help you today?",
        ),
        "sales_route": ReceptionistScript(
            key="sales_route",
            intent=CallIntent.SALES.value,
            step=ReceptionistStep.ROUTING.value,
            text=(
                "Thank you. I can route this to our sales team. "
                "Before I do that, may I know what goal you want to achieve with this service?"
            ),
        ),
        "support_route": ReceptionistScript(
            key="support_route",
            intent=CallIntent.SUPPORT.value,
            step=ReceptionistStep.ROUTING.value,
            text=(
                "I understand. I can route this to support. "
                "Please briefly describe the issue so the right person can help."
            ),
        ),
        "billing_route": ReceptionistScript(
            key="billing_route",
            intent=CallIntent.BILLING.value,
            step=ReceptionistStep.ROUTING.value,
            text=(
                "I can help route this to billing. "
                "Please share a short note about the billing question."
            ),
        ),
        "appointment_route": ReceptionistScript(
            key="appointment_route",
            intent=CallIntent.APPOINTMENT.value,
            step=ReceptionistStep.ROUTING.value,
            text=(
                "I can help arrange an appointment. "
                "What day and time usually works best for you?"
            ),
        ),
        "voicemail": ReceptionistScript(
            key="voicemail",
            intent=CallIntent.VOICEMAIL.value,
            step=ReceptionistStep.ROUTING.value,
            text=(
                "Our team is not available to take the call directly right now. "
                "Please leave your name, phone number, and a short message, and we will follow up."
            ),
        ),
        "human_review": ReceptionistScript(
            key="human_review",
            step=ReceptionistStep.ROUTING.value,
            text=(
                "Thank you. I will make sure this is reviewed by the right person. "
                "May I confirm your name and best callback number?"
            ),
        ),
        "closing": ReceptionistScript(
            key="closing",
            step=ReceptionistStep.CLOSING.value,
            text="Thank you for calling {business_name}. Have a great day.",
            variables=["business_name"],
        ),
        "safe_block": ReceptionistScript(
            key="safe_block",
            step=ReceptionistStep.CLOSING.value,
            text=(
                "I am not able to help with that request over this call. "
                "I can take a general message or route you to a human review queue."
            ),
        ),
        "emergency": ReceptionistScript(
            key="emergency",
            intent=CallIntent.EMERGENCY.value,
            step=ReceptionistStep.CLOSING.value,
            text="{emergency_disclaimer}",
            variables=["emergency_disclaimer"],
        ),
    }

    DEFAULT_DESTINATIONS: List[RoutingDestination] = [
        RoutingDestination(
            route_name="sales_priority",
            route_type=CallRouteType.TRANSFER,
            destination_ref="department:sales",
            department="Sales",
            allowed_intents=[CallIntent.SALES.value, CallIntent.NEW_LEAD.value],
            priority=10,
            requires_security_approval=True,
            script_key="sales_route",
        ),
        RoutingDestination(
            route_name="support_queue",
            route_type=CallRouteType.TRANSFER,
            destination_ref="department:support",
            department="Support",
            allowed_intents=[CallIntent.SUPPORT.value, CallIntent.EXISTING_CUSTOMER.value],
            priority=20,
            requires_security_approval=True,
            script_key="support_route",
        ),
        RoutingDestination(
            route_name="billing_queue",
            route_type=CallRouteType.TRANSFER,
            destination_ref="department:billing",
            department="Billing",
            allowed_intents=[CallIntent.BILLING.value],
            priority=30,
            requires_security_approval=True,
            script_key="billing_route",
        ),
        RoutingDestination(
            route_name="appointment_booking",
            route_type=CallRouteType.APPOINTMENT,
            destination_ref="module:appointment_booker",
            department="Scheduling",
            allowed_intents=[CallIntent.APPOINTMENT.value],
            priority=40,
            requires_security_approval=False,
            script_key="appointment_route",
        ),
        RoutingDestination(
            route_name="voicemail",
            route_type=CallRouteType.VOICEMAIL,
            destination_ref="module:voicemail_handler",
            department="Reception",
            allowed_intents=[CallIntent.VOICEMAIL.value],
            priority=90,
            requires_security_approval=False,
            script_key="voicemail",
        ),
        RoutingDestination(
            route_name="human_review",
            route_type=CallRouteType.HUMAN_REVIEW,
            destination_ref="queue:human_review",
            department="Reception",
            allowed_intents=[CallIntent.UNKNOWN.value, CallIntent.GENERAL.value, CallIntent.HUMAN_AGENT.value],
            priority=100,
            requires_security_approval=False,
            script_key="human_review",
        ),
    ]

    INTENT_KEYWORDS: Dict[str, List[str]] = {
        CallIntent.SALES.value: [
            "price",
            "pricing",
            "quote",
            "buy",
            "purchase",
            "new service",
            "website",
            "seo",
            "marketing",
            "ads",
            "automation",
            "interested",
            "package",
            "plan",
        ],
        CallIntent.SUPPORT.value: [
            "support",
            "issue",
            "problem",
            "not working",
            "error",
            "help",
            "fix",
            "broken",
            "technical",
            "login",
            "account issue",
        ],
        CallIntent.BILLING.value: [
            "invoice",
            "bill",
            "billing",
            "payment",
            "refund",
            "charge",
            "receipt",
            "subscription",
            "paid",
        ],
        CallIntent.APPOINTMENT.value: [
            "appointment",
            "schedule",
            "meeting",
            "book",
            "calendar",
            "call back",
            "callback",
            "consultation",
        ],
        CallIntent.COMPLAINT.value: [
            "complaint",
            "angry",
            "unhappy",
            "bad service",
            "cancel",
            "manager",
            "escalate",
        ],
        CallIntent.EMERGENCY.value: [
            "emergency",
            "danger",
            "hurt",
            "medical",
            "fire",
            "police",
            "life threatening",
            "unsafe",
        ],
        CallIntent.EXISTING_CUSTOMER.value: [
            "existing customer",
            "already customer",
            "my account",
            "current client",
            "project",
            "order",
        ],
        CallIntent.PARTNERSHIP.value: [
            "partner",
            "partnership",
            "reseller",
            "affiliate",
            "collaboration",
            "agency partner",
        ],
        CallIntent.HUMAN_AGENT.value: [
            "human",
            "representative",
            "agent",
            "person",
            "operator",
            "talk to someone",
            "speak to someone",
        ],
        CallIntent.VOICEMAIL.value: [
            "leave message",
            "voicemail",
            "message",
            "not available",
        ],
    }

    UNSAFE_REQUEST_PATTERNS: List[str] = [
        r"\bcredit card number\b",
        r"\bpassword\b",
        r"\bone time password\b",
        r"\botp\b",
        r"\bsocial security\b",
        r"\bssn\b",
        r"\bbank login\b",
        r"\bseed phrase\b",
        r"\bprivate key\b",
    ]

    def __init__(
        self,
        business_profile: Optional[Union[BusinessProfile, Mapping[str, Any]]] = None,
        intake_fields: Optional[Sequence[Union[IntakeField, Mapping[str, Any]]]] = None,
        destinations: Optional[Sequence[Union[RoutingDestination, Mapping[str, Any]]]] = None,
        scripts: Optional[Mapping[str, Union[ReceptionistScript, Mapping[str, Any]]]] = None,
        security_agent: Any = None,
        memory_agent: Any = None,
        verification_agent: Any = None,
        logger: Optional[logging.Logger] = None,
        enable_security_checks: bool = True,
        enable_audit_log: bool = True,
        enable_memory_payloads: bool = True,
        enable_verification_payloads: bool = True,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.AGENT_NAME, agent_id=self.AGENT_TYPE, **kwargs)

        self.logger = logger or LOGGER
        self.business_profile = self._normalize_business_profile(business_profile)
        self.intake_fields = self._normalize_intake_fields(intake_fields or self.DEFAULT_INTAKE_FIELDS)
        self.destinations = self._normalize_destinations(destinations or self.DEFAULT_DESTINATIONS)
        self.scripts = self._normalize_scripts(scripts or self.DEFAULT_SCRIPTS)

        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent

        self.enable_security_checks = bool(enable_security_checks)
        self.enable_audit_log = bool(enable_audit_log)
        self.enable_memory_payloads = bool(enable_memory_payloads)
        self.enable_verification_payloads = bool(enable_verification_payloads)

    # =========================================================================
    # Master Agent Entry Point
    # =========================================================================

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Master Agent / Agent Router entry point.

        Supported actions:
            - generate_greeting
            - build_intake_questions
            - parse_caller_intake
            - detect_intent
            - route_caller
            - generate_script
            - process_receptionist_turn
        """

        context_validation = self._validate_task_context(task)
        if not context_validation.get("success"):
            return context_validation

        action = str(task.get("action", "")).strip().lower()
        payload = task.get("payload", {}) or {}
        user_id = str(task.get("user_id"))
        workspace_id = str(task.get("workspace_id"))

        if self._requires_security_check(task):
            approval = self._request_security_approval(task)
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval denied for receptionist task.",
                    error="security_approval_denied",
                    metadata={
                        "action": action,
                        "approval": approval,
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

        try:
            if action == "generate_greeting":
                result = self.generate_greeting(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    business_profile=payload.get("business_profile"),
                    include_consent=bool(payload.get("include_consent", True)),
                    metadata=task.get("metadata", {}),
                )

            elif action == "build_intake_questions":
                result = self.build_intake_questions(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    collected=payload.get("collected", {}),
                    metadata=task.get("metadata", {}),
                )

            elif action == "parse_caller_intake":
                result = self.parse_caller_intake(
                    transcript=payload.get("transcript", ""),
                    existing_intake=payload.get("existing_intake"),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=task.get("metadata", {}),
                )

            elif action == "detect_intent":
                result = self.detect_intent(
                    text=payload.get("text", payload.get("transcript", "")),
                    intake=payload.get("intake"),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=task.get("metadata", {}),
                )

            elif action == "route_caller":
                result = self.route_caller(
                    intake=payload.get("intake", {}),
                    transcript=payload.get("transcript", ""),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=task.get("metadata", {}),
                )

            elif action == "generate_script":
                result = self.generate_script(
                    script_key=payload.get("script_key", "greeting"),
                    variables=payload.get("variables", {}),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=task.get("metadata", {}),
                )

            elif action == "process_receptionist_turn":
                result = self.process_receptionist_turn(
                    transcript=payload.get("transcript", ""),
                    existing_intake=payload.get("existing_intake"),
                    call_state=payload.get("call_state", {}),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    metadata=task.get("metadata", {}),
                )

            else:
                return self._error_result(
                    message=f"Unsupported receptionist action: {action or 'missing'}",
                    error="unsupported_action",
                    metadata={
                        "supported_actions": [
                            "generate_greeting",
                            "build_intake_questions",
                            "parse_caller_intake",
                            "detect_intent",
                            "route_caller",
                            "generate_script",
                            "process_receptionist_turn",
                        ],
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

            self._emit_agent_event(
                event_type="receptionist_mode.task_completed",
                payload={
                    "action": action,
                    "success": result.get("success"),
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )
            return result

        except Exception as exc:
            self.logger.exception("ReceptionistMode.run failed")
            return self._error_result(
                message="Receptionist task failed.",
                error=str(exc),
                metadata={
                    "action": action,
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

    # =========================================================================
    # Public Methods
    # =========================================================================

    def generate_greeting(
        self,
        user_id: str,
        workspace_id: str,
        business_profile: Optional[Union[BusinessProfile, Mapping[str, Any]]] = None,
        include_consent: bool = True,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate a safe business greeting for an inbound caller."""

        try:
            context_result = self._validate_context_values(user_id, workspace_id)
            if not context_result.get("success"):
                return context_result

            profile = self._normalize_business_profile(business_profile) if business_profile else self.business_profile

            if profile.custom_greeting:
                greeting = profile.custom_greeting
            else:
                greeting = self._render_script(
                    self.scripts["greeting"].text,
                    {
                        "business_name": profile.business_name,
                        "assistant_name": profile.assistant_name,
                    },
                )

            consent_text = ""
            if include_consent and profile.consent_notice_enabled:
                consent_text = self._render_script(
                    self.scripts["consent_notice"].text,
                    {"consent_notice": profile.consent_notice},
                )

            full_text = " ".join(part for part in [greeting, consent_text] if part).strip()

            result = self._safe_result(
                message="Business greeting generated successfully.",
                data={
                    "greeting": greeting,
                    "consent_notice": consent_text,
                    "full_text": full_text,
                    "next_step": ReceptionistStep.REASON_FOR_CALL.value,
                    "business_profile": self._serialize_dataclass(profile),
                },
                metadata=self._build_metadata(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    operation="generate_greeting",
                    input_metadata=metadata,
                ),
            )

            self._after_decision_hooks("generate_greeting", user_id, workspace_id, result)
            return result

        except Exception as exc:
            self.logger.exception("generate_greeting failed")
            return self._error_result(
                message="Failed to generate greeting.",
                error=str(exc),
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

    def build_intake_questions(
        self,
        user_id: str,
        workspace_id: str,
        collected: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build remaining intake questions based on already collected details.

        Voice Agent can ask these one by one.
        """

        try:
            context_result = self._validate_context_values(user_id, workspace_id)
            if not context_result.get("success"):
                return context_result

            collected = collected or {}
            questions: List[Dict[str, Any]] = []
            missing_required: List[str] = []

            for field_def in self.intake_fields:
                value = collected.get(field_def.key)
                is_missing = self._is_empty(value)

                if is_missing:
                    question_entry = {
                        "key": field_def.key,
                        "question": field_def.question,
                        "required": field_def.required,
                        "validator": field_def.validator,
                        "metadata": field_def.metadata,
                    }
                    questions.append(question_entry)

                    if field_def.required:
                        missing_required.append(field_def.key)

            result = self._safe_result(
                message="Intake questions built successfully.",
                data={
                    "questions": questions,
                    "missing_required": missing_required,
                    "next_question": questions[0] if questions else None,
                    "intake_complete": len(missing_required) == 0,
                },
                metadata=self._build_metadata(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    operation="build_intake_questions",
                    input_metadata=metadata,
                ),
            )

            self._after_decision_hooks("build_intake_questions", user_id, workspace_id, result)
            return result

        except Exception as exc:
            self.logger.exception("build_intake_questions failed")
            return self._error_result(
                message="Failed to build intake questions.",
                error=str(exc),
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

    def parse_caller_intake(
        self,
        transcript: str,
        existing_intake: Optional[Union[CallerIntake, Mapping[str, Any]]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Parse caller intake details from transcript.

        This is deterministic and import-safe. It does not require an LLM.
        A future Call Transcriber / Lead Qualifier can improve extraction.
        """

        try:
            context_result = self._validate_context_values(user_id, workspace_id)
            if not context_result.get("success"):
                return context_result

            transcript = str(transcript or "").strip()
            intake = self._normalize_caller_intake(existing_intake)
            intake.raw_transcript = transcript or intake.raw_transcript

            if transcript:
                extracted_name = self._extract_name(transcript)
                extracted_phone = self._extract_phone(transcript)
                extracted_email = self._extract_email(transcript)
                extracted_company = self._extract_company(transcript)
                extracted_budget = self._extract_budget(transcript)

                if extracted_name and not intake.caller_name:
                    intake.caller_name = extracted_name
                if extracted_phone and not intake.phone_number:
                    intake.phone_number = extracted_phone
                if extracted_email and not intake.email:
                    intake.email = extracted_email
                if extracted_company and not intake.company:
                    intake.company = extracted_company
                if extracted_budget and not intake.budget:
                    intake.budget = extracted_budget

                if not intake.reason:
                    intake.reason = self._extract_reason(transcript)

                if not intake.service_interest:
                    intake.service_interest = self._extract_service_interest(transcript)

                if not intake.urgency:
                    intake.urgency = self._extract_urgency(transcript)

                if intake.existing_customer is None:
                    intake.existing_customer = self._detect_existing_customer(transcript)

            validation = self._validate_intake(intake)

            result = self._safe_result(
                message="Caller intake parsed successfully.",
                data={
                    "intake": self._serialize_dataclass(intake),
                    "validation": validation,
                    "safe_to_continue": not self._contains_unsafe_request(transcript),
                    "unsafe_request_detected": self._contains_unsafe_request(transcript),
                },
                metadata=self._build_metadata(
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                    operation="parse_caller_intake",
                    input_metadata=metadata,
                ),
            )

            self._after_decision_hooks("parse_caller_intake", str(user_id), str(workspace_id), result)
            return result

        except Exception as exc:
            self.logger.exception("parse_caller_intake failed")
            return self._error_result(
                message="Failed to parse caller intake.",
                error=str(exc),
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

    def detect_intent(
        self,
        text: str,
        intake: Optional[Union[CallerIntake, Mapping[str, Any]]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Detect caller intent from transcript text and intake details."""

        try:
            context_result = self._validate_context_values(user_id, workspace_id)
            if not context_result.get("success"):
                return context_result

            intake_obj = self._normalize_caller_intake(intake)
            combined_text = " ".join(
                str(item or "")
                for item in [
                    text,
                    intake_obj.reason,
                    intake_obj.service_interest,
                    intake_obj.urgency,
                    intake_obj.raw_transcript,
                ]
            ).lower()

            if self._contains_unsafe_request(combined_text):
                intent = CallIntent.HUMAN_AGENT.value
                confidence = 0.95
                matched_keywords = ["unsafe_sensitive_request"]
                priority = CallPriority.HIGH.value
            else:
                intent, confidence, matched_keywords = self._keyword_detect_intent(combined_text)
                priority = self._determine_priority(intent, combined_text, intake_obj)

            result = self._safe_result(
                message="Caller intent detected successfully.",
                data={
                    "intent": intent,
                    "confidence": confidence,
                    "matched_keywords": matched_keywords,
                    "priority": priority,
                    "requires_human_review": confidence < 0.45 or intent == CallIntent.UNKNOWN.value,
                },
                metadata=self._build_metadata(
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                    operation="detect_intent",
                    input_metadata=metadata,
                    risk_level=RiskLevel.MEDIUM.value if priority in {CallPriority.HIGH.value, CallPriority.URGENT.value} else RiskLevel.LOW.value,
                ),
            )

            self._after_decision_hooks("detect_intent", str(user_id), str(workspace_id), result)
            return result

        except Exception as exc:
            self.logger.exception("detect_intent failed")
            return self._error_result(
                message="Failed to detect caller intent.",
                error=str(exc),
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

    def route_caller(
        self,
        intake: Union[CallerIntake, Mapping[str, Any]],
        transcript: str = "",
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Decide caller route without executing the transfer.

        Real transfer/callback/appointment/voicemail execution must happen in
        downstream protected modules after approval where required.
        """

        try:
            context_result = self._validate_context_values(user_id, workspace_id)
            if not context_result.get("success"):
                return context_result

            intake_obj = self._normalize_caller_intake(intake)
            validation = self._validate_intake(intake_obj)
            intent_result = self.detect_intent(
                text=transcript,
                intake=intake_obj,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                metadata=metadata,
            )
            intent_data = intent_result.get("data", {})
            intent = str(intent_data.get("intent", CallIntent.UNKNOWN.value))
            confidence = float(intent_data.get("confidence", 0.0))
            priority = str(intent_data.get("priority", CallPriority.NORMAL.value))

            if self._contains_unsafe_request(transcript):
                destination = RoutingDestination(
                    route_name="safe_block",
                    route_type=CallRouteType.SAFE_BLOCK,
                    destination_ref="queue:human_review",
                    department="Safety",
                    allowed_intents=[CallIntent.HUMAN_AGENT.value],
                    priority=1,
                    requires_security_approval=False,
                    script_key="safe_block",
                )
                reason = "Sensitive or unsafe request detected. Route to safe handling."
            elif validation["missing_required"]:
                destination = RoutingDestination(
                    route_name="intake_required",
                    route_type=CallRouteType.INFO_COLLECT,
                    destination_ref="module:receptionist_mode",
                    department="Reception",
                    allowed_intents=[intent],
                    priority=5,
                    requires_security_approval=False,
                    script_key=self._script_for_missing_field(validation["missing_required"][0]),
                )
                reason = "Required caller intake details are missing."
            elif intent == CallIntent.EMERGENCY.value:
                destination = RoutingDestination(
                    route_name="emergency_notice",
                    route_type=CallRouteType.END_CALL,
                    destination_ref=None,
                    department="Safety",
                    allowed_intents=[CallIntent.EMERGENCY.value],
                    priority=1,
                    requires_security_approval=False,
                    script_key="emergency",
                )
                reason = "Emergency intent detected. Provide emergency disclaimer."
            else:
                destination = self._select_destination(intent)
                reason = f"Matched destination for intent: {intent}."

            script_key = destination.script_key or "human_review"
            script_result = self.generate_script(
                script_key=script_key,
                variables={
                    "business_name": self.business_profile.business_name,
                    "assistant_name": self.business_profile.assistant_name,
                    "phone_number": intake_obj.phone_number or "",
                    "caller_name": intake_obj.caller_name or "",
                    "emergency_disclaimer": self.business_profile.emergency_disclaimer,
                    "consent_notice": self.business_profile.consent_notice,
                },
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                metadata=metadata,
            )
            script_text = str((script_result.get("data") or {}).get("script", ""))

            decision = ReceptionistDecision(
                intent=intent,
                priority=priority,
                route_type=str(destination.route_type.value if isinstance(destination.route_type, CallRouteType) else destination.route_type),
                route_name=destination.route_name,
                script=script_text,
                next_step=self._next_step_for_route(destination),
                collected_intake=self._serialize_dataclass(intake_obj),
                missing_fields=list(validation["missing_required"]),
                confidence=confidence,
                reason=reason,
                requires_security_approval=bool(destination.requires_security_approval),
                metadata={
                    "destination": self._serialize_dataclass(destination),
                    "intake_validation": validation,
                },
            )

            result = self._safe_result(
                message="Caller routing decision prepared successfully.",
                data={
                    "decision": self._serialize_dataclass(decision),
                    "execute_action": False,
                    "execution_note": (
                        "No real transfer/callback/appointment/voicemail action was executed. "
                        "Send this decision to protected downstream Call Agent modules."
                    ),
                },
                metadata=self._build_metadata(
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                    operation="route_caller",
                    input_metadata=metadata,
                    risk_level=RiskLevel.MEDIUM.value if decision.requires_security_approval else RiskLevel.LOW.value,
                ),
            )

            self._after_decision_hooks("route_caller", str(user_id), str(workspace_id), result)
            return result

        except Exception as exc:
            self.logger.exception("route_caller failed")
            return self._error_result(
                message="Failed to route caller.",
                error=str(exc),
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

    def generate_script(
        self,
        script_key: str,
        variables: Optional[Mapping[str, Any]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate a receptionist script by key."""

        try:
            context_result = self._validate_context_values(user_id, workspace_id)
            if not context_result.get("success"):
                return context_result

            script_key = str(script_key or "greeting").strip()
            script = self.scripts.get(script_key)
            if not script:
                return self._error_result(
                    message=f"Script not found: {script_key}",
                    error="script_not_found",
                    metadata={
                        "script_key": script_key,
                        "available_scripts": sorted(self.scripts.keys()),
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                )

            default_vars = {
                "business_name": self.business_profile.business_name,
                "assistant_name": self.business_profile.assistant_name,
                "consent_notice": self.business_profile.consent_notice,
                "emergency_disclaimer": self.business_profile.emergency_disclaimer,
            }
            merged_vars = {**default_vars, **dict(variables or {})}
            rendered = self._render_script(script.text, merged_vars)

            result = self._safe_result(
                message="Receptionist script generated successfully.",
                data={
                    "script_key": script.key,
                    "script": rendered,
                    "step": script.step,
                    "intent": script.intent,
                    "variables_used": list(merged_vars.keys()),
                },
                metadata=self._build_metadata(
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                    operation="generate_script",
                    input_metadata=metadata,
                ),
            )

            self._after_decision_hooks("generate_script", str(user_id), str(workspace_id), result)
            return result

        except Exception as exc:
            self.logger.exception("generate_script failed")
            return self._error_result(
                message="Failed to generate script.",
                error=str(exc),
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

    def process_receptionist_turn(
        self,
        transcript: str,
        existing_intake: Optional[Union[CallerIntake, Mapping[str, Any]]] = None,
        call_state: Optional[Mapping[str, Any]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Process one receptionist conversation turn.

        This is the main method Voice Agent can call after each transcribed user turn.
        """

        try:
            context_result = self._validate_context_values(user_id, workspace_id)
            if not context_result.get("success"):
                return context_result

            call_state = dict(call_state or {})
            parse_result = self.parse_caller_intake(
                transcript=transcript,
                existing_intake=existing_intake,
                user_id=str(user_id),
                workspace_id=str(workspace_id),
                metadata=metadata,
            )
            if not parse_result.get("success"):
                return parse_result

            intake_data = (parse_result.get("data") or {}).get("intake", {})
            validation = (parse_result.get("data") or {}).get("validation", {})
            unsafe_detected = bool((parse_result.get("data") or {}).get("unsafe_request_detected", False))

            if unsafe_detected:
                route_result = self.route_caller(
                    intake=intake_data,
                    transcript=transcript,
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                    metadata=metadata,
                )
                result_data = {
                    "turn_type": "safe_block",
                    "intake": intake_data,
                    "validation": validation,
                    "routing": route_result.get("data", {}),
                    "next_prompt": ((route_result.get("data", {}).get("decision") or {}).get("script")),
                    "call_state": {
                        **call_state,
                        "last_step": ReceptionistStep.ROUTING.value,
                        "unsafe_request_detected": True,
                    },
                }
            elif validation.get("missing_required"):
                missing_field = validation["missing_required"][0]
                script_key = self._script_for_missing_field(missing_field)
                script_result = self.generate_script(
                    script_key=script_key,
                    variables=intake_data,
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                    metadata=metadata,
                )
                result_data = {
                    "turn_type": "intake_continue",
                    "intake": intake_data,
                    "validation": validation,
                    "routing": None,
                    "next_prompt": (script_result.get("data") or {}).get("script"),
                    "next_field": missing_field,
                    "call_state": {
                        **call_state,
                        "last_step": ReceptionistStep.INTAKE_DETAILS.value,
                        "awaiting_field": missing_field,
                    },
                }
            else:
                route_result = self.route_caller(
                    intake=intake_data,
                    transcript=transcript,
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                    metadata=metadata,
                )
                decision = (route_result.get("data") or {}).get("decision", {})
                result_data = {
                    "turn_type": "routing_ready",
                    "intake": intake_data,
                    "validation": validation,
                    "routing": route_result.get("data", {}),
                    "next_prompt": decision.get("script"),
                    "call_state": {
                        **call_state,
                        "last_step": ReceptionistStep.ROUTING.value,
                        "route_name": decision.get("route_name"),
                        "route_type": decision.get("route_type"),
                    },
                }

            result = self._safe_result(
                message="Receptionist turn processed successfully.",
                data=result_data,
                metadata=self._build_metadata(
                    user_id=str(user_id),
                    workspace_id=str(workspace_id),
                    operation="process_receptionist_turn",
                    input_metadata=metadata,
                    risk_level=RiskLevel.MEDIUM.value if unsafe_detected else RiskLevel.LOW.value,
                ),
            )

            self._after_decision_hooks("process_receptionist_turn", str(user_id), str(workspace_id), result)
            return result

        except Exception as exc:
            self.logger.exception("process_receptionist_turn failed")
            return self._error_result(
                message="Failed to process receptionist turn.",
                error=str(exc),
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

    # =========================================================================
    # Intent / Routing Helpers
    # =========================================================================

    def _keyword_detect_intent(self, text: str) -> Tuple[str, float, List[str]]:
        """Simple deterministic keyword intent detection."""

        text = str(text or "").lower()
        best_intent = CallIntent.UNKNOWN.value
        best_score = 0
        best_matches: List[str] = []

        for intent, keywords in self.INTENT_KEYWORDS.items():
            matches = [keyword for keyword in keywords if keyword in text]
            score = len(matches)
            if score > best_score:
                best_score = score
                best_intent = intent
                best_matches = matches

        if best_score == 0:
            return CallIntent.UNKNOWN.value, 0.2, []

        confidence = min(0.95, 0.35 + (best_score * 0.15))
        return best_intent, confidence, best_matches

    def _determine_priority(self, intent: str, text: str, intake: CallerIntake) -> str:
        """Determine call priority."""

        urgent_words = ["urgent", "as soon as possible", "asap", "immediately", "today", "right now"]
        high_words = ["complaint", "manager", "cancel", "refund", "not working", "deadline"]

        if intent == CallIntent.EMERGENCY.value:
            return CallPriority.URGENT.value

        if any(word in text for word in urgent_words):
            return CallPriority.HIGH.value

        if any(word in text for word in high_words):
            return CallPriority.HIGH.value

        if intake.urgency and any(word in intake.urgency.lower() for word in urgent_words):
            return CallPriority.HIGH.value

        if intent in {CallIntent.SALES.value, CallIntent.NEW_LEAD.value, CallIntent.HUMAN_AGENT.value}:
            return CallPriority.NORMAL.value

        return CallPriority.NORMAL.value

    def _select_destination(self, intent: str) -> RoutingDestination:
        """Select best routing destination for intent."""

        candidates = [
            destination
            for destination in self.destinations
            if intent in destination.allowed_intents
        ]

        if not candidates:
            candidates = [
                destination
                for destination in self.destinations
                if CallIntent.GENERAL.value in destination.allowed_intents
                or CallIntent.UNKNOWN.value in destination.allowed_intents
            ]

        if not candidates:
            return RoutingDestination(
                route_name="human_review",
                route_type=CallRouteType.HUMAN_REVIEW,
                destination_ref="queue:human_review",
                department="Reception",
                allowed_intents=[CallIntent.UNKNOWN.value],
                priority=100,
                requires_security_approval=False,
                script_key="human_review",
            )

        candidates.sort(key=lambda item: int(item.priority))
        return candidates[0]

    def _next_step_for_route(self, destination: RoutingDestination) -> str:
        """Map destination to next step."""

        route_type = str(destination.route_type.value if isinstance(destination.route_type, CallRouteType) else destination.route_type)

        if route_type == CallRouteType.INFO_COLLECT.value:
            return ReceptionistStep.INTAKE_DETAILS.value
        if route_type in {CallRouteType.TRANSFER.value, CallRouteType.APPOINTMENT.value, CallRouteType.VOICEMAIL.value}:
            return ReceptionistStep.ROUTING.value
        if route_type == CallRouteType.END_CALL.value:
            return ReceptionistStep.CLOSING.value
        return ReceptionistStep.ROUTING.value

    def _script_for_missing_field(self, field_key: str) -> str:
        """Return script key for missing intake field."""

        mapping = {
            "caller_name": "name_request",
            "phone_number": "phone_request",
            "reason": "reason_request",
        }
        return mapping.get(field_key, "human_review")

    # =========================================================================
    # Parsing / Validation Helpers
    # =========================================================================

    def _extract_name(self, text: str) -> Optional[str]:
        """Extract likely caller name."""

        patterns = [
            r"\bmy name is\s+([A-Za-z][A-Za-z\s.'-]{1,60})",
            r"\bthis is\s+([A-Za-z][A-Za-z\s.'-]{1,60})",
            r"\bi am\s+([A-Za-z][A-Za-z\s.'-]{1,60})",
            r"\bi'm\s+([A-Za-z][A-Za-z\s.'-]{1,60})",
        ]

        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                name = self._clean_extracted_phrase(match.group(1))
                if 2 <= len(name) <= 80:
                    return name

        return None

    def _extract_phone(self, text: str) -> Optional[str]:
        """Extract likely phone number."""

        matches = re.findall(r"(?:\+?\d[\d\s().-]{7,}\d)", text)
        for match in matches:
            digits = re.sub(r"\D+", "", match)
            if 8 <= len(digits) <= 15:
                return match.strip()
        return None

    def _extract_email(self, text: str) -> Optional[str]:
        """Extract email address."""

        match = re.search(r"[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}", text, flags=re.IGNORECASE)
        return match.group(0).lower() if match else None

    def _extract_company(self, text: str) -> Optional[str]:
        """Extract company name from simple patterns."""

        patterns = [
            r"\bcompany is\s+([A-Za-z0-9&.,'\-\s]{2,80})",
            r"\bfrom\s+([A-Za-z0-9&.,'\-\s]{2,80})\s+(?:company|business)",
            r"\bmy business is\s+([A-Za-z0-9&.,'\-\s]{2,80})",
        ]

        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                return self._clean_extracted_phrase(match.group(1))
        return None

    def _extract_budget(self, text: str) -> Optional[str]:
        """Extract budget-like phrase."""

        patterns = [
            r"\bbudget(?: is| around| about)?\s*[:\-]?\s*(\$?\d[\d,]*(?:\.\d{1,2})?)",
            r"\b(\$?\d[\d,]*(?:\.\d{1,2})?)\s*(?:budget|for this|for the project)",
        ]

        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _extract_reason(self, text: str) -> Optional[str]:
        """Extract short reason from transcript."""

        cleaned = " ".join(str(text or "").split())
        if not cleaned:
            return None

        if len(cleaned) <= 240:
            return cleaned

        return cleaned[:237] + "..."

    def _extract_service_interest(self, text: str) -> Optional[str]:
        """Extract likely service interest."""

        service_keywords = [
            "website",
            "web design",
            "web development",
            "seo",
            "google ads",
            "meta ads",
            "facebook ads",
            "automation",
            "ai agent",
            "chatbot",
            "voice agent",
            "branding",
            "logo",
            "social media",
            "ppc",
        ]

        lower_text = text.lower()
        matches = [keyword for keyword in service_keywords if keyword in lower_text]
        return ", ".join(matches) if matches else None

    def _extract_urgency(self, text: str) -> Optional[str]:
        """Extract urgency label."""

        lower_text = text.lower()
        if any(word in lower_text for word in ["urgent", "asap", "immediately", "right now", "today"]):
            return "urgent"
        if any(word in lower_text for word in ["tomorrow", "this week", "soon"]):
            return "soon"
        if any(word in lower_text for word in ["not urgent", "no rush", "normal"]):
            return "normal"
        return None

    def _detect_existing_customer(self, text: str) -> Optional[bool]:
        """Detect if caller says they are an existing customer."""

        lower_text = text.lower()
        if any(phrase in lower_text for phrase in ["existing customer", "current customer", "already a customer", "my account", "my project"]):
            return True
        if any(phrase in lower_text for phrase in ["new customer", "not a customer", "first time", "new lead"]):
            return False
        return None

    def _validate_intake(self, intake: CallerIntake) -> Dict[str, Any]:
        """Validate caller intake fields."""

        intake_dict = self._serialize_dataclass(intake)
        missing_required: List[str] = []
        invalid_fields: List[Dict[str, Any]] = []

        for field_def in self.intake_fields:
            value = intake_dict.get(field_def.key)

            if field_def.required and self._is_empty(value):
                missing_required.append(field_def.key)
                continue

            if not self._is_empty(value) and field_def.validator:
                valid, reason = self._validate_field_value(field_def.validator, str(value))
                if not valid:
                    invalid_fields.append({
                        "field": field_def.key,
                        "reason": reason,
                    })

        return {
            "is_valid": not missing_required and not invalid_fields,
            "missing_required": missing_required,
            "invalid_fields": invalid_fields,
        }

    def _validate_field_value(self, validator: str, value: str) -> Tuple[bool, str]:
        """Validate intake field value."""

        validator = validator.lower()

        if validator == "name":
            cleaned = value.strip()
            if len(cleaned) < 2:
                return False, "Name is too short."
            if len(cleaned) > 100:
                return False, "Name is too long."
            return True, "valid"

        if validator == "phone":
            digits = re.sub(r"\D+", "", value)
            if 8 <= len(digits) <= 15:
                return True, "valid"
            return False, "Phone number should contain 8 to 15 digits."

        if validator == "email":
            if re.match(r"^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}$", value, flags=re.IGNORECASE):
                return True, "valid"
            return False, "Invalid email format."

        if validator == "text":
            if len(value.strip()) >= 2:
                return True, "valid"
            return False, "Text is too short."

        return True, "valid"

    def _contains_unsafe_request(self, text: str) -> bool:
        """Detect sensitive data request patterns."""

        text = str(text or "").lower()
        return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in self.UNSAFE_REQUEST_PATTERNS)

    def _clean_extracted_phrase(self, value: str) -> str:
        """Clean extracted phrase."""

        value = re.split(r"\b(?:and|because|calling|about|for|my phone|phone|email)\b", value, maxsplit=1, flags=re.IGNORECASE)[0]
        value = re.sub(r"[^A-Za-z0-9&.,'\-\s]", "", value)
        value = " ".join(value.split())
        return value.strip(" .,-")

    # =========================================================================
    # Normalizers
    # =========================================================================

    def _normalize_business_profile(
        self,
        profile: Optional[Union[BusinessProfile, Mapping[str, Any]]],
    ) -> BusinessProfile:
        """Normalize business profile."""

        if profile is None:
            return BusinessProfile()

        if isinstance(profile, BusinessProfile):
            return profile

        if not isinstance(profile, Mapping):
            raise TypeError("business_profile must be BusinessProfile or mapping.")

        return BusinessProfile(
            business_name=str(profile.get("business_name", "Digital Promotix")),
            assistant_name=str(profile.get("assistant_name", "William")),
            greeting_style=str(profile.get("greeting_style", "professional")),
            timezone=str(profile.get("timezone", "UTC")),
            business_hours_note=str(profile.get("business_hours_note", "Our team will respond as soon as possible.")),
            default_language=str(profile.get("default_language", "en")),
            consent_notice_enabled=bool(profile.get("consent_notice_enabled", True)),
            consent_notice=str(
                profile.get(
                    "consent_notice",
                    "This call may be processed by an AI assistant to help route your request accurately.",
                )
            ),
            emergency_disclaimer=str(
                profile.get(
                    "emergency_disclaimer",
                    "If this is a medical, fire, safety, or life-threatening emergency, please hang up and call your local emergency number immediately.",
                )
            ),
            custom_greeting=profile.get("custom_greeting"),
            custom_closing=profile.get("custom_closing"),
            metadata=dict(profile.get("metadata", {}) or {}),
        )

    def _normalize_intake_fields(
        self,
        fields: Sequence[Union[IntakeField, Mapping[str, Any]]],
    ) -> List[IntakeField]:
        """Normalize intake fields."""

        normalized: List[IntakeField] = []

        for item in fields:
            if isinstance(item, IntakeField):
                normalized.append(item)
            elif isinstance(item, Mapping):
                key = str(item.get("key", "")).strip()
                question = str(item.get("question", "")).strip()
                if not key or not question:
                    continue
                normalized.append(
                    IntakeField(
                        key=key,
                        question=question,
                        required=bool(item.get("required", True)),
                        validator=item.get("validator"),
                        redact_in_logs=bool(item.get("redact_in_logs", False)),
                        metadata=dict(item.get("metadata", {}) or {}),
                    )
                )
            else:
                raise TypeError("intake field must be IntakeField or mapping.")

        return normalized

    def _normalize_destinations(
        self,
        destinations: Sequence[Union[RoutingDestination, Mapping[str, Any]]],
    ) -> List[RoutingDestination]:
        """Normalize routing destinations."""

        normalized: List[RoutingDestination] = []

        for item in destinations:
            if isinstance(item, RoutingDestination):
                normalized.append(item)
            elif isinstance(item, Mapping):
                route_name = str(item.get("route_name", "")).strip()
                if not route_name:
                    continue
                normalized.append(
                    RoutingDestination(
                        route_name=route_name,
                        route_type=item.get("route_type", CallRouteType.HUMAN_REVIEW.value),
                        destination_ref=item.get("destination_ref"),
                        department=item.get("department"),
                        allowed_intents=list(item.get("allowed_intents", []) or []),
                        priority=int(item.get("priority", 100)),
                        business_hours_only=bool(item.get("business_hours_only", False)),
                        requires_security_approval=bool(item.get("requires_security_approval", False)),
                        script_key=item.get("script_key"),
                        metadata=dict(item.get("metadata", {}) or {}),
                    )
                )
            else:
                raise TypeError("destination must be RoutingDestination or mapping.")

        return normalized

    def _normalize_scripts(
        self,
        scripts: Mapping[str, Union[ReceptionistScript, Mapping[str, Any]]],
    ) -> Dict[str, ReceptionistScript]:
        """Normalize script templates."""

        normalized: Dict[str, ReceptionistScript] = {}

        for key, item in scripts.items():
            if isinstance(item, ReceptionistScript):
                normalized[str(key)] = item
            elif isinstance(item, Mapping):
                script_key = str(item.get("key", key))
                normalized[str(key)] = ReceptionistScript(
                    key=script_key,
                    text=str(item.get("text", "")),
                    intent=item.get("intent"),
                    step=item.get("step"),
                    variables=list(item.get("variables", []) or []),
                    metadata=dict(item.get("metadata", {}) or {}),
                )
            else:
                raise TypeError("script must be ReceptionistScript or mapping.")

        return normalized

    def _normalize_caller_intake(
        self,
        intake: Optional[Union[CallerIntake, Mapping[str, Any]]],
    ) -> CallerIntake:
        """Normalize caller intake."""

        if intake is None:
            return CallerIntake()

        if isinstance(intake, CallerIntake):
            return copy.deepcopy(intake)

        if not isinstance(intake, Mapping):
            raise TypeError("intake must be CallerIntake or mapping.")

        return CallerIntake(
            caller_name=intake.get("caller_name"),
            phone_number=intake.get("phone_number"),
            email=intake.get("email"),
            company=intake.get("company"),
            reason=intake.get("reason"),
            service_interest=intake.get("service_interest"),
            urgency=intake.get("urgency"),
            budget=intake.get("budget"),
            preferred_callback_time=intake.get("preferred_callback_time"),
            existing_customer=intake.get("existing_customer"),
            raw_transcript=intake.get("raw_transcript"),
            extra=dict(intake.get("extra", {}) or {}),
        )

    # =========================================================================
    # Compatibility Hooks
    # =========================================================================

    def _validate_task_context(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate task context.

        Every user/workspace execution requires user_id and workspace_id to prevent
        cross-tenant data mixing.
        """

        if not isinstance(task, Mapping):
            return self._error_result(
                message="Task must be a mapping/dict.",
                error="invalid_task",
            )

        return self._validate_context_values(task.get("user_id"), task.get("workspace_id"))

    def _validate_context_values(
        self,
        user_id: Optional[Any],
        workspace_id: Optional[Any],
    ) -> Dict[str, Any]:
        """Validate SaaS context values."""

        if user_id is None or str(user_id).strip() == "":
            return self._error_result(
                message="user_id is required for Call Agent receptionist execution.",
                error="missing_user_id",
            )

        if workspace_id is None or str(workspace_id).strip() == "":
            return self._error_result(
                message="workspace_id is required for Call Agent receptionist execution.",
                error="missing_workspace_id",
                metadata={"user_id": str(user_id)},
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": str(user_id),
                "workspace_id": str(workspace_id),
            },
        )

    def _requires_security_check(self, task: Mapping[str, Any]) -> bool:
        """
        Decide if Security Agent approval is required.

        Real transfer/callback/external actions are sensitive, even though this
        module itself only prepares decisions.
        """

        if not self.enable_security_checks:
            return False

        if bool(task.get("requires_security_check", False)):
            return True

        action = str(task.get("action", "")).lower()
        payload = task.get("payload", {}) or {}
        route_type = str(payload.get("route_type", "")).lower()
        downstream_action = str(task.get("downstream_action", "")).lower()
        risk_level = str(task.get("risk_level", "")).lower()

        if risk_level in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}:
            return True

        sensitive_actions = {"route_caller"}
        sensitive_route_types = {
            CallRouteType.TRANSFER.value,
            CallRouteType.CALLBACK.value,
            CallRouteType.APPOINTMENT.value,
        }
        sensitive_downstream_keywords = {"transfer", "call", "send", "book", "calendar", "external"}

        return (
            action in sensitive_actions
            or route_type in sensitive_route_types
            or any(keyword in downstream_action for keyword in sensitive_downstream_keywords)
        )

    def _request_security_approval(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Request Security Agent approval if available.

        Fallback policy:
            - Low/medium risk decision preparation is allowed.
            - High/critical real-action requests are denied unless preapproved.
        """

        approval_request = {
            "request_id": self._new_id("sec"),
            "agent": self.AGENT_TYPE,
            "action": task.get("action"),
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "risk_level": task.get("risk_level", RiskLevel.LOW.value),
            "metadata": task.get("metadata", {}),
            "created_at": self._utc_now(),
        }

        if self.security_agent and hasattr(self.security_agent, "approve"):
            try:
                response = self.security_agent.approve(approval_request)
                if isinstance(response, Mapping):
                    return dict(response)
            except Exception as exc:
                self.logger.warning("Security approval call failed: %s", exc)

        if bool(task.get("security_preapproved", False)):
            return {
                "approved": True,
                "mode": "fallback_preapproved",
                "request": approval_request,
            }

        risk = str(task.get("risk_level", RiskLevel.LOW.value)).lower()
        approved = risk not in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}

        return {
            "approved": approved,
            "mode": "fallback_policy",
            "request": approval_request,
            "reason": "Fallback policy denies high/critical risk tasks without explicit approval."
            if not approved
            else "Fallback policy approved non-destructive receptionist task.",
        }

    def _prepare_verification_payload(
        self,
        operation: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Prepare Verification Agent payload."""

        return {
            "verification_id": self._new_id("ver"),
            "source_agent": self.AGENT_TYPE,
            "operation": operation,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "success": bool(result.get("success", False)),
            "message": result.get("message"),
            "data_summary": self._safe_summary(result.get("data", {})),
            "metadata": result.get("metadata", {}),
            "created_at": self._utc_now(),
        }

    def _prepare_memory_payload(
        self,
        operation: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Prepare Memory Agent compatible payload."""

        return {
            "memory_id": self._new_id("mem"),
            "source_agent": self.AGENT_TYPE,
            "memory_type": "call_receptionist_context",
            "operation": operation,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "content": {
                "message": result.get("message"),
                "success": result.get("success", False),
                "data_summary": self._safe_summary(result.get("data", {})),
            },
            "metadata": result.get("metadata", {}),
            "created_at": self._utc_now(),
        }

    def _emit_agent_event(self, event_type: str, payload: Mapping[str, Any]) -> None:
        """Emit dashboard/API/event-bus compatible event."""

        try:
            safe_payload = self._redact_sensitive(copy.deepcopy(dict(payload)))
            self.logger.info("agent_event=%s payload=%s", event_type, safe_payload)
        except Exception:
            self.logger.debug("Failed to emit receptionist event.", exc_info=True)

    def _log_audit_event(
        self,
        operation: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        result: Mapping[str, Any],
    ) -> None:
        """Audit logging hook."""

        if not self.enable_audit_log:
            return

        audit_event = {
            "audit_id": self._new_id("aud"),
            "agent": self.AGENT_TYPE,
            "operation": operation,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "success": result.get("success", False),
            "message": result.get("message"),
            "risk_level": (result.get("metadata") or {}).get("risk_level", RiskLevel.LOW.value),
            "created_at": self._utc_now(),
        }

        try:
            self.logger.info("audit_event=%s", self._redact_sensitive(audit_event))
        except Exception:
            self.logger.debug("Failed to log receptionist audit event.", exc_info=True)

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard success result."""

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
        error: Any,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard error result."""

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": str(error) if error is not None else "unknown_error",
            "metadata": metadata or {},
        }

    # =========================================================================
    # Hook Orchestration / Utility
    # =========================================================================

    def _after_decision_hooks(
        self,
        operation: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
        result: Dict[str, Any],
    ) -> None:
        """Run audit, verification, memory, and event hooks."""

        self._log_audit_event(operation, user_id, workspace_id, result)

        if self.enable_verification_payloads:
            verification_payload = self._prepare_verification_payload(
                operation=operation,
                user_id=user_id,
                workspace_id=workspace_id,
                result=result,
            )
            result.setdefault("metadata", {})["verification_payload"] = verification_payload

            if self.verification_agent and hasattr(self.verification_agent, "receive_payload"):
                try:
                    self.verification_agent.receive_payload(verification_payload)
                except Exception as exc:
                    self.logger.warning("Verification Agent payload delivery failed: %s", exc)

        if self.enable_memory_payloads:
            memory_payload = self._prepare_memory_payload(
                operation=operation,
                user_id=user_id,
                workspace_id=workspace_id,
                result=result,
            )
            result.setdefault("metadata", {})["memory_payload"] = memory_payload

            if self.memory_agent and hasattr(self.memory_agent, "remember"):
                try:
                    self.memory_agent.remember(memory_payload)
                except Exception as exc:
                    self.logger.warning("Memory Agent payload delivery failed: %s", exc)

        self._emit_agent_event(
            event_type=f"receptionist_mode.{operation}",
            payload={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "success": result.get("success"),
                "message": result.get("message"),
            },
        )

    def _build_metadata(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
        operation: str,
        input_metadata: Optional[Dict[str, Any]] = None,
        risk_level: str = RiskLevel.LOW.value,
    ) -> Dict[str, Any]:
        """Build standard metadata."""

        return {
            "agent": self.AGENT_TYPE,
            "agent_name": self.AGENT_NAME,
            "version": self.VERSION,
            "operation": operation,
            "user_id": str(user_id) if user_id is not None else None,
            "workspace_id": str(workspace_id) if workspace_id is not None else None,
            "risk_level": risk_level,
            "request_id": self._new_id("rec"),
            "timestamp": self._utc_now(),
            "input_metadata": input_metadata or {},
        }

    def _render_script(self, template: str, variables: Mapping[str, Any]) -> str:
        """
        Safely render script template.

        Missing variables are replaced with an empty string instead of raising.
        """

        rendered = str(template or "")

        for match in re.findall(r"{([a-zA-Z0-9_]+)}", rendered):
            replacement = str(variables.get(match, ""))
            rendered = rendered.replace("{" + match + "}", replacement)

        return " ".join(rendered.split())

    def _serialize_dataclass(self, value: Any) -> Any:
        """Serialize dataclasses/enums into JSON-safe data."""

        if hasattr(value, "__dataclass_fields__"):
            return self._serialize_dataclass(asdict(value))

        if isinstance(value, Enum):
            return value.value

        if isinstance(value, Mapping):
            return {key: self._serialize_dataclass(val) for key, val in value.items()}

        if isinstance(value, list):
            return [self._serialize_dataclass(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self._serialize_dataclass(item) for item in value)

        return value

    def _safe_summary(self, value: Any, max_length: int = 1200) -> Any:
        """Create a short redacted summary for memory/verification."""

        redacted = self._redact_sensitive(copy.deepcopy(value))
        text = str(redacted)

        if len(text) <= max_length:
            return redacted

        return {
            "summary_truncated": True,
            "preview": text[:max_length],
            "original_length": len(text),
        }

    def _redact_sensitive(self, value: Any) -> Any:
        """Redact sensitive-looking keys and phone values."""

        sensitive_keys = {
            "password",
            "token",
            "secret",
            "api_key",
            "apikey",
            "authorization",
            "cookie",
            "private_key",
            "access_token",
            "refresh_token",
            "phone_number",
            "phone",
            "mobile",
            "otp",
            "ssn",
            "credit_card",
        }

        if isinstance(value, Mapping):
            cleaned: Dict[str, Any] = {}
            for key, val in value.items():
                key_text = str(key).lower()
                if any(sensitive in key_text for sensitive in sensitive_keys):
                    cleaned[key] = "***REDACTED***"
                else:
                    cleaned[key] = self._redact_sensitive(val)
            return cleaned

        if isinstance(value, list):
            return [self._redact_sensitive(item) for item in value]

        if isinstance(value, tuple):
            return tuple(self._redact_sensitive(item) for item in value)

        return value

    def _is_empty(self, value: Any) -> bool:
        """Check empty-like values."""

        if value is None:
            return True

        if isinstance(value, str):
            return value.strip() == ""

        if isinstance(value, (list, tuple, set, dict)):
            return len(value) == 0

        return False

    def _new_id(self, prefix: str) -> str:
        """Create unique ID."""

        return f"{prefix}_{uuid.uuid4().hex}"

    def _utc_now(self) -> str:
        """Return current UTC timestamp."""

        return datetime.now(timezone.utc).isoformat()

    # =========================================================================
    # Registry Metadata
    # =========================================================================

    @classmethod
    def registry_metadata(cls) -> Dict[str, Any]:
        """
        Agent Registry / Agent Loader metadata.

        This can be called without instantiating the class.
        """

        return {
            "agent_name": cls.AGENT_NAME,
            "agent_type": cls.AGENT_TYPE,
            "class_name": cls.__name__,
            "version": cls.VERSION,
            "module": "agents.super_agents.call_agent.receptionist_mode",
            "file_path": "agents/super_agents/call_agent/receptionist_mode.py",
            "safe_to_import": True,
            "requires_user_context": True,
            "requires_workspace_context": True,
            "capabilities": [
                "business_greeting",
                "caller_intake",
                "intent_detection",
                "call_routing_decisions",
                "receptionist_scripts",
                "safe_transfer_preparation",
                "voicemail_preparation",
                "appointment_preparation",
                "memory_agent_payload",
                "verification_agent_payload",
                "audit_event_hook",
                "security_agent_hook",
            ],
        }


__all__ = [
    "ReceptionistMode",
    "BusinessProfile",
    "IntakeField",
    "CallerIntake",
    "RoutingDestination",
    "ReceptionistScript",
    "ReceptionistDecision",
    "CallIntent",
    "CallPriority",
    "CallRouteType",
    "ReceptionistStep",
    "RiskLevel",
]