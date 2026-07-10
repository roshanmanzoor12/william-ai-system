"""
agents/super_agents/call_agent/contact_router.py

William / Jarvis Multi-Agent AI SaaS System
Call Agent - Contact Router

Purpose:
    Routes callers to owner, team members, CRM, support queues, voicemail, or safe
    fallback handling based on caller intent, urgency, business rules, workspace
    configuration, and permissions.

Core responsibilities:
    - Detect call intent from transcript, caller metadata, explicit intent labels,
      receptionist notes, or CRM/context payloads.
    - Route callers safely to the correct destination: owner, sales, support,
      billing, CRM, appointment booking, emergency escalation, voicemail, or
      human callback.
    - Prevent cross-user/workspace data leakage in SaaS environments.
    - Avoid direct real-world transfer/message/call execution unless protected by
      permission and security hooks.
    - Return structured JSON-style results for Master Agent, dashboard, API,
      Verification Agent, and Memory Agent.

Architecture connections:
    - Master Agent / Agent Router:
        Exposes ContactRouter with public methods that accept structured task
        contexts and return structured dict results.

    - Security Agent:
        Real call transfer, SMS/WhatsApp/email notifications, owner escalation,
        CRM writes, or emergency routing can be marked sensitive and routed
        through _request_security_approval() before execution.

    - Memory Agent:
        Routing outcomes and useful caller context are prepared through
        _prepare_memory_payload().

    - Verification Agent:
        Every completed routing decision can produce a verification payload
        through _prepare_verification_payload().

    - Dashboard/API:
        Emits serializable event/audit payloads for live call dashboards,
        routing history, support analytics, and workspace-level reporting.

Import safety:
    This file uses safe optional imports and fallback stubs so it can be imported
    even if the rest of William/Jarvis is still being generated.
"""

from __future__ import annotations

import copy
import dataclasses
import enum
import hashlib
import json
import logging
import re
import threading
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Optional BaseAgent import with fallback
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover

    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        The real project BaseAgent may provide registry, permissions, routing,
        event bus, memory, and audit integrations. This fallback keeps this file
        safe to import during staged development.
        """

        agent_name: str = "base_agent"
        agent_type: str = "generic"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = logging.getLogger(self.__class__.__name__)

        def emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
            self.logger.debug("Fallback emit_event: %s %s", event_type, payload)

        def log_audit(self, payload: Dict[str, Any]) -> None:
            self.logger.info("Fallback audit: %s", payload)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logging.NullHandler()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ContactIntent(str, enum.Enum):
    """Supported caller intents."""

    UNKNOWN = "unknown"
    GENERAL_INQUIRY = "general_inquiry"
    SALES = "sales"
    SUPPORT = "support"
    TECHNICAL_SUPPORT = "technical_support"
    BILLING = "billing"
    EXISTING_CUSTOMER = "existing_customer"
    NEW_LEAD = "new_lead"
    APPOINTMENT = "appointment"
    RESCHEDULE = "reschedule"
    CANCELLATION = "cancellation"
    OWNER_REQUEST = "owner_request"
    TEAM_MEMBER_REQUEST = "team_member_request"
    CRM_LOOKUP = "crm_lookup"
    COMPLAINT = "complaint"
    URGENT = "urgent"
    EMERGENCY = "emergency"
    SPAM_OR_ROBOCALL = "spam_or_robocall"
    VOICEMAIL = "voicemail"
    HUMAN_CALLBACK = "human_callback"


class RouteDestinationType(str, enum.Enum):
    """Destination types supported by the router."""

    OWNER = "owner"
    TEAM_MEMBER = "team_member"
    TEAM_QUEUE = "team_queue"
    CRM = "crm"
    SUPPORT_QUEUE = "support_queue"
    SALES_QUEUE = "sales_queue"
    BILLING_QUEUE = "billing_queue"
    APPOINTMENT_BOOKER = "appointment_booker"
    VOICEMAIL = "voicemail"
    RECEPTIONIST = "receptionist"
    CALLBACK_QUEUE = "callback_queue"
    BLOCKED = "blocked"
    FALLBACK = "fallback"
    EXTERNAL_PROVIDER = "external_provider"


class RouteAction(str, enum.Enum):
    """Action that should happen after a route decision."""

    TRANSFER_CALL = "transfer_call"
    CREATE_CRM_TASK = "create_crm_task"
    CREATE_SUPPORT_TICKET = "create_support_ticket"
    CREATE_LEAD = "create_lead"
    BOOK_APPOINTMENT = "book_appointment"
    TAKE_MESSAGE = "take_message"
    SEND_NOTIFICATION = "send_notification"
    QUEUE_CALLBACK = "queue_callback"
    SEND_TO_VOICEMAIL = "send_to_voicemail"
    ESCALATE_TO_OWNER = "escalate_to_owner"
    BLOCK_CALL = "block_call"
    CONTINUE_RECEPTIONIST = "continue_receptionist"
    NO_ACTION = "no_action"


class RoutePriority(str, enum.Enum):
    """Routing priority."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"
    EMERGENCY = "emergency"


class RoutingStatus(str, enum.Enum):
    """Routing lifecycle status."""

    PENDING = "pending"
    APPROVED = "approved"
    ROUTED = "routed"
    BLOCKED = "blocked"
    NEEDS_SECURITY_APPROVAL = "needs_security_approval"
    NEEDS_MORE_INFO = "needs_more_info"
    FAILED = "failed"
    FALLBACK_USED = "fallback_used"


class SafetyLevel(str, enum.Enum):
    """Safety level for route action."""

    SAFE = "safe"
    CAUTION = "caution"
    SENSITIVE = "sensitive"
    UNSAFE = "unsafe"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class RoutingPolicy:
    """
    Contact routing policy.

    require_security_for_transfers:
        Real call transfer actions must go through Security Agent.

    require_security_for_owner_escalation:
        Owner escalation can reveal business/private contacts, so it is sensitive.

    require_security_for_crm_write:
        CRM writes are sensitive because they change customer records.

    allow_unknown_intent_fallback:
        Unknown intent is allowed to continue to receptionist/fallback.

    block_spam:
        Spam/robocall routing can be blocked.

    max_transcript_chars:
        Used to safely limit transcript analysis and event payload size.
    """

    require_security_for_transfers: bool = True
    require_security_for_owner_escalation: bool = True
    require_security_for_crm_write: bool = True
    allow_unknown_intent_fallback: bool = True
    block_spam: bool = True
    route_emergency_to_owner: bool = True
    default_business_hours_only: bool = False
    max_transcript_chars: int = 8000
    confidence_threshold: float = 0.45
    high_confidence_threshold: float = 0.72
    enable_in_memory_history: bool = True

    def normalized(self) -> "RoutingPolicy":
        """Return normalized safe policy."""
        return RoutingPolicy(
            require_security_for_transfers=bool(self.require_security_for_transfers),
            require_security_for_owner_escalation=bool(self.require_security_for_owner_escalation),
            require_security_for_crm_write=bool(self.require_security_for_crm_write),
            allow_unknown_intent_fallback=bool(self.allow_unknown_intent_fallback),
            block_spam=bool(self.block_spam),
            route_emergency_to_owner=bool(self.route_emergency_to_owner),
            default_business_hours_only=bool(self.default_business_hours_only),
            max_transcript_chars=max(256, int(self.max_transcript_chars)),
            confidence_threshold=max(0.0, min(1.0, float(self.confidence_threshold))),
            high_confidence_threshold=max(0.0, min(1.0, float(self.high_confidence_threshold))),
            enable_in_memory_history=bool(self.enable_in_memory_history),
        )


@dataclasses.dataclass
class ContactEndpoint:
    """
    Routeable contact endpoint.

    The endpoint can represent owner, department, support queue, CRM queue,
    team member, appointment booker, or external provider.
    """

    endpoint_id: str
    name: str
    destination_type: RouteDestinationType
    action: RouteAction
    priority: RoutePriority = RoutePriority.NORMAL
    phone: Optional[str] = None
    email: Optional[str] = None
    queue_name: Optional[str] = None
    crm_pipeline: Optional[str] = None
    team_member_id: Optional[str] = None
    role: Optional[str] = None
    active: bool = True
    business_hours_only: bool = False
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize endpoint."""
        return {
            "endpoint_id": self.endpoint_id,
            "name": self.name,
            "destination_type": self.destination_type.value,
            "action": self.action.value,
            "priority": self.priority.value,
            "phone": self.phone,
            "email": self.email,
            "queue_name": self.queue_name,
            "crm_pipeline": self.crm_pipeline,
            "team_member_id": self.team_member_id,
            "role": self.role,
            "active": self.active,
            "business_hours_only": self.business_hours_only,
            "metadata": self.metadata,
        }


@dataclasses.dataclass
class RouteDecision:
    """Represents a contact routing decision."""

    route_id: str
    user_id: str
    workspace_id: str
    call_id: str
    caller_id: str
    intent: ContactIntent
    confidence: float
    priority: RoutePriority
    destination_type: RouteDestinationType
    action: RouteAction
    status: RoutingStatus
    endpoint: Optional[ContactEndpoint]
    reason: str
    created_at: str
    updated_at: str
    requires_security_approval: bool = False
    safe_to_execute: bool = False
    route_payload: Dict[str, Any] = dataclasses.field(default_factory=dict)
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)
    error: Optional[Union[str, Dict[str, Any]]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize route decision."""
        return {
            "route_id": self.route_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "call_id": self.call_id,
            "caller_id": self.caller_id,
            "intent": self.intent.value,
            "confidence": self.confidence,
            "priority": self.priority.value,
            "destination_type": self.destination_type.value,
            "action": self.action.value,
            "status": self.status.value,
            "endpoint": self.endpoint.to_dict() if self.endpoint else None,
            "reason": self.reason,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "requires_security_approval": self.requires_security_approval,
            "safe_to_execute": self.safe_to_execute,
            "route_payload": self.route_payload,
            "metadata": self.metadata,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Intent keyword model
# ---------------------------------------------------------------------------

INTENT_KEYWORDS: Dict[ContactIntent, Tuple[str, ...]] = {
    ContactIntent.SALES: (
        "price",
        "pricing",
        "quote",
        "proposal",
        "estimate",
        "buy",
        "purchase",
        "package",
        "service",
        "website",
        "seo",
        "ads",
        "marketing",
        "new project",
        "interested",
        "sales",
    ),
    ContactIntent.SUPPORT: (
        "support",
        "help",
        "issue",
        "problem",
        "not working",
        "broken",
        "error",
        "bug",
        "complaint",
        "trouble",
        "fix",
    ),
    ContactIntent.TECHNICAL_SUPPORT: (
        "technical",
        "developer",
        "server",
        "hosting",
        "domain",
        "dns",
        "email not working",
        "website down",
        "login problem",
        "api",
        "integration",
    ),
    ContactIntent.BILLING: (
        "invoice",
        "payment",
        "paid",
        "billing",
        "refund",
        "charge",
        "subscription",
        "receipt",
        "card",
        "accounting",
    ),
    ContactIntent.EXISTING_CUSTOMER: (
        "existing customer",
        "current client",
        "my account",
        "my project",
        "already working",
        "project update",
        "status update",
    ),
    ContactIntent.NEW_LEAD: (
        "new client",
        "new customer",
        "looking for",
        "need a",
        "want a",
        "can you make",
        "can you build",
        "do you provide",
    ),
    ContactIntent.APPOINTMENT: (
        "appointment",
        "meeting",
        "schedule",
        "book",
        "calendar",
        "consultation",
        "call back",
        "available time",
    ),
    ContactIntent.RESCHEDULE: (
        "reschedule",
        "change meeting",
        "move appointment",
        "different time",
        "postpone",
    ),
    ContactIntent.CANCELLATION: (
        "cancel",
        "cancellation",
        "stop service",
        "terminate",
        "no longer need",
    ),
    ContactIntent.OWNER_REQUEST: (
        "owner",
        "founder",
        "ceo",
        "manager",
        "boss",
        "supervisor",
        "speak to the owner",
        "decision maker",
    ),
    ContactIntent.TEAM_MEMBER_REQUEST: (
        "speak with",
        "talk to",
        "connect me to",
        "transfer me to",
        "agent",
        "representative",
        "team member",
    ),
    ContactIntent.CRM_LOOKUP: (
        "case number",
        "ticket number",
        "reference number",
        "lead id",
        "customer id",
        "account number",
    ),
    ContactIntent.COMPLAINT: (
        "complaint",
        "angry",
        "not happy",
        "bad service",
        "disappointed",
        "escalate",
        "urgent complaint",
    ),
    ContactIntent.URGENT: (
        "urgent",
        "as soon as possible",
        "right now",
        "immediately",
        "important",
        "critical",
        "emergency",
    ),
    ContactIntent.EMERGENCY: (
        "emergency",
        "danger",
        "threat",
        "life threatening",
        "police",
        "ambulance",
        "fire",
    ),
    ContactIntent.SPAM_OR_ROBOCALL: (
        "robocall",
        "spam",
        "telemarketing",
        "free money",
        "loan offer",
        "crypto investment",
        "unknown automated",
    ),
    ContactIntent.VOICEMAIL: (
        "leave message",
        "voicemail",
        "record message",
        "message for",
    ),
    ContactIntent.HUMAN_CALLBACK: (
        "call me back",
        "callback",
        "have someone call",
        "human call",
        "specialist call",
    ),
    ContactIntent.GENERAL_INQUIRY: (
        "question",
        "information",
        "details",
        "hours",
        "location",
        "address",
        "available",
        "inquiry",
    ),
}


# ---------------------------------------------------------------------------
# ContactRouter
# ---------------------------------------------------------------------------

class ContactRouter(BaseAgent):
    """
    Routes callers based on intent, workspace policy, and contact endpoints.

    Public methods:
        - detect_intent()
        - build_route_plan()
        - route_contact()
        - execute_route()
        - register_endpoint()
        - unregister_endpoint()
        - list_endpoints()
        - get_routing_history()
        - health_check()
        - get_registry_metadata()

    This class does not directly perform live call transfers, CRM writes, ticket
    creation, or outbound notifications. Those are delegated to executor callables
    only after safety checks and optional Security Agent approval.
    """

    agent_name = "call_contact_router"
    agent_type = "call_agent_helper"
    module_name = "call_agent"
    file_name = "contact_router.py"

    def __init__(
        self,
        policy: Optional[RoutingPolicy] = None,
        endpoints: Optional[Sequence[Union[ContactEndpoint, Mapping[str, Any]]]] = None,
        route_executors: Optional[Mapping[str, Callable[[Dict[str, Any]], Dict[str, Any]]]] = None,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_emitter: Optional[Any] = None,
        crm_client: Optional[Any] = None,
        support_client: Optional[Any] = None,
        clock: Optional[Callable[[], datetime]] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize ContactRouter.

        Args:
            policy: Routing policy.
            endpoints: Optional endpoints for owner/team/support/CRM queues.
            route_executors: Optional mapping action -> executor callable.
            security_client: Optional Security Agent/client integration.
            memory_client: Optional Memory Agent/client integration.
            verification_client: Optional Verification Agent/client integration.
            audit_logger: Optional audit integration.
            event_emitter: Optional event bus/dashboard integration.
            crm_client: Optional CRM connector/client.
            support_client: Optional support/helpdesk connector/client.
            clock: Optional datetime provider for tests.
            **kwargs: Passed to BaseAgent when supported.
        """
        try:
            super().__init__(**kwargs)
        except TypeError:
            super().__init__()

        self.logger = logger_instance or getattr(self, "logger", logging.getLogger(self.__class__.__name__))
        self.policy = (policy or RoutingPolicy()).normalized()
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.crm_client = crm_client
        self.support_client = support_client
        self.clock = clock or (lambda: datetime.now(timezone.utc))

        self._lock = threading.RLock()
        self._endpoints: Dict[str, ContactEndpoint] = {}
        self._routing_history: Dict[str, List[RouteDecision]] = {}
        self._route_executors: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = dict(route_executors or {})

        self._load_default_endpoints()
        for endpoint in endpoints or []:
            self.register_endpoint(endpoint, replace=True)

    # ---------------------------------------------------------------------
    # Structured result helpers
    # ---------------------------------------------------------------------

    def _safe_result(
        self,
        success: bool = True,
        message: str = "OK",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis structured result."""
        return {
            "success": bool(success),
            "message": str(message),
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Union[str, Exception, Dict[str, Any]]] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis structured error result."""
        if isinstance(error, Exception):
            error_payload: Union[str, Dict[str, Any], None] = {
                "type": error.__class__.__name__,
                "message": str(error),
            }
        else:
            error_payload = error

        return {
            "success": False,
            "message": str(message),
            "data": data or {},
            "error": error_payload,
            "metadata": metadata or {},
        }

    # ---------------------------------------------------------------------
    # Context validation and security hooks
    # ---------------------------------------------------------------------

    def _validate_task_context(self, task_context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS-safe routing context.

        Required:
            user_id, workspace_id, call_id

        Recommended:
            caller_id or caller_phone, transcript, caller_name, metadata
        """
        if not isinstance(task_context, Mapping):
            return self._error_result(
                message="Invalid task context.",
                error="task_context must be a mapping/dict.",
                metadata={"hook": "_validate_task_context"},
            )

        required = ("user_id", "workspace_id", "call_id")
        missing = [key for key in required if not str(task_context.get(key, "")).strip()]
        if missing:
            return self._error_result(
                message="Missing required call routing context.",
                error={"missing_fields": missing},
                metadata={"hook": "_validate_task_context"},
            )

        user_id = str(task_context.get("user_id")).strip()
        workspace_id = str(task_context.get("workspace_id")).strip()
        call_id = str(task_context.get("call_id")).strip()

        null_like = {"none", "null", "undefined", "nan"}
        if user_id.lower() in null_like:
            return self._error_result(
                message="Invalid user_id.",
                error="user_id cannot be null-like.",
                metadata={"hook": "_validate_task_context"},
            )

        if workspace_id.lower() in null_like:
            return self._error_result(
                message="Invalid workspace_id.",
                error="workspace_id cannot be null-like.",
                metadata={"hook": "_validate_task_context"},
            )

        if call_id.lower() in null_like:
            return self._error_result(
                message="Invalid call_id.",
                error="call_id cannot be null-like.",
                metadata={"hook": "_validate_task_context"},
            )

        return self._safe_result(
            message="Call routing context is valid.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "call_id": call_id,
                "caller_id": str(
                    task_context.get("caller_id")
                    or task_context.get("caller_phone")
                    or task_context.get("from_number")
                    or "unknown"
                ),
            },
            metadata={"hook": "_validate_task_context"},
        )

    def _requires_security_check(
        self,
        action: Union[str, RouteAction],
        destination_type: Optional[Union[str, RouteDestinationType]] = None,
        task_context: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide whether this route requires Security Agent approval.

        Sensitive:
            - Live call transfer
            - Owner escalation
            - External notification
            - CRM/ticket write
            - Blocking caller
        """
        action_value = self._enum_value(action)
        destination_value = self._enum_value(destination_type)
        task_context = task_context or {}

        if bool(task_context.get("requires_security_check")):
            return True

        safety = self.classify_route_safety(action_value, destination_value)

        if safety == SafetyLevel.UNSAFE:
            return True

        if action_value == RouteAction.TRANSFER_CALL.value and self.policy.require_security_for_transfers:
            return True

        if action_value == RouteAction.ESCALATE_TO_OWNER.value and self.policy.require_security_for_owner_escalation:
            return True

        if action_value in {
            RouteAction.CREATE_CRM_TASK.value,
            RouteAction.CREATE_SUPPORT_TICKET.value,
            RouteAction.CREATE_LEAD.value,
        } and self.policy.require_security_for_crm_write:
            return True

        if action_value == RouteAction.SEND_NOTIFICATION.value:
            return True

        return False

    def _request_security_approval(
        self,
        action: Union[str, RouteAction],
        task_context: Mapping[str, Any],
        route_decision: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If no security client is configured:
            - Safe/caution internal routing can pass.
            - Sensitive route actions are blocked.
        """
        action_value = self._enum_value(action)
        destination_type = None
        if route_decision:
            destination_type = route_decision.get("destination_type")
        safety = self.classify_route_safety(action_value, self._enum_value(destination_type))

        payload = {
            "request_id": self._new_id("security"),
            "source_agent": self.agent_name,
            "source_module": self.module_name,
            "action": action_value,
            "safety_level": safety.value,
            "user_id": str(task_context.get("user_id", "")),
            "workspace_id": str(task_context.get("workspace_id", "")),
            "call_id": str(task_context.get("call_id", "")),
            "route_decision": self._redact_sensitive(copy.deepcopy(dict(route_decision or {}))),
            "task_context_summary": self._safe_call_context_summary(task_context),
            "created_at": self._now_iso(),
        }

        if self.security_client is not None:
            try:
                if hasattr(self.security_client, "approve_call_route"):
                    response = self.security_client.approve_call_route(payload)
                elif hasattr(self.security_client, "request_approval"):
                    response = self.security_client.request_approval(payload)
                elif callable(self.security_client):
                    response = self.security_client(payload)
                else:
                    response = None

                if isinstance(response, Mapping):
                    approved = bool(response.get("approved", response.get("success", False)))
                    return self._safe_result(
                        success=approved,
                        message="Security approval granted." if approved else "Security approval denied.",
                        data={"approved": approved, "response": dict(response)},
                        metadata={"hook": "_request_security_approval", "safety_level": safety.value},
                    )

                if isinstance(response, bool):
                    return self._safe_result(
                        success=response,
                        message="Security approval granted." if response else "Security approval denied.",
                        data={"approved": response},
                        metadata={"hook": "_request_security_approval", "safety_level": safety.value},
                    )

            except Exception as exc:
                self.logger.exception("Security approval request failed.")
                return self._error_result(
                    message="Security approval request failed.",
                    error=exc,
                    metadata={"hook": "_request_security_approval", "safety_level": safety.value},
                )

        if safety == SafetyLevel.SAFE:
            return self._safe_result(
                message="Local security approval granted for safe route.",
                data={"approved": True, "fallback": True},
                metadata={"hook": "_request_security_approval", "safety_level": safety.value},
            )

        if safety == SafetyLevel.CAUTION and action_value in {
            RouteAction.TAKE_MESSAGE.value,
            RouteAction.QUEUE_CALLBACK.value,
            RouteAction.SEND_TO_VOICEMAIL.value,
            RouteAction.CONTINUE_RECEPTIONIST.value,
        }:
            return self._safe_result(
                message="Local security approval granted for caution route.",
                data={"approved": True, "fallback": True},
                metadata={"hook": "_request_security_approval", "safety_level": safety.value},
            )

        return self._error_result(
            message="Route requires Security Agent approval but no security client approved it.",
            error={
                "action": action_value,
                "safety_level": safety.value,
                "code": "security_approval_required",
            },
            metadata={"hook": "_request_security_approval"},
        )

    # ---------------------------------------------------------------------
    # Public intent and routing methods
    # ---------------------------------------------------------------------

    def detect_intent(self, task_context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Detect caller intent from explicit labels, transcript, notes, and metadata.

        This deterministic implementation is import-safe and testable. Later, the
        Master Agent can replace or augment it with an LLM/NLU model while keeping
        the same structured output.
        """
        validation = self._validate_task_context(task_context)
        if not validation["success"]:
            return validation

        explicit_intent = self._extract_explicit_intent(task_context)
        transcript = self._collect_text_for_intent(task_context)

        if explicit_intent:
            intent = explicit_intent
            confidence = 0.95
            evidence = ["explicit_intent"]
        else:
            intent, confidence, evidence = self._keyword_detect_intent(transcript)

        priority = self._detect_priority(intent, transcript, task_context)
        caller_type = self._detect_caller_type(task_context, transcript)

        return self._safe_result(
            message="Caller intent detected.",
            data={
                "intent": intent.value,
                "confidence": round(confidence, 4),
                "priority": priority.value,
                "caller_type": caller_type,
                "evidence": evidence,
                "transcript_excerpt": transcript[:500],
            },
            metadata={
                "agent": self.agent_name,
                "module": self.module_name,
                "created_at": self._now_iso(),
            },
        )

    def build_route_plan(
        self,
        task_context: Mapping[str, Any],
        workspace_config: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build route plan without executing transfer/CRM/ticket side effects.

        Args:
            task_context:
                SaaS-safe call context with user_id, workspace_id, call_id.
            workspace_config:
                Optional workspace-specific routing config. It can include:
                    - owner_endpoint
                    - support_queue_endpoint
                    - sales_queue_endpoint
                    - billing_queue_endpoint
                    - team_endpoints
                    - business_hours
                    - routing_overrides
        """
        validation = self._validate_task_context(task_context)
        if not validation["success"]:
            return validation

        intent_result = self.detect_intent(task_context)
        if not intent_result["success"]:
            return intent_result

        intent = ContactIntent(intent_result["data"]["intent"])
        confidence = float(intent_result["data"]["confidence"])
        priority = RoutePriority(intent_result["data"]["priority"])

        endpoint = self._select_endpoint(intent, priority, task_context, workspace_config or {})
        action = endpoint.action if endpoint else RouteAction.CONTINUE_RECEPTIONIST
        destination_type = endpoint.destination_type if endpoint else RouteDestinationType.FALLBACK

        if intent == ContactIntent.SPAM_OR_ROBOCALL and self.policy.block_spam:
            endpoint = ContactEndpoint(
                endpoint_id="blocked_spam",
                name="Blocked spam route",
                destination_type=RouteDestinationType.BLOCKED,
                action=RouteAction.BLOCK_CALL,
                priority=RoutePriority.LOW,
                active=True,
                metadata={"reason": "spam_or_robocall_detected"},
            )
            action = RouteAction.BLOCK_CALL
            destination_type = RouteDestinationType.BLOCKED

        if intent == ContactIntent.UNKNOWN and not self.policy.allow_unknown_intent_fallback:
            endpoint = ContactEndpoint(
                endpoint_id="unknown_blocked",
                name="Unknown intent blocked",
                destination_type=RouteDestinationType.BLOCKED,
                action=RouteAction.NO_ACTION,
                priority=RoutePriority.NORMAL,
                active=True,
            )
            action = RouteAction.NO_ACTION
            destination_type = RouteDestinationType.BLOCKED

        in_business_hours = self._is_in_business_hours(task_context, workspace_config or {})
        if endpoint and endpoint.business_hours_only and not in_business_hours:
            endpoint = self._get_voicemail_or_callback_endpoint(intent, priority)
            action = endpoint.action
            destination_type = endpoint.destination_type

        requires_security = self._requires_security_check(action, destination_type, task_context)
        safe_to_execute = not requires_security and self.classify_route_safety(action, destination_type) in {
            SafetyLevel.SAFE,
            SafetyLevel.CAUTION,
        }

        status = RoutingStatus.PENDING
        if destination_type == RouteDestinationType.BLOCKED:
            status = RoutingStatus.BLOCKED
        elif requires_security:
            status = RoutingStatus.NEEDS_SECURITY_APPROVAL

        route_id = self._new_id("route")
        now = self._now_iso()

        route_payload = self._build_route_payload(
            task_context=task_context,
            intent=intent,
            confidence=confidence,
            priority=priority,
            endpoint=endpoint,
            workspace_config=workspace_config or {},
        )

        decision = RouteDecision(
            route_id=route_id,
            user_id=str(task_context.get("user_id")),
            workspace_id=str(task_context.get("workspace_id")),
            call_id=str(task_context.get("call_id")),
            caller_id=str(
                task_context.get("caller_id")
                or task_context.get("caller_phone")
                or task_context.get("from_number")
                or "unknown"
            ),
            intent=intent,
            confidence=round(confidence, 4),
            priority=priority,
            destination_type=destination_type,
            action=action,
            status=status,
            endpoint=endpoint,
            reason=self._build_route_reason(intent, confidence, priority, endpoint, requires_security),
            created_at=now,
            updated_at=now,
            requires_security_approval=requires_security,
            safe_to_execute=safe_to_execute,
            route_payload=route_payload,
            metadata={
                "intent_evidence": intent_result["data"].get("evidence", []),
                "caller_type": intent_result["data"].get("caller_type"),
                "in_business_hours": in_business_hours,
                "policy": self.policy_to_dict(),
            },
        )

        self._store_route_decision(decision)
        self._emit_agent_event(
            event_type="call_route_plan_built",
            payload={"route_decision": decision.to_dict()},
        )

        return self._safe_result(
            message="Contact route plan built.",
            data={"route_decision": decision.to_dict()},
            metadata={
                "agent": self.agent_name,
                "module": self.module_name,
                "created_at": now,
            },
        )

    def route_contact(
        self,
        task_context: Mapping[str, Any],
        workspace_config: Optional[Mapping[str, Any]] = None,
        executor: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        execute: bool = False,
    ) -> Dict[str, Any]:
        """
        Build route decision and optionally execute it.

        By default execute=False, so this method is safe for dashboard/API preview.
        """
        plan_result = self.build_route_plan(task_context, workspace_config)
        if not plan_result["success"]:
            return plan_result

        route_decision = plan_result["data"]["route_decision"]

        if not execute:
            verification_payload = self._prepare_verification_payload(
                task_context=task_context,
                route_decision=route_decision,
                execution_result=None,
            )
            memory_payload = self._prepare_memory_payload(
                task_context=task_context,
                route_decision=route_decision,
                execution_result=None,
            )

            self._log_audit_event(
                event_type="call.route.planned",
                task_context=task_context,
                details={
                    "route_decision": route_decision,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
            )

            return self._safe_result(
                message="Contact route decision prepared.",
                data={
                    "route_decision": route_decision,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "executed": False,
                },
                metadata=plan_result.get("metadata", {}),
            )

        return self.execute_route(route_decision, task_context, executor=executor)

    def execute_route(
        self,
        route_decision: Mapping[str, Any],
        task_context: Mapping[str, Any],
        executor: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a route decision through a safe executor.

        This method never directly transfers calls, sends messages, writes CRM, or
        creates support tickets. It delegates to an executor after required
        security checks pass.
        """
        validation = self._validate_task_context(task_context)
        if not validation["success"]:
            return validation

        if not isinstance(route_decision, Mapping):
            return self._error_result(
                message="Invalid route decision.",
                error="route_decision must be a mapping/dict.",
            )

        action = str(route_decision.get("action", RouteAction.NO_ACTION.value))
        destination_type = str(route_decision.get("destination_type", RouteDestinationType.FALLBACK.value))

        if self._requires_security_check(action, destination_type, task_context):
            approval = self._request_security_approval(action, task_context, route_decision)
            if not approval["success"] or not bool(approval.get("data", {}).get("approved")):
                blocked = self._update_route_status_dict(
                    route_decision,
                    status=RoutingStatus.NEEDS_SECURITY_APPROVAL,
                    error=approval.get("error") or {"code": "security_approval_required"},
                )
                self._log_audit_event(
                    event_type="call.route.security_blocked",
                    task_context=task_context,
                    details={"route_decision": blocked, "security_approval": approval},
                )
                return self._error_result(
                    message="Route execution requires Security Agent approval.",
                    error=approval.get("error") or {"code": "security_approval_required"},
                    data={
                        "route_decision": blocked,
                        "security_approval": approval.get("data", {}),
                    },
                    metadata={"status": RoutingStatus.NEEDS_SECURITY_APPROVAL.value},
                )

        if action in {RouteAction.NO_ACTION.value, RouteAction.CONTINUE_RECEPTIONIST.value}:
            routed = self._update_route_status_dict(
                route_decision,
                status=RoutingStatus.ROUTED,
                metadata_extra={"executed_by": "contact_router_noop"},
            )
            return self._complete_route(task_context, routed, execution_result={
                "success": True,
                "message": "No external route action required.",
                "data": {"action": action},
                "error": None,
                "metadata": {},
            })

        if action == RouteAction.BLOCK_CALL.value:
            routed = self._update_route_status_dict(
                route_decision,
                status=RoutingStatus.BLOCKED,
                metadata_extra={"blocked_by": self.agent_name},
            )
            return self._complete_route(task_context, routed, execution_result={
                "success": True,
                "message": "Caller route blocked according to policy.",
                "data": {"action": action},
                "error": None,
                "metadata": {},
            })

        chosen_executor = executor or self._route_executors.get(action)
        if chosen_executor is None:
            chosen_executor = self._infer_builtin_executor(action)

        if chosen_executor is None:
            blocked = self._update_route_status_dict(
                route_decision,
                status=RoutingStatus.FAILED,
                error={"code": "executor_not_configured", "action": action},
            )
            return self._error_result(
                message="No executor configured for route action.",
                error={"action": action},
                data={"route_decision": blocked},
                metadata={"status": RoutingStatus.FAILED.value},
            )

        execution_context = self._build_execution_context(route_decision, task_context)
        started_at = time.monotonic()

        try:
            raw_result = chosen_executor(execution_context)
            if not isinstance(raw_result, Mapping):
                raw_result = {
                    "success": True,
                    "message": "Route executor completed.",
                    "data": {"raw_result": raw_result},
                    "error": None,
                    "metadata": {},
                }

            execution_result = self._normalize_executor_result(raw_result)
            duration_ms = int((time.monotonic() - started_at) * 1000)

            status = RoutingStatus.ROUTED if execution_result["success"] else RoutingStatus.FAILED
            routed = self._update_route_status_dict(
                route_decision,
                status=status,
                error=execution_result.get("error"),
                metadata_extra={"duration_ms": duration_ms},
            )

            if execution_result["success"]:
                return self._complete_route(task_context, routed, execution_result)

            return self._error_result(
                message="Route execution failed.",
                error=execution_result.get("error"),
                data={
                    "route_decision": routed,
                    "execution_result": execution_result,
                },
                metadata={"status": RoutingStatus.FAILED.value, "duration_ms": duration_ms},
            )

        except Exception as exc:
            duration_ms = int((time.monotonic() - started_at) * 1000)
            self.logger.exception("Route executor failed.")
            failed = self._update_route_status_dict(
                route_decision,
                status=RoutingStatus.FAILED,
                error={"type": exc.__class__.__name__, "message": str(exc)},
                metadata_extra={
                    "duration_ms": duration_ms,
                    "traceback": traceback.format_exc(),
                },
            )
            return self._error_result(
                message="Route executor raised an exception.",
                error=exc,
                data={"route_decision": failed},
                metadata={"status": RoutingStatus.FAILED.value, "duration_ms": duration_ms},
            )

    # ---------------------------------------------------------------------
    # Endpoint management
    # ---------------------------------------------------------------------

    def register_endpoint(
        self,
        endpoint: Union[ContactEndpoint, Mapping[str, Any]],
        replace: bool = True,
    ) -> Dict[str, Any]:
        """
        Register owner/team/CRM/support endpoint.

        Endpoint registration is local and import-safe. In production, endpoints
        may come from workspace config, database, CRM connector, or admin dashboard.
        """
        try:
            parsed = self._parse_endpoint(endpoint)
        except Exception as exc:
            return self._error_result(
                message="Invalid endpoint.",
                error=exc,
            )

        if not parsed.endpoint_id:
            return self._error_result(
                message="endpoint_id is required.",
                error="missing_endpoint_id",
            )

        with self._lock:
            if parsed.endpoint_id in self._endpoints and not replace:
                return self._error_result(
                    message="Endpoint already exists.",
                    error={"endpoint_id": parsed.endpoint_id},
                )
            self._endpoints[parsed.endpoint_id] = parsed

        return self._safe_result(
            message="Endpoint registered.",
            data={"endpoint": parsed.to_dict()},
            metadata={"replace": replace},
        )

    def unregister_endpoint(self, endpoint_id: str) -> Dict[str, Any]:
        """Remove a registered endpoint."""
        endpoint_id = str(endpoint_id).strip()
        if not endpoint_id:
            return self._error_result("endpoint_id is required.", error="missing_endpoint_id")

        with self._lock:
            removed = self._endpoints.pop(endpoint_id, None)

        if not removed:
            return self._error_result(
                message="Endpoint not found.",
                error={"endpoint_id": endpoint_id},
            )

        return self._safe_result(
            message="Endpoint unregistered.",
            data={"endpoint": removed.to_dict()},
        )

    def list_endpoints(
        self,
        destination_type: Optional[Union[str, RouteDestinationType]] = None,
        active_only: bool = True,
    ) -> Dict[str, Any]:
        """List route endpoints."""
        destination_value = self._enum_value(destination_type) if destination_type else None

        with self._lock:
            endpoints = []
            for endpoint in self._endpoints.values():
                if active_only and not endpoint.active:
                    continue
                if destination_value and endpoint.destination_type.value != destination_value:
                    continue
                endpoints.append(endpoint.to_dict())

        endpoints.sort(key=lambda item: (item["destination_type"], item["name"]))

        return self._safe_result(
            message="Endpoints retrieved.",
            data={"endpoints": endpoints, "count": len(endpoints)},
            metadata={"active_only": active_only, "destination_type": destination_value},
        )

    def register_route_executor(
        self,
        action: Union[str, RouteAction],
        executor: Callable[[Dict[str, Any]], Dict[str, Any]],
        replace: bool = True,
    ) -> Dict[str, Any]:
        """Register executor for route action."""
        action_value = self._enum_value(action)
        if not action_value:
            return self._error_result("Action is required.", error="missing_action")
        if not callable(executor):
            return self._error_result("Executor must be callable.", error="executor_not_callable")

        with self._lock:
            if action_value in self._route_executors and not replace:
                return self._error_result(
                    message="Route executor already exists.",
                    error={"action": action_value},
                )
            self._route_executors[action_value] = executor

        return self._safe_result(
            message="Route executor registered.",
            data={"action": action_value, "replace": replace},
        )

    # ---------------------------------------------------------------------
    # History / registry / health
    # ---------------------------------------------------------------------

    def get_routing_history(
        self,
        user_id: str,
        workspace_id: str,
        call_id: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Return routing history scoped by user/workspace.

        Never returns another workspace's call route records.
        """
        user_id = str(user_id).strip()
        workspace_id = str(workspace_id).strip()
        if not user_id or not workspace_id:
            return self._error_result(
                message="user_id and workspace_id are required.",
                error="missing_scope",
            )

        records: List[Dict[str, Any]] = []
        with self._lock:
            for history_key, decisions in self._routing_history.items():
                for decision in decisions:
                    if decision.user_id != user_id or decision.workspace_id != workspace_id:
                        continue
                    if call_id and decision.call_id != str(call_id):
                        continue
                    records.append(decision.to_dict())

        records.sort(key=lambda item: item.get("updated_at", ""), reverse=True)
        safe_limit = max(1, min(int(limit), 1000))

        return self._safe_result(
            message="Routing history retrieved.",
            data={
                "records": records[:safe_limit],
                "count": min(len(records), safe_limit),
                "total_matching": len(records),
            },
            metadata={"user_id": user_id, "workspace_id": workspace_id, "call_id": call_id},
        )

    def health_check(self) -> Dict[str, Any]:
        """Return health information for dashboard/API."""
        with self._lock:
            endpoint_count = len(self._endpoints)
            history_count = sum(len(records) for records in self._routing_history.values())
            executor_count = len(self._route_executors)

        return self._safe_result(
            message="ContactRouter is healthy.",
            data={
                "agent": self.agent_name,
                "module": self.module_name,
                "file": self.file_name,
                "endpoint_count": endpoint_count,
                "routing_history_count": history_count,
                "registered_executor_count": executor_count,
                "policy": self.policy_to_dict(),
                "import_safe": True,
            },
            metadata={"checked_at": self._now_iso()},
        )

    def get_registry_metadata(self) -> Dict[str, Any]:
        """Return metadata for Agent Registry / Agent Loader."""
        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "module_name": self.module_name,
            "file_name": self.file_name,
            "class_name": self.__class__.__name__,
            "public_methods": [
                "detect_intent",
                "build_route_plan",
                "route_contact",
                "execute_route",
                "register_endpoint",
                "unregister_endpoint",
                "list_endpoints",
                "register_route_executor",
                "get_routing_history",
                "health_check",
                "get_registry_metadata",
            ],
            "supports_user_workspace_isolation": True,
            "supports_security_approval": True,
            "supports_memory_payload": True,
            "supports_verification_payload": True,
            "supports_dashboard_events": True,
            "safe_to_import": True,
        }

    # ---------------------------------------------------------------------
    # Verification, Memory, Audit, Events
    # ---------------------------------------------------------------------

    def _prepare_verification_payload(
        self,
        task_context: Mapping[str, Any],
        route_decision: Mapping[str, Any],
        execution_result: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can confirm:
            - user/workspace isolation
            - route safety classification
            - security requirement status
            - structured routing output
            - no direct unsafe action occurred inside router
        """
        return {
            "verification_id": self._new_id("verify"),
            "source_agent": self.agent_name,
            "source_module": self.module_name,
            "event": "call_contact_routed",
            "user_id": str(task_context.get("user_id", "")),
            "workspace_id": str(task_context.get("workspace_id", "")),
            "call_id": str(task_context.get("call_id", "")),
            "caller_id": str(
                task_context.get("caller_id")
                or task_context.get("caller_phone")
                or task_context.get("from_number")
                or "unknown"
            ),
            "route_id": str(route_decision.get("route_id", "")),
            "intent": str(route_decision.get("intent", "")),
            "destination_type": str(route_decision.get("destination_type", "")),
            "action": str(route_decision.get("action", "")),
            "status": str(route_decision.get("status", "")),
            "checks": {
                "user_workspace_isolation": True,
                "structured_result": True,
                "security_check_evaluated": True,
                "direct_side_effect_prevented": True,
                "safe_import_compatible": True,
            },
            "route_decision": self._redact_sensitive(copy.deepcopy(dict(route_decision))),
            "execution_result_summary": self._summarize_result(execution_result or {}),
            "created_at": self._now_iso(),
        }

    def _prepare_memory_payload(
        self,
        task_context: Mapping[str, Any],
        route_decision: Mapping[str, Any],
        execution_result: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Useful for future call routing optimization, repeat callers, successful
        route patterns, and workspace-level call analytics.
        """
        return {
            "memory_id": self._new_id("memory"),
            "source_agent": self.agent_name,
            "source_module": self.module_name,
            "memory_type": "call_routing_event",
            "user_id": str(task_context.get("user_id", "")),
            "workspace_id": str(task_context.get("workspace_id", "")),
            "call_id": str(task_context.get("call_id", "")),
            "caller_id": str(
                task_context.get("caller_id")
                or task_context.get("caller_phone")
                or task_context.get("from_number")
                or "unknown"
            ),
            "summary": {
                "intent": route_decision.get("intent"),
                "confidence": route_decision.get("confidence"),
                "priority": route_decision.get("priority"),
                "destination_type": route_decision.get("destination_type"),
                "action": route_decision.get("action"),
                "status": route_decision.get("status"),
                "execution_success": bool((execution_result or {}).get("success", False)),
            },
            "tags": [
                "call_agent",
                "contact_router",
                str(route_decision.get("intent", "unknown")),
                str(route_decision.get("destination_type", "unknown")),
                str(route_decision.get("status", "unknown")),
            ],
            "created_at": self._now_iso(),
            "retention_hint": "medium_term_operational_analytics",
        }

    def _emit_agent_event(self, event_type: str, payload: Mapping[str, Any]) -> None:
        """Emit dashboard/API/agent event without breaking route flow."""
        event = {
            "event_id": self._new_id("event"),
            "event_type": event_type,
            "source_agent": self.agent_name,
            "source_module": self.module_name,
            "payload": self._redact_sensitive(copy.deepcopy(dict(payload))),
            "created_at": self._now_iso(),
        }

        try:
            if self.event_emitter is not None:
                if hasattr(self.event_emitter, "emit"):
                    self.event_emitter.emit(event_type, event)
                elif callable(self.event_emitter):
                    self.event_emitter(event_type, event)
                return

            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_type, event)  # type: ignore[misc]
                except Exception:
                    self.logger.debug("BaseAgent emit_event failed.", exc_info=True)
        except Exception:
            self.logger.debug("Event emission failed.", exc_info=True)

    def _log_audit_event(
        self,
        event_type: str,
        task_context: Mapping[str, Any],
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """Log audit event with user/workspace scope."""
        payload = {
            "audit_id": self._new_id("audit"),
            "event_type": event_type,
            "source_agent": self.agent_name,
            "source_module": self.module_name,
            "user_id": str(task_context.get("user_id", "")),
            "workspace_id": str(task_context.get("workspace_id", "")),
            "call_id": str(task_context.get("call_id", "")),
            "caller_id": str(
                task_context.get("caller_id")
                or task_context.get("caller_phone")
                or task_context.get("from_number")
                or "unknown"
            ),
            "details": self._redact_sensitive(copy.deepcopy(dict(details or {}))),
            "created_at": self._now_iso(),
        }

        try:
            if self.audit_logger is not None:
                if hasattr(self.audit_logger, "log"):
                    self.audit_logger.log(payload)
                elif hasattr(self.audit_logger, "log_audit"):
                    self.audit_logger.log_audit(payload)
                elif callable(self.audit_logger):
                    self.audit_logger(payload)
                return

            if hasattr(super(), "log_audit"):
                try:
                    super().log_audit(payload)  # type: ignore[misc]
                except Exception:
                    self.logger.debug("BaseAgent audit log failed.", exc_info=True)
        except Exception:
            self.logger.debug("Audit logging failed.", exc_info=True)

    def _send_verification_payload(self, payload: Mapping[str, Any]) -> None:
        """Send payload to Verification Agent/client if configured."""
        try:
            if self.verification_client is None:
                return
            if hasattr(self.verification_client, "verify"):
                self.verification_client.verify(dict(payload))
            elif hasattr(self.verification_client, "submit"):
                self.verification_client.submit(dict(payload))
            elif callable(self.verification_client):
                self.verification_client(dict(payload))
        except Exception:
            self.logger.debug("Verification payload send failed.", exc_info=True)

    def _send_memory_payload(self, payload: Mapping[str, Any]) -> None:
        """Send payload to Memory Agent/client if configured."""
        try:
            if self.memory_client is None:
                return
            if hasattr(self.memory_client, "remember"):
                self.memory_client.remember(dict(payload))
            elif hasattr(self.memory_client, "store"):
                self.memory_client.store(dict(payload))
            elif callable(self.memory_client):
                self.memory_client(dict(payload))
        except Exception:
            self.logger.debug("Memory payload send failed.", exc_info=True)

    # ---------------------------------------------------------------------
    # Internal routing helpers
    # ---------------------------------------------------------------------

    def _complete_route(
        self,
        task_context: Mapping[str, Any],
        route_decision: Mapping[str, Any],
        execution_result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Finalize route with verification, memory, audit, and event payloads."""
        verification_payload = self._prepare_verification_payload(
            task_context=task_context,
            route_decision=route_decision,
            execution_result=execution_result,
        )
        memory_payload = self._prepare_memory_payload(
            task_context=task_context,
            route_decision=route_decision,
            execution_result=execution_result,
        )

        self._send_verification_payload(verification_payload)
        self._send_memory_payload(memory_payload)

        self._log_audit_event(
            event_type="call.route.completed",
            task_context=task_context,
            details={
                "route_decision": route_decision,
                "execution_result": execution_result,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
        )

        self._emit_agent_event(
            event_type="call_route_completed",
            payload={
                "route_decision": route_decision,
                "execution_result": execution_result,
                "verification_payload": verification_payload,
            },
        )

        return self._safe_result(
            message="Contact route completed.",
            data={
                "route_decision": dict(route_decision),
                "execution_result": dict(execution_result),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "agent": self.agent_name,
                "module": self.module_name,
                "status": route_decision.get("status"),
            },
        )

    def _select_endpoint(
        self,
        intent: ContactIntent,
        priority: RoutePriority,
        task_context: Mapping[str, Any],
        workspace_config: Mapping[str, Any],
    ) -> Optional[ContactEndpoint]:
        """Select best endpoint based on intent and workspace config."""
        override = self._endpoint_from_workspace_override(intent, workspace_config)
        if override:
            return override

        requested_person = self._extract_requested_person(task_context)
        if requested_person:
            team_endpoint = self._find_team_member_endpoint(requested_person, workspace_config)
            if team_endpoint:
                return team_endpoint

        if intent == ContactIntent.EMERGENCY and self.policy.route_emergency_to_owner:
            return self._get_endpoint_by_type(RouteDestinationType.OWNER)

        if intent in {ContactIntent.OWNER_REQUEST, ContactIntent.COMPLAINT, ContactIntent.URGENT}:
            owner = self._get_endpoint_by_type(RouteDestinationType.OWNER)
            if owner:
                return owner

        if intent in {ContactIntent.SALES, ContactIntent.NEW_LEAD, ContactIntent.GENERAL_INQUIRY}:
            return self._get_endpoint_by_type(RouteDestinationType.SALES_QUEUE) or self._get_endpoint_by_type(RouteDestinationType.CRM)

        if intent in {ContactIntent.SUPPORT, ContactIntent.TECHNICAL_SUPPORT, ContactIntent.EXISTING_CUSTOMER}:
            return self._get_endpoint_by_type(RouteDestinationType.SUPPORT_QUEUE) or self._get_endpoint_by_type(RouteDestinationType.CRM)

        if intent == ContactIntent.BILLING:
            return self._get_endpoint_by_type(RouteDestinationType.BILLING_QUEUE) or self._get_endpoint_by_type(RouteDestinationType.SUPPORT_QUEUE)

        if intent in {ContactIntent.APPOINTMENT, ContactIntent.RESCHEDULE, ContactIntent.CANCELLATION}:
            return self._get_endpoint_by_type(RouteDestinationType.APPOINTMENT_BOOKER)

        if intent == ContactIntent.CRM_LOOKUP:
            return self._get_endpoint_by_type(RouteDestinationType.CRM)

        if intent in {ContactIntent.VOICEMAIL, ContactIntent.HUMAN_CALLBACK}:
            return self._get_voicemail_or_callback_endpoint(intent, priority)

        if intent == ContactIntent.SPAM_OR_ROBOCALL:
            return self._get_endpoint_by_type(RouteDestinationType.BLOCKED)

        return self._get_endpoint_by_type(RouteDestinationType.RECEPTIONIST) or self._get_endpoint_by_type(RouteDestinationType.FALLBACK)

    def _build_route_payload(
        self,
        task_context: Mapping[str, Any],
        intent: ContactIntent,
        confidence: float,
        priority: RoutePriority,
        endpoint: Optional[ContactEndpoint],
        workspace_config: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Build route payload for downstream executor/CRM/support/dashboard."""
        caller_phone = str(task_context.get("caller_phone") or task_context.get("from_number") or "")
        caller_name = str(task_context.get("caller_name") or task_context.get("name") or "").strip()
        transcript = self._collect_text_for_intent(task_context)

        return {
            "user_id": str(task_context.get("user_id", "")),
            "workspace_id": str(task_context.get("workspace_id", "")),
            "call_id": str(task_context.get("call_id", "")),
            "caller": {
                "caller_id": str(task_context.get("caller_id") or caller_phone or "unknown"),
                "caller_name": caller_name,
                "caller_phone": caller_phone,
            },
            "intent": intent.value,
            "confidence": round(confidence, 4),
            "priority": priority.value,
            "endpoint": endpoint.to_dict() if endpoint else None,
            "recommended_script": self._recommended_script(intent, endpoint),
            "crm_context": self._redact_sensitive(copy.deepcopy(dict(task_context.get("crm_context", {}) or {}))),
            "support_context": self._redact_sensitive(copy.deepcopy(dict(task_context.get("support_context", {}) or {}))),
            "call_summary": str(task_context.get("call_summary") or task_context.get("summary") or "")[:1200],
            "transcript_excerpt": transcript[:1200],
            "workspace_routing_version": str(workspace_config.get("routing_version", "default")),
            "created_at": self._now_iso(),
        }

    def _build_execution_context(
        self,
        route_decision: Mapping[str, Any],
        task_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """Build executor context."""
        return {
            "user_id": str(task_context.get("user_id", "")),
            "workspace_id": str(task_context.get("workspace_id", "")),
            "call_id": str(task_context.get("call_id", "")),
            "caller_id": str(
                task_context.get("caller_id")
                or task_context.get("caller_phone")
                or task_context.get("from_number")
                or "unknown"
            ),
            "route_decision": self._redact_sensitive(copy.deepcopy(dict(route_decision))),
            "route_payload": self._redact_sensitive(copy.deepcopy(dict(route_decision.get("route_payload", {}) or {}))),
            "task_context": self._redact_sensitive(copy.deepcopy(dict(task_context))),
            "idempotency_key": self._build_route_idempotency_key(route_decision, task_context),
            "source_agent": self.agent_name,
            "created_at": self._now_iso(),
        }

    def _build_route_reason(
        self,
        intent: ContactIntent,
        confidence: float,
        priority: RoutePriority,
        endpoint: Optional[ContactEndpoint],
        requires_security: bool,
    ) -> str:
        """Build human-readable route reason."""
        endpoint_name = endpoint.name if endpoint else "fallback receptionist"
        security_note = " Security approval is required before execution." if requires_security else ""
        return (
            f"Intent '{intent.value}' detected with confidence {confidence:.2f}. "
            f"Priority is '{priority.value}'. Routed to {endpoint_name}.{security_note}"
        )

    def _recommended_script(self, intent: ContactIntent, endpoint: Optional[ContactEndpoint]) -> str:
        """Return a safe receptionist handoff line."""
        if intent == ContactIntent.SALES:
            return "Thanks for sharing that. I can connect you with our sales team or arrange a specialist callback."
        if intent in {ContactIntent.SUPPORT, ContactIntent.TECHNICAL_SUPPORT}:
            return "I understand you need support. I will route this to the right support team with your call details."
        if intent == ContactIntent.BILLING:
            return "I can route your billing question to the billing team and include your call details."
        if intent == ContactIntent.APPOINTMENT:
            return "I can help prepare an appointment request and route it for booking."
        if intent in {ContactIntent.OWNER_REQUEST, ContactIntent.COMPLAINT, ContactIntent.URGENT}:
            return "I will escalate this carefully and make sure the right person receives the details."
        if intent == ContactIntent.SPAM_OR_ROBOCALL:
            return "This call may be marked as unwanted according to workspace policy."
        if endpoint and endpoint.destination_type == RouteDestinationType.VOICEMAIL:
            return "I can take a clear message and make sure it is saved for follow-up."
        return "I can take your details and route your request to the right team."

    def _get_voicemail_or_callback_endpoint(
        self,
        intent: ContactIntent,
        priority: RoutePriority,
    ) -> ContactEndpoint:
        """Return voicemail/callback endpoint."""
        if intent == ContactIntent.HUMAN_CALLBACK:
            endpoint = self._get_endpoint_by_type(RouteDestinationType.CALLBACK_QUEUE)
            if endpoint:
                return endpoint

        endpoint = self._get_endpoint_by_type(RouteDestinationType.VOICEMAIL)
        if endpoint:
            return endpoint

        return ContactEndpoint(
            endpoint_id="fallback_voicemail",
            name="Fallback Voicemail",
            destination_type=RouteDestinationType.VOICEMAIL,
            action=RouteAction.SEND_TO_VOICEMAIL,
            priority=priority,
            active=True,
        )

    def _endpoint_from_workspace_override(
        self,
        intent: ContactIntent,
        workspace_config: Mapping[str, Any],
    ) -> Optional[ContactEndpoint]:
        """Parse workspace-specific route override."""
        overrides = workspace_config.get("routing_overrides", {})
        if not isinstance(overrides, Mapping):
            return None

        raw = overrides.get(intent.value)
        if not raw:
            return None

        try:
            return self._parse_endpoint(raw)
        except Exception:
            self.logger.debug("Invalid workspace routing override ignored.", exc_info=True)
            return None

    def _find_team_member_endpoint(
        self,
        requested_person: str,
        workspace_config: Mapping[str, Any],
    ) -> Optional[ContactEndpoint]:
        """Find endpoint for requested team member by name/role."""
        needle = self._normalize_text(requested_person)

        team_endpoints = workspace_config.get("team_endpoints", [])
        if isinstance(team_endpoints, Sequence) and not isinstance(team_endpoints, (str, bytes)):
            for raw in team_endpoints:
                try:
                    endpoint = self._parse_endpoint(raw)
                except Exception:
                    continue
                haystack = self._normalize_text(
                    " ".join(
                        [
                            endpoint.name,
                            endpoint.role or "",
                            endpoint.team_member_id or "",
                            endpoint.email or "",
                        ]
                    )
                )
                if needle and needle in haystack:
                    return endpoint

        with self._lock:
            for endpoint in self._endpoints.values():
                if endpoint.destination_type != RouteDestinationType.TEAM_MEMBER or not endpoint.active:
                    continue
                haystack = self._normalize_text(
                    " ".join(
                        [
                            endpoint.name,
                            endpoint.role or "",
                            endpoint.team_member_id or "",
                            endpoint.email or "",
                        ]
                    )
                )
                if needle and needle in haystack:
                    return endpoint

        return None

    def _get_endpoint_by_type(self, destination_type: RouteDestinationType) -> Optional[ContactEndpoint]:
        """Return first active endpoint by destination type."""
        with self._lock:
            candidates = [
                endpoint
                for endpoint in self._endpoints.values()
                if endpoint.destination_type == destination_type and endpoint.active
            ]

        if not candidates:
            return None

        priority_order = {
            RoutePriority.EMERGENCY: 0,
            RoutePriority.URGENT: 1,
            RoutePriority.HIGH: 2,
            RoutePriority.NORMAL: 3,
            RoutePriority.LOW: 4,
        }
        candidates.sort(key=lambda item: priority_order.get(item.priority, 99))
        return candidates[0]

    def _load_default_endpoints(self) -> None:
        """Load safe default endpoints."""
        defaults = [
            ContactEndpoint(
                endpoint_id="default_owner",
                name="Workspace Owner",
                destination_type=RouteDestinationType.OWNER,
                action=RouteAction.ESCALATE_TO_OWNER,
                priority=RoutePriority.HIGH,
                active=True,
                metadata={"default": True},
            ),
            ContactEndpoint(
                endpoint_id="default_sales_queue",
                name="Sales Queue",
                destination_type=RouteDestinationType.SALES_QUEUE,
                action=RouteAction.CREATE_LEAD,
                priority=RoutePriority.NORMAL,
                queue_name="sales",
                crm_pipeline="sales",
                active=True,
                metadata={"default": True},
            ),
            ContactEndpoint(
                endpoint_id="default_support_queue",
                name="Support Queue",
                destination_type=RouteDestinationType.SUPPORT_QUEUE,
                action=RouteAction.CREATE_SUPPORT_TICKET,
                priority=RoutePriority.NORMAL,
                queue_name="support",
                active=True,
                metadata={"default": True},
            ),
            ContactEndpoint(
                endpoint_id="default_billing_queue",
                name="Billing Queue",
                destination_type=RouteDestinationType.BILLING_QUEUE,
                action=RouteAction.CREATE_SUPPORT_TICKET,
                priority=RoutePriority.NORMAL,
                queue_name="billing",
                active=True,
                metadata={"default": True},
            ),
            ContactEndpoint(
                endpoint_id="default_crm",
                name="CRM Routing",
                destination_type=RouteDestinationType.CRM,
                action=RouteAction.CREATE_CRM_TASK,
                priority=RoutePriority.NORMAL,
                crm_pipeline="general",
                active=True,
                metadata={"default": True},
            ),
            ContactEndpoint(
                endpoint_id="default_appointment_booker",
                name="Appointment Booker",
                destination_type=RouteDestinationType.APPOINTMENT_BOOKER,
                action=RouteAction.BOOK_APPOINTMENT,
                priority=RoutePriority.NORMAL,
                active=True,
                metadata={"default": True},
            ),
            ContactEndpoint(
                endpoint_id="default_voicemail",
                name="Voicemail",
                destination_type=RouteDestinationType.VOICEMAIL,
                action=RouteAction.SEND_TO_VOICEMAIL,
                priority=RoutePriority.NORMAL,
                active=True,
                metadata={"default": True},
            ),
            ContactEndpoint(
                endpoint_id="default_callback_queue",
                name="Callback Queue",
                destination_type=RouteDestinationType.CALLBACK_QUEUE,
                action=RouteAction.QUEUE_CALLBACK,
                priority=RoutePriority.NORMAL,
                active=True,
                metadata={"default": True},
            ),
            ContactEndpoint(
                endpoint_id="default_receptionist",
                name="Receptionist",
                destination_type=RouteDestinationType.RECEPTIONIST,
                action=RouteAction.CONTINUE_RECEPTIONIST,
                priority=RoutePriority.NORMAL,
                active=True,
                metadata={"default": True},
            ),
        ]

        with self._lock:
            for endpoint in defaults:
                self._endpoints[endpoint.endpoint_id] = endpoint

    # ---------------------------------------------------------------------
    # Intent helpers
    # ---------------------------------------------------------------------

    def _extract_explicit_intent(self, task_context: Mapping[str, Any]) -> Optional[ContactIntent]:
        """Extract explicit intent label if provided."""
        candidates = [
            task_context.get("intent"),
            task_context.get("caller_intent"),
            task_context.get("detected_intent"),
            (task_context.get("metadata") or {}).get("intent") if isinstance(task_context.get("metadata"), Mapping) else None,
        ]

        for candidate in candidates:
            if not candidate:
                continue
            value = str(candidate).strip().lower().replace(" ", "_").replace("-", "_")
            for intent in ContactIntent:
                if value == intent.value:
                    return intent

        return None

    def _collect_text_for_intent(self, task_context: Mapping[str, Any]) -> str:
        """Collect text fields for intent detection."""
        parts = [
            task_context.get("transcript"),
            task_context.get("live_transcript"),
            task_context.get("call_summary"),
            task_context.get("summary"),
            task_context.get("receptionist_notes"),
            task_context.get("caller_message"),
            task_context.get("subject"),
            task_context.get("notes"),
        ]

        metadata = task_context.get("metadata")
        if isinstance(metadata, Mapping):
            parts.extend(
                [
                    metadata.get("transcript"),
                    metadata.get("summary"),
                    metadata.get("notes"),
                    metadata.get("reason"),
                ]
            )

        text = " ".join(str(part) for part in parts if part)
        text = re.sub(r"\s+", " ", text).strip()
        return text[: self.policy.max_transcript_chars]

    def _keyword_detect_intent(self, text: str) -> Tuple[ContactIntent, float, List[str]]:
        """Simple deterministic keyword intent detection."""
        normalized = self._normalize_text(text)
        if not normalized:
            return ContactIntent.UNKNOWN, 0.0, ["empty_text"]

        scores: Dict[ContactIntent, int] = {}
        evidence: Dict[ContactIntent, List[str]] = {}

        for intent, keywords in INTENT_KEYWORDS.items():
            for keyword in keywords:
                keyword_norm = self._normalize_text(keyword)
                if keyword_norm and keyword_norm in normalized:
                    scores[intent] = scores.get(intent, 0) + max(1, len(keyword_norm.split()))
                    evidence.setdefault(intent, []).append(keyword)

        if not scores:
            return ContactIntent.UNKNOWN, 0.2, ["no_keyword_match"]

        sorted_scores = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        best_intent, best_score = sorted_scores[0]
        second_score = sorted_scores[1][1] if len(sorted_scores) > 1 else 0

        token_count = max(1, len(normalized.split()))
        base_confidence = min(0.95, 0.35 + (best_score / max(6.0, token_count * 0.35)))
        separation_bonus = min(0.2, max(0, best_score - second_score) * 0.04)
        confidence = min(0.98, base_confidence + separation_bonus)

        if best_intent == ContactIntent.URGENT and any(word in normalized for word in ("emergency", "danger", "threat")):
            best_intent = ContactIntent.EMERGENCY
            confidence = max(confidence, 0.85)

        return best_intent, confidence, evidence.get(best_intent, [])

    def _detect_priority(
        self,
        intent: ContactIntent,
        text: str,
        task_context: Mapping[str, Any],
    ) -> RoutePriority:
        """Detect route priority."""
        explicit = str(task_context.get("priority", "")).strip().lower()
        for priority in RoutePriority:
            if explicit == priority.value:
                return priority

        normalized = self._normalize_text(text)

        if intent == ContactIntent.EMERGENCY:
            return RoutePriority.EMERGENCY
        if intent in {ContactIntent.URGENT, ContactIntent.COMPLAINT, ContactIntent.OWNER_REQUEST}:
            return RoutePriority.HIGH
        if any(term in normalized for term in ("as soon as possible", "right now", "immediately", "critical")):
            return RoutePriority.URGENT
        if intent in {ContactIntent.SALES, ContactIntent.NEW_LEAD, ContactIntent.SUPPORT, ContactIntent.BILLING}:
            return RoutePriority.NORMAL
        if intent == ContactIntent.SPAM_OR_ROBOCALL:
            return RoutePriority.LOW
        return RoutePriority.NORMAL

    def _detect_caller_type(self, task_context: Mapping[str, Any], text: str) -> str:
        """Detect caller type from CRM context and text."""
        crm_context = task_context.get("crm_context")
        if isinstance(crm_context, Mapping):
            if crm_context.get("customer_id") or crm_context.get("contact_id"):
                return "known_contact"
            if crm_context.get("lead_id"):
                return "known_lead"

        normalized = self._normalize_text(text)
        if any(term in normalized for term in ("existing customer", "current client", "my project", "my account")):
            return "existing_customer"
        if any(term in normalized for term in ("new client", "looking for", "need a", "want a")):
            return "new_lead"

        return "unknown"

    def _extract_requested_person(self, task_context: Mapping[str, Any]) -> Optional[str]:
        """Extract requested person/team member from context or transcript."""
        for key in ("requested_person", "team_member", "transfer_to", "agent_name"):
            value = task_context.get(key)
            if value:
                return str(value).strip()

        text = self._collect_text_for_intent(task_context)
        patterns = [
            r"(?:speak with|talk to|connect me to|transfer me to)\s+([A-Za-z][A-Za-z .'-]{1,60})",
            r"(?:is|can)\s+([A-Za-z][A-Za-z .'-]{1,60})\s+(?:available|there)",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                return match.group(1).strip(" .,'\"")

        return None

    # ---------------------------------------------------------------------
    # Safety and executor helpers
    # ---------------------------------------------------------------------

    def classify_route_safety(
        self,
        action: Union[str, RouteAction],
        destination_type: Optional[Union[str, RouteDestinationType]] = None,
    ) -> SafetyLevel:
        """Classify route action safety."""
        action_value = self._enum_value(action)
        destination_value = self._enum_value(destination_type)

        if action_value in {
            RouteAction.NO_ACTION.value,
            RouteAction.CONTINUE_RECEPTIONIST.value,
            RouteAction.TAKE_MESSAGE.value,
            RouteAction.SEND_TO_VOICEMAIL.value,
        }:
            return SafetyLevel.SAFE

        if action_value in {
            RouteAction.QUEUE_CALLBACK.value,
            RouteAction.BOOK_APPOINTMENT.value,
        }:
            return SafetyLevel.CAUTION

        if action_value in {
            RouteAction.TRANSFER_CALL.value,
            RouteAction.SEND_NOTIFICATION.value,
            RouteAction.ESCALATE_TO_OWNER.value,
            RouteAction.CREATE_CRM_TASK.value,
            RouteAction.CREATE_SUPPORT_TICKET.value,
            RouteAction.CREATE_LEAD.value,
        }:
            return SafetyLevel.SENSITIVE

        if action_value == RouteAction.BLOCK_CALL.value:
            return SafetyLevel.CAUTION

        if destination_value in {
            RouteDestinationType.EXTERNAL_PROVIDER.value,
            RouteDestinationType.OWNER.value,
        }:
            return SafetyLevel.SENSITIVE

        return SafetyLevel.UNKNOWN

    def _infer_builtin_executor(self, action: str) -> Optional[Callable[[Dict[str, Any]], Dict[str, Any]]]:
        """
        Infer safe built-in executor wrappers for optional CRM/support clients.

        These still do not hardcode external actions. They call provided clients
        only when configured by the app.
        """
        if action == RouteAction.CREATE_CRM_TASK.value and self.crm_client is not None:
            return self._execute_crm_task
        if action == RouteAction.CREATE_LEAD.value and self.crm_client is not None:
            return self._execute_crm_lead
        if action == RouteAction.CREATE_SUPPORT_TICKET.value and self.support_client is not None:
            return self._execute_support_ticket
        return None

    def _execute_crm_task(self, execution_context: Dict[str, Any]) -> Dict[str, Any]:
        """Optional CRM task executor wrapper."""
        if self.crm_client is None:
            return self._error_result("CRM client is not configured.", error="missing_crm_client")

        payload = execution_context.get("route_payload", {})
        try:
            if hasattr(self.crm_client, "create_task"):
                response = self.crm_client.create_task(payload)
            elif hasattr(self.crm_client, "route_call"):
                response = self.crm_client.route_call(payload)
            elif callable(self.crm_client):
                response = self.crm_client(payload)
            else:
                return self._error_result("CRM client does not support task creation.", error="unsupported_crm_client")

            return self._normalize_external_response(response, "CRM task created.")
        except Exception as exc:
            return self._error_result("CRM task creation failed.", error=exc)

    def _execute_crm_lead(self, execution_context: Dict[str, Any]) -> Dict[str, Any]:
        """Optional CRM lead executor wrapper."""
        if self.crm_client is None:
            return self._error_result("CRM client is not configured.", error="missing_crm_client")

        payload = execution_context.get("route_payload", {})
        try:
            if hasattr(self.crm_client, "create_lead"):
                response = self.crm_client.create_lead(payload)
            elif hasattr(self.crm_client, "upsert_lead"):
                response = self.crm_client.upsert_lead(payload)
            elif callable(self.crm_client):
                response = self.crm_client(payload)
            else:
                return self._error_result("CRM client does not support lead creation.", error="unsupported_crm_client")

            return self._normalize_external_response(response, "CRM lead created.")
        except Exception as exc:
            return self._error_result("CRM lead creation failed.", error=exc)

    def _execute_support_ticket(self, execution_context: Dict[str, Any]) -> Dict[str, Any]:
        """Optional support ticket executor wrapper."""
        if self.support_client is None:
            return self._error_result("Support client is not configured.", error="missing_support_client")

        payload = execution_context.get("route_payload", {})
        try:
            if hasattr(self.support_client, "create_ticket"):
                response = self.support_client.create_ticket(payload)
            elif hasattr(self.support_client, "route_call"):
                response = self.support_client.route_call(payload)
            elif callable(self.support_client):
                response = self.support_client(payload)
            else:
                return self._error_result("Support client does not support ticket creation.", error="unsupported_support_client")

            return self._normalize_external_response(response, "Support ticket created.")
        except Exception as exc:
            return self._error_result("Support ticket creation failed.", error=exc)

    # ---------------------------------------------------------------------
    # Utility methods
    # ---------------------------------------------------------------------

    def policy_to_dict(self) -> Dict[str, Any]:
        """Return policy as dict."""
        return {
            "require_security_for_transfers": self.policy.require_security_for_transfers,
            "require_security_for_owner_escalation": self.policy.require_security_for_owner_escalation,
            "require_security_for_crm_write": self.policy.require_security_for_crm_write,
            "allow_unknown_intent_fallback": self.policy.allow_unknown_intent_fallback,
            "block_spam": self.policy.block_spam,
            "route_emergency_to_owner": self.policy.route_emergency_to_owner,
            "default_business_hours_only": self.policy.default_business_hours_only,
            "max_transcript_chars": self.policy.max_transcript_chars,
            "confidence_threshold": self.policy.confidence_threshold,
            "high_confidence_threshold": self.policy.high_confidence_threshold,
            "enable_in_memory_history": self.policy.enable_in_memory_history,
        }

    def _parse_endpoint(self, endpoint: Union[ContactEndpoint, Mapping[str, Any]]) -> ContactEndpoint:
        """Parse endpoint from dataclass or mapping."""
        if isinstance(endpoint, ContactEndpoint):
            return endpoint

        if not isinstance(endpoint, Mapping):
            raise TypeError("Endpoint must be ContactEndpoint or mapping/dict.")

        destination_type = self._parse_enum(
            RouteDestinationType,
            endpoint.get("destination_type", endpoint.get("type", RouteDestinationType.FALLBACK.value)),
        )
        action = self._parse_enum(RouteAction, endpoint.get("action", RouteAction.NO_ACTION.value))
        priority = self._parse_enum(RoutePriority, endpoint.get("priority", RoutePriority.NORMAL.value))

        return ContactEndpoint(
            endpoint_id=str(endpoint.get("endpoint_id") or endpoint.get("id") or self._new_id("endpoint")),
            name=str(endpoint.get("name") or endpoint.get("label") or "Unnamed Endpoint"),
            destination_type=destination_type,
            action=action,
            priority=priority,
            phone=self._optional_str(endpoint.get("phone")),
            email=self._optional_str(endpoint.get("email")),
            queue_name=self._optional_str(endpoint.get("queue_name")),
            crm_pipeline=self._optional_str(endpoint.get("crm_pipeline")),
            team_member_id=self._optional_str(endpoint.get("team_member_id")),
            role=self._optional_str(endpoint.get("role")),
            active=bool(endpoint.get("active", True)),
            business_hours_only=bool(endpoint.get("business_hours_only", False)),
            metadata=dict(endpoint.get("metadata", {}) or {}),
        )

    def _parse_enum(self, enum_cls: Any, value: Any) -> Any:
        """Parse enum value safely."""
        if isinstance(value, enum_cls):
            return value

        normalized = str(value).strip().lower().replace(" ", "_").replace("-", "_")
        for item in enum_cls:
            if normalized == item.value:
                return item

        raise ValueError(f"Invalid {enum_cls.__name__}: {value}")

    def _optional_str(self, value: Any) -> Optional[str]:
        """Return optional string."""
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _enum_value(self, value: Optional[Union[str, enum.Enum]]) -> str:
        """Return enum/string value."""
        if value is None:
            return ""
        if isinstance(value, enum.Enum):
            return str(value.value)
        return str(value).strip().lower().replace(" ", "_").replace("-", "_")

    def _normalize_text(self, value: Any) -> str:
        """Normalize text for matching."""
        text = str(value or "").lower()
        text = re.sub(r"[^a-z0-9+@._' -]+", " ", text)
        text = re.sub(r"\s+", " ", text)
        return text.strip()

    def _is_in_business_hours(
        self,
        task_context: Mapping[str, Any],
        workspace_config: Mapping[str, Any],
    ) -> bool:
        """
        Determine business-hours status.

        This method is intentionally conservative and import-safe. If business
        hours are not supplied, returns True unless policy requires business hours.
        """
        explicit = task_context.get("in_business_hours")
        if isinstance(explicit, bool):
            return explicit

        config_explicit = workspace_config.get("in_business_hours")
        if isinstance(config_explicit, bool):
            return config_explicit

        business_hours = workspace_config.get("business_hours")
        if not business_hours:
            return not self.policy.default_business_hours_only

        if not isinstance(business_hours, Mapping):
            return True

        now = self.clock().astimezone(timezone.utc)
        weekday = now.strftime("%A").lower()
        day_config = business_hours.get(weekday)
        if not day_config:
            return False

        if isinstance(day_config, bool):
            return day_config

        return True

    def _store_route_decision(self, decision: RouteDecision) -> None:
        """Store in-memory route history if enabled."""
        if not self.policy.enable_in_memory_history:
            return

        key = f"{decision.user_id}:{decision.workspace_id}:{decision.call_id}"
        with self._lock:
            self._routing_history.setdefault(key, []).append(decision)

    def _update_route_status_dict(
        self,
        route_decision: Mapping[str, Any],
        status: RoutingStatus,
        error: Optional[Any] = None,
        metadata_extra: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update route decision dict status."""
        updated = copy.deepcopy(dict(route_decision))
        updated["status"] = status.value
        updated["updated_at"] = self._now_iso()
        updated["error"] = self._error_to_safe_payload(error)

        metadata = dict(updated.get("metadata", {}) or {})
        metadata.update(dict(metadata_extra or {}))
        updated["metadata"] = metadata

        return updated

    def _normalize_executor_result(self, result: Mapping[str, Any]) -> Dict[str, Any]:
        """Normalize executor result."""
        return {
            "success": bool(result.get("success", False)),
            "message": str(result.get("message", "Route executor returned result.")),
            "data": dict(result.get("data", {}) or {}),
            "error": result.get("error"),
            "metadata": dict(result.get("metadata", {}) or {}),
        }

    def _normalize_external_response(self, response: Any, default_message: str) -> Dict[str, Any]:
        """Normalize CRM/support external response."""
        if isinstance(response, Mapping):
            return {
                "success": bool(response.get("success", True)),
                "message": str(response.get("message", default_message)),
                "data": dict(response.get("data", response) or {}),
                "error": response.get("error"),
                "metadata": dict(response.get("metadata", {}) or {}),
            }

        return {
            "success": True,
            "message": default_message,
            "data": {"response": self._json_safe(response)},
            "error": None,
            "metadata": {},
        }

    def _safe_call_context_summary(self, task_context: Mapping[str, Any]) -> Dict[str, Any]:
        """Safe summary for security/audit without full private transcript."""
        return {
            "user_id": str(task_context.get("user_id", "")),
            "workspace_id": str(task_context.get("workspace_id", "")),
            "call_id": str(task_context.get("call_id", "")),
            "caller_id": str(
                task_context.get("caller_id")
                or task_context.get("caller_phone")
                or task_context.get("from_number")
                or "unknown"
            ),
            "caller_name_present": bool(task_context.get("caller_name") or task_context.get("name")),
            "transcript_present": bool(task_context.get("transcript") or task_context.get("live_transcript")),
            "crm_context_present": bool(task_context.get("crm_context")),
            "support_context_present": bool(task_context.get("support_context")),
        }

    def _summarize_result(self, result: Mapping[str, Any]) -> Dict[str, Any]:
        """Summarize execution result safely."""
        if not isinstance(result, Mapping):
            return {"success": False, "message": "", "data_keys": [], "error_present": False}

        data = result.get("data", {})
        metadata = result.get("metadata", {})

        return {
            "success": bool(result.get("success", False)),
            "message": str(result.get("message", ""))[:300],
            "data_keys": sorted([str(k) for k in data.keys()]) if isinstance(data, Mapping) else [],
            "metadata_keys": sorted([str(k) for k in metadata.keys()]) if isinstance(metadata, Mapping) else [],
            "error_present": bool(result.get("error")),
        }

    def _build_route_idempotency_key(
        self,
        route_decision: Mapping[str, Any],
        task_context: Mapping[str, Any],
    ) -> str:
        """Build stable idempotency key for route execution."""
        material = {
            "user_id": str(task_context.get("user_id", "")),
            "workspace_id": str(task_context.get("workspace_id", "")),
            "call_id": str(task_context.get("call_id", "")),
            "caller_id": str(
                task_context.get("caller_id")
                or task_context.get("caller_phone")
                or task_context.get("from_number")
                or "unknown"
            ),
            "route_id": str(route_decision.get("route_id", "")),
            "action": str(route_decision.get("action", "")),
            "destination_type": str(route_decision.get("destination_type", "")),
        }
        return "call_route:" + self._fingerprint(material)

    def _fingerprint(self, value: Any) -> str:
        """Create deterministic SHA256 fingerprint."""
        encoded = json.dumps(
            self._json_safe(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()[:32]

    def _json_safe(self, value: Any) -> Any:
        """Convert arbitrary values into JSON-safe structures."""
        if dataclasses.is_dataclass(value):
            return self._json_safe(dataclasses.asdict(value))
        if isinstance(value, enum.Enum):
            return value.value
        if isinstance(value, Mapping):
            return {str(k): self._json_safe(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [self._json_safe(v) for v in value]
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        return str(value)

    def _redact_sensitive(self, value: Any) -> Any:
        """Redact secrets and sensitive tokens from payloads."""
        sensitive_fragments = (
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "auth_key",
            "private_key",
            "access_key",
            "refresh",
            "bearer",
            "cookie",
        )

        if isinstance(value, Mapping):
            redacted: Dict[str, Any] = {}
            for key, item in value.items():
                key_str = str(key)
                if any(fragment in key_str.lower() for fragment in sensitive_fragments):
                    redacted[key_str] = "***REDACTED***"
                else:
                    redacted[key_str] = self._redact_sensitive(item)
            return redacted

        if isinstance(value, list):
            return [self._redact_sensitive(item) for item in value]
        if isinstance(value, tuple):
            return tuple(self._redact_sensitive(item) for item in value)
        return value

    def _error_to_safe_payload(self, error: Optional[Any]) -> Optional[Union[str, Dict[str, Any]]]:
        """Convert error to safe payload."""
        if error is None:
            return None
        if isinstance(error, Exception):
            return {"type": error.__class__.__name__, "message": str(error)}
        if isinstance(error, Mapping):
            return self._redact_sensitive(self._json_safe(error))
        return str(error)

    def _new_id(self, prefix: str) -> str:
        """Generate unique ID."""
        return f"{prefix}_{uuid.uuid4().hex}"

    def _now_iso(self) -> str:
        """Return current UTC ISO timestamp."""
        return self.clock().astimezone(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Factory and exports
# ---------------------------------------------------------------------------

def create_contact_router(
    policy: Optional[RoutingPolicy] = None,
    endpoints: Optional[Sequence[Union[ContactEndpoint, Mapping[str, Any]]]] = None,
    **kwargs: Any,
) -> ContactRouter:
    """
    Factory for Agent Loader / Registry.

    Example:
        router = create_contact_router()
    """
    return ContactRouter(policy=policy, endpoints=endpoints, **kwargs)


__all__ = [
    "ContactRouter",
    "RoutingPolicy",
    "ContactEndpoint",
    "RouteDecision",
    "ContactIntent",
    "RouteDestinationType",
    "RouteAction",
    "RoutePriority",
    "RoutingStatus",
    "SafetyLevel",
    "create_contact_router",
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    router = ContactRouter(
        policy=RoutingPolicy(
            require_security_for_transfers=False,
            require_security_for_owner_escalation=False,
            require_security_for_crm_write=False,
        )
    )

    def demo_create_lead_executor(context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "success": True,
            "message": "Demo lead route executed.",
            "data": {
                "idempotency_key": context.get("idempotency_key"),
                "route_id": context.get("route_decision", {}).get("route_id"),
            },
            "error": None,
            "metadata": {"demo": True},
        }

    router.register_route_executor(RouteAction.CREATE_LEAD, demo_create_lead_executor)

    demo_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "call_id": "call_001",
        "caller_id": "+15551234567",
        "caller_name": "John Smith",
        "transcript": "Hi, I need pricing for a new website and SEO package. Can someone call me back?",
        "metadata": {"source": "self_test"},
    }

    result = router.route_contact(demo_context, execute=True)
    print(json.dumps(result, indent=2))