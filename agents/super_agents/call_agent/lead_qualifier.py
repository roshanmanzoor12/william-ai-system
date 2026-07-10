"""
agents/super_agents/call_agent/lead_qualifier.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix

Purpose:
    Qualifies caller budget, service, urgency, and contact details.

This module belongs to the Call Agent stack. It is designed to be called by:
    - Master Agent
    - Call Agent
    - Receptionist Mode
    - Call Summarizer
    - Appointment Booker
    - CRM Connector
    - Workflow Agent

It does not place calls, send messages, book appointments, modify CRM records,
or execute destructive actions directly. It only analyzes caller/lead data and
returns structured qualification results that can be safely routed to other
agents after permission/security checks.

Key responsibilities:
    - Validate SaaS user/workspace isolation context.
    - Extract/normalize caller contact details.
    - Identify requested service.
    - Estimate urgency and budget level.
    - Score lead quality.
    - Classify lead status.
    - Suggest the next safe question or handoff action.
    - Prepare Verification Agent payload.
    - Prepare Memory Agent compatible payload.
    - Emit audit/event payloads for dashboard/API integrations.

All public methods return dict/JSON style results:
    {
        "success": bool,
        "message": str,
        "data": dict,
        "error": Optional[Any],
        "metadata": dict
    }

This file is import-safe even if future William/Jarvis modules are not created yet.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# =============================================================================
# Safe optional imports
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent.

        This keeps the file import-safe while the rest of the William/Jarvis
        framework is still being generated.
        """

        agent_name: str = "base_agent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", getattr(self, "agent_name", self.__class__.__name__))
            self.logger = logging.getLogger(self.agent_name)

        def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent.run() called. No real BaseAgent is attached.",
                "data": {},
                "error": "BASE_AGENT_FALLBACK",
                "metadata": {},
            }


try:
    from agents.super_agents.call_agent.config import LEAD_QUALIFIER_DEFAULTS  # type: ignore
except Exception:  # pragma: no cover
    LEAD_QUALIFIER_DEFAULTS: Dict[str, Any] = {
        "minimum_hot_score": 75,
        "minimum_warm_score": 50,
        "minimum_budget_for_high_value": 1000.0,
        "minimum_budget_for_medium_value": 300.0,
        "default_currency": "USD",
        "max_notes_length": 3000,
        "allow_memory_payload": True,
        "allow_verification_payload": True,
        "strict_contact_collection": False,
        "default_required_fields": ["full_name", "phone_number", "service"],
    }


# =============================================================================
# Logging
# =============================================================================

logger = logging.getLogger("william.super_agents.call_agent.lead_qualifier")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Enums and data models
# =============================================================================

class LeadTemperature(str, Enum):
    """Final qualification temperature."""

    HOT = "hot"
    WARM = "warm"
    COLD = "cold"
    UNQUALIFIED = "unqualified"
    UNKNOWN = "unknown"


class UrgencyLevel(str, Enum):
    """Caller urgency level."""

    IMMEDIATE = "immediate"
    THIS_WEEK = "this_week"
    THIS_MONTH = "this_month"
    FLEXIBLE = "flexible"
    UNKNOWN = "unknown"


class BudgetLevel(str, Enum):
    """Budget quality bucket."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ContactQuality(str, Enum):
    """How complete the caller contact details are."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    MISSING = "missing"


class QualificationStatus(str, Enum):
    """Lifecycle status of qualification."""

    QUALIFIED = "qualified"
    NEEDS_MORE_INFO = "needs_more_info"
    DISQUALIFIED = "disqualified"
    PENDING_REVIEW = "pending_review"


class CallService(str, Enum):
    """Supported high-level service categories."""

    WEBSITE = "website"
    SEO = "seo"
    PPC = "ppc"
    META_ADS = "meta_ads"
    GOOGLE_ADS = "google_ads"
    SOCIAL_MEDIA = "social_media"
    AI_AUTOMATION = "ai_automation"
    CHATBOT = "chatbot"
    VOICE_AGENT = "voice_agent"
    CRM = "crm"
    GRAPHIC_DESIGN = "graphic_design"
    VIDEO_ADS = "video_ads"
    BRANDING = "branding"
    CONSULTATION = "consultation"
    UNKNOWN = "unknown"


@dataclass
class LeadQualifierConfig:
    """Runtime configuration for LeadQualifier."""

    minimum_hot_score: int = 75
    minimum_warm_score: int = 50
    minimum_budget_for_high_value: float = 1000.0
    minimum_budget_for_medium_value: float = 300.0
    default_currency: str = "USD"
    max_notes_length: int = 3000
    allow_memory_payload: bool = True
    allow_verification_payload: bool = True
    strict_contact_collection: bool = False
    default_required_fields: List[str] = field(default_factory=lambda: ["full_name", "phone_number", "service"])


@dataclass
class LeadContactDetails:
    """Normalized caller contact details."""

    full_name: Optional[str] = None
    phone_number: Optional[str] = None
    email: Optional[str] = None
    company_name: Optional[str] = None
    website: Optional[str] = None
    country: Optional[str] = None
    timezone: Optional[str] = None
    preferred_contact_method: Optional[str] = None


@dataclass
class LeadQualification:
    """Full lead qualification result."""

    lead_id: str
    user_id: str
    workspace_id: str
    call_id: Optional[str]
    caller_id: Optional[str]
    contact: LeadContactDetails
    service: str
    service_confidence: float
    budget_amount: Optional[float]
    budget_currency: str
    budget_level: str
    urgency_level: str
    lead_temperature: str
    qualification_status: str
    score: int
    score_breakdown: Dict[str, int]
    missing_fields: List[str]
    disqualification_reasons: List[str]
    qualifying_signals: List[str]
    risk_flags: List[str]
    recommended_next_action: str
    next_question: Optional[str]
    notes: str
    created_at: str
    metadata: Dict[str, Any] = field(default_factory=dict)


# =============================================================================
# Utility helpers
# =============================================================================

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_iso() -> str:
    return _utc_now().isoformat()


def _safe_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def _safe_lower(value: Any) -> str:
    return _safe_str(value).lower()


def _clean_whitespace(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def _truncate(value: str, max_length: int) -> str:
    clean = _clean_whitespace(value)
    if len(clean) <= max_length:
        return clean
    return clean[: max_length - 3] + "..."


def _hash_dict(payload: Mapping[str, Any]) -> str:
    try:
        safe = json.dumps(payload, sort_keys=True, default=str)
    except Exception:
        safe = repr(payload)
    return hashlib.sha256(safe.encode("utf-8")).hexdigest()[:24]


def _redact_value(key: str, value: Any) -> Any:
    sensitive = (
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "bearer",
        "credential",
        "private_key",
        "otp",
    )
    if any(marker in key.lower() for marker in sensitive):
        return "***REDACTED***"

    if isinstance(value, Mapping):
        return {str(k): _redact_value(str(k), v) for k, v in value.items()}

    if isinstance(value, list):
        return [_redact_value(key, item) for item in value]

    return value


def _redact_payload(payload: Any) -> Any:
    if isinstance(payload, Mapping):
        return {str(k): _redact_value(str(k), v) for k, v in payload.items()}
    if isinstance(payload, list):
        return [_redact_payload(item) for item in payload]
    return payload


def _digits_only(value: str) -> str:
    return re.sub(r"\D+", "", value or "")


def _normalize_phone(value: Any) -> Optional[str]:
    raw = _safe_str(value)
    if not raw:
        return None

    digits = _digits_only(raw)
    if len(digits) < 7:
        return None

    if raw.strip().startswith("+"):
        return "+" + digits

    return digits


def _extract_email(text: str) -> Optional[str]:
    match = re.search(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", text or "")
    return match.group(0).strip() if match else None


def _extract_website(text: str) -> Optional[str]:
    match = re.search(
        r"\b((?:https?://)?(?:www\.)?[A-Za-z0-9\-]+\.[A-Za-z]{2,}(?:/[^\s]*)?)\b",
        text or "",
        flags=re.IGNORECASE,
    )
    if not match:
        return None

    website = match.group(1).strip().rstrip(".,)")
    if "@" in website:
        return None
    return website


def _extract_budget_amount(text: str) -> Tuple[Optional[float], str]:
    """
    Extract approximate budget amount and currency.

    Supports examples:
        "$500", "500 dollars", "1k", "2.5k", "3000 USD", "£800"
    """

    if not text:
        return None, "USD"

    lowered = text.lower()

    currency = "USD"
    if "£" in lowered or "gbp" in lowered or "pound" in lowered:
        currency = "GBP"
    elif "€" in lowered or "eur" in lowered or "euro" in lowered:
        currency = "EUR"
    elif "aed" in lowered or "dirham" in lowered:
        currency = "AED"
    elif "sar" in lowered or "riyal" in lowered:
        currency = "SAR"
    elif "pkr" in lowered or "rupee" in lowered or "rs" in lowered:
        currency = "PKR"
    elif "$" in lowered or "usd" in lowered or "dollar" in lowered:
        currency = "USD"

    patterns = [
        r"[$£€]?\s*(\d+(?:,\d{3})*(?:\.\d+)?)\s*(k|thousand|m|million)?",
    ]

    for pattern in patterns:
        matches = re.findall(pattern, lowered)
        if not matches:
            continue

        amounts: List[float] = []
        for number_raw, suffix in matches:
            try:
                amount = float(number_raw.replace(",", ""))
            except Exception:
                continue

            suffix = suffix.lower().strip()
            if suffix in {"k", "thousand"}:
                amount *= 1000
            elif suffix in {"m", "million"}:
                amount *= 1_000_000

            if amount > 0:
                amounts.append(amount)

        if amounts:
            return max(amounts), currency

    return None, currency


def _contains_any(text: str, words: Iterable[str]) -> bool:
    lowered = text.lower()
    return any(word.lower() in lowered for word in words)


# =============================================================================
# LeadQualifier
# =============================================================================

class LeadQualifier(BaseAgent):
    """
    Qualifies caller leads for the Call Agent.

    Main public methods:
        - qualify_lead(...)
        - update_qualification(...)
        - get_next_question(...)
        - score_lead(...)
        - extract_contact_details(...)
        - run(...)

    This class is safe for Master Agent routing, Agent Registry loading,
    dashboard/API use, and future CRM/workflow integrations.
    """

    agent_name = "call_lead_qualifier"
    registry_name = "LeadQualifier"
    module_name = "call_agent"
    file_path = "agents/super_agents/call_agent/lead_qualifier.py"

    SERVICE_KEYWORDS: Dict[str, Tuple[str, ...]] = {
        CallService.WEBSITE.value: (
            "website",
            "web site",
            "web design",
            "web development",
            "landing page",
            "wordpress",
            "shopify",
            "woocommerce",
            "ecommerce",
            "e-commerce",
            "site",
        ),
        CallService.SEO.value: (
            "seo",
            "search engine",
            "rank",
            "ranking",
            "google ranking",
            "organic traffic",
            "local seo",
            "gmb",
            "google business profile",
        ),
        CallService.PPC.value: (
            "ppc",
            "paid ads",
            "paid advertising",
            "campaign",
            "ad campaign",
        ),
        CallService.GOOGLE_ADS.value: (
            "google ads",
            "google adwords",
            "search ads",
            "youtube ads",
        ),
        CallService.META_ADS.value: (
            "meta ads",
            "facebook ads",
            "instagram ads",
            "fb ads",
            "ig ads",
        ),
        CallService.SOCIAL_MEDIA.value: (
            "social media",
            "posting",
            "content calendar",
            "social posts",
            "facebook page",
            "instagram page",
        ),
        CallService.AI_AUTOMATION.value: (
            "ai automation",
            "automation",
            "workflow automation",
            "automate",
            "ai system",
            "agent",
            "jarvis",
        ),
        CallService.CHATBOT.value: (
            "chatbot",
            "chat bot",
            "website chat",
            "support bot",
            "ai chat",
        ),
        CallService.VOICE_AGENT.value: (
            "voice agent",
            "ai caller",
            "call agent",
            "receptionist",
            "phone agent",
            "ai voice",
        ),
        CallService.CRM.value: (
            "crm",
            "pipeline",
            "lead management",
            "customer management",
            "hubspot",
            "salesforce",
            "ghl",
            "go high level",
        ),
        CallService.GRAPHIC_DESIGN.value: (
            "graphic",
            "poster",
            "flyer",
            "banner",
            "creative",
            "design",
        ),
        CallService.VIDEO_ADS.value: (
            "video ad",
            "video ads",
            "reel",
            "short video",
            "commercial video",
            "promo video",
        ),
        CallService.BRANDING.value: (
            "branding",
            "brand",
            "logo",
            "identity",
            "brand identity",
        ),
        CallService.CONSULTATION.value: (
            "consultation",
            "consult",
            "strategy",
            "audit",
            "advice",
            "proposal",
        ),
    }

    URGENCY_KEYWORDS: Dict[str, Tuple[str, ...]] = {
        UrgencyLevel.IMMEDIATE.value: (
            "today",
            "now",
            "right now",
            "as soon as possible",
            "asap",
            "urgent",
            "immediately",
            "same day",
        ),
        UrgencyLevel.THIS_WEEK.value: (
            "this week",
            "few days",
            "couple days",
            "within a week",
            "by friday",
            "by monday",
        ),
        UrgencyLevel.THIS_MONTH.value: (
            "this month",
            "within a month",
            "next few weeks",
            "in two weeks",
            "in 2 weeks",
            "30 days",
        ),
        UrgencyLevel.FLEXIBLE.value: (
            "no rush",
            "flexible",
            "whenever",
            "later",
            "next quarter",
            "future",
        ),
    }

    DISQUALIFYING_KEYWORDS: Tuple[str, ...] = (
        "free only",
        "no budget",
        "just browsing",
        "not interested",
        "do not call",
        "wrong number",
        "spam",
        "scam",
        "remove me",
    )

    RISK_KEYWORDS: Tuple[str, ...] = (
        "password",
        "login",
        "credit card",
        "bank",
        "ssn",
        "social security",
        "private key",
        "secret",
        "otp",
        "verification code",
    )

    def __init__(
        self,
        config: Optional[Union[LeadQualifierConfig, Mapping[str, Any]]] = None,
        event_emitter: Optional[Callable[..., Any]] = None,
        audit_logger: Optional[Callable[..., Any]] = None,
        security_agent: Optional[Any] = None,
        agent_name: Optional[str] = None,
    ) -> None:
        super().__init__(agent_name=agent_name or self.agent_name)

        if isinstance(config, LeadQualifierConfig):
            self.config = config
        else:
            merged = dict(LEAD_QUALIFIER_DEFAULTS)
            if config:
                merged.update(dict(config))

            self.config = LeadQualifierConfig(
                minimum_hot_score=int(merged.get("minimum_hot_score", 75)),
                minimum_warm_score=int(merged.get("minimum_warm_score", 50)),
                minimum_budget_for_high_value=float(merged.get("minimum_budget_for_high_value", 1000.0)),
                minimum_budget_for_medium_value=float(merged.get("minimum_budget_for_medium_value", 300.0)),
                default_currency=_safe_str(merged.get("default_currency", "USD"), "USD").upper(),
                max_notes_length=int(merged.get("max_notes_length", 3000)),
                allow_memory_payload=bool(merged.get("allow_memory_payload", True)),
                allow_verification_payload=bool(merged.get("allow_verification_payload", True)),
                strict_contact_collection=bool(merged.get("strict_contact_collection", False)),
                default_required_fields=list(merged.get("default_required_fields", ["full_name", "phone_number", "service"])),
            )

        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.security_agent = security_agent
        self.logger = logging.getLogger("william.super_agents.call_agent.lead_qualifier")

    # =========================================================================
    # Required compatibility hooks
    # =========================================================================

    def _safe_result(
        self,
        success: bool = True,
        message: str = "OK",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        if isinstance(error, Exception):
            error_payload: Any = {
                "type": error.__class__.__name__,
                "message": str(error),
            }
        else:
            error_payload = error or message

        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error_payload,
            metadata=metadata or {},
        )

    def _validate_task_context(
        self,
        task_context: Mapping[str, Any],
        require_call_id: bool = False,
    ) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Required:
            - user_id
            - workspace_id

        Optional:
            - call_id
            - caller_id
            - agent_id
            - session_id
        """

        if not isinstance(task_context, Mapping):
            return self._error_result(
                message="Invalid task_context. Expected dict/mapping.",
                error="INVALID_TASK_CONTEXT",
            )

        user_id = _safe_str(task_context.get("user_id"))
        workspace_id = _safe_str(task_context.get("workspace_id"))
        call_id = _safe_str(task_context.get("call_id"))

        missing: List[str] = []
        if not user_id:
            missing.append("user_id")
        if not workspace_id:
            missing.append("workspace_id")
        if require_call_id and not call_id:
            missing.append("call_id")

        if missing:
            return self._error_result(
                message=f"Missing required task context fields: {', '.join(missing)}",
                error="MISSING_TASK_CONTEXT",
                metadata={"missing_fields": missing},
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "call_id": call_id or None,
                "caller_id": _safe_str(task_context.get("caller_id")) or None,
                "agent_id": _safe_str(task_context.get("agent_id")) or None,
                "session_id": _safe_str(task_context.get("session_id")) or None,
            },
            metadata={
                "scope_key": f"{user_id}:{workspace_id}",
                "validated_at": _utc_iso(),
            },
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
        task_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Determine if the requested qualification-side operation needs Security Agent.

        Lead qualification itself is not sensitive, but exporting contact data,
        writing CRM, sending follow-ups, or using secrets should require security.
        """

        action_clean = _safe_lower(action)
        payload = payload or {}
        payload_text = json.dumps(_redact_payload(payload), default=str).lower()

        sensitive_actions = {
            "send_message",
            "send_email",
            "send_whatsapp",
            "crm_write",
            "crm_update",
            "create_deal",
            "book_appointment",
            "start_call",
            "transfer_call",
            "delete_lead",
            "export_lead",
        }

        contains_risk_data = _contains_any(payload_text, self.RISK_KEYWORDS)
        requires = action_clean in sensitive_actions or contains_risk_data

        return self._safe_result(
            success=True,
            message="Security check requirement evaluated.",
            data={
                "required": requires,
                "action": action_clean,
                "contains_risk_data": contains_risk_data,
                "reason": (
                    "Sensitive action or risky data detected."
                    if requires
                    else "Lead qualification analysis does not require Security Agent approval."
                ),
            },
            metadata={
                "scope_key": self._scope_key(task_context or {}),
                "payload_hash": _hash_dict(payload) if isinstance(payload, Mapping) else None,
            },
        )

    def _request_security_approval(
        self,
        action: str,
        payload: Mapping[str, Any],
        task_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval when future integrations perform
        sensitive operations.

        This file never executes sensitive actions directly. If no Security Agent
        is attached, sensitive actions are blocked by default.
        """

        check = self._requires_security_check(action=action, payload=payload, task_context=task_context)
        if not check["success"]:
            return check

        if not check["data"].get("required"):
            return self._safe_result(
                success=True,
                message="Security approval is not required.",
                data={"approved": True, "required": False},
            )

        if self.security_agent is None:
            return self._safe_result(
                success=False,
                message="Security approval is required but no Security Agent is attached.",
                data={"approved": False, "required": True},
                error="SECURITY_AGENT_NOT_ATTACHED",
            )

        security_payload = {
            "action": action,
            "payload": _redact_payload(dict(payload)),
            "task_context": _redact_payload(dict(task_context)),
            "source_agent": self.agent_name,
            "timestamp": _utc_iso(),
        }

        try:
            for method_name in ("approve_action", "request_approval", "evaluate_action", "run"):
                method = getattr(self.security_agent, method_name, None)
                if not callable(method):
                    continue

                response = method(security_payload)  # type: ignore[misc]
                approved = self._parse_security_approved(response)
                return self._safe_result(
                    success=approved,
                    message="Security approval completed." if approved else "Security approval denied or unresolved.",
                    data={
                        "approved": approved,
                        "required": True,
                        "security_response": self._safe_security_response(response),
                    },
                    error=None if approved else "SECURITY_APPROVAL_DENIED",
                    metadata={"security_method": method_name},
                )

            return self._safe_result(
                success=False,
                message="Attached Security Agent has no compatible approval method.",
                data={"approved": False, "required": True},
                error="SECURITY_METHOD_MISSING",
            )

        except Exception as exc:
            self.logger.exception("Security approval failed.")
            return self._error_result(
                message="Security approval request failed.",
                error=exc,
                data={"approved": False, "required": True},
            )

    def _prepare_verification_payload(
        self,
        qualification: LeadQualification,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can use this to confirm the lead qualification was
        performed with correct user/workspace scope, no direct action execution,
        and clear scoring evidence.
        """

        return {
            "verification_type": "call_lead_qualification",
            "source_agent": self.agent_name,
            "module": self.module_name,
            "lead_id": qualification.lead_id,
            "user_id": qualification.user_id,
            "workspace_id": qualification.workspace_id,
            "call_id": qualification.call_id,
            "caller_id": qualification.caller_id,
            "status": qualification.qualification_status,
            "lead_temperature": qualification.lead_temperature,
            "score": qualification.score,
            "evidence": {
                "service": qualification.service,
                "service_confidence": qualification.service_confidence,
                "budget_level": qualification.budget_level,
                "urgency_level": qualification.urgency_level,
                "missing_fields": qualification.missing_fields,
                "disqualification_reasons": qualification.disqualification_reasons,
                "score_breakdown": qualification.score_breakdown,
            },
            "safe_execution": {
                "placed_call": False,
                "sent_message": False,
                "modified_crm": False,
                "booked_appointment": False,
                "requires_permission_for_next_action": self._next_action_requires_permission(
                    qualification.recommended_next_action
                ),
            },
            "created_at": _utc_iso(),
        }

    def _prepare_memory_payload(
        self,
        qualification: LeadQualification,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This should be stored only through Memory Agent permissions. The payload
        avoids secrets and includes useful sales/call context.
        """

        return {
            "memory_type": "call_lead_qualification",
            "source_agent": self.agent_name,
            "user_id": qualification.user_id,
            "workspace_id": qualification.workspace_id,
            "content": {
                "lead_id": qualification.lead_id,
                "call_id": qualification.call_id,
                "caller_id": qualification.caller_id,
                "contact": {
                    "full_name": qualification.contact.full_name,
                    "phone_number": qualification.contact.phone_number,
                    "email": qualification.contact.email,
                    "company_name": qualification.contact.company_name,
                    "website": qualification.contact.website,
                    "country": qualification.contact.country,
                    "preferred_contact_method": qualification.contact.preferred_contact_method,
                },
                "service": qualification.service,
                "budget_amount": qualification.budget_amount,
                "budget_currency": qualification.budget_currency,
                "budget_level": qualification.budget_level,
                "urgency_level": qualification.urgency_level,
                "lead_temperature": qualification.lead_temperature,
                "qualification_status": qualification.qualification_status,
                "recommended_next_action": qualification.recommended_next_action,
                "notes": qualification.notes,
            },
            "tags": [
                "call_agent",
                "lead_qualification",
                qualification.lead_temperature,
                qualification.qualification_status,
                qualification.service,
            ],
            "metadata": {
                "contains_secret": False,
                "safe_for_memory": True,
                "score": qualification.score,
                "created_at": qualification.created_at,
            },
        }

    def _emit_agent_event(
        self,
        event_type: str,
        task_context: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Emit event for dashboard, Master Agent, or observability pipeline."""

        event = {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "module": self.module_name,
            "timestamp": _utc_iso(),
            "task_context": _redact_payload(dict(task_context or {})),
            "payload": _redact_payload(dict(payload or {})),
        }

        try:
            if callable(self.event_emitter):
                self.event_emitter(event)
            else:
                self.logger.debug("Agent event: %s", event)

            return self._safe_result(
                success=True,
                message="Agent event emitted.",
                data={"event": event},
            )
        except Exception as exc:
            self.logger.exception("Failed to emit agent event.")
            return self._error_result(
                message="Failed to emit agent event.",
                error=exc,
                data={"event": event},
            )

    def _log_audit_event(
        self,
        event_type: str,
        task_context: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log audit event with SaaS user/workspace isolation."""

        context = dict(task_context or {})
        audit_event = {
            "audit_id": str(uuid.uuid4()),
            "event_type": event_type,
            "agent": self.agent_name,
            "module": self.module_name,
            "timestamp": _utc_iso(),
            "user_id": _safe_str(context.get("user_id")),
            "workspace_id": _safe_str(context.get("workspace_id")),
            "call_id": _safe_str(context.get("call_id")) or None,
            "caller_id": _safe_str(context.get("caller_id")) or None,
            "payload": _redact_payload(dict(payload or {})),
        }

        try:
            if callable(self.audit_logger):
                self.audit_logger(audit_event)
            else:
                self.logger.info("Audit event: %s", audit_event)

            return self._safe_result(
                success=True,
                message="Audit event logged.",
                data={"audit_event": audit_event},
            )
        except Exception as exc:
            self.logger.exception("Failed to log audit event.")
            return self._error_result(
                message="Failed to log audit event.",
                error=exc,
                data={"audit_event": audit_event},
            )

    # =========================================================================
    # Public API
    # =========================================================================

    def qualify_lead(
        self,
        task_context: Mapping[str, Any],
        caller_data: Optional[Mapping[str, Any]] = None,
        transcript: Optional[str] = None,
        notes: Optional[str] = None,
        required_fields: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        Qualify a caller/lead.

        Args:
            task_context:
                Must include user_id and workspace_id. call_id/caller_id optional.
            caller_data:
                Existing structured caller fields from receptionist/call listener.
            transcript:
                Call transcript or latest caller message.
            notes:
                Extra notes from call summarizer/receptionist.
            required_fields:
                Optional custom required fields.

        Returns:
            Structured qualification result with score, status, next question,
            memory payload, and verification payload.
        """

        validation = self._validate_task_context(task_context, require_call_id=False)
        if not validation["success"]:
            return validation

        caller_data = dict(caller_data or {})
        transcript_text = _safe_str(transcript)
        notes_text = _truncate(_safe_str(notes), self.config.max_notes_length)
        combined_text = _clean_whitespace(" ".join([transcript_text, notes_text, json.dumps(caller_data, default=str)]))

        try:
            contact_result = self.extract_contact_details(
                caller_data=caller_data,
                transcript=combined_text,
                task_context=task_context,
            )
            if not contact_result["success"]:
                return contact_result

            contact = contact_result["data"]["contact"]
            service, service_confidence = self._detect_service(caller_data=caller_data, text=combined_text)
            budget_amount, budget_currency = self._detect_budget(caller_data=caller_data, text=combined_text)
            budget_level = self._classify_budget(budget_amount)
            urgency_level = self._detect_urgency(caller_data=caller_data, text=combined_text)

            missing_fields = self._detect_missing_fields(
                contact=contact,
                service=service,
                budget_amount=budget_amount,
                urgency_level=urgency_level,
                required_fields=required_fields or self.config.default_required_fields,
            )

            disqualification_reasons = self._detect_disqualification_reasons(combined_text, budget_amount)
            qualifying_signals = self._detect_qualifying_signals(
                contact=contact,
                service=service,
                budget_amount=budget_amount,
                urgency_level=urgency_level,
                text=combined_text,
            )
            risk_flags = self._detect_risk_flags(combined_text)

            score_result = self.score_lead(
                task_context=task_context,
                contact=contact,
                service=service,
                service_confidence=service_confidence,
                budget_amount=budget_amount,
                budget_level=budget_level,
                urgency_level=urgency_level,
                missing_fields=missing_fields,
                disqualification_reasons=disqualification_reasons,
                risk_flags=risk_flags,
            )
            if not score_result["success"]:
                return score_result

            score = int(score_result["data"]["score"])
            score_breakdown = dict(score_result["data"]["score_breakdown"])
            lead_temperature = self._classify_temperature(score, disqualification_reasons, missing_fields)
            qualification_status = self._classify_status(
                lead_temperature=lead_temperature,
                missing_fields=missing_fields,
                disqualification_reasons=disqualification_reasons,
                risk_flags=risk_flags,
            )
            recommended_next_action = self._recommend_next_action(
                qualification_status=qualification_status,
                lead_temperature=lead_temperature,
                missing_fields=missing_fields,
                risk_flags=risk_flags,
            )
            next_question = self._build_next_question(
                missing_fields=missing_fields,
                service=service,
                lead_temperature=lead_temperature,
                qualification_status=qualification_status,
            )

            lead_id = self._make_lead_id(
                user_id=validation["data"]["user_id"],
                workspace_id=validation["data"]["workspace_id"],
                call_id=validation["data"].get("call_id"),
                phone_number=contact.phone_number,
            )

            qualification = LeadQualification(
                lead_id=lead_id,
                user_id=validation["data"]["user_id"],
                workspace_id=validation["data"]["workspace_id"],
                call_id=validation["data"].get("call_id"),
                caller_id=validation["data"].get("caller_id"),
                contact=contact,
                service=service,
                service_confidence=service_confidence,
                budget_amount=budget_amount,
                budget_currency=budget_currency,
                budget_level=budget_level,
                urgency_level=urgency_level,
                lead_temperature=lead_temperature,
                qualification_status=qualification_status,
                score=score,
                score_breakdown=score_breakdown,
                missing_fields=missing_fields,
                disqualification_reasons=disqualification_reasons,
                qualifying_signals=qualifying_signals,
                risk_flags=risk_flags,
                recommended_next_action=recommended_next_action,
                next_question=next_question,
                notes=notes_text,
                created_at=_utc_iso(),
                metadata={
                    "service_confidence": service_confidence,
                    "contact_quality": self._contact_quality(contact),
                    "input_hash": _hash_dict(
                        {
                            "caller_data": _redact_payload(caller_data),
                            "transcript": transcript_text[:500],
                            "notes": notes_text[:500],
                        }
                    ),
                    "strict_contact_collection": self.config.strict_contact_collection,
                },
            )

            verification_payload = (
                self._prepare_verification_payload(qualification)
                if self.config.allow_verification_payload
                else {}
            )
            memory_payload = (
                self._prepare_memory_payload(qualification)
                if self.config.allow_memory_payload
                else {}
            )

            self._emit_agent_event(
                event_type="lead.qualified",
                task_context=task_context,
                payload={
                    "lead_id": lead_id,
                    "score": score,
                    "lead_temperature": lead_temperature,
                    "qualification_status": qualification_status,
                    "service": service,
                    "missing_fields": missing_fields,
                },
            )

            self._log_audit_event(
                event_type="lead.qualification_completed",
                task_context=task_context,
                payload={
                    "lead_id": lead_id,
                    "score": score,
                    "lead_temperature": lead_temperature,
                    "qualification_status": qualification_status,
                    "service": service,
                    "risk_flags": risk_flags,
                },
            )

            return self._safe_result(
                success=True,
                message="Lead qualification completed.",
                data={
                    "lead_id": lead_id,
                    "qualification": self._qualification_to_dict(qualification),
                    "contact": asdict(contact),
                    "score": score,
                    "score_breakdown": score_breakdown,
                    "lead_temperature": lead_temperature,
                    "qualification_status": qualification_status,
                    "recommended_next_action": recommended_next_action,
                    "next_question": next_question,
                    "missing_fields": missing_fields,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "scope_key": self._scope_key(task_context),
                    "module": self.module_name,
                    "agent": self.agent_name,
                    "completed_at": _utc_iso(),
                },
            )

        except Exception as exc:
            self.logger.exception("Lead qualification failed.")
            self._log_audit_event(
                event_type="lead.qualification_failed",
                task_context=task_context,
                payload={"error": str(exc)},
            )
            return self._error_result(
                message="Lead qualification failed.",
                error=exc,
            )

    def update_qualification(
        self,
        task_context: Mapping[str, Any],
        existing_qualification: Mapping[str, Any],
        new_caller_data: Optional[Mapping[str, Any]] = None,
        new_transcript: Optional[str] = None,
        new_notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Re-qualify a lead by merging previous qualification data with new data.

        This is useful when Receptionist Mode asks one missing question at a time.
        """

        validation = self._validate_task_context(task_context, require_call_id=False)
        if not validation["success"]:
            return validation

        merged_data: Dict[str, Any] = {}

        previous_contact = existing_qualification.get("contact", {})
        if isinstance(previous_contact, Mapping):
            merged_data.update(previous_contact)

        previous_service = existing_qualification.get("service")
        if previous_service:
            merged_data["service"] = previous_service

        previous_budget = existing_qualification.get("budget_amount")
        if previous_budget:
            merged_data["budget"] = previous_budget

        if new_caller_data:
            merged_data.update(dict(new_caller_data))

        merged_notes = _clean_whitespace(
            " ".join(
                [
                    _safe_str(existing_qualification.get("notes")),
                    _safe_str(new_notes),
                ]
            )
        )

        return self.qualify_lead(
            task_context=task_context,
            caller_data=merged_data,
            transcript=new_transcript,
            notes=merged_notes,
        )

    def get_next_question(
        self,
        task_context: Mapping[str, Any],
        partial_lead: Optional[Mapping[str, Any]] = None,
        transcript: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Return only the next best qualification question.

        Good for live call flow where the Call Agent must ask one question at a time.
        """

        result = self.qualify_lead(
            task_context=task_context,
            caller_data=partial_lead or {},
            transcript=transcript,
        )
        if not result["success"]:
            return result

        return self._safe_result(
            success=True,
            message="Next qualification question prepared.",
            data={
                "next_question": result["data"].get("next_question"),
                "missing_fields": result["data"].get("missing_fields", []),
                "recommended_next_action": result["data"].get("recommended_next_action"),
                "qualification_status": result["data"].get("qualification_status"),
                "lead_temperature": result["data"].get("lead_temperature"),
            },
            metadata=result.get("metadata", {}),
        )

    def score_lead(
        self,
        task_context: Mapping[str, Any],
        contact: Union[LeadContactDetails, Mapping[str, Any]],
        service: str,
        service_confidence: float,
        budget_amount: Optional[float],
        budget_level: str,
        urgency_level: str,
        missing_fields: Optional[Sequence[str]] = None,
        disqualification_reasons: Optional[Sequence[str]] = None,
        risk_flags: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """
        Score a lead from 0 to 100.

        Score areas:
            - Contact completeness
            - Service clarity
            - Budget quality
            - Urgency
            - Intent/fit
            - Risk/disqualification penalties
        """

        validation = self._validate_task_context(task_context, require_call_id=False)
        if not validation["success"]:
            return validation

        if isinstance(contact, Mapping):
            contact_obj = LeadContactDetails(**{k: contact.get(k) for k in LeadContactDetails.__dataclass_fields__.keys()})
        else:
            contact_obj = contact

        missing = list(missing_fields or [])
        disqualified = list(disqualification_reasons or [])
        risks = list(risk_flags or [])

        breakdown: Dict[str, int] = {
            "contact": 0,
            "service": 0,
            "budget": 0,
            "urgency": 0,
            "fit": 0,
            "penalty": 0,
        }

        if contact_obj.full_name:
            breakdown["contact"] += 10
        if contact_obj.phone_number:
            breakdown["contact"] += 15
        if contact_obj.email:
            breakdown["contact"] += 5
        if contact_obj.company_name:
            breakdown["contact"] += 5
        if contact_obj.website:
            breakdown["contact"] += 5
        breakdown["contact"] = min(breakdown["contact"], 30)

        if service and service != CallService.UNKNOWN.value:
            breakdown["service"] = 15 if service_confidence >= 0.6 else 10
        else:
            breakdown["service"] = 0

        if budget_level == BudgetLevel.HIGH.value:
            breakdown["budget"] = 25
        elif budget_level == BudgetLevel.MEDIUM.value:
            breakdown["budget"] = 17
        elif budget_level == BudgetLevel.LOW.value:
            breakdown["budget"] = 7
        else:
            breakdown["budget"] = 0

        if urgency_level == UrgencyLevel.IMMEDIATE.value:
            breakdown["urgency"] = 15
        elif urgency_level == UrgencyLevel.THIS_WEEK.value:
            breakdown["urgency"] = 12
        elif urgency_level == UrgencyLevel.THIS_MONTH.value:
            breakdown["urgency"] = 8
        elif urgency_level == UrgencyLevel.FLEXIBLE.value:
            breakdown["urgency"] = 4
        else:
            breakdown["urgency"] = 0

        if service != CallService.UNKNOWN.value and not disqualified:
            breakdown["fit"] = 15
        elif service != CallService.UNKNOWN.value:
            breakdown["fit"] = 5

        penalty = 0
        penalty += len(missing) * 4
        penalty += len(disqualified) * 25
        penalty += len(risks) * 8
        breakdown["penalty"] = -min(penalty, 60)

        score = sum(breakdown.values())
        score = max(0, min(100, score))

        return self._safe_result(
            success=True,
            message="Lead score calculated.",
            data={
                "score": score,
                "score_breakdown": breakdown,
                "budget_amount": budget_amount,
                "budget_level": budget_level,
                "urgency_level": urgency_level,
                "service": service,
            },
            metadata={
                "scope_key": self._scope_key(task_context),
                "minimum_hot_score": self.config.minimum_hot_score,
                "minimum_warm_score": self.config.minimum_warm_score,
            },
        )

    def extract_contact_details(
        self,
        caller_data: Optional[Mapping[str, Any]] = None,
        transcript: Optional[str] = None,
        task_context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Extract and normalize caller contact details.

        This method does not store data. It only returns normalized values.
        """

        caller_data = dict(caller_data or {})
        text = _safe_str(transcript)
        combined = _clean_whitespace(" ".join([text, json.dumps(caller_data, default=str)]))

        full_name = (
            _safe_str(caller_data.get("full_name"))
            or _safe_str(caller_data.get("name"))
            or self._extract_name_from_text(combined)
        )

        phone_number = (
            _normalize_phone(caller_data.get("phone_number"))
            or _normalize_phone(caller_data.get("phone"))
            or _normalize_phone(caller_data.get("mobile"))
            or self._extract_phone_from_text(combined)
        )

        email = (
            _safe_str(caller_data.get("email"))
            or _extract_email(combined)
            or None
        )

        company_name = (
            _safe_str(caller_data.get("company_name"))
            or _safe_str(caller_data.get("company"))
            or _safe_str(caller_data.get("business_name"))
            or self._extract_company_from_text(combined)
        )

        website = (
            _safe_str(caller_data.get("website"))
            or _safe_str(caller_data.get("domain"))
            or _extract_website(combined)
            or None
        )

        contact = LeadContactDetails(
            full_name=full_name or None,
            phone_number=phone_number or None,
            email=email or None,
            company_name=company_name or None,
            website=website or None,
            country=_safe_str(caller_data.get("country")) or None,
            timezone=_safe_str(caller_data.get("timezone")) or None,
            preferred_contact_method=_safe_str(caller_data.get("preferred_contact_method")) or None,
        )

        return self._safe_result(
            success=True,
            message="Contact details extracted.",
            data={
                "contact": contact,
                "contact_dict": asdict(contact),
                "contact_quality": self._contact_quality(contact),
            },
            metadata={
                "scope_key": self._scope_key(task_context or {}),
                "extracted_at": _utc_iso(),
            },
        )

    def run(self, task: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        """
        BaseAgent-compatible router.

        Supported operations:
            - qualify_lead
            - update_qualification
            - get_next_question
            - score_lead
            - extract_contact_details
        """

        payload: Dict[str, Any] = dict(task or {})
        payload.update(kwargs)

        operation = _safe_lower(payload.get("operation") or "qualify_lead")
        task_context = payload.get("task_context") or payload.get("context") or {}

        try:
            if operation == "qualify_lead":
                return self.qualify_lead(
                    task_context=task_context,
                    caller_data=payload.get("caller_data"),
                    transcript=payload.get("transcript"),
                    notes=payload.get("notes"),
                    required_fields=payload.get("required_fields"),
                )

            if operation == "update_qualification":
                return self.update_qualification(
                    task_context=task_context,
                    existing_qualification=payload.get("existing_qualification") or {},
                    new_caller_data=payload.get("new_caller_data"),
                    new_transcript=payload.get("new_transcript"),
                    new_notes=payload.get("new_notes"),
                )

            if operation == "get_next_question":
                return self.get_next_question(
                    task_context=task_context,
                    partial_lead=payload.get("partial_lead") or payload.get("caller_data"),
                    transcript=payload.get("transcript"),
                )

            if operation == "extract_contact_details":
                return self.extract_contact_details(
                    caller_data=payload.get("caller_data"),
                    transcript=payload.get("transcript"),
                    task_context=task_context,
                )

            if operation == "score_lead":
                return self.score_lead(
                    task_context=task_context,
                    contact=payload.get("contact") or {},
                    service=_safe_str(payload.get("service"), CallService.UNKNOWN.value),
                    service_confidence=float(payload.get("service_confidence", 0.0)),
                    budget_amount=payload.get("budget_amount"),
                    budget_level=_safe_str(payload.get("budget_level"), BudgetLevel.UNKNOWN.value),
                    urgency_level=_safe_str(payload.get("urgency_level"), UrgencyLevel.UNKNOWN.value),
                    missing_fields=payload.get("missing_fields"),
                    disqualification_reasons=payload.get("disqualification_reasons"),
                    risk_flags=payload.get("risk_flags"),
                )

            return self._error_result(
                message=f"Unsupported LeadQualifier operation: {operation}",
                error="UNSUPPORTED_OPERATION",
                metadata={
                    "supported_operations": [
                        "qualify_lead",
                        "update_qualification",
                        "get_next_question",
                        "score_lead",
                        "extract_contact_details",
                    ]
                },
            )

        except Exception as exc:
            self.logger.exception("LeadQualifier.run failed.")
            return self._error_result(
                message="LeadQualifier operation failed.",
                error=exc,
                metadata={"operation": operation},
            )

    # =========================================================================
    # Internal qualification logic
    # =========================================================================

    def _detect_service(self, caller_data: Mapping[str, Any], text: str) -> Tuple[str, float]:
        explicit = _safe_lower(caller_data.get("service") or caller_data.get("requested_service"))
        if explicit:
            normalized = self._normalize_service(explicit)
            return normalized, 0.95 if normalized != CallService.UNKNOWN.value else 0.4

        lowered = text.lower()
        scores: Dict[str, int] = {}

        for service, keywords in self.SERVICE_KEYWORDS.items():
            score = 0
            for keyword in keywords:
                if keyword in lowered:
                    score += 2 if " " in keyword else 1
            if score:
                scores[service] = score

        if not scores:
            return CallService.UNKNOWN.value, 0.0

        best_service = max(scores, key=scores.get)
        best_score = scores[best_service]
        total_score = sum(scores.values())
        confidence = min(1.0, max(0.2, best_score / max(total_score, 1)))

        return best_service, round(confidence, 3)

    def _normalize_service(self, value: str) -> str:
        lowered = value.lower().strip()
        for service, keywords in self.SERVICE_KEYWORDS.items():
            if lowered == service:
                return service
            if any(keyword in lowered for keyword in keywords):
                return service
        return CallService.UNKNOWN.value

    def _detect_budget(self, caller_data: Mapping[str, Any], text: str) -> Tuple[Optional[float], str]:
        for key in ("budget_amount", "budget", "monthly_budget", "project_budget"):
            value = caller_data.get(key)
            if isinstance(value, (int, float)) and value > 0:
                return float(value), _safe_str(caller_data.get("budget_currency"), self.config.default_currency).upper()
            if isinstance(value, str) and value.strip():
                amount, currency = _extract_budget_amount(value)
                if amount:
                    return amount, _safe_str(caller_data.get("budget_currency"), currency).upper()

        amount, currency = _extract_budget_amount(text)
        return amount, currency or self.config.default_currency

    def _classify_budget(self, budget_amount: Optional[float]) -> str:
        if budget_amount is None:
            return BudgetLevel.UNKNOWN.value
        if budget_amount >= self.config.minimum_budget_for_high_value:
            return BudgetLevel.HIGH.value
        if budget_amount >= self.config.minimum_budget_for_medium_value:
            return BudgetLevel.MEDIUM.value
        return BudgetLevel.LOW.value

    def _detect_urgency(self, caller_data: Mapping[str, Any], text: str) -> str:
        explicit = _safe_lower(caller_data.get("urgency") or caller_data.get("timeline") or caller_data.get("deadline"))
        if explicit:
            normalized = self._normalize_urgency(explicit)
            if normalized != UrgencyLevel.UNKNOWN.value:
                return normalized

        lowered = text.lower()
        for urgency, keywords in self.URGENCY_KEYWORDS.items():
            if any(keyword in lowered for keyword in keywords):
                return urgency

        return UrgencyLevel.UNKNOWN.value

    def _normalize_urgency(self, value: str) -> str:
        lowered = value.lower().strip()
        if lowered in {item.value for item in UrgencyLevel}:
            return lowered
        for urgency, keywords in self.URGENCY_KEYWORDS.items():
            if any(keyword in lowered for keyword in keywords):
                return urgency
        return UrgencyLevel.UNKNOWN.value

    def _detect_missing_fields(
        self,
        contact: LeadContactDetails,
        service: str,
        budget_amount: Optional[float],
        urgency_level: str,
        required_fields: Sequence[str],
    ) -> List[str]:
        missing: List[str] = []

        for field_name in required_fields:
            normalized = field_name.strip().lower()

            if normalized in {"full_name", "name"} and not contact.full_name:
                missing.append("full_name")
            elif normalized in {"phone", "phone_number", "mobile"} and not contact.phone_number:
                missing.append("phone_number")
            elif normalized == "email" and not contact.email:
                missing.append("email")
            elif normalized in {"company", "company_name", "business_name"} and not contact.company_name:
                missing.append("company_name")
            elif normalized == "website" and not contact.website:
                missing.append("website")
            elif normalized in {"service", "requested_service"} and service == CallService.UNKNOWN.value:
                missing.append("service")
            elif normalized in {"budget", "budget_amount"} and budget_amount is None:
                missing.append("budget")
            elif normalized in {"urgency", "timeline"} and urgency_level == UrgencyLevel.UNKNOWN.value:
                missing.append("urgency")

        return list(dict.fromkeys(missing))

    def _detect_disqualification_reasons(self, text: str, budget_amount: Optional[float]) -> List[str]:
        lowered = text.lower()
        reasons: List[str] = []

        for keyword in self.DISQUALIFYING_KEYWORDS:
            if keyword in lowered:
                reasons.append(f"Caller mentioned '{keyword}'.")

        if budget_amount is not None and budget_amount <= 0:
            reasons.append("Budget is zero or invalid.")

        return reasons

    def _detect_qualifying_signals(
        self,
        contact: LeadContactDetails,
        service: str,
        budget_amount: Optional[float],
        urgency_level: str,
        text: str,
    ) -> List[str]:
        signals: List[str] = []

        if contact.phone_number:
            signals.append("Phone number captured.")
        if contact.full_name:
            signals.append("Full name captured.")
        if contact.company_name:
            signals.append("Business/company name captured.")
        if contact.website:
            signals.append("Website/domain captured.")
        if service != CallService.UNKNOWN.value:
            signals.append(f"Requested service identified: {service}.")
        if budget_amount is not None:
            signals.append("Budget amount mentioned.")
        if urgency_level in {UrgencyLevel.IMMEDIATE.value, UrgencyLevel.THIS_WEEK.value}:
            signals.append(f"Strong urgency detected: {urgency_level}.")
        if _contains_any(text, ("ready", "interested", "need", "looking for", "want to start", "call me")):
            signals.append("Buyer intent language detected.")

        return signals

    def _detect_risk_flags(self, text: str) -> List[str]:
        lowered = text.lower()
        flags: List[str] = []

        for keyword in self.RISK_KEYWORDS:
            if keyword in lowered:
                flags.append(f"Sensitive data/risk keyword detected: {keyword}")

        return flags

    def _classify_temperature(
        self,
        score: int,
        disqualification_reasons: Sequence[str],
        missing_fields: Sequence[str],
    ) -> str:
        if disqualification_reasons:
            return LeadTemperature.UNQUALIFIED.value

        if self.config.strict_contact_collection and ("full_name" in missing_fields or "phone_number" in missing_fields):
            return LeadTemperature.UNKNOWN.value

        if score >= self.config.minimum_hot_score:
            return LeadTemperature.HOT.value
        if score >= self.config.minimum_warm_score:
            return LeadTemperature.WARM.value
        if score > 0:
            return LeadTemperature.COLD.value
        return LeadTemperature.UNKNOWN.value

    def _classify_status(
        self,
        lead_temperature: str,
        missing_fields: Sequence[str],
        disqualification_reasons: Sequence[str],
        risk_flags: Sequence[str],
    ) -> str:
        if disqualification_reasons:
            return QualificationStatus.DISQUALIFIED.value

        if risk_flags:
            return QualificationStatus.PENDING_REVIEW.value

        if missing_fields:
            return QualificationStatus.NEEDS_MORE_INFO.value

        if lead_temperature in {LeadTemperature.HOT.value, LeadTemperature.WARM.value}:
            return QualificationStatus.QUALIFIED.value

        return QualificationStatus.NEEDS_MORE_INFO.value

    def _recommend_next_action(
        self,
        qualification_status: str,
        lead_temperature: str,
        missing_fields: Sequence[str],
        risk_flags: Sequence[str],
    ) -> str:
        if risk_flags:
            return "route_to_security_review"

        if qualification_status == QualificationStatus.DISQUALIFIED.value:
            return "politely_close_call"

        if missing_fields:
            return "ask_next_qualification_question"

        if lead_temperature == LeadTemperature.HOT.value:
            return "handoff_to_specialist_or_book_appointment"

        if lead_temperature == LeadTemperature.WARM.value:
            return "offer_specialist_callback"

        if lead_temperature == LeadTemperature.COLD.value:
            return "nurture_or_collect_more_context"

        return "collect_basic_contact_details"

    def _build_next_question(
        self,
        missing_fields: Sequence[str],
        service: str,
        lead_temperature: str,
        qualification_status: str,
    ) -> Optional[str]:
        if qualification_status == QualificationStatus.DISQUALIFIED.value:
            return None

        ordered_questions = {
            "full_name": "May I have your full name, please?",
            "phone_number": "What is the best phone number for our specialist to call you back?",
            "service": "Which service are you interested in: website, SEO, ads, social media, or AI automation?",
            "budget": "Do you have a budget range in mind for this project?",
            "urgency": "When would you like to get this started?",
            "company_name": "What is your business or company name?",
            "website": "Do you already have a website or domain?",
            "email": "What email address should we use for sending details if needed?",
        }

        for field_name in missing_fields:
            if field_name in ordered_questions:
                return ordered_questions[field_name]

        if service == CallService.UNKNOWN.value:
            return ordered_questions["service"]

        if lead_temperature in {LeadTemperature.HOT.value, LeadTemperature.WARM.value}:
            return "Would you like to receive a call from our specialist to discuss this in more detail?"

        return "Could you tell me a little more about what you need help with?"

    def _contact_quality(self, contact: LeadContactDetails) -> str:
        has_name = bool(contact.full_name)
        has_phone = bool(contact.phone_number)
        has_email = bool(contact.email)

        if has_name and has_phone:
            return ContactQuality.COMPLETE.value

        if has_phone or has_email or has_name:
            return ContactQuality.PARTIAL.value

        return ContactQuality.MISSING.value

    def _extract_name_from_text(self, text: str) -> Optional[str]:
        patterns = [
            r"\bmy name is\s+([A-Za-z][A-Za-z .'\-]{1,80})",
            r"\bi am\s+([A-Za-z][A-Za-z .'\-]{1,80})",
            r"\bthis is\s+([A-Za-z][A-Za-z .'\-]{1,80})",
            r"\bname[:\s]+([A-Za-z][A-Za-z .'\-]{1,80})",
        ]

        for pattern in patterns:
            match = re.search(pattern, text or "", flags=re.IGNORECASE)
            if match:
                name = _clean_whitespace(match.group(1))
                name = re.split(r"\b(?:and|from|with|calling|phone|number|email)\b", name, flags=re.IGNORECASE)[0]
                name = _clean_whitespace(name).strip(" .,-")
                if 2 <= len(name) <= 80:
                    return name

        return None

    def _extract_phone_from_text(self, text: str) -> Optional[str]:
        patterns = [
            r"(\+?\d[\d\s().\-]{7,}\d)",
        ]

        for pattern in patterns:
            match = re.search(pattern, text or "")
            if match:
                phone = _normalize_phone(match.group(1))
                if phone:
                    return phone

        return None

    def _extract_company_from_text(self, text: str) -> Optional[str]:
        patterns = [
            r"\bcompany is\s+([A-Za-z0-9 &.'\-]{2,100})",
            r"\bbusiness is\s+([A-Za-z0-9 &.'\-]{2,100})",
            r"\bfrom\s+([A-Za-z0-9 &.'\-]{2,100})",
            r"\bcompany[:\s]+([A-Za-z0-9 &.'\-]{2,100})",
        ]

        for pattern in patterns:
            match = re.search(pattern, text or "", flags=re.IGNORECASE)
            if match:
                company = _clean_whitespace(match.group(1))
                company = re.split(r"\b(?:and|my|phone|number|email|website|budget)\b", company, flags=re.IGNORECASE)[0]
                company = _clean_whitespace(company).strip(" .,-")
                if 2 <= len(company) <= 100:
                    return company

        return None

    def _make_lead_id(
        self,
        user_id: str,
        workspace_id: str,
        call_id: Optional[str],
        phone_number: Optional[str],
    ) -> str:
        seed = f"{user_id}:{workspace_id}:{call_id or ''}:{phone_number or ''}:{time.time_ns()}:{uuid.uuid4()}"
        digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:20]
        return f"lead_{digest}"

    def _qualification_to_dict(self, qualification: LeadQualification) -> Dict[str, Any]:
        data = asdict(qualification)
        data["contact"] = asdict(qualification.contact)
        return data

    def _scope_key(self, task_context: Mapping[str, Any]) -> str:
        user_id = _safe_str(task_context.get("user_id"))
        workspace_id = _safe_str(task_context.get("workspace_id"))
        if not user_id or not workspace_id:
            return ""
        return f"{user_id}:{workspace_id}"

    def _next_action_requires_permission(self, action: str) -> bool:
        return action in {
            "handoff_to_specialist_or_book_appointment",
            "offer_specialist_callback",
            "route_to_security_review",
        }

    def _parse_security_approved(self, response: Any) -> bool:
        if isinstance(response, bool):
            return response

        if isinstance(response, Mapping):
            if response.get("approved") is True:
                return True
            if response.get("allowed") is True:
                return True
            data = response.get("data")
            if isinstance(data, Mapping):
                if data.get("approved") is True:
                    return True
                if data.get("allowed") is True:
                    return True

            decision = _safe_lower(response.get("decision"))
            if decision in {"approved", "approve", "allow", "allowed"}:
                return True

        return False

    def _safe_security_response(self, response: Any) -> Any:
        if isinstance(response, Mapping):
            allowed_keys = {"success", "message", "approved", "allowed", "decision", "status", "error", "metadata"}
            return _redact_payload({str(k): v for k, v in response.items() if str(k) in allowed_keys})
        if isinstance(response, (str, int, float, bool)) or response is None:
            return response
        return type(response).__name__


__all__ = [
    "LeadQualifier",
    "LeadQualifierConfig",
    "LeadQualification",
    "LeadContactDetails",
    "LeadTemperature",
    "UrgencyLevel",
    "BudgetLevel",
    "ContactQuality",
    "QualificationStatus",
    "CallService",
]