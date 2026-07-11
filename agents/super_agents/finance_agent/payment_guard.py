"""
agents/super_agents/finance_agent/payment_guard.py

FinancePaymentGuard
-------------------
Finance-specific payment safety and Security Agent handoff helper for the
William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    - Validate payment/transaction-related requests before any sensitive action.
    - Classify payment risk.
    - Prepare Security Agent approval payloads.
    - Enforce SaaS user/workspace isolation.
    - Produce Verification Agent payloads after completed guard checks.
    - Prepare Memory Agent-compatible context for useful finance safety history.
    - Never execute, submit, send, transfer, debit, charge, refund, or move money.

Architecture Compatibility:
    - Import-safe even if BaseAgent, Security Agent, Registry, Router, or future
      modules do not exist yet.
    - Structured result format:
        {
            "success": bool,
            "message": str,
            "data": dict,
            "error": Optional[str],
            "metadata": dict
        }
    - Compatible with Master Agent routing, Agent Registry, Agent Loader,
      Dashboard/API integration, Audit Logs, Memory Agent, and Verification Agent.

Safety Rule:
    This file only performs safety evaluation and Security Agent handoff.
    It must never perform a real financial transaction.
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
from decimal import Decimal, InvalidOperation
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps payment_guard.py import-safe before the full William/Jarvis
        platform is available. In production, the real BaseAgent should provide
        shared logging, routing, permissions, task context, registry metadata,
        and lifecycle hooks.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())

        def emit_event(self, *args: Any, **kwargs: Any) -> None:
            return None

        def log_audit_event(self, *args: Any, **kwargs: Any) -> None:
            return None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Enums and constants
# ---------------------------------------------------------------------------

class PaymentRiskLevel(str, Enum):
    """Normalized finance payment risk levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PaymentGuardDecision(str, Enum):
    """Decision produced by FinancePaymentGuard."""

    ALLOW_DRAFT_ONLY = "allow_draft_only"
    REQUIRE_SECURITY_APPROVAL = "require_security_approval"
    BLOCK = "block"
    NEED_MORE_INFORMATION = "need_more_information"


class PaymentActionType(str, Enum):
    """
    Payment-related action categories.

    All action types are evaluated only. This file does not execute any action.
    """

    INVOICE_PAYMENT = "invoice_payment"
    VENDOR_PAYMENT = "vendor_payment"
    CLIENT_REFUND = "client_refund"
    SUBSCRIPTION_PAYMENT = "subscription_payment"
    PAYROLL_PAYMENT = "payroll_payment"
    TAX_PAYMENT = "tax_payment"
    BANK_TRANSFER = "bank_transfer"
    CARD_PAYMENT = "card_payment"
    WALLET_TRANSFER = "wallet_transfer"
    CRYPTO_TRANSFER = "crypto_transfer"
    INTERNATIONAL_TRANSFER = "international_transfer"
    PAYMENT_LINK = "payment_link"
    PAYMENT_METHOD_UPDATE = "payment_method_update"
    PAYMENT_DRAFT = "payment_draft"
    UNKNOWN = "unknown"


class SecurityApprovalStatus(str, Enum):
    """Security Agent handoff status values."""

    NOT_REQUIRED = "not_required"
    REQUIRED = "required"
    REQUESTED = "requested"
    APPROVED = "approved"
    DENIED = "denied"
    UNAVAILABLE = "unavailable"


class PaymentGuardEventType(str, Enum):
    """Events emitted for dashboard, analytics, and audit pipelines."""

    GUARD_STARTED = "finance.payment_guard.started"
    GUARD_COMPLETED = "finance.payment_guard.completed"
    GUARD_BLOCKED = "finance.payment_guard.blocked"
    SECURITY_HANDOFF_PREPARED = "finance.payment_guard.security_handoff_prepared"
    SECURITY_APPROVAL_REQUESTED = "finance.payment_guard.security_approval_requested"
    VERIFICATION_PAYLOAD_PREPARED = "finance.payment_guard.verification_payload_prepared"


SUPPORTED_CURRENCIES = {
    "USD", "EUR", "GBP", "PKR", "AED", "SAR", "CAD", "AUD", "NZD",
    "INR", "JPY", "CNY", "CHF", "SGD", "HKD", "ZAR"
}

DEFAULT_HIGH_VALUE_THRESHOLD = Decimal("1000.00")
DEFAULT_CRITICAL_VALUE_THRESHOLD = Decimal("10000.00")

DEFAULT_ALLOWED_DRAFT_ACTIONS = {
    PaymentActionType.PAYMENT_DRAFT.value,
    PaymentActionType.INVOICE_PAYMENT.value,
    PaymentActionType.VENDOR_PAYMENT.value,
    PaymentActionType.CLIENT_REFUND.value,
    PaymentActionType.SUBSCRIPTION_PAYMENT.value,
    PaymentActionType.TAX_PAYMENT.value,
}

DEFAULT_SENSITIVE_ACTIONS = {
    PaymentActionType.INVOICE_PAYMENT.value,
    PaymentActionType.VENDOR_PAYMENT.value,
    PaymentActionType.CLIENT_REFUND.value,
    PaymentActionType.SUBSCRIPTION_PAYMENT.value,
    PaymentActionType.PAYROLL_PAYMENT.value,
    PaymentActionType.TAX_PAYMENT.value,
    PaymentActionType.BANK_TRANSFER.value,
    PaymentActionType.CARD_PAYMENT.value,
    PaymentActionType.WALLET_TRANSFER.value,
    PaymentActionType.CRYPTO_TRANSFER.value,
    PaymentActionType.INTERNATIONAL_TRANSFER.value,
    PaymentActionType.PAYMENT_LINK.value,
    PaymentActionType.PAYMENT_METHOD_UPDATE.value,
}

DANGEROUS_EXECUTION_PHRASES = {
    "send payment",
    "make payment",
    "transfer now",
    "pay now",
    "submit payment",
    "charge card",
    "debit account",
    "withdraw",
    "wire money",
    "send funds",
    "release funds",
    "execute transfer",
    "complete transfer",
    "process refund",
    "send crypto",
    "broadcast transaction",
    "approve without review",
}

SUSPICIOUS_PAYMENT_PATTERNS = {
    "urgent": re.compile(r"\burgent\b|\basap\b|\bimmediately\b", re.IGNORECASE),
    "secrecy": re.compile(r"\bsecret\b|\bdo not tell\b|\bkeep this private\b|\bconfidential transfer\b", re.IGNORECASE),
    "gift_card": re.compile(r"\bgift\s*card\b|\bitunes\b|\bgoogle play card\b|\bsteam card\b", re.IGNORECASE),
    "crypto": re.compile(r"\bcrypto\b|\bbitcoin\b|\bbtc\b|\beth\b|\busdt\b|\bwallet address\b", re.IGNORECASE),
    "wire": re.compile(r"\bwire transfer\b|\bswift\b|\biban\b|\brouting number\b", re.IGNORECASE),
    "new_payee": re.compile(r"\bnew vendor\b|\bnew payee\b|\bfirst time\b|\bnew beneficiary\b", re.IGNORECASE),
    "payment_method_change": re.compile(r"\bchange bank\b|\bnew account\b|\bupdate payment method\b|\bchanged account\b", re.IGNORECASE),
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class PaymentGuardConfig:
    """
    Runtime configuration for FinancePaymentGuard.

    Can be loaded from a future config.py, database, workspace settings,
    dashboard settings, or SaaS tenant policy.
    """

    high_value_threshold: Decimal = DEFAULT_HIGH_VALUE_THRESHOLD
    critical_value_threshold: Decimal = DEFAULT_CRITICAL_VALUE_THRESHOLD
    allowed_currencies: set = field(default_factory=lambda: set(SUPPORTED_CURRENCIES))
    sensitive_actions: set = field(default_factory=lambda: set(DEFAULT_SENSITIVE_ACTIONS))
    allowed_draft_actions: set = field(default_factory=lambda: set(DEFAULT_ALLOWED_DRAFT_ACTIONS))
    require_security_for_all_sensitive_actions: bool = True
    require_security_for_new_payees: bool = True
    require_security_for_international: bool = True
    require_security_for_crypto: bool = True
    block_real_execution: bool = True
    allow_draft_only_mode: bool = True
    max_description_length: int = 5000
    max_metadata_size_bytes: int = 65536
    audit_enabled: bool = True
    event_emission_enabled: bool = True
    memory_payload_enabled: bool = True
    verification_payload_enabled: bool = True


@dataclass
class PaymentGuardContext:
    """
    SaaS context required for every user/workspace-specific guard check.
    """

    user_id: str
    workspace_id: str
    request_id: str
    role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    source: Optional[str] = None
    session_id: Optional[str] = None
    ip_address_hash: Optional[str] = None
    user_agent_hash: Optional[str] = None


@dataclass
class PaymentGuardRequest:
    """
    Normalized payment safety request.

    The request may originate from Finance Agent, Master Agent, Dashboard/API,
    Workflow Agent, Invoice Manager, Transaction Preparer, or a future plugin.
    """

    action_type: str = PaymentActionType.UNKNOWN.value
    amount: Optional[Decimal] = None
    currency: Optional[str] = None
    payee_name: Optional[str] = None
    payee_id: Optional[str] = None
    payer_name: Optional[str] = None
    payer_id: Optional[str] = None
    invoice_id: Optional[str] = None
    transaction_draft_id: Optional[str] = None
    payment_method_type: Optional[str] = None
    destination_country: Optional[str] = None
    origin_country: Optional[str] = None
    description: Optional[str] = None
    external_reference: Optional[str] = None
    is_new_payee: bool = False
    is_payment_method_change: bool = False
    is_international: bool = False
    is_crypto: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PaymentRiskFinding:
    """Individual finding from risk analysis."""

    code: str
    message: str
    severity: PaymentRiskLevel
    field_name: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PaymentGuardEvaluation:
    """Structured internal evaluation object."""

    decision: PaymentGuardDecision
    risk_level: PaymentRiskLevel
    security_status: SecurityApprovalStatus
    findings: List[PaymentRiskFinding]
    normalized_request: PaymentGuardRequest
    context: PaymentGuardContext
    security_payload: Optional[Dict[str, Any]] = None
    verification_payload: Optional[Dict[str, Any]] = None
    memory_payload: Optional[Dict[str, Any]] = None
    audit_payload: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def _safe_uuid(prefix: str = "pg") -> str:
    """Create a safe unique ID for guard operations."""

    return f"{prefix}_{uuid.uuid4().hex}"


def _hash_value(value: Optional[str]) -> Optional[str]:
    """Hash sensitive values for logs/audit records."""

    if not value:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_str(value: Any, max_length: int = 500) -> str:
    """Convert any value to a safe string with truncation."""

    try:
        text = str(value)
    except Exception:
        text = "<unprintable>"
    if len(text) > max_length:
        return text[: max_length - 3] + "..."
    return text


def _json_size_bytes(payload: Mapping[str, Any]) -> int:
    """Approximate JSON byte size for metadata safety limits."""

    try:
        return len(json.dumps(payload, default=str).encode("utf-8"))
    except Exception:
        return 10**9


def _decimal_or_none(value: Any) -> Optional[Decimal]:
    """Convert amount to Decimal safely."""

    if value is None or value == "":
        return None
    if isinstance(value, Decimal):
        return value
    try:
        return Decimal(str(value))
    except (InvalidOperation, ValueError, TypeError):
        return None


def _normalize_currency(currency: Optional[str]) -> Optional[str]:
    """Normalize ISO-like currency code."""

    if not currency:
        return None
    return str(currency).strip().upper()


def _normalize_action_type(action_type: Optional[str]) -> str:
    """Normalize action type into known enum value or unknown."""

    if not action_type:
        return PaymentActionType.UNKNOWN.value

    text = str(action_type).strip().lower().replace("-", "_").replace(" ", "_")

    aliases = {
        "invoice": PaymentActionType.INVOICE_PAYMENT.value,
        "pay_invoice": PaymentActionType.INVOICE_PAYMENT.value,
        "vendor": PaymentActionType.VENDOR_PAYMENT.value,
        "vendor_bill": PaymentActionType.VENDOR_PAYMENT.value,
        "refund": PaymentActionType.CLIENT_REFUND.value,
        "client_refund": PaymentActionType.CLIENT_REFUND.value,
        "subscription": PaymentActionType.SUBSCRIPTION_PAYMENT.value,
        "payroll": PaymentActionType.PAYROLL_PAYMENT.value,
        "tax": PaymentActionType.TAX_PAYMENT.value,
        "bank": PaymentActionType.BANK_TRANSFER.value,
        "bank_transfer": PaymentActionType.BANK_TRANSFER.value,
        "wire": PaymentActionType.BANK_TRANSFER.value,
        "card": PaymentActionType.CARD_PAYMENT.value,
        "wallet": PaymentActionType.WALLET_TRANSFER.value,
        "crypto": PaymentActionType.CRYPTO_TRANSFER.value,
        "international": PaymentActionType.INTERNATIONAL_TRANSFER.value,
        "payment_link": PaymentActionType.PAYMENT_LINK.value,
        "payment_method": PaymentActionType.PAYMENT_METHOD_UPDATE.value,
        "draft": PaymentActionType.PAYMENT_DRAFT.value,
        "payment_draft": PaymentActionType.PAYMENT_DRAFT.value,
    }

    if text in aliases:
        return aliases[text]

    try:
        return PaymentActionType(text).value
    except ValueError:
        return PaymentActionType.UNKNOWN.value


def _redact_payment_request(request: PaymentGuardRequest) -> Dict[str, Any]:
    """
    Redact payment request for logs, audit, memory, and verification records.

    Avoid storing full payment method data, full account numbers, card numbers,
    wallet private details, or raw sensitive metadata.
    """

    raw = asdict(request)

    sensitive_keys = {
        "account_number",
        "routing_number",
        "iban",
        "swift",
        "card_number",
        "card_cvv",
        "cvv",
        "secret",
        "private_key",
        "seed_phrase",
        "password",
        "token",
        "api_key",
        "auth",
    }

    def redact_value(key: str, value: Any) -> Any:
        lowered = key.lower()
        if any(s in lowered for s in sensitive_keys):
            return "[REDACTED]"
        if isinstance(value, str) and len(value) > 120:
            return value[:117] + "..."
        return value

    redacted: Dict[str, Any] = {}
    for key, value in raw.items():
        if key == "metadata" and isinstance(value, dict):
            safe_meta: Dict[str, Any] = {}
            for meta_key, meta_value in value.items():
                safe_meta[str(meta_key)] = redact_value(str(meta_key), meta_value)
            redacted[key] = safe_meta
        elif isinstance(value, Decimal):
            redacted[key] = str(value)
        else:
            redacted[key] = redact_value(key, value)

    if redacted.get("payee_id"):
        redacted["payee_id_hash"] = _hash_value(str(redacted["payee_id"]))
        redacted.pop("payee_id", None)

    if redacted.get("payer_id"):
        redacted["payer_id_hash"] = _hash_value(str(redacted["payer_id"]))
        redacted.pop("payer_id", None)

    return redacted


# ---------------------------------------------------------------------------
# FinancePaymentGuard
# ---------------------------------------------------------------------------

class FinancePaymentGuard(BaseAgent):
    """
    Finance-specific payment safety and Security Agent handoff.

    This guard is used by:
        - Finance Agent
        - Transaction Preparer
        - Invoice Manager
        - Budget Tracker
        - Master Agent
        - Dashboard/API
        - Workflow Agent
        - Future finance plugins

    This class never executes financial actions. It only validates, evaluates,
    blocks unsafe requests, and prepares handoff payloads for Security Agent.
    """

    agent_name = "FinancePaymentGuard"
    agent_type = "finance_payment_guard"
    version = "1.0.0"

    def __init__(
        self,
        config: Optional[PaymentGuardConfig] = None,
        security_client: Optional[Any] = None,
        event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize FinancePaymentGuard.

        Args:
            config:
                Optional PaymentGuardConfig. If omitted, safe defaults are used.
            security_client:
                Optional Security Agent adapter/client. Supported methods:
                    - request_approval(payload)
                    - evaluate_sensitive_action(payload)
                    - create_approval_request(payload)
            event_emitter:
                Optional callable for dashboard/event bus integration.
            audit_logger:
                Optional callable for audit log persistence.
            logger_instance:
                Optional logger override.
            **kwargs:
                Passed to BaseAgent when available.
        """

        try:
            super().__init__(agent_name=self.agent_name, agent_id=self.agent_type, **kwargs)
        except TypeError:
            super().__init__()

        self.config = config or PaymentGuardConfig()
        self.security_client = security_client
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.logger = logger_instance or logger

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    def evaluate_payment_request(
        self,
        payment_request: Union[PaymentGuardRequest, Mapping[str, Any]],
        task_context: Mapping[str, Any],
        request_security: bool = True,
    ) -> Dict[str, Any]:
        """
        Evaluate a payment-related request and optionally prepare/request
        Security Agent approval.

        This is the main public method used by Finance Agent, Master Agent,
        Dashboard/API, and future finance plugins.

        Args:
            payment_request:
                PaymentGuardRequest or dict-like payload.
            task_context:
                Must include user_id and workspace_id for SaaS isolation.
            request_security:
                If True, attempt Security Agent handoff when required.
                If Security Agent is unavailable, the result remains safe and
                no payment execution is allowed.

        Returns:
            Structured dict with success, message, data, error, metadata.
        """

        operation_id = _safe_uuid("payment_guard")
        started_at = _utc_now_iso()

        try:
            context_result = self._validate_task_context(task_context, operation_id=operation_id)
            if not context_result["success"]:
                return context_result

            context = context_result["data"]["context"]

            self._emit_agent_event(
                PaymentGuardEventType.GUARD_STARTED.value,
                {
                    "operation_id": operation_id,
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                    "started_at": started_at,
                },
            )

            normalized = self._normalize_payment_request(payment_request)
            validation_findings = self._validate_payment_request(normalized)
            risk_findings = self._analyze_payment_risk(normalized)
            findings = validation_findings + risk_findings

            risk_level = self._calculate_risk_level(normalized, findings)
            decision = self._decide(normalized, risk_level, findings)

            security_payload: Optional[Dict[str, Any]] = None
            security_status = SecurityApprovalStatus.NOT_REQUIRED

            if self._requires_security_check(normalized, risk_level, decision):
                security_status = SecurityApprovalStatus.REQUIRED
                security_payload = self._build_security_handoff_payload(
                    context=context,
                    payment_request=normalized,
                    risk_level=risk_level,
                    decision=decision,
                    findings=findings,
                    operation_id=operation_id,
                )

                self._emit_agent_event(
                    PaymentGuardEventType.SECURITY_HANDOFF_PREPARED.value,
                    {
                        "operation_id": operation_id,
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                        "risk_level": risk_level.value,
                        "decision": decision.value,
                    },
                )

                if request_security:
                    security_result = self._request_security_approval(security_payload)
                    security_status = security_result["data"].get(
                        "security_status",
                        SecurityApprovalStatus.UNAVAILABLE.value,
                    )

                    if security_status == SecurityApprovalStatus.DENIED.value:
                        decision = PaymentGuardDecision.BLOCK
                        findings.append(
                            PaymentRiskFinding(
                                code="security_denied",
                                message="Security Agent denied the payment-related request.",
                                severity=PaymentRiskLevel.CRITICAL,
                                field_name=None,
                                details={"security_result": security_result.get("data", {})},
                            )
                        )

                    self._emit_agent_event(
                        PaymentGuardEventType.SECURITY_APPROVAL_REQUESTED.value,
                        {
                            "operation_id": operation_id,
                            "user_id": context.user_id,
                            "workspace_id": context.workspace_id,
                            "security_status": security_status,
                        },
                    )

            verification_payload = self._prepare_verification_payload(
                context=context,
                payment_request=normalized,
                risk_level=risk_level,
                decision=decision,
                security_status=security_status,
                findings=findings,
                operation_id=operation_id,
            )

            memory_payload = self._prepare_memory_payload(
                context=context,
                payment_request=normalized,
                risk_level=risk_level,
                decision=decision,
                findings=findings,
                operation_id=operation_id,
            )

            audit_payload = self._build_audit_payload(
                context=context,
                payment_request=normalized,
                risk_level=risk_level,
                decision=decision,
                security_status=security_status,
                findings=findings,
                operation_id=operation_id,
            )

            self._log_audit_event(audit_payload)

            evaluation = PaymentGuardEvaluation(
                decision=decision,
                risk_level=risk_level,
                security_status=SecurityApprovalStatus(str(security_status)),
                findings=findings,
                normalized_request=normalized,
                context=context,
                security_payload=security_payload,
                verification_payload=verification_payload,
                memory_payload=memory_payload,
                audit_payload=audit_payload,
            )

            self._emit_agent_event(
                PaymentGuardEventType.GUARD_COMPLETED.value,
                {
                    "operation_id": operation_id,
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "risk_level": risk_level.value,
                    "decision": decision.value,
                    "completed_at": _utc_now_iso(),
                },
            )

            if decision == PaymentGuardDecision.BLOCK:
                self._emit_agent_event(
                    PaymentGuardEventType.GUARD_BLOCKED.value,
                    {
                        "operation_id": operation_id,
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                        "risk_level": risk_level.value,
                    },
                )

            return self._safe_result(
                success=True,
                message=self._decision_message(decision, risk_level, security_status),
                data=self._evaluation_to_data(evaluation),
                metadata={
                    "operation_id": operation_id,
                    "agent": self.agent_name,
                    "agent_type": self.agent_type,
                    "version": self.version,
                    "started_at": started_at,
                    "completed_at": _utc_now_iso(),
                    "safety_note": "No financial transaction was executed by FinancePaymentGuard.",
                },
            )

        except Exception as exc:
            self.logger.exception("FinancePaymentGuard evaluation failed.")
            return self._error_result(
                message="Payment guard evaluation failed safely. No financial action was executed.",
                error=str(exc),
                metadata={
                    "operation_id": operation_id,
                    "agent": self.agent_name,
                    "agent_type": self.agent_type,
                    "version": self.version,
                    "failed_at": _utc_now_iso(),
                },
            )

    def guard_payment_action(
        self,
        action_payload: Mapping[str, Any],
        task_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Guard a payment action before execution by another component.

        This method intentionally never executes the action. It returns whether
        the downstream caller may continue preparing a draft or must stop and
        wait for Security Agent approval.

        Args:
            action_payload:
                Dict containing payment request details.
            task_context:
                SaaS context with user_id and workspace_id.

        Returns:
            Structured result.
        """

        result = self.evaluate_payment_request(
            payment_request=action_payload,
            task_context=task_context,
            request_security=True,
        )

        if not result.get("success"):
            return result

        decision = result.get("data", {}).get("decision")
        can_prepare_draft = decision in {
            PaymentGuardDecision.ALLOW_DRAFT_ONLY.value,
            PaymentGuardDecision.REQUIRE_SECURITY_APPROVAL.value,
        }
        can_execute = False

        result["data"]["can_prepare_draft"] = can_prepare_draft
        result["data"]["can_execute"] = can_execute
        result["data"]["execution_blocked_by_design"] = True
        result["data"]["execution_note"] = (
            "FinancePaymentGuard never executes real payments. "
            "Only draft preparation and Security Agent handoff are supported."
        )

        return result

    def validate_payment_draft(
        self,
        draft_payload: Mapping[str, Any],
        task_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Validate a prepared payment draft.

        Used by Transaction Preparer, Invoice Manager, Dashboard/API, or Master
        Agent before displaying a draft to a user or routing it to Security Agent.
        """

        payload = dict(draft_payload)
        payload.setdefault("action_type", PaymentActionType.PAYMENT_DRAFT.value)

        return self.evaluate_payment_request(
            payment_request=payload,
            task_context=task_context,
            request_security=False,
        )

    def prepare_security_handoff(
        self,
        payment_request: Union[PaymentGuardRequest, Mapping[str, Any]],
        task_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare a Security Agent handoff payload without calling Security Agent.

        Useful for APIs or workflows that want to inspect/queue the security
        request separately.
        """

        operation_id = _safe_uuid("payment_security_handoff")

        context_result = self._validate_task_context(task_context, operation_id=operation_id)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]["context"]
        normalized = self._normalize_payment_request(payment_request)
        findings = self._validate_payment_request(normalized) + self._analyze_payment_risk(normalized)
        risk_level = self._calculate_risk_level(normalized, findings)
        decision = self._decide(normalized, risk_level, findings)

        security_payload = self._build_security_handoff_payload(
            context=context,
            payment_request=normalized,
            risk_level=risk_level,
            decision=decision,
            findings=findings,
            operation_id=operation_id,
        )

        self._emit_agent_event(
            PaymentGuardEventType.SECURITY_HANDOFF_PREPARED.value,
            {
                "operation_id": operation_id,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "risk_level": risk_level.value,
                "decision": decision.value,
            },
        )

        return self._safe_result(
            success=True,
            message="Security Agent handoff payload prepared. No payment was executed.",
            data={
                "security_payload": security_payload,
                "risk_level": risk_level.value,
                "decision": decision.value,
                "findings": [self._finding_to_dict(finding) for finding in findings],
            },
            metadata={
                "operation_id": operation_id,
                "agent": self.agent_name,
                "created_at": _utc_now_iso(),
            },
        )

    def build_dashboard_summary(
        self,
        evaluation_result: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Build a dashboard/API-friendly summary from an evaluation result.

        This keeps UI logic separate from guard internals and supports later
        FastAPI/dashboard integration.
        """

        data = dict(evaluation_result.get("data", {}))
        findings = data.get("findings", [])

        summary = {
            "decision": data.get("decision"),
            "risk_level": data.get("risk_level"),
            "security_status": data.get("security_status"),
            "can_prepare_draft": data.get("can_prepare_draft", False),
            "can_execute": False,
            "finding_count": len(findings) if isinstance(findings, list) else 0,
            "critical_findings": [
                item for item in findings
                if isinstance(item, dict) and item.get("severity") == PaymentRiskLevel.CRITICAL.value
            ],
            "high_findings": [
                item for item in findings
                if isinstance(item, dict) and item.get("severity") == PaymentRiskLevel.HIGH.value
            ],
            "safety_note": "Payment execution is blocked by design in FinancePaymentGuard.",
        }

        return self._safe_result(
            success=True,
            message="Dashboard payment guard summary prepared.",
            data=summary,
            metadata={
                "agent": self.agent_name,
                "prepared_at": _utc_now_iso(),
            },
        )

    def health_check(self) -> Dict[str, Any]:
        """
        Basic import/runtime health check for Agent Loader and Registry.

        Returns:
            Structured result with capability metadata.
        """

        return self._safe_result(
            success=True,
            message="FinancePaymentGuard is available.",
            data={
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "capabilities": [
                    "payment_risk_evaluation",
                    "payment_draft_validation",
                    "security_agent_handoff",
                    "verification_payload_preparation",
                    "memory_payload_preparation",
                    "audit_event_preparation",
                    "saas_user_workspace_isolation",
                ],
                "executes_payments": False,
                "safe_to_import": True,
            },
            metadata={
                "checked_at": _utc_now_iso(),
            },
        )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(
        self,
        task_context: Mapping[str, Any],
        operation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Required global rule:
            Every user-specific execution must include user_id and workspace_id.
        """

        operation_id = operation_id or _safe_uuid("payment_guard_context")

        if not isinstance(task_context, Mapping):
            return self._error_result(
                message="Invalid task context. Expected a mapping with user_id and workspace_id.",
                error="invalid_task_context_type",
                metadata={"operation_id": operation_id},
            )

        user_id = _safe_str(task_context.get("user_id", "")).strip()
        workspace_id = _safe_str(task_context.get("workspace_id", "")).strip()

        if not user_id:
            return self._error_result(
                message="Missing user_id. Payment safety checks require SaaS user isolation.",
                error="missing_user_id",
                metadata={"operation_id": operation_id},
            )

        if not workspace_id:
            return self._error_result(
                message="Missing workspace_id. Payment safety checks require workspace isolation.",
                error="missing_workspace_id",
                metadata={"operation_id": operation_id},
            )

        request_id = _safe_str(
            task_context.get("request_id")
            or task_context.get("task_id")
            or operation_id
        ).strip()

        permissions_raw = task_context.get("permissions", [])
        permissions: List[str]
        if isinstance(permissions_raw, str):
            permissions = [permissions_raw]
        elif isinstance(permissions_raw, Iterable):
            permissions = [str(item) for item in permissions_raw]
        else:
            permissions = []

        context = PaymentGuardContext(
            user_id=user_id,
            workspace_id=workspace_id,
            request_id=request_id,
            role=_safe_str(task_context.get("role")) if task_context.get("role") else None,
            permissions=permissions,
            source=_safe_str(task_context.get("source")) if task_context.get("source") else None,
            session_id=_safe_str(task_context.get("session_id")) if task_context.get("session_id") else None,
            ip_address_hash=_hash_value(_safe_str(task_context.get("ip_address"))) if task_context.get("ip_address") else None,
            user_agent_hash=_hash_value(_safe_str(task_context.get("user_agent"))) if task_context.get("user_agent") else None,
        )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={"context": context},
            metadata={"operation_id": operation_id},
        )

    def _requires_security_check(
        self,
        payment_request: PaymentGuardRequest,
        risk_level: PaymentRiskLevel,
        decision: Optional[PaymentGuardDecision] = None,
    ) -> bool:
        """
        Decide whether Security Agent approval is required.

        Sensitive payment actions, high-value amounts, critical findings,
        international transfers, crypto transfers, new payees, and payment method
        changes require Security Agent handoff.
        """

        if decision == PaymentGuardDecision.BLOCK:
            return True

        if self.config.require_security_for_all_sensitive_actions:
            if payment_request.action_type in self.config.sensitive_actions:
                return True

        if risk_level in {PaymentRiskLevel.HIGH, PaymentRiskLevel.CRITICAL}:
            return True

        if (
            payment_request.amount is not None
            and payment_request.amount >= self.config.high_value_threshold
        ):
            return True

        if self.config.require_security_for_new_payees and payment_request.is_new_payee:
            return True

        if self.config.require_security_for_international and payment_request.is_international:
            return True

        if self.config.require_security_for_crypto and payment_request.is_crypto:
            return True

        if payment_request.is_payment_method_change:
            return True

        return False

    def _request_security_approval(self, security_payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Request approval from Security Agent if a compatible client exists.

        This method is defensive:
            - If Security Agent is unavailable, it returns REQUIRED/UNAVAILABLE.
            - It never fails open.
            - It never treats missing approval as approval.
        """

        if not self.security_client:
            return self._safe_result(
                success=True,
                message="Security Agent client is unavailable. Approval remains required.",
                data={
                    "security_status": SecurityApprovalStatus.UNAVAILABLE.value,
                    "approved": False,
                    "approval_id": None,
                    "fail_open": False,
                },
                metadata={"checked_at": _utc_now_iso()},
            )

        try:
            response: Any = None

            if hasattr(self.security_client, "request_approval"):
                response = self.security_client.request_approval(dict(security_payload))
            elif hasattr(self.security_client, "evaluate_sensitive_action"):
                response = self.security_client.evaluate_sensitive_action(dict(security_payload))
            elif hasattr(self.security_client, "create_approval_request"):
                response = self.security_client.create_approval_request(dict(security_payload))
            else:
                return self._safe_result(
                    success=True,
                    message="Security Agent client has no compatible approval method.",
                    data={
                        "security_status": SecurityApprovalStatus.UNAVAILABLE.value,
                        "approved": False,
                        "approval_id": None,
                        "fail_open": False,
                    },
                    metadata={"checked_at": _utc_now_iso()},
                )

            parsed = self._parse_security_response(response)

            return self._safe_result(
                success=True,
                message="Security Agent approval request processed.",
                data=parsed,
                metadata={"checked_at": _utc_now_iso()},
            )

        except Exception as exc:
            self.logger.exception("Security Agent approval request failed.")
            return self._safe_result(
                success=True,
                message="Security Agent approval request failed safely. Approval remains required.",
                data={
                    "security_status": SecurityApprovalStatus.UNAVAILABLE.value,
                    "approved": False,
                    "approval_id": None,
                    "fail_open": False,
                    "error": str(exc),
                },
                metadata={"checked_at": _utc_now_iso()},
            )

    def _prepare_verification_payload(
        self,
        context: PaymentGuardContext,
        payment_request: PaymentGuardRequest,
        risk_level: PaymentRiskLevel,
        decision: PaymentGuardDecision,
        security_status: Union[SecurityApprovalStatus, str],
        findings: List[PaymentRiskFinding],
        operation_id: str,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can use this to confirm:
            - No payment was executed.
            - Correct user/workspace context was used.
            - Required Security Agent handoff was prepared.
            - Risk findings and decision are traceable.
        """

        payload = {
            "verification_type": "finance_payment_guard",
            "operation_id": operation_id,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "decision": decision.value,
            "risk_level": risk_level.value,
            "security_status": str(security_status),
            "executed_financial_action": False,
            "execution_blocked_by_design": True,
            "payment_request_redacted": _redact_payment_request(payment_request),
            "findings": [self._finding_to_dict(finding) for finding in findings],
            "checks": {
                "saas_context_validated": True,
                "user_workspace_isolation_enforced": True,
                "payment_execution_prevented": True,
                "security_required": self._requires_security_check(payment_request, risk_level, decision),
                "draft_only_supported": self.config.allow_draft_only_mode,
            },
            "created_at": _utc_now_iso(),
        }

        self._emit_agent_event(
            PaymentGuardEventType.VERIFICATION_PAYLOAD_PREPARED.value,
            {
                "operation_id": operation_id,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "decision": decision.value,
            },
        )

        return payload

    def _prepare_memory_payload(
        self,
        context: PaymentGuardContext,
        payment_request: PaymentGuardRequest,
        risk_level: PaymentRiskLevel,
        decision: PaymentGuardDecision,
        findings: List[PaymentRiskFinding],
        operation_id: str,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        This payload is intentionally redacted. It can help future finance
        actions remember workspace-level safety preferences and repeated risks
        without storing secrets or raw payment credentials.
        """

        if not self.config.memory_payload_enabled:
            return {}

        finding_codes = [finding.code for finding in findings]

        return {
            "memory_type": "finance_payment_safety_context",
            "operation_id": operation_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "scope": "workspace",
            "importance": "high" if risk_level in {PaymentRiskLevel.HIGH, PaymentRiskLevel.CRITICAL} else "normal",
            "summary": (
                f"Payment guard evaluated {payment_request.action_type} "
                f"with {risk_level.value} risk and decision {decision.value}."
            ),
            "redacted_payment_context": {
                "action_type": payment_request.action_type,
                "currency": payment_request.currency,
                "amount_band": self._amount_band(payment_request.amount),
                "is_new_payee": payment_request.is_new_payee,
                "is_international": payment_request.is_international,
                "is_crypto": payment_request.is_crypto,
                "is_payment_method_change": payment_request.is_payment_method_change,
                "finding_codes": finding_codes,
            },
            "do_not_store": [
                "card_number",
                "cvv",
                "bank_account_number",
                "routing_number",
                "private_key",
                "seed_phrase",
                "raw_payment_credentials",
            ],
            "created_at": _utc_now_iso(),
        }

    def _emit_agent_event(self, event_type: str, payload: Mapping[str, Any]) -> None:
        """
        Emit event to dashboard/event bus when available.

        Compatible with BaseAgent event emission and custom event emitter.
        """

        if not self.config.event_emission_enabled:
            return

        safe_payload = dict(payload)
        safe_payload.setdefault("agent", self.agent_name)
        safe_payload.setdefault("agent_type", self.agent_type)
        safe_payload.setdefault("timestamp", _utc_now_iso())

        try:
            if self.event_emitter:
                self.event_emitter(event_type, safe_payload)
                return

            if hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_type, safe_payload)  # type: ignore[misc]
                    return
                except Exception:
                    pass

        except Exception:
            self.logger.debug("Event emission failed safely.", exc_info=True)

    def _log_audit_event(self, audit_payload: Mapping[str, Any]) -> None:
        """
        Write audit event through available audit logger.

        Audit payloads are redacted and SaaS-scoped.
        """

        if not self.config.audit_enabled:
            return

        try:
            if self.audit_logger:
                self.audit_logger(dict(audit_payload))
                return

            if hasattr(super(), "log_audit_event"):
                try:
                    super().log_audit_event(dict(audit_payload))  # type: ignore[misc]
                    return
                except Exception:
                    pass

            self.logger.info(
                "Finance payment guard audit event prepared: %s",
                json.dumps(dict(audit_payload), default=str),
            )

        except Exception:
            self.logger.debug("Audit logging failed safely.", exc_info=True)

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured success/safe result.

        Required global output shape:
            success, message, data, error, metadata
        """

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
        error: Union[str, Exception],
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured error result.

        Errors fail closed. No financial action is executed.
        """

        return {
            "success": False,
            "message": message,
            "data": data or {},
            "error": _safe_str(error),
            "metadata": metadata or {},
        }

    # ------------------------------------------------------------------
    # Internal normalization and validation
    # ------------------------------------------------------------------

    def _normalize_payment_request(
        self,
        payment_request: Union[PaymentGuardRequest, Mapping[str, Any]],
    ) -> PaymentGuardRequest:
        """Normalize incoming payment payload into PaymentGuardRequest."""

        if isinstance(payment_request, PaymentGuardRequest):
            request = payment_request
        elif isinstance(payment_request, Mapping):
            request = PaymentGuardRequest(
                action_type=_normalize_action_type(payment_request.get("action_type")),
                amount=_decimal_or_none(payment_request.get("amount")),
                currency=_normalize_currency(payment_request.get("currency")),
                payee_name=self._optional_clean_text(payment_request.get("payee_name")),
                payee_id=self._optional_clean_text(payment_request.get("payee_id")),
                payer_name=self._optional_clean_text(payment_request.get("payer_name")),
                payer_id=self._optional_clean_text(payment_request.get("payer_id")),
                invoice_id=self._optional_clean_text(payment_request.get("invoice_id")),
                transaction_draft_id=self._optional_clean_text(payment_request.get("transaction_draft_id")),
                payment_method_type=self._optional_clean_text(payment_request.get("payment_method_type")),
                destination_country=self._optional_clean_text(payment_request.get("destination_country")),
                origin_country=self._optional_clean_text(payment_request.get("origin_country")),
                description=self._optional_clean_text(payment_request.get("description"), self.config.max_description_length),
                external_reference=self._optional_clean_text(payment_request.get("external_reference")),
                is_new_payee=bool(payment_request.get("is_new_payee", False)),
                is_payment_method_change=bool(payment_request.get("is_payment_method_change", False)),
                is_international=bool(payment_request.get("is_international", False)),
                is_crypto=bool(payment_request.get("is_crypto", False)),
                metadata=self._safe_metadata(payment_request.get("metadata", {})),
            )
        else:
            request = PaymentGuardRequest(
                action_type=PaymentActionType.UNKNOWN.value,
                metadata={"raw_type": type(payment_request).__name__},
            )

        request.action_type = _normalize_action_type(request.action_type)
        request.currency = _normalize_currency(request.currency)
        request.amount = _decimal_or_none(request.amount)
        request.metadata = self._safe_metadata(request.metadata)

        text_blob = " ".join(
            str(item or "")
            for item in [
                request.description,
                request.payment_method_type,
                request.action_type,
                json.dumps(request.metadata, default=str)[:2000],
            ]
        )

        if SUSPICIOUS_PAYMENT_PATTERNS["crypto"].search(text_blob):
            request.is_crypto = True
            if request.action_type == PaymentActionType.UNKNOWN.value:
                request.action_type = PaymentActionType.CRYPTO_TRANSFER.value

        if SUSPICIOUS_PAYMENT_PATTERNS["wire"].search(text_blob):
            if request.action_type == PaymentActionType.UNKNOWN.value:
                request.action_type = PaymentActionType.BANK_TRANSFER.value

        if SUSPICIOUS_PAYMENT_PATTERNS["new_payee"].search(text_blob):
            request.is_new_payee = True

        if SUSPICIOUS_PAYMENT_PATTERNS["payment_method_change"].search(text_blob):
            request.is_payment_method_change = True

        if request.origin_country and request.destination_country:
            request.is_international = (
                request.origin_country.strip().lower()
                != request.destination_country.strip().lower()
            )

        if request.action_type in {
            PaymentActionType.INTERNATIONAL_TRANSFER.value,
            PaymentActionType.CRYPTO_TRANSFER.value,
        }:
            request.is_international = (
                request.is_international
                or request.action_type == PaymentActionType.INTERNATIONAL_TRANSFER.value
            )
            request.is_crypto = (
                request.is_crypto
                or request.action_type == PaymentActionType.CRYPTO_TRANSFER.value
            )

        return request

    def _validate_payment_request(
        self,
        request: PaymentGuardRequest,
    ) -> List[PaymentRiskFinding]:
        """Validate required payment fields and safe payload bounds."""

        findings: List[PaymentRiskFinding] = []

        if request.action_type == PaymentActionType.UNKNOWN.value:
            findings.append(
                PaymentRiskFinding(
                    code="unknown_action_type",
                    message="Payment action type is unknown.",
                    severity=PaymentRiskLevel.MEDIUM,
                    field_name="action_type",
                )
            )

        if request.amount is None:
            findings.append(
                PaymentRiskFinding(
                    code="missing_amount",
                    message="Payment amount is missing or invalid.",
                    severity=PaymentRiskLevel.MEDIUM,
                    field_name="amount",
                )
            )
        elif request.amount <= Decimal("0"):
            findings.append(
                PaymentRiskFinding(
                    code="non_positive_amount",
                    message="Payment amount must be greater than zero.",
                    severity=PaymentRiskLevel.HIGH,
                    field_name="amount",
                    details={"amount": str(request.amount)},
                )
            )

        if not request.currency:
            findings.append(
                PaymentRiskFinding(
                    code="missing_currency",
                    message="Payment currency is missing.",
                    severity=PaymentRiskLevel.MEDIUM,
                    field_name="currency",
                )
            )
        elif request.currency not in self.config.allowed_currencies:
            findings.append(
                PaymentRiskFinding(
                    code="unsupported_currency",
                    message=f"Currency {request.currency} is not currently allowed by FinancePaymentGuard.",
                    severity=PaymentRiskLevel.HIGH,
                    field_name="currency",
                    details={"currency": request.currency},
                )
            )

        if not request.payee_name and not request.payee_id:
            findings.append(
                PaymentRiskFinding(
                    code="missing_payee",
                    message="Payee identity is missing.",
                    severity=PaymentRiskLevel.HIGH,
                    field_name="payee",
                )
            )

        if request.description and len(request.description) > self.config.max_description_length:
            findings.append(
                PaymentRiskFinding(
                    code="description_too_long",
                    message="Payment description exceeds configured safety length.",
                    severity=PaymentRiskLevel.MEDIUM,
                    field_name="description",
                    details={"max_length": self.config.max_description_length},
                )
            )

        if _json_size_bytes(request.metadata) > self.config.max_metadata_size_bytes:
            findings.append(
                PaymentRiskFinding(
                    code="metadata_too_large",
                    message="Payment metadata exceeds configured safety size.",
                    severity=PaymentRiskLevel.HIGH,
                    field_name="metadata",
                    details={"max_size_bytes": self.config.max_metadata_size_bytes},
                )
            )

        return findings

    def _analyze_payment_risk(
        self,
        request: PaymentGuardRequest,
    ) -> List[PaymentRiskFinding]:
        """Analyze finance-specific payment risk signals."""

        findings: List[PaymentRiskFinding] = []

        if request.amount is not None:
            if request.amount >= self.config.critical_value_threshold:
                findings.append(
                    PaymentRiskFinding(
                        code="critical_value_payment",
                        message="Payment amount meets or exceeds the critical value threshold.",
                        severity=PaymentRiskLevel.CRITICAL,
                        field_name="amount",
                        details={
                            "amount": str(request.amount),
                            "threshold": str(self.config.critical_value_threshold),
                        },
                    )
                )
            elif request.amount >= self.config.high_value_threshold:
                findings.append(
                    PaymentRiskFinding(
                        code="high_value_payment",
                        message="Payment amount meets or exceeds the high value threshold.",
                        severity=PaymentRiskLevel.HIGH,
                        field_name="amount",
                        details={
                            "amount": str(request.amount),
                            "threshold": str(self.config.high_value_threshold),
                        },
                    )
                )

        if request.action_type in {
            PaymentActionType.BANK_TRANSFER.value,
            PaymentActionType.INTERNATIONAL_TRANSFER.value,
            PaymentActionType.CRYPTO_TRANSFER.value,
            PaymentActionType.CLIENT_REFUND.value,
            PaymentActionType.PAYMENT_METHOD_UPDATE.value,
        }:
            findings.append(
                PaymentRiskFinding(
                    code="sensitive_payment_action",
                    message=f"Action type {request.action_type} is sensitive and requires review.",
                    severity=PaymentRiskLevel.HIGH,
                    field_name="action_type",
                    details={"action_type": request.action_type},
                )
            )

        if request.is_new_payee:
            findings.append(
                PaymentRiskFinding(
                    code="new_payee",
                    message="Payment is for a new payee or beneficiary.",
                    severity=PaymentRiskLevel.HIGH,
                    field_name="payee",
                )
            )

        if request.is_payment_method_change:
            findings.append(
                PaymentRiskFinding(
                    code="payment_method_change",
                    message="Payment method or beneficiary account appears to have changed.",
                    severity=PaymentRiskLevel.HIGH,
                    field_name="payment_method",
                )
            )

        if request.is_international:
            findings.append(
                PaymentRiskFinding(
                    code="international_payment",
                    message="Payment appears to be international.",
                    severity=PaymentRiskLevel.HIGH,
                    field_name="destination_country",
                    details={
                        "origin_country": request.origin_country,
                        "destination_country": request.destination_country,
                    },
                )
            )

        if request.is_crypto:
            findings.append(
                PaymentRiskFinding(
                    code="crypto_payment",
                    message="Crypto-related payments require strict Security Agent review.",
                    severity=PaymentRiskLevel.CRITICAL,
                    field_name="payment_method_type",
                )
            )

        text_blob = " ".join(
            [
                request.description or "",
                request.external_reference or "",
                request.payment_method_type or "",
                json.dumps(request.metadata, default=str)[:5000],
            ]
        ).lower()

        for phrase in DANGEROUS_EXECUTION_PHRASES:
            if phrase in text_blob:
                findings.append(
                    PaymentRiskFinding(
                        code="real_execution_requested",
                        message=(
                            "The request appears to ask for real payment execution. "
                            "FinancePaymentGuard only allows draft/safety handoff."
                        ),
                        severity=PaymentRiskLevel.CRITICAL,
                        field_name="description",
                        details={"matched_phrase": phrase},
                    )
                )

        for pattern_name, pattern in SUSPICIOUS_PAYMENT_PATTERNS.items():
            if pattern.search(text_blob):
                severity = PaymentRiskLevel.HIGH
                if pattern_name in {"gift_card", "secrecy", "crypto"}:
                    severity = PaymentRiskLevel.CRITICAL

                findings.append(
                    PaymentRiskFinding(
                        code=f"suspicious_pattern_{pattern_name}",
                        message=f"Suspicious payment pattern detected: {pattern_name}.",
                        severity=severity,
                        field_name="description",
                    )
                )

        if self._metadata_contains_raw_credentials(request.metadata):
            findings.append(
                PaymentRiskFinding(
                    code="raw_payment_credentials_detected",
                    message="Raw payment credentials or secrets appear to be present in metadata.",
                    severity=PaymentRiskLevel.CRITICAL,
                    field_name="metadata",
                )
            )

        return findings

    def _calculate_risk_level(
        self,
        request: PaymentGuardRequest,
        findings: List[PaymentRiskFinding],
    ) -> PaymentRiskLevel:
        """Calculate final risk level from findings and request profile."""

        if any(finding.severity == PaymentRiskLevel.CRITICAL for finding in findings):
            return PaymentRiskLevel.CRITICAL

        if any(finding.severity == PaymentRiskLevel.HIGH for finding in findings):
            return PaymentRiskLevel.HIGH

        if any(finding.severity == PaymentRiskLevel.MEDIUM for finding in findings):
            return PaymentRiskLevel.MEDIUM

        if request.action_type in self.config.sensitive_actions:
            return PaymentRiskLevel.MEDIUM

        return PaymentRiskLevel.LOW

    def _decide(
        self,
        request: PaymentGuardRequest,
        risk_level: PaymentRiskLevel,
        findings: List[PaymentRiskFinding],
    ) -> PaymentGuardDecision:
        """
        Decide guard outcome.

        Policy:
            - Real execution requests are blocked.
            - Invalid required fields need more information.
            - Critical risk is blocked unless only draft/handoff is possible.
            - Sensitive/high risk requires Security Agent approval.
            - Low risk can allow draft-only preparation.
        """

        finding_codes = {finding.code for finding in findings}

        if self.config.block_real_execution and "real_execution_requested" in finding_codes:
            return PaymentGuardDecision.BLOCK

        if "raw_payment_credentials_detected" in finding_codes:
            return PaymentGuardDecision.BLOCK

        hard_invalid_codes = {
            "non_positive_amount",
            "unsupported_currency",
            "metadata_too_large",
        }
        if finding_codes.intersection(hard_invalid_codes):
            return PaymentGuardDecision.BLOCK

        missing_info_codes = {
            "missing_amount",
            "missing_currency",
            "missing_payee",
            "unknown_action_type",
        }
        if finding_codes.intersection(missing_info_codes):
            return PaymentGuardDecision.NEED_MORE_INFORMATION

        if risk_level == PaymentRiskLevel.CRITICAL:
            return PaymentGuardDecision.REQUIRE_SECURITY_APPROVAL

        if self._requires_security_check(request, risk_level):
            return PaymentGuardDecision.REQUIRE_SECURITY_APPROVAL

        return PaymentGuardDecision.ALLOW_DRAFT_ONLY

    # ------------------------------------------------------------------
    # Payload builders
    # ------------------------------------------------------------------

    def _build_security_handoff_payload(
        self,
        context: PaymentGuardContext,
        payment_request: PaymentGuardRequest,
        risk_level: PaymentRiskLevel,
        decision: PaymentGuardDecision,
        findings: List[PaymentRiskFinding],
        operation_id: str,
    ) -> Dict[str, Any]:
        """
        Build Security Agent approval payload.

        This payload is redacted and includes enough context for the Security
        Agent to make a policy decision without exposing raw financial secrets.
        """

        return {
            "handoff_type": "finance_payment_security_review",
            "operation_id": operation_id,
            "source_agent": self.agent_name,
            "source_agent_type": self.agent_type,
            "target_agent": "SecurityAgent",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "role": context.role,
            "permissions": context.permissions,
            "risk_level": risk_level.value,
            "guard_decision": decision.value,
            "approval_required": True,
            "financial_execution_requested": False,
            "financial_execution_allowed": False,
            "draft_only": True,
            "payment_request_redacted": _redact_payment_request(payment_request),
            "findings": [self._finding_to_dict(finding) for finding in findings],
            "policy": {
                "block_real_execution": self.config.block_real_execution,
                "require_security_for_all_sensitive_actions": self.config.require_security_for_all_sensitive_actions,
                "require_security_for_new_payees": self.config.require_security_for_new_payees,
                "require_security_for_international": self.config.require_security_for_international,
                "require_security_for_crypto": self.config.require_security_for_crypto,
                "high_value_threshold": str(self.config.high_value_threshold),
                "critical_value_threshold": str(self.config.critical_value_threshold),
            },
            "required_security_checks": [
                "user_permission_check",
                "workspace_policy_check",
                "payee_verification",
                "amount_threshold_review",
                "payment_method_change_review",
                "fraud_pattern_review",
                "final_human_or_policy_approval",
            ],
            "created_at": _utc_now_iso(),
        }

    def _build_audit_payload(
        self,
        context: PaymentGuardContext,
        payment_request: PaymentGuardRequest,
        risk_level: PaymentRiskLevel,
        decision: PaymentGuardDecision,
        security_status: Union[SecurityApprovalStatus, str],
        findings: List[PaymentRiskFinding],
        operation_id: str,
    ) -> Dict[str, Any]:
        """Build redacted audit event payload."""

        return {
            "audit_type": "finance_payment_guard",
            "operation_id": operation_id,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "role": context.role,
            "source": context.source,
            "session_id": context.session_id,
            "ip_address_hash": context.ip_address_hash,
            "user_agent_hash": context.user_agent_hash,
            "risk_level": risk_level.value,
            "decision": decision.value,
            "security_status": str(security_status),
            "payment_request_redacted": _redact_payment_request(payment_request),
            "finding_codes": [finding.code for finding in findings],
            "finding_count": len(findings),
            "executed_financial_action": False,
            "created_at": _utc_now_iso(),
        }

    def _evaluation_to_data(self, evaluation: PaymentGuardEvaluation) -> Dict[str, Any]:
        """Convert evaluation object to structured result data."""

        return {
            "decision": evaluation.decision.value,
            "risk_level": evaluation.risk_level.value,
            "security_status": evaluation.security_status.value,
            "findings": [self._finding_to_dict(finding) for finding in evaluation.findings],
            "payment_request_redacted": _redact_payment_request(evaluation.normalized_request),
            "security_payload": evaluation.security_payload,
            "verification_payload": evaluation.verification_payload,
            "memory_payload": evaluation.memory_payload,
            "audit_payload": evaluation.audit_payload,
            "can_prepare_draft": evaluation.decision in {
                PaymentGuardDecision.ALLOW_DRAFT_ONLY,
                PaymentGuardDecision.REQUIRE_SECURITY_APPROVAL,
            },
            "can_execute": False,
            "execution_blocked_by_design": True,
            "requires_security_check": self._requires_security_check(
                evaluation.normalized_request,
                evaluation.risk_level,
                evaluation.decision,
            ),
            "safe_next_actions": self._safe_next_actions(evaluation.decision),
        }

    # ------------------------------------------------------------------
    # Small internal utilities
    # ------------------------------------------------------------------

    def _parse_security_response(self, response: Any) -> Dict[str, Any]:
        """Normalize Security Agent response into guard-safe shape."""

        if response is None:
            return {
                "security_status": SecurityApprovalStatus.UNAVAILABLE.value,
                "approved": False,
                "approval_id": None,
                "fail_open": False,
            }

        if isinstance(response, Mapping):
            approved = bool(
                response.get("approved")
                or response.get("is_approved")
                or response.get("success") and response.get("status") == "approved"
            )

            status_raw = response.get("security_status") or response.get("status")
            if approved:
                status = SecurityApprovalStatus.APPROVED.value
            elif status_raw in {
                SecurityApprovalStatus.DENIED.value,
                "rejected",
                "blocked",
                "failed",
            }:
                status = SecurityApprovalStatus.DENIED.value
            elif status_raw in {
                SecurityApprovalStatus.REQUESTED.value,
                "pending",
                "queued",
                "created",
            }:
                status = SecurityApprovalStatus.REQUESTED.value
            else:
                status = SecurityApprovalStatus.REQUESTED.value

            return {
                "security_status": status,
                "approved": approved,
                "approval_id": response.get("approval_id") or response.get("id") or response.get("request_id"),
                "fail_open": False,
                "raw_response_redacted": self._redact_mapping(response),
            }

        return {
            "security_status": SecurityApprovalStatus.REQUESTED.value,
            "approved": False,
            "approval_id": None,
            "fail_open": False,
            "raw_response_summary": _safe_str(response),
        }

    def _safe_metadata(self, metadata: Any) -> Dict[str, Any]:
        """Normalize metadata to safe dict."""

        if metadata is None:
            return {}

        if isinstance(metadata, Mapping):
            safe = dict(metadata)
        else:
            safe = {"value": _safe_str(metadata, max_length=1000)}

        if _json_size_bytes(safe) > self.config.max_metadata_size_bytes:
            return {
                "metadata_truncated": True,
                "original_size_exceeded": True,
                "safe_preview": _safe_str(safe, max_length=1000),
            }

        return safe

    def _metadata_contains_raw_credentials(self, metadata: Mapping[str, Any]) -> bool:
        """Detect obvious raw payment credentials/secrets in metadata keys."""

        sensitive_fragments = {
            "card_number",
            "cvv",
            "cvc",
            "iban",
            "routing",
            "account_number",
            "private_key",
            "seed_phrase",
            "secret_key",
            "password",
            "pin",
        }

        def walk(prefix: str, value: Any) -> bool:
            if isinstance(value, Mapping):
                for key, nested in value.items():
                    key_text = f"{prefix}.{key}".lower()
                    if any(fragment in key_text for fragment in sensitive_fragments):
                        return True
                    if walk(key_text, nested):
                        return True
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    if walk(f"{prefix}[{index}]", item):
                        return True
            return False

        return walk("metadata", metadata)

    def _redact_mapping(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Redact a mapping for logs/results."""

        sensitive_fragments = {
            "secret",
            "token",
            "password",
            "private",
            "card",
            "cvv",
            "cvc",
            "iban",
            "routing",
            "account",
            "seed",
            "key",
        }

        redacted: Dict[str, Any] = {}
        for key, value in payload.items():
            key_text = str(key).lower()
            if any(fragment in key_text for fragment in sensitive_fragments):
                redacted[str(key)] = "[REDACTED]"
            elif isinstance(value, Mapping):
                redacted[str(key)] = self._redact_mapping(value)
            elif isinstance(value, list):
                redacted[str(key)] = [
                    self._redact_mapping(item) if isinstance(item, Mapping) else _safe_str(item)
                    for item in value[:20]
                ]
            else:
                redacted[str(key)] = _safe_str(value, max_length=500)
        return redacted

    def _finding_to_dict(self, finding: PaymentRiskFinding) -> Dict[str, Any]:
        """Convert PaymentRiskFinding to JSON-safe dict."""

        return {
            "code": finding.code,
            "message": finding.message,
            "severity": finding.severity.value,
            "field": finding.field_name,
            "details": finding.details,
        }

    def _optional_clean_text(self, value: Any, max_length: int = 500) -> Optional[str]:
        """Clean optional text values."""

        if value is None:
            return None

        text = _safe_str(value, max_length=max_length).strip()
        if not text:
            return None
        return text

    def _amount_band(self, amount: Optional[Decimal]) -> str:
        """Return non-sensitive amount band for memory context."""

        if amount is None:
            return "unknown"

        if amount < Decimal("100"):
            return "under_100"
        if amount < Decimal("1000"):
            return "100_to_999"
        if amount < Decimal("10000"):
            return "1000_to_9999"
        return "10000_plus"

    def _decision_message(
        self,
        decision: PaymentGuardDecision,
        risk_level: PaymentRiskLevel,
        security_status: Union[SecurityApprovalStatus, str],
    ) -> str:
        """Human-readable structured result message."""

        if decision == PaymentGuardDecision.BLOCK:
            return (
                f"Payment request blocked due to {risk_level.value} risk. "
                "No financial action was executed."
            )

        if decision == PaymentGuardDecision.NEED_MORE_INFORMATION:
            return (
                "Payment request needs more information before a safe draft or "
                "Security Agent handoff can proceed. No financial action was executed."
            )

        if decision == PaymentGuardDecision.REQUIRE_SECURITY_APPROVAL:
            return (
                f"Payment request requires Security Agent approval. "
                f"Current security status: {security_status}. "
                "No financial action was executed."
            )

        return (
            "Payment request passed guard checks for draft-only preparation. "
            "No financial action was executed."
        )

    def _safe_next_actions(self, decision: PaymentGuardDecision) -> List[str]:
        """Safe next action recommendations for Master Agent/Dashboard."""

        if decision == PaymentGuardDecision.BLOCK:
            return [
                "Stop payment workflow.",
                "Show user the blocking safety findings.",
                "Route to Security Agent or human admin for review if appropriate.",
                "Do not execute or submit payment.",
            ]

        if decision == PaymentGuardDecision.NEED_MORE_INFORMATION:
            return [
                "Ask for missing payment draft details.",
                "Re-run FinancePaymentGuard after details are provided.",
                "Do not execute or submit payment.",
            ]

        if decision == PaymentGuardDecision.REQUIRE_SECURITY_APPROVAL:
            return [
                "Keep payment as draft only.",
                "Send prepared handoff payload to Security Agent.",
                "Wait for explicit Security Agent approval before any downstream sensitive workflow.",
                "Do not execute or submit payment from this guard.",
            ]

        return [
            "Allow draft-only preparation.",
            "Prepare Verification Agent payload.",
            "Keep payment execution disabled unless handled by a separate approved payment system.",
        ]


# ---------------------------------------------------------------------------
# Module-level convenience factory and self-test helpers
# ---------------------------------------------------------------------------

def create_finance_payment_guard(
    config: Optional[PaymentGuardConfig] = None,
    security_client: Optional[Any] = None,
    event_emitter: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> FinancePaymentGuard:
    """
    Factory for Agent Loader / Registry integration.

    Returns:
        FinancePaymentGuard instance.
    """

    return FinancePaymentGuard(
        config=config,
        security_client=security_client,
        event_emitter=event_emitter,
        audit_logger=audit_logger,
    )


def get_agent_metadata() -> Dict[str, Any]:
    """
    Registry-friendly module metadata.

    Agent Registry, Agent Loader, and Master Agent can inspect this function
    without instantiating the class.
    """

    return {
        "agent_name": FinancePaymentGuard.agent_name,
        "agent_type": FinancePaymentGuard.agent_type,
        "class_name": "FinancePaymentGuard",
        "version": FinancePaymentGuard.version,
        "module": "agents.super_agents.finance_agent.payment_guard",
        "file_path": "agents/super_agents/finance_agent/payment_guard.py",
        "capabilities": [
            "finance_payment_safety",
            "payment_risk_scoring",
            "security_agent_handoff",
            "payment_draft_validation",
            "verification_payload",
            "memory_payload",
            "audit_logging",
            "saas_isolation",
        ],
        "executes_financial_actions": False,
        "requires_user_id": True,
        "requires_workspace_id": True,
        "safe_to_import": True,
    }


def run_basic_self_test() -> Dict[str, Any]:
    """
    Lightweight self-test for local development.

    This does not contact external services and does not execute payments.
    """

    guard = FinancePaymentGuard()

    result = guard.evaluate_payment_request(
        payment_request={
            "action_type": "vendor_payment",
            "amount": "1500.00",
            "currency": "USD",
            "payee_name": "Example Vendor LLC",
            "description": "Prepare vendor payment draft for invoice INV-1001.",
            "is_new_payee": True,
        },
        task_context={
            "user_id": "test_user",
            "workspace_id": "test_workspace",
            "request_id": "test_request",
            "role": "admin",
            "permissions": ["finance:draft"],
            "source": "self_test",
        },
        request_security=False,
    )

    return result


__all__ = [
    "FinancePaymentGuard",
    "PaymentGuardConfig",
    "PaymentGuardContext",
    "PaymentGuardRequest",
    "PaymentRiskFinding",
    "PaymentGuardEvaluation",
    "PaymentRiskLevel",
    "PaymentGuardDecision",
    "PaymentActionType",
    "SecurityApprovalStatus",
    "create_finance_payment_guard",
    "get_agent_metadata",
    "run_basic_self_test",
]