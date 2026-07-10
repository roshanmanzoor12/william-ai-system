"""
agents/super_agents/finance_agent/transaction_preparer.py

Purpose:
    Transaction draft preparation helper for the William / Jarvis Finance Agent.

Core safety rule:
    This module prepares transaction drafts only.
    It NEVER submits, executes, initiates, schedules, confirms, authorizes,
    or sends a real money movement.

Architecture compatibility:
    - Master Agent routing compatible
    - BaseAgent compatible with safe fallback
    - Agent Registry / Agent Loader import-safe
    - Security Agent approval handoff compatible
    - Verification Agent payload compatible
    - Memory Agent payload compatible
    - Dashboard / FastAPI structured result compatible
    - SaaS user_id / workspace_id isolation enforced

Public class:
    TransactionPreparer
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ======================================================================================
# Safe optional imports
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for isolated import/testing
    class BaseAgent:  # type: ignore
        """
        Minimal fallback BaseAgent.

        This keeps the file import-safe even before the full William/Jarvis
        BaseAgent implementation exists.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent does not implement run().",
                "data": {},
                "error": "BASE_AGENT_FALLBACK",
                "metadata": {"agent": self.agent_name},
            }


try:
    from agents.super_agents.finance_agent.config import FinanceAgentConfig  # type: ignore
except Exception:  # pragma: no cover
    FinanceAgentConfig = None  # type: ignore


# ======================================================================================
# Logging
# ======================================================================================

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ======================================================================================
# Constants
# ======================================================================================

MODULE_NAME = "transaction_preparer"
AGENT_NAME = "TransactionPreparer"
AGENT_MODULE = "Finance Agent"
DEFAULT_VERSION = "1.0.0"

REDACTED_VALUE = "***REDACTED***"

DEFAULT_SUPPORTED_CURRENCIES = {
    "USD",
    "EUR",
    "GBP",
    "CAD",
    "AUD",
    "AED",
    "SAR",
    "PKR",
    "INR",
    "JPY",
    "CHF",
    "NZD",
    "SGD",
}

DEFAULT_PAYMENT_METHODS = {
    "bank_transfer",
    "wire_transfer",
    "ach",
    "sepa",
    "card_payment",
    "vendor_payment",
    "internal_book_entry",
    "manual_payment",
    "other",
}

SENSITIVE_FIELD_NAMES = {
    "account_number",
    "routing_number",
    "iban",
    "swift",
    "bic",
    "card_number",
    "cvv",
    "cvc",
    "pin",
    "password",
    "secret",
    "token",
    "api_key",
    "access_key",
    "private_key",
    "wallet_private_key",
    "seed_phrase",
    "bank_login",
}

NEVER_EXECUTE_KEYWORDS = {
    "submit",
    "send",
    "transfer",
    "execute",
    "pay_now",
    "confirm_payment",
    "initiate",
    "authorize",
    "capture",
    "settle",
    "charge",
    "wire_now",
    "debit",
    "withdraw",
}

DRAFT_ONLY_NOTICE = (
    "Draft prepared only. No transfer, payment, debit, withdrawal, charge, or "
    "external financial action was submitted."
)


# ======================================================================================
# Enums
# ======================================================================================

class TransactionDraftStatus(str, Enum):
    DRAFT = "draft"
    NEEDS_SECURITY_REVIEW = "needs_security_review"
    NEEDS_USER_REVIEW = "needs_user_review"
    READY_FOR_MANUAL_PROCESSING = "ready_for_manual_processing"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class TransactionType(str, Enum):
    VENDOR_PAYMENT = "vendor_payment"
    BANK_TRANSFER = "bank_transfer"
    WIRE_TRANSFER = "wire_transfer"
    CARD_PAYMENT = "card_payment"
    INTERNAL_BOOK_ENTRY = "internal_book_entry"
    REIMBURSEMENT = "reimbursement"
    REFUND = "refund"
    OTHER = "other"


class TransactionRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityDecision(str, Enum):
    NOT_REQUIRED = "not_required"
    REQUIRED = "required"
    REQUESTED = "requested"
    APPROVED_EXTERNALLY = "approved_externally"
    REJECTED_EXTERNALLY = "rejected_externally"


# ======================================================================================
# Dataclasses
# ======================================================================================

@dataclass(frozen=True)
class ActorContext:
    """
    SaaS isolation context.

    Every user-specific finance operation must provide user_id and workspace_id.
    This prevents records, drafts, logs, memory payloads, and dashboard events
    from mixing between tenants.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Payee:
    """
    Payee/recipient details for a transaction draft.

    Sensitive bank/payment data is accepted for draft preparation only and is
    redacted in logs, audit events, memory payloads, and verification payloads.
    """

    name: str
    payee_id: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    country: Optional[str] = None
    address: Optional[str] = None
    bank_name: Optional[str] = None
    account_last4: Optional[str] = None
    account_number: Optional[str] = None
    routing_number: Optional[str] = None
    iban: Optional[str] = None
    swift: Optional[str] = None
    bic: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TransactionLineItem:
    """
    Optional transaction line item.

    Useful for vendor payments, reimbursements, expense categorization,
    dashboard reporting, and future Finance Agent analytics.
    """

    description: str
    amount: Union[str, int, float, Decimal]
    category: Optional[str] = None
    quantity: Union[str, int, float, Decimal] = Decimal("1")
    tax_amount: Union[str, int, float, Decimal] = Decimal("0")
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TransactionDraft:
    """
    Internal transaction draft representation.

    This is not a payment instruction to an external provider.
    It is a reviewable draft object for dashboard/API display and optional
    Security Agent / Verification Agent handoff.
    """

    draft_id: str
    user_id: str
    workspace_id: str
    transaction_type: str
    amount: str
    currency: str
    payee: Dict[str, Any]
    payment_method: str
    memo: Optional[str]
    reference: Optional[str]
    scheduled_for: Optional[str]
    due_date: Optional[str]
    line_items: List[Dict[str, Any]]
    attachments: List[Dict[str, Any]]
    status: str
    risk_level: str
    security_decision: str
    warnings: List[str]
    validation_errors: List[str]
    idempotency_key: str
    created_at: str
    updated_at: str
    created_by: Dict[str, Any]
    source: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    draft_only: bool = True
    external_execution_allowed: bool = False


# ======================================================================================
# Utility helpers
# ======================================================================================

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    return _utc_now().isoformat()


def _normalize_string(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _safe_json_dumps(value: Any) -> str:
    try:
        return json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    except Exception:
        return json.dumps(str(value), sort_keys=True)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _mask_value(value: Any, keep_last: int = 4) -> Any:
    """
    Redact sensitive scalar values while preserving safe debugging shape.
    """

    if value is None:
        return None

    text = str(value)
    if not text:
        return ""

    if len(text) <= keep_last:
        return REDACTED_VALUE

    return f"{REDACTED_VALUE}{text[-keep_last:]}"


def _deep_redact(value: Any, sensitive_keys: Optional[Iterable[str]] = None) -> Any:
    """
    Recursively redact sensitive fields for logs, audit, memory, and verification.
    """

    keys = {k.lower() for k in (sensitive_keys or SENSITIVE_FIELD_NAMES)}

    if isinstance(value, Mapping):
        redacted: Dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            lowered = key_text.lower()
            if lowered in keys or any(secret_key in lowered for secret_key in keys):
                redacted[key_text] = _mask_value(item)
            else:
                redacted[key_text] = _deep_redact(item, keys)
        return redacted

    if isinstance(value, list):
        return [_deep_redact(item, keys) for item in value]

    if isinstance(value, tuple):
        return tuple(_deep_redact(item, keys) for item in value)

    return value


def _to_decimal(value: Union[str, int, float, Decimal], field_name: str = "amount") -> Decimal:
    """
    Convert user-provided amount values to Decimal safely.
    """

    if isinstance(value, Decimal):
        decimal_value = value
    else:
        try:
            decimal_value = Decimal(str(value).replace(",", "").strip())
        except (InvalidOperation, ValueError, TypeError) as exc:
            raise ValueError(f"{field_name} must be a valid decimal number.") from exc

    if not decimal_value.is_finite():
        raise ValueError(f"{field_name} must be a finite decimal number.")

    return decimal_value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)


def _parse_optional_date(value: Any, field_name: str) -> Optional[str]:
    """
    Parse ISO-like date/datetime values into ISO string.

    Returns None when value is absent.
    """

    if value is None or value == "":
        return None

    if isinstance(value, datetime):
        return value.isoformat()

    if isinstance(value, date):
        return value.isoformat()

    text = str(value).strip()
    if not text:
        return None

    try:
        if "T" in text:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
        return date.fromisoformat(text).isoformat()
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO date or datetime string.") from exc


def _coerce_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _clean_currency(currency: Any) -> str:
    return str(currency or "").strip().upper()


def _clean_payment_method(payment_method: Any) -> str:
    return str(payment_method or "").strip().lower().replace(" ", "_").replace("-", "_")


def _clean_transaction_type(transaction_type: Any) -> str:
    return str(transaction_type or "").strip().lower().replace(" ", "_").replace("-", "_")


def _contains_execution_intent(payload: Mapping[str, Any]) -> bool:
    """
    Detect accidental or malicious attempts to execute a real financial action.

    This file must never execute real transactions. This function blocks common
    command-like fields from being treated as valid draft preparation requests.
    """

    haystack = _safe_json_dumps(payload).lower()
    return any(keyword in haystack for keyword in NEVER_EXECUTE_KEYWORDS)


def _public_error(error: Exception) -> str:
    return f"{error.__class__.__name__}: {str(error)}"


# ======================================================================================
# Main class
# ======================================================================================

class TransactionPreparer(BaseAgent):
    """
    Prepares reviewable transaction drafts for the William/Jarvis Finance Agent.

    This class is intentionally draft-only:
        - It validates transaction inputs.
        - It calculates totals.
        - It creates structured draft payloads.
        - It estimates risk.
        - It requests Security Agent approval where relevant.
        - It prepares Verification Agent and Memory Agent payloads.
        - It emits audit/dashboard events through optional callbacks.

    It does NOT:
        - Submit transfers.
        - Connect to banks.
        - Charge cards.
        - Send wires.
        - Create ACH/SEPA instructions externally.
        - Store or expose full sensitive account/card data in logs/memory.
    """

    agent_name = AGENT_NAME
    module_name = MODULE_NAME
    version = DEFAULT_VERSION

    def __init__(
        self,
        config: Optional[Any] = None,
        security_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], Any]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], Any]] = None,
        logger_instance: Optional[logging.Logger] = None,
        in_memory_store_enabled: bool = True,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the transaction preparer.

        Args:
            config:
                Optional FinanceAgentConfig or dict-like config.
            security_client:
                Optional Security Agent adapter. If provided, this class may call
                request_approval/approve/check style methods, but never executes
                a financial transaction.
            verification_client:
                Optional Verification Agent adapter.
            memory_client:
                Optional Memory Agent adapter.
            event_emitter:
                Optional dashboard/event bus callback.
            audit_logger:
                Optional audit callback.
            logger_instance:
                Optional logger.
            in_memory_store_enabled:
                Enables local draft storage for tests/dev usage.
            **kwargs:
                Forward-compatible BaseAgent kwargs.
        """

        try:
            super().__init__(agent_name=AGENT_NAME, agent_id=MODULE_NAME, **kwargs)
        except TypeError:
            super().__init__(**kwargs)

        self.config = config or self._build_default_config()
        self.security_client = security_client
        self.verification_client = verification_client
        self.memory_client = memory_client
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.logger = logger_instance or logging.getLogger(f"{AGENT_MODULE}.{AGENT_NAME}")

        self.in_memory_store_enabled = bool(in_memory_store_enabled)
        self._draft_store: Dict[Tuple[str, str, str], TransactionDraft] = {}

        self.supported_currencies = self._config_get(
            "supported_currencies",
            DEFAULT_SUPPORTED_CURRENCIES,
        )
        self.supported_payment_methods = self._config_get(
            "supported_payment_methods",
            DEFAULT_PAYMENT_METHODS,
        )

        self.max_low_risk_amount = _to_decimal(
            self._config_get("max_low_risk_amount", "1000.00"),
            "max_low_risk_amount",
        )
        self.max_medium_risk_amount = _to_decimal(
            self._config_get("max_medium_risk_amount", "10000.00"),
            "max_medium_risk_amount",
        )
        self.max_high_risk_amount = _to_decimal(
            self._config_get("max_high_risk_amount", "50000.00"),
            "max_high_risk_amount",
        )
        self.require_security_for_all_external_payments = bool(
            self._config_get("require_security_for_all_external_payments", True)
        )

    # ----------------------------------------------------------------------------------
    # BaseAgent / Master Agent entrypoints
    # ----------------------------------------------------------------------------------

    async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Master Agent compatible async entrypoint.

        Expected task shape:
            {
                "action": "prepare_transaction_draft",
                "user_id": "...",
                "workspace_id": "...",
                "payload": {...}
            }

        Supported actions:
            - prepare_transaction_draft
            - prepare_vendor_payment_draft
            - prepare_bank_transfer_draft
            - prepare_card_payment_draft
            - get_transaction_draft
            - cancel_transaction_draft
            - list_transaction_drafts
            - validate_transaction_request

        Even when action names contain payment/transfer words, this module only
        prepares drafts and never submits anything externally.
        """

        return self.handle_task(task)

    def handle_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Synchronous task router for Agent Router / dashboard integration.
        """

        try:
            context_result = self._validate_task_context(task)
            if not context_result["success"]:
                return context_result

            context = context_result["data"]["context"]
            action = str(task.get("action") or "prepare_transaction_draft").strip().lower()
            payload = task.get("payload") or task.get("data") or {}

            if not isinstance(payload, Mapping):
                return self._error_result(
                    message="Task payload must be an object/dict.",
                    error="INVALID_PAYLOAD",
                    metadata={"action": action},
                )

            if action in {
                "prepare_transaction_draft",
                "prepare_draft",
                "draft_transaction",
            }:
                return self.prepare_transaction_draft(
                    context=context,
                    transaction_request=dict(payload),
                )

            if action == "prepare_vendor_payment_draft":
                return self.prepare_vendor_payment_draft(
                    context=context,
                    transaction_request=dict(payload),
                )

            if action == "prepare_bank_transfer_draft":
                return self.prepare_bank_transfer_draft(
                    context=context,
                    transaction_request=dict(payload),
                )

            if action == "prepare_card_payment_draft":
                return self.prepare_card_payment_draft(
                    context=context,
                    transaction_request=dict(payload),
                )

            if action == "get_transaction_draft":
                return self.get_transaction_draft(
                    context=context,
                    draft_id=str(payload.get("draft_id") or task.get("draft_id") or ""),
                )

            if action == "cancel_transaction_draft":
                return self.cancel_transaction_draft(
                    context=context,
                    draft_id=str(payload.get("draft_id") or task.get("draft_id") or ""),
                    reason=payload.get("reason"),
                )

            if action == "list_transaction_drafts":
                return self.list_transaction_drafts(
                    context=context,
                    status=payload.get("status"),
                    limit=int(payload.get("limit", 50)),
                )

            if action == "validate_transaction_request":
                validation = self.validate_transaction_request(
                    context=context,
                    transaction_request=dict(payload),
                )
                return self._safe_result(
                    success=validation["valid"],
                    message=(
                        "Transaction request is valid for draft preparation."
                        if validation["valid"]
                        else "Transaction request has validation errors."
                    ),
                    data=validation,
                    metadata={"action": action, "draft_only": True},
                )

            if action in NEVER_EXECUTE_KEYWORDS:
                return self._error_result(
                    message=(
                        "This module cannot execute financial actions. "
                        "It can prepare a draft for manual review only."
                    ),
                    error="EXECUTION_BLOCKED_DRAFT_ONLY",
                    metadata={
                        "action": action,
                        "draft_only": True,
                        "external_execution_allowed": False,
                    },
                )

            return self._error_result(
                message=f"Unsupported TransactionPreparer action: {action}",
                error="UNSUPPORTED_ACTION",
                metadata={"action": action},
            )

        except Exception as exc:
            self.logger.exception("TransactionPreparer task failed.")
            return self._error_result(
                message="TransactionPreparer task failed safely.",
                error=_public_error(exc),
                metadata={"module": MODULE_NAME},
            )

    # ----------------------------------------------------------------------------------
    # Public draft preparation methods
    # ----------------------------------------------------------------------------------

    def prepare_transaction_draft(
        self,
        context: Union[ActorContext, Mapping[str, Any]],
        transaction_request: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare a generic transaction draft.

        This is the main public method. It returns a structured draft payload
        and does not submit anything externally.
        """

        try:
            actor = self._coerce_actor_context(context)

            if not isinstance(transaction_request, Mapping):
                return self._error_result(
                    message="Transaction request must be a dict/object.",
                    error="INVALID_TRANSACTION_REQUEST",
                )

            raw_request = copy.deepcopy(dict(transaction_request))

            if _contains_execution_intent(raw_request):
                return self._error_result(
                    message=(
                        "Execution intent detected. TransactionPreparer only creates "
                        "drafts and cannot submit, execute, charge, or transfer funds."
                    ),
                    error="EXECUTION_INTENT_BLOCKED",
                    metadata={
                        "draft_only": True,
                        "external_execution_allowed": False,
                    },
                )

            validation = self.validate_transaction_request(actor, raw_request)
            if not validation["valid"]:
                self._log_audit_event(
                    event_type="transaction_draft_validation_failed",
                    context=actor,
                    payload={
                        "request": _deep_redact(raw_request),
                        "validation_errors": validation["errors"],
                    },
                )
                return self._safe_result(
                    success=False,
                    message="Transaction draft could not be prepared because validation failed.",
                    data=validation,
                    error="VALIDATION_FAILED",
                    metadata={
                        "draft_only": True,
                        "module": MODULE_NAME,
                    },
                )

            normalized = validation["normalized"]
            risk = self._assess_risk(actor, normalized)
            security_required = self._requires_security_check(
                action="prepare_transaction_draft",
                context=actor,
                payload=normalized,
                risk_level=risk["risk_level"],
            )

            draft_id = self._generate_draft_id(actor, normalized)
            now = _utc_now_iso()

            security_decision = (
                SecurityDecision.REQUIRED.value
                if security_required
                else SecurityDecision.NOT_REQUIRED.value
            )

            status = (
                TransactionDraftStatus.NEEDS_SECURITY_REVIEW.value
                if security_required
                else TransactionDraftStatus.NEEDS_USER_REVIEW.value
            )

            draft = TransactionDraft(
                draft_id=draft_id,
                user_id=actor.user_id,
                workspace_id=actor.workspace_id,
                transaction_type=normalized["transaction_type"],
                amount=str(normalized["amount"]),
                currency=normalized["currency"],
                payee=_deep_redact(normalized["payee"]),
                payment_method=normalized["payment_method"],
                memo=normalized.get("memo"),
                reference=normalized.get("reference"),
                scheduled_for=normalized.get("scheduled_for"),
                due_date=normalized.get("due_date"),
                line_items=normalized.get("line_items", []),
                attachments=normalized.get("attachments", []),
                status=status,
                risk_level=risk["risk_level"],
                security_decision=security_decision,
                warnings=validation["warnings"] + risk["warnings"],
                validation_errors=[],
                idempotency_key=normalized["idempotency_key"],
                created_at=now,
                updated_at=now,
                created_by=actor.to_dict(),
                source=normalized.get("source"),
                tags=normalized.get("tags", []),
                metadata={
                    "draft_only_notice": DRAFT_ONLY_NOTICE,
                    "risk": risk,
                    "original_request_hash": _sha256_text(_safe_json_dumps(_deep_redact(raw_request))),
                    "line_item_total": str(normalized.get("line_item_total", normalized["amount"])),
                    "external_execution_allowed": False,
                    "prepared_by": AGENT_NAME,
                    "module": AGENT_MODULE,
                },
                draft_only=True,
                external_execution_allowed=False,
            )

            if self.in_memory_store_enabled:
                self._store_draft(draft)

            security_payload = None
            if security_required:
                security_payload = self._request_security_approval(
                    action="prepare_transaction_draft",
                    context=actor,
                    payload=self._draft_to_dict(draft),
                    risk_level=risk["risk_level"],
                )
                if security_payload.get("success"):
                    draft.security_decision = SecurityDecision.REQUESTED.value
                    draft.updated_at = _utc_now_iso()
                    if self.in_memory_store_enabled:
                        self._store_draft(draft)

            verification_payload = self._prepare_verification_payload(
                action="transaction_draft_prepared",
                context=actor,
                payload=self._draft_to_dict(draft),
            )

            memory_payload = self._prepare_memory_payload(
                action="transaction_draft_prepared",
                context=actor,
                payload=self._draft_to_dict(draft),
            )

            self._emit_agent_event(
                event_type="transaction_draft_prepared",
                context=actor,
                payload={
                    "draft_id": draft.draft_id,
                    "status": draft.status,
                    "risk_level": draft.risk_level,
                    "security_required": security_required,
                    "amount": draft.amount,
                    "currency": draft.currency,
                    "transaction_type": draft.transaction_type,
                    "payment_method": draft.payment_method,
                    "draft_only": True,
                },
            )

            self._log_audit_event(
                event_type="transaction_draft_prepared",
                context=actor,
                payload={
                    "draft": self._draft_to_dict(draft),
                    "security_required": security_required,
                    "security_payload": security_payload,
                },
            )

            return self._safe_result(
                success=True,
                message=DRAFT_ONLY_NOTICE,
                data={
                    "draft": self._draft_to_dict(draft),
                    "security_required": security_required,
                    "security_payload": security_payload,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "next_action": (
                        "Security Agent review required before this draft can be marked ready for manual processing."
                        if security_required
                        else "User review required. Manual processing must happen outside this module."
                    ),
                },
                metadata={
                    "module": MODULE_NAME,
                    "agent": AGENT_NAME,
                    "draft_only": True,
                    "external_execution_allowed": False,
                    "version": self.version,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to prepare transaction draft.")
            return self._error_result(
                message="Failed to prepare transaction draft safely.",
                error=_public_error(exc),
                metadata={
                    "module": MODULE_NAME,
                    "draft_only": True,
                    "external_execution_allowed": False,
                },
            )

    def prepare_vendor_payment_draft(
        self,
        context: Union[ActorContext, Mapping[str, Any]],
        transaction_request: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare a vendor payment draft only.
        """

        request = dict(transaction_request)
        request["transaction_type"] = TransactionType.VENDOR_PAYMENT.value
        request.setdefault("payment_method", "vendor_payment")
        return self.prepare_transaction_draft(context, request)

    def prepare_bank_transfer_draft(
        self,
        context: Union[ActorContext, Mapping[str, Any]],
        transaction_request: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare a bank transfer draft only.

        No bank API call is made.
        """

        request = dict(transaction_request)
        request["transaction_type"] = request.get(
            "transaction_type",
            TransactionType.BANK_TRANSFER.value,
        )
        request.setdefault("payment_method", "bank_transfer")
        return self.prepare_transaction_draft(context, request)

    def prepare_card_payment_draft(
        self,
        context: Union[ActorContext, Mapping[str, Any]],
        transaction_request: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare a card payment draft only.

        No card authorization, capture, charge, tokenization, or payment gateway
        call is performed.
        """

        request = dict(transaction_request)
        request["transaction_type"] = TransactionType.CARD_PAYMENT.value
        request.setdefault("payment_method", "card_payment")
        return self.prepare_transaction_draft(context, request)

    # ----------------------------------------------------------------------------------
    # Public validation and draft management
    # ----------------------------------------------------------------------------------

    def validate_transaction_request(
        self,
        context: Union[ActorContext, Mapping[str, Any]],
        transaction_request: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Validate and normalize a transaction draft request.

        Returns:
            {
                "valid": bool,
                "errors": [...],
                "warnings": [...],
                "normalized": {...}
            }
        """

        errors: List[str] = []
        warnings: List[str] = []
        normalized: Dict[str, Any] = {}

        try:
            actor = self._coerce_actor_context(context)
        except Exception as exc:
            return {
                "valid": False,
                "errors": [str(exc)],
                "warnings": [],
                "normalized": {},
            }

        if not isinstance(transaction_request, Mapping):
            return {
                "valid": False,
                "errors": ["transaction_request must be a dict/object."],
                "warnings": [],
                "normalized": {},
            }

        request = copy.deepcopy(dict(transaction_request))

        transaction_type = _clean_transaction_type(
            request.get("transaction_type") or request.get("type") or TransactionType.OTHER.value
        )
        valid_transaction_types = {item.value for item in TransactionType}
        if transaction_type not in valid_transaction_types:
            warnings.append(
                f"Unknown transaction_type '{transaction_type}' normalized to 'other'."
            )
            transaction_type = TransactionType.OTHER.value

        payment_method = _clean_payment_method(
            request.get("payment_method") or request.get("method") or "other"
        )
        if payment_method not in set(self.supported_payment_methods):
            errors.append(
                f"Unsupported payment_method '{payment_method}'. "
                f"Supported methods: {sorted(self.supported_payment_methods)}"
            )

        currency = _clean_currency(request.get("currency"))
        if not currency:
            errors.append("currency is required.")
        elif currency not in set(self.supported_currencies):
            errors.append(
                f"Unsupported currency '{currency}'. "
                f"Supported currencies: {sorted(self.supported_currencies)}"
            )

        try:
            amount = _to_decimal(request.get("amount"), "amount")
            if amount <= Decimal("0"):
                errors.append("amount must be greater than zero.")
        except Exception as exc:
            amount = Decimal("0.00")
            errors.append(str(exc))

        payee_result = self._normalize_payee(request.get("payee") or request.get("recipient"))
        if payee_result["errors"]:
            errors.extend(payee_result["errors"])

        line_items_result = self._normalize_line_items(request.get("line_items"))
        if line_items_result["errors"]:
            errors.extend(line_items_result["errors"])

        line_item_total = line_items_result["total"]
        if line_items_result["items"]:
            if line_item_total != amount:
                warnings.append(
                    "Line item total does not match transaction amount. "
                    f"line_item_total={line_item_total}, amount={amount}."
                )

        try:
            scheduled_for = _parse_optional_date(
                request.get("scheduled_for") or request.get("scheduled_date"),
                "scheduled_for",
            )
        except Exception as exc:
            scheduled_for = None
            errors.append(str(exc))

        try:
            due_date = _parse_optional_date(request.get("due_date"), "due_date")
        except Exception as exc:
            due_date = None
            errors.append(str(exc))

        memo = _normalize_string(request.get("memo") or request.get("description"))
        reference = _normalize_string(request.get("reference") or request.get("invoice_id"))

        attachments = self._normalize_attachments(request.get("attachments"))
        tags = [
            _normalize_string(tag)
            for tag in _coerce_list(request.get("tags"))
            if _normalize_string(tag)
        ]

        source = _normalize_string(request.get("source") or "finance_agent")
        idempotency_key = self._build_idempotency_key(
            actor=actor,
            transaction_type=transaction_type,
            amount=amount,
            currency=currency,
            payee=payee_result["payee"],
            payment_method=payment_method,
            reference=reference,
            scheduled_for=scheduled_for,
            explicit_key=request.get("idempotency_key"),
        )

        if not reference:
            warnings.append("No reference/invoice_id provided. Manual review is recommended.")

        if payment_method in {"bank_transfer", "wire_transfer", "ach", "sepa"}:
            payee = payee_result["payee"]
            has_bank_identifier = any(
                payee.get(key)
                for key in (
                    "account_number",
                    "account_last4",
                    "iban",
                    "routing_number",
                    "swift",
                    "bic",
                )
            )
            if not has_bank_identifier:
                warnings.append(
                    "Bank-style payment method selected but no bank identifier was provided."
                )

        normalized = {
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "transaction_type": transaction_type,
            "amount": amount,
            "currency": currency,
            "payee": payee_result["payee"],
            "payment_method": payment_method,
            "memo": memo or None,
            "reference": reference or None,
            "scheduled_for": scheduled_for,
            "due_date": due_date,
            "line_items": line_items_result["items"],
            "line_item_total": line_item_total,
            "attachments": attachments,
            "tags": tags,
            "source": source,
            "idempotency_key": idempotency_key,
        }

        return {
            "valid": not errors,
            "errors": errors,
            "warnings": warnings,
            "normalized": normalized,
        }

    def get_transaction_draft(
        self,
        context: Union[ActorContext, Mapping[str, Any]],
        draft_id: str,
    ) -> Dict[str, Any]:
        """
        Get a stored draft by draft_id while enforcing user/workspace isolation.

        This uses the local in-memory store only. In production, the Dashboard/API
        layer can persist returned draft payloads in a tenant-isolated database.
        """

        try:
            actor = self._coerce_actor_context(context)
            clean_draft_id = _normalize_string(draft_id)

            if not clean_draft_id:
                return self._error_result(
                    message="draft_id is required.",
                    error="MISSING_DRAFT_ID",
                )

            draft = self._draft_store.get((actor.user_id, actor.workspace_id, clean_draft_id))
            if not draft:
                return self._error_result(
                    message="Transaction draft was not found for this user/workspace.",
                    error="DRAFT_NOT_FOUND",
                    metadata={"draft_id": clean_draft_id},
                )

            return self._safe_result(
                success=True,
                message="Transaction draft retrieved.",
                data={"draft": self._draft_to_dict(draft)},
                metadata={
                    "draft_only": True,
                    "external_execution_allowed": False,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to retrieve transaction draft.",
                error=_public_error(exc),
            )

    def list_transaction_drafts(
        self,
        context: Union[ActorContext, Mapping[str, Any]],
        status: Optional[str] = None,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """
        List stored drafts for the current user/workspace only.
        """

        try:
            actor = self._coerce_actor_context(context)
            clean_status = _normalize_string(status).lower() if status else None
            safe_limit = max(1, min(int(limit), 250))

            drafts: List[Dict[str, Any]] = []
            for (user_id, workspace_id, _draft_id), draft in self._draft_store.items():
                if user_id != actor.user_id or workspace_id != actor.workspace_id:
                    continue
                if clean_status and draft.status != clean_status:
                    continue
                drafts.append(self._draft_to_dict(draft))
                if len(drafts) >= safe_limit:
                    break

            drafts.sort(key=lambda item: item.get("created_at", ""), reverse=True)

            return self._safe_result(
                success=True,
                message="Transaction drafts listed.",
                data={
                    "drafts": drafts,
                    "count": len(drafts),
                    "limit": safe_limit,
                    "status_filter": clean_status,
                },
                metadata={
                    "draft_only": True,
                    "external_execution_allowed": False,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to list transaction drafts.",
                error=_public_error(exc),
            )

    def cancel_transaction_draft(
        self,
        context: Union[ActorContext, Mapping[str, Any]],
        draft_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Cancel a local draft.

        This does not cancel any external payment, because this module never
        creates external payments.
        """

        try:
            actor = self._coerce_actor_context(context)
            clean_draft_id = _normalize_string(draft_id)

            if not clean_draft_id:
                return self._error_result(
                    message="draft_id is required.",
                    error="MISSING_DRAFT_ID",
                )

            key = (actor.user_id, actor.workspace_id, clean_draft_id)
            draft = self._draft_store.get(key)
            if not draft:
                return self._error_result(
                    message="Transaction draft was not found for this user/workspace.",
                    error="DRAFT_NOT_FOUND",
                    metadata={"draft_id": clean_draft_id},
                )

            draft.status = TransactionDraftStatus.CANCELLED.value
            draft.updated_at = _utc_now_iso()
            draft.metadata["cancel_reason"] = _normalize_string(reason) or "No reason provided."
            self._draft_store[key] = draft

            self._emit_agent_event(
                event_type="transaction_draft_cancelled",
                context=actor,
                payload={
                    "draft_id": draft.draft_id,
                    "reason": draft.metadata["cancel_reason"],
                    "draft_only": True,
                },
            )

            self._log_audit_event(
                event_type="transaction_draft_cancelled",
                context=actor,
                payload={
                    "draft_id": draft.draft_id,
                    "reason": draft.metadata["cancel_reason"],
                    "draft_only": True,
                },
            )

            return self._safe_result(
                success=True,
                message="Transaction draft cancelled. No external financial action was affected.",
                data={"draft": self._draft_to_dict(draft)},
                metadata={
                    "draft_only": True,
                    "external_execution_allowed": False,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to cancel transaction draft.",
                error=_public_error(exc),
            )

    # ----------------------------------------------------------------------------------
    # Required compatibility hooks
    # ----------------------------------------------------------------------------------

    def _validate_task_context(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate user/workspace context from a routed task.

        Required hook for William/Jarvis compatibility.
        """

        if not isinstance(task, Mapping):
            return self._error_result(
                message="Task must be a dict/object.",
                error="INVALID_TASK",
            )

        user_id = _normalize_string(task.get("user_id") or task.get("userId"))
        workspace_id = _normalize_string(task.get("workspace_id") or task.get("workspaceId"))

        payload = task.get("payload") or task.get("data") or {}
        if isinstance(payload, Mapping):
            user_id = user_id or _normalize_string(payload.get("user_id") or payload.get("userId"))
            workspace_id = workspace_id or _normalize_string(
                payload.get("workspace_id") or payload.get("workspaceId")
            )

        if not user_id:
            return self._error_result(
                message="user_id is required for transaction draft preparation.",
                error="MISSING_USER_ID",
            )

        if not workspace_id:
            return self._error_result(
                message="workspace_id is required for transaction draft preparation.",
                error="MISSING_WORKSPACE_ID",
            )

        context = ActorContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=_normalize_string(task.get("role")) or None,
            request_id=_normalize_string(task.get("request_id")) or str(uuid.uuid4()),
            session_id=_normalize_string(task.get("session_id")) or None,
            ip_address=_normalize_string(task.get("ip_address")) or None,
            user_agent=_normalize_string(task.get("user_agent")) or None,
        )

        return self._safe_result(
            success=True,
            message="Task context validated.",
            data={"context": context},
            metadata={"module": MODULE_NAME},
        )

    def _requires_security_check(
        self,
        action: str,
        context: ActorContext,
        payload: Mapping[str, Any],
        risk_level: Optional[str] = None,
    ) -> bool:
        """
        Decide whether Security Agent review is required.

        Required hook for William/Jarvis compatibility.

        Finance drafts are sensitive. External payment methods and medium+
        risk levels require a Security Agent handoff by default.
        """

        payment_method = _clean_payment_method(payload.get("payment_method"))
        transaction_type = _clean_transaction_type(payload.get("transaction_type"))
        amount = payload.get("amount", Decimal("0"))

        try:
            amount_decimal = _to_decimal(amount)
        except Exception:
            amount_decimal = Decimal("0.00")

        external_methods = {
            "bank_transfer",
            "wire_transfer",
            "ach",
            "sepa",
            "card_payment",
            "vendor_payment",
            "manual_payment",
        }

        if risk_level in {
            TransactionRiskLevel.MEDIUM.value,
            TransactionRiskLevel.HIGH.value,
            TransactionRiskLevel.CRITICAL.value,
        }:
            return True

        if self.require_security_for_all_external_payments and payment_method in external_methods:
            return True

        if transaction_type in {
            TransactionType.BANK_TRANSFER.value,
            TransactionType.WIRE_TRANSFER.value,
            TransactionType.VENDOR_PAYMENT.value,
            TransactionType.CARD_PAYMENT.value,
            TransactionType.REIMBURSEMENT.value,
            TransactionType.REFUND.value,
        }:
            return True

        if amount_decimal > self.max_low_risk_amount:
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: ActorContext,
        payload: Mapping[str, Any],
        risk_level: str,
    ) -> Dict[str, Any]:
        """
        Prepare/request Security Agent approval.

        Required hook for William/Jarvis compatibility.

        This method only requests review/approval metadata. It does not give this
        module permission to submit a real transaction.
        """

        approval_request = {
            "approval_id": f"sec_{uuid.uuid4().hex}",
            "action": action,
            "agent": AGENT_NAME,
            "module": AGENT_MODULE,
            "risk_level": risk_level,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "payload": _deep_redact(payload),
            "constraints": {
                "draft_only": True,
                "external_execution_allowed": False,
                "security_review_purpose": "Review transaction draft preparation only.",
                "cannot_submit_transfer": True,
            },
            "created_at": _utc_now_iso(),
        }

        if self.security_client is None:
            return self._safe_result(
                success=True,
                message="Security approval payload prepared. No Security Agent client is attached.",
                data={"approval_request": approval_request},
                metadata={
                    "security_decision": SecurityDecision.REQUESTED.value,
                    "draft_only": True,
                },
            )

        try:
            client = self.security_client

            if hasattr(client, "request_approval"):
                response = client.request_approval(approval_request)
            elif hasattr(client, "review"):
                response = client.review(approval_request)
            elif hasattr(client, "check"):
                response = client.check(approval_request)
            else:
                response = {
                    "success": False,
                    "message": "Security client has no supported approval method.",
                }

            return self._safe_result(
                success=True,
                message="Security Agent approval request prepared/sent for draft review.",
                data={
                    "approval_request": approval_request,
                    "security_client_response": _deep_redact(response),
                },
                metadata={
                    "security_decision": SecurityDecision.REQUESTED.value,
                    "draft_only": True,
                    "external_execution_allowed": False,
                },
            )

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return self._error_result(
                message="Security approval request failed safely.",
                error=_public_error(exc),
                data={"approval_request": approval_request},
                metadata={
                    "security_decision": SecurityDecision.REQUIRED.value,
                    "draft_only": True,
                    "external_execution_allowed": False,
                },
            )

    def _prepare_verification_payload(
        self,
        action: str,
        context: ActorContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Required hook for William/Jarvis compatibility.
        """

        verification_payload = {
            "verification_id": f"ver_{uuid.uuid4().hex}",
            "action": action,
            "agent": AGENT_NAME,
            "module": AGENT_MODULE,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "created_at": _utc_now_iso(),
            "payload": _deep_redact(payload),
            "checks": [
                "draft_only_confirmed",
                "no_external_execution",
                "tenant_context_present",
                "amount_currency_validated",
                "payee_redacted",
                "security_review_marked_where_required",
            ],
            "assertions": {
                "draft_only": True,
                "external_execution_allowed": False,
                "real_transfer_submitted": False,
                "requires_manual_human_processing": True,
            },
        }

        if self.verification_client is not None:
            try:
                if hasattr(self.verification_client, "prepare"):
                    client_response = self.verification_client.prepare(verification_payload)
                elif hasattr(self.verification_client, "record"):
                    client_response = self.verification_client.record(verification_payload)
                else:
                    client_response = None
                verification_payload["verification_client_response"] = _deep_redact(client_response)
            except Exception as exc:
                verification_payload["verification_client_error"] = _public_error(exc)

        return verification_payload

    def _prepare_memory_payload(
        self,
        action: str,
        context: ActorContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Required hook for William/Jarvis compatibility.

        Memory payload deliberately excludes full sensitive financial details.
        """

        safe_payload = _deep_redact(payload)
        draft = safe_payload.get("draft", safe_payload)

        memory_payload = {
            "memory_id": f"mem_{uuid.uuid4().hex}",
            "action": action,
            "agent": AGENT_NAME,
            "module": AGENT_MODULE,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "created_at": _utc_now_iso(),
            "memory_type": "finance_transaction_draft_summary",
            "summary": {
                "draft_id": draft.get("draft_id"),
                "transaction_type": draft.get("transaction_type"),
                "payment_method": draft.get("payment_method"),
                "amount": draft.get("amount"),
                "currency": draft.get("currency"),
                "status": draft.get("status"),
                "risk_level": draft.get("risk_level"),
                "draft_only": True,
            },
            "payload": safe_payload,
            "privacy": {
                "contains_sensitive_finance_data": True,
                "sensitive_values_redacted": True,
                "tenant_scoped": True,
            },
        }

        if self.memory_client is not None:
            try:
                if hasattr(self.memory_client, "prepare"):
                    client_response = self.memory_client.prepare(memory_payload)
                elif hasattr(self.memory_client, "store"):
                    client_response = self.memory_client.store(memory_payload)
                elif hasattr(self.memory_client, "remember"):
                    client_response = self.memory_client.remember(memory_payload)
                else:
                    client_response = None
                memory_payload["memory_client_response"] = _deep_redact(client_response)
            except Exception as exc:
                memory_payload["memory_client_error"] = _public_error(exc)

        return memory_payload

    def _emit_agent_event(
        self,
        event_type: str,
        context: ActorContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Emit dashboard/API/analytics event.

        Required hook for William/Jarvis compatibility.
        """

        event = {
            "event_id": f"evt_{uuid.uuid4().hex}",
            "event_type": event_type,
            "agent": AGENT_NAME,
            "module": AGENT_MODULE,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "created_at": _utc_now_iso(),
            "payload": _deep_redact(payload),
        }

        if self.event_emitter is not None:
            try:
                self.event_emitter(event)
                event["emitted"] = True
            except Exception as exc:
                event["emitted"] = False
                event["emit_error"] = _public_error(exc)
                self.logger.warning("Failed to emit TransactionPreparer event: %s", exc)
        else:
            event["emitted"] = False
            event["emit_reason"] = "No event_emitter configured."

        return event

    def _log_audit_event(
        self,
        event_type: str,
        context: ActorContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Log audit event.

        Required hook for William/Jarvis compatibility.

        Audit payloads are tenant-scoped and redacted.
        """

        audit_event = {
            "audit_id": f"aud_{uuid.uuid4().hex}",
            "event_type": event_type,
            "agent": AGENT_NAME,
            "module": AGENT_MODULE,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "created_at": _utc_now_iso(),
            "payload": _deep_redact(payload),
            "safety": {
                "draft_only": True,
                "external_execution_allowed": False,
                "real_financial_action_performed": False,
            },
        }

        if self.audit_logger is not None:
            try:
                self.audit_logger(audit_event)
                audit_event["logged"] = True
            except Exception as exc:
                audit_event["logged"] = False
                audit_event["log_error"] = _public_error(exc)
                self.logger.warning("Failed to write TransactionPreparer audit event: %s", exc)
        else:
            audit_event["logged"] = False
            audit_event["log_reason"] = "No audit_logger configured."
            self.logger.info("Audit event prepared: %s", _safe_json_dumps(audit_event))

        return audit_event

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Any] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured result.

        Required hook for William/Jarvis compatibility.
        """

        return {
            "success": bool(success),
            "message": str(message),
            "data": data if data is not None else {},
            "error": error,
            "metadata": {
                "agent": AGENT_NAME,
                "module": MODULE_NAME,
                "agent_module": AGENT_MODULE,
                "version": self.version,
                "timestamp": _utc_now_iso(),
                **dict(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard structured error result.

        Required hook for William/Jarvis compatibility.
        """

        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error or "ERROR",
            metadata={
                "draft_only": True,
                "external_execution_allowed": False,
                **dict(metadata or {}),
            },
        )

    # ----------------------------------------------------------------------------------
    # Internal normalization helpers
    # ----------------------------------------------------------------------------------

    def _coerce_actor_context(
        self,
        context: Union[ActorContext, Mapping[str, Any]],
    ) -> ActorContext:
        if isinstance(context, ActorContext):
            if not context.user_id or not context.workspace_id:
                raise ValueError("ActorContext requires user_id and workspace_id.")
            return context

        if not isinstance(context, Mapping):
            raise ValueError("context must be ActorContext or dict/object.")

        user_id = _normalize_string(context.get("user_id") or context.get("userId"))
        workspace_id = _normalize_string(context.get("workspace_id") or context.get("workspaceId"))

        if not user_id:
            raise ValueError("user_id is required.")
        if not workspace_id:
            raise ValueError("workspace_id is required.")

        return ActorContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=_normalize_string(context.get("role")) or None,
            request_id=_normalize_string(context.get("request_id")) or str(uuid.uuid4()),
            session_id=_normalize_string(context.get("session_id")) or None,
            ip_address=_normalize_string(context.get("ip_address")) or None,
            user_agent=_normalize_string(context.get("user_agent")) or None,
        )

    def _normalize_payee(self, payee_input: Any) -> Dict[str, Any]:
        errors: List[str] = []

        if payee_input is None:
            return {
                "payee": {},
                "errors": ["payee/recipient is required."],
            }

        if isinstance(payee_input, Payee):
            payee = asdict(payee_input)
        elif isinstance(payee_input, Mapping):
            payee = dict(payee_input)
        else:
            return {
                "payee": {},
                "errors": ["payee/recipient must be a dict/object or Payee."],
            }

        name = _normalize_string(payee.get("name") or payee.get("business_name"))
        if not name:
            errors.append("payee.name is required.")

        email = _normalize_string(payee.get("email"))
        if email and not self._is_probable_email(email):
            errors.append("payee.email is not valid.")

        account_last4 = _normalize_string(payee.get("account_last4"))
        account_number = _normalize_string(payee.get("account_number"))
        if not account_last4 and account_number:
            digits = re.sub(r"\D", "", account_number)
            if digits:
                account_last4 = digits[-4:]

        normalized = {
            "name": name,
            "payee_id": _normalize_string(payee.get("payee_id") or payee.get("id")) or None,
            "email": email or None,
            "phone": _normalize_string(payee.get("phone")) or None,
            "country": _normalize_string(payee.get("country")).upper() or None,
            "address": _normalize_string(payee.get("address")) or None,
            "bank_name": _normalize_string(payee.get("bank_name")) or None,
            "account_last4": account_last4 or None,
            "account_number": account_number or None,
            "routing_number": _normalize_string(payee.get("routing_number")) or None,
            "iban": _normalize_string(payee.get("iban")).replace(" ", "").upper() or None,
            "swift": _normalize_string(payee.get("swift")).replace(" ", "").upper() or None,
            "bic": _normalize_string(payee.get("bic")).replace(" ", "").upper() or None,
            "metadata": dict(payee.get("metadata") or {}),
        }

        iban = normalized.get("iban")
        if iban and not self._is_probable_iban(iban):
            errors.append("payee.iban does not look valid.")

        swift = normalized.get("swift")
        bic = normalized.get("bic")
        if swift and not self._is_probable_swift(swift):
            errors.append("payee.swift does not look valid.")
        if bic and not self._is_probable_swift(bic):
            errors.append("payee.bic does not look valid.")

        return {
            "payee": normalized,
            "errors": errors,
        }

    def _normalize_line_items(self, line_items_input: Any) -> Dict[str, Any]:
        errors: List[str] = []
        normalized_items: List[Dict[str, Any]] = []
        total = Decimal("0.00")

        for index, item in enumerate(_coerce_list(line_items_input)):
            if item is None:
                continue

            if isinstance(item, TransactionLineItem):
                raw = asdict(item)
            elif isinstance(item, Mapping):
                raw = dict(item)
            else:
                errors.append(f"line_items[{index}] must be a dict/object.")
                continue

            description = _normalize_string(raw.get("description") or raw.get("name"))
            if not description:
                errors.append(f"line_items[{index}].description is required.")

            try:
                amount = _to_decimal(raw.get("amount"), f"line_items[{index}].amount")
            except Exception as exc:
                amount = Decimal("0.00")
                errors.append(str(exc))

            try:
                quantity = _to_decimal(raw.get("quantity", "1"), f"line_items[{index}].quantity")
            except Exception as exc:
                quantity = Decimal("1.00")
                errors.append(str(exc))

            try:
                tax_amount = _to_decimal(raw.get("tax_amount", "0"), f"line_items[{index}].tax_amount")
            except Exception as exc:
                tax_amount = Decimal("0.00")
                errors.append(str(exc))

            if quantity <= Decimal("0"):
                errors.append(f"line_items[{index}].quantity must be greater than zero.")

            if amount < Decimal("0"):
                errors.append(f"line_items[{index}].amount cannot be negative.")

            if tax_amount < Decimal("0"):
                errors.append(f"line_items[{index}].tax_amount cannot be negative.")

            line_total = (amount * quantity + tax_amount).quantize(
                Decimal("0.01"),
                rounding=ROUND_HALF_UP,
            )
            total += line_total

            normalized_items.append(
                {
                    "description": description,
                    "amount": str(amount),
                    "quantity": str(quantity),
                    "tax_amount": str(tax_amount),
                    "line_total": str(line_total),
                    "category": _normalize_string(raw.get("category")) or None,
                    "metadata": _deep_redact(dict(raw.get("metadata") or {})),
                }
            )

        return {
            "items": normalized_items,
            "total": total.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP),
            "errors": errors,
        }

    def _normalize_attachments(self, attachments_input: Any) -> List[Dict[str, Any]]:
        attachments: List[Dict[str, Any]] = []

        for item in _coerce_list(attachments_input):
            if not item:
                continue

            if isinstance(item, Mapping):
                attachment = {
                    "attachment_id": _normalize_string(item.get("attachment_id") or item.get("id")) or None,
                    "filename": _normalize_string(item.get("filename") or item.get("name")) or None,
                    "mime_type": _normalize_string(item.get("mime_type")) or None,
                    "size_bytes": item.get("size_bytes"),
                    "source": _normalize_string(item.get("source")) or None,
                    "metadata": _deep_redact(dict(item.get("metadata") or {})),
                }
            else:
                attachment = {
                    "attachment_id": None,
                    "filename": _normalize_string(item),
                    "mime_type": None,
                    "size_bytes": None,
                    "source": None,
                    "metadata": {},
                }

            attachments.append(attachment)

        return attachments

    def _build_idempotency_key(
        self,
        actor: ActorContext,
        transaction_type: str,
        amount: Decimal,
        currency: str,
        payee: Mapping[str, Any],
        payment_method: str,
        reference: Optional[str],
        scheduled_for: Optional[str],
        explicit_key: Optional[Any] = None,
    ) -> str:
        explicit = _normalize_string(explicit_key)
        if explicit:
            return explicit

        base = {
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "transaction_type": transaction_type,
            "amount": str(amount),
            "currency": currency,
            "payee_name": payee.get("name"),
            "payee_id": payee.get("payee_id"),
            "payment_method": payment_method,
            "reference": reference,
            "scheduled_for": scheduled_for,
        }
        return f"txn_draft_{_sha256_text(_safe_json_dumps(base))[:32]}"

    def _generate_draft_id(
        self,
        actor: ActorContext,
        normalized_request: Mapping[str, Any],
    ) -> str:
        seed = {
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "idempotency_key": normalized_request.get("idempotency_key"),
        }
        return f"tdraft_{_sha256_text(_safe_json_dumps(seed))[:24]}"

    def _assess_risk(
        self,
        context: ActorContext,
        normalized_request: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Simple deterministic risk scoring for draft review.

        This is not fraud detection. It is a Finance Agent preparation signal
        for Security Agent and dashboard review.
        """

        warnings: List[str] = []
        score = 0

        amount = _to_decimal(normalized_request.get("amount", "0"))
        payment_method = _clean_payment_method(normalized_request.get("payment_method"))
        transaction_type = _clean_transaction_type(normalized_request.get("transaction_type"))
        payee = normalized_request.get("payee") or {}

        if amount > self.max_high_risk_amount:
            score += 70
            warnings.append("Amount exceeds high-risk threshold.")
        elif amount > self.max_medium_risk_amount:
            score += 45
            warnings.append("Amount exceeds medium-risk threshold.")
        elif amount > self.max_low_risk_amount:
            score += 20
            warnings.append("Amount exceeds low-risk threshold.")

        if payment_method in {"wire_transfer", "bank_transfer", "ach", "sepa"}:
            score += 20

        if transaction_type in {"refund", "reimbursement"}:
            score += 10

        if not payee.get("payee_id"):
            score += 10
            warnings.append("Payee has no internal payee_id.")

        if not normalized_request.get("reference"):
            score += 10

        if payee.get("country") and str(payee.get("country")).upper() not in {
            "US",
            "USA",
            "GB",
            "UK",
            "CA",
            "AU",
            "AE",
            "SA",
            "PK",
        }:
            score += 15
            warnings.append("Payee country may require additional review.")

        if score >= 80:
            risk_level = TransactionRiskLevel.CRITICAL.value
        elif score >= 50:
            risk_level = TransactionRiskLevel.HIGH.value
        elif score >= 20:
            risk_level = TransactionRiskLevel.MEDIUM.value
        else:
            risk_level = TransactionRiskLevel.LOW.value

        return {
            "risk_level": risk_level,
            "risk_score": min(score, 100),
            "warnings": warnings,
            "thresholds": {
                "max_low_risk_amount": str(self.max_low_risk_amount),
                "max_medium_risk_amount": str(self.max_medium_risk_amount),
                "max_high_risk_amount": str(self.max_high_risk_amount),
            },
        }

    # ----------------------------------------------------------------------------------
    # Store and serialization
    # ----------------------------------------------------------------------------------

    def _store_draft(self, draft: TransactionDraft) -> None:
        key = (draft.user_id, draft.workspace_id, draft.draft_id)
        self._draft_store[key] = draft

    def _draft_to_dict(self, draft: TransactionDraft) -> Dict[str, Any]:
        data = asdict(draft)
        return _deep_redact(data)

    # ----------------------------------------------------------------------------------
    # Config helpers
    # ----------------------------------------------------------------------------------

    def _build_default_config(self) -> Any:
        if FinanceAgentConfig is not None:
            try:
                return FinanceAgentConfig()
            except Exception:
                pass

        return {
            "supported_currencies": DEFAULT_SUPPORTED_CURRENCIES,
            "supported_payment_methods": DEFAULT_PAYMENT_METHODS,
            "max_low_risk_amount": "1000.00",
            "max_medium_risk_amount": "10000.00",
            "max_high_risk_amount": "50000.00",
            "require_security_for_all_external_payments": True,
        }

    def _config_get(self, key: str, default: Any = None) -> Any:
        config = self.config

        if isinstance(config, Mapping):
            return config.get(key, default)

        if hasattr(config, key):
            return getattr(config, key)

        if hasattr(config, "get"):
            try:
                return config.get(key, default)
            except Exception:
                return default

        return default

    # ----------------------------------------------------------------------------------
    # Validators
    # ----------------------------------------------------------------------------------

    @staticmethod
    def _is_probable_email(value: str) -> bool:
        return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value))

    @staticmethod
    def _is_probable_iban(value: str) -> bool:
        compact = value.replace(" ", "").upper()
        return bool(re.match(r"^[A-Z]{2}[0-9A-Z]{13,32}$", compact))

    @staticmethod
    def _is_probable_swift(value: str) -> bool:
        compact = value.replace(" ", "").upper()
        return bool(re.match(r"^[A-Z]{4}[A-Z]{2}[0-9A-Z]{2}([0-9A-Z]{3})?$", compact))

    # ----------------------------------------------------------------------------------
    # Explicitly blocked execution methods
    # ----------------------------------------------------------------------------------

    def submit_transaction(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """
        Explicit safety blocker.

        This method exists so accidental calls fail safely with a structured
        response instead of attempting any real action.
        """

        return self._error_result(
            message=(
                "submit_transaction is blocked. TransactionPreparer only prepares "
                "drafts and never submits real transfers."
            ),
            error="METHOD_BLOCKED_DRAFT_ONLY",
            metadata={
                "blocked_method": "submit_transaction",
                "draft_only": True,
                "external_execution_allowed": False,
            },
        )

    def execute_transaction(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """
        Explicit safety blocker.
        """

        return self._error_result(
            message=(
                "execute_transaction is blocked. TransactionPreparer only prepares "
                "drafts and never executes real financial actions."
            ),
            error="METHOD_BLOCKED_DRAFT_ONLY",
            metadata={
                "blocked_method": "execute_transaction",
                "draft_only": True,
                "external_execution_allowed": False,
            },
        )

    def send_transfer(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """
        Explicit safety blocker.
        """

        return self._error_result(
            message=(
                "send_transfer is blocked. TransactionPreparer only prepares "
                "drafts and never sends transfers."
            ),
            error="METHOD_BLOCKED_DRAFT_ONLY",
            metadata={
                "blocked_method": "send_transfer",
                "draft_only": True,
                "external_execution_allowed": False,
            },
        )

    def charge_card(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """
        Explicit safety blocker.
        """

        return self._error_result(
            message=(
                "charge_card is blocked. TransactionPreparer only prepares "
                "drafts and never charges cards."
            ),
            error="METHOD_BLOCKED_DRAFT_ONLY",
            metadata={
                "blocked_method": "charge_card",
                "draft_only": True,
                "external_execution_allowed": False,
            },
        )


# ======================================================================================
# Registry metadata
# ======================================================================================

AGENT_REGISTRY_METADATA: Dict[str, Any] = {
    "agent_name": AGENT_NAME,
    "module": AGENT_MODULE,
    "file": "transaction_preparer.py",
    "class_name": "TransactionPreparer",
    "version": DEFAULT_VERSION,
    "purpose": "Prepares transaction drafts only; never submits transfer.",
    "draft_only": True,
    "external_execution_allowed": False,
    "requires_user_id": True,
    "requires_workspace_id": True,
    "compatible_with": [
        "BaseAgent",
        "AgentRegistry",
        "AgentLoader",
        "AgentRouter",
        "MasterAgent",
        "SecurityAgent",
        "VerificationAgent",
        "MemoryAgent",
        "DashboardAPI",
    ],
    "public_methods": [
        "handle_task",
        "run",
        "prepare_transaction_draft",
        "prepare_vendor_payment_draft",
        "prepare_bank_transfer_draft",
        "prepare_card_payment_draft",
        "validate_transaction_request",
        "get_transaction_draft",
        "list_transaction_drafts",
        "cancel_transaction_draft",
    ],
    "blocked_methods": [
        "submit_transaction",
        "execute_transaction",
        "send_transfer",
        "charge_card",
    ],
}


def get_agent_registry_metadata() -> Dict[str, Any]:
    """
    Agent Loader / Agent Registry discovery helper.
    """

    return copy.deepcopy(AGENT_REGISTRY_METADATA)


def build_transaction_preparer(**kwargs: Any) -> TransactionPreparer:
    """
    Factory helper for Agent Loader, tests, and FastAPI dependency injection.
    """

    return TransactionPreparer(**kwargs)


__all__ = [
    "ActorContext",
    "Payee",
    "TransactionLineItem",
    "TransactionDraft",
    "TransactionDraftStatus",
    "TransactionType",
    "TransactionRiskLevel",
    "SecurityDecision",
    "TransactionPreparer",
    "AGENT_REGISTRY_METADATA",
    "get_agent_registry_metadata",
    "build_transaction_preparer",
]


"""
Where to place it:
    agents/super_agents/finance_agent/transaction_preparer.py

Required dependencies:
    Python standard library only.
    Optional project dependency:
        agents.base_agent.BaseAgent
        agents.super_agents.finance_agent.config.FinanceAgentConfig

How to test it:
    from agents.super_agents.finance_agent.transaction_preparer import TransactionPreparer

    preparer = TransactionPreparer()
    result = preparer.prepare_transaction_draft(
        context={
            "user_id": "user_123",
            "workspace_id": "workspace_abc",
            "role": "owner",
        },
        transaction_request={
            "transaction_type": "vendor_payment",
            "amount": "250.00",
            "currency": "USD",
            "payment_method": "vendor_payment",
            "payee": {
                "name": "Example Vendor",
                "email": "billing@example.com",
                "payee_id": "vendor_001",
            },
            "reference": "INV-1001",
            "memo": "Website design milestone draft",
            "line_items": [
                {
                    "description": "Milestone 1",
                    "amount": "250.00",
                    "quantity": 1,
                    "tax_amount": "0.00",
                    "category": "web_development",
                }
            ],
        },
    )

    assert result["success"] is True
    assert result["data"]["draft"]["draft_only"] is True
    assert result["data"]["draft"]["external_execution_allowed"] is False

Agent/module completion percentage after this file:
    25.0%

Next file to generate:
    agents/super_agents/finance_agent/budget_tracker.py

Completion tracking:
    Agent/Module: Finance Agent
    File Completed: transaction_preparer.py
    Completion: 25.0%
    Completed Files: ['finance_agent.py', 'invoice_manager.py', 'transaction_preparer.py']
    Remaining Files: ['budget_tracker.py', 'payment_guard.py', 'finance_reports.py', 'receipt_reader.py', 'tax_helper.py', 'subscription_tracker.py', 'expense_categorizer.py', 'finance_memory.py', 'config.py']
    Next Recommended File: agents/super_agents/finance_agent/budget_tracker.py

FILE COMPLETE
"""