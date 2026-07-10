"""
agents/super_agents/finance_agent/invoice_manager.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Creates, tracks, updates invoices and reminders for the Finance Agent.

Architecture Compatibility:
    - BaseAgent compatible, with safe fallback if BaseAgent is not available yet.
    - Master Agent / Agent Router friendly public interfaces.
    - Agent Registry / Loader safe import behavior.
    - Security Agent approval hooks for sensitive invoice/payment/reminder actions.
    - Verification Agent payload preparation after completed actions.
    - Memory Agent payload preparation for useful invoice context.
    - Dashboard/API ready structured JSON-style results.
    - SaaS user/workspace isolation enforced on every public operation.

Important:
    This module does NOT execute real payments, send real emails/SMS, or modify external
    financial systems. It prepares safe, structured records and payloads that other
    approved agents/services may use after permission checks.
"""

from __future__ import annotations

import copy
import logging
import math
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional BaseAgent import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for early project generation
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe before the final William/Jarvis BaseAgent
        is created. The real BaseAgent can replace this automatically when present.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "finance")
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent.run() called. Real BaseAgent not installed.",
                "data": {},
                "error": "base_agent_missing",
                "metadata": {},
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("william.finance.invoice_manager")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants and enums
# ---------------------------------------------------------------------------

MONEY_QUANT = Decimal("0.01")
DEFAULT_CURRENCY = "USD"
MAX_INVOICE_ITEMS = 250
MAX_NOTES_LENGTH = 5000
MAX_TERMS_LENGTH = 5000
MAX_CLIENT_NAME_LENGTH = 160
MAX_EMAIL_LENGTH = 254
MAX_REFERENCE_LENGTH = 160
MAX_METADATA_KEYS = 100
MAX_METADATA_VALUE_LENGTH = 2000


class InvoiceStatus(str, Enum):
    """Supported invoice lifecycle statuses."""

    DRAFT = "draft"
    ISSUED = "issued"
    PARTIALLY_PAID = "partially_paid"
    PAID = "paid"
    OVERDUE = "overdue"
    VOID = "void"
    CANCELLED = "cancelled"


class ReminderStatus(str, Enum):
    """Supported reminder lifecycle statuses."""

    SCHEDULED = "scheduled"
    READY = "ready"
    SENT = "sent"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"
    FAILED = "failed"


class ReminderChannel(str, Enum):
    """Allowed reminder channels. Actual delivery is handled elsewhere."""

    EMAIL = "email"
    SMS = "sms"
    WHATSAPP = "whatsapp"
    DASHBOARD = "dashboard"
    INTERNAL_TASK = "internal_task"


class SecurityAction(str, Enum):
    """Action names used by Security Agent permission flows."""

    CREATE_INVOICE = "finance.invoice.create"
    UPDATE_INVOICE = "finance.invoice.update"
    ISSUE_INVOICE = "finance.invoice.issue"
    RECORD_PAYMENT = "finance.invoice.record_payment"
    VOID_INVOICE = "finance.invoice.void"
    CANCEL_INVOICE = "finance.invoice.cancel"
    CREATE_REMINDER = "finance.invoice.reminder.create"
    UPDATE_REMINDER = "finance.invoice.reminder.update"
    CANCEL_REMINDER = "finance.invoice.reminder.cancel"
    PREPARE_REMINDER = "finance.invoice.reminder.prepare"


SENSITIVE_ACTIONS = {
    SecurityAction.ISSUE_INVOICE.value,
    SecurityAction.RECORD_PAYMENT.value,
    SecurityAction.VOID_INVOICE.value,
    SecurityAction.CANCEL_INVOICE.value,
    SecurityAction.CREATE_REMINDER.value,
    SecurityAction.UPDATE_REMINDER.value,
    SecurityAction.CANCEL_REMINDER.value,
    SecurityAction.PREPARE_REMINDER.value,
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class InvoiceItem:
    """Single invoice line item."""

    description: str
    quantity: Decimal
    unit_price: Decimal
    tax_rate: Decimal = Decimal("0")
    discount_amount: Decimal = Decimal("0")
    item_id: str = field(default_factory=lambda: f"itm_{uuid.uuid4().hex[:16]}")
    metadata: Dict[str, Any] = field(default_factory=dict)

    def subtotal(self) -> Decimal:
        amount = self.quantity * self.unit_price
        amount = amount - self.discount_amount
        return money(max_decimal(amount, Decimal("0")))

    def tax_amount(self) -> Decimal:
        return money(self.subtotal() * self.tax_rate / Decimal("100"))

    def total(self) -> Decimal:
        return money(self.subtotal() + self.tax_amount())


@dataclass
class PaymentRecord:
    """Internal payment tracking record.

    This does not execute a payment. It only records that a payment was reported
    or confirmed by an approved payment provider/workflow.
    """

    amount: Decimal
    paid_at: datetime
    method: Optional[str] = None
    reference: Optional[str] = None
    note: Optional[str] = None
    payment_id: str = field(default_factory=lambda: f"pay_{uuid.uuid4().hex[:16]}")
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InvoiceRecord:
    """Invoice entity stored by InvoiceManager."""

    invoice_id: str
    invoice_number: str
    user_id: str
    workspace_id: str
    client_name: str
    client_email: Optional[str]
    currency: str
    issue_date: date
    due_date: date
    status: InvoiceStatus
    items: List[InvoiceItem]
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None
    client_id: Optional[str] = None
    project_id: Optional[str] = None
    deal_id: Optional[str] = None
    external_reference: Optional[str] = None
    notes: Optional[str] = None
    terms: Optional[str] = None
    payments: List[PaymentRecord] = field(default_factory=list)
    reminders: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)

    def subtotal(self) -> Decimal:
        return money(sum((item.subtotal() for item in self.items), Decimal("0")))

    def tax_total(self) -> Decimal:
        return money(sum((item.tax_amount() for item in self.items), Decimal("0")))

    def total(self) -> Decimal:
        return money(sum((item.total() for item in self.items), Decimal("0")))

    def amount_paid(self) -> Decimal:
        return money(sum((payment.amount for payment in self.payments), Decimal("0")))

    def balance_due(self) -> Decimal:
        return money(max_decimal(self.total() - self.amount_paid(), Decimal("0")))


@dataclass
class InvoiceReminder:
    """Reminder record for an invoice.

    Reminder delivery is intentionally not performed here. This manager only creates,
    updates, lists, and prepares reminder payloads for approved delivery services.
    """

    reminder_id: str
    invoice_id: str
    user_id: str
    workspace_id: str
    scheduled_for: datetime
    channel: ReminderChannel
    status: ReminderStatus
    created_at: datetime
    updated_at: datetime
    message_template: Optional[str] = None
    recipient: Optional[str] = None
    created_by: Optional[str] = None
    sent_at: Optional[datetime] = None
    last_error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""

    return datetime.now(timezone.utc)


def today_utc() -> date:
    """Return current UTC date."""

    return utc_now().date()


def parse_date(value: Union[str, date, datetime, None], field_name: str) -> date:
    """Parse a date from supported input values."""

    if value is None:
        raise ValueError(f"{field_name} is required.")
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            raise ValueError(f"{field_name} cannot be empty.")
        try:
            return datetime.fromisoformat(cleaned.replace("Z", "+00:00")).date()
        except ValueError:
            try:
                return date.fromisoformat(cleaned)
            except ValueError as exc:
                raise ValueError(f"{field_name} must be ISO date format YYYY-MM-DD.") from exc
    raise ValueError(f"{field_name} must be a date, datetime, or ISO date string.")


def parse_datetime(value: Union[str, date, datetime, None], field_name: str) -> datetime:
    """Parse a timezone-aware datetime from supported input values."""

    if value is None:
        raise ValueError(f"{field_name} is required.")
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            raise ValueError(f"{field_name} cannot be empty.")
        try:
            parsed = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise ValueError(f"{field_name} must be ISO datetime format.") from exc
    raise ValueError(f"{field_name} must be a date, datetime, or ISO datetime string.")


def to_decimal(value: Any, field_name: str, *, allow_zero: bool = True) -> Decimal:
    """Convert money/numeric values to Decimal safely."""

    if isinstance(value, Decimal):
        result = value
    elif isinstance(value, int):
        result = Decimal(value)
    elif isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{field_name} must be finite.")
        result = Decimal(str(value))
    elif isinstance(value, str):
        cleaned = value.strip().replace(",", "")
        if not cleaned:
            raise ValueError(f"{field_name} cannot be empty.")
        try:
            result = Decimal(cleaned)
        except InvalidOperation as exc:
            raise ValueError(f"{field_name} must be numeric.") from exc
    else:
        raise ValueError(f"{field_name} must be numeric.")

    if result.is_nan() or result.is_infinite():
        raise ValueError(f"{field_name} must be finite.")
    if result < 0:
        raise ValueError(f"{field_name} cannot be negative.")
    if not allow_zero and result == 0:
        raise ValueError(f"{field_name} must be greater than zero.")
    return result


def money(value: Decimal) -> Decimal:
    """Quantize Decimal to standard 2 decimal places."""

    return value.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)


def max_decimal(left: Decimal, right: Decimal) -> Decimal:
    """Return max Decimal value without float conversion."""

    return left if left >= right else right


def decimal_to_str(value: Decimal) -> str:
    """Serialize Decimal as string for JSON-style output."""

    return format(money(value), "f")


def normalize_currency(currency: Optional[str]) -> str:
    """Normalize ISO-like currency code."""

    if not currency:
        return DEFAULT_CURRENCY
    normalized = currency.strip().upper()
    if not re.fullmatch(r"[A-Z]{3}", normalized):
        raise ValueError("currency must be a 3-letter ISO-style code, e.g. USD.")
    return normalized


def clean_optional_str(value: Any, field_name: str, max_length: int) -> Optional[str]:
    """Clean and length-limit optional strings."""

    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > max_length:
        raise ValueError(f"{field_name} cannot exceed {max_length} characters.")
    return cleaned


def require_str(value: Any, field_name: str, max_length: int = 160) -> str:
    """Validate required string."""

    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} is required.")
    if len(cleaned) > max_length:
        raise ValueError(f"{field_name} cannot exceed {max_length} characters.")
    return cleaned


def validate_email(value: Optional[str], field_name: str = "email") -> Optional[str]:
    """Lightweight email validation."""

    cleaned = clean_optional_str(value, field_name, MAX_EMAIL_LENGTH)
    if cleaned is None:
        return None
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", cleaned):
        raise ValueError(f"{field_name} must be a valid email address.")
    return cleaned


def sanitize_metadata(metadata: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """Sanitize metadata to keep it JSON-friendly and bounded."""

    if metadata is None:
        return {}
    if not isinstance(metadata, Mapping):
        raise ValueError("metadata must be a mapping/dict.")
    if len(metadata) > MAX_METADATA_KEYS:
        raise ValueError(f"metadata cannot exceed {MAX_METADATA_KEYS} keys.")

    cleaned: Dict[str, Any] = {}
    for key, value in metadata.items():
        if not isinstance(key, str):
            raise ValueError("metadata keys must be strings.")
        clean_key = key.strip()
        if not clean_key:
            raise ValueError("metadata keys cannot be empty.")
        if len(clean_key) > 120:
            raise ValueError("metadata keys cannot exceed 120 characters.")

        if isinstance(value, Decimal):
            cleaned[clean_key] = decimal_to_str(value)
        elif isinstance(value, (str, int, float, bool)) or value is None:
            if isinstance(value, str) and len(value) > MAX_METADATA_VALUE_LENGTH:
                raise ValueError(
                    f"metadata value for {clean_key} cannot exceed "
                    f"{MAX_METADATA_VALUE_LENGTH} characters."
                )
            cleaned[clean_key] = value
        elif isinstance(value, (date, datetime)):
            cleaned[clean_key] = value.isoformat()
        else:
            cleaned[clean_key] = str(value)[:MAX_METADATA_VALUE_LENGTH]
    return cleaned


def serialize_item(item: InvoiceItem) -> Dict[str, Any]:
    """Serialize InvoiceItem."""

    return {
        "item_id": item.item_id,
        "description": item.description,
        "quantity": str(item.quantity),
        "unit_price": decimal_to_str(item.unit_price),
        "discount_amount": decimal_to_str(item.discount_amount),
        "tax_rate": str(item.tax_rate),
        "subtotal": decimal_to_str(item.subtotal()),
        "tax_amount": decimal_to_str(item.tax_amount()),
        "total": decimal_to_str(item.total()),
        "metadata": copy.deepcopy(item.metadata),
    }


def serialize_payment(payment: PaymentRecord) -> Dict[str, Any]:
    """Serialize PaymentRecord."""

    return {
        "payment_id": payment.payment_id,
        "amount": decimal_to_str(payment.amount),
        "paid_at": payment.paid_at.isoformat(),
        "method": payment.method,
        "reference": payment.reference,
        "note": payment.note,
        "metadata": copy.deepcopy(payment.metadata),
    }


def serialize_invoice(invoice: InvoiceRecord) -> Dict[str, Any]:
    """Serialize InvoiceRecord."""

    return {
        "invoice_id": invoice.invoice_id,
        "invoice_number": invoice.invoice_number,
        "user_id": invoice.user_id,
        "workspace_id": invoice.workspace_id,
        "client_name": invoice.client_name,
        "client_email": invoice.client_email,
        "client_id": invoice.client_id,
        "project_id": invoice.project_id,
        "deal_id": invoice.deal_id,
        "external_reference": invoice.external_reference,
        "currency": invoice.currency,
        "issue_date": invoice.issue_date.isoformat(),
        "due_date": invoice.due_date.isoformat(),
        "status": invoice.status.value,
        "items": [serialize_item(item) for item in invoice.items],
        "subtotal": decimal_to_str(invoice.subtotal()),
        "tax_total": decimal_to_str(invoice.tax_total()),
        "total": decimal_to_str(invoice.total()),
        "amount_paid": decimal_to_str(invoice.amount_paid()),
        "balance_due": decimal_to_str(invoice.balance_due()),
        "notes": invoice.notes,
        "terms": invoice.terms,
        "payments": [serialize_payment(payment) for payment in invoice.payments],
        "reminders": list(invoice.reminders),
        "created_by": invoice.created_by,
        "created_at": invoice.created_at.isoformat(),
        "updated_at": invoice.updated_at.isoformat(),
        "metadata": copy.deepcopy(invoice.metadata),
        "audit_trail": copy.deepcopy(invoice.audit_trail),
    }


def serialize_reminder(reminder: InvoiceReminder) -> Dict[str, Any]:
    """Serialize InvoiceReminder."""

    return {
        "reminder_id": reminder.reminder_id,
        "invoice_id": reminder.invoice_id,
        "user_id": reminder.user_id,
        "workspace_id": reminder.workspace_id,
        "scheduled_for": reminder.scheduled_for.isoformat(),
        "channel": reminder.channel.value,
        "status": reminder.status.value,
        "message_template": reminder.message_template,
        "recipient": reminder.recipient,
        "created_by": reminder.created_by,
        "sent_at": reminder.sent_at.isoformat() if reminder.sent_at else None,
        "last_error": reminder.last_error,
        "created_at": reminder.created_at.isoformat(),
        "updated_at": reminder.updated_at.isoformat(),
        "metadata": copy.deepcopy(reminder.metadata),
    }


# ---------------------------------------------------------------------------
# In-memory repository
# ---------------------------------------------------------------------------

class InMemoryInvoiceRepository:
    """
    Safe in-memory repository.

    This is production-test friendly and import-safe. In live deployment, this can
    be replaced by a database-backed repository with the same method names.
    All methods require user_id and workspace_id filters to prevent cross-tenant
    leakage.
    """

    def __init__(self) -> None:
        self._invoices: Dict[Tuple[str, str, str], InvoiceRecord] = {}
        self._reminders: Dict[Tuple[str, str, str], InvoiceReminder] = {}

    def save_invoice(self, invoice: InvoiceRecord) -> InvoiceRecord:
        key = (invoice.user_id, invoice.workspace_id, invoice.invoice_id)
        self._invoices[key] = copy.deepcopy(invoice)
        return copy.deepcopy(invoice)

    def get_invoice(self, user_id: str, workspace_id: str, invoice_id: str) -> Optional[InvoiceRecord]:
        invoice = self._invoices.get((user_id, workspace_id, invoice_id))
        return copy.deepcopy(invoice) if invoice else None

    def list_invoices(
        self,
        user_id: str,
        workspace_id: str,
        *,
        status: Optional[InvoiceStatus] = None,
        client_id: Optional[str] = None,
        client_email: Optional[str] = None,
        due_before: Optional[date] = None,
        due_after: Optional[date] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[InvoiceRecord]:
        invoices = [
            copy.deepcopy(invoice)
            for (uid, wid, _), invoice in self._invoices.items()
            if uid == user_id and wid == workspace_id
        ]

        if status:
            invoices = [invoice for invoice in invoices if invoice.status == status]
        if client_id:
            invoices = [invoice for invoice in invoices if invoice.client_id == client_id]
        if client_email:
            invoices = [
                invoice for invoice in invoices
                if invoice.client_email and invoice.client_email.lower() == client_email.lower()
            ]
        if due_before:
            invoices = [invoice for invoice in invoices if invoice.due_date <= due_before]
        if due_after:
            invoices = [invoice for invoice in invoices if invoice.due_date >= due_after]

        invoices.sort(key=lambda inv: (inv.due_date, inv.created_at), reverse=True)
        return invoices[offset: offset + limit]

    def save_reminder(self, reminder: InvoiceReminder) -> InvoiceReminder:
        key = (reminder.user_id, reminder.workspace_id, reminder.reminder_id)
        self._reminders[key] = copy.deepcopy(reminder)
        return copy.deepcopy(reminder)

    def get_reminder(
        self,
        user_id: str,
        workspace_id: str,
        reminder_id: str,
    ) -> Optional[InvoiceReminder]:
        reminder = self._reminders.get((user_id, workspace_id, reminder_id))
        return copy.deepcopy(reminder) if reminder else None

    def list_reminders(
        self,
        user_id: str,
        workspace_id: str,
        *,
        invoice_id: Optional[str] = None,
        status: Optional[ReminderStatus] = None,
        due_before: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[InvoiceReminder]:
        reminders = [
            copy.deepcopy(reminder)
            for (uid, wid, _), reminder in self._reminders.items()
            if uid == user_id and wid == workspace_id
        ]

        if invoice_id:
            reminders = [reminder for reminder in reminders if reminder.invoice_id == invoice_id]
        if status:
            reminders = [reminder for reminder in reminders if reminder.status == status]
        if due_before:
            reminders = [reminder for reminder in reminders if reminder.scheduled_for <= due_before]

        reminders.sort(key=lambda rem: (rem.scheduled_for, rem.created_at))
        return reminders[offset: offset + limit]


# ---------------------------------------------------------------------------
# Invoice Manager
# ---------------------------------------------------------------------------

class InvoiceManager(BaseAgent):
    """
    Finance Agent helper for invoice and reminder management.

    Public methods return structured dicts:
        {
            "success": bool,
            "message": str,
            "data": dict/list,
            "error": str|None,
            "metadata": dict
        }

    Master Agent:
        Can route finance invoice intents here, such as create_invoice,
        list_invoices, record_payment, create_reminder, and prepare_due_reminders.

    Security Agent:
        Sensitive actions are gated through _requires_security_check() and
        _request_security_approval(). This default implementation is safe and can
        be wired to the real Security Agent later.

    Verification Agent:
        Every completed state-changing action includes a verification payload.

    Memory Agent:
        Useful context is returned as memory_payload and can be stored only by the
        Memory Agent after policy/consent checks.

    Dashboard/API:
        All outputs are JSON-style and avoid raw Decimal/date objects.
    """

    agent_name = "FinanceInvoiceManager"
    agent_type = "finance"
    version = "1.0.0"

    def __init__(
        self,
        repository: Optional[InMemoryInvoiceRepository] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name=self.agent_name, agent_type=self.agent_type, **kwargs)
        self.repository = repository or InMemoryInvoiceRepository()
        self.security_approval_callback = security_approval_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.logger = logger or LOGGER

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: Mapping[str, Any]) -> Dict[str, str]:
        """
        Validate SaaS user/workspace isolation context.

        Required:
            - user_id
            - workspace_id

        Recommended:
            - actor_id
            - request_id
            - role
            - permissions
        """

        if not isinstance(context, Mapping):
            raise ValueError("context must be a mapping/dict.")

        user_id = require_str(context.get("user_id"), "context.user_id", 120)
        workspace_id = require_str(context.get("workspace_id"), "context.workspace_id", 120)
        actor_id = clean_optional_str(context.get("actor_id"), "context.actor_id", 120) or user_id
        request_id = clean_optional_str(context.get("request_id"), "context.request_id", 160) or f"req_{uuid.uuid4().hex[:16]}"
        role = clean_optional_str(context.get("role"), "context.role", 80) or "user"

        return {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "actor_id": actor_id,
            "request_id": request_id,
            "role": role,
        }

    def _requires_security_check(self, action: str, payload: Optional[Mapping[str, Any]] = None) -> bool:
        """
        Decide whether an action needs Security Agent approval.

        Sensitive financial state changes and reminder preparation require checks.
        Basic read/list operations do not.
        """

        if action in SENSITIVE_ACTIONS:
            return True

        payload = payload or {}
        amount_value = payload.get("amount") or payload.get("total")
        if amount_value is not None:
            try:
                amount = to_decimal(amount_value, "amount")
                if amount >= Decimal("10000"):
                    return True
            except Exception:
                return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: Mapping[str, Any],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent or fallback policy.

        Fallback behavior:
            - Allows actions when context has security_approved=True.
            - Allows actions when required permission appears in context.permissions.
            - Allows non-sensitive actions.
            - Blocks sensitive actions otherwise.
        """

        payload_dict = dict(payload or {})
        context_dict = dict(context)

        approval_request = {
            "action": action,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": context_dict.get("user_id"),
            "workspace_id": context_dict.get("workspace_id"),
            "actor_id": context_dict.get("actor_id"),
            "request_id": context_dict.get("request_id"),
            "payload": payload_dict,
            "created_at": utc_now().isoformat(),
        }

        if self.security_approval_callback:
            try:
                response = self.security_approval_callback(approval_request)
                if isinstance(response, Mapping):
                    return {
                        "approved": bool(response.get("approved")),
                        "reason": response.get("reason") or response.get("message"),
                        "approval_id": response.get("approval_id"),
                        "metadata": dict(response.get("metadata") or {}),
                    }
            except Exception as exc:
                self.logger.exception("Security approval callback failed.")
                return {
                    "approved": False,
                    "reason": f"Security approval callback failed: {exc}",
                    "approval_id": None,
                    "metadata": {"fallback": True},
                }

        if not self._requires_security_check(action, payload_dict):
            return {
                "approved": True,
                "reason": "Non-sensitive action.",
                "approval_id": None,
                "metadata": {"fallback": True},
            }

        if context_dict.get("security_approved") is True:
            return {
                "approved": True,
                "reason": "Context marked as security approved.",
                "approval_id": context_dict.get("security_approval_id"),
                "metadata": {"fallback": True},
            }

        permissions = context_dict.get("permissions") or []
        if isinstance(permissions, str):
            permissions = [permissions]

        if action in permissions or "finance.invoice.*" in permissions or "finance.*" in permissions:
            return {
                "approved": True,
                "reason": "Permission matched fallback security policy.",
                "approval_id": None,
                "metadata": {"fallback": True},
            }

        return {
            "approved": False,
            "reason": f"Security approval required for {action}.",
            "approval_id": None,
            "metadata": {"fallback": True},
        }

    def _prepare_verification_payload(
        self,
        action: str,
        context: Mapping[str, Any],
        entity: Optional[Mapping[str, Any]] = None,
        before: Optional[Mapping[str, Any]] = None,
        after: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare Verification Agent payload after completed action."""

        return {
            "verification_type": "finance_invoice_action",
            "agent": self.agent_name,
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "actor_id": context.get("actor_id"),
            "request_id": context.get("request_id"),
            "entity": copy.deepcopy(dict(entity or {})),
            "before": copy.deepcopy(dict(before or {})),
            "after": copy.deepcopy(dict(after or {})),
            "created_at": utc_now().isoformat(),
            "checks": [
                "tenant_context_validated",
                "structured_result_returned",
                "security_gate_evaluated",
                "no_external_payment_or_message_executed",
            ],
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: Mapping[str, Any],
        invoice: Optional[InvoiceRecord] = None,
        reminder: Optional[InvoiceReminder] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible context.

        This module only prepares memory payloads. It does not store memory directly.
        """

        payload: Dict[str, Any] = {
            "memory_type": "finance_invoice_context",
            "agent": self.agent_name,
            "action": action,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "created_at": utc_now().isoformat(),
            "importance": "normal",
            "summary": None,
            "data": {},
        }

        if invoice:
            payload["summary"] = (
                f"Invoice {invoice.invoice_number} for {invoice.client_name} "
                f"is {invoice.status.value} with balance {invoice.currency} "
                f"{decimal_to_str(invoice.balance_due())}."
            )
            payload["data"]["invoice"] = {
                "invoice_id": invoice.invoice_id,
                "invoice_number": invoice.invoice_number,
                "client_name": invoice.client_name,
                "client_email": invoice.client_email,
                "currency": invoice.currency,
                "status": invoice.status.value,
                "due_date": invoice.due_date.isoformat(),
                "total": decimal_to_str(invoice.total()),
                "balance_due": decimal_to_str(invoice.balance_due()),
            }

        if reminder:
            payload["data"]["reminder"] = {
                "reminder_id": reminder.reminder_id,
                "invoice_id": reminder.invoice_id,
                "scheduled_for": reminder.scheduled_for.isoformat(),
                "channel": reminder.channel.value,
                "status": reminder.status.value,
            }

        return payload

    def _emit_agent_event(self, event_type: str, payload: Mapping[str, Any]) -> None:
        """
        Emit internal event for dashboard, task history, or agent bus.

        Safe no-op if no callback is configured.
        """

        event = {
            "event_id": f"evt_{uuid.uuid4().hex[:16]}",
            "event_type": event_type,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "payload": copy.deepcopy(dict(payload)),
            "created_at": utc_now().isoformat(),
        }

        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception:
                self.logger.exception("Agent event callback failed.")

    def _log_audit_event(
        self,
        action: str,
        context: Mapping[str, Any],
        payload: Optional[Mapping[str, Any]] = None,
        outcome: str = "success",
    ) -> None:
        """
        Log audit event.

        Safe no-op callback behavior. This avoids hard dependency on a future
        AuditLog service while keeping the interface ready.
        """

        audit_event = {
            "audit_id": f"aud_{uuid.uuid4().hex[:16]}",
            "action": action,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "user_id": context.get("user_id"),
            "workspace_id": context.get("workspace_id"),
            "actor_id": context.get("actor_id"),
            "request_id": context.get("request_id"),
            "outcome": outcome,
            "payload": copy.deepcopy(dict(payload or {})),
            "created_at": utc_now().isoformat(),
        }

        if self.audit_callback:
            try:
                self.audit_callback(audit_event)
            except Exception:
                self.logger.exception("Audit callback failed.")
        else:
            self.logger.info("Audit event: %s", audit_event)

    def _safe_result(
        self,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard success response."""

        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": dict(metadata or {}),
        }

    def _error_result(
        self,
        message: str,
        error: Union[str, Exception],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard error response."""

        error_text = str(error)
        return {
            "success": False,
            "message": message,
            "data": {},
            "error": error_text,
            "metadata": dict(metadata or {}),
        }

    # ------------------------------------------------------------------
    # Public invoice methods
    # ------------------------------------------------------------------

    def create_invoice(
        self,
        context: Mapping[str, Any],
        *,
        client_name: str,
        items: Sequence[Mapping[str, Any]],
        client_email: Optional[str] = None,
        currency: str = DEFAULT_CURRENCY,
        issue_date: Optional[Union[str, date, datetime]] = None,
        due_date: Optional[Union[str, date, datetime]] = None,
        payment_terms_days: int = 30,
        status: Union[str, InvoiceStatus] = InvoiceStatus.DRAFT,
        invoice_number: Optional[str] = None,
        client_id: Optional[str] = None,
        project_id: Optional[str] = None,
        deal_id: Optional[str] = None,
        external_reference: Optional[str] = None,
        notes: Optional[str] = None,
        terms: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a new invoice in draft or issued status."""

        action = SecurityAction.CREATE_INVOICE.value

        try:
            validated_context = self._validate_task_context(context)
            full_context = {**dict(context), **validated_context}

            invoice_status = self._parse_invoice_status(status)
            if invoice_status not in {InvoiceStatus.DRAFT, InvoiceStatus.ISSUED}:
                raise ValueError("New invoices can only be created as draft or issued.")

            parsed_issue_date = parse_date(issue_date or today_utc(), "issue_date")
            if due_date:
                parsed_due_date = parse_date(due_date, "due_date")
            else:
                if not isinstance(payment_terms_days, int) or payment_terms_days < 0 or payment_terms_days > 3650:
                    raise ValueError("payment_terms_days must be an integer between 0 and 3650.")
                parsed_due_date = parsed_issue_date + timedelta(days=payment_terms_days)

            if parsed_due_date < parsed_issue_date:
                raise ValueError("due_date cannot be before issue_date.")

            parsed_items = self._parse_items(items)
            normalized_currency = normalize_currency(currency)
            cleaned_client_name = require_str(client_name, "client_name", MAX_CLIENT_NAME_LENGTH)
            cleaned_client_email = validate_email(client_email, "client_email")

            now = utc_now()
            invoice_id = f"inv_{uuid.uuid4().hex[:18]}"
            final_invoice_number = (
                clean_optional_str(invoice_number, "invoice_number", MAX_REFERENCE_LENGTH)
                or self._generate_invoice_number(validated_context["workspace_id"], parsed_issue_date)
            )

            invoice = InvoiceRecord(
                invoice_id=invoice_id,
                invoice_number=final_invoice_number,
                user_id=validated_context["user_id"],
                workspace_id=validated_context["workspace_id"],
                client_name=cleaned_client_name,
                client_email=cleaned_client_email,
                currency=normalized_currency,
                issue_date=parsed_issue_date,
                due_date=parsed_due_date,
                status=invoice_status,
                items=parsed_items,
                created_at=now,
                updated_at=now,
                created_by=validated_context["actor_id"],
                client_id=clean_optional_str(client_id, "client_id", MAX_REFERENCE_LENGTH),
                project_id=clean_optional_str(project_id, "project_id", MAX_REFERENCE_LENGTH),
                deal_id=clean_optional_str(deal_id, "deal_id", MAX_REFERENCE_LENGTH),
                external_reference=clean_optional_str(
                    external_reference,
                    "external_reference",
                    MAX_REFERENCE_LENGTH,
                ),
                notes=clean_optional_str(notes, "notes", MAX_NOTES_LENGTH),
                terms=clean_optional_str(terms, "terms", MAX_TERMS_LENGTH),
                metadata=sanitize_metadata(metadata),
            )

            if invoice_status == InvoiceStatus.ISSUED:
                action = SecurityAction.ISSUE_INVOICE.value

            approval = self._request_security_approval(
                action,
                full_context,
                {
                    "invoice_id": invoice.invoice_id,
                    "invoice_number": invoice.invoice_number,
                    "total": decimal_to_str(invoice.total()),
                    "currency": invoice.currency,
                    "status": invoice.status.value,
                },
            )
            if not approval.get("approved"):
                self._log_audit_event(action, validated_context, {"reason": approval.get("reason")}, "blocked")
                return self._error_result(
                    "Invoice action blocked by security policy.",
                    approval.get("reason") or "security_approval_required",
                    {"security": approval},
                )

            invoice.audit_trail.append(
                self._build_entity_audit_entry(action, validated_context, "invoice_created")
            )
            saved = self.repository.save_invoice(invoice)
            serialized = serialize_invoice(saved)

            verification_payload = self._prepare_verification_payload(
                action,
                validated_context,
                entity={"invoice_id": saved.invoice_id, "invoice_number": saved.invoice_number},
                after=serialized,
            )
            memory_payload = self._prepare_memory_payload(action, validated_context, invoice=saved)

            self._emit_agent_event(
                "finance.invoice.created",
                {
                    "context": validated_context,
                    "invoice": serialized,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
            )
            self._log_audit_event(action, validated_context, {"invoice_id": saved.invoice_id}, "success")

            return self._safe_result(
                "Invoice created successfully.",
                {
                    "invoice": serialized,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                {"security": approval},
            )

        except Exception as exc:
            self.logger.exception("Failed to create invoice.")
            return self._error_result("Failed to create invoice.", exc)

    def update_invoice(
        self,
        context: Mapping[str, Any],
        invoice_id: str,
        *,
        client_name: Optional[str] = None,
        client_email: Optional[str] = None,
        items: Optional[Sequence[Mapping[str, Any]]] = None,
        issue_date: Optional[Union[str, date, datetime]] = None,
        due_date: Optional[Union[str, date, datetime]] = None,
        status: Optional[Union[str, InvoiceStatus]] = None,
        client_id: Optional[str] = None,
        project_id: Optional[str] = None,
        deal_id: Optional[str] = None,
        external_reference: Optional[str] = None,
        notes: Optional[str] = None,
        terms: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update invoice fields while preserving tenant isolation."""

        action = SecurityAction.UPDATE_INVOICE.value

        try:
            validated_context = self._validate_task_context(context)
            full_context = {**dict(context), **validated_context}
            cleaned_invoice_id = require_str(invoice_id, "invoice_id", 120)

            invoice = self.repository.get_invoice(
                validated_context["user_id"],
                validated_context["workspace_id"],
                cleaned_invoice_id,
            )
            if not invoice:
                return self._error_result("Invoice not found.", "invoice_not_found")

            before = serialize_invoice(invoice)

            if invoice.status in {InvoiceStatus.VOID, InvoiceStatus.CANCELLED}:
                raise ValueError("Void or cancelled invoices cannot be updated.")

            if client_name is not None:
                invoice.client_name = require_str(client_name, "client_name", MAX_CLIENT_NAME_LENGTH)
            if client_email is not None:
                invoice.client_email = validate_email(client_email, "client_email")
            if items is not None:
                if invoice.payments:
                    raise ValueError("Cannot replace invoice items after payments are recorded.")
                invoice.items = self._parse_items(items)
            if issue_date is not None:
                invoice.issue_date = parse_date(issue_date, "issue_date")
            if due_date is not None:
                invoice.due_date = parse_date(due_date, "due_date")
            if invoice.due_date < invoice.issue_date:
                raise ValueError("due_date cannot be before issue_date.")

            if status is not None:
                new_status = self._parse_invoice_status(status)
                invoice.status = self._validate_status_transition(invoice.status, new_status)
                if new_status == InvoiceStatus.ISSUED:
                    action = SecurityAction.ISSUE_INVOICE.value
                elif new_status == InvoiceStatus.VOID:
                    action = SecurityAction.VOID_INVOICE.value
                elif new_status == InvoiceStatus.CANCELLED:
                    action = SecurityAction.CANCEL_INVOICE.value

            if client_id is not None:
                invoice.client_id = clean_optional_str(client_id, "client_id", MAX_REFERENCE_LENGTH)
            if project_id is not None:
                invoice.project_id = clean_optional_str(project_id, "project_id", MAX_REFERENCE_LENGTH)
            if deal_id is not None:
                invoice.deal_id = clean_optional_str(deal_id, "deal_id", MAX_REFERENCE_LENGTH)
            if external_reference is not None:
                invoice.external_reference = clean_optional_str(
                    external_reference,
                    "external_reference",
                    MAX_REFERENCE_LENGTH,
                )
            if notes is not None:
                invoice.notes = clean_optional_str(notes, "notes", MAX_NOTES_LENGTH)
            if terms is not None:
                invoice.terms = clean_optional_str(terms, "terms", MAX_TERMS_LENGTH)
            if metadata is not None:
                invoice.metadata.update(sanitize_metadata(metadata))

            self._refresh_invoice_status(invoice)
            invoice.updated_at = utc_now()

            approval = self._request_security_approval(
                action,
                full_context,
                {
                    "invoice_id": invoice.invoice_id,
                    "invoice_number": invoice.invoice_number,
                    "total": decimal_to_str(invoice.total()),
                    "balance_due": decimal_to_str(invoice.balance_due()),
                    "status": invoice.status.value,
                },
            )
            if not approval.get("approved"):
                self._log_audit_event(action, validated_context, {"reason": approval.get("reason")}, "blocked")
                return self._error_result(
                    "Invoice update blocked by security policy.",
                    approval.get("reason") or "security_approval_required",
                    {"security": approval},
                )

            invoice.audit_trail.append(
                self._build_entity_audit_entry(action, validated_context, "invoice_updated")
            )
            saved = self.repository.save_invoice(invoice)
            after = serialize_invoice(saved)

            verification_payload = self._prepare_verification_payload(
                action,
                validated_context,
                entity={"invoice_id": saved.invoice_id, "invoice_number": saved.invoice_number},
                before=before,
                after=after,
            )
            memory_payload = self._prepare_memory_payload(action, validated_context, invoice=saved)

            self._emit_agent_event(
                "finance.invoice.updated",
                {
                    "context": validated_context,
                    "invoice": after,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
            )
            self._log_audit_event(action, validated_context, {"invoice_id": saved.invoice_id}, "success")

            return self._safe_result(
                "Invoice updated successfully.",
                {
                    "invoice": after,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                {"security": approval},
            )

        except Exception as exc:
            self.logger.exception("Failed to update invoice.")
            return self._error_result("Failed to update invoice.", exc)

    def get_invoice(self, context: Mapping[str, Any], invoice_id: str) -> Dict[str, Any]:
        """Get one invoice by ID with strict user/workspace scoping."""

        try:
            validated_context = self._validate_task_context(context)
            cleaned_invoice_id = require_str(invoice_id, "invoice_id", 120)
            invoice = self.repository.get_invoice(
                validated_context["user_id"],
                validated_context["workspace_id"],
                cleaned_invoice_id,
            )

            if not invoice:
                return self._error_result("Invoice not found.", "invoice_not_found")

            self._refresh_invoice_status(invoice)
            saved = self.repository.save_invoice(invoice)

            return self._safe_result(
                "Invoice retrieved successfully.",
                {"invoice": serialize_invoice(saved)},
                {"request_id": validated_context["request_id"]},
            )

        except Exception as exc:
            self.logger.exception("Failed to retrieve invoice.")
            return self._error_result("Failed to retrieve invoice.", exc)

    def list_invoices(
        self,
        context: Mapping[str, Any],
        *,
        status: Optional[Union[str, InvoiceStatus]] = None,
        client_id: Optional[str] = None,
        client_email: Optional[str] = None,
        due_before: Optional[Union[str, date, datetime]] = None,
        due_after: Optional[Union[str, date, datetime]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List invoices for the current user/workspace only."""

        try:
            validated_context = self._validate_task_context(context)
            parsed_status = self._parse_invoice_status(status) if status else None
            parsed_due_before = parse_date(due_before, "due_before") if due_before else None
            parsed_due_after = parse_date(due_after, "due_after") if due_after else None
            cleaned_client_email = validate_email(client_email, "client_email") if client_email else None

            safe_limit, safe_offset = self._safe_pagination(limit, offset)

            invoices = self.repository.list_invoices(
                validated_context["user_id"],
                validated_context["workspace_id"],
                status=parsed_status,
                client_id=clean_optional_str(client_id, "client_id", MAX_REFERENCE_LENGTH),
                client_email=cleaned_client_email,
                due_before=parsed_due_before,
                due_after=parsed_due_after,
                limit=safe_limit,
                offset=safe_offset,
            )

            refreshed: List[InvoiceRecord] = []
            for invoice in invoices:
                self._refresh_invoice_status(invoice)
                refreshed.append(self.repository.save_invoice(invoice))

            serialized = [serialize_invoice(invoice) for invoice in refreshed]

            return self._safe_result(
                "Invoices listed successfully.",
                {
                    "invoices": serialized,
                    "count": len(serialized),
                    "limit": safe_limit,
                    "offset": safe_offset,
                },
                {"request_id": validated_context["request_id"]},
            )

        except Exception as exc:
            self.logger.exception("Failed to list invoices.")
            return self._error_result("Failed to list invoices.", exc)

    def record_payment(
        self,
        context: Mapping[str, Any],
        invoice_id: str,
        *,
        amount: Any,
        paid_at: Optional[Union[str, date, datetime]] = None,
        method: Optional[str] = None,
        reference: Optional[str] = None,
        note: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record a payment against an invoice.

        This does not charge a card, transfer funds, or call a payment processor.
        It only records a payment after Security Agent approval.
        """

        action = SecurityAction.RECORD_PAYMENT.value

        try:
            validated_context = self._validate_task_context(context)
            full_context = {**dict(context), **validated_context}
            cleaned_invoice_id = require_str(invoice_id, "invoice_id", 120)

            invoice = self.repository.get_invoice(
                validated_context["user_id"],
                validated_context["workspace_id"],
                cleaned_invoice_id,
            )
            if not invoice:
                return self._error_result("Invoice not found.", "invoice_not_found")

            if invoice.status in {InvoiceStatus.VOID, InvoiceStatus.CANCELLED}:
                raise ValueError("Cannot record payment on void or cancelled invoice.")

            before = serialize_invoice(invoice)
            payment_amount = money(to_decimal(amount, "amount", allow_zero=False))
            if payment_amount > invoice.balance_due():
                raise ValueError("Payment amount cannot exceed invoice balance due.")

            payment = PaymentRecord(
                amount=payment_amount,
                paid_at=parse_datetime(paid_at or utc_now(), "paid_at"),
                method=clean_optional_str(method, "method", 80),
                reference=clean_optional_str(reference, "reference", MAX_REFERENCE_LENGTH),
                note=clean_optional_str(note, "note", 1000),
                metadata=sanitize_metadata(metadata),
            )

            approval = self._request_security_approval(
                action,
                full_context,
                {
                    "invoice_id": invoice.invoice_id,
                    "invoice_number": invoice.invoice_number,
                    "payment_amount": decimal_to_str(payment_amount),
                    "currency": invoice.currency,
                    "balance_before": decimal_to_str(invoice.balance_due()),
                },
            )
            if not approval.get("approved"):
                self._log_audit_event(action, validated_context, {"reason": approval.get("reason")}, "blocked")
                return self._error_result(
                    "Payment recording blocked by security policy.",
                    approval.get("reason") or "security_approval_required",
                    {"security": approval},
                )

            invoice.payments.append(payment)
            self._refresh_invoice_status(invoice)
            invoice.updated_at = utc_now()
            invoice.audit_trail.append(
                self._build_entity_audit_entry(action, validated_context, "payment_recorded")
            )

            saved = self.repository.save_invoice(invoice)
            after = serialize_invoice(saved)

            verification_payload = self._prepare_verification_payload(
                action,
                validated_context,
                entity={
                    "invoice_id": saved.invoice_id,
                    "invoice_number": saved.invoice_number,
                    "payment_id": payment.payment_id,
                },
                before=before,
                after=after,
            )
            memory_payload = self._prepare_memory_payload(action, validated_context, invoice=saved)

            self._emit_agent_event(
                "finance.invoice.payment_recorded",
                {
                    "context": validated_context,
                    "invoice": after,
                    "payment": serialize_payment(payment),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
            )
            self._log_audit_event(
                action,
                validated_context,
                {
                    "invoice_id": saved.invoice_id,
                    "payment_id": payment.payment_id,
                    "amount": decimal_to_str(payment_amount),
                },
                "success",
            )

            return self._safe_result(
                "Payment recorded successfully.",
                {
                    "invoice": after,
                    "payment": serialize_payment(payment),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                {"security": approval},
            )

        except Exception as exc:
            self.logger.exception("Failed to record payment.")
            return self._error_result("Failed to record payment.", exc)

    def mark_invoice_void(
        self,
        context: Mapping[str, Any],
        invoice_id: str,
        *,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Mark invoice as void with Security Agent approval."""

        return self.update_invoice(
            context,
            invoice_id,
            status=InvoiceStatus.VOID,
            metadata={"void_reason": reason or "No reason provided.", "voided_at": utc_now().isoformat()},
        )

    def mark_invoice_cancelled(
        self,
        context: Mapping[str, Any],
        invoice_id: str,
        *,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Mark invoice as cancelled with Security Agent approval."""

        return self.update_invoice(
            context,
            invoice_id,
            status=InvoiceStatus.CANCELLED,
            metadata={
                "cancel_reason": reason or "No reason provided.",
                "cancelled_at": utc_now().isoformat(),
            },
        )

    def get_invoice_summary(self, context: Mapping[str, Any]) -> Dict[str, Any]:
        """Return invoice KPI summary for current user/workspace."""

        try:
            validated_context = self._validate_task_context(context)

            invoices = self.repository.list_invoices(
                validated_context["user_id"],
                validated_context["workspace_id"],
                limit=10000,
                offset=0,
            )

            totals_by_status: Dict[str, Dict[str, str]] = {}
            count_by_status: Dict[str, int] = {}
            total_outstanding = Decimal("0")
            total_paid = Decimal("0")
            total_invoiced = Decimal("0")
            overdue_count = 0

            for invoice in invoices:
                self._refresh_invoice_status(invoice)
                saved = self.repository.save_invoice(invoice)
                status_value = saved.status.value

                count_by_status[status_value] = count_by_status.get(status_value, 0) + 1
                if status_value not in totals_by_status:
                    totals_by_status[status_value] = {
                        "total": decimal_to_str(Decimal("0")),
                        "balance_due": decimal_to_str(Decimal("0")),
                        "paid": decimal_to_str(Decimal("0")),
                    }

                current_total = Decimal(totals_by_status[status_value]["total"])
                current_balance = Decimal(totals_by_status[status_value]["balance_due"])
                current_paid = Decimal(totals_by_status[status_value]["paid"])

                totals_by_status[status_value] = {
                    "total": decimal_to_str(current_total + saved.total()),
                    "balance_due": decimal_to_str(current_balance + saved.balance_due()),
                    "paid": decimal_to_str(current_paid + saved.amount_paid()),
                }

                total_invoiced += saved.total()
                total_outstanding += saved.balance_due()
                total_paid += saved.amount_paid()
                if saved.status == InvoiceStatus.OVERDUE:
                    overdue_count += 1

            return self._safe_result(
                "Invoice summary generated successfully.",
                {
                    "total_invoices": len(invoices),
                    "count_by_status": count_by_status,
                    "totals_by_status": totals_by_status,
                    "total_invoiced": decimal_to_str(total_invoiced),
                    "total_paid": decimal_to_str(total_paid),
                    "total_outstanding": decimal_to_str(total_outstanding),
                    "overdue_count": overdue_count,
                    "currency_note": "Totals are aggregated numerically. Use one currency per workspace or group by currency in reports.",
                },
                {"request_id": validated_context["request_id"]},
            )

        except Exception as exc:
            self.logger.exception("Failed to generate invoice summary.")
            return self._error_result("Failed to generate invoice summary.", exc)

    # ------------------------------------------------------------------
    # Public reminder methods
    # ------------------------------------------------------------------

    def create_reminder(
        self,
        context: Mapping[str, Any],
        invoice_id: str,
        *,
        scheduled_for: Union[str, date, datetime],
        channel: Union[str, ReminderChannel] = ReminderChannel.EMAIL,
        message_template: Optional[str] = None,
        recipient: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create invoice reminder.

        This schedules/records a reminder but does not send it.
        """

        action = SecurityAction.CREATE_REMINDER.value

        try:
            validated_context = self._validate_task_context(context)
            full_context = {**dict(context), **validated_context}
            cleaned_invoice_id = require_str(invoice_id, "invoice_id", 120)

            invoice = self.repository.get_invoice(
                validated_context["user_id"],
                validated_context["workspace_id"],
                cleaned_invoice_id,
            )
            if not invoice:
                return self._error_result("Invoice not found.", "invoice_not_found")
            if invoice.status in {InvoiceStatus.PAID, InvoiceStatus.VOID, InvoiceStatus.CANCELLED}:
                raise ValueError("Cannot create reminders for paid, void, or cancelled invoices.")

            reminder_channel = self._parse_reminder_channel(channel)
            scheduled_dt = parse_datetime(scheduled_for, "scheduled_for")
            cleaned_recipient = (
                validate_email(recipient, "recipient")
                if reminder_channel == ReminderChannel.EMAIL and recipient
                else clean_optional_str(recipient, "recipient", 160)
            )

            if not cleaned_recipient and reminder_channel == ReminderChannel.EMAIL:
                cleaned_recipient = invoice.client_email

            reminder = InvoiceReminder(
                reminder_id=f"rem_{uuid.uuid4().hex[:18]}",
                invoice_id=invoice.invoice_id,
                user_id=validated_context["user_id"],
                workspace_id=validated_context["workspace_id"],
                scheduled_for=scheduled_dt,
                channel=reminder_channel,
                status=ReminderStatus.SCHEDULED,
                created_at=utc_now(),
                updated_at=utc_now(),
                message_template=clean_optional_str(message_template, "message_template", 3000),
                recipient=cleaned_recipient,
                created_by=validated_context["actor_id"],
                metadata=sanitize_metadata(metadata),
            )

            approval = self._request_security_approval(
                action,
                full_context,
                {
                    "invoice_id": invoice.invoice_id,
                    "invoice_number": invoice.invoice_number,
                    "reminder_channel": reminder.channel.value,
                    "scheduled_for": reminder.scheduled_for.isoformat(),
                    "recipient": reminder.recipient,
                },
            )
            if not approval.get("approved"):
                self._log_audit_event(action, validated_context, {"reason": approval.get("reason")}, "blocked")
                return self._error_result(
                    "Reminder creation blocked by security policy.",
                    approval.get("reason") or "security_approval_required",
                    {"security": approval},
                )

            saved_reminder = self.repository.save_reminder(reminder)

            invoice.reminders.append(saved_reminder.reminder_id)
            invoice.updated_at = utc_now()
            invoice.audit_trail.append(
                self._build_entity_audit_entry(action, validated_context, "reminder_created")
            )
            saved_invoice = self.repository.save_invoice(invoice)

            reminder_data = serialize_reminder(saved_reminder)
            invoice_data = serialize_invoice(saved_invoice)

            verification_payload = self._prepare_verification_payload(
                action,
                validated_context,
                entity={
                    "invoice_id": invoice.invoice_id,
                    "invoice_number": invoice.invoice_number,
                    "reminder_id": reminder.reminder_id,
                },
                after={"invoice": invoice_data, "reminder": reminder_data},
            )
            memory_payload = self._prepare_memory_payload(
                action,
                validated_context,
                invoice=saved_invoice,
                reminder=saved_reminder,
            )

            self._emit_agent_event(
                "finance.invoice.reminder_created",
                {
                    "context": validated_context,
                    "invoice": invoice_data,
                    "reminder": reminder_data,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
            )
            self._log_audit_event(
                action,
                validated_context,
                {
                    "invoice_id": invoice.invoice_id,
                    "reminder_id": reminder.reminder_id,
                },
                "success",
            )

            return self._safe_result(
                "Invoice reminder created successfully.",
                {
                    "invoice": invoice_data,
                    "reminder": reminder_data,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                {"security": approval},
            )

        except Exception as exc:
            self.logger.exception("Failed to create invoice reminder.")
            return self._error_result("Failed to create invoice reminder.", exc)

    def update_reminder(
        self,
        context: Mapping[str, Any],
        reminder_id: str,
        *,
        scheduled_for: Optional[Union[str, date, datetime]] = None,
        channel: Optional[Union[str, ReminderChannel]] = None,
        status: Optional[Union[str, ReminderStatus]] = None,
        message_template: Optional[str] = None,
        recipient: Optional[str] = None,
        last_error: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update an invoice reminder safely."""

        action = SecurityAction.UPDATE_REMINDER.value

        try:
            validated_context = self._validate_task_context(context)
            full_context = {**dict(context), **validated_context}
            cleaned_reminder_id = require_str(reminder_id, "reminder_id", 120)

            reminder = self.repository.get_reminder(
                validated_context["user_id"],
                validated_context["workspace_id"],
                cleaned_reminder_id,
            )
            if not reminder:
                return self._error_result("Reminder not found.", "reminder_not_found")

            before = serialize_reminder(reminder)

            if reminder.status == ReminderStatus.SENT:
                raise ValueError("Sent reminders cannot be edited.")

            if scheduled_for is not None:
                reminder.scheduled_for = parse_datetime(scheduled_for, "scheduled_for")
            if channel is not None:
                reminder.channel = self._parse_reminder_channel(channel)
            if status is not None:
                reminder.status = self._parse_reminder_status(status)
                if reminder.status == ReminderStatus.CANCELLED:
                    action = SecurityAction.CANCEL_REMINDER.value
            if message_template is not None:
                reminder.message_template = clean_optional_str(
                    message_template,
                    "message_template",
                    3000,
                )
            if recipient is not None:
                reminder.recipient = (
                    validate_email(recipient, "recipient")
                    if reminder.channel == ReminderChannel.EMAIL
                    else clean_optional_str(recipient, "recipient", 160)
                )
            if last_error is not None:
                reminder.last_error = clean_optional_str(last_error, "last_error", 1000)
            if metadata is not None:
                reminder.metadata.update(sanitize_metadata(metadata))

            reminder.updated_at = utc_now()

            approval = self._request_security_approval(
                action,
                full_context,
                {
                    "reminder_id": reminder.reminder_id,
                    "invoice_id": reminder.invoice_id,
                    "status": reminder.status.value,
                    "channel": reminder.channel.value,
                    "scheduled_for": reminder.scheduled_for.isoformat(),
                },
            )
            if not approval.get("approved"):
                self._log_audit_event(action, validated_context, {"reason": approval.get("reason")}, "blocked")
                return self._error_result(
                    "Reminder update blocked by security policy.",
                    approval.get("reason") or "security_approval_required",
                    {"security": approval},
                )

            saved = self.repository.save_reminder(reminder)
            after = serialize_reminder(saved)

            invoice = self.repository.get_invoice(
                validated_context["user_id"],
                validated_context["workspace_id"],
                saved.invoice_id,
            )
            if invoice:
                invoice.updated_at = utc_now()
                invoice.audit_trail.append(
                    self._build_entity_audit_entry(action, validated_context, "reminder_updated")
                )
                self.repository.save_invoice(invoice)

            verification_payload = self._prepare_verification_payload(
                action,
                validated_context,
                entity={"reminder_id": saved.reminder_id, "invoice_id": saved.invoice_id},
                before=before,
                after=after,
            )
            memory_payload = self._prepare_memory_payload(
                action,
                validated_context,
                invoice=invoice,
                reminder=saved,
            )

            self._emit_agent_event(
                "finance.invoice.reminder_updated",
                {
                    "context": validated_context,
                    "reminder": after,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
            )
            self._log_audit_event(
                action,
                validated_context,
                {"reminder_id": saved.reminder_id, "invoice_id": saved.invoice_id},
                "success",
            )

            return self._safe_result(
                "Invoice reminder updated successfully.",
                {
                    "reminder": after,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                {"security": approval},
            )

        except Exception as exc:
            self.logger.exception("Failed to update invoice reminder.")
            return self._error_result("Failed to update invoice reminder.", exc)

    def list_reminders(
        self,
        context: Mapping[str, Any],
        *,
        invoice_id: Optional[str] = None,
        status: Optional[Union[str, ReminderStatus]] = None,
        due_before: Optional[Union[str, date, datetime]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List reminders in current user/workspace only."""

        try:
            validated_context = self._validate_task_context(context)
            parsed_status = self._parse_reminder_status(status) if status else None
            parsed_due_before = parse_datetime(due_before, "due_before") if due_before else None
            safe_limit, safe_offset = self._safe_pagination(limit, offset)

            reminders = self.repository.list_reminders(
                validated_context["user_id"],
                validated_context["workspace_id"],
                invoice_id=clean_optional_str(invoice_id, "invoice_id", 120),
                status=parsed_status,
                due_before=parsed_due_before,
                limit=safe_limit,
                offset=safe_offset,
            )

            serialized = [serialize_reminder(reminder) for reminder in reminders]

            return self._safe_result(
                "Invoice reminders listed successfully.",
                {
                    "reminders": serialized,
                    "count": len(serialized),
                    "limit": safe_limit,
                    "offset": safe_offset,
                },
                {"request_id": validated_context["request_id"]},
            )

        except Exception as exc:
            self.logger.exception("Failed to list reminders.")
            return self._error_result("Failed to list reminders.", exc)

    def prepare_due_reminders(
        self,
        context: Mapping[str, Any],
        *,
        due_before: Optional[Union[str, date, datetime]] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """
        Prepare due reminder payloads for another approved delivery workflow.

        No message is sent here. This returns safe payloads that Security Agent,
        Workflow Agent, or Call/Voice/Mail integrations may use later.
        """

        action = SecurityAction.PREPARE_REMINDER.value

        try:
            validated_context = self._validate_task_context(context)
            full_context = {**dict(context), **validated_context}
            cutoff = parse_datetime(due_before or utc_now(), "due_before")
            safe_limit, _ = self._safe_pagination(limit, 0)

            approval = self._request_security_approval(
                action,
                full_context,
                {"due_before": cutoff.isoformat(), "limit": safe_limit},
            )
            if not approval.get("approved"):
                self._log_audit_event(action, validated_context, {"reason": approval.get("reason")}, "blocked")
                return self._error_result(
                    "Reminder preparation blocked by security policy.",
                    approval.get("reason") or "security_approval_required",
                    {"security": approval},
                )

            reminders = self.repository.list_reminders(
                validated_context["user_id"],
                validated_context["workspace_id"],
                status=ReminderStatus.SCHEDULED,
                due_before=cutoff,
                limit=safe_limit,
                offset=0,
            )

            prepared: List[Dict[str, Any]] = []
            for reminder in reminders:
                invoice = self.repository.get_invoice(
                    validated_context["user_id"],
                    validated_context["workspace_id"],
                    reminder.invoice_id,
                )
                if not invoice:
                    reminder.status = ReminderStatus.SKIPPED
                    reminder.last_error = "Invoice no longer exists."
                    reminder.updated_at = utc_now()
                    self.repository.save_reminder(reminder)
                    continue

                self._refresh_invoice_status(invoice)
                self.repository.save_invoice(invoice)

                if invoice.status in {InvoiceStatus.PAID, InvoiceStatus.VOID, InvoiceStatus.CANCELLED}:
                    reminder.status = ReminderStatus.SKIPPED
                    reminder.last_error = f"Invoice status is {invoice.status.value}."
                    reminder.updated_at = utc_now()
                    self.repository.save_reminder(reminder)
                    continue

                reminder.status = ReminderStatus.READY
                reminder.updated_at = utc_now()
                saved_reminder = self.repository.save_reminder(reminder)

                prepared.append(
                    {
                        "reminder": serialize_reminder(saved_reminder),
                        "invoice": serialize_invoice(invoice),
                        "delivery_payload": self._build_delivery_payload(invoice, saved_reminder),
                    }
                )

            verification_payload = self._prepare_verification_payload(
                action,
                validated_context,
                entity={"prepared_count": len(prepared)},
                after={"prepared_reminders": prepared},
            )

            self._emit_agent_event(
                "finance.invoice.reminders_prepared",
                {
                    "context": validated_context,
                    "prepared_count": len(prepared),
                    "verification_payload": verification_payload,
                },
            )
            self._log_audit_event(
                action,
                validated_context,
                {"prepared_count": len(prepared), "due_before": cutoff.isoformat()},
                "success",
            )

            return self._safe_result(
                "Due invoice reminders prepared successfully.",
                {
                    "prepared_reminders": prepared,
                    "count": len(prepared),
                    "verification_payload": verification_payload,
                },
                {"security": approval},
            )

        except Exception as exc:
            self.logger.exception("Failed to prepare due reminders.")
            return self._error_result("Failed to prepare due reminders.", exc)

    def record_reminder_sent(
        self,
        context: Mapping[str, Any],
        reminder_id: str,
        *,
        sent_at: Optional[Union[str, date, datetime]] = None,
        delivery_reference: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Mark reminder as sent after an external approved sender completes delivery.

        This method records the state only.
        """

        return self.update_reminder(
            context,
            reminder_id,
            status=ReminderStatus.SENT,
            metadata={
                "delivery_reference": delivery_reference,
                "sent_recorded_at": parse_datetime(sent_at or utc_now(), "sent_at").isoformat(),
            },
        )

    # ------------------------------------------------------------------
    # Router-compatible generic execution
    # ------------------------------------------------------------------

    async def run(self, task: Optional[Mapping[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
        """
        Generic async entry point for Master Agent / Router.

        Expected task shape:
            {
                "action": "create_invoice",
                "context": {"user_id": "...", "workspace_id": "..."},
                "payload": {...}
            }
        """

        try:
            task_dict = dict(task or {})
            action = task_dict.get("action") or kwargs.get("action")
            context = task_dict.get("context") or kwargs.get("context") or {}
            payload = task_dict.get("payload") or kwargs.get("payload") or {}

            if not action:
                return self._error_result("No action provided.", "missing_action")

            action_map = {
                "create_invoice": self.create_invoice,
                "update_invoice": self.update_invoice,
                "get_invoice": self.get_invoice,
                "list_invoices": self.list_invoices,
                "record_payment": self.record_payment,
                "mark_invoice_void": self.mark_invoice_void,
                "mark_invoice_cancelled": self.mark_invoice_cancelled,
                "get_invoice_summary": self.get_invoice_summary,
                "create_reminder": self.create_reminder,
                "update_reminder": self.update_reminder,
                "list_reminders": self.list_reminders,
                "prepare_due_reminders": self.prepare_due_reminders,
                "record_reminder_sent": self.record_reminder_sent,
            }

            handler = action_map.get(str(action))
            if not handler:
                return self._error_result(
                    "Unsupported invoice manager action.",
                    f"unsupported_action:{action}",
                    {"supported_actions": sorted(action_map.keys())},
                )

            if not isinstance(payload, Mapping):
                return self._error_result("Payload must be a mapping/dict.", "invalid_payload")

            return handler(context, **dict(payload))

        except Exception as exc:
            self.logger.exception("InvoiceManager.run failed.")
            return self._error_result("InvoiceManager run failed.", exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_items(self, items: Sequence[Mapping[str, Any]]) -> List[InvoiceItem]:
        """Validate and parse invoice line items."""

        if not isinstance(items, Sequence) or isinstance(items, (str, bytes)):
            raise ValueError("items must be a sequence/list of item objects.")
        if not items:
            raise ValueError("At least one invoice item is required.")
        if len(items) > MAX_INVOICE_ITEMS:
            raise ValueError(f"Cannot exceed {MAX_INVOICE_ITEMS} invoice items.")

        parsed: List[InvoiceItem] = []
        for index, raw_item in enumerate(items):
            if not isinstance(raw_item, Mapping):
                raise ValueError(f"items[{index}] must be a mapping/dict.")

            description = require_str(raw_item.get("description"), f"items[{index}].description", 500)
            quantity = to_decimal(raw_item.get("quantity", 1), f"items[{index}].quantity", allow_zero=False)
            unit_price = money(to_decimal(raw_item.get("unit_price"), f"items[{index}].unit_price"))
            tax_rate = to_decimal(raw_item.get("tax_rate", 0), f"items[{index}].tax_rate")
            discount_amount = money(
                to_decimal(raw_item.get("discount_amount", 0), f"items[{index}].discount_amount")
            )

            if tax_rate > Decimal("100"):
                raise ValueError(f"items[{index}].tax_rate cannot exceed 100.")
            if discount_amount > quantity * unit_price:
                raise ValueError(f"items[{index}].discount_amount cannot exceed item subtotal.")

            item_id = clean_optional_str(raw_item.get("item_id"), f"items[{index}].item_id", 120)
            parsed.append(
                InvoiceItem(
                    description=description,
                    quantity=quantity,
                    unit_price=unit_price,
                    tax_rate=tax_rate,
                    discount_amount=discount_amount,
                    item_id=item_id or f"itm_{uuid.uuid4().hex[:16]}",
                    metadata=sanitize_metadata(raw_item.get("metadata")),
                )
            )

        return parsed

    def _parse_invoice_status(self, status: Union[str, InvoiceStatus]) -> InvoiceStatus:
        """Parse invoice status enum."""

        if isinstance(status, InvoiceStatus):
            return status
        if isinstance(status, str):
            cleaned = status.strip().lower()
            try:
                return InvoiceStatus(cleaned)
            except ValueError as exc:
                raise ValueError(f"Unsupported invoice status: {status}") from exc
        raise ValueError("status must be a string or InvoiceStatus.")

    def _parse_reminder_status(self, status: Union[str, ReminderStatus]) -> ReminderStatus:
        """Parse reminder status enum."""

        if isinstance(status, ReminderStatus):
            return status
        if isinstance(status, str):
            cleaned = status.strip().lower()
            try:
                return ReminderStatus(cleaned)
            except ValueError as exc:
                raise ValueError(f"Unsupported reminder status: {status}") from exc
        raise ValueError("status must be a string or ReminderStatus.")

    def _parse_reminder_channel(self, channel: Union[str, ReminderChannel]) -> ReminderChannel:
        """Parse reminder channel enum."""

        if isinstance(channel, ReminderChannel):
            return channel
        if isinstance(channel, str):
            cleaned = channel.strip().lower()
            try:
                return ReminderChannel(cleaned)
            except ValueError as exc:
                raise ValueError(f"Unsupported reminder channel: {channel}") from exc
        raise ValueError("channel must be a string or ReminderChannel.")

    def _validate_status_transition(
        self,
        current: InvoiceStatus,
        new_status: InvoiceStatus,
    ) -> InvoiceStatus:
        """Validate invoice status transition."""

        if current == new_status:
            return new_status

        terminal = {InvoiceStatus.VOID, InvoiceStatus.CANCELLED}
        if current in terminal:
            raise ValueError(f"Cannot transition invoice from terminal status {current.value}.")

        allowed: Dict[InvoiceStatus, set[InvoiceStatus]] = {
            InvoiceStatus.DRAFT: {
                InvoiceStatus.ISSUED,
                InvoiceStatus.CANCELLED,
                InvoiceStatus.VOID,
            },
            InvoiceStatus.ISSUED: {
                InvoiceStatus.PARTIALLY_PAID,
                InvoiceStatus.PAID,
                InvoiceStatus.OVERDUE,
                InvoiceStatus.CANCELLED,
                InvoiceStatus.VOID,
            },
            InvoiceStatus.PARTIALLY_PAID: {
                InvoiceStatus.PAID,
                InvoiceStatus.OVERDUE,
                InvoiceStatus.VOID,
            },
            InvoiceStatus.OVERDUE: {
                InvoiceStatus.PARTIALLY_PAID,
                InvoiceStatus.PAID,
                InvoiceStatus.VOID,
                InvoiceStatus.CANCELLED,
            },
            InvoiceStatus.PAID: {
                InvoiceStatus.VOID,
            },
            InvoiceStatus.VOID: set(),
            InvoiceStatus.CANCELLED: set(),
        }

        if new_status not in allowed.get(current, set()):
            raise ValueError(f"Invalid invoice status transition from {current.value} to {new_status.value}.")

        return new_status

    def _refresh_invoice_status(self, invoice: InvoiceRecord) -> None:
        """Refresh invoice status based on payments and due date."""

        if invoice.status in {InvoiceStatus.DRAFT, InvoiceStatus.VOID, InvoiceStatus.CANCELLED}:
            return

        balance = invoice.balance_due()
        paid = invoice.amount_paid()

        if balance <= Decimal("0") and paid > Decimal("0"):
            invoice.status = InvoiceStatus.PAID
        elif paid > Decimal("0"):
            if invoice.due_date < today_utc():
                invoice.status = InvoiceStatus.OVERDUE
            else:
                invoice.status = InvoiceStatus.PARTIALLY_PAID
        elif invoice.due_date < today_utc() and invoice.status == InvoiceStatus.ISSUED:
            invoice.status = InvoiceStatus.OVERDUE

    def _generate_invoice_number(self, workspace_id: str, issue_date: date) -> str:
        """Generate readable invoice number without database dependency."""

        workspace_slug = re.sub(r"[^A-Za-z0-9]", "", workspace_id.upper())[:6] or "WS"
        stamp = issue_date.strftime("%Y%m%d")
        suffix = uuid.uuid4().hex[:6].upper()
        return f"INV-{workspace_slug}-{stamp}-{suffix}"

    def _safe_pagination(self, limit: int, offset: int) -> Tuple[int, int]:
        """Normalize pagination."""

        if not isinstance(limit, int):
            raise ValueError("limit must be an integer.")
        if not isinstance(offset, int):
            raise ValueError("offset must be an integer.")
        safe_limit = min(max(limit, 1), 500)
        safe_offset = max(offset, 0)
        return safe_limit, safe_offset

    def _build_entity_audit_entry(
        self,
        action: str,
        context: Mapping[str, Any],
        message: str,
    ) -> Dict[str, Any]:
        """Build audit entry stored inside invoice record."""

        return {
            "action": action,
            "message": message,
            "actor_id": context.get("actor_id"),
            "request_id": context.get("request_id"),
            "created_at": utc_now().isoformat(),
        }

    def _build_delivery_payload(
        self,
        invoice: InvoiceRecord,
        reminder: InvoiceReminder,
    ) -> Dict[str, Any]:
        """
        Build safe delivery payload for another approved sender.

        No delivery is performed here.
        """

        default_message = (
            f"Reminder: Invoice {invoice.invoice_number} for {invoice.currency} "
            f"{decimal_to_str(invoice.balance_due())} is due on {invoice.due_date.isoformat()}."
        )

        return {
            "delivery_type": "invoice_reminder",
            "channel": reminder.channel.value,
            "recipient": reminder.recipient or invoice.client_email,
            "subject": f"Invoice reminder: {invoice.invoice_number}",
            "message": reminder.message_template or default_message,
            "invoice_id": invoice.invoice_id,
            "invoice_number": invoice.invoice_number,
            "client_name": invoice.client_name,
            "client_email": invoice.client_email,
            "currency": invoice.currency,
            "total": decimal_to_str(invoice.total()),
            "balance_due": decimal_to_str(invoice.balance_due()),
            "due_date": invoice.due_date.isoformat(),
            "metadata": {
                "user_id": invoice.user_id,
                "workspace_id": invoice.workspace_id,
                "reminder_id": reminder.reminder_id,
                "prepared_at": utc_now().isoformat(),
                "requires_sender_approval": True,
            },
        }


__all__ = [
    "InvoiceManager",
    "InvoiceItem",
    "InvoiceRecord",
    "InvoiceReminder",
    "PaymentRecord",
    "InvoiceStatus",
    "ReminderStatus",
    "ReminderChannel",
    "SecurityAction",
    "InMemoryInvoiceRepository",
]


"""
Where to place it:
    agents/super_agents/finance_agent/invoice_manager.py

Required dependencies:
    Python standard library only.

How to test it:
    1. Save this file at agents/super_agents/finance_agent/invoice_manager.py
    2. Run:
        python -m py_compile agents/super_agents/finance_agent/invoice_manager.py
    3. Minimal manual test:
        from agents.super_agents.finance_agent.invoice_manager import InvoiceManager

        manager = InvoiceManager()
        context = {
            "user_id": "user_1",
            "workspace_id": "workspace_1",
            "actor_id": "user_1",
            "permissions": ["finance.*"]
        }

        result = manager.create_invoice(
            context,
            client_name="Acme Inc",
            client_email="billing@acme.com",
            items=[
                {
                    "description": "Website development",
                    "quantity": 1,
                    "unit_price": "1500.00",
                    "tax_rate": "0"
                }
            ],
            status="issued"
        )
        print(result)

Agent/module completion percentage after this file:
    16.7%

Next file to generate:
    agents/super_agents/finance_agent/transaction_preparer.py

Agent/Module: Finance Agent
File Completed: invoice_manager.py
Completion: 16.7%
Completed Files: ['finance_agent.py', 'invoice_manager.py']
Remaining Files: ['transaction_preparer.py', 'budget_tracker.py', 'payment_guard.py', 'finance_reports.py', 'receipt_reader.py', 'tax_helper.py', 'subscription_tracker.py', 'expense_categorizer.py', 'finance_memory.py', 'config.py']
Next Recommended File: agents/super_agents/finance_agent/transaction_preparer.py

FILE COMPLETE
"""