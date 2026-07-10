"""
agents/super_agents/business_agent/revenue_tracker.py

William / Jarvis Multi-Agent AI SaaS System
Business Agent - Revenue Tracker

Purpose:
    Tracks revenue, invoices, paid/unpaid amounts, MRR, ARR, overdue invoices,
    pipeline value, and payment activity for SaaS users and workspaces.

Architecture Compatibility:
    - Safe to import even if future William/Jarvis modules are not created yet.
    - Compatible with BaseAgent-style execution.
    - Compatible with Agent Registry, Agent Loader, Agent Router, and Master Agent routing.
    - Enforces user_id and workspace_id isolation for every user-specific operation.
    - Sensitive actions are routed through Security Agent hooks.
    - Completed actions prepare Verification Agent payloads.
    - Useful context can be prepared for Memory Agent.
    - Dashboard/API-ready structured dict responses.

Security Notes:
    This file does not execute real payment, banking, invoice delivery, deletion,
    refund, or external financial actions. It safely tracks structured revenue data
    in an in-memory store by default. Production systems can replace the repository
    layer with a database-backed adapter while keeping the public interface stable.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Safe optional imports for William/Jarvis architecture compatibility
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe during staged development when the real
        BaseAgent has not been generated yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent does not implement run().")


try:
    from agents.super_agents.business_agent.config import BUSINESS_AGENT_CONFIG  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    BUSINESS_AGENT_CONFIG: Dict[str, Any] = {
        "agent_name": "BusinessAgent",
        "module": "business_agent",
        "default_currency": "USD",
        "audit_enabled": True,
        "memory_enabled": True,
        "verification_enabled": True,
        "security_enabled": True,
    }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants and enums
# ---------------------------------------------------------------------------

MONEY_QUANT = Decimal("0.01")


class InvoiceStatus(str, Enum):
    """Supported invoice lifecycle states."""

    DRAFT = "draft"
    SENT = "sent"
    PARTIALLY_PAID = "partially_paid"
    PAID = "paid"
    UNPAID = "unpaid"
    OVERDUE = "overdue"
    CANCELLED = "cancelled"
    VOID = "void"


class PaymentStatus(str, Enum):
    """Supported payment states."""

    RECORDED = "recorded"
    REFUNDED = "refunded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RevenueFrequency(str, Enum):
    """Frequency values used for recurring revenue calculations."""

    ONE_TIME = "one_time"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    SEMI_ANNUAL = "semi_annual"
    ANNUAL = "annual"


class PipelineStatus(str, Enum):
    """Pipeline status values for forecasted/potential revenue."""

    OPEN = "open"
    WON = "won"
    LOST = "lost"
    STALLED = "stalled"


SENSITIVE_ACTIONS = {
    "create_invoice",
    "update_invoice",
    "record_payment",
    "cancel_invoice",
    "void_invoice",
    "mark_invoice_paid",
    "delete_invoice",
    "export_revenue",
    "bulk_update",
}


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    """Return timezone-aware UTC now."""

    return datetime.now(timezone.utc)


def _iso_now() -> str:
    """Return current UTC timestamp in ISO format."""

    return _utc_now().isoformat()


def _parse_date(value: Any, field_name: str = "date") -> Optional[date]:
    """
    Parse a date-like value into a date.

    Accepts:
        - None
        - datetime.date
        - datetime.datetime
        - ISO string YYYY-MM-DD
        - ISO datetime string
    """

    if value is None:
        return None

    if isinstance(value, datetime):
        return value.date()

    if isinstance(value, date):
        return value

    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            if "T" in cleaned:
                return datetime.fromisoformat(cleaned.replace("Z", "+00:00")).date()
            return date.fromisoformat(cleaned)
        except ValueError as exc:
            raise ValueError(f"Invalid {field_name}: expected ISO date string.") from exc

    raise ValueError(f"Invalid {field_name}: unsupported date value.")


def _parse_decimal(value: Any, field_name: str = "amount") -> Decimal:
    """Parse a value into a safely rounded Decimal."""

    if value is None:
        raise ValueError(f"{field_name} is required.")

    try:
        parsed = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise ValueError(f"{field_name} must be a valid number.") from exc

    if parsed.is_nan() or parsed.is_infinite():
        raise ValueError(f"{field_name} must be a finite number.")

    return parsed.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)


def _money(value: Decimal) -> str:
    """Serialize Decimal money safely as a string."""

    return str(value.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP))


def _normalize_currency(currency: Optional[str], default_currency: str = "USD") -> str:
    """Normalize currency code."""

    raw = (currency or default_currency or "USD").strip().upper()
    if len(raw) != 3 or not raw.isalpha():
        raise ValueError("currency must be a valid 3-letter currency code.")
    return raw


def _new_id(prefix: str) -> str:
    """Generate stable prefixed IDs."""

    return f"{prefix}_{uuid.uuid4().hex}"


def _safe_text(value: Any, max_length: int = 500) -> str:
    """Return a safe bounded string."""

    if value is None:
        return ""
    text = str(value).strip()
    if len(text) > max_length:
        return text[:max_length].rstrip()
    return text


def _decimal_sum(values: Iterable[Decimal]) -> Decimal:
    """Return rounded Decimal sum."""

    total = Decimal("0.00")
    for value in values:
        total += value
    return total.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class InvoiceLineItem:
    """Line item stored inside an invoice."""

    description: str
    quantity: Decimal
    unit_price: Decimal
    tax_rate: Decimal = Decimal("0.00")
    discount_amount: Decimal = Decimal("0.00")

    @property
    def subtotal(self) -> Decimal:
        raw = self.quantity * self.unit_price
        return raw.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

    @property
    def tax_amount(self) -> Decimal:
        taxable = max(self.subtotal - self.discount_amount, Decimal("0.00"))
        raw = taxable * (self.tax_rate / Decimal("100"))
        return raw.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

    @property
    def total(self) -> Decimal:
        raw = self.subtotal - self.discount_amount + self.tax_amount
        return max(raw, Decimal("0.00")).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "description": self.description,
            "quantity": _money(self.quantity),
            "unit_price": _money(self.unit_price),
            "tax_rate": _money(self.tax_rate),
            "discount_amount": _money(self.discount_amount),
            "subtotal": _money(self.subtotal),
            "tax_amount": _money(self.tax_amount),
            "total": _money(self.total),
        }


@dataclass
class PaymentRecord:
    """Payment record linked to an invoice."""

    payment_id: str
    user_id: str
    workspace_id: str
    invoice_id: str
    amount: Decimal
    currency: str
    payment_date: date
    method: str = "manual"
    reference: str = ""
    status: PaymentStatus = PaymentStatus.RECORDED
    notes: str = ""
    created_at: str = field(default_factory=_iso_now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["amount"] = _money(self.amount)
        payload["payment_date"] = self.payment_date.isoformat()
        payload["status"] = self.status.value
        return payload


@dataclass
class InvoiceRecord:
    """Invoice model scoped to one user and one workspace."""

    invoice_id: str
    user_id: str
    workspace_id: str
    client_id: str
    client_name: str
    currency: str
    issue_date: date
    due_date: Optional[date]
    line_items: List[InvoiceLineItem]
    status: InvoiceStatus = InvoiceStatus.DRAFT
    invoice_number: str = ""
    project_id: str = ""
    deal_id: str = ""
    frequency: RevenueFrequency = RevenueFrequency.ONE_TIME
    notes: str = ""
    tags: List[str] = field(default_factory=list)
    payments: List[PaymentRecord] = field(default_factory=list)
    created_at: str = field(default_factory=_iso_now)
    updated_at: str = field(default_factory=_iso_now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def subtotal(self) -> Decimal:
        return _decimal_sum(item.subtotal for item in self.line_items)

    @property
    def tax_total(self) -> Decimal:
        return _decimal_sum(item.tax_amount for item in self.line_items)

    @property
    def discount_total(self) -> Decimal:
        return _decimal_sum(item.discount_amount for item in self.line_items)

    @property
    def total_amount(self) -> Decimal:
        return _decimal_sum(item.total for item in self.line_items)

    @property
    def paid_amount(self) -> Decimal:
        return _decimal_sum(
            payment.amount
            for payment in self.payments
            if payment.status == PaymentStatus.RECORDED
        )

    @property
    def unpaid_amount(self) -> Decimal:
        return max(self.total_amount - self.paid_amount, Decimal("0.00")).quantize(
            MONEY_QUANT,
            rounding=ROUND_HALF_UP,
        )

    @property
    def is_overdue(self) -> bool:
        if self.status in {InvoiceStatus.PAID, InvoiceStatus.CANCELLED, InvoiceStatus.VOID}:
            return False
        if self.due_date is None:
            return False
        return self.due_date < _utc_now().date() and self.unpaid_amount > Decimal("0.00")

    def refresh_status_from_payments(self) -> None:
        """Update status based on paid/unpaid amount unless invoice is terminal."""

        if self.status in {InvoiceStatus.CANCELLED, InvoiceStatus.VOID}:
            self.updated_at = _iso_now()
            return

        if self.total_amount <= Decimal("0.00"):
            self.status = InvoiceStatus.PAID
        elif self.paid_amount >= self.total_amount:
            self.status = InvoiceStatus.PAID
        elif self.paid_amount > Decimal("0.00"):
            self.status = InvoiceStatus.PARTIALLY_PAID
        elif self.is_overdue:
            self.status = InvoiceStatus.OVERDUE
        elif self.status == InvoiceStatus.DRAFT:
            self.status = InvoiceStatus.DRAFT
        else:
            self.status = InvoiceStatus.UNPAID

        self.updated_at = _iso_now()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "invoice_id": self.invoice_id,
            "invoice_number": self.invoice_number,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "client_id": self.client_id,
            "client_name": self.client_name,
            "project_id": self.project_id,
            "deal_id": self.deal_id,
            "currency": self.currency,
            "issue_date": self.issue_date.isoformat(),
            "due_date": self.due_date.isoformat() if self.due_date else None,
            "frequency": self.frequency.value,
            "status": self.status.value,
            "computed_is_overdue": self.is_overdue,
            "line_items": [item.to_dict() for item in self.line_items],
            "subtotal": _money(self.subtotal),
            "tax_total": _money(self.tax_total),
            "discount_total": _money(self.discount_total),
            "total_amount": _money(self.total_amount),
            "paid_amount": _money(self.paid_amount),
            "unpaid_amount": _money(self.unpaid_amount),
            "notes": self.notes,
            "tags": list(self.tags),
            "payments": [payment.to_dict() for payment in self.payments],
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": dict(self.metadata),
        }


@dataclass
class PipelineRevenueRecord:
    """Pipeline revenue/opportunity forecast record."""

    pipeline_id: str
    user_id: str
    workspace_id: str
    title: str
    amount: Decimal
    currency: str
    probability: Decimal
    expected_close_date: Optional[date] = None
    client_id: str = ""
    deal_id: str = ""
    source: str = ""
    status: PipelineStatus = PipelineStatus.OPEN
    notes: str = ""
    created_at: str = field(default_factory=_iso_now)
    updated_at: str = field(default_factory=_iso_now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def weighted_value(self) -> Decimal:
        raw = self.amount * (self.probability / Decimal("100"))
        return raw.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pipeline_id": self.pipeline_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "title": self.title,
            "client_id": self.client_id,
            "deal_id": self.deal_id,
            "source": self.source,
            "amount": _money(self.amount),
            "currency": self.currency,
            "probability": _money(self.probability),
            "weighted_value": _money(self.weighted_value),
            "expected_close_date": (
                self.expected_close_date.isoformat()
                if self.expected_close_date
                else None
            ),
            "status": self.status.value,
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "metadata": dict(self.metadata),
        }


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------

class InMemoryRevenueRepository:
    """
    Default in-memory repository.

    This keeps the module independently testable and import-safe. In production,
    replace this with a DB-backed repository while keeping the same method names.
    Data is stored under user_id -> workspace_id boundaries to prevent mixing
    tenant data.
    """

    def __init__(self) -> None:
        self._invoices: Dict[Tuple[str, str], Dict[str, InvoiceRecord]] = {}
        self._pipeline: Dict[Tuple[str, str], Dict[str, PipelineRevenueRecord]] = {}

    @staticmethod
    def _scope(user_id: str, workspace_id: str) -> Tuple[str, str]:
        return user_id, workspace_id

    def save_invoice(self, invoice: InvoiceRecord) -> InvoiceRecord:
        scope = self._scope(invoice.user_id, invoice.workspace_id)
        self._invoices.setdefault(scope, {})[invoice.invoice_id] = invoice
        return invoice

    def get_invoice(
        self,
        user_id: str,
        workspace_id: str,
        invoice_id: str,
    ) -> Optional[InvoiceRecord]:
        return self._invoices.get(self._scope(user_id, workspace_id), {}).get(invoice_id)

    def list_invoices(
        self,
        user_id: str,
        workspace_id: str,
    ) -> List[InvoiceRecord]:
        return list(self._invoices.get(self._scope(user_id, workspace_id), {}).values())

    def save_pipeline_record(
        self,
        record: PipelineRevenueRecord,
    ) -> PipelineRevenueRecord:
        scope = self._scope(record.user_id, record.workspace_id)
        self._pipeline.setdefault(scope, {})[record.pipeline_id] = record
        return record

    def get_pipeline_record(
        self,
        user_id: str,
        workspace_id: str,
        pipeline_id: str,
    ) -> Optional[PipelineRevenueRecord]:
        return self._pipeline.get(self._scope(user_id, workspace_id), {}).get(pipeline_id)

    def list_pipeline_records(
        self,
        user_id: str,
        workspace_id: str,
    ) -> List[PipelineRevenueRecord]:
        return list(self._pipeline.get(self._scope(user_id, workspace_id), {}).values())


# ---------------------------------------------------------------------------
# Revenue Tracker
# ---------------------------------------------------------------------------

class RevenueTracker(BaseAgent):
    """
    Revenue tracking helper/agent for the William/Jarvis Business Agent.

    Main responsibilities:
        - Create and update invoices.
        - Track paid, unpaid, partially paid, and overdue invoices.
        - Record manual payment events.
        - Calculate revenue totals, MRR, ARR, overdue amount, and unpaid amount.
        - Track pipeline value and weighted pipeline forecast.
        - Prepare Memory Agent and Verification Agent payloads.
        - Emit audit/event payloads for dashboards and agent registry integrations.

    This class is intentionally storage-adapter friendly. The default repository
    is in-memory for safe testing. Production can inject a database repository.
    """

    agent_type = "business_agent.revenue_tracker"
    public_name = "Revenue Tracker"
    version = "1.0.0"

    def __init__(
        self,
        repository: Optional[InMemoryRevenueRepository] = None,
        config: Optional[Dict[str, Any]] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(*args, agent_name=self.public_name, **kwargs)
        except TypeError:
            super().__init__(*args, **kwargs)

        self.config = dict(BUSINESS_AGENT_CONFIG)
        if config:
            self.config.update(config)

        self.repository = repository or InMemoryRevenueRepository()
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self.default_currency = _normalize_currency(
            self.config.get("default_currency", "USD")
        )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _safe_result(
        self,
        success: bool = True,
        message: str = "",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return William/Jarvis standard structured result."""

        return {
            "success": bool(success),
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": {
                "agent": self.public_name,
                "agent_type": self.agent_type,
                "version": self.version,
                "timestamp": _iso_now(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error: Optional[Any] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standardized error result."""

        error_payload: Any
        if isinstance(error, Exception):
            error_payload = {
                "type": error.__class__.__name__,
                "message": str(error),
            }
        else:
            error_payload = error

        logger.warning("%s: %s", message, error_payload)
        return self._safe_result(
            success=False,
            message=message,
            data={},
            error=error_payload,
            metadata=metadata,
        )

    def _validate_task_context(self, task: Dict[str, Any]) -> Tuple[str, str]:
        """
        Validate SaaS tenant context.

        Every user-specific revenue action must include user_id and workspace_id.
        This protects revenue, invoices, payments, pipeline, logs, and analytics
        from cross-workspace leakage.
        """

        if not isinstance(task, dict):
            raise ValueError("task must be a dictionary.")

        user_id = _safe_text(task.get("user_id"), max_length=120)
        workspace_id = _safe_text(task.get("workspace_id"), max_length=120)

        if not user_id:
            raise ValueError("user_id is required for RevenueTracker operations.")
        if not workspace_id:
            raise ValueError("workspace_id is required for RevenueTracker operations.")

        return user_id, workspace_id

    def _requires_security_check(self, action: str, task: Optional[Dict[str, Any]] = None) -> bool:
        """
        Decide whether an action requires Security Agent approval.

        Financial write actions are treated as sensitive. This method protects
        future integrations where invoice/payment actions may trigger real systems.
        """

        action_name = _safe_text(action).lower()
        if action_name in SENSITIVE_ACTIONS:
            return True

        if task and bool(task.get("force_security_check")):
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        task: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        If no Security Agent is connected, this method returns a safe local
        approval for non-destructive internal tracking only. It does not approve
        real money movement, external invoice sending, bank operations, refunds,
        or destructive deletion.
        """

        approval_payload = {
            "action": action,
            "agent": self.agent_type,
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "risk_level": "medium",
            "reason": "Revenue/invoice/payment tracking action.",
            "requested_at": _iso_now(),
            "task_summary": {
                key: task.get(key)
                for key in (
                    "invoice_id",
                    "client_id",
                    "deal_id",
                    "amount",
                    "currency",
                    "status",
                )
                if key in task
            },
        }

        if self.security_agent and hasattr(self.security_agent, "approve_action"):
            try:
                response = self.security_agent.approve_action(approval_payload)
                if isinstance(response, dict):
                    return response
            except Exception as exc:
                return {
                    "approved": False,
                    "reason": f"Security Agent error: {exc}",
                    "payload": approval_payload,
                }

        return {
            "approved": True,
            "reason": "Local safe approval for internal tracking only.",
            "payload": approval_payload,
            "external_actions_allowed": False,
        }

    def _prepare_verification_payload(
        self,
        action: str,
        task: Dict[str, Any],
        result_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        The Verification Agent can later confirm calculations, invoice status,
        totals, paid/unpaid amounts, and dashboard metrics.
        """

        return {
            "verification_type": "business_revenue_action",
            "agent": self.agent_type,
            "action": action,
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "created_at": _iso_now(),
            "checks": [
                "tenant_scope_validated",
                "amounts_rounded_to_currency_precision",
                "invoice_status_consistent_with_payments",
                "result_has_standard_schema",
            ],
            "result_data": result_data,
        }

    def _prepare_memory_payload(
        self,
        action: str,
        task: Dict[str, Any],
        result_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible context.

        This does not store memory directly unless a Memory Agent is injected.
        It creates safe, scoped business memory context.
        """

        return {
            "memory_type": "business_revenue_context",
            "agent": self.agent_type,
            "action": action,
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "scope": "workspace",
            "created_at": _iso_now(),
            "summary": self._build_memory_summary(action, result_data),
            "data": result_data,
        }

    def _emit_agent_event(
        self,
        event_name: str,
        payload: Dict[str, Any],
    ) -> None:
        """
        Emit event for dashboards, Agent Registry, Agent Router, or analytics.

        Safe no-op if no event bus is connected.
        """

        event = {
            "event_name": event_name,
            "agent": self.agent_type,
            "timestamp": _iso_now(),
            "payload": payload,
        }

        try:
            if self.event_bus and hasattr(self.event_bus, "emit"):
                self.event_bus.emit(event_name, event)
            else:
                logger.debug("Agent event: %s", event)
        except Exception as exc:
            logger.warning("Failed to emit RevenueTracker event: %s", exc)

    def _log_audit_event(
        self,
        action: str,
        user_id: str,
        workspace_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Write audit event.

        Production systems can connect this to the global audit log service.
        """

        if not self.config.get("audit_enabled", True):
            return

        event = {
            "agent": self.agent_type,
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "details": details or {},
            "timestamp": _iso_now(),
        }

        try:
            if self.audit_logger and hasattr(self.audit_logger, "log"):
                self.audit_logger.log(event)
            else:
                logger.info("Audit event: %s", event)
        except Exception as exc:
            logger.warning("Failed to write audit event: %s", exc)

    # ------------------------------------------------------------------
    # Agent routing entrypoints
    # ------------------------------------------------------------------

    async def run(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible async execution entrypoint.

        Master Agent / Router can call this with:
            {
                "action": "create_invoice",
                "user_id": "...",
                "workspace_id": "...",
                ...
            }
        """

        return self.execute_task(task)

    def execute_task(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synchronous task router for Master Agent, Agent Router, dashboards, and API.

        Supported actions:
            - create_invoice
            - update_invoice_status
            - record_payment
            - mark_invoice_sent
            - mark_invoice_paid
            - cancel_invoice
            - list_invoices
            - get_invoice
            - revenue_summary
            - dashboard_metrics
            - aging_report
            - create_pipeline_record
            - update_pipeline_record
            - pipeline_value
            - mrr
        """

        try:
            user_id, workspace_id = self._validate_task_context(task)
            action = _safe_text(task.get("action"), max_length=120).lower()

            if not action:
                return self._error_result(
                    "Missing action for RevenueTracker task.",
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            if self._requires_security_check(action, task):
                approval = self._request_security_approval(action, task)
                if not approval.get("approved", False):
                    return self._error_result(
                        "Security approval denied for revenue action.",
                        error=approval,
                        metadata={"user_id": user_id, "workspace_id": workspace_id},
                    )

            handlers = {
                "create_invoice": self.create_invoice,
                "update_invoice_status": self.update_invoice_status,
                "record_payment": self.record_payment,
                "mark_invoice_sent": self.mark_invoice_sent,
                "mark_invoice_paid": self.mark_invoice_paid,
                "cancel_invoice": self.cancel_invoice,
                "list_invoices": self.list_invoices,
                "get_invoice": self.get_invoice,
                "revenue_summary": self.get_revenue_summary,
                "dashboard_metrics": self.get_dashboard_metrics,
                "aging_report": self.get_aging_report,
                "create_pipeline_record": self.create_pipeline_record,
                "update_pipeline_record": self.update_pipeline_record,
                "pipeline_value": self.calculate_pipeline_value,
                "mrr": self.calculate_mrr,
            }

            handler = handlers.get(action)
            if handler is None:
                return self._error_result(
                    f"Unsupported RevenueTracker action: {action}",
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            return handler(task)

        except Exception as exc:
            return self._error_result("RevenueTracker task failed.", error=exc)

    # ------------------------------------------------------------------
    # Invoice methods
    # ------------------------------------------------------------------

    def create_invoice(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Create a scoped invoice record."""

        try:
            user_id, workspace_id = self._validate_task_context(task)
            currency = _normalize_currency(task.get("currency"), self.default_currency)

            client_id = _safe_text(task.get("client_id"), max_length=120)
            client_name = _safe_text(task.get("client_name"), max_length=240)

            if not client_id:
                raise ValueError("client_id is required.")
            if not client_name:
                raise ValueError("client_name is required.")

            line_items = self._parse_line_items(task.get("line_items"))
            issue_date = _parse_date(task.get("issue_date"), "issue_date") or _utc_now().date()
            due_date = _parse_date(task.get("due_date"), "due_date")

            invoice_id = _safe_text(task.get("invoice_id"), max_length=120) or _new_id("inv")
            invoice_number = (
                _safe_text(task.get("invoice_number"), max_length=120)
                or self._generate_invoice_number(user_id, workspace_id)
            )

            frequency = self._parse_frequency(task.get("frequency"))

            invoice = InvoiceRecord(
                invoice_id=invoice_id,
                invoice_number=invoice_number,
                user_id=user_id,
                workspace_id=workspace_id,
                client_id=client_id,
                client_name=client_name,
                project_id=_safe_text(task.get("project_id"), max_length=120),
                deal_id=_safe_text(task.get("deal_id"), max_length=120),
                currency=currency,
                issue_date=issue_date,
                due_date=due_date,
                line_items=line_items,
                status=self._parse_invoice_status(task.get("status"), InvoiceStatus.DRAFT),
                frequency=frequency,
                notes=_safe_text(task.get("notes"), max_length=1000),
                tags=self._parse_tags(task.get("tags")),
                metadata=dict(task.get("metadata") or {}),
            )
            invoice.refresh_status_from_payments()
            self.repository.save_invoice(invoice)

            data = {"invoice": invoice.to_dict()}
            self._post_success_hooks("create_invoice", task, data)
            return self._safe_result(
                True,
                "Invoice created successfully.",
                data=data,
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        except Exception as exc:
            return self._error_result("Failed to create invoice.", error=exc)

    def get_invoice(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Return a single invoice within user/workspace scope."""

        try:
            user_id, workspace_id = self._validate_task_context(task)
            invoice_id = _safe_text(task.get("invoice_id"), max_length=120)

            if not invoice_id:
                raise ValueError("invoice_id is required.")

            invoice = self.repository.get_invoice(user_id, workspace_id, invoice_id)
            if invoice is None:
                return self._error_result(
                    "Invoice not found in this workspace.",
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            invoice.refresh_status_from_payments()
            data = {"invoice": invoice.to_dict()}
            return self._safe_result(
                True,
                "Invoice retrieved successfully.",
                data=data,
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        except Exception as exc:
            return self._error_result("Failed to retrieve invoice.", error=exc)

    def list_invoices(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """List invoices with optional filters."""

        try:
            user_id, workspace_id = self._validate_task_context(task)
            invoices = self.repository.list_invoices(user_id, workspace_id)

            status_filter = task.get("status")
            client_id = _safe_text(task.get("client_id"), max_length=120)
            project_id = _safe_text(task.get("project_id"), max_length=120)
            deal_id = _safe_text(task.get("deal_id"), max_length=120)
            currency = task.get("currency")
            include_overdue_refresh = bool(task.get("refresh_overdue", True))

            if include_overdue_refresh:
                for invoice in invoices:
                    invoice.refresh_status_from_payments()

            if status_filter:
                parsed_status = self._parse_invoice_status(status_filter)
                invoices = [inv for inv in invoices if inv.status == parsed_status]

            if client_id:
                invoices = [inv for inv in invoices if inv.client_id == client_id]

            if project_id:
                invoices = [inv for inv in invoices if inv.project_id == project_id]

            if deal_id:
                invoices = [inv for inv in invoices if inv.deal_id == deal_id]

            if currency:
                normalized_currency = _normalize_currency(currency, self.default_currency)
                invoices = [inv for inv in invoices if inv.currency == normalized_currency]

            start_date = _parse_date(task.get("start_date"), "start_date")
            end_date = _parse_date(task.get("end_date"), "end_date")

            if start_date:
                invoices = [inv for inv in invoices if inv.issue_date >= start_date]
            if end_date:
                invoices = [inv for inv in invoices if inv.issue_date <= end_date]

            invoices.sort(key=lambda inv: (inv.issue_date, inv.created_at), reverse=True)

            data = {
                "invoices": [invoice.to_dict() for invoice in invoices],
                "count": len(invoices),
            }
            return self._safe_result(
                True,
                "Invoices listed successfully.",
                data=data,
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        except Exception as exc:
            return self._error_result("Failed to list invoices.", error=exc)

    def update_invoice_status(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Update invoice status safely."""

        try:
            user_id, workspace_id = self._validate_task_context(task)
            invoice_id = _safe_text(task.get("invoice_id"), max_length=120)
            new_status = self._parse_invoice_status(task.get("status"))

            if not invoice_id:
                raise ValueError("invoice_id is required.")

            invoice = self.repository.get_invoice(user_id, workspace_id, invoice_id)
            if invoice is None:
                return self._error_result(
                    "Invoice not found in this workspace.",
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            invoice.status = new_status
            invoice.updated_at = _iso_now()
            self.repository.save_invoice(invoice)

            data = {"invoice": invoice.to_dict()}
            self._post_success_hooks("update_invoice_status", task, data)
            return self._safe_result(
                True,
                "Invoice status updated successfully.",
                data=data,
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        except Exception as exc:
            return self._error_result("Failed to update invoice status.", error=exc)

    def mark_invoice_sent(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Mark an invoice as sent/unpaid without sending external email."""

        task = dict(task)
        task["status"] = InvoiceStatus.UNPAID.value
        return self.update_invoice_status(task)

    def mark_invoice_paid(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Mark invoice paid.

        If no amount is provided, records remaining unpaid amount as a manual
        payment. This is internal tracking only.
        """

        try:
            user_id, workspace_id = self._validate_task_context(task)
            invoice_id = _safe_text(task.get("invoice_id"), max_length=120)

            if not invoice_id:
                raise ValueError("invoice_id is required.")

            invoice = self.repository.get_invoice(user_id, workspace_id, invoice_id)
            if invoice is None:
                return self._error_result(
                    "Invoice not found in this workspace.",
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            amount = task.get("amount")
            if amount is None:
                amount = invoice.unpaid_amount

            payment_task = dict(task)
            payment_task["amount"] = amount
            payment_task.setdefault("method", "manual")
            payment_task.setdefault("notes", "Invoice marked as paid.")
            return self.record_payment(payment_task)

        except Exception as exc:
            return self._error_result("Failed to mark invoice as paid.", error=exc)

    def cancel_invoice(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Cancel an invoice within scope."""

        task = dict(task)
        task["status"] = InvoiceStatus.CANCELLED.value
        return self.update_invoice_status(task)

    def record_payment(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Record a manual payment against an invoice."""

        try:
            user_id, workspace_id = self._validate_task_context(task)
            invoice_id = _safe_text(task.get("invoice_id"), max_length=120)

            if not invoice_id:
                raise ValueError("invoice_id is required.")

            invoice = self.repository.get_invoice(user_id, workspace_id, invoice_id)
            if invoice is None:
                return self._error_result(
                    "Invoice not found in this workspace.",
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            if invoice.status in {InvoiceStatus.CANCELLED, InvoiceStatus.VOID}:
                raise ValueError("Cannot record payment on cancelled or void invoice.")

            amount = _parse_decimal(task.get("amount"), "amount")
            if amount <= Decimal("0.00"):
                raise ValueError("Payment amount must be greater than zero.")

            if amount > invoice.unpaid_amount:
                allow_overpayment = bool(task.get("allow_overpayment", False))
                if not allow_overpayment:
                    raise ValueError("Payment amount cannot exceed unpaid invoice amount.")

            payment_currency = _normalize_currency(task.get("currency"), invoice.currency)
            if payment_currency != invoice.currency:
                raise ValueError("Payment currency must match invoice currency.")

            payment_date = _parse_date(task.get("payment_date"), "payment_date") or _utc_now().date()

            payment = PaymentRecord(
                payment_id=_safe_text(task.get("payment_id"), max_length=120) or _new_id("pay"),
                user_id=user_id,
                workspace_id=workspace_id,
                invoice_id=invoice_id,
                amount=amount,
                currency=payment_currency,
                payment_date=payment_date,
                method=_safe_text(task.get("method"), max_length=120) or "manual",
                reference=_safe_text(task.get("reference"), max_length=240),
                notes=_safe_text(task.get("notes"), max_length=1000),
                metadata=dict(task.get("metadata") or {}),
            )

            invoice.payments.append(payment)
            invoice.refresh_status_from_payments()
            self.repository.save_invoice(invoice)

            data = {
                "payment": payment.to_dict(),
                "invoice": invoice.to_dict(),
            }
            self._post_success_hooks("record_payment", task, data)
            return self._safe_result(
                True,
                "Payment recorded successfully.",
                data=data,
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        except Exception as exc:
            return self._error_result("Failed to record payment.", error=exc)

    # ------------------------------------------------------------------
    # Revenue analytics
    # ------------------------------------------------------------------

    def get_revenue_summary(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Return total revenue, paid/unpaid, overdue, invoice counts, MRR, ARR."""

        try:
            user_id, workspace_id = self._validate_task_context(task)
            invoices = self._filtered_invoices_for_metrics(task)
            grouped = self._group_invoices_by_currency(invoices)

            summary_by_currency: Dict[str, Any] = {}
            for currency, currency_invoices in grouped.items():
                paid_total = _decimal_sum(inv.paid_amount for inv in currency_invoices)
                invoiced_total = _decimal_sum(inv.total_amount for inv in currency_invoices)
                unpaid_total = _decimal_sum(inv.unpaid_amount for inv in currency_invoices)
                overdue_total = _decimal_sum(
                    inv.unpaid_amount for inv in currency_invoices if inv.is_overdue
                )
                mrr = self._calculate_mrr_for_invoices(currency_invoices)
                arr = (mrr * Decimal("12")).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

                summary_by_currency[currency] = {
                    "currency": currency,
                    "invoice_count": len(currency_invoices),
                    "paid_invoice_count": sum(1 for inv in currency_invoices if inv.status == InvoiceStatus.PAID),
                    "unpaid_invoice_count": sum(
                        1
                        for inv in currency_invoices
                        if inv.status in {
                            InvoiceStatus.UNPAID,
                            InvoiceStatus.PARTIALLY_PAID,
                            InvoiceStatus.OVERDUE,
                            InvoiceStatus.SENT,
                        }
                    ),
                    "overdue_invoice_count": sum(1 for inv in currency_invoices if inv.is_overdue),
                    "cancelled_invoice_count": sum(
                        1
                        for inv in currency_invoices
                        if inv.status in {InvoiceStatus.CANCELLED, InvoiceStatus.VOID}
                    ),
                    "invoiced_total": _money(invoiced_total),
                    "paid_total": _money(paid_total),
                    "unpaid_total": _money(unpaid_total),
                    "overdue_total": _money(overdue_total),
                    "mrr": _money(mrr),
                    "arr": _money(arr),
                }

            data = {
                "summary_by_currency": summary_by_currency,
                "filters": self._metric_filter_payload(task),
            }
            return self._safe_result(
                True,
                "Revenue summary calculated successfully.",
                data=data,
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        except Exception as exc:
            return self._error_result("Failed to calculate revenue summary.", error=exc)

    def calculate_mrr(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate MRR and ARR from recurring invoices."""

        try:
            user_id, workspace_id = self._validate_task_context(task)
            invoices = self._filtered_invoices_for_metrics(task)
            grouped = self._group_invoices_by_currency(invoices)

            mrr_by_currency: Dict[str, Any] = {}
            for currency, currency_invoices in grouped.items():
                mrr = self._calculate_mrr_for_invoices(currency_invoices)
                arr = (mrr * Decimal("12")).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
                recurring_invoices = [
                    inv for inv in currency_invoices
                    if inv.frequency != RevenueFrequency.ONE_TIME
                    and inv.status not in {InvoiceStatus.CANCELLED, InvoiceStatus.VOID}
                ]
                mrr_by_currency[currency] = {
                    "currency": currency,
                    "mrr": _money(mrr),
                    "arr": _money(arr),
                    "recurring_invoice_count": len(recurring_invoices),
                }

            return self._safe_result(
                True,
                "MRR calculated successfully.",
                data={
                    "mrr_by_currency": mrr_by_currency,
                    "filters": self._metric_filter_payload(task),
                },
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        except Exception as exc:
            return self._error_result("Failed to calculate MRR.", error=exc)

    def get_aging_report(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Return unpaid invoice aging buckets."""

        try:
            user_id, workspace_id = self._validate_task_context(task)
            invoices = self._filtered_invoices_for_metrics(task)
            today = _utc_now().date()

            buckets: Dict[str, Dict[str, Any]] = {}
            for invoice in invoices:
                if invoice.unpaid_amount <= Decimal("0.00"):
                    continue
                if invoice.status in {InvoiceStatus.CANCELLED, InvoiceStatus.VOID}:
                    continue

                currency = invoice.currency
                buckets.setdefault(
                    currency,
                    {
                        "currency": currency,
                        "current": Decimal("0.00"),
                        "days_1_30": Decimal("0.00"),
                        "days_31_60": Decimal("0.00"),
                        "days_61_90": Decimal("0.00"),
                        "days_90_plus": Decimal("0.00"),
                        "invoice_count": 0,
                    },
                )

                due = invoice.due_date or invoice.issue_date
                days_overdue = (today - due).days

                if days_overdue <= 0:
                    bucket_name = "current"
                elif days_overdue <= 30:
                    bucket_name = "days_1_30"
                elif days_overdue <= 60:
                    bucket_name = "days_31_60"
                elif days_overdue <= 90:
                    bucket_name = "days_61_90"
                else:
                    bucket_name = "days_90_plus"

                buckets[currency][bucket_name] += invoice.unpaid_amount
                buckets[currency]["invoice_count"] += 1

            serialized = {}
            for currency, bucket in buckets.items():
                serialized[currency] = {
                    key: _money(value) if isinstance(value, Decimal) else value
                    for key, value in bucket.items()
                }

            return self._safe_result(
                True,
                "Invoice aging report generated successfully.",
                data={
                    "aging_by_currency": serialized,
                    "filters": self._metric_filter_payload(task),
                },
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        except Exception as exc:
            return self._error_result("Failed to generate aging report.", error=exc)

    def get_dashboard_metrics(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Return dashboard-ready revenue metrics.

        Designed for FastAPI/dashboard integration.
        """

        try:
            user_id, workspace_id = self._validate_task_context(task)
            invoices = self._filtered_invoices_for_metrics(task)
            pipeline_records = self.repository.list_pipeline_records(user_id, workspace_id)

            invoices_by_currency = self._group_invoices_by_currency(invoices)
            pipeline_by_currency = self._group_pipeline_by_currency(pipeline_records)

            metrics_by_currency: Dict[str, Any] = {}
            currencies = set(invoices_by_currency.keys()) | set(pipeline_by_currency.keys())

            for currency in sorted(currencies):
                currency_invoices = invoices_by_currency.get(currency, [])
                currency_pipeline = pipeline_by_currency.get(currency, [])

                paid_total = _decimal_sum(inv.paid_amount for inv in currency_invoices)
                unpaid_total = _decimal_sum(inv.unpaid_amount for inv in currency_invoices)
                overdue_total = _decimal_sum(
                    inv.unpaid_amount for inv in currency_invoices if inv.is_overdue
                )
                pipeline_total = _decimal_sum(
                    rec.amount for rec in currency_pipeline if rec.status == PipelineStatus.OPEN
                )
                weighted_pipeline = _decimal_sum(
                    rec.weighted_value for rec in currency_pipeline if rec.status == PipelineStatus.OPEN
                )
                mrr = self._calculate_mrr_for_invoices(currency_invoices)

                metrics_by_currency[currency] = {
                    "currency": currency,
                    "paid_total": _money(paid_total),
                    "unpaid_total": _money(unpaid_total),
                    "overdue_total": _money(overdue_total),
                    "mrr": _money(mrr),
                    "arr": _money(mrr * Decimal("12")),
                    "pipeline_total": _money(pipeline_total),
                    "weighted_pipeline": _money(weighted_pipeline),
                    "invoice_count": len(currency_invoices),
                    "open_pipeline_count": sum(
                        1 for rec in currency_pipeline if rec.status == PipelineStatus.OPEN
                    ),
                }

            data = {
                "metrics_by_currency": metrics_by_currency,
                "invoice_status_counts": self._invoice_status_counts(invoices),
                "generated_at": _iso_now(),
                "filters": self._metric_filter_payload(task),
            }

            return self._safe_result(
                True,
                "Revenue dashboard metrics generated successfully.",
                data=data,
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        except Exception as exc:
            return self._error_result("Failed to generate dashboard metrics.", error=exc)

    # ------------------------------------------------------------------
    # Pipeline revenue methods
    # ------------------------------------------------------------------

    def create_pipeline_record(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Create an expected/forecasted revenue pipeline record."""

        try:
            user_id, workspace_id = self._validate_task_context(task)

            title = _safe_text(task.get("title"), max_length=240)
            if not title:
                raise ValueError("title is required.")

            amount = _parse_decimal(task.get("amount"), "amount")
            if amount < Decimal("0.00"):
                raise ValueError("amount cannot be negative.")

            probability = _parse_decimal(task.get("probability", "0"), "probability")
            if probability < Decimal("0.00") or probability > Decimal("100.00"):
                raise ValueError("probability must be between 0 and 100.")

            currency = _normalize_currency(task.get("currency"), self.default_currency)

            record = PipelineRevenueRecord(
                pipeline_id=_safe_text(task.get("pipeline_id"), max_length=120) or _new_id("pipe"),
                user_id=user_id,
                workspace_id=workspace_id,
                title=title,
                amount=amount,
                currency=currency,
                probability=probability,
                expected_close_date=_parse_date(
                    task.get("expected_close_date"),
                    "expected_close_date",
                ),
                client_id=_safe_text(task.get("client_id"), max_length=120),
                deal_id=_safe_text(task.get("deal_id"), max_length=120),
                source=_safe_text(task.get("source"), max_length=120),
                status=self._parse_pipeline_status(task.get("status"), PipelineStatus.OPEN),
                notes=_safe_text(task.get("notes"), max_length=1000),
                metadata=dict(task.get("metadata") or {}),
            )

            self.repository.save_pipeline_record(record)

            data = {"pipeline_record": record.to_dict()}
            self._post_success_hooks("create_pipeline_record", task, data)
            return self._safe_result(
                True,
                "Pipeline revenue record created successfully.",
                data=data,
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        except Exception as exc:
            return self._error_result("Failed to create pipeline revenue record.", error=exc)

    def update_pipeline_record(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Update a pipeline revenue record within workspace scope."""

        try:
            user_id, workspace_id = self._validate_task_context(task)
            pipeline_id = _safe_text(task.get("pipeline_id"), max_length=120)

            if not pipeline_id:
                raise ValueError("pipeline_id is required.")

            record = self.repository.get_pipeline_record(user_id, workspace_id, pipeline_id)
            if record is None:
                return self._error_result(
                    "Pipeline record not found in this workspace.",
                    metadata={"user_id": user_id, "workspace_id": workspace_id},
                )

            if "title" in task:
                title = _safe_text(task.get("title"), max_length=240)
                if not title:
                    raise ValueError("title cannot be empty.")
                record.title = title

            if "amount" in task:
                amount = _parse_decimal(task.get("amount"), "amount")
                if amount < Decimal("0.00"):
                    raise ValueError("amount cannot be negative.")
                record.amount = amount

            if "probability" in task:
                probability = _parse_decimal(task.get("probability"), "probability")
                if probability < Decimal("0.00") or probability > Decimal("100.00"):
                    raise ValueError("probability must be between 0 and 100.")
                record.probability = probability

            if "currency" in task:
                record.currency = _normalize_currency(task.get("currency"), record.currency)

            if "expected_close_date" in task:
                record.expected_close_date = _parse_date(
                    task.get("expected_close_date"),
                    "expected_close_date",
                )

            if "status" in task:
                record.status = self._parse_pipeline_status(task.get("status"))

            for key in ("client_id", "deal_id", "source", "notes"):
                if key in task:
                    setattr(record, key, _safe_text(task.get(key), max_length=1000))

            if "metadata" in task:
                record.metadata.update(dict(task.get("metadata") or {}))

            record.updated_at = _iso_now()
            self.repository.save_pipeline_record(record)

            data = {"pipeline_record": record.to_dict()}
            self._post_success_hooks("update_pipeline_record", task, data)
            return self._safe_result(
                True,
                "Pipeline revenue record updated successfully.",
                data=data,
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        except Exception as exc:
            return self._error_result("Failed to update pipeline revenue record.", error=exc)

    def calculate_pipeline_value(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate raw and weighted pipeline value."""

        try:
            user_id, workspace_id = self._validate_task_context(task)
            records = self.repository.list_pipeline_records(user_id, workspace_id)

            status_filter = task.get("status")
            if status_filter:
                parsed_status = self._parse_pipeline_status(status_filter)
                records = [record for record in records if record.status == parsed_status]

            client_id = _safe_text(task.get("client_id"), max_length=120)
            deal_id = _safe_text(task.get("deal_id"), max_length=120)
            currency_filter = task.get("currency")

            if client_id:
                records = [record for record in records if record.client_id == client_id]
            if deal_id:
                records = [record for record in records if record.deal_id == deal_id]
            if currency_filter:
                normalized = _normalize_currency(currency_filter, self.default_currency)
                records = [record for record in records if record.currency == normalized]

            start_date = _parse_date(task.get("start_date"), "start_date")
            end_date = _parse_date(task.get("end_date"), "end_date")

            if start_date:
                records = [
                    record for record in records
                    if record.expected_close_date and record.expected_close_date >= start_date
                ]
            if end_date:
                records = [
                    record for record in records
                    if record.expected_close_date and record.expected_close_date <= end_date
                ]

            grouped = self._group_pipeline_by_currency(records)
            value_by_currency: Dict[str, Any] = {}

            for currency, currency_records in grouped.items():
                raw_total = _decimal_sum(record.amount for record in currency_records)
                weighted_total = _decimal_sum(record.weighted_value for record in currency_records)
                open_count = sum(1 for record in currency_records if record.status == PipelineStatus.OPEN)
                won_count = sum(1 for record in currency_records if record.status == PipelineStatus.WON)
                lost_count = sum(1 for record in currency_records if record.status == PipelineStatus.LOST)

                value_by_currency[currency] = {
                    "currency": currency,
                    "pipeline_total": _money(raw_total),
                    "weighted_pipeline_total": _money(weighted_total),
                    "record_count": len(currency_records),
                    "open_count": open_count,
                    "won_count": won_count,
                    "lost_count": lost_count,
                }

            return self._safe_result(
                True,
                "Pipeline value calculated successfully.",
                data={
                    "pipeline_value_by_currency": value_by_currency,
                    "records": [record.to_dict() for record in records],
                    "filters": self._metric_filter_payload(task),
                },
                metadata={"user_id": user_id, "workspace_id": workspace_id},
            )

        except Exception as exc:
            return self._error_result("Failed to calculate pipeline value.", error=exc)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _post_success_hooks(
        self,
        action: str,
        task: Dict[str, Any],
        result_data: Dict[str, Any],
    ) -> None:
        """Run audit, event, memory, and verification hooks after successful action."""

        user_id = _safe_text(task.get("user_id"), max_length=120)
        workspace_id = _safe_text(task.get("workspace_id"), max_length=120)

        verification_payload = self._prepare_verification_payload(action, task, result_data)
        memory_payload = self._prepare_memory_payload(action, task, result_data)

        self._log_audit_event(action, user_id, workspace_id, result_data)
        self._emit_agent_event(
            f"business.revenue.{action}",
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "result": result_data,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
        )

        if self.verification_agent and hasattr(self.verification_agent, "queue_verification"):
            try:
                self.verification_agent.queue_verification(verification_payload)
            except Exception as exc:
                logger.warning("Verification hook failed: %s", exc)

        if (
            self.config.get("memory_enabled", True)
            and self.memory_agent
            and hasattr(self.memory_agent, "store_context")
        ):
            try:
                self.memory_agent.store_context(memory_payload)
            except Exception as exc:
                logger.warning("Memory hook failed: %s", exc)

    def _build_memory_summary(self, action: str, result_data: Dict[str, Any]) -> str:
        """Build safe human-readable summary for Memory Agent."""

        if "invoice" in result_data:
            invoice = result_data["invoice"]
            return (
                f"Revenue action '{action}' for invoice "
                f"{invoice.get('invoice_number') or invoice.get('invoice_id')} "
                f"with total {invoice.get('total_amount')} {invoice.get('currency')} "
                f"and status {invoice.get('status')}."
            )

        if "pipeline_record" in result_data:
            record = result_data["pipeline_record"]
            return (
                f"Pipeline revenue action '{action}' for "
                f"{record.get('title')} worth {record.get('amount')} "
                f"{record.get('currency')} at {record.get('probability')}% probability."
            )

        return f"Revenue action '{action}' completed."

    def _parse_line_items(self, raw_items: Any) -> List[InvoiceLineItem]:
        """Parse and validate invoice line items."""

        if not isinstance(raw_items, list) or not raw_items:
            raise ValueError("line_items must be a non-empty list.")

        parsed: List[InvoiceLineItem] = []
        for index, raw in enumerate(raw_items):
            if not isinstance(raw, dict):
                raise ValueError(f"line_items[{index}] must be a dictionary.")

            description = _safe_text(raw.get("description"), max_length=500)
            if not description:
                raise ValueError(f"line_items[{index}].description is required.")

            quantity = _parse_decimal(raw.get("quantity", "1"), f"line_items[{index}].quantity")
            unit_price = _parse_decimal(raw.get("unit_price"), f"line_items[{index}].unit_price")
            tax_rate = _parse_decimal(raw.get("tax_rate", "0"), f"line_items[{index}].tax_rate")
            discount_amount = _parse_decimal(
                raw.get("discount_amount", "0"),
                f"line_items[{index}].discount_amount",
            )

            if quantity <= Decimal("0.00"):
                raise ValueError(f"line_items[{index}].quantity must be greater than zero.")
            if unit_price < Decimal("0.00"):
                raise ValueError(f"line_items[{index}].unit_price cannot be negative.")
            if tax_rate < Decimal("0.00"):
                raise ValueError(f"line_items[{index}].tax_rate cannot be negative.")
            if discount_amount < Decimal("0.00"):
                raise ValueError(f"line_items[{index}].discount_amount cannot be negative.")

            parsed.append(
                InvoiceLineItem(
                    description=description,
                    quantity=quantity,
                    unit_price=unit_price,
                    tax_rate=tax_rate,
                    discount_amount=discount_amount,
                )
            )

        return parsed

    def _parse_invoice_status(
        self,
        value: Any,
        default: Optional[InvoiceStatus] = None,
    ) -> InvoiceStatus:
        """Parse invoice status."""

        if value is None:
            if default is not None:
                return default
            raise ValueError("status is required.")

        if isinstance(value, InvoiceStatus):
            return value

        raw = _safe_text(value).lower()
        try:
            return InvoiceStatus(raw)
        except ValueError as exc:
            allowed = ", ".join(status.value for status in InvoiceStatus)
            raise ValueError(f"Invalid invoice status. Allowed: {allowed}.") from exc

    def _parse_payment_status(
        self,
        value: Any,
        default: PaymentStatus = PaymentStatus.RECORDED,
    ) -> PaymentStatus:
        """Parse payment status."""

        if value is None:
            return default

        if isinstance(value, PaymentStatus):
            return value

        raw = _safe_text(value).lower()
        try:
            return PaymentStatus(raw)
        except ValueError as exc:
            allowed = ", ".join(status.value for status in PaymentStatus)
            raise ValueError(f"Invalid payment status. Allowed: {allowed}.") from exc

    def _parse_pipeline_status(
        self,
        value: Any,
        default: Optional[PipelineStatus] = None,
    ) -> PipelineStatus:
        """Parse pipeline status."""

        if value is None:
            if default is not None:
                return default
            raise ValueError("pipeline status is required.")

        if isinstance(value, PipelineStatus):
            return value

        raw = _safe_text(value).lower()
        try:
            return PipelineStatus(raw)
        except ValueError as exc:
            allowed = ", ".join(status.value for status in PipelineStatus)
            raise ValueError(f"Invalid pipeline status. Allowed: {allowed}.") from exc

    def _parse_frequency(self, value: Any) -> RevenueFrequency:
        """Parse revenue frequency."""

        if value is None:
            return RevenueFrequency.ONE_TIME

        if isinstance(value, RevenueFrequency):
            return value

        raw = _safe_text(value).lower()
        try:
            return RevenueFrequency(raw)
        except ValueError as exc:
            allowed = ", ".join(freq.value for freq in RevenueFrequency)
            raise ValueError(f"Invalid revenue frequency. Allowed: {allowed}.") from exc

    def _parse_tags(self, value: Any) -> List[str]:
        """Parse tags into a safe list."""

        if value is None:
            return []

        if isinstance(value, str):
            return [_safe_text(value, max_length=80)] if value.strip() else []

        if not isinstance(value, list):
            raise ValueError("tags must be a list of strings or a single string.")

        tags: List[str] = []
        for item in value:
            tag = _safe_text(item, max_length=80)
            if tag and tag not in tags:
                tags.append(tag)

        return tags

    def _generate_invoice_number(self, user_id: str, workspace_id: str) -> str:
        """Generate readable invoice number within workspace scope."""

        count = len(self.repository.list_invoices(user_id, workspace_id)) + 1
        year = _utc_now().year
        return f"INV-{year}-{count:05d}"

    def _filtered_invoices_for_metrics(self, task: Dict[str, Any]) -> List[InvoiceRecord]:
        """Return invoices filtered for metric calculations."""

        user_id, workspace_id = self._validate_task_context(task)
        invoices = self.repository.list_invoices(user_id, workspace_id)

        for invoice in invoices:
            invoice.refresh_status_from_payments()

        start_date = _parse_date(task.get("start_date"), "start_date")
        end_date = _parse_date(task.get("end_date"), "end_date")
        client_id = _safe_text(task.get("client_id"), max_length=120)
        project_id = _safe_text(task.get("project_id"), max_length=120)
        deal_id = _safe_text(task.get("deal_id"), max_length=120)
        currency = task.get("currency")
        include_cancelled = bool(task.get("include_cancelled", False))

        if start_date:
            invoices = [invoice for invoice in invoices if invoice.issue_date >= start_date]
        if end_date:
            invoices = [invoice for invoice in invoices if invoice.issue_date <= end_date]
        if client_id:
            invoices = [invoice for invoice in invoices if invoice.client_id == client_id]
        if project_id:
            invoices = [invoice for invoice in invoices if invoice.project_id == project_id]
        if deal_id:
            invoices = [invoice for invoice in invoices if invoice.deal_id == deal_id]
        if currency:
            normalized = _normalize_currency(currency, self.default_currency)
            invoices = [invoice for invoice in invoices if invoice.currency == normalized]
        if not include_cancelled:
            invoices = [
                invoice for invoice in invoices
                if invoice.status not in {InvoiceStatus.CANCELLED, InvoiceStatus.VOID}
            ]

        return invoices

    def _metric_filter_payload(self, task: Dict[str, Any]) -> Dict[str, Any]:
        """Return safe filter summary for API/dashboard responses."""

        allowed_keys = (
            "start_date",
            "end_date",
            "client_id",
            "project_id",
            "deal_id",
            "currency",
            "status",
            "include_cancelled",
        )
        return {
            key: task.get(key)
            for key in allowed_keys
            if key in task
        }

    def _group_invoices_by_currency(
        self,
        invoices: Iterable[InvoiceRecord],
    ) -> Dict[str, List[InvoiceRecord]]:
        """Group invoices by currency."""

        grouped: Dict[str, List[InvoiceRecord]] = {}
        for invoice in invoices:
            grouped.setdefault(invoice.currency, []).append(invoice)
        return grouped

    def _group_pipeline_by_currency(
        self,
        records: Iterable[PipelineRevenueRecord],
    ) -> Dict[str, List[PipelineRevenueRecord]]:
        """Group pipeline records by currency."""

        grouped: Dict[str, List[PipelineRevenueRecord]] = {}
        for record in records:
            grouped.setdefault(record.currency, []).append(record)
        return grouped

    def _calculate_mrr_for_invoices(
        self,
        invoices: Iterable[InvoiceRecord],
    ) -> Decimal:
        """
        Calculate MRR from recurring invoices.

        Formula:
            monthly invoice = total
            quarterly invoice = total / 3
            semi_annual invoice = total / 6
            annual invoice = total / 12

        Only active/non-cancelled invoices are included.
        """

        total = Decimal("0.00")

        for invoice in invoices:
            if invoice.status in {InvoiceStatus.CANCELLED, InvoiceStatus.VOID}:
                continue

            amount = invoice.total_amount

            if invoice.frequency == RevenueFrequency.MONTHLY:
                total += amount
            elif invoice.frequency == RevenueFrequency.QUARTERLY:
                total += amount / Decimal("3")
            elif invoice.frequency == RevenueFrequency.SEMI_ANNUAL:
                total += amount / Decimal("6")
            elif invoice.frequency == RevenueFrequency.ANNUAL:
                total += amount / Decimal("12")

        return total.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

    def _invoice_status_counts(self, invoices: Iterable[InvoiceRecord]) -> Dict[str, int]:
        """Return invoice counts by status."""

        counts = {status.value: 0 for status in InvoiceStatus}
        for invoice in invoices:
            counts[invoice.status.value] = counts.get(invoice.status.value, 0) + 1
        return counts


# ---------------------------------------------------------------------------
# Registry metadata
# ---------------------------------------------------------------------------

AGENT_METADATA: Dict[str, Any] = {
    "agent": "Business Agent",
    "module": "business_agent",
    "file": "revenue_tracker.py",
    "class_name": "RevenueTracker",
    "agent_type": RevenueTracker.agent_type,
    "version": RevenueTracker.version,
    "purpose": "Tracks revenue, invoices, paid/unpaid, MRR, pipeline value.",
    "supports_saas_isolation": True,
    "requires_user_id": True,
    "requires_workspace_id": True,
    "security_sensitive_actions": sorted(SENSITIVE_ACTIONS),
    "public_methods": [
        "execute_task",
        "create_invoice",
        "get_invoice",
        "list_invoices",
        "update_invoice_status",
        "mark_invoice_sent",
        "mark_invoice_paid",
        "cancel_invoice",
        "record_payment",
        "get_revenue_summary",
        "calculate_mrr",
        "get_aging_report",
        "get_dashboard_metrics",
        "create_pipeline_record",
        "update_pipeline_record",
        "calculate_pipeline_value",
    ],
}


__all__ = [
    "RevenueTracker",
    "InvoiceStatus",
    "PaymentStatus",
    "RevenueFrequency",
    "PipelineStatus",
    "InvoiceLineItem",
    "PaymentRecord",
    "InvoiceRecord",
    "PipelineRevenueRecord",
    "InMemoryRevenueRepository",
    "AGENT_METADATA",
]


"""
Where to place:
    agents/super_agents/business_agent/revenue_tracker.py

Required dependencies:
    Python standard library only:
        - dataclasses
        - datetime
        - decimal
        - enum
        - logging
        - typing
        - uuid

How to test:
    tracker = RevenueTracker()
    result = tracker.create_invoice({
        "user_id": "user_1",
        "workspace_id": "workspace_1",
        "client_id": "client_1",
        "client_name": "Acme Inc.",
        "currency": "USD",
        "frequency": "monthly",
        "line_items": [
            {
                "description": "Website care plan",
                "quantity": 1,
                "unit_price": 299,
                "tax_rate": 0
            }
        ]
    })
    invoice_id = result["data"]["invoice"]["invoice_id"]

    tracker.record_payment({
        "user_id": "user_1",
        "workspace_id": "workspace_1",
        "invoice_id": invoice_id,
        "amount": 299,
        "currency": "USD",
        "method": "manual"
    })

    summary = tracker.get_revenue_summary({
        "user_id": "user_1",
        "workspace_id": "workspace_1"
    })

Agent/Module: Business Agent
File Completed: revenue_tracker.py
Completion: 66.7%
Completed Files: [
    'business_agent.py',
    'crm_manager.py',
    'lead_tracker.py',
    'analytics_engine.py',
    'client_manager.py',
    'sales_pipeline.py',
    'campaign_tracker.py',
    'revenue_tracker.py'
]
Remaining Files: [
    'report_builder.py',
    'task_manager.py',
    'business_memory.py',
    'config.py'
]
Next Recommended File: agents/super_agents/business_agent/report_builder.py

FILE COMPLETE
"""