"""
agents/super_agents/finance_agent/subscription_tracker.py

William / Jarvis Multi-Agent AI SaaS System - Finance Agent
Digital Promotix

Purpose:
    Tracks SaaS subscriptions, renewals, invoices, cancellation reminders,
    subscription spend, billing cycles, renewal risk, and dashboard-ready
    subscription summaries.

Architecture Compatibility:
    - BaseAgent compatible with safe fallback if BaseAgent is unavailable.
    - Master Agent / Agent Router compatible via execute_task().
    - Agent Registry compatible via AGENT_METADATA.
    - Security Agent compatible through approval hooks for sensitive actions.
    - Memory Agent compatible through prepared memory payloads.
    - Verification Agent compatible through verification payloads.
    - Dashboard/API ready through structured dict/JSON style responses.
    - SaaS-safe through strict user_id/workspace_id context validation.

Safety Rules:
    - This module NEVER performs real payments, bank transfers, card actions,
      provider API cancellations, or destructive financial actions.
    - Cancellation actions are represented as reminders/drafts/intent records only.
    - Every user/workspace-scoped operation validates isolation context.
    - Sensitive operations can request Security Agent approval through hooks.
"""

from __future__ import annotations

import copy
import csv
import io
import json
import logging
import math
import uuid
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for isolated import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe when the full William/Jarvis system
        has not been generated yet. In production, agents.base_agent.BaseAgent
        should be used instead.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())


try:
    from agents.core.agent_events import AgentEventBus  # type: ignore
except Exception:  # pragma: no cover
    AgentEventBus = None  # type: ignore


try:
    from agents.core.audit_logger import AuditLogger  # type: ignore
except Exception:  # pragma: no cover
    AuditLogger = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants / Metadata
# ---------------------------------------------------------------------------

AGENT_METADATA: Dict[str, Any] = {
    "agent_name": "SubscriptionTracker",
    "agent_module": "Finance Agent",
    "file_path": "agents/super_agents/finance_agent/subscription_tracker.py",
    "class_name": "SubscriptionTracker",
    "version": "1.0.0",
    "status": "production_ready",
    "supports_user_workspace_isolation": True,
    "supports_security_agent": True,
    "supports_memory_agent": True,
    "supports_verification_agent": True,
    "supports_dashboard_api": True,
    "safe_to_import_without_full_system": True,
    "does_real_financial_actions": False,
    "public_methods": [
        "execute_task",
        "add_subscription",
        "update_subscription",
        "get_subscription",
        "list_subscriptions",
        "deactivate_subscription",
        "create_cancellation_reminder",
        "list_cancellation_reminders",
        "get_upcoming_renewals",
        "record_invoice",
        "mark_invoice_paid",
        "list_invoices",
        "calculate_monthly_recurring_cost",
        "calculate_annualized_cost",
        "analyze_subscription_spend",
        "detect_duplicate_subscriptions",
        "detect_unused_or_risky_subscriptions",
        "generate_dashboard_summary",
        "export_subscriptions_csv",
        "export_subscriptions_json",
    ],
}


DEFAULT_CURRENCY = "USD"
DEFAULT_RENEWAL_WARNING_DAYS = 14
DEFAULT_UNUSED_DAYS_THRESHOLD = 60
MONEY_QUANT = Decimal("0.01")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class BillingCycle(str, Enum):
    """Supported subscription billing cycles."""

    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    SEMI_ANNUAL = "semi_annual"
    ANNUAL = "annual"
    CUSTOM = "custom"


class SubscriptionStatus(str, Enum):
    """Subscription lifecycle status."""

    ACTIVE = "active"
    TRIAL = "trial"
    PAUSED = "paused"
    PENDING_CANCEL = "pending_cancel"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class InvoiceStatus(str, Enum):
    """Subscription invoice/payment status."""

    DRAFT = "draft"
    DUE = "due"
    PAID = "paid"
    OVERDUE = "overdue"
    VOID = "void"
    UNKNOWN = "unknown"


class ReminderStatus(str, Enum):
    """Cancellation reminder status."""

    OPEN = "open"
    SNOOZED = "snoozed"
    COMPLETED = "completed"
    DISMISSED = "dismissed"


class RenewalRisk(str, Enum):
    """Renewal risk level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class TaskAction(str, Enum):
    """Master Agent / Router action names supported by this file."""

    ADD_SUBSCRIPTION = "add_subscription"
    UPDATE_SUBSCRIPTION = "update_subscription"
    GET_SUBSCRIPTION = "get_subscription"
    LIST_SUBSCRIPTIONS = "list_subscriptions"
    DEACTIVATE_SUBSCRIPTION = "deactivate_subscription"
    CREATE_CANCELLATION_REMINDER = "create_cancellation_reminder"
    LIST_CANCELLATION_REMINDERS = "list_cancellation_reminders"
    UPCOMING_RENEWALS = "get_upcoming_renewals"
    RECORD_INVOICE = "record_invoice"
    MARK_INVOICE_PAID = "mark_invoice_paid"
    LIST_INVOICES = "list_invoices"
    MONTHLY_COST = "calculate_monthly_recurring_cost"
    ANNUAL_COST = "calculate_annualized_cost"
    SPEND_ANALYSIS = "analyze_subscription_spend"
    DUPLICATES = "detect_duplicate_subscriptions"
    UNUSED_RISKY = "detect_unused_or_risky_subscriptions"
    DASHBOARD_SUMMARY = "generate_dashboard_summary"
    EXPORT_CSV = "export_subscriptions_csv"
    EXPORT_JSON = "export_subscriptions_json"


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class SaaSContext:
    """
    Per-request SaaS isolation context.

    Every user/workspace scoped operation must include user_id and workspace_id.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    actor_id: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SubscriptionRecord:
    """Stored SaaS subscription record."""

    subscription_id: str
    user_id: str
    workspace_id: str
    vendor_name: str
    plan_name: Optional[str]
    amount: Decimal
    currency: str
    billing_cycle: BillingCycle
    start_date: Optional[date]
    next_renewal_date: Optional[date]
    status: SubscriptionStatus = SubscriptionStatus.ACTIVE
    seats: int = 1
    category: Optional[str] = None
    payment_method_label: Optional[str] = None
    owner_name: Optional[str] = None
    owner_email: Optional[str] = None
    website_url: Optional[str] = None
    notes: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    invoice_ids: List[str] = field(default_factory=list)
    reminder_ids: List[str] = field(default_factory=list)
    last_used_at: Optional[date] = None
    auto_renew: bool = True
    cancellation_url: Optional[str] = None
    contract_end_date: Optional[date] = None
    custom_cycle_days: Optional[int] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SubscriptionInvoice:
    """Invoice record attached to a subscription."""

    invoice_id: str
    subscription_id: str
    user_id: str
    workspace_id: str
    vendor_name: str
    invoice_number: Optional[str]
    amount: Decimal
    currency: str
    invoice_date: Optional[date]
    due_date: Optional[date]
    paid_date: Optional[date] = None
    status: InvoiceStatus = InvoiceStatus.DUE
    file_ref: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CancellationReminder:
    """
    Reminder/draft record for cancellation.

    This is intentionally not a real provider cancellation action.
    """

    reminder_id: str
    subscription_id: str
    user_id: str
    workspace_id: str
    vendor_name: str
    remind_on: date
    reason: Optional[str]
    status: ReminderStatus = ReminderStatus.OPEN
    priority: str = "normal"
    assigned_to: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------

class InMemorySubscriptionRepository:
    """
    Safe in-memory repository.

    Production systems can replace this repository with a database-backed
    implementation while preserving method signatures.
    """

    def __init__(self) -> None:
        self._subscriptions: Dict[str, SubscriptionRecord] = {}
        self._invoices: Dict[str, SubscriptionInvoice] = {}
        self._reminders: Dict[str, CancellationReminder] = {}

    def save_subscription(self, record: SubscriptionRecord) -> SubscriptionRecord:
        self._subscriptions[record.subscription_id] = copy.deepcopy(record)
        return copy.deepcopy(record)

    def get_subscription(
        self,
        subscription_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Optional[SubscriptionRecord]:
        record = self._subscriptions.get(subscription_id)
        if not record:
            return None
        if record.user_id != user_id or record.workspace_id != workspace_id:
            return None
        return copy.deepcopy(record)

    def list_subscriptions(
        self,
        user_id: str,
        workspace_id: str,
        filters: Optional[Mapping[str, Any]] = None,
    ) -> List[SubscriptionRecord]:
        filters = dict(filters or {})
        records: List[SubscriptionRecord] = []
        for record in self._subscriptions.values():
            if record.user_id != user_id or record.workspace_id != workspace_id:
                continue
            if not self._matches_subscription_filters(record, filters):
                continue
            records.append(copy.deepcopy(record))

        records.sort(
            key=lambda item: (
                item.next_renewal_date or date.max,
                item.vendor_name.lower(),
            )
        )
        return records

    def save_invoice(self, invoice: SubscriptionInvoice) -> SubscriptionInvoice:
        self._invoices[invoice.invoice_id] = copy.deepcopy(invoice)
        return copy.deepcopy(invoice)

    def get_invoice(
        self,
        invoice_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Optional[SubscriptionInvoice]:
        invoice = self._invoices.get(invoice_id)
        if not invoice:
            return None
        if invoice.user_id != user_id or invoice.workspace_id != workspace_id:
            return None
        return copy.deepcopy(invoice)

    def list_invoices(
        self,
        user_id: str,
        workspace_id: str,
        subscription_id: Optional[str] = None,
        filters: Optional[Mapping[str, Any]] = None,
    ) -> List[SubscriptionInvoice]:
        filters = dict(filters or {})
        invoices: List[SubscriptionInvoice] = []

        for invoice in self._invoices.values():
            if invoice.user_id != user_id or invoice.workspace_id != workspace_id:
                continue
            if subscription_id and invoice.subscription_id != subscription_id:
                continue
            if not self._matches_invoice_filters(invoice, filters):
                continue
            invoices.append(copy.deepcopy(invoice))

        invoices.sort(key=lambda item: item.due_date or date.max)
        return invoices

    def save_reminder(self, reminder: CancellationReminder) -> CancellationReminder:
        self._reminders[reminder.reminder_id] = copy.deepcopy(reminder)
        return copy.deepcopy(reminder)

    def get_reminder(
        self,
        reminder_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Optional[CancellationReminder]:
        reminder = self._reminders.get(reminder_id)
        if not reminder:
            return None
        if reminder.user_id != user_id or reminder.workspace_id != workspace_id:
            return None
        return copy.deepcopy(reminder)

    def list_reminders(
        self,
        user_id: str,
        workspace_id: str,
        subscription_id: Optional[str] = None,
        filters: Optional[Mapping[str, Any]] = None,
    ) -> List[CancellationReminder]:
        filters = dict(filters or {})
        reminders: List[CancellationReminder] = []

        for reminder in self._reminders.values():
            if reminder.user_id != user_id or reminder.workspace_id != workspace_id:
                continue
            if subscription_id and reminder.subscription_id != subscription_id:
                continue
            if not self._matches_reminder_filters(reminder, filters):
                continue
            reminders.append(copy.deepcopy(reminder))

        reminders.sort(key=lambda item: item.remind_on)
        return reminders

    @staticmethod
    def _matches_subscription_filters(
        record: SubscriptionRecord,
        filters: Mapping[str, Any],
    ) -> bool:
        status = filters.get("status")
        if status and record.status.value != str(status):
            return False

        vendor_name = filters.get("vendor_name")
        if vendor_name and str(vendor_name).lower() not in record.vendor_name.lower():
            return False

        category = filters.get("category")
        if category and str(category).lower() != str(record.category or "").lower():
            return False

        tag = filters.get("tag")
        if tag and str(tag).lower() not in [item.lower() for item in record.tags]:
            return False

        auto_renew = filters.get("auto_renew")
        if auto_renew is not None and bool(auto_renew) != record.auto_renew:
            return False

        return True

    @staticmethod
    def _matches_invoice_filters(
        invoice: SubscriptionInvoice,
        filters: Mapping[str, Any],
    ) -> bool:
        status = filters.get("status")
        if status and invoice.status.value != str(status):
            return False

        vendor_name = filters.get("vendor_name")
        if vendor_name and str(vendor_name).lower() not in invoice.vendor_name.lower():
            return False

        return True

    @staticmethod
    def _matches_reminder_filters(
        reminder: CancellationReminder,
        filters: Mapping[str, Any],
    ) -> bool:
        status = filters.get("status")
        if status and reminder.status.value != str(status):
            return False

        priority = filters.get("priority")
        if priority and str(priority).lower() != reminder.priority.lower():
            return False

        return True


# ---------------------------------------------------------------------------
# Subscription Tracker
# ---------------------------------------------------------------------------

class SubscriptionTracker(BaseAgent):
    """
    Tracks SaaS subscriptions, renewals, invoices, and cancellation reminders.

    Connection points:
        Master Agent:
            Use execute_task(context, task) for router-friendly action dispatch.

        Security Agent:
            Sensitive actions call _requires_security_check() and
            _request_security_approval() before continuing.

        Memory Agent:
            Useful durable subscription context is prepared with
            _prepare_memory_payload() but not directly written to memory here.

        Verification Agent:
            Every completed operation prepares a verification payload via
            _prepare_verification_payload().

        Dashboard/API:
            Public methods return structured dicts with:
            success, message, data, error, metadata.
    """

    def __init__(
        self,
        repository: Optional[InMemorySubscriptionRepository] = None,
        security_approval_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        default_currency: str = DEFAULT_CURRENCY,
        renewal_warning_days: int = DEFAULT_RENEWAL_WARNING_DAYS,
        unused_days_threshold: int = DEFAULT_UNUSED_DAYS_THRESHOLD,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(agent_name="SubscriptionTracker", agent_id="finance.subscription_tracker", **kwargs)

        self.repository = repository or InMemorySubscriptionRepository()
        self.security_approval_callback = security_approval_callback
        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.default_currency = self._normalize_currency(default_currency)
        self.renewal_warning_days = max(1, int(renewal_warning_days))
        self.unused_days_threshold = max(1, int(unused_days_threshold))
        self.logger = logger_instance or logger

    # ---------------------------------------------------------------------
    # Master Agent / Router entrypoint
    # ---------------------------------------------------------------------

    def execute_task(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        task: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Router-compatible task executor.

        Expected task format:
            {
                "action": "add_subscription",
                "payload": {...},
                "metadata": {...}
            }
        """

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result

        ctx = ctx_result["data"]["context"]

        try:
            action = str(task.get("action", "")).strip()
            payload = dict(task.get("payload") or {})

            if not action:
                return self._error_result(
                    message="Task action is required.",
                    error_code="MISSING_ACTION",
                    metadata={"supported_actions": [item.value for item in TaskAction]},
                )

            dispatch: Dict[str, Callable[..., Dict[str, Any]]] = {
                TaskAction.ADD_SUBSCRIPTION.value: self.add_subscription,
                TaskAction.UPDATE_SUBSCRIPTION.value: self.update_subscription,
                TaskAction.GET_SUBSCRIPTION.value: self.get_subscription,
                TaskAction.LIST_SUBSCRIPTIONS.value: self.list_subscriptions,
                TaskAction.DEACTIVATE_SUBSCRIPTION.value: self.deactivate_subscription,
                TaskAction.CREATE_CANCELLATION_REMINDER.value: self.create_cancellation_reminder,
                TaskAction.LIST_CANCELLATION_REMINDERS.value: self.list_cancellation_reminders,
                TaskAction.UPCOMING_RENEWALS.value: self.get_upcoming_renewals,
                TaskAction.RECORD_INVOICE.value: self.record_invoice,
                TaskAction.MARK_INVOICE_PAID.value: self.mark_invoice_paid,
                TaskAction.LIST_INVOICES.value: self.list_invoices,
                TaskAction.MONTHLY_COST.value: self.calculate_monthly_recurring_cost,
                TaskAction.ANNUAL_COST.value: self.calculate_annualized_cost,
                TaskAction.SPEND_ANALYSIS.value: self.analyze_subscription_spend,
                TaskAction.DUPLICATES.value: self.detect_duplicate_subscriptions,
                TaskAction.UNUSED_RISKY.value: self.detect_unused_or_risky_subscriptions,
                TaskAction.DASHBOARD_SUMMARY.value: self.generate_dashboard_summary,
                TaskAction.EXPORT_CSV.value: self.export_subscriptions_csv,
                TaskAction.EXPORT_JSON.value: self.export_subscriptions_json,
            }

            handler = dispatch.get(action)
            if not handler:
                return self._error_result(
                    message=f"Unsupported subscription tracker action: {action}",
                    error_code="UNSUPPORTED_ACTION",
                    metadata={"supported_actions": sorted(dispatch.keys())},
                )

            return handler(context=ctx, **payload)

        except Exception as exc:
            self.logger.exception("SubscriptionTracker execute_task failed.")
            return self._error_result(
                message="Subscription tracker task failed.",
                error_code="TASK_EXECUTION_ERROR",
                exception=exc,
            )

    # ---------------------------------------------------------------------
    # Public subscription methods
    # ---------------------------------------------------------------------

    def add_subscription(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        vendor_name: str,
        amount: Union[str, float, int, Decimal],
        billing_cycle: Union[str, BillingCycle],
        currency: Optional[str] = None,
        plan_name: Optional[str] = None,
        start_date: Optional[Union[str, date, datetime]] = None,
        next_renewal_date: Optional[Union[str, date, datetime]] = None,
        status: Union[str, SubscriptionStatus] = SubscriptionStatus.ACTIVE,
        seats: int = 1,
        category: Optional[str] = None,
        payment_method_label: Optional[str] = None,
        owner_name: Optional[str] = None,
        owner_email: Optional[str] = None,
        website_url: Optional[str] = None,
        notes: Optional[str] = None,
        tags: Optional[Iterable[str]] = None,
        last_used_at: Optional[Union[str, date, datetime]] = None,
        auto_renew: bool = True,
        cancellation_url: Optional[str] = None,
        contract_end_date: Optional[Union[str, date, datetime]] = None,
        custom_cycle_days: Optional[int] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Add a SaaS subscription record."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            vendor_name = self._clean_required_text(vendor_name, "vendor_name")
            amount_dec = self._parse_money(amount)
            cycle = self._parse_billing_cycle(billing_cycle)
            status_enum = self._parse_subscription_status(status)

            if amount_dec < Decimal("0"):
                return self._error_result(
                    message="Subscription amount cannot be negative.",
                    error_code="INVALID_AMOUNT",
                )

            if int(seats) < 1:
                return self._error_result(
                    message="Seats must be at least 1.",
                    error_code="INVALID_SEATS",
                )

            if cycle == BillingCycle.CUSTOM and not custom_cycle_days:
                return self._error_result(
                    message="custom_cycle_days is required when billing_cycle is custom.",
                    error_code="CUSTOM_CYCLE_DAYS_REQUIRED",
                )

            if custom_cycle_days is not None and int(custom_cycle_days) < 1:
                return self._error_result(
                    message="custom_cycle_days must be at least 1.",
                    error_code="INVALID_CUSTOM_CYCLE_DAYS",
                )

            parsed_start = self._parse_optional_date(start_date)
            parsed_next_renewal = self._parse_optional_date(next_renewal_date)
            parsed_last_used = self._parse_optional_date(last_used_at)
            parsed_contract_end = self._parse_optional_date(contract_end_date)

            if not parsed_next_renewal and parsed_start:
                parsed_next_renewal = self._calculate_next_renewal_date(
                    from_date=parsed_start,
                    billing_cycle=cycle,
                    custom_cycle_days=custom_cycle_days,
                )

            subscription = SubscriptionRecord(
                subscription_id=self._new_id("sub"),
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
                vendor_name=vendor_name,
                plan_name=self._clean_optional_text(plan_name),
                amount=self._quantize_money(amount_dec),
                currency=self._normalize_currency(currency or self.default_currency),
                billing_cycle=cycle,
                start_date=parsed_start,
                next_renewal_date=parsed_next_renewal,
                status=status_enum,
                seats=int(seats),
                category=self._clean_optional_text(category),
                payment_method_label=self._clean_optional_text(payment_method_label),
                owner_name=self._clean_optional_text(owner_name),
                owner_email=self._clean_optional_text(owner_email),
                website_url=self._clean_optional_text(website_url),
                notes=self._clean_optional_text(notes),
                tags=self._normalize_tags(tags),
                last_used_at=parsed_last_used,
                auto_renew=bool(auto_renew),
                cancellation_url=self._clean_optional_text(cancellation_url),
                contract_end_date=parsed_contract_end,
                custom_cycle_days=int(custom_cycle_days) if custom_cycle_days else None,
                metadata=dict(metadata or {}),
            )

            saved = self.repository.save_subscription(subscription)

            audit_payload = self._log_audit_event(
                context=ctx,
                action="subscription.added",
                resource_id=saved.subscription_id,
                details={
                    "vendor_name": saved.vendor_name,
                    "amount": str(saved.amount),
                    "currency": saved.currency,
                    "billing_cycle": saved.billing_cycle.value,
                    "status": saved.status.value,
                },
            )

            event_payload = self._emit_agent_event(
                context=ctx,
                event_name="finance.subscription.added",
                payload={
                    "subscription_id": saved.subscription_id,
                    "vendor_name": saved.vendor_name,
                    "next_renewal_date": self._date_to_iso(saved.next_renewal_date),
                },
            )

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                action="add_subscription",
                resource_type="subscription",
                resource_id=saved.subscription_id,
                before=None,
                after=self._subscription_to_dict(saved),
            )

            memory_payload = self._prepare_memory_payload(
                context=ctx,
                memory_type="finance_subscription",
                importance="medium",
                summary=f"Added SaaS subscription for {saved.vendor_name}.",
                data=self._subscription_to_dict(saved),
            )

            return self._safe_result(
                success=True,
                message="Subscription added successfully.",
                data={"subscription": self._subscription_to_dict(saved)},
                metadata={
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "audit_payload": audit_payload,
                    "event_payload": event_payload,
                },
            )

        except ValueError as exc:
            return self._error_result(
                message=str(exc),
                error_code="VALIDATION_ERROR",
                exception=exc,
            )
        except Exception as exc:
            self.logger.exception("Failed to add subscription.")
            return self._error_result(
                message="Failed to add subscription.",
                error_code="ADD_SUBSCRIPTION_ERROR",
                exception=exc,
            )

    def update_subscription(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        subscription_id: str,
        updates: Optional[Mapping[str, Any]] = None,
        **direct_updates: Any,
    ) -> Dict[str, Any]:
        """Update an existing subscription record safely."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            subscription_id = self._clean_required_text(subscription_id, "subscription_id")
            existing = self.repository.get_subscription(subscription_id, ctx.user_id, ctx.workspace_id)

            if not existing:
                return self._error_result(
                    message="Subscription not found for this user/workspace.",
                    error_code="SUBSCRIPTION_NOT_FOUND",
                )

            update_data: Dict[str, Any] = {}
            update_data.update(dict(updates or {}))
            update_data.update(direct_updates)

            if not update_data:
                return self._error_result(
                    message="No update fields provided.",
                    error_code="NO_UPDATES",
                )

            sensitive = self._requires_security_check(
                action="update_subscription",
                payload=update_data,
                current_record=self._subscription_to_dict(existing),
            )
            if sensitive:
                approval = self._request_security_approval(
                    context=ctx,
                    action="update_subscription",
                    payload={
                        "subscription_id": subscription_id,
                        "updates": self._json_safe(update_data),
                    },
                )
                if not approval.get("approved", False):
                    return self._error_result(
                        message="Security approval required before updating sensitive subscription fields.",
                        error_code="SECURITY_APPROVAL_REQUIRED",
                        metadata={"security_approval": approval},
                    )

            before = self._subscription_to_dict(existing)
            updated = self._apply_subscription_updates(existing, update_data)
            updated.updated_at = datetime.now(timezone.utc)

            saved = self.repository.save_subscription(updated)

            audit_payload = self._log_audit_event(
                context=ctx,
                action="subscription.updated",
                resource_id=saved.subscription_id,
                details={
                    "updated_fields": sorted(update_data.keys()),
                    "vendor_name": saved.vendor_name,
                },
            )

            event_payload = self._emit_agent_event(
                context=ctx,
                event_name="finance.subscription.updated",
                payload={
                    "subscription_id": saved.subscription_id,
                    "updated_fields": sorted(update_data.keys()),
                },
            )

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                action="update_subscription",
                resource_type="subscription",
                resource_id=saved.subscription_id,
                before=before,
                after=self._subscription_to_dict(saved),
            )

            memory_payload = self._prepare_memory_payload(
                context=ctx,
                memory_type="finance_subscription_update",
                importance="medium",
                summary=f"Updated SaaS subscription for {saved.vendor_name}.",
                data={
                    "subscription_id": saved.subscription_id,
                    "updated_fields": sorted(update_data.keys()),
                    "subscription": self._subscription_to_dict(saved),
                },
            )

            return self._safe_result(
                success=True,
                message="Subscription updated successfully.",
                data={"subscription": self._subscription_to_dict(saved)},
                metadata={
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "audit_payload": audit_payload,
                    "event_payload": event_payload,
                },
            )

        except ValueError as exc:
            return self._error_result(
                message=str(exc),
                error_code="VALIDATION_ERROR",
                exception=exc,
            )
        except Exception as exc:
            self.logger.exception("Failed to update subscription.")
            return self._error_result(
                message="Failed to update subscription.",
                error_code="UPDATE_SUBSCRIPTION_ERROR",
                exception=exc,
            )

    def get_subscription(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        subscription_id: str,
    ) -> Dict[str, Any]:
        """Get one subscription by ID with strict user/workspace isolation."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            subscription_id = self._clean_required_text(subscription_id, "subscription_id")
            record = self.repository.get_subscription(subscription_id, ctx.user_id, ctx.workspace_id)

            if not record:
                return self._error_result(
                    message="Subscription not found for this user/workspace.",
                    error_code="SUBSCRIPTION_NOT_FOUND",
                )

            invoices = self.repository.list_invoices(
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
                subscription_id=subscription_id,
            )
            reminders = self.repository.list_reminders(
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
                subscription_id=subscription_id,
            )

            data = self._subscription_to_dict(record)
            data["invoices"] = [self._invoice_to_dict(item) for item in invoices]
            data["cancellation_reminders"] = [self._reminder_to_dict(item) for item in reminders]
            data["renewal_risk"] = self._calculate_renewal_risk(record).value

            return self._safe_result(
                success=True,
                message="Subscription retrieved successfully.",
                data={"subscription": data},
                metadata={"count": 1},
            )

        except Exception as exc:
            self.logger.exception("Failed to get subscription.")
            return self._error_result(
                message="Failed to get subscription.",
                error_code="GET_SUBSCRIPTION_ERROR",
                exception=exc,
            )

    def list_subscriptions(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        filters: Optional[Mapping[str, Any]] = None,
        include_inactive: bool = True,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """List subscriptions for the current user/workspace."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            effective_filters = dict(filters or {})
            records = self.repository.list_subscriptions(
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
                filters=effective_filters,
            )

            if not include_inactive:
                records = [
                    item for item in records
                    if item.status in {
                        SubscriptionStatus.ACTIVE,
                        SubscriptionStatus.TRIAL,
                        SubscriptionStatus.PAUSED,
                        SubscriptionStatus.PENDING_CANCEL,
                    }
                ]

            total = len(records)
            offset = max(0, int(offset))
            if limit is not None:
                limit = max(0, int(limit))
                records = records[offset: offset + limit]
            elif offset:
                records = records[offset:]

            return self._safe_result(
                success=True,
                message="Subscriptions listed successfully.",
                data={
                    "subscriptions": [self._subscription_to_dict(item) for item in records],
                },
                metadata={
                    "total": total,
                    "returned": len(records),
                    "offset": offset,
                    "limit": limit,
                    "filters": effective_filters,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to list subscriptions.")
            return self._error_result(
                message="Failed to list subscriptions.",
                error_code="LIST_SUBSCRIPTIONS_ERROR",
                exception=exc,
            )

    def deactivate_subscription(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        subscription_id: str,
        reason: Optional[str] = None,
        status: Union[str, SubscriptionStatus] = SubscriptionStatus.CANCELLED,
    ) -> Dict[str, Any]:
        """
        Mark a subscription as cancelled/expired/paused.

        This does NOT cancel the real provider subscription. It only updates
        William/Jarvis internal tracking status.
        """

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            new_status = self._parse_subscription_status(status)
            if new_status not in {
                SubscriptionStatus.CANCELLED,
                SubscriptionStatus.EXPIRED,
                SubscriptionStatus.PAUSED,
                SubscriptionStatus.PENDING_CANCEL,
            }:
                return self._error_result(
                    message="Deactivate status must be cancelled, expired, paused, or pending_cancel.",
                    error_code="INVALID_DEACTIVATE_STATUS",
                )

            approval = self._request_security_approval(
                context=ctx,
                action="deactivate_subscription",
                payload={
                    "subscription_id": subscription_id,
                    "new_status": new_status.value,
                    "reason": reason,
                    "note": "Internal tracking only. No real provider cancellation is performed.",
                },
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval required before deactivating subscription tracking.",
                    error_code="SECURITY_APPROVAL_REQUIRED",
                    metadata={"security_approval": approval},
                )

            return self.update_subscription(
                context=ctx,
                subscription_id=subscription_id,
                updates={
                    "status": new_status.value,
                    "auto_renew": False if new_status in {SubscriptionStatus.CANCELLED, SubscriptionStatus.EXPIRED} else None,
                    "notes": self._append_note(None, f"Deactivation reason: {reason or 'Not provided'}"),
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to deactivate subscription.")
            return self._error_result(
                message="Failed to deactivate subscription.",
                error_code="DEACTIVATE_SUBSCRIPTION_ERROR",
                exception=exc,
            )

    # ---------------------------------------------------------------------
    # Cancellation reminders
    # ---------------------------------------------------------------------

    def create_cancellation_reminder(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        subscription_id: str,
        remind_on: Union[str, date, datetime],
        reason: Optional[str] = None,
        priority: str = "normal",
        assigned_to: Optional[str] = None,
        notes: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a cancellation reminder.

        This creates a reminder only; it does not cancel the provider account.
        """

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            subscription_id = self._clean_required_text(subscription_id, "subscription_id")
            subscription = self.repository.get_subscription(subscription_id, ctx.user_id, ctx.workspace_id)

            if not subscription:
                return self._error_result(
                    message="Subscription not found for this user/workspace.",
                    error_code="SUBSCRIPTION_NOT_FOUND",
                )

            parsed_remind_on = self._parse_required_date(remind_on, "remind_on")
            priority = self._clean_optional_text(priority) or "normal"

            approval = self._request_security_approval(
                context=ctx,
                action="create_cancellation_reminder",
                payload={
                    "subscription_id": subscription_id,
                    "vendor_name": subscription.vendor_name,
                    "remind_on": parsed_remind_on.isoformat(),
                    "reason": reason,
                    "note": "Reminder only. No real cancellation is performed.",
                },
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval required before creating cancellation reminder.",
                    error_code="SECURITY_APPROVAL_REQUIRED",
                    metadata={"security_approval": approval},
                )

            reminder = CancellationReminder(
                reminder_id=self._new_id("rem"),
                subscription_id=subscription.subscription_id,
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
                vendor_name=subscription.vendor_name,
                remind_on=parsed_remind_on,
                reason=self._clean_optional_text(reason),
                priority=priority,
                assigned_to=self._clean_optional_text(assigned_to),
                notes=self._clean_optional_text(notes),
                metadata=dict(metadata or {}),
            )

            saved_reminder = self.repository.save_reminder(reminder)

            subscription.reminder_ids.append(saved_reminder.reminder_id)
            subscription.status = (
                SubscriptionStatus.PENDING_CANCEL
                if subscription.status in {SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL}
                else subscription.status
            )
            subscription.updated_at = datetime.now(timezone.utc)
            self.repository.save_subscription(subscription)

            audit_payload = self._log_audit_event(
                context=ctx,
                action="subscription.cancellation_reminder.created",
                resource_id=saved_reminder.reminder_id,
                details={
                    "subscription_id": subscription.subscription_id,
                    "vendor_name": subscription.vendor_name,
                    "remind_on": saved_reminder.remind_on.isoformat(),
                    "priority": saved_reminder.priority,
                },
            )

            event_payload = self._emit_agent_event(
                context=ctx,
                event_name="finance.subscription.cancellation_reminder.created",
                payload=self._reminder_to_dict(saved_reminder),
            )

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                action="create_cancellation_reminder",
                resource_type="cancellation_reminder",
                resource_id=saved_reminder.reminder_id,
                before=None,
                after=self._reminder_to_dict(saved_reminder),
            )

            memory_payload = self._prepare_memory_payload(
                context=ctx,
                memory_type="finance_cancellation_reminder",
                importance="high",
                summary=f"Cancellation reminder created for {subscription.vendor_name}.",
                data=self._reminder_to_dict(saved_reminder),
            )

            return self._safe_result(
                success=True,
                message="Cancellation reminder created successfully. No real subscription cancellation was performed.",
                data={
                    "reminder": self._reminder_to_dict(saved_reminder),
                    "subscription": self._subscription_to_dict(subscription),
                },
                metadata={
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "audit_payload": audit_payload,
                    "event_payload": event_payload,
                    "security_approval": approval,
                },
            )

        except ValueError as exc:
            return self._error_result(
                message=str(exc),
                error_code="VALIDATION_ERROR",
                exception=exc,
            )
        except Exception as exc:
            self.logger.exception("Failed to create cancellation reminder.")
            return self._error_result(
                message="Failed to create cancellation reminder.",
                error_code="CREATE_CANCELLATION_REMINDER_ERROR",
                exception=exc,
            )

    def list_cancellation_reminders(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        subscription_id: Optional[str] = None,
        filters: Optional[Mapping[str, Any]] = None,
        due_within_days: Optional[int] = None,
    ) -> Dict[str, Any]:
        """List cancellation reminders for user/workspace."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            reminders = self.repository.list_reminders(
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
                subscription_id=subscription_id,
                filters=filters,
            )

            if due_within_days is not None:
                cutoff = date.today() + timedelta(days=max(0, int(due_within_days)))
                reminders = [item for item in reminders if item.remind_on <= cutoff]

            return self._safe_result(
                success=True,
                message="Cancellation reminders listed successfully.",
                data={"reminders": [self._reminder_to_dict(item) for item in reminders]},
                metadata={"count": len(reminders)},
            )

        except Exception as exc:
            self.logger.exception("Failed to list cancellation reminders.")
            return self._error_result(
                message="Failed to list cancellation reminders.",
                error_code="LIST_CANCELLATION_REMINDERS_ERROR",
                exception=exc,
            )

    # ---------------------------------------------------------------------
    # Renewal tracking
    # ---------------------------------------------------------------------

    def get_upcoming_renewals(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        within_days: Optional[int] = None,
        include_auto_renew_only: bool = False,
        include_trials: bool = True,
    ) -> Dict[str, Any]:
        """Return subscriptions renewing soon."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            days = self.renewal_warning_days if within_days is None else max(0, int(within_days))
            today = date.today()
            cutoff = today + timedelta(days=days)

            records = self.repository.list_subscriptions(
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
            )

            eligible_statuses = {SubscriptionStatus.ACTIVE, SubscriptionStatus.PENDING_CANCEL, SubscriptionStatus.PAUSED}
            if include_trials:
                eligible_statuses.add(SubscriptionStatus.TRIAL)

            upcoming: List[Dict[str, Any]] = []
            for record in records:
                if record.status not in eligible_statuses:
                    continue
                if include_auto_renew_only and not record.auto_renew:
                    continue
                if not record.next_renewal_date:
                    continue
                if today <= record.next_renewal_date <= cutoff:
                    item = self._subscription_to_dict(record)
                    item["days_until_renewal"] = (record.next_renewal_date - today).days
                    item["renewal_risk"] = self._calculate_renewal_risk(record).value
                    item["monthly_equivalent"] = str(self._monthly_equivalent(record))
                    upcoming.append(item)

            upcoming.sort(key=lambda item: item["days_until_renewal"])

            return self._safe_result(
                success=True,
                message="Upcoming renewals retrieved successfully.",
                data={"upcoming_renewals": upcoming},
                metadata={
                    "count": len(upcoming),
                    "within_days": days,
                    "from_date": today.isoformat(),
                    "to_date": cutoff.isoformat(),
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to get upcoming renewals.")
            return self._error_result(
                message="Failed to get upcoming renewals.",
                error_code="UPCOMING_RENEWALS_ERROR",
                exception=exc,
            )

    # ---------------------------------------------------------------------
    # Invoice tracking
    # ---------------------------------------------------------------------

    def record_invoice(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        subscription_id: str,
        amount: Union[str, float, int, Decimal],
        invoice_number: Optional[str] = None,
        currency: Optional[str] = None,
        invoice_date: Optional[Union[str, date, datetime]] = None,
        due_date: Optional[Union[str, date, datetime]] = None,
        paid_date: Optional[Union[str, date, datetime]] = None,
        status: Union[str, InvoiceStatus] = InvoiceStatus.DUE,
        file_ref: Optional[str] = None,
        notes: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record a subscription invoice for tracking only."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            subscription_id = self._clean_required_text(subscription_id, "subscription_id")
            subscription = self.repository.get_subscription(subscription_id, ctx.user_id, ctx.workspace_id)

            if not subscription:
                return self._error_result(
                    message="Subscription not found for this user/workspace.",
                    error_code="SUBSCRIPTION_NOT_FOUND",
                )

            amount_dec = self._parse_money(amount)
            if amount_dec < Decimal("0"):
                return self._error_result(
                    message="Invoice amount cannot be negative.",
                    error_code="INVALID_AMOUNT",
                )

            status_enum = self._parse_invoice_status(status)
            parsed_invoice_date = self._parse_optional_date(invoice_date) or date.today()
            parsed_due_date = self._parse_optional_date(due_date)
            parsed_paid_date = self._parse_optional_date(paid_date)

            if parsed_paid_date and status_enum == InvoiceStatus.DUE:
                status_enum = InvoiceStatus.PAID

            invoice = SubscriptionInvoice(
                invoice_id=self._new_id("inv"),
                subscription_id=subscription.subscription_id,
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
                vendor_name=subscription.vendor_name,
                invoice_number=self._clean_optional_text(invoice_number),
                amount=self._quantize_money(amount_dec),
                currency=self._normalize_currency(currency or subscription.currency),
                invoice_date=parsed_invoice_date,
                due_date=parsed_due_date,
                paid_date=parsed_paid_date,
                status=status_enum,
                file_ref=self._clean_optional_text(file_ref),
                notes=self._clean_optional_text(notes),
                metadata=dict(metadata or {}),
            )

            saved_invoice = self.repository.save_invoice(invoice)

            subscription.invoice_ids.append(saved_invoice.invoice_id)
            subscription.updated_at = datetime.now(timezone.utc)
            self.repository.save_subscription(subscription)

            audit_payload = self._log_audit_event(
                context=ctx,
                action="subscription.invoice.recorded",
                resource_id=saved_invoice.invoice_id,
                details={
                    "subscription_id": subscription.subscription_id,
                    "vendor_name": subscription.vendor_name,
                    "amount": str(saved_invoice.amount),
                    "currency": saved_invoice.currency,
                    "status": saved_invoice.status.value,
                },
            )

            event_payload = self._emit_agent_event(
                context=ctx,
                event_name="finance.subscription.invoice.recorded",
                payload=self._invoice_to_dict(saved_invoice),
            )

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                action="record_invoice",
                resource_type="subscription_invoice",
                resource_id=saved_invoice.invoice_id,
                before=None,
                after=self._invoice_to_dict(saved_invoice),
            )

            memory_payload = self._prepare_memory_payload(
                context=ctx,
                memory_type="finance_subscription_invoice",
                importance="medium",
                summary=f"Recorded invoice for {subscription.vendor_name}.",
                data=self._invoice_to_dict(saved_invoice),
            )

            return self._safe_result(
                success=True,
                message="Subscription invoice recorded successfully.",
                data={
                    "invoice": self._invoice_to_dict(saved_invoice),
                    "subscription": self._subscription_to_dict(subscription),
                },
                metadata={
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "audit_payload": audit_payload,
                    "event_payload": event_payload,
                },
            )

        except ValueError as exc:
            return self._error_result(
                message=str(exc),
                error_code="VALIDATION_ERROR",
                exception=exc,
            )
        except Exception as exc:
            self.logger.exception("Failed to record subscription invoice.")
            return self._error_result(
                message="Failed to record subscription invoice.",
                error_code="RECORD_INVOICE_ERROR",
                exception=exc,
            )

    def mark_invoice_paid(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        invoice_id: str,
        paid_date: Optional[Union[str, date, datetime]] = None,
        notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Mark a tracked invoice as paid.

        This does not execute any real payment.
        """

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            invoice_id = self._clean_required_text(invoice_id, "invoice_id")
            invoice = self.repository.get_invoice(invoice_id, ctx.user_id, ctx.workspace_id)

            if not invoice:
                return self._error_result(
                    message="Invoice not found for this user/workspace.",
                    error_code="INVOICE_NOT_FOUND",
                )

            before = self._invoice_to_dict(invoice)
            invoice.status = InvoiceStatus.PAID
            invoice.paid_date = self._parse_optional_date(paid_date) or date.today()
            if notes:
                invoice.notes = self._append_note(invoice.notes, notes)
            invoice.updated_at = datetime.now(timezone.utc)

            saved = self.repository.save_invoice(invoice)

            audit_payload = self._log_audit_event(
                context=ctx,
                action="subscription.invoice.marked_paid",
                resource_id=saved.invoice_id,
                details={
                    "subscription_id": saved.subscription_id,
                    "vendor_name": saved.vendor_name,
                    "paid_date": self._date_to_iso(saved.paid_date),
                },
            )

            event_payload = self._emit_agent_event(
                context=ctx,
                event_name="finance.subscription.invoice.marked_paid",
                payload=self._invoice_to_dict(saved),
            )

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                action="mark_invoice_paid",
                resource_type="subscription_invoice",
                resource_id=saved.invoice_id,
                before=before,
                after=self._invoice_to_dict(saved),
            )

            return self._safe_result(
                success=True,
                message="Invoice marked as paid for tracking only. No real payment was executed.",
                data={"invoice": self._invoice_to_dict(saved)},
                metadata={
                    "verification_payload": verification_payload,
                    "audit_payload": audit_payload,
                    "event_payload": event_payload,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to mark invoice paid.")
            return self._error_result(
                message="Failed to mark invoice paid.",
                error_code="MARK_INVOICE_PAID_ERROR",
                exception=exc,
            )

    def list_invoices(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        subscription_id: Optional[str] = None,
        filters: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """List tracked invoices for user/workspace."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            invoices = self.repository.list_invoices(
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
                subscription_id=subscription_id,
                filters=filters,
            )

            today = date.today()
            normalized: List[Dict[str, Any]] = []
            for invoice in invoices:
                if invoice.status == InvoiceStatus.DUE and invoice.due_date and invoice.due_date < today:
                    invoice.status = InvoiceStatus.OVERDUE
                normalized.append(self._invoice_to_dict(invoice))

            return self._safe_result(
                success=True,
                message="Subscription invoices listed successfully.",
                data={"invoices": normalized},
                metadata={"count": len(normalized)},
            )

        except Exception as exc:
            self.logger.exception("Failed to list invoices.")
            return self._error_result(
                message="Failed to list invoices.",
                error_code="LIST_INVOICES_ERROR",
                exception=exc,
            )

    # ---------------------------------------------------------------------
    # Spend calculations / analytics
    # ---------------------------------------------------------------------

    def calculate_monthly_recurring_cost(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        filters: Optional[Mapping[str, Any]] = None,
        active_only: bool = True,
    ) -> Dict[str, Any]:
        """Calculate monthly recurring subscription cost."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            records = self.repository.list_subscriptions(
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
                filters=filters,
            )

            if active_only:
                records = [item for item in records if item.status in {SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL}]

            totals_by_currency: Dict[str, Decimal] = {}
            items: List[Dict[str, Any]] = []

            for record in records:
                monthly = self._monthly_equivalent(record)
                totals_by_currency[record.currency] = totals_by_currency.get(record.currency, Decimal("0")) + monthly
                items.append({
                    "subscription_id": record.subscription_id,
                    "vendor_name": record.vendor_name,
                    "billing_cycle": record.billing_cycle.value,
                    "amount": str(record.amount),
                    "currency": record.currency,
                    "monthly_equivalent": str(monthly),
                })

            totals = {
                currency: str(self._quantize_money(amount))
                for currency, amount in sorted(totals_by_currency.items())
            }

            return self._safe_result(
                success=True,
                message="Monthly recurring cost calculated successfully.",
                data={
                    "totals_by_currency": totals,
                    "items": items,
                },
                metadata={
                    "count": len(records),
                    "active_only": active_only,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to calculate monthly recurring cost.")
            return self._error_result(
                message="Failed to calculate monthly recurring cost.",
                error_code="MONTHLY_RECURRING_COST_ERROR",
                exception=exc,
            )

    def calculate_annualized_cost(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        filters: Optional[Mapping[str, Any]] = None,
        active_only: bool = True,
    ) -> Dict[str, Any]:
        """Calculate annualized subscription cost."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            records = self.repository.list_subscriptions(
                user_id=ctx.user_id,
                workspace_id=ctx.workspace_id,
                filters=filters,
            )

            if active_only:
                records = [item for item in records if item.status in {SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL}]

            totals_by_currency: Dict[str, Decimal] = {}
            items: List[Dict[str, Any]] = []

            for record in records:
                annual = self._annual_equivalent(record)
                totals_by_currency[record.currency] = totals_by_currency.get(record.currency, Decimal("0")) + annual
                items.append({
                    "subscription_id": record.subscription_id,
                    "vendor_name": record.vendor_name,
                    "billing_cycle": record.billing_cycle.value,
                    "amount": str(record.amount),
                    "currency": record.currency,
                    "annualized_equivalent": str(annual),
                })

            totals = {
                currency: str(self._quantize_money(amount))
                for currency, amount in sorted(totals_by_currency.items())
            }

            return self._safe_result(
                success=True,
                message="Annualized subscription cost calculated successfully.",
                data={
                    "totals_by_currency": totals,
                    "items": items,
                },
                metadata={
                    "count": len(records),
                    "active_only": active_only,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to calculate annualized cost.")
            return self._error_result(
                message="Failed to calculate annualized subscription cost.",
                error_code="ANNUALIZED_COST_ERROR",
                exception=exc,
            )

    def analyze_subscription_spend(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        active_only: bool = True,
    ) -> Dict[str, Any]:
        """Analyze subscription spend by vendor, category, status, and billing cycle."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            records = self.repository.list_subscriptions(ctx.user_id, ctx.workspace_id)

            if active_only:
                records = [item for item in records if item.status in {SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL}]

            by_currency: Dict[str, Dict[str, Decimal]] = {}
            by_category: Dict[str, Dict[str, Decimal]] = {}
            by_cycle: Dict[str, Dict[str, Decimal]] = {}
            by_status: Dict[str, int] = {}
            highest_monthly: List[Dict[str, Any]] = []

            for record in records:
                monthly = self._monthly_equivalent(record)
                category = record.category or "uncategorized"

                by_currency.setdefault(record.currency, {})
                by_currency[record.currency]["monthly"] = by_currency[record.currency].get("monthly", Decimal("0")) + monthly
                by_currency[record.currency]["annualized"] = by_currency[record.currency].get("annualized", Decimal("0")) + self._annual_equivalent(record)

                by_category.setdefault(category, {})
                by_category[category][record.currency] = by_category[category].get(record.currency, Decimal("0")) + monthly

                cycle_key = record.billing_cycle.value
                by_cycle.setdefault(cycle_key, {})
                by_cycle[cycle_key][record.currency] = by_cycle[cycle_key].get(record.currency, Decimal("0")) + monthly

                by_status[record.status.value] = by_status.get(record.status.value, 0) + 1

                highest_monthly.append({
                    "subscription_id": record.subscription_id,
                    "vendor_name": record.vendor_name,
                    "plan_name": record.plan_name,
                    "currency": record.currency,
                    "monthly_equivalent": str(monthly),
                    "annualized_equivalent": str(self._annual_equivalent(record)),
                    "renewal_risk": self._calculate_renewal_risk(record).value,
                })

            highest_monthly.sort(
                key=lambda item: Decimal(item["monthly_equivalent"]),
                reverse=True,
            )

            analysis = {
                "subscription_count": len(records),
                "totals_by_currency": {
                    currency: {
                        key: str(self._quantize_money(value))
                        for key, value in totals.items()
                    }
                    for currency, totals in sorted(by_currency.items())
                },
                "monthly_by_category": {
                    category: {
                        currency: str(self._quantize_money(value))
                        for currency, value in sorted(totals.items())
                    }
                    for category, totals in sorted(by_category.items())
                },
                "monthly_by_billing_cycle": {
                    cycle: {
                        currency: str(self._quantize_money(value))
                        for currency, value in sorted(totals.items())
                    }
                    for cycle, totals in sorted(by_cycle.items())
                },
                "count_by_status": dict(sorted(by_status.items())),
                "highest_monthly_costs": highest_monthly[:10],
            }

            return self._safe_result(
                success=True,
                message="Subscription spend analyzed successfully.",
                data={"analysis": analysis},
                metadata={"active_only": active_only},
            )

        except Exception as exc:
            self.logger.exception("Failed to analyze subscription spend.")
            return self._error_result(
                message="Failed to analyze subscription spend.",
                error_code="SUBSCRIPTION_SPEND_ANALYSIS_ERROR",
                exception=exc,
            )

    def detect_duplicate_subscriptions(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        strict_vendor_match: bool = False,
    ) -> Dict[str, Any]:
        """Detect possible duplicate SaaS subscriptions by vendor/category/domain."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            records = self.repository.list_subscriptions(ctx.user_id, ctx.workspace_id)
            active_records = [
                item for item in records
                if item.status in {SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL, SubscriptionStatus.PAUSED}
            ]

            groups: Dict[str, List[SubscriptionRecord]] = {}
            for record in active_records:
                key = self._duplicate_key(record, strict_vendor_match=strict_vendor_match)
                groups.setdefault(key, []).append(record)

            duplicates: List[Dict[str, Any]] = []
            for key, group in groups.items():
                if len(group) < 2:
                    continue

                duplicates.append({
                    "duplicate_key": key,
                    "count": len(group),
                    "subscriptions": [self._subscription_to_dict(item) for item in group],
                    "monthly_total_by_currency": self._monthly_total_for_records(group),
                })

            duplicates.sort(key=lambda item: item["count"], reverse=True)

            return self._safe_result(
                success=True,
                message="Duplicate subscription detection completed.",
                data={"duplicates": duplicates},
                metadata={
                    "duplicate_group_count": len(duplicates),
                    "strict_vendor_match": strict_vendor_match,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to detect duplicate subscriptions.")
            return self._error_result(
                message="Failed to detect duplicate subscriptions.",
                error_code="DUPLICATE_DETECTION_ERROR",
                exception=exc,
            )

    def detect_unused_or_risky_subscriptions(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        unused_days_threshold: Optional[int] = None,
        renewal_days: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Detect subscriptions that appear unused, risky, or renewal-sensitive."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            unused_threshold = (
                self.unused_days_threshold
                if unused_days_threshold is None
                else max(1, int(unused_days_threshold))
            )
            renewal_window = (
                self.renewal_warning_days
                if renewal_days is None
                else max(0, int(renewal_days))
            )

            today = date.today()
            records = self.repository.list_subscriptions(ctx.user_id, ctx.workspace_id)
            active_records = [
                item for item in records
                if item.status in {SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL, SubscriptionStatus.PAUSED, SubscriptionStatus.PENDING_CANCEL}
            ]

            risky: List[Dict[str, Any]] = []
            for record in active_records:
                reasons: List[str] = []

                if record.last_used_at:
                    unused_days = (today - record.last_used_at).days
                    if unused_days >= unused_threshold:
                        reasons.append(f"Not used for {unused_days} days.")
                elif record.status == SubscriptionStatus.ACTIVE:
                    reasons.append("No last_used_at date available.")

                if record.next_renewal_date:
                    days_until = (record.next_renewal_date - today).days
                    if 0 <= days_until <= renewal_window:
                        reasons.append(f"Renews in {days_until} days.")
                    elif days_until < 0:
                        reasons.append(f"Renewal date passed {abs(days_until)} days ago.")

                if record.status == SubscriptionStatus.PENDING_CANCEL:
                    reasons.append("Marked pending cancellation.")

                if record.auto_renew and self._annual_equivalent(record) >= Decimal("1000"):
                    reasons.append("High annualized auto-renew cost.")

                risk = self._calculate_renewal_risk(record)

                if reasons or risk != RenewalRisk.LOW:
                    item = self._subscription_to_dict(record)
                    item["risk"] = risk.value
                    item["risk_reasons"] = reasons
                    item["monthly_equivalent"] = str(self._monthly_equivalent(record))
                    item["annualized_equivalent"] = str(self._annual_equivalent(record))
                    risky.append(item)

            risk_order = {RenewalRisk.HIGH.value: 0, RenewalRisk.MEDIUM.value: 1, RenewalRisk.LOW.value: 2}
            risky.sort(key=lambda item: (risk_order.get(item["risk"], 99), item.get("next_renewal_date") or "9999-12-31"))

            return self._safe_result(
                success=True,
                message="Unused/risky subscription detection completed.",
                data={"subscriptions": risky},
                metadata={
                    "count": len(risky),
                    "unused_days_threshold": unused_threshold,
                    "renewal_days": renewal_window,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to detect unused or risky subscriptions.")
            return self._error_result(
                message="Failed to detect unused or risky subscriptions.",
                error_code="UNUSED_RISKY_DETECTION_ERROR",
                exception=exc,
            )

    def generate_dashboard_summary(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Generate dashboard-ready subscription summary."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            records = self.repository.list_subscriptions(ctx.user_id, ctx.workspace_id)
            invoices = self.repository.list_invoices(ctx.user_id, ctx.workspace_id)
            reminders = self.repository.list_reminders(ctx.user_id, ctx.workspace_id)

            active = [item for item in records if item.status in {SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIAL}]
            upcoming_result = self.get_upcoming_renewals(context=ctx, within_days=self.renewal_warning_days)
            risky_result = self.detect_unused_or_risky_subscriptions(context=ctx)

            monthly_totals = self._monthly_total_for_records(active)
            annual_totals = self._annual_total_for_records(active)

            today = date.today()
            open_reminders = [
                item for item in reminders
                if item.status in {ReminderStatus.OPEN, ReminderStatus.SNOOZED}
            ]
            due_reminders = [
                item for item in open_reminders
                if item.remind_on <= today
            ]

            overdue_invoices = [
                item for item in invoices
                if item.status in {InvoiceStatus.DUE, InvoiceStatus.OVERDUE}
                and item.due_date
                and item.due_date < today
            ]

            summary = {
                "subscription_count": len(records),
                "active_subscription_count": len(active),
                "monthly_recurring_cost_by_currency": monthly_totals,
                "annualized_cost_by_currency": annual_totals,
                "upcoming_renewal_count": len(upcoming_result.get("data", {}).get("upcoming_renewals", [])),
                "risky_subscription_count": len(risky_result.get("data", {}).get("subscriptions", [])),
                "open_cancellation_reminder_count": len(open_reminders),
                "due_cancellation_reminder_count": len(due_reminders),
                "overdue_invoice_count": len(overdue_invoices),
                "status_breakdown": self._status_breakdown(records),
                "billing_cycle_breakdown": self._billing_cycle_breakdown(records),
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

            return self._safe_result(
                success=True,
                message="Subscription dashboard summary generated successfully.",
                data={
                    "summary": summary,
                    "upcoming_renewals": upcoming_result.get("data", {}).get("upcoming_renewals", []),
                    "risky_subscriptions": risky_result.get("data", {}).get("subscriptions", [])[:10],
                    "due_cancellation_reminders": [self._reminder_to_dict(item) for item in due_reminders],
                    "overdue_invoices": [self._invoice_to_dict(item) for item in overdue_invoices],
                },
                metadata={"dashboard_ready": True},
            )

        except Exception as exc:
            self.logger.exception("Failed to generate dashboard summary.")
            return self._error_result(
                message="Failed to generate dashboard summary.",
                error_code="DASHBOARD_SUMMARY_ERROR",
                exception=exc,
            )

    # ---------------------------------------------------------------------
    # Export methods
    # ---------------------------------------------------------------------

    def export_subscriptions_csv(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        filters: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Export subscriptions as CSV string for API/dashboard download."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            records = self.repository.list_subscriptions(ctx.user_id, ctx.workspace_id, filters=filters)

            fieldnames = [
                "subscription_id",
                "vendor_name",
                "plan_name",
                "amount",
                "currency",
                "billing_cycle",
                "monthly_equivalent",
                "annualized_equivalent",
                "status",
                "seats",
                "category",
                "owner_name",
                "owner_email",
                "next_renewal_date",
                "auto_renew",
                "last_used_at",
                "tags",
            ]

            buffer = io.StringIO()
            writer = csv.DictWriter(buffer, fieldnames=fieldnames)
            writer.writeheader()

            for record in records:
                writer.writerow({
                    "subscription_id": record.subscription_id,
                    "vendor_name": record.vendor_name,
                    "plan_name": record.plan_name or "",
                    "amount": str(record.amount),
                    "currency": record.currency,
                    "billing_cycle": record.billing_cycle.value,
                    "monthly_equivalent": str(self._monthly_equivalent(record)),
                    "annualized_equivalent": str(self._annual_equivalent(record)),
                    "status": record.status.value,
                    "seats": record.seats,
                    "category": record.category or "",
                    "owner_name": record.owner_name or "",
                    "owner_email": record.owner_email or "",
                    "next_renewal_date": self._date_to_iso(record.next_renewal_date) or "",
                    "auto_renew": record.auto_renew,
                    "last_used_at": self._date_to_iso(record.last_used_at) or "",
                    "tags": ",".join(record.tags),
                })

            csv_content = buffer.getvalue()
            filename = f"subscriptions_{ctx.workspace_id}_{date.today().isoformat()}.csv"

            audit_payload = self._log_audit_event(
                context=ctx,
                action="subscription.export.csv",
                resource_id=ctx.workspace_id,
                details={"count": len(records), "filename": filename},
            )

            return self._safe_result(
                success=True,
                message="Subscriptions exported as CSV successfully.",
                data={
                    "filename": filename,
                    "content_type": "text/csv",
                    "csv": csv_content,
                },
                metadata={
                    "count": len(records),
                    "audit_payload": audit_payload,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to export subscriptions CSV.")
            return self._error_result(
                message="Failed to export subscriptions as CSV.",
                error_code="EXPORT_CSV_ERROR",
                exception=exc,
            )

    def export_subscriptions_json(
        self,
        context: Union[SaaSContext, Mapping[str, Any]],
        filters: Optional[Mapping[str, Any]] = None,
        pretty: bool = True,
    ) -> Dict[str, Any]:
        """Export subscriptions as JSON string for API/dashboard download."""

        ctx_result = self._validate_task_context(context)
        if not ctx_result["success"]:
            return ctx_result
        ctx: SaaSContext = ctx_result["data"]["context"]

        try:
            records = self.repository.list_subscriptions(ctx.user_id, ctx.workspace_id, filters=filters)
            payload = {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "exported_at": datetime.now(timezone.utc).isoformat(),
                "count": len(records),
                "subscriptions": [self._subscription_to_dict(item) for item in records],
            }

            json_content = json.dumps(
                payload,
                indent=2 if pretty else None,
                sort_keys=True,
                default=str,
            )
            filename = f"subscriptions_{ctx.workspace_id}_{date.today().isoformat()}.json"

            audit_payload = self._log_audit_event(
                context=ctx,
                action="subscription.export.json",
                resource_id=ctx.workspace_id,
                details={"count": len(records), "filename": filename},
            )

            return self._safe_result(
                success=True,
                message="Subscriptions exported as JSON successfully.",
                data={
                    "filename": filename,
                    "content_type": "application/json",
                    "json": json_content,
                },
                metadata={
                    "count": len(records),
                    "audit_payload": audit_payload,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to export subscriptions JSON.")
            return self._error_result(
                message="Failed to export subscriptions as JSON.",
                error_code="EXPORT_JSON_ERROR",
                exception=exc,
            )

    # ---------------------------------------------------------------------
    # Required compatibility hooks
    # ---------------------------------------------------------------------

    def _validate_task_context(
        self,
        context: Union[SaaSContext, Mapping[str, Any], None],
    ) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Required by William/Jarvis global rules.
        """

        try:
            if context is None:
                return self._error_result(
                    message="Task context is required.",
                    error_code="MISSING_CONTEXT",
                )

            if isinstance(context, SaaSContext):
                ctx = context
            elif isinstance(context, Mapping):
                ctx = SaaSContext(
                    user_id=str(context.get("user_id") or "").strip(),
                    workspace_id=str(context.get("workspace_id") or "").strip(),
                    role=self._clean_optional_text(context.get("role")),
                    request_id=str(context.get("request_id") or uuid.uuid4()),
                    actor_id=self._clean_optional_text(context.get("actor_id")),
                    session_id=self._clean_optional_text(context.get("session_id")),
                    ip_address=self._clean_optional_text(context.get("ip_address")),
                    user_agent=self._clean_optional_text(context.get("user_agent")),
                    metadata=dict(context.get("metadata") or {}),
                )
            else:
                return self._error_result(
                    message="Task context must be a SaaSContext or mapping.",
                    error_code="INVALID_CONTEXT_TYPE",
                )

            if not ctx.user_id or ctx.user_id.lower() in {"none", "null", "undefined"}:
                return self._error_result(
                    message="user_id is required for SaaS isolation.",
                    error_code="MISSING_USER_ID",
                )

            if not ctx.workspace_id or ctx.workspace_id.lower() in {"none", "null", "undefined"}:
                return self._error_result(
                    message="workspace_id is required for SaaS isolation.",
                    error_code="MISSING_WORKSPACE_ID",
                )

            return self._safe_result(
                success=True,
                message="Task context validated.",
                data={"context": ctx},
                metadata={"request_id": ctx.request_id},
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to validate task context.",
                error_code="CONTEXT_VALIDATION_ERROR",
                exception=exc,
            )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
        current_record: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Decide whether a Finance Agent action needs Security Agent approval.

        Sensitive examples:
            - Status changes to cancelled/pending_cancel.
            - Amount increases.
            - Payment method label updates.
            - Cancellation reminder creation.
            - Any field that could affect financial tracking/audit meaning.
        """

        payload = dict(payload or {})
        action = str(action)

        always_sensitive = {
            "deactivate_subscription",
            "create_cancellation_reminder",
        }
        if action in always_sensitive:
            return True

        sensitive_fields = {
            "amount",
            "currency",
            "billing_cycle",
            "payment_method_label",
            "status",
            "auto_renew",
            "next_renewal_date",
            "contract_end_date",
            "cancellation_url",
        }

        if any(field in payload and payload.get(field) is not None for field in sensitive_fields):
            return True

        if current_record and "amount" in payload:
            try:
                old_amount = self._parse_money(current_record.get("amount", "0"))
                new_amount = self._parse_money(payload.get("amount", "0"))
                if new_amount > old_amount:
                    return True
            except Exception:
                return True

        return False

    def _request_security_approval(
        self,
        context: SaaSContext,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        In this standalone file, approval is safely simulated unless a callback
        is injected. Production Security Agent can be wired through
        security_approval_callback.
        """

        approval_request = {
            "approval_id": self._new_id("sec"),
            "agent": self.__class__.__name__,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "payload": self._json_safe(dict(payload or {})),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "safety_note": "Finance subscription tracking only; no real payment/cancellation action executed.",
        }

        if self.security_approval_callback:
            try:
                response = self.security_approval_callback(approval_request)
                if isinstance(response, Mapping):
                    merged = dict(approval_request)
                    merged.update(dict(response))
                    merged["approved"] = bool(merged.get("approved", False))
                    return merged
            except Exception as exc:
                self.logger.exception("Security approval callback failed.")
                return {
                    **approval_request,
                    "approved": False,
                    "error": str(exc),
                    "mode": "callback_error",
                }

        safe_auto_approve_actions = {
            "create_cancellation_reminder",
            "deactivate_subscription",
            "update_subscription",
        }

        return {
            **approval_request,
            "approved": action in safe_auto_approve_actions,
            "mode": "local_safe_default",
            "note": "No Security Agent callback configured. Local safe default used for internal tracking-only action.",
        }

    def _prepare_verification_payload(
        self,
        context: SaaSContext,
        action: str,
        resource_type: str,
        resource_id: str,
        before: Optional[Mapping[str, Any]],
        after: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        This file does not directly call Verification Agent to remain import-safe.
        """

        return {
            "verification_id": self._new_id("ver"),
            "source_agent": self.__class__.__name__,
            "module": "Finance Agent",
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "before": self._json_safe(before),
            "after": self._json_safe(after),
            "requires_human_review": action in {
                "deactivate_subscription",
                "create_cancellation_reminder",
            },
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def _prepare_memory_payload(
        self,
        context: SaaSContext,
        memory_type: str,
        importance: str,
        summary: str,
        data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        This payload can be handed to Memory Agent by Finance Agent or Master Agent.
        """

        return {
            "memory_id": self._new_id("mem"),
            "source_agent": self.__class__.__name__,
            "memory_type": memory_type,
            "importance": importance,
            "summary": summary,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "data": self._json_safe(dict(data)),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "ttl_policy": "workspace_finance_context",
        }

    def _emit_agent_event(
        self,
        context: SaaSContext,
        event_name: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit an agent event for dashboards, analytics, task history, or registry.

        Uses an injected event callback when available.
        """

        event = {
            "event_id": self._new_id("evt"),
            "event_name": event_name,
            "agent": self.__class__.__name__,
            "module": "Finance Agent",
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "payload": self._json_safe(dict(payload or {})),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        if self.event_callback:
            try:
                self.event_callback(event)
            except Exception:
                self.logger.exception("Agent event callback failed.")

        return event

    def _log_audit_event(
        self,
        context: SaaSContext,
        action: str,
        resource_id: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log an audit event.

        This returns an audit payload and optionally sends it to audit_callback.
        """

        audit = {
            "audit_id": self._new_id("aud"),
            "action": action,
            "agent": self.__class__.__name__,
            "module": "Finance Agent",
            "resource_id": resource_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "actor_id": context.actor_id,
            "role": context.role,
            "request_id": context.request_id,
            "session_id": context.session_id,
            "ip_address": context.ip_address,
            "details": self._json_safe(dict(details or {})),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        if self.audit_callback:
            try:
                self.audit_callback(audit)
            except Exception:
                self.logger.exception("Audit callback failed.")

        return audit

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        error: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis structured result."""

        return {
            "success": bool(success),
            "message": str(message),
            "data": self._json_safe(dict(data or {})),
            "error": self._json_safe(dict(error or {})) if error else None,
            "metadata": self._json_safe(dict(metadata or {})),
        }

    def _error_result(
        self,
        message: str,
        error_code: str = "ERROR",
        exception: Optional[BaseException] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis structured error result."""

        error = {
            "code": error_code,
            "message": str(message),
        }
        if exception is not None:
            error["exception_type"] = exception.__class__.__name__
            error["exception_message"] = str(exception)

        return self._safe_result(
            success=False,
            message=message,
            data={},
            error=error,
            metadata=metadata or {},
        )

    # ---------------------------------------------------------------------
    # Internal update helpers
    # ---------------------------------------------------------------------

    def _apply_subscription_updates(
        self,
        record: SubscriptionRecord,
        updates: Mapping[str, Any],
    ) -> SubscriptionRecord:
        """Validate and apply subscription updates."""

        updated = copy.deepcopy(record)

        allowed_fields = {
            "vendor_name",
            "plan_name",
            "amount",
            "currency",
            "billing_cycle",
            "start_date",
            "next_renewal_date",
            "status",
            "seats",
            "category",
            "payment_method_label",
            "owner_name",
            "owner_email",
            "website_url",
            "notes",
            "tags",
            "last_used_at",
            "auto_renew",
            "cancellation_url",
            "contract_end_date",
            "custom_cycle_days",
            "metadata",
        }

        unknown = set(updates.keys()) - allowed_fields
        if unknown:
            raise ValueError(f"Unsupported update fields: {sorted(unknown)}")

        for key, value in updates.items():
            if value is None:
                continue

            if key == "vendor_name":
                updated.vendor_name = self._clean_required_text(value, "vendor_name")
            elif key == "plan_name":
                updated.plan_name = self._clean_optional_text(value)
            elif key == "amount":
                amount = self._parse_money(value)
                if amount < Decimal("0"):
                    raise ValueError("Subscription amount cannot be negative.")
                updated.amount = self._quantize_money(amount)
            elif key == "currency":
                updated.currency = self._normalize_currency(value)
            elif key == "billing_cycle":
                updated.billing_cycle = self._parse_billing_cycle(value)
            elif key == "start_date":
                updated.start_date = self._parse_optional_date(value)
            elif key == "next_renewal_date":
                updated.next_renewal_date = self._parse_optional_date(value)
            elif key == "status":
                updated.status = self._parse_subscription_status(value)
            elif key == "seats":
                seats = int(value)
                if seats < 1:
                    raise ValueError("Seats must be at least 1.")
                updated.seats = seats
            elif key == "category":
                updated.category = self._clean_optional_text(value)
            elif key == "payment_method_label":
                updated.payment_method_label = self._clean_optional_text(value)
            elif key == "owner_name":
                updated.owner_name = self._clean_optional_text(value)
            elif key == "owner_email":
                updated.owner_email = self._clean_optional_text(value)
            elif key == "website_url":
                updated.website_url = self._clean_optional_text(value)
            elif key == "notes":
                updated.notes = self._clean_optional_text(value)
            elif key == "tags":
                updated.tags = self._normalize_tags(value)
            elif key == "last_used_at":
                updated.last_used_at = self._parse_optional_date(value)
            elif key == "auto_renew":
                updated.auto_renew = bool(value)
            elif key == "cancellation_url":
                updated.cancellation_url = self._clean_optional_text(value)
            elif key == "contract_end_date":
                updated.contract_end_date = self._parse_optional_date(value)
            elif key == "custom_cycle_days":
                days = int(value)
                if days < 1:
                    raise ValueError("custom_cycle_days must be at least 1.")
                updated.custom_cycle_days = days
            elif key == "metadata":
                if not isinstance(value, Mapping):
                    raise ValueError("metadata must be a mapping.")
                updated.metadata.update(dict(value))

        if updated.billing_cycle == BillingCycle.CUSTOM and not updated.custom_cycle_days:
            raise ValueError("custom_cycle_days is required when billing_cycle is custom.")

        return updated

    # ---------------------------------------------------------------------
    # Internal calculations
    # ---------------------------------------------------------------------

    def _monthly_equivalent(self, record: SubscriptionRecord) -> Decimal:
        """Convert subscription amount to monthly equivalent."""

        amount = record.amount

        if record.billing_cycle == BillingCycle.DAILY:
            return self._quantize_money(amount * Decimal("30.4375"))
        if record.billing_cycle == BillingCycle.WEEKLY:
            return self._quantize_money(amount * Decimal("4.34524"))
        if record.billing_cycle == BillingCycle.MONTHLY:
            return self._quantize_money(amount)
        if record.billing_cycle == BillingCycle.QUARTERLY:
            return self._quantize_money(amount / Decimal("3"))
        if record.billing_cycle == BillingCycle.SEMI_ANNUAL:
            return self._quantize_money(amount / Decimal("6"))
        if record.billing_cycle == BillingCycle.ANNUAL:
            return self._quantize_money(amount / Decimal("12"))
        if record.billing_cycle == BillingCycle.CUSTOM:
            days = Decimal(str(record.custom_cycle_days or 30))
            return self._quantize_money((amount / days) * Decimal("30.4375"))

        return self._quantize_money(amount)

    def _annual_equivalent(self, record: SubscriptionRecord) -> Decimal:
        """Convert subscription amount to annualized equivalent."""

        return self._quantize_money(self._monthly_equivalent(record) * Decimal("12"))

    def _monthly_total_for_records(self, records: Iterable[SubscriptionRecord]) -> Dict[str, str]:
        """Monthly totals by currency for records."""

        totals: Dict[str, Decimal] = {}
        for record in records:
            totals[record.currency] = totals.get(record.currency, Decimal("0")) + self._monthly_equivalent(record)
        return {
            currency: str(self._quantize_money(amount))
            for currency, amount in sorted(totals.items())
        }

    def _annual_total_for_records(self, records: Iterable[SubscriptionRecord]) -> Dict[str, str]:
        """Annual totals by currency for records."""

        totals: Dict[str, Decimal] = {}
        for record in records:
            totals[record.currency] = totals.get(record.currency, Decimal("0")) + self._annual_equivalent(record)
        return {
            currency: str(self._quantize_money(amount))
            for currency, amount in sorted(totals.items())
        }

    def _calculate_next_renewal_date(
        self,
        from_date: date,
        billing_cycle: BillingCycle,
        custom_cycle_days: Optional[int] = None,
    ) -> date:
        """Calculate next renewal date from a start date."""

        if billing_cycle == BillingCycle.DAILY:
            return from_date + timedelta(days=1)
        if billing_cycle == BillingCycle.WEEKLY:
            return from_date + timedelta(days=7)
        if billing_cycle == BillingCycle.MONTHLY:
            return self._add_months(from_date, 1)
        if billing_cycle == BillingCycle.QUARTERLY:
            return self._add_months(from_date, 3)
        if billing_cycle == BillingCycle.SEMI_ANNUAL:
            return self._add_months(from_date, 6)
        if billing_cycle == BillingCycle.ANNUAL:
            return self._add_months(from_date, 12)
        if billing_cycle == BillingCycle.CUSTOM:
            return from_date + timedelta(days=int(custom_cycle_days or 30))
        return self._add_months(from_date, 1)

    def _calculate_renewal_risk(self, record: SubscriptionRecord) -> RenewalRisk:
        """Calculate simple renewal risk level."""

        today = date.today()
        score = 0

        if record.status == SubscriptionStatus.PENDING_CANCEL:
            score += 4
        if record.status == SubscriptionStatus.TRIAL:
            score += 1
        if record.auto_renew:
            score += 1
        if record.next_renewal_date:
            days_until = (record.next_renewal_date - today).days
            if days_until < 0:
                score += 4
            elif days_until <= 3:
                score += 4
            elif days_until <= self.renewal_warning_days:
                score += 2
        if record.last_used_at:
            unused_days = (today - record.last_used_at).days
            if unused_days >= self.unused_days_threshold:
                score += 2
        else:
            score += 1
        if self._annual_equivalent(record) >= Decimal("1000"):
            score += 2

        if score >= 5:
            return RenewalRisk.HIGH
        if score >= 2:
            return RenewalRisk.MEDIUM
        return RenewalRisk.LOW

    def _duplicate_key(self, record: SubscriptionRecord, strict_vendor_match: bool = False) -> str:
        """Build duplicate detection key."""

        vendor = self._normalize_key(record.vendor_name)
        if strict_vendor_match:
            return f"vendor:{vendor}"

        domain = self._domain_from_url(record.website_url)
        if domain:
            return f"domain:{domain}"

        category = self._normalize_key(record.category or "uncategorized")
        plan = self._normalize_key(record.plan_name or "")
        return f"vendor_category:{vendor}:{category}:{plan}"

    def _status_breakdown(self, records: Iterable[SubscriptionRecord]) -> Dict[str, int]:
        """Count subscriptions by status."""

        output: Dict[str, int] = {}
        for record in records:
            output[record.status.value] = output.get(record.status.value, 0) + 1
        return dict(sorted(output.items()))

    def _billing_cycle_breakdown(self, records: Iterable[SubscriptionRecord]) -> Dict[str, int]:
        """Count subscriptions by billing cycle."""

        output: Dict[str, int] = {}
        for record in records:
            output[record.billing_cycle.value] = output.get(record.billing_cycle.value, 0) + 1
        return dict(sorted(output.items()))

    # ---------------------------------------------------------------------
    # Parsing / serialization helpers
    # ---------------------------------------------------------------------

    def _subscription_to_dict(self, record: SubscriptionRecord) -> Dict[str, Any]:
        """Serialize subscription record safely."""

        data = asdict(record)
        data["amount"] = str(record.amount)
        data["billing_cycle"] = record.billing_cycle.value
        data["status"] = record.status.value
        data["start_date"] = self._date_to_iso(record.start_date)
        data["next_renewal_date"] = self._date_to_iso(record.next_renewal_date)
        data["last_used_at"] = self._date_to_iso(record.last_used_at)
        data["contract_end_date"] = self._date_to_iso(record.contract_end_date)
        data["created_at"] = record.created_at.isoformat()
        data["updated_at"] = record.updated_at.isoformat()
        return self._json_safe(data)

    def _invoice_to_dict(self, invoice: SubscriptionInvoice) -> Dict[str, Any]:
        """Serialize invoice safely."""

        data = asdict(invoice)
        data["amount"] = str(invoice.amount)
        data["status"] = invoice.status.value
        data["invoice_date"] = self._date_to_iso(invoice.invoice_date)
        data["due_date"] = self._date_to_iso(invoice.due_date)
        data["paid_date"] = self._date_to_iso(invoice.paid_date)
        data["created_at"] = invoice.created_at.isoformat()
        data["updated_at"] = invoice.updated_at.isoformat()
        return self._json_safe(data)

    def _reminder_to_dict(self, reminder: CancellationReminder) -> Dict[str, Any]:
        """Serialize cancellation reminder safely."""

        data = asdict(reminder)
        data["status"] = reminder.status.value
        data["remind_on"] = reminder.remind_on.isoformat()
        data["created_at"] = reminder.created_at.isoformat()
        data["updated_at"] = reminder.updated_at.isoformat()
        return self._json_safe(data)

    def _parse_billing_cycle(self, value: Union[str, BillingCycle]) -> BillingCycle:
        """Parse billing cycle enum."""

        if isinstance(value, BillingCycle):
            return value
        normalized = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        try:
            return BillingCycle(normalized)
        except ValueError as exc:
            allowed = [item.value for item in BillingCycle]
            raise ValueError(f"Invalid billing_cycle '{value}'. Allowed: {allowed}") from exc

    def _parse_subscription_status(self, value: Union[str, SubscriptionStatus]) -> SubscriptionStatus:
        """Parse subscription status enum."""

        if isinstance(value, SubscriptionStatus):
            return value
        normalized = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        try:
            return SubscriptionStatus(normalized)
        except ValueError as exc:
            allowed = [item.value for item in SubscriptionStatus]
            raise ValueError(f"Invalid subscription status '{value}'. Allowed: {allowed}") from exc

    def _parse_invoice_status(self, value: Union[str, InvoiceStatus]) -> InvoiceStatus:
        """Parse invoice status enum."""

        if isinstance(value, InvoiceStatus):
            return value
        normalized = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        try:
            return InvoiceStatus(normalized)
        except ValueError as exc:
            allowed = [item.value for item in InvoiceStatus]
            raise ValueError(f"Invalid invoice status '{value}'. Allowed: {allowed}") from exc

    def _parse_money(self, value: Union[str, float, int, Decimal, None]) -> Decimal:
        """Parse money safely using Decimal."""

        if value is None:
            raise ValueError("Money amount is required.")

        try:
            if isinstance(value, Decimal):
                amount = value
            elif isinstance(value, float):
                if math.isnan(value) or math.isinf(value):
                    raise ValueError("Money amount cannot be NaN or infinite.")
                amount = Decimal(str(value))
            else:
                cleaned = str(value).strip().replace(",", "")
                if not cleaned:
                    raise ValueError("Money amount cannot be empty.")
                amount = Decimal(cleaned)
            return self._quantize_money(amount)
        except (InvalidOperation, ValueError) as exc:
            raise ValueError(f"Invalid money amount: {value}") from exc

    def _quantize_money(self, value: Decimal) -> Decimal:
        """Round money to two decimals."""

        return value.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

    def _parse_optional_date(
        self,
        value: Optional[Union[str, date, datetime]],
    ) -> Optional[date]:
        """Parse optional date value."""

        if value is None or value == "":
            return None
        return self._parse_required_date(value, "date")

    def _parse_required_date(
        self,
        value: Union[str, date, datetime],
        field_name: str,
    ) -> date:
        """Parse required date value."""

        if isinstance(value, datetime):
            return value.date()
        if isinstance(value, date):
            return value

        raw = str(value).strip()
        if not raw:
            raise ValueError(f"{field_name} cannot be empty.")

        try:
            return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
        except ValueError:
            try:
                return datetime.strptime(raw, "%Y-%m-%d").date()
            except ValueError as exc:
                raise ValueError(f"{field_name} must be ISO date format YYYY-MM-DD.") from exc

    def _date_to_iso(self, value: Optional[date]) -> Optional[str]:
        """Convert date to ISO string."""

        return value.isoformat() if value else None

    def _normalize_currency(self, value: Any) -> str:
        """Normalize currency code."""

        currency = str(value or self.default_currency).strip().upper()
        if not currency:
            currency = DEFAULT_CURRENCY
        if len(currency) > 10:
            raise ValueError("Currency code is too long.")
        return currency

    def _clean_required_text(self, value: Any, field_name: str) -> str:
        """Clean required text."""

        text = str(value or "").strip()
        if not text:
            raise ValueError(f"{field_name} is required.")
        return text

    def _clean_optional_text(self, value: Any) -> Optional[str]:
        """Clean optional text."""

        if value is None:
            return None
        text = str(value).strip()
        return text or None

    def _normalize_tags(self, tags: Optional[Iterable[str]]) -> List[str]:
        """Normalize tags."""

        if not tags:
            return []

        output: List[str] = []
        seen = set()
        for tag in tags:
            cleaned = str(tag).strip()
            if not cleaned:
                continue
            key = cleaned.lower()
            if key in seen:
                continue
            seen.add(key)
            output.append(cleaned)
        return output

    def _append_note(self, existing: Optional[str], note: Optional[str]) -> Optional[str]:
        """Append note with timestamp."""

        if not note:
            return existing
        stamp = datetime.now(timezone.utc).isoformat()
        addition = f"[{stamp}] {note}"
        if existing:
            return f"{existing}\n{addition}"
        return addition

    def _new_id(self, prefix: str) -> str:
        """Generate stable prefixed ID."""

        return f"{prefix}_{uuid.uuid4().hex}"

    def _add_months(self, source_date: date, months: int) -> date:
        """Add months to date without external dependencies."""

        month = source_date.month - 1 + months
        year = source_date.year + month // 12
        month = month % 12 + 1
        day = min(source_date.day, self._days_in_month(year, month))
        return date(year, month, day)

    def _days_in_month(self, year: int, month: int) -> int:
        """Return days in month."""

        if month == 12:
            next_month = date(year + 1, 1, 1)
        else:
            next_month = date(year, month + 1, 1)
        this_month = date(year, month, 1)
        return (next_month - this_month).days

    def _normalize_key(self, value: str) -> str:
        """Normalize string for grouping keys."""

        return " ".join(str(value or "").strip().lower().split())

    def _domain_from_url(self, url: Optional[str]) -> Optional[str]:
        """Extract simple domain from URL without external imports."""

        if not url:
            return None

        raw = str(url).strip().lower()
        if not raw:
            return None

        raw = raw.replace("https://", "").replace("http://", "")
        raw = raw.split("/")[0]
        raw = raw.split("?")[0]
        raw = raw.split("#")[0]

        if raw.startswith("www."):
            raw = raw[4:]

        return raw or None

    def _json_safe(self, value: Any) -> Any:
        """Convert dataclasses/enums/Decimal/datetime/date to JSON-safe structures."""

        if value is None:
            return None
        if isinstance(value, Decimal):
            return str(value)
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        if isinstance(value, Mapping):
            return {str(key): self._json_safe(val) for key, val in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [self._json_safe(item) for item in value]
        if hasattr(value, "__dataclass_fields__"):
            return self._json_safe(asdict(value))
        return value


__all__ = [
    "AGENT_METADATA",
    "BillingCycle",
    "CancellationReminder",
    "InMemorySubscriptionRepository",
    "InvoiceStatus",
    "ReminderStatus",
    "RenewalRisk",
    "SaaSContext",
    "SubscriptionInvoice",
    "SubscriptionRecord",
    "SubscriptionStatus",
    "SubscriptionTracker",
    "TaskAction",
]