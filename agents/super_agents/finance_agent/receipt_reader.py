"""
agents/super_agents/finance_agent/finance_reports.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Revenue, expenses, cash flow, profit/loss, and subscription reports for the
    Finance Agent.

Architecture Compatibility:
    - Master Agent routing
    - BaseAgent compatibility
    - Agent Registry / Agent Loader compatibility
    - Security Agent approval workflow
    - Verification Agent payload preparation
    - Memory Agent payload preparation
    - Dashboard / FastAPI structured responses
    - SaaS user/workspace isolation
    - Audit logging and event emission

Safety:
    This module only prepares and analyzes financial report data.
    It does not submit payments, execute transfers, modify accounts, contact banks,
    send emails, or perform destructive financial actions.

Public Class:
    FinanceReports
"""

from __future__ import annotations

import csv
import io
import json
import logging
import math
import statistics
import uuid
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe even when the full William/Jarvis
        framework has not been generated yet.
        """

        agent_name: str = "base_agent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_id = kwargs.get("agent_id", self.__class__.__name__)
            self.logger = logging.getLogger(self.__class__.__name__)


try:
    from agents.super_agents.finance_agent.config import FinanceReportConfig  # type: ignore
except Exception:  # pragma: no cover
    FinanceReportConfig = None  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MONEY_QUANT = Decimal("0.01")
DEFAULT_CURRENCY = "USD"

SAFE_EXPORT_FORMATS = {"json", "csv"}
SUPPORTED_REPORT_TYPES = {
    "revenue",
    "expenses",
    "cash_flow",
    "profit_loss",
    "subscriptions",
    "dashboard_summary",
    "combined",
}

SENSITIVE_REPORT_TYPES = {
    "profit_loss",
    "cash_flow",
    "combined",
}

ALLOWED_PERIODS = {
    "daily",
    "weekly",
    "monthly",
    "quarterly",
    "yearly",
    "custom",
}


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FinanceReportType(str, Enum):
    """Supported finance report types."""

    REVENUE = "revenue"
    EXPENSES = "expenses"
    CASH_FLOW = "cash_flow"
    PROFIT_LOSS = "profit_loss"
    SUBSCRIPTIONS = "subscriptions"
    DASHBOARD_SUMMARY = "dashboard_summary"
    COMBINED = "combined"


class ReportPeriod(str, Enum):
    """Supported report grouping periods."""

    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"
    CUSTOM = "custom"


class TransactionKind(str, Enum):
    """Normalized transaction kinds."""

    REVENUE = "revenue"
    EXPENSE = "expense"
    REFUND = "refund"
    CREDIT = "credit"
    ADJUSTMENT = "adjustment"


class SubscriptionStatus(str, Enum):
    """Subscription status values used by subscription reports."""

    ACTIVE = "active"
    TRIALING = "trialing"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    PAUSED = "paused"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class FinanceContext:
    """
    SaaS execution context.

    Every report must be scoped to both user_id and workspace_id to prevent
    cross-user or cross-workspace leakage.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = "finance_reports"
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReportRequest:
    """Normalized report request model."""

    report_type: str
    start_date: Optional[date] = None
    end_date: Optional[date] = None
    period: str = ReportPeriod.MONTHLY.value
    currency: str = DEFAULT_CURRENCY
    include_forecast: bool = False
    include_sensitive_breakdown: bool = False
    export_format: Optional[str] = None
    filters: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedTransaction:
    """
    Normalized transaction record.

    This model intentionally accepts already-provided transaction data and does
    not fetch from banks or processors directly.
    """

    transaction_id: str
    user_id: str
    workspace_id: str
    kind: str
    amount: Decimal
    currency: str
    occurred_at: datetime
    category: str = "uncategorized"
    source: str = "manual"
    client_id: Optional[str] = None
    invoice_id: Optional[str] = None
    subscription_id: Optional[str] = None
    description: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NormalizedSubscription:
    """Normalized subscription record for MRR/ARR/churn reporting."""

    subscription_id: str
    user_id: str
    workspace_id: str
    customer_id: Optional[str]
    plan_name: str
    status: str
    amount: Decimal
    currency: str
    billing_interval: str = "monthly"
    started_at: Optional[datetime] = None
    current_period_start: Optional[datetime] = None
    current_period_end: Optional[datetime] = None
    canceled_at: Optional[datetime] = None
    trial_end: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReportSummary:
    """Common report summary structure."""

    total_revenue: Decimal = Decimal("0.00")
    total_expenses: Decimal = Decimal("0.00")
    gross_profit: Decimal = Decimal("0.00")
    net_cash_flow: Decimal = Decimal("0.00")
    profit_margin_percent: Decimal = Decimal("0.00")
    revenue_count: int = 0
    expense_count: int = 0
    currency: str = DEFAULT_CURRENCY


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _to_decimal(value: Any, default: Decimal = Decimal("0.00")) -> Decimal:
    """Safely convert common numeric inputs to Decimal."""
    if value is None:
        return default

    if isinstance(value, Decimal):
        return value.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

    try:
        return Decimal(str(value)).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError, TypeError):
        return default


def _decimal_to_float(value: Any) -> Any:
    """Convert Decimal values recursively for JSON-safe output."""
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, list):
        return [_decimal_to_float(item) for item in value]
    if isinstance(value, tuple):
        return [_decimal_to_float(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _decimal_to_float(val) for key, val in value.items()}
    return value


def _parse_datetime(value: Any) -> Optional[datetime]:
    """Parse date/datetime-like values safely."""
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)

    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None

        try:
            if cleaned.endswith("Z"):
                cleaned = cleaned[:-1] + "+00:00"
            parsed = datetime.fromisoformat(cleaned)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
        except ValueError:
            pass

        for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y", "%Y/%m/%d"):
            try:
                parsed = datetime.strptime(cleaned, fmt)
                return parsed.replace(tzinfo=timezone.utc)
            except ValueError:
                continue

    return None


def _parse_date(value: Any) -> Optional[date]:
    parsed = _parse_datetime(value)
    return parsed.date() if parsed else None


def _safe_percent(numerator: Decimal, denominator: Decimal) -> Decimal:
    if denominator == Decimal("0.00"):
        return Decimal("0.00")
    return ((numerator / denominator) * Decimal("100")).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)


def _normalize_currency(value: Any) -> str:
    if not value:
        return DEFAULT_CURRENCY
    currency = str(value).strip().upper()
    if len(currency) != 3 or not currency.isalpha():
        return DEFAULT_CURRENCY
    return currency


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _period_key(dt: datetime, period: str) -> str:
    """Return a stable period bucket key."""
    if period == ReportPeriod.DAILY.value:
        return dt.strftime("%Y-%m-%d")

    if period == ReportPeriod.WEEKLY.value:
        iso_year, iso_week, _ = dt.isocalendar()
        return f"{iso_year}-W{iso_week:02d}"

    if period == ReportPeriod.MONTHLY.value:
        return dt.strftime("%Y-%m")

    if period == ReportPeriod.QUARTERLY.value:
        quarter = math.ceil(dt.month / 3)
        return f"{dt.year}-Q{quarter}"

    if period == ReportPeriod.YEARLY.value:
        return str(dt.year)

    return "custom"


def _sanitize_text(value: Any, max_length: int = 500) -> str:
    if value is None:
        return ""
    text = str(value).replace("\x00", "").strip()
    return text[:max_length]


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class FinanceReports(BaseAgent):
    """
    Finance reporting helper for William/Jarvis Finance Agent.

    Responsibilities:
        - Build revenue reports.
        - Build expense reports.
        - Build cash flow reports.
        - Build profit/loss reports.
        - Build subscription reports.
        - Build combined finance dashboards.
        - Prepare verification, memory, audit, and dashboard-compatible payloads.

    Non-responsibilities:
        - No real payment submission.
        - No bank action.
        - No fund transfer.
        - No destructive update.
        - No external system execution unless injected by the hosting app and guarded.

    Master Agent:
        The Master Agent can route report-generation tasks here using the
        `run()` or `generate_report()` method.

    Security Agent:
        Sensitive reports can require approval through `_request_security_approval()`.

    Memory Agent:
        Useful recurring finance report preferences can be prepared using
        `_prepare_memory_payload()`.

    Verification Agent:
        Completed reports expose a verification payload using
        `_prepare_verification_payload()`.
    """

    agent_name = "finance_reports"
    agent_type = "finance_agent_helper"
    registry_name = "FinanceReports"
    version = "1.0.0"

    def __init__(
        self,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        config: Optional[Any] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.audit_logger = audit_logger
        self.event_emitter = event_emitter
        self.config = config or self._load_default_config()
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    # ------------------------------------------------------------------
    # Public Master Agent / Router interfaces
    # ------------------------------------------------------------------

    def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Router-compatible entrypoint.

        Expected task shape:
            {
                "user_id": "...",
                "workspace_id": "...",
                "report_type": "profit_loss",
                "transactions": [...],
                "subscriptions": [...],
                "start_date": "2026-01-01",
                "end_date": "2026-01-31",
                "period": "monthly",
                "currency": "USD",
                "include_forecast": false,
                "include_sensitive_breakdown": false
            }
        """
        try:
            context = self._context_from_task(task)
            request = self._request_from_task(task)
            transactions = task.get("transactions") or []
            subscriptions = task.get("subscriptions") or []

            return self.generate_report(
                context=context,
                request=request,
                transactions=transactions,
                subscriptions=subscriptions,
            )
        except Exception as exc:
            self.logger.exception("FinanceReports.run failed")
            return self._error_result(
                message="Failed to run finance report task.",
                error=exc,
                metadata={"agent": self.agent_name},
            )

    def generate_report(
        self,
        context: Union[FinanceContext, Mapping[str, Any]],
        request: Union[ReportRequest, Mapping[str, Any]],
        transactions: Optional[Sequence[Mapping[str, Any]]] = None,
        subscriptions: Optional[Sequence[Mapping[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Generate any supported finance report with SaaS isolation.

        This is the main public method for API/dashboard/Master Agent usage.
        """
        try:
            ctx = self._ensure_context(context)
            req = self._ensure_request(request)

            context_validation = self._validate_task_context(ctx)
            if not context_validation["success"]:
                return context_validation

            security_required = self._requires_security_check(ctx, req)
            if security_required:
                approval = self._request_security_approval(ctx, req)
                if not approval.get("approved", False):
                    return self._safe_result(
                        success=False,
                        message="Security approval is required before generating this finance report.",
                        data={
                            "approval_required": True,
                            "approval_status": approval,
                        },
                        metadata=self._base_metadata(ctx, req),
                    )

            normalized_transactions = self._normalize_transactions(
                transactions or [],
                ctx,
                req.currency,
            )
            normalized_subscriptions = self._normalize_subscriptions(
                subscriptions or [],
                ctx,
                req.currency,
            )

            scoped_transactions = self._filter_transactions(
                transactions=normalized_transactions,
                context=ctx,
                request=req,
            )
            scoped_subscriptions = self._filter_subscriptions(
                subscriptions=normalized_subscriptions,
                context=ctx,
                request=req,
            )

            if req.report_type == FinanceReportType.REVENUE.value:
                report_data = self.build_revenue_report(ctx, req, scoped_transactions)["data"]
            elif req.report_type == FinanceReportType.EXPENSES.value:
                report_data = self.build_expense_report(ctx, req, scoped_transactions)["data"]
            elif req.report_type == FinanceReportType.CASH_FLOW.value:
                report_data = self.build_cash_flow_report(ctx, req, scoped_transactions)["data"]
            elif req.report_type == FinanceReportType.PROFIT_LOSS.value:
                report_data = self.build_profit_loss_report(ctx, req, scoped_transactions)["data"]
            elif req.report_type == FinanceReportType.SUBSCRIPTIONS.value:
                report_data = self.build_subscription_report(ctx, req, scoped_subscriptions)["data"]
            elif req.report_type == FinanceReportType.DASHBOARD_SUMMARY.value:
                report_data = self.build_dashboard_summary(
                    ctx,
                    req,
                    scoped_transactions,
                    scoped_subscriptions,
                )["data"]
            elif req.report_type == FinanceReportType.COMBINED.value:
                report_data = self.build_combined_report(
                    ctx,
                    req,
                    scoped_transactions,
                    scoped_subscriptions,
                )["data"]
            else:
                return self._error_result(
                    message=f"Unsupported report_type: {req.report_type}",
                    error="unsupported_report_type",
                    metadata=self._base_metadata(ctx, req),
                )

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                request=req,
                report_data=report_data,
            )
            memory_payload = self._prepare_memory_payload(
                context=ctx,
                request=req,
                report_data=report_data,
            )

            export_payload = None
            if req.export_format:
                export_payload = self.export_report(
                    context=ctx,
                    request=req,
                    report_data=report_data,
                    export_format=req.export_format,
                ).get("data")

            final_data = {
                "report": report_data,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "export": export_payload,
            }

            self._emit_agent_event(
                event_name="finance_report.generated",
                context=ctx,
                payload={
                    "report_type": req.report_type,
                    "transaction_count": len(scoped_transactions),
                    "subscription_count": len(scoped_subscriptions),
                },
            )
            self._log_audit_event(
                action="generate_report",
                context=ctx,
                request=req,
                status="success",
                metadata={
                    "report_type": req.report_type,
                    "security_required": security_required,
                },
            )

            return self._safe_result(
                success=True,
                message="Finance report generated successfully.",
                data=final_data,
                metadata=self._base_metadata(ctx, req),
            )

        except Exception as exc:
            self.logger.exception("generate_report failed")
            return self._error_result(
                message="Failed to generate finance report.",
                error=exc,
                metadata={"agent": self.agent_name},
            )

    def build_revenue_report(
        self,
        context: Union[FinanceContext, Mapping[str, Any]],
        request: Union[ReportRequest, Mapping[str, Any]],
        transactions: Sequence[Union[NormalizedTransaction, Mapping[str, Any]]],
    ) -> Dict[str, Any]:
        """Build revenue report from scoped transactions."""
        try:
            ctx = self._ensure_context(context)
            req = self._ensure_request(request)
            txns = self._ensure_normalized_transactions(transactions, ctx, req.currency)

            revenue_txns = [
                txn for txn in txns
                if txn.kind in {TransactionKind.REVENUE.value, TransactionKind.CREDIT.value}
            ]

            total_revenue = sum((txn.amount for txn in revenue_txns), Decimal("0.00"))
            by_period = self._aggregate_transactions(revenue_txns, req.period)
            by_category = self._aggregate_by_field(revenue_txns, "category")
            by_source = self._aggregate_by_field(revenue_txns, "source")
            by_client = self._aggregate_by_field(revenue_txns, "client_id", empty_label="unknown_client")

            average_transaction = (
                (total_revenue / Decimal(len(revenue_txns))).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
                if revenue_txns else Decimal("0.00")
            )

            data = {
                "report_type": FinanceReportType.REVENUE.value,
                "currency": req.currency,
                "date_range": self._date_range_payload(req),
                "summary": {
                    "total_revenue": total_revenue,
                    "transaction_count": len(revenue_txns),
                    "average_transaction": average_transaction,
                    "highest_transaction": max((txn.amount for txn in revenue_txns), default=Decimal("0.00")),
                    "lowest_transaction": min((txn.amount for txn in revenue_txns), default=Decimal("0.00")),
                },
                "by_period": by_period,
                "by_category": by_category,
                "by_source": by_source,
                "by_client": by_client,
                "trend": self._calculate_trend(by_period),
                "forecast": self._forecast_from_periods(by_period) if req.include_forecast else None,
            }

            return self._safe_result(
                success=True,
                message="Revenue report built successfully.",
                data=data,
                metadata=self._base_metadata(ctx, req),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to build revenue report.",
                error=exc,
                metadata={"report_type": FinanceReportType.REVENUE.value},
            )

    def build_expense_report(
        self,
        context: Union[FinanceContext, Mapping[str, Any]],
        request: Union[ReportRequest, Mapping[str, Any]],
        transactions: Sequence[Union[NormalizedTransaction, Mapping[str, Any]]],
    ) -> Dict[str, Any]:
        """Build expense report from scoped transactions."""
        try:
            ctx = self._ensure_context(context)
            req = self._ensure_request(request)
            txns = self._ensure_normalized_transactions(transactions, ctx, req.currency)

            expense_txns = [txn for txn in txns if txn.kind == TransactionKind.EXPENSE.value]
            total_expenses = sum((txn.amount for txn in expense_txns), Decimal("0.00"))

            by_period = self._aggregate_transactions(expense_txns, req.period)
            by_category = self._aggregate_by_field(expense_txns, "category")
            by_source = self._aggregate_by_field(expense_txns, "source")
            largest_expenses = sorted(
                [
                    {
                        "transaction_id": txn.transaction_id,
                        "amount": txn.amount,
                        "category": txn.category,
                        "occurred_at": txn.occurred_at,
                        "description": txn.description,
                    }
                    for txn in expense_txns
                ],
                key=lambda item: item["amount"],
                reverse=True,
            )[:10]

            data = {
                "report_type": FinanceReportType.EXPENSES.value,
                "currency": req.currency,
                "date_range": self._date_range_payload(req),
                "summary": {
                    "total_expenses": total_expenses,
                    "transaction_count": len(expense_txns),
                    "average_expense": (
                        (total_expenses / Decimal(len(expense_txns))).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
                        if expense_txns else Decimal("0.00")
                    ),
                    "highest_expense": max((txn.amount for txn in expense_txns), default=Decimal("0.00")),
                    "lowest_expense": min((txn.amount for txn in expense_txns), default=Decimal("0.00")),
                },
                "by_period": by_period,
                "by_category": by_category,
                "by_source": by_source,
                "largest_expenses": largest_expenses if req.include_sensitive_breakdown else [],
                "trend": self._calculate_trend(by_period),
                "forecast": self._forecast_from_periods(by_period) if req.include_forecast else None,
            }

            return self._safe_result(
                success=True,
                message="Expense report built successfully.",
                data=data,
                metadata=self._base_metadata(ctx, req),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to build expense report.",
                error=exc,
                metadata={"report_type": FinanceReportType.EXPENSES.value},
            )

    def build_cash_flow_report(
        self,
        context: Union[FinanceContext, Mapping[str, Any]],
        request: Union[ReportRequest, Mapping[str, Any]],
        transactions: Sequence[Union[NormalizedTransaction, Mapping[str, Any]]],
    ) -> Dict[str, Any]:
        """Build cash flow report from scoped transactions."""
        try:
            ctx = self._ensure_context(context)
            req = self._ensure_request(request)
            txns = self._ensure_normalized_transactions(transactions, ctx, req.currency)

            revenue_txns = [
                txn for txn in txns
                if txn.kind in {TransactionKind.REVENUE.value, TransactionKind.CREDIT.value}
            ]
            expense_txns = [txn for txn in txns if txn.kind == TransactionKind.EXPENSE.value]
            refund_txns = [txn for txn in txns if txn.kind == TransactionKind.REFUND.value]

            inflow = sum((txn.amount for txn in revenue_txns), Decimal("0.00"))
            outflow = sum((txn.amount for txn in expense_txns), Decimal("0.00"))
            refunds = sum((txn.amount for txn in refund_txns), Decimal("0.00"))
            net_cash_flow = inflow - outflow - refunds

            period_map: Dict[str, Dict[str, Decimal]] = defaultdict(
                lambda: {
                    "cash_in": Decimal("0.00"),
                    "cash_out": Decimal("0.00"),
                    "refunds": Decimal("0.00"),
                    "net_cash_flow": Decimal("0.00"),
                }
            )

            for txn in txns:
                key = _period_key(txn.occurred_at, req.period)
                if txn.kind in {TransactionKind.REVENUE.value, TransactionKind.CREDIT.value}:
                    period_map[key]["cash_in"] += txn.amount
                elif txn.kind == TransactionKind.EXPENSE.value:
                    period_map[key]["cash_out"] += txn.amount
                elif txn.kind == TransactionKind.REFUND.value:
                    period_map[key]["refunds"] += txn.amount

            for key in period_map:
                period_map[key]["net_cash_flow"] = (
                    period_map[key]["cash_in"]
                    - period_map[key]["cash_out"]
                    - period_map[key]["refunds"]
                )

            by_period = {
                key: {name: value.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP) for name, value in values.items()}
                for key, values in sorted(period_map.items())
            }

            data = {
                "report_type": FinanceReportType.CASH_FLOW.value,
                "currency": req.currency,
                "date_range": self._date_range_payload(req),
                "summary": {
                    "cash_in": inflow,
                    "cash_out": outflow,
                    "refunds": refunds,
                    "net_cash_flow": net_cash_flow,
                    "cash_flow_margin_percent": _safe_percent(net_cash_flow, inflow),
                },
                "by_period": by_period,
                "cash_flow_health": self._cash_flow_health(net_cash_flow, inflow, outflow),
                "forecast": self._forecast_cash_flow(by_period) if req.include_forecast else None,
            }

            return self._safe_result(
                success=True,
                message="Cash flow report built successfully.",
                data=data,
                metadata=self._base_metadata(ctx, req),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to build cash flow report.",
                error=exc,
                metadata={"report_type": FinanceReportType.CASH_FLOW.value},
            )

    def build_profit_loss_report(
        self,
        context: Union[FinanceContext, Mapping[str, Any]],
        request: Union[ReportRequest, Mapping[str, Any]],
        transactions: Sequence[Union[NormalizedTransaction, Mapping[str, Any]]],
    ) -> Dict[str, Any]:
        """Build profit and loss report from scoped transactions."""
        try:
            ctx = self._ensure_context(context)
            req = self._ensure_request(request)
            txns = self._ensure_normalized_transactions(transactions, ctx, req.currency)

            revenue_txns = [
                txn for txn in txns
                if txn.kind in {TransactionKind.REVENUE.value, TransactionKind.CREDIT.value}
            ]
            expense_txns = [txn for txn in txns if txn.kind == TransactionKind.EXPENSE.value]
            refund_txns = [txn for txn in txns if txn.kind == TransactionKind.REFUND.value]

            total_revenue = sum((txn.amount for txn in revenue_txns), Decimal("0.00"))
            total_expenses = sum((txn.amount for txn in expense_txns), Decimal("0.00"))
            total_refunds = sum((txn.amount for txn in refund_txns), Decimal("0.00"))
            net_revenue = total_revenue - total_refunds
            gross_profit = net_revenue - total_expenses
            margin = _safe_percent(gross_profit, net_revenue)

            revenue_by_category = self._aggregate_by_field(revenue_txns, "category")
            expense_by_category = self._aggregate_by_field(expense_txns, "category")

            period_map: Dict[str, Dict[str, Decimal]] = defaultdict(
                lambda: {
                    "revenue": Decimal("0.00"),
                    "refunds": Decimal("0.00"),
                    "expenses": Decimal("0.00"),
                    "profit": Decimal("0.00"),
                    "profit_margin_percent": Decimal("0.00"),
                }
            )

            for txn in txns:
                key = _period_key(txn.occurred_at, req.period)
                if txn.kind in {TransactionKind.REVENUE.value, TransactionKind.CREDIT.value}:
                    period_map[key]["revenue"] += txn.amount
                elif txn.kind == TransactionKind.REFUND.value:
                    period_map[key]["refunds"] += txn.amount
                elif txn.kind == TransactionKind.EXPENSE.value:
                    period_map[key]["expenses"] += txn.amount

            for key in period_map:
                net = period_map[key]["revenue"] - period_map[key]["refunds"]
                profit = net - period_map[key]["expenses"]
                period_map[key]["profit"] = profit
                period_map[key]["profit_margin_percent"] = _safe_percent(profit, net)

            by_period = {
                key: {name: value.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP) for name, value in values.items()}
                for key, values in sorted(period_map.items())
            }

            data = {
                "report_type": FinanceReportType.PROFIT_LOSS.value,
                "currency": req.currency,
                "date_range": self._date_range_payload(req),
                "summary": {
                    "gross_revenue": total_revenue,
                    "refunds": total_refunds,
                    "net_revenue": net_revenue,
                    "total_expenses": total_expenses,
                    "gross_profit": gross_profit,
                    "profit_margin_percent": margin,
                    "revenue_transaction_count": len(revenue_txns),
                    "expense_transaction_count": len(expense_txns),
                    "refund_transaction_count": len(refund_txns),
                },
                "by_period": by_period,
                "revenue_by_category": revenue_by_category,
                "expense_by_category": expense_by_category,
                "profit_health": self._profit_health(gross_profit, margin),
                "forecast": self._forecast_profit_loss(by_period) if req.include_forecast else None,
            }

            return self._safe_result(
                success=True,
                message="Profit/loss report built successfully.",
                data=data,
                metadata=self._base_metadata(ctx, req),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to build profit/loss report.",
                error=exc,
                metadata={"report_type": FinanceReportType.PROFIT_LOSS.value},
            )

    def build_subscription_report(
        self,
        context: Union[FinanceContext, Mapping[str, Any]],
        request: Union[ReportRequest, Mapping[str, Any]],
        subscriptions: Sequence[Union[NormalizedSubscription, Mapping[str, Any]]],
    ) -> Dict[str, Any]:
        """Build SaaS subscription revenue report."""
        try:
            ctx = self._ensure_context(context)
            req = self._ensure_request(request)
            subs = self._ensure_normalized_subscriptions(subscriptions, ctx, req.currency)

            active_statuses = {
                SubscriptionStatus.ACTIVE.value,
                SubscriptionStatus.TRIALING.value,
                SubscriptionStatus.PAST_DUE.value,
            }
            active_subs = [sub for sub in subs if sub.status in active_statuses]
            canceled_subs = [sub for sub in subs if sub.status == SubscriptionStatus.CANCELED.value]
            past_due_subs = [sub for sub in subs if sub.status == SubscriptionStatus.PAST_DUE.value]
            trialing_subs = [sub for sub in subs if sub.status == SubscriptionStatus.TRIALING.value]

            mrr = sum((self._monthly_value(sub) for sub in active_subs), Decimal("0.00"))
            arr = (mrr * Decimal("12")).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
            arpu = (
                (mrr / Decimal(len(active_subs))).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
                if active_subs else Decimal("0.00")
            )
            churn_rate = _safe_percent(Decimal(len(canceled_subs)), Decimal(len(subs))) if subs else Decimal("0.00")

            by_status = self._aggregate_subscriptions_by_status(subs)
            by_plan = self._aggregate_subscriptions_by_plan(subs)

            data = {
                "report_type": FinanceReportType.SUBSCRIPTIONS.value,
                "currency": req.currency,
                "date_range": self._date_range_payload(req),
                "summary": {
                    "total_subscriptions": len(subs),
                    "active_subscriptions": len(active_subs),
                    "trialing_subscriptions": len(trialing_subs),
                    "past_due_subscriptions": len(past_due_subs),
                    "canceled_subscriptions": len(canceled_subs),
                    "mrr": mrr,
                    "arr": arr,
                    "arpu": arpu,
                    "logo_churn_rate_percent": churn_rate,
                },
                "by_status": by_status,
                "by_plan": by_plan,
                "risk_flags": self._subscription_risk_flags(subs),
                "forecast": self._forecast_subscription_revenue(mrr, churn_rate) if req.include_forecast else None,
            }

            return self._safe_result(
                success=True,
                message="Subscription report built successfully.",
                data=data,
                metadata=self._base_metadata(ctx, req),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to build subscription report.",
                error=exc,
                metadata={"report_type": FinanceReportType.SUBSCRIPTIONS.value},
            )

    def build_dashboard_summary(
        self,
        context: Union[FinanceContext, Mapping[str, Any]],
        request: Union[ReportRequest, Mapping[str, Any]],
        transactions: Sequence[Union[NormalizedTransaction, Mapping[str, Any]]],
        subscriptions: Optional[Sequence[Union[NormalizedSubscription, Mapping[str, Any]]]] = None,
    ) -> Dict[str, Any]:
        """Build a compact dashboard-friendly finance summary."""
        try:
            ctx = self._ensure_context(context)
            req = self._ensure_request(request)
            txns = self._ensure_normalized_transactions(transactions, ctx, req.currency)
            subs = self._ensure_normalized_subscriptions(subscriptions or [], ctx, req.currency)

            revenue_report = self.build_revenue_report(ctx, req, txns)["data"]
            expense_report = self.build_expense_report(ctx, req, txns)["data"]
            cash_flow_report = self.build_cash_flow_report(ctx, req, txns)["data"]
            pnl_report = self.build_profit_loss_report(ctx, req, txns)["data"]
            subscription_report = self.build_subscription_report(ctx, req, subs)["data"]

            data = {
                "report_type": FinanceReportType.DASHBOARD_SUMMARY.value,
                "currency": req.currency,
                "date_range": self._date_range_payload(req),
                "cards": {
                    "revenue": revenue_report["summary"]["total_revenue"],
                    "expenses": expense_report["summary"]["total_expenses"],
                    "net_cash_flow": cash_flow_report["summary"]["net_cash_flow"],
                    "gross_profit": pnl_report["summary"]["gross_profit"],
                    "profit_margin_percent": pnl_report["summary"]["profit_margin_percent"],
                    "mrr": subscription_report["summary"]["mrr"],
                    "arr": subscription_report["summary"]["arr"],
                    "active_subscriptions": subscription_report["summary"]["active_subscriptions"],
                },
                "health": {
                    "cash_flow": cash_flow_report["cash_flow_health"],
                    "profit": pnl_report["profit_health"],
                    "subscription_risks": subscription_report["risk_flags"],
                },
                "charts": {
                    "revenue_by_period": revenue_report["by_period"],
                    "expenses_by_period": expense_report["by_period"],
                    "cash_flow_by_period": cash_flow_report["by_period"],
                    "profit_by_period": pnl_report["by_period"],
                    "expenses_by_category": expense_report["by_category"],
                    "revenue_by_category": revenue_report["by_category"],
                },
            }

            return self._safe_result(
                success=True,
                message="Dashboard finance summary built successfully.",
                data=data,
                metadata=self._base_metadata(ctx, req),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to build dashboard summary.",
                error=exc,
                metadata={"report_type": FinanceReportType.DASHBOARD_SUMMARY.value},
            )

    def build_combined_report(
        self,
        context: Union[FinanceContext, Mapping[str, Any]],
        request: Union[ReportRequest, Mapping[str, Any]],
        transactions: Sequence[Union[NormalizedTransaction, Mapping[str, Any]]],
        subscriptions: Optional[Sequence[Union[NormalizedSubscription, Mapping[str, Any]]]] = None,
    ) -> Dict[str, Any]:
        """Build a full combined finance report."""
        try:
            ctx = self._ensure_context(context)
            req = self._ensure_request(request)
            txns = self._ensure_normalized_transactions(transactions, ctx, req.currency)
            subs = self._ensure_normalized_subscriptions(subscriptions or [], ctx, req.currency)

            data = {
                "report_type": FinanceReportType.COMBINED.value,
                "currency": req.currency,
                "date_range": self._date_range_payload(req),
                "revenue": self.build_revenue_report(ctx, req, txns)["data"],
                "expenses": self.build_expense_report(ctx, req, txns)["data"],
                "cash_flow": self.build_cash_flow_report(ctx, req, txns)["data"],
                "profit_loss": self.build_profit_loss_report(ctx, req, txns)["data"],
                "subscriptions": self.build_subscription_report(ctx, req, subs)["data"],
            }

            data["executive_summary"] = self._build_executive_summary(data)

            return self._safe_result(
                success=True,
                message="Combined finance report built successfully.",
                data=data,
                metadata=self._base_metadata(ctx, req),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to build combined finance report.",
                error=exc,
                metadata={"report_type": FinanceReportType.COMBINED.value},
            )

    def export_report(
        self,
        context: Union[FinanceContext, Mapping[str, Any]],
        request: Union[ReportRequest, Mapping[str, Any]],
        report_data: Mapping[str, Any],
        export_format: str = "json",
    ) -> Dict[str, Any]:
        """
        Export report data as safe JSON or CSV payload.

        This method returns content only. It does not write files to disk.
        """
        try:
            ctx = self._ensure_context(context)
            req = self._ensure_request(request)
            fmt = str(export_format or "").strip().lower()

            if fmt not in SAFE_EXPORT_FORMATS:
                return self._error_result(
                    message=f"Unsupported export format: {fmt}",
                    error="unsupported_export_format",
                    metadata=self._base_metadata(ctx, req),
                )

            safe_data = _decimal_to_float(dict(report_data))

            if fmt == "json":
                content = json.dumps(safe_data, indent=2, sort_keys=True)
                mime_type = "application/json"
                extension = "json"
            else:
                content = self._report_to_csv(safe_data)
                mime_type = "text/csv"
                extension = "csv"

            filename = self._build_export_filename(ctx, req, extension)

            return self._safe_result(
                success=True,
                message="Report exported successfully.",
                data={
                    "filename": filename,
                    "format": fmt,
                    "mime_type": mime_type,
                    "content": content,
                },
                metadata=self._base_metadata(ctx, req),
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to export report.",
                error=exc,
                metadata={"export_format": export_format},
            )

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: Union[FinanceContext, Mapping[str, Any]]) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Required by William/Jarvis global rules:
            - user_id is mandatory.
            - workspace_id is mandatory.
            - no report is generated without both.
        """
        try:
            ctx = self._ensure_context(context)

            if not ctx.user_id or not isinstance(ctx.user_id, str):
                return self._error_result(
                    message="Missing or invalid user_id in finance report context.",
                    error="invalid_user_id",
                    metadata={"agent": self.agent_name},
                )

            if not ctx.workspace_id or not isinstance(ctx.workspace_id, str):
                return self._error_result(
                    message="Missing or invalid workspace_id in finance report context.",
                    error="invalid_workspace_id",
                    metadata={"agent": self.agent_name},
                )

            return self._safe_result(
                success=True,
                message="Finance report context validated successfully.",
                data={
                    "user_id": ctx.user_id,
                    "workspace_id": ctx.workspace_id,
                    "request_id": ctx.request_id,
                    "correlation_id": ctx.correlation_id,
                },
                metadata={"agent": self.agent_name},
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to validate finance report context.",
                error=exc,
                metadata={"agent": self.agent_name},
            )

    def _requires_security_check(
        self,
        context: Union[FinanceContext, Mapping[str, Any]],
        request: Union[ReportRequest, Mapping[str, Any]],
    ) -> bool:
        """
        Decide whether Security Agent approval is needed.

        Reports containing profit/loss, cash flow, combined financial details,
        sensitive breakdowns, or export requests are treated as sensitive.
        """
        ctx = self._ensure_context(context)
        req = self._ensure_request(request)

        if req.report_type in SENSITIVE_REPORT_TYPES:
            return True

        if req.include_sensitive_breakdown:
            return True

        if req.export_format:
            return True

        permissions = set(ctx.permissions or [])
        if "finance_reports:read_sensitive" in permissions:
            return False

        return False

    def _request_security_approval(
        self,
        context: Union[FinanceContext, Mapping[str, Any]],
        request: Union[ReportRequest, Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval if available.

        If no security client is injected, this method uses conservative safe
        behavior:
            - Approves non-sensitive read-only reports.
            - Requires approval for sensitive reports unless the context already
              includes finance_reports:read_sensitive permission.
        """
        ctx = self._ensure_context(context)
        req = self._ensure_request(request)

        permissions = set(ctx.permissions or [])
        if "finance_reports:read_sensitive" in permissions or "finance:admin" in permissions:
            return {
                "approved": True,
                "reason": "Permission grants sensitive finance report access.",
                "approval_source": "context_permissions",
            }

        if self.security_client and hasattr(self.security_client, "request_approval"):
            try:
                approval = self.security_client.request_approval(
                    user_id=ctx.user_id,
                    workspace_id=ctx.workspace_id,
                    action="finance_reports.generate",
                    resource=req.report_type,
                    metadata={
                        "request_id": ctx.request_id,
                        "correlation_id": ctx.correlation_id,
                        "include_sensitive_breakdown": req.include_sensitive_breakdown,
                        "export_format": req.export_format,
                    },
                )
                if isinstance(approval, Mapping):
                    return dict(approval)
            except Exception as exc:
                self.logger.warning("Security approval request failed: %s", exc)

        return {
            "approved": False,
            "reason": "Sensitive finance report requires Security Agent approval or finance_reports:read_sensitive permission.",
            "approval_source": "fallback_policy",
        }

    def _prepare_verification_payload(
        self,
        context: Union[FinanceContext, Mapping[str, Any]],
        request: Union[ReportRequest, Mapping[str, Any]],
        report_data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Verification Agent can use this to check that calculations, scope,
        report type, and date range are consistent.
        """
        ctx = self._ensure_context(context)
        req = self._ensure_request(request)

        summary = report_data.get("summary") or report_data.get("cards") or {}

        return {
            "verification_type": "finance_report",
            "agent": self.agent_name,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "request_id": ctx.request_id,
            "correlation_id": ctx.correlation_id,
            "report_type": req.report_type,
            "currency": req.currency,
            "date_range": self._date_range_payload(req),
            "checks": [
                "saas_context_present",
                "workspace_scope_enforced",
                "no_real_financial_action_executed",
                "report_calculations_completed",
                "structured_result_format",
            ],
            "summary": _decimal_to_float(summary),
            "created_at": _utc_now().isoformat(),
        }

    def _prepare_memory_payload(
        self,
        context: Union[FinanceContext, Mapping[str, Any]],
        request: Union[ReportRequest, Mapping[str, Any]],
        report_data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent-compatible payload.

        This does not store memory directly. It prepares safe preferences and
        reusable context that a Memory Agent may choose to store.
        """
        ctx = self._ensure_context(context)
        req = self._ensure_request(request)

        return {
            "memory_type": "finance_report_preference",
            "agent": self.agent_name,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "safe_to_store": True,
            "payload": {
                "preferred_report_type": req.report_type,
                "preferred_period": req.period,
                "preferred_currency": req.currency,
                "include_forecast": req.include_forecast,
                "last_report_generated_at": _utc_now().isoformat(),
            },
            "do_not_store": [
                "raw_transactions",
                "raw_subscription_customer_data",
                "bank_details",
                "payment_methods",
                "secrets",
            ],
        }

    def _emit_agent_event(
        self,
        event_name: str,
        context: Union[FinanceContext, Mapping[str, Any]],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit dashboard/analytics event.

        Safe no-op if no event emitter is configured.
        """
        ctx = self._ensure_context(context)
        event = {
            "event_name": event_name,
            "agent": self.agent_name,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "request_id": ctx.request_id,
            "correlation_id": ctx.correlation_id,
            "payload": _decimal_to_float(dict(payload or {})),
            "created_at": _utc_now().isoformat(),
        }

        if callable(self.event_emitter):
            try:
                self.event_emitter(event)
            except Exception as exc:
                self.logger.warning("Agent event emitter failed: %s", exc)

    def _log_audit_event(
        self,
        action: str,
        context: Union[FinanceContext, Mapping[str, Any]],
        request: Optional[Union[ReportRequest, Mapping[str, Any]]] = None,
        status: str = "info",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        Safe no-op if no audit logger is configured.
        """
        ctx = self._ensure_context(context)
        req = self._ensure_request(request or {"report_type": "unknown"})

        audit_payload = {
            "action": action,
            "agent": self.agent_name,
            "status": status,
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "request_id": ctx.request_id,
            "correlation_id": ctx.correlation_id,
            "report_type": req.report_type,
            "metadata": _decimal_to_float(dict(metadata or {})),
            "created_at": _utc_now().isoformat(),
        }

        if self.audit_logger and hasattr(self.audit_logger, "log"):
            try:
                self.audit_logger.log(audit_payload)
                return
            except Exception as exc:
                self.logger.warning("Audit logger failed: %s", exc)

        self.logger.info("Audit event: %s", audit_payload)

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Any] = None,
        error: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return structured William/Jarvis result."""
        return {
            "success": bool(success),
            "message": str(message),
            "data": _decimal_to_float(data if data is not None else {}),
            "error": self._serialize_error(error),
            "metadata": _decimal_to_float(dict(metadata or {})),
        }

    def _error_result(
        self,
        message: str,
        error: Any,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return structured William/Jarvis error result."""
        return self._safe_result(
            success=False,
            message=message,
            data=data or {},
            error=error,
            metadata=metadata or {"agent": self.agent_name},
        )

    # ------------------------------------------------------------------
    # Normalization helpers
    # ------------------------------------------------------------------

    def _context_from_task(self, task: Mapping[str, Any]) -> FinanceContext:
        return FinanceContext(
            user_id=_sanitize_text(task.get("user_id")),
            workspace_id=_sanitize_text(task.get("workspace_id")),
            role=_sanitize_text(task.get("role")) or None,
            subscription_plan=_sanitize_text(task.get("subscription_plan")) or None,
            request_id=_sanitize_text(task.get("request_id")) or str(uuid.uuid4()),
            correlation_id=_sanitize_text(task.get("correlation_id")) or str(uuid.uuid4()),
            source=_sanitize_text(task.get("source")) or "finance_reports",
            permissions=list(task.get("permissions") or []),
            metadata=dict(task.get("context_metadata") or task.get("metadata") or {}),
        )

    def _request_from_task(self, task: Mapping[str, Any]) -> ReportRequest:
        return ReportRequest(
            report_type=self._normalize_report_type(task.get("report_type", FinanceReportType.DASHBOARD_SUMMARY.value)),
            start_date=_parse_date(task.get("start_date")),
            end_date=_parse_date(task.get("end_date")),
            period=self._normalize_period(task.get("period", ReportPeriod.MONTHLY.value)),
            currency=_normalize_currency(task.get("currency", DEFAULT_CURRENCY)),
            include_forecast=_coerce_bool(task.get("include_forecast", False)),
            include_sensitive_breakdown=_coerce_bool(task.get("include_sensitive_breakdown", False)),
            export_format=(
                str(task.get("export_format")).strip().lower()
                if task.get("export_format") else None
            ),
            filters=dict(task.get("filters") or {}),
            metadata=dict(task.get("request_metadata") or {}),
        )

    def _ensure_context(self, context: Union[FinanceContext, Mapping[str, Any]]) -> FinanceContext:
        if isinstance(context, FinanceContext):
            return context

        if isinstance(context, Mapping):
            return FinanceContext(
                user_id=_sanitize_text(context.get("user_id")),
                workspace_id=_sanitize_text(context.get("workspace_id")),
                role=_sanitize_text(context.get("role")) or None,
                subscription_plan=_sanitize_text(context.get("subscription_plan")) or None,
                request_id=_sanitize_text(context.get("request_id")) or str(uuid.uuid4()),
                correlation_id=_sanitize_text(context.get("correlation_id")) or str(uuid.uuid4()),
                source=_sanitize_text(context.get("source")) or "finance_reports",
                permissions=list(context.get("permissions") or []),
                metadata=dict(context.get("metadata") or {}),
            )

        raise TypeError("context must be FinanceContext or mapping")

    def _ensure_request(self, request: Union[ReportRequest, Mapping[str, Any]]) -> ReportRequest:
        if isinstance(request, ReportRequest):
            request.report_type = self._normalize_report_type(request.report_type)
            request.period = self._normalize_period(request.period)
            request.currency = _normalize_currency(request.currency)
            return request

        if isinstance(request, Mapping):
            return ReportRequest(
                report_type=self._normalize_report_type(request.get("report_type", FinanceReportType.DASHBOARD_SUMMARY.value)),
                start_date=_parse_date(request.get("start_date")),
                end_date=_parse_date(request.get("end_date")),
                period=self._normalize_period(request.get("period", ReportPeriod.MONTHLY.value)),
                currency=_normalize_currency(request.get("currency", DEFAULT_CURRENCY)),
                include_forecast=_coerce_bool(request.get("include_forecast", False)),
                include_sensitive_breakdown=_coerce_bool(request.get("include_sensitive_breakdown", False)),
                export_format=(
                    str(request.get("export_format")).strip().lower()
                    if request.get("export_format") else None
                ),
                filters=dict(request.get("filters") or {}),
                metadata=dict(request.get("metadata") or {}),
            )

        raise TypeError("request must be ReportRequest or mapping")

    def _normalize_report_type(self, value: Any) -> str:
        report_type = str(value or FinanceReportType.DASHBOARD_SUMMARY.value).strip().lower()
        if report_type not in SUPPORTED_REPORT_TYPES:
            return FinanceReportType.DASHBOARD_SUMMARY.value
        return report_type

    def _normalize_period(self, value: Any) -> str:
        period = str(value or ReportPeriod.MONTHLY.value).strip().lower()
        if period not in ALLOWED_PERIODS:
            return ReportPeriod.MONTHLY.value
        return period

    def _normalize_transactions(
        self,
        transactions: Sequence[Mapping[str, Any]],
        context: FinanceContext,
        default_currency: str,
    ) -> List[NormalizedTransaction]:
        normalized: List[NormalizedTransaction] = []

        for raw in transactions:
            if not isinstance(raw, Mapping):
                continue

            user_id = _sanitize_text(raw.get("user_id") or context.user_id)
            workspace_id = _sanitize_text(raw.get("workspace_id") or context.workspace_id)

            if user_id != context.user_id or workspace_id != context.workspace_id:
                continue

            occurred_at = _parse_datetime(
                raw.get("occurred_at")
                or raw.get("date")
                or raw.get("created_at")
                or raw.get("paid_at")
            )
            if not occurred_at:
                continue

            kind = self._normalize_transaction_kind(raw)
            amount = _to_decimal(raw.get("amount"))

            if amount < Decimal("0.00"):
                amount = abs(amount)

            normalized.append(
                NormalizedTransaction(
                    transaction_id=_sanitize_text(raw.get("transaction_id") or raw.get("id") or str(uuid.uuid4())),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    kind=kind,
                    amount=amount,
                    currency=_normalize_currency(raw.get("currency") or default_currency),
                    occurred_at=occurred_at,
                    category=_sanitize_text(raw.get("category") or "uncategorized", 120) or "uncategorized",
                    source=_sanitize_text(raw.get("source") or "manual", 120) or "manual",
                    client_id=_sanitize_text(raw.get("client_id")) or None,
                    invoice_id=_sanitize_text(raw.get("invoice_id")) or None,
                    subscription_id=_sanitize_text(raw.get("subscription_id")) or None,
                    description=_sanitize_text(raw.get("description"), 500) or None,
                    tags=list(raw.get("tags") or []),
                    metadata=dict(raw.get("metadata") or {}),
                )
            )

        return normalized

    def _ensure_normalized_transactions(
        self,
        transactions: Sequence[Union[NormalizedTransaction, Mapping[str, Any]]],
        context: FinanceContext,
        currency: str,
    ) -> List[NormalizedTransaction]:
        if all(isinstance(txn, NormalizedTransaction) for txn in transactions):
            return list(transactions)  # type: ignore[arg-type]

        mappings = [txn for txn in transactions if isinstance(txn, Mapping)]
        return self._normalize_transactions(mappings, context, currency)

    def _normalize_transaction_kind(self, raw: Mapping[str, Any]) -> str:
        value = str(
            raw.get("kind")
            or raw.get("type")
            or raw.get("transaction_type")
            or ""
        ).strip().lower()

        aliases = {
            "income": TransactionKind.REVENUE.value,
            "sale": TransactionKind.REVENUE.value,
            "sales": TransactionKind.REVENUE.value,
            "payment": TransactionKind.REVENUE.value,
            "paid_invoice": TransactionKind.REVENUE.value,
            "expense": TransactionKind.EXPENSE.value,
            "cost": TransactionKind.EXPENSE.value,
            "spend": TransactionKind.EXPENSE.value,
            "debit": TransactionKind.EXPENSE.value,
            "refund": TransactionKind.REFUND.value,
            "chargeback": TransactionKind.REFUND.value,
            "credit": TransactionKind.CREDIT.value,
            "adjustment": TransactionKind.ADJUSTMENT.value,
        }

        if value in aliases:
            return aliases[value]

        if value in {item.value for item in TransactionKind}:
            return value

        amount = _to_decimal(raw.get("amount"))
        if str(raw.get("direction", "")).lower() in {"out", "outflow"}:
            return TransactionKind.EXPENSE.value
        if str(raw.get("direction", "")).lower() in {"in", "inflow"}:
            return TransactionKind.REVENUE.value
        if amount < Decimal("0.00"):
            return TransactionKind.EXPENSE.value

        return TransactionKind.REVENUE.value

    def _normalize_subscriptions(
        self,
        subscriptions: Sequence[Mapping[str, Any]],
        context: FinanceContext,
        default_currency: str,
    ) -> List[NormalizedSubscription]:
        normalized: List[NormalizedSubscription] = []

        for raw in subscriptions:
            if not isinstance(raw, Mapping):
                continue

            user_id = _sanitize_text(raw.get("user_id") or context.user_id)
            workspace_id = _sanitize_text(raw.get("workspace_id") or context.workspace_id)

            if user_id != context.user_id or workspace_id != context.workspace_id:
                continue

            normalized.append(
                NormalizedSubscription(
                    subscription_id=_sanitize_text(raw.get("subscription_id") or raw.get("id") or str(uuid.uuid4())),
                    user_id=user_id,
                    workspace_id=workspace_id,
                    customer_id=_sanitize_text(raw.get("customer_id") or raw.get("client_id")) or None,
                    plan_name=_sanitize_text(raw.get("plan_name") or raw.get("plan") or "unknown_plan", 120) or "unknown_plan",
                    status=self._normalize_subscription_status(raw.get("status")),
                    amount=abs(_to_decimal(raw.get("amount") or raw.get("price") or raw.get("unit_amount"))),
                    currency=_normalize_currency(raw.get("currency") or default_currency),
                    billing_interval=_sanitize_text(raw.get("billing_interval") or raw.get("interval") or "monthly", 50) or "monthly",
                    started_at=_parse_datetime(raw.get("started_at") or raw.get("created_at")),
                    current_period_start=_parse_datetime(raw.get("current_period_start")),
                    current_period_end=_parse_datetime(raw.get("current_period_end")),
                    canceled_at=_parse_datetime(raw.get("canceled_at") or raw.get("cancelled_at")),
                    trial_end=_parse_datetime(raw.get("trial_end")),
                    metadata=dict(raw.get("metadata") or {}),
                )
            )

        return normalized

    def _ensure_normalized_subscriptions(
        self,
        subscriptions: Sequence[Union[NormalizedSubscription, Mapping[str, Any]]],
        context: FinanceContext,
        currency: str,
    ) -> List[NormalizedSubscription]:
        if all(isinstance(sub, NormalizedSubscription) for sub in subscriptions):
            return list(subscriptions)  # type: ignore[arg-type]

        mappings = [sub for sub in subscriptions if isinstance(sub, Mapping)]
        return self._normalize_subscriptions(mappings, context, currency)

    def _normalize_subscription_status(self, value: Any) -> str:
        status = str(value or SubscriptionStatus.UNKNOWN.value).strip().lower()
        aliases = {
            "active": SubscriptionStatus.ACTIVE.value,
            "trial": SubscriptionStatus.TRIALING.value,
            "trialing": SubscriptionStatus.TRIALING.value,
            "pastdue": SubscriptionStatus.PAST_DUE.value,
            "past_due": SubscriptionStatus.PAST_DUE.value,
            "unpaid": SubscriptionStatus.PAST_DUE.value,
            "cancelled": SubscriptionStatus.CANCELED.value,
            "canceled": SubscriptionStatus.CANCELED.value,
            "paused": SubscriptionStatus.PAUSED.value,
            "expired": SubscriptionStatus.EXPIRED.value,
        }
        return aliases.get(status, SubscriptionStatus.UNKNOWN.value)

    # ------------------------------------------------------------------
    # Filtering and aggregation
    # ------------------------------------------------------------------

    def _filter_transactions(
        self,
        transactions: Sequence[NormalizedTransaction],
        context: FinanceContext,
        request: ReportRequest,
    ) -> List[NormalizedTransaction]:
        filtered: List[NormalizedTransaction] = []

        for txn in transactions:
            if txn.user_id != context.user_id or txn.workspace_id != context.workspace_id:
                continue

            if txn.currency != request.currency:
                continue

            if request.start_date and txn.occurred_at.date() < request.start_date:
                continue

            if request.end_date and txn.occurred_at.date() > request.end_date:
                continue

            if not self._passes_transaction_filters(txn, request.filters):
                continue

            filtered.append(txn)

        return filtered

    def _filter_subscriptions(
        self,
        subscriptions: Sequence[NormalizedSubscription],
        context: FinanceContext,
        request: ReportRequest,
    ) -> List[NormalizedSubscription]:
        filtered: List[NormalizedSubscription] = []

        for sub in subscriptions:
            if sub.user_id != context.user_id or sub.workspace_id != context.workspace_id:
                continue

            if sub.currency != request.currency:
                continue

            if request.start_date and sub.started_at and sub.started_at.date() < request.start_date:
                pass

            if not self._passes_subscription_filters(sub, request.filters):
                continue

            filtered.append(sub)

        return filtered

    def _passes_transaction_filters(
        self,
        txn: NormalizedTransaction,
        filters: Mapping[str, Any],
    ) -> bool:
        if not filters:
            return True

        category = filters.get("category")
        if category and txn.category != str(category):
            return False

        source = filters.get("source")
        if source and txn.source != str(source):
            return False

        client_id = filters.get("client_id")
        if client_id and txn.client_id != str(client_id):
            return False

        invoice_id = filters.get("invoice_id")
        if invoice_id and txn.invoice_id != str(invoice_id):
            return False

        subscription_id = filters.get("subscription_id")
        if subscription_id and txn.subscription_id != str(subscription_id):
            return False

        tags = filters.get("tags")
        if tags:
            required_tags = set(tags if isinstance(tags, list) else [tags])
            if not required_tags.intersection(set(txn.tags)):
                return False

        return True

    def _passes_subscription_filters(
        self,
        sub: NormalizedSubscription,
        filters: Mapping[str, Any],
    ) -> bool:
        if not filters:
            return True

        status = filters.get("status")
        if status and sub.status != str(status).lower():
            return False

        plan_name = filters.get("plan_name") or filters.get("plan")
        if plan_name and sub.plan_name != str(plan_name):
            return False

        customer_id = filters.get("customer_id") or filters.get("client_id")
        if customer_id and sub.customer_id != str(customer_id):
            return False

        return True

    def _aggregate_transactions(
        self,
        transactions: Sequence[NormalizedTransaction],
        period: str,
    ) -> Dict[str, Dict[str, Any]]:
        buckets: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "amount": Decimal("0.00"),
                "count": 0,
            }
        )

        for txn in transactions:
            key = _period_key(txn.occurred_at, period)
            buckets[key]["amount"] += txn.amount
            buckets[key]["count"] += 1

        return {
            key: {
                "amount": values["amount"].quantize(MONEY_QUANT, rounding=ROUND_HALF_UP),
                "count": values["count"],
            }
            for key, values in sorted(buckets.items())
        }

    def _aggregate_by_field(
        self,
        transactions: Sequence[NormalizedTransaction],
        field_name: str,
        empty_label: str = "unknown",
    ) -> Dict[str, Dict[str, Any]]:
        buckets: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "amount": Decimal("0.00"),
                "count": 0,
            }
        )

        for txn in transactions:
            value = getattr(txn, field_name, None) or empty_label
            key = str(value)
            buckets[key]["amount"] += txn.amount
            buckets[key]["count"] += 1

        sorted_items = sorted(
            buckets.items(),
            key=lambda item: item[1]["amount"],
            reverse=True,
        )

        return {
            key: {
                "amount": values["amount"].quantize(MONEY_QUANT, rounding=ROUND_HALF_UP),
                "count": values["count"],
            }
            for key, values in sorted_items
        }

    def _aggregate_subscriptions_by_status(
        self,
        subscriptions: Sequence[NormalizedSubscription],
    ) -> Dict[str, Dict[str, Any]]:
        buckets: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "mrr": Decimal("0.00"),
                "count": 0,
            }
        )

        for sub in subscriptions:
            buckets[sub.status]["mrr"] += self._monthly_value(sub)
            buckets[sub.status]["count"] += 1

        return {
            key: {
                "mrr": values["mrr"].quantize(MONEY_QUANT, rounding=ROUND_HALF_UP),
                "count": values["count"],
            }
            for key, values in sorted(buckets.items())
        }

    def _aggregate_subscriptions_by_plan(
        self,
        subscriptions: Sequence[NormalizedSubscription],
    ) -> Dict[str, Dict[str, Any]]:
        buckets: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {
                "mrr": Decimal("0.00"),
                "count": 0,
            }
        )

        for sub in subscriptions:
            buckets[sub.plan_name]["mrr"] += self._monthly_value(sub)
            buckets[sub.plan_name]["count"] += 1

        sorted_items = sorted(
            buckets.items(),
            key=lambda item: item[1]["mrr"],
            reverse=True,
        )

        return {
            key: {
                "mrr": values["mrr"].quantize(MONEY_QUANT, rounding=ROUND_HALF_UP),
                "count": values["count"],
            }
            for key, values in sorted_items
        }

    # ------------------------------------------------------------------
    # Finance calculations
    # ------------------------------------------------------------------

    def _monthly_value(self, subscription: NormalizedSubscription) -> Decimal:
        interval = (subscription.billing_interval or "monthly").lower()
        amount = subscription.amount

        if interval in {"month", "monthly"}:
            return amount.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

        if interval in {"year", "yearly", "annual", "annually"}:
            return (amount / Decimal("12")).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

        if interval in {"week", "weekly"}:
            return (amount * Decimal("4.3333")).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

        if interval in {"day", "daily"}:
            return (amount * Decimal("30")).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

        if interval in {"quarter", "quarterly"}:
            return (amount / Decimal("3")).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

        return amount.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)

    def _calculate_trend(self, by_period: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
        amounts = [_to_decimal(values.get("amount")) for _, values in sorted(by_period.items())]

        if len(amounts) < 2:
            return {
                "direction": "flat",
                "change_amount": Decimal("0.00"),
                "change_percent": Decimal("0.00"),
                "points": len(amounts),
            }

        first = amounts[0]
        last = amounts[-1]
        change = last - first
        change_percent = _safe_percent(change, first if first != Decimal("0.00") else Decimal("1.00"))

        if change > Decimal("0.00"):
            direction = "up"
        elif change < Decimal("0.00"):
            direction = "down"
        else:
            direction = "flat"

        return {
            "direction": direction,
            "change_amount": change.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP),
            "change_percent": change_percent,
            "points": len(amounts),
        }

    def _forecast_from_periods(
        self,
        by_period: Mapping[str, Mapping[str, Any]],
        periods_ahead: int = 3,
    ) -> Dict[str, Any]:
        amounts = [_to_decimal(values.get("amount")) for _, values in sorted(by_period.items())]

        if not amounts:
            return {
                "method": "simple_average",
                "periods_ahead": periods_ahead,
                "forecast_amount": Decimal("0.00"),
                "confidence": "low",
            }

        if len(amounts) == 1:
            forecast = amounts[0]
            confidence = "low"
        else:
            average = sum(amounts, Decimal("0.00")) / Decimal(len(amounts))
            recent = amounts[-1]
            forecast = ((average + recent) / Decimal("2")).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)
            confidence = "medium" if len(amounts) >= 3 else "low"

        return {
            "method": "simple_average_recent_blend",
            "periods_ahead": periods_ahead,
            "forecast_amount_per_period": forecast,
            "forecast_total": (forecast * Decimal(periods_ahead)).quantize(MONEY_QUANT, rounding=ROUND_HALF_UP),
            "confidence": confidence,
        }

    def _forecast_cash_flow(self, by_period: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
        net_values = [
            _to_decimal(values.get("net_cash_flow"))
            for _, values in sorted(by_period.items())
        ]

        if not net_values:
            return {
                "method": "simple_average_net_cash_flow",
                "forecast_net_cash_flow": Decimal("0.00"),
                "confidence": "low",
            }

        average = sum(net_values, Decimal("0.00")) / Decimal(len(net_values))
        return {
            "method": "simple_average_net_cash_flow",
            "forecast_net_cash_flow": average.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP),
            "confidence": "medium" if len(net_values) >= 3 else "low",
        }

    def _forecast_profit_loss(self, by_period: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
        profits = [_to_decimal(values.get("profit")) for _, values in sorted(by_period.items())]

        if not profits:
            return {
                "method": "simple_average_profit",
                "forecast_profit": Decimal("0.00"),
                "confidence": "low",
            }

        average = sum(profits, Decimal("0.00")) / Decimal(len(profits))
        return {
            "method": "simple_average_profit",
            "forecast_profit": average.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP),
            "confidence": "medium" if len(profits) >= 3 else "low",
        }

    def _forecast_subscription_revenue(
        self,
        mrr: Decimal,
        churn_rate_percent: Decimal,
        months_ahead: int = 12,
    ) -> Dict[str, Any]:
        monthly_churn = churn_rate_percent / Decimal("100")
        projected: List[Dict[str, Any]] = []
        current_mrr = mrr

        for month in range(1, months_ahead + 1):
            current_mrr = current_mrr * (Decimal("1.00") - monthly_churn)
            projected.append(
                {
                    "month": month,
                    "projected_mrr": current_mrr.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP),
                }
            )

        return {
            "method": "mrr_churn_decay",
            "months_ahead": months_ahead,
            "starting_mrr": mrr,
            "assumed_monthly_churn_percent": churn_rate_percent,
            "projected": projected,
            "confidence": "low",
        }

    def _cash_flow_health(
        self,
        net_cash_flow: Decimal,
        inflow: Decimal,
        outflow: Decimal,
    ) -> Dict[str, Any]:
        if net_cash_flow > Decimal("0.00"):
            status = "healthy"
            message = "Cash inflow is higher than cash outflow."
        elif net_cash_flow == Decimal("0.00"):
            status = "neutral"
            message = "Cash inflow and outflow are balanced."
        else:
            status = "negative"
            message = "Cash outflow is higher than cash inflow."

        burn_ratio = _safe_percent(outflow, inflow) if inflow else Decimal("0.00")

        return {
            "status": status,
            "message": message,
            "burn_ratio_percent": burn_ratio,
        }

    def _profit_health(
        self,
        profit: Decimal,
        margin_percent: Decimal,
    ) -> Dict[str, Any]:
        if profit > Decimal("0.00") and margin_percent >= Decimal("20.00"):
            status = "strong"
            message = "Profit and margin are strong."
        elif profit > Decimal("0.00"):
            status = "positive"
            message = "Business is profitable, but margin can improve."
        elif profit == Decimal("0.00"):
            status = "break_even"
            message = "Business is around break-even."
        else:
            status = "loss"
            message = "Business is currently reporting a loss."

        return {
            "status": status,
            "message": message,
            "profit": profit,
            "profit_margin_percent": margin_percent,
        }

    def _subscription_risk_flags(
        self,
        subscriptions: Sequence[NormalizedSubscription],
    ) -> List[Dict[str, Any]]:
        flags: List[Dict[str, Any]] = []

        past_due = [sub for sub in subscriptions if sub.status == SubscriptionStatus.PAST_DUE.value]
        canceled = [sub for sub in subscriptions if sub.status == SubscriptionStatus.CANCELED.value]
        unknown = [sub for sub in subscriptions if sub.status == SubscriptionStatus.UNKNOWN.value]

        if past_due:
            flags.append(
                {
                    "type": "past_due_revenue",
                    "severity": "medium",
                    "count": len(past_due),
                    "message": "Some subscriptions are past due.",
                }
            )

        if canceled:
            flags.append(
                {
                    "type": "canceled_subscriptions",
                    "severity": "medium",
                    "count": len(canceled),
                    "message": "Canceled subscriptions are present in the reporting period.",
                }
            )

        if unknown:
            flags.append(
                {
                    "type": "unknown_subscription_status",
                    "severity": "low",
                    "count": len(unknown),
                    "message": "Some subscriptions have unknown status.",
                }
            )

        return flags

    def _build_executive_summary(self, combined_data: Mapping[str, Any]) -> Dict[str, Any]:
        pnl = combined_data.get("profit_loss", {}).get("summary", {})
        cash = combined_data.get("cash_flow", {}).get("summary", {})
        subs = combined_data.get("subscriptions", {}).get("summary", {})

        gross_profit = _to_decimal(pnl.get("gross_profit"))
        net_cash_flow = _to_decimal(cash.get("net_cash_flow"))
        mrr = _to_decimal(subs.get("mrr"))
        margin = _to_decimal(pnl.get("profit_margin_percent"))

        highlights: List[str] = []
        risks: List[str] = []

        if gross_profit > Decimal("0.00"):
            highlights.append("Profit/loss report shows positive gross profit.")
        else:
            risks.append("Profit/loss report does not show positive gross profit.")

        if net_cash_flow > Decimal("0.00"):
            highlights.append("Cash flow is positive for the selected period.")
        else:
            risks.append("Cash flow is not positive for the selected period.")

        if mrr > Decimal("0.00"):
            highlights.append("Subscription MRR is active.")
        else:
            risks.append("No active subscription MRR detected.")

        if margin < Decimal("10.00"):
            risks.append("Profit margin is below 10%.")

        return {
            "gross_profit": gross_profit,
            "net_cash_flow": net_cash_flow,
            "mrr": mrr,
            "profit_margin_percent": margin,
            "highlights": highlights,
            "risks": risks,
        }

    # ------------------------------------------------------------------
    # Export helpers
    # ------------------------------------------------------------------

    def _report_to_csv(self, report_data: Mapping[str, Any]) -> str:
        """
        Flatten report data into CSV.

        This produces a simple key/path/value export suitable for dashboards
        and admin downloads.
        """
        rows: List[Tuple[str, Any]] = []

        def walk(prefix: str, value: Any) -> None:
            if isinstance(value, Mapping):
                for key, child in value.items():
                    child_prefix = f"{prefix}.{key}" if prefix else str(key)
                    walk(child_prefix, child)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    child_prefix = f"{prefix}[{index}]"
                    walk(child_prefix, child)
            else:
                rows.append((prefix, value))

        walk("", report_data)

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["path", "value"])
        for key, value in rows:
            writer.writerow([key, value])

        return output.getvalue()

    def _build_export_filename(
        self,
        context: FinanceContext,
        request: ReportRequest,
        extension: str,
    ) -> str:
        today = _utc_now().strftime("%Y%m%d")
        safe_report_type = request.report_type.replace("/", "_")
        safe_workspace = context.workspace_id.replace("/", "_")[:32]
        return f"{safe_report_type}_{safe_workspace}_{today}.{extension}"

    # ------------------------------------------------------------------
    # Metadata and serialization
    # ------------------------------------------------------------------

    def _base_metadata(
        self,
        context: FinanceContext,
        request: Optional[ReportRequest] = None,
    ) -> Dict[str, Any]:
        metadata = {
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "registry_name": self.registry_name,
            "version": self.version,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "correlation_id": context.correlation_id,
            "generated_at": _utc_now().isoformat(),
            "safe_mode": True,
            "real_financial_action_executed": False,
        }

        if request:
            metadata.update(
                {
                    "report_type": request.report_type,
                    "period": request.period,
                    "currency": request.currency,
                    "start_date": request.start_date.isoformat() if request.start_date else None,
                    "end_date": request.end_date.isoformat() if request.end_date else None,
                }
            )

        return metadata

    def _date_range_payload(self, request: ReportRequest) -> Dict[str, Optional[str]]:
        return {
            "start_date": request.start_date.isoformat() if request.start_date else None,
            "end_date": request.end_date.isoformat() if request.end_date else None,
            "period": request.period,
        }

    def _serialize_error(self, error: Any) -> Optional[Dict[str, Any]]:
        if error is None:
            return None

        if isinstance(error, BaseException):
            return {
                "type": error.__class__.__name__,
                "message": str(error),
            }

        if isinstance(error, Mapping):
            return dict(error)

        return {
            "type": "Error",
            "message": str(error),
        }

    def _load_default_config(self) -> Dict[str, Any]:
        if FinanceReportConfig is not None:
            try:
                config = FinanceReportConfig()  # type: ignore
                if hasattr(config, "dict"):
                    return config.dict()
                if hasattr(config, "__dict__"):
                    return dict(config.__dict__)
            except Exception:
                pass

        return {
            "default_currency": DEFAULT_CURRENCY,
            "supported_report_types": sorted(SUPPORTED_REPORT_TYPES),
            "allowed_periods": sorted(ALLOWED_PERIODS),
            "safe_export_formats": sorted(SAFE_EXPORT_FORMATS),
            "sensitive_report_types": sorted(SENSITIVE_REPORT_TYPES),
            "requires_security_for_export": True,
            "requires_security_for_sensitive_breakdown": True,
        }

    # ------------------------------------------------------------------
    # Registry / loader helpers
    # ------------------------------------------------------------------

    def get_registry_metadata(self) -> Dict[str, Any]:
        """
        Return Agent Registry-compatible metadata.
        """
        return {
            "agent_name": self.agent_name,
            "agent_type": self.agent_type,
            "registry_name": self.registry_name,
            "version": self.version,
            "module": __name__,
            "class_name": self.__class__.__name__,
            "capabilities": [
                "finance.reports.revenue",
                "finance.reports.expenses",
                "finance.reports.cash_flow",
                "finance.reports.profit_loss",
                "finance.reports.subscriptions",
                "finance.reports.dashboard_summary",
                "finance.reports.combined",
                "finance.reports.export_json",
                "finance.reports.export_csv",
            ],
            "requires_context": ["user_id", "workspace_id"],
            "requires_security_agent": True,
            "supports_memory_agent": True,
            "supports_verification_agent": True,
            "safe_to_import": True,
            "executes_real_financial_actions": False,
        }

    def health_check(self) -> Dict[str, Any]:
        """
        Simple import/runtime health check for dashboard/API monitoring.
        """
        return self._safe_result(
            success=True,
            message="FinanceReports is healthy.",
            data={
                "agent": self.agent_name,
                "version": self.version,
                "supported_report_types": sorted(SUPPORTED_REPORT_TYPES),
                "allowed_periods": sorted(ALLOWED_PERIODS),
                "safe_export_formats": sorted(SAFE_EXPORT_FORMATS),
            },
            metadata={
                "checked_at": _utc_now().isoformat(),
            },
        )


# ---------------------------------------------------------------------------
# Module-level factory for Agent Loader compatibility
# ---------------------------------------------------------------------------

def create_agent(*args: Any, **kwargs: Any) -> FinanceReports:
    """
    Agent Loader factory.

    Allows dynamic loaders to instantiate this file without knowing the class
    constructor details.
    """
    return FinanceReports(*args, **kwargs)


def get_agent_metadata() -> Dict[str, Any]:
    """
    Module-level registry metadata helper.
    """
    return FinanceReports().get_registry_metadata()


__all__ = [
    "FinanceReports",
    "FinanceContext",
    "ReportRequest",
    "NormalizedTransaction",
    "NormalizedSubscription",
    "ReportSummary",
    "FinanceReportType",
    "ReportPeriod",
    "TransactionKind",
    "SubscriptionStatus",
    "create_agent",
    "get_agent_metadata",
]


if __name__ == "__main__":
    # Safe local smoke test. No real financial action is executed.
    agent = FinanceReports()
    sample_task = {
        "user_id": "user_demo",
        "workspace_id": "workspace_demo",
        "permissions": ["finance_reports:read_sensitive"],
        "report_type": "combined",
        "period": "monthly",
        "currency": "USD",
        "include_forecast": True,
        "transactions": [
            {
                "id": "txn_001",
                "user_id": "user_demo",
                "workspace_id": "workspace_demo",
                "type": "revenue",
                "amount": "1500.00",
                "currency": "USD",
                "date": "2026-01-10",
                "category": "web_design",
                "source": "invoice",
                "client_id": "client_001",
            },
            {
                "id": "txn_002",
                "user_id": "user_demo",
                "workspace_id": "workspace_demo",
                "type": "expense",
                "amount": "300.00",
                "currency": "USD",
                "date": "2026-01-12",
                "category": "software",
                "source": "manual",
            },
            {
                "id": "txn_003",
                "user_id": "user_demo",
                "workspace_id": "workspace_demo",
                "type": "revenue",
                "amount": "2500.00",
                "currency": "USD",
                "date": "2026-02-03",
                "category": "seo",
                "source": "invoice",
                "client_id": "client_002",
            },
        ],
        "subscriptions": [
            {
                "id": "sub_001",
                "user_id": "user_demo",
                "workspace_id": "workspace_demo",
                "customer_id": "client_003",
                "plan": "Growth",
                "status": "active",
                "amount": "199.00",
                "currency": "USD",
                "interval": "monthly",
                "started_at": "2026-01-01",
            }
        ],
    }

    print(json.dumps(agent.run(sample_task), indent=2))