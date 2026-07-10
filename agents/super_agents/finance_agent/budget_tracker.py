"""
agents/super_agents/finance_agent/budget_tracker.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Finance Agent Module - Budget Tracker

Purpose:
    Tracks budgets, categories, limits, spending, remaining amounts, and burn rates.

Architecture Compatibility:
    - Master Agent routing compatible
    - BaseAgent compatible with fallback stub
    - Agent Registry / Agent Loader safe import
    - SaaS user_id/workspace_id isolation enforced
    - Security Agent approval hooks included for sensitive budget actions
    - Memory Agent payload preparation included
    - Verification Agent payload preparation included
    - Dashboard/API-ready structured responses
    - Import-safe even if other William/Jarvis modules are not created yet

Safety:
    This module never performs real payments, transfers, bank actions, or destructive
    financial actions outside local budget tracking structures. Sensitive actions
    are routed through security approval hooks.
"""

from __future__ import annotations

import copy
import logging
import math
import uuid
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for import-safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe if the real William/Jarvis BaseAgent
        has not been generated yet.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)

        async def run(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() is not implemented.",
                "data": {},
                "error": "BASE_AGENT_NOT_AVAILABLE",
                "metadata": {},
            }


try:
    from agents.super_agents.finance_agent.config import FinanceAgentConfig  # type: ignore
except Exception:  # pragma: no cover - fallback for import-safety
    class FinanceAgentConfig:  # type: ignore
        """
        Fallback FinanceAgentConfig.

        The future config.py may override these defaults.
        """

        DEFAULT_CURRENCY = "USD"
        DEFAULT_BUDGET_PERIOD = "monthly"
        MONEY_DECIMAL_PLACES = 2
        BUDGET_WARNING_THRESHOLD_PERCENT = Decimal("80")
        BUDGET_CRITICAL_THRESHOLD_PERCENT = Decimal("95")
        DEFAULT_SECURITY_REQUIRED_ACTIONS = {
            "delete_budget",
            "delete_category",
            "record_spend_over_limit",
            "reset_budget",
            "bulk_import_budgets",
        }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MONEY_QUANT = Decimal("0.01")
PERCENT_QUANT = Decimal("0.01")
DEFAULT_AGENT_NAME = "BudgetTracker"
DEFAULT_AGENT_TYPE = "finance_budget_tracker"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class BudgetPeriod(str, Enum):
    """Supported budget periods."""

    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"
    CUSTOM = "custom"


class BudgetStatus(str, Enum):
    """Budget lifecycle status."""

    ACTIVE = "active"
    PAUSED = "paused"
    CLOSED = "closed"
    ARCHIVED = "archived"


class BudgetAlertLevel(str, Enum):
    """Budget alert severity."""

    OK = "ok"
    WARNING = "warning"
    CRITICAL = "critical"
    EXCEEDED = "exceeded"


class SpendType(str, Enum):
    """Tracked spend transaction type."""

    EXPENSE = "expense"
    ADJUSTMENT = "adjustment"
    REFUND = "refund"
    REVERSAL = "reversal"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class BudgetCategory:
    """
    A single category inside a budget.

    Categories are scoped inside one budget and one user/workspace context.
    """

    category_id: str
    name: str
    limit_amount: Decimal
    spent_amount: Decimal = Decimal("0.00")
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: _utc_now_iso())
    updated_at: str = field(default_factory=lambda: _utc_now_iso())

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["limit_amount"] = _money_to_str(self.limit_amount)
        payload["spent_amount"] = _money_to_str(self.spent_amount)
        payload["remaining_amount"] = _money_to_str(self.remaining_amount)
        payload["usage_percent"] = _decimal_to_str(self.usage_percent)
        payload["alert_level"] = self.alert_level.value
        return payload

    @property
    def remaining_amount(self) -> Decimal:
        return _safe_money(self.limit_amount - self.spent_amount)

    @property
    def usage_percent(self) -> Decimal:
        if self.limit_amount <= Decimal("0"):
            return Decimal("0.00")
        return _safe_percent((self.spent_amount / self.limit_amount) * Decimal("100"))

    @property
    def alert_level(self) -> BudgetAlertLevel:
        if self.spent_amount > self.limit_amount:
            return BudgetAlertLevel.EXCEEDED

        usage = self.usage_percent
        warning_threshold = _to_decimal(
            getattr(FinanceAgentConfig, "BUDGET_WARNING_THRESHOLD_PERCENT", Decimal("80")),
            default=Decimal("80"),
        )
        critical_threshold = _to_decimal(
            getattr(FinanceAgentConfig, "BUDGET_CRITICAL_THRESHOLD_PERCENT", Decimal("95")),
            default=Decimal("95"),
        )

        if usage >= critical_threshold:
            return BudgetAlertLevel.CRITICAL
        if usage >= warning_threshold:
            return BudgetAlertLevel.WARNING
        return BudgetAlertLevel.OK


@dataclass
class BudgetSpendRecord:
    """
    A budget spend record.

    This is an internal ledger-style tracking record only. It does not execute
    payments or interact with financial providers.
    """

    spend_id: str
    budget_id: str
    category_id: str
    amount: Decimal
    spend_type: SpendType
    description: str = ""
    source_reference: Optional[str] = None
    transaction_date: str = field(default_factory=lambda: date.today().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: _utc_now_iso())
    created_by: Optional[str] = None
    reversed_spend_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["amount"] = _money_to_str(self.amount)
        payload["spend_type"] = self.spend_type.value
        return payload


@dataclass
class Budget:
    """
    Budget container.

    Budget records are always scoped by user_id and workspace_id.
    """

    budget_id: str
    user_id: str
    workspace_id: str
    name: str
    total_limit: Decimal
    currency: str
    period: BudgetPeriod = BudgetPeriod.MONTHLY
    status: BudgetStatus = BudgetStatus.ACTIVE
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    categories: Dict[str, BudgetCategory] = field(default_factory=dict)
    spend_records: Dict[str, BudgetSpendRecord] = field(default_factory=dict)
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: _utc_now_iso())
    updated_at: str = field(default_factory=lambda: _utc_now_iso())

    def to_dict(self, include_spend_records: bool = True) -> Dict[str, Any]:
        payload = asdict(self)
        payload["total_limit"] = _money_to_str(self.total_limit)
        payload["period"] = self.period.value
        payload["status"] = self.status.value
        payload["spent_amount"] = _money_to_str(self.spent_amount)
        payload["remaining_amount"] = _money_to_str(self.remaining_amount)
        payload["usage_percent"] = _decimal_to_str(self.usage_percent)
        payload["alert_level"] = self.alert_level.value
        payload["category_count"] = len(self.categories)
        payload["spend_record_count"] = len(self.spend_records)
        payload["categories"] = {
            category_id: category.to_dict()
            for category_id, category in self.categories.items()
        }

        if include_spend_records:
            payload["spend_records"] = {
                spend_id: spend_record.to_dict()
                for spend_id, spend_record in self.spend_records.items()
            }
        else:
            payload["spend_records"] = {}

        return payload

    @property
    def spent_amount(self) -> Decimal:
        return _safe_money(sum((c.spent_amount for c in self.categories.values()), Decimal("0")))

    @property
    def remaining_amount(self) -> Decimal:
        return _safe_money(self.total_limit - self.spent_amount)

    @property
    def allocated_amount(self) -> Decimal:
        return _safe_money(sum((c.limit_amount for c in self.categories.values()), Decimal("0")))

    @property
    def unallocated_amount(self) -> Decimal:
        return _safe_money(self.total_limit - self.allocated_amount)

    @property
    def usage_percent(self) -> Decimal:
        if self.total_limit <= Decimal("0"):
            return Decimal("0.00")
        return _safe_percent((self.spent_amount / self.total_limit) * Decimal("100"))

    @property
    def alert_level(self) -> BudgetAlertLevel:
        if self.spent_amount > self.total_limit:
            return BudgetAlertLevel.EXCEEDED

        usage = self.usage_percent
        warning_threshold = _to_decimal(
            getattr(FinanceAgentConfig, "BUDGET_WARNING_THRESHOLD_PERCENT", Decimal("80")),
            default=Decimal("80"),
        )
        critical_threshold = _to_decimal(
            getattr(FinanceAgentConfig, "BUDGET_CRITICAL_THRESHOLD_PERCENT", Decimal("95")),
            default=Decimal("95"),
        )

        if usage >= critical_threshold:
            return BudgetAlertLevel.CRITICAL
        if usage >= warning_threshold:
            return BudgetAlertLevel.WARNING
        return BudgetAlertLevel.OK


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex}"


def _to_decimal(value: Any, default: Decimal = Decimal("0.00")) -> Decimal:
    if isinstance(value, Decimal):
        return value

    if value is None:
        return default

    try:
        return Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError):
        return default


def _safe_money(value: Any) -> Decimal:
    decimal_value = _to_decimal(value)
    return decimal_value.quantize(MONEY_QUANT, rounding=ROUND_HALF_UP)


def _safe_percent(value: Any) -> Decimal:
    decimal_value = _to_decimal(value)
    if decimal_value.is_nan() or decimal_value.is_infinite():
        return Decimal("0.00")
    return decimal_value.quantize(PERCENT_QUANT, rounding=ROUND_HALF_UP)


def _money_to_str(value: Decimal) -> str:
    return str(_safe_money(value))


def _decimal_to_str(value: Decimal) -> str:
    return str(_safe_percent(value))


def _normalize_currency(currency: Optional[str]) -> str:
    selected = currency or getattr(FinanceAgentConfig, "DEFAULT_CURRENCY", "USD")
    selected = str(selected).upper().strip()
    if not selected:
        return "USD"
    return selected[:12]


def _normalize_text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return str(value).strip()


def _safe_metadata(metadata: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    if not metadata:
        return {}
    safe: Dict[str, Any] = {}
    for key, value in metadata.items():
        safe_key = str(key).strip()
        if safe_key:
            safe[safe_key] = copy.deepcopy(value)
    return safe


def _parse_period(value: Any) -> BudgetPeriod:
    if isinstance(value, BudgetPeriod):
        return value
    raw = str(value or getattr(FinanceAgentConfig, "DEFAULT_BUDGET_PERIOD", "monthly")).strip().lower()
    for period in BudgetPeriod:
        if raw == period.value:
            return period
    return BudgetPeriod.MONTHLY


def _parse_status(value: Any) -> BudgetStatus:
    if isinstance(value, BudgetStatus):
        return value
    raw = str(value or BudgetStatus.ACTIVE.value).strip().lower()
    for status in BudgetStatus:
        if raw == status.value:
            return status
    return BudgetStatus.ACTIVE


def _parse_spend_type(value: Any) -> SpendType:
    if isinstance(value, SpendType):
        return value
    raw = str(value or SpendType.EXPENSE.value).strip().lower()
    for spend_type in SpendType:
        if raw == spend_type.value:
            return spend_type
    return SpendType.EXPENSE


def _date_or_none(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None

    if isinstance(value, date):
        return value.isoformat()

    raw = str(value).strip()
    try:
        date.fromisoformat(raw)
        return raw
    except ValueError:
        return None


def _days_between(start_date: Optional[str], end_date: Optional[str]) -> Optional[int]:
    if not start_date or not end_date:
        return None
    try:
        start = date.fromisoformat(start_date)
        end = date.fromisoformat(end_date)
    except ValueError:
        return None

    delta = (end - start).days + 1
    if delta <= 0:
        return None
    return delta


def _days_elapsed(start_date: Optional[str], as_of_date: Optional[str] = None) -> Optional[int]:
    if not start_date:
        return None

    try:
        start = date.fromisoformat(start_date)
        current = date.fromisoformat(as_of_date) if as_of_date else date.today()
    except ValueError:
        return None

    delta = (current - start).days + 1
    if delta <= 0:
        return 0
    return delta


# ---------------------------------------------------------------------------
# Budget Tracker
# ---------------------------------------------------------------------------

class BudgetTracker(BaseAgent):
    """
    Tracks budgets, categories, limits, spending, remaining balances, and burn rates.

    This class is designed to sit under the Finance Agent. The Master Agent can
    route budget-related tasks here, while Security Agent, Memory Agent, and
    Verification Agent can consume the structured payload hooks.

    Storage:
        By default, this class uses isolated in-memory storage:
            user_id -> workspace_id -> budget_id -> Budget

        Production systems can wrap these methods with a database repository
        later without changing public interfaces.

    Important:
        This tracker does not execute real financial actions. It only prepares
        and tracks budget information safely.
    """

    agent_name = DEFAULT_AGENT_NAME
    agent_type = DEFAULT_AGENT_TYPE
    registry_metadata = {
        "name": DEFAULT_AGENT_NAME,
        "type": DEFAULT_AGENT_TYPE,
        "module": "finance_agent",
        "file_path": "agents/super_agents/finance_agent/budget_tracker.py",
        "class_name": "BudgetTracker",
        "description": "Tracks budgets, categories, limits, spending, and burn rates.",
        "safe_import": True,
        "requires_user_workspace": True,
        "performs_real_financial_actions": False,
    }

    def __init__(
        self,
        storage: Optional[Dict[str, Dict[str, Dict[str, Budget]]]] = None,
        security_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        config: Optional[Any] = None,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        try:
            super().__init__(*args, agent_name=self.agent_name, **kwargs)
        except TypeError:
            try:
                super().__init__(*args, **kwargs)
            except Exception:
                BaseAgent.__init__(self)

        self.storage: Dict[str, Dict[str, Dict[str, Budget]]] = storage if storage is not None else {}
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.audit_logger = audit_logger
        self.event_bus = event_bus
        self.config = config or FinanceAgentConfig

        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    # ---------------------------------------------------------------------
    # Base/Master Agent entrypoint
    # ---------------------------------------------------------------------

    async def run(self, task: Mapping[str, Any], context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """
        Master Agent compatible async entrypoint.

        Expected task format:
            {
                "action": "create_budget",
                "payload": {...}
            }

        The context must contain user_id and workspace_id for user-specific work.
        """

        context_dict = dict(context or {})
        task_dict = dict(task or {})
        action = _normalize_text(task_dict.get("action")).lower()
        payload = task_dict.get("payload") or {}

        if not isinstance(payload, Mapping):
            return self._error_result(
                message="Task payload must be a dictionary.",
                error="INVALID_TASK_PAYLOAD",
                metadata={"action": action},
            )

        handlers = {
            "create_budget": self.create_budget,
            "update_budget": self.update_budget,
            "delete_budget": self.delete_budget,
            "add_category": self.add_category,
            "update_category": self.update_category,
            "delete_category": self.delete_category,
            "record_spend": self.record_spend,
            "reverse_spend": self.reverse_spend,
            "get_budget": self.get_budget,
            "list_budgets": self.list_budgets,
            "get_budget_summary": self.get_budget_summary,
            "get_burn_rate": self.get_burn_rate,
            "check_limits": self.check_limits,
            "export_dashboard_payload": self.export_dashboard_payload,
        }

        handler = handlers.get(action)
        if handler is None:
            return self._error_result(
                message=f"Unsupported budget tracker action: {action or 'missing'}",
                error="UNSUPPORTED_ACTION",
                metadata={
                    "supported_actions": sorted(handlers.keys()),
                    "agent": self.agent_name,
                },
            )

        try:
            return handler(context=context_dict, **dict(payload))
        except TypeError as exc:
            self.logger.exception("Invalid handler arguments for action %s", action)
            return self._error_result(
                message="Invalid arguments for budget tracker action.",
                error="INVALID_ACTION_ARGUMENTS",
                metadata={"action": action, "details": str(exc)},
            )
        except Exception as exc:
            self.logger.exception("Budget tracker action failed: %s", action)
            return self._error_result(
                message="Budget tracker action failed.",
                error="BUDGET_TRACKER_ACTION_FAILED",
                metadata={"action": action, "details": str(exc)},
            )

    # ---------------------------------------------------------------------
    # Public budget methods
    # ---------------------------------------------------------------------

    def create_budget(
        self,
        context: Mapping[str, Any],
        name: str,
        total_limit: Union[str, int, float, Decimal],
        currency: Optional[str] = None,
        period: Union[str, BudgetPeriod] = BudgetPeriod.MONTHLY,
        start_date: Optional[Any] = None,
        end_date: Optional[Any] = None,
        categories: Optional[Iterable[Mapping[str, Any]]] = None,
        description: str = "",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a new budget for a user/workspace.

        Categories may be provided as:
            [
                {"name": "Ads", "limit_amount": "500"},
                {"name": "Tools", "limit_amount": "100"}
            ]
        """

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        clean_name = _normalize_text(name)
        if not clean_name:
            return self._error_result("Budget name is required.", "BUDGET_NAME_REQUIRED")

        clean_limit = _safe_money(total_limit)
        if clean_limit <= Decimal("0"):
            return self._error_result("Budget total_limit must be greater than zero.", "INVALID_BUDGET_LIMIT")

        clean_start = _date_or_none(start_date)
        clean_end = _date_or_none(end_date)

        if start_date and clean_start is None:
            return self._error_result("Invalid start_date. Use YYYY-MM-DD.", "INVALID_START_DATE")

        if end_date and clean_end is None:
            return self._error_result("Invalid end_date. Use YYYY-MM-DD.", "INVALID_END_DATE")

        if clean_start and clean_end:
            try:
                if date.fromisoformat(clean_end) < date.fromisoformat(clean_start):
                    return self._error_result("end_date cannot be before start_date.", "INVALID_DATE_RANGE")
            except ValueError:
                return self._error_result("Invalid budget date range.", "INVALID_DATE_RANGE")

        budget_id = _new_id("budget")
        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])

        budget = Budget(
            budget_id=budget_id,
            user_id=user_id,
            workspace_id=workspace_id,
            name=clean_name,
            total_limit=clean_limit,
            currency=_normalize_currency(currency),
            period=_parse_period(period),
            start_date=clean_start,
            end_date=clean_end,
            description=_normalize_text(description),
            metadata=_safe_metadata(metadata),
        )

        category_errors: List[Dict[str, Any]] = []
        if categories:
            for index, category_input in enumerate(categories):
                if not isinstance(category_input, Mapping):
                    category_errors.append({"index": index, "error": "CATEGORY_MUST_BE_DICT"})
                    continue

                category_name = _normalize_text(category_input.get("name"))
                category_limit = _safe_money(category_input.get("limit_amount"))

                if not category_name:
                    category_errors.append({"index": index, "error": "CATEGORY_NAME_REQUIRED"})
                    continue

                if category_limit < Decimal("0"):
                    category_errors.append({"index": index, "error": "CATEGORY_LIMIT_CANNOT_BE_NEGATIVE"})
                    continue

                category_id = _new_id("cat")
                budget.categories[category_id] = BudgetCategory(
                    category_id=category_id,
                    name=category_name,
                    limit_amount=category_limit,
                    description=_normalize_text(category_input.get("description")),
                    metadata=_safe_metadata(category_input.get("metadata") if isinstance(category_input.get("metadata"), Mapping) else None),
                )

        if budget.allocated_amount > budget.total_limit:
            return self._error_result(
                message="Category allocations exceed the total budget limit.",
                error="CATEGORY_ALLOCATIONS_EXCEED_BUDGET",
                data={
                    "total_limit": _money_to_str(budget.total_limit),
                    "allocated_amount": _money_to_str(budget.allocated_amount),
                    "excess_amount": _money_to_str(budget.allocated_amount - budget.total_limit),
                    "category_errors": category_errors,
                },
            )

        self._set_budget(budget)

        verification_payload = self._prepare_verification_payload(
            action="create_budget",
            context=context,
            resource_id=budget_id,
            data=budget.to_dict(include_spend_records=False),
        )
        memory_payload = self._prepare_memory_payload(
            action="create_budget",
            context=context,
            data={
                "budget_id": budget_id,
                "name": budget.name,
                "total_limit": _money_to_str(budget.total_limit),
                "currency": budget.currency,
                "period": budget.period.value,
            },
        )

        self._log_audit_event(
            action="create_budget",
            context=context,
            resource_id=budget_id,
            details={"budget_name": budget.name, "total_limit": _money_to_str(budget.total_limit)},
        )
        self._emit_agent_event(
            event_type="budget.created",
            context=context,
            payload={"budget_id": budget_id, "name": budget.name},
        )

        return self._safe_result(
            message="Budget created successfully.",
            data={
                "budget": budget.to_dict(include_spend_records=False),
                "category_errors": category_errors,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata=self._result_metadata(context=context, action="create_budget"),
        )

    def update_budget(
        self,
        context: Mapping[str, Any],
        budget_id: str,
        name: Optional[str] = None,
        total_limit: Optional[Union[str, int, float, Decimal]] = None,
        currency: Optional[str] = None,
        period: Optional[Union[str, BudgetPeriod]] = None,
        status: Optional[Union[str, BudgetStatus]] = None,
        start_date: Optional[Any] = None,
        end_date: Optional[Any] = None,
        description: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update budget fields safely."""

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        budget = self._get_budget_for_context(context, budget_id)
        if budget is None:
            return self._error_result("Budget not found for this user/workspace.", "BUDGET_NOT_FOUND")

        old_budget = budget.to_dict(include_spend_records=False)

        if name is not None:
            clean_name = _normalize_text(name)
            if not clean_name:
                return self._error_result("Budget name cannot be empty.", "BUDGET_NAME_REQUIRED")
            budget.name = clean_name

        if total_limit is not None:
            clean_limit = _safe_money(total_limit)
            if clean_limit <= Decimal("0"):
                return self._error_result("Budget total_limit must be greater than zero.", "INVALID_BUDGET_LIMIT")

            if budget.allocated_amount > clean_limit:
                return self._error_result(
                    message="New budget limit is lower than allocated category limits.",
                    error="TOTAL_LIMIT_BELOW_ALLOCATED_AMOUNT",
                    data={
                        "requested_total_limit": _money_to_str(clean_limit),
                        "allocated_amount": _money_to_str(budget.allocated_amount),
                    },
                )

            budget.total_limit = clean_limit

        if currency is not None:
            budget.currency = _normalize_currency(currency)

        if period is not None:
            budget.period = _parse_period(period)

        if status is not None:
            budget.status = _parse_status(status)

        if start_date is not None:
            clean_start = _date_or_none(start_date)
            if clean_start is None:
                return self._error_result("Invalid start_date. Use YYYY-MM-DD.", "INVALID_START_DATE")
            budget.start_date = clean_start

        if end_date is not None:
            clean_end = _date_or_none(end_date)
            if clean_end is None:
                return self._error_result("Invalid end_date. Use YYYY-MM-DD.", "INVALID_END_DATE")
            budget.end_date = clean_end

        if budget.start_date and budget.end_date:
            try:
                if date.fromisoformat(budget.end_date) < date.fromisoformat(budget.start_date):
                    return self._error_result("end_date cannot be before start_date.", "INVALID_DATE_RANGE")
            except ValueError:
                return self._error_result("Invalid budget date range.", "INVALID_DATE_RANGE")

        if description is not None:
            budget.description = _normalize_text(description)

        if metadata is not None:
            budget.metadata.update(_safe_metadata(metadata))

        budget.updated_at = _utc_now_iso()
        self._set_budget(budget)

        verification_payload = self._prepare_verification_payload(
            action="update_budget",
            context=context,
            resource_id=budget.budget_id,
            data={"before": old_budget, "after": budget.to_dict(include_spend_records=False)},
        )

        memory_payload = self._prepare_memory_payload(
            action="update_budget",
            context=context,
            data={
                "budget_id": budget.budget_id,
                "name": budget.name,
                "total_limit": _money_to_str(budget.total_limit),
                "status": budget.status.value,
            },
        )

        self._log_audit_event(
            action="update_budget",
            context=context,
            resource_id=budget.budget_id,
            details={"updated_fields": self._provided_fields(locals())},
        )
        self._emit_agent_event(
            event_type="budget.updated",
            context=context,
            payload={"budget_id": budget.budget_id, "name": budget.name},
        )

        return self._safe_result(
            message="Budget updated successfully.",
            data={
                "budget": budget.to_dict(include_spend_records=False),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata=self._result_metadata(context=context, action="update_budget"),
        )

    def delete_budget(
        self,
        context: Mapping[str, Any],
        budget_id: str,
        hard_delete: bool = False,
        reason: str = "",
    ) -> Dict[str, Any]:
        """
        Archive or delete a budget.

        Default behavior is safe archive. hard_delete requires security approval.
        """

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        budget = self._get_budget_for_context(context, budget_id)
        if budget is None:
            return self._error_result("Budget not found for this user/workspace.", "BUDGET_NOT_FOUND")

        action = "delete_budget"
        if self._requires_security_check(action=action, context=context, payload={"budget_id": budget_id, "hard_delete": hard_delete}):
            approval = self._request_security_approval(
                action=action,
                context=context,
                payload={
                    "budget_id": budget_id,
                    "hard_delete": hard_delete,
                    "reason": reason,
                    "risk": "Budget deletion can remove or hide financial planning records.",
                },
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval is required before deleting this budget.",
                    error="SECURITY_APPROVAL_REQUIRED",
                    data={"approval": approval},
                    metadata=self._result_metadata(context=context, action=action),
                )

        before = budget.to_dict(include_spend_records=True)

        if hard_delete:
            self._delete_budget_from_storage(context, budget_id)
            message = "Budget permanently deleted from local tracker storage."
            event_type = "budget.deleted"
        else:
            budget.status = BudgetStatus.ARCHIVED
            budget.updated_at = _utc_now_iso()
            self._set_budget(budget)
            message = "Budget archived successfully."
            event_type = "budget.archived"

        verification_payload = self._prepare_verification_payload(
            action=action,
            context=context,
            resource_id=budget_id,
            data={"before": before, "hard_delete": hard_delete, "reason": reason},
        )

        self._log_audit_event(
            action=action,
            context=context,
            resource_id=budget_id,
            details={"hard_delete": hard_delete, "reason": reason},
        )
        self._emit_agent_event(
            event_type=event_type,
            context=context,
            payload={"budget_id": budget_id, "hard_delete": hard_delete},
        )

        return self._safe_result(
            message=message,
            data={"budget_id": budget_id, "hard_delete": hard_delete, "verification_payload": verification_payload},
            metadata=self._result_metadata(context=context, action=action),
        )

    def get_budget(
        self,
        context: Mapping[str, Any],
        budget_id: str,
        include_spend_records: bool = True,
    ) -> Dict[str, Any]:
        """Return one budget by ID."""

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        budget = self._get_budget_for_context(context, budget_id)
        if budget is None:
            return self._error_result("Budget not found for this user/workspace.", "BUDGET_NOT_FOUND")

        return self._safe_result(
            message="Budget retrieved successfully.",
            data={"budget": budget.to_dict(include_spend_records=include_spend_records)},
            metadata=self._result_metadata(context=context, action="get_budget"),
        )

    def list_budgets(
        self,
        context: Mapping[str, Any],
        status: Optional[Union[str, BudgetStatus]] = None,
        include_archived: bool = False,
        include_spend_records: bool = False,
    ) -> Dict[str, Any]:
        """List budgets for the current user/workspace only."""

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        budgets = list(self._workspace_budgets(context).values())

        if status is not None:
            selected_status = _parse_status(status)
            budgets = [budget for budget in budgets if budget.status == selected_status]
        elif not include_archived:
            budgets = [budget for budget in budgets if budget.status != BudgetStatus.ARCHIVED]

        budgets_sorted = sorted(budgets, key=lambda item: item.created_at, reverse=True)

        return self._safe_result(
            message="Budgets listed successfully.",
            data={
                "budgets": [
                    budget.to_dict(include_spend_records=include_spend_records)
                    for budget in budgets_sorted
                ],
                "count": len(budgets_sorted),
            },
            metadata=self._result_metadata(context=context, action="list_budgets"),
        )

    # ---------------------------------------------------------------------
    # Public category methods
    # ---------------------------------------------------------------------

    def add_category(
        self,
        context: Mapping[str, Any],
        budget_id: str,
        name: str,
        limit_amount: Union[str, int, float, Decimal],
        description: str = "",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Add a category to a budget."""

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        budget = self._get_budget_for_context(context, budget_id)
        if budget is None:
            return self._error_result("Budget not found for this user/workspace.", "BUDGET_NOT_FOUND")

        clean_name = _normalize_text(name)
        if not clean_name:
            return self._error_result("Category name is required.", "CATEGORY_NAME_REQUIRED")

        clean_limit = _safe_money(limit_amount)
        if clean_limit < Decimal("0"):
            return self._error_result("Category limit cannot be negative.", "INVALID_CATEGORY_LIMIT")

        if any(category.name.lower() == clean_name.lower() for category in budget.categories.values()):
            return self._error_result("Category name already exists in this budget.", "CATEGORY_ALREADY_EXISTS")

        if budget.allocated_amount + clean_limit > budget.total_limit:
            return self._error_result(
                message="Adding this category exceeds the total budget limit.",
                error="CATEGORY_ALLOCATIONS_EXCEED_BUDGET",
                data={
                    "total_limit": _money_to_str(budget.total_limit),
                    "allocated_amount": _money_to_str(budget.allocated_amount),
                    "requested_category_limit": _money_to_str(clean_limit),
                    "available_unallocated_amount": _money_to_str(budget.unallocated_amount),
                },
            )

        category_id = _new_id("cat")
        category = BudgetCategory(
            category_id=category_id,
            name=clean_name,
            limit_amount=clean_limit,
            description=_normalize_text(description),
            metadata=_safe_metadata(metadata),
        )

        budget.categories[category_id] = category
        budget.updated_at = _utc_now_iso()
        self._set_budget(budget)

        verification_payload = self._prepare_verification_payload(
            action="add_category",
            context=context,
            resource_id=budget_id,
            data={"category": category.to_dict()},
        )

        self._log_audit_event(
            action="add_category",
            context=context,
            resource_id=budget_id,
            details={"category_id": category_id, "category_name": category.name},
        )
        self._emit_agent_event(
            event_type="budget.category_added",
            context=context,
            payload={"budget_id": budget_id, "category_id": category_id},
        )

        return self._safe_result(
            message="Budget category added successfully.",
            data={"budget": budget.to_dict(include_spend_records=False), "category": category.to_dict(), "verification_payload": verification_payload},
            metadata=self._result_metadata(context=context, action="add_category"),
        )

    def update_category(
        self,
        context: Mapping[str, Any],
        budget_id: str,
        category_id: str,
        name: Optional[str] = None,
        limit_amount: Optional[Union[str, int, float, Decimal]] = None,
        description: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update a budget category."""

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        budget = self._get_budget_for_context(context, budget_id)
        if budget is None:
            return self._error_result("Budget not found for this user/workspace.", "BUDGET_NOT_FOUND")

        category = budget.categories.get(str(category_id))
        if category is None:
            return self._error_result("Category not found in this budget.", "CATEGORY_NOT_FOUND")

        before = category.to_dict()

        if name is not None:
            clean_name = _normalize_text(name)
            if not clean_name:
                return self._error_result("Category name cannot be empty.", "CATEGORY_NAME_REQUIRED")

            duplicate = any(
                existing.category_id != category.category_id and existing.name.lower() == clean_name.lower()
                for existing in budget.categories.values()
            )
            if duplicate:
                return self._error_result("Category name already exists in this budget.", "CATEGORY_ALREADY_EXISTS")

            category.name = clean_name

        if limit_amount is not None:
            clean_limit = _safe_money(limit_amount)
            if clean_limit < Decimal("0"):
                return self._error_result("Category limit cannot be negative.", "INVALID_CATEGORY_LIMIT")

            other_allocated = budget.allocated_amount - category.limit_amount
            if other_allocated + clean_limit > budget.total_limit:
                return self._error_result(
                    message="Updated category limit exceeds total budget limit.",
                    error="CATEGORY_ALLOCATIONS_EXCEED_BUDGET",
                    data={
                        "total_limit": _money_to_str(budget.total_limit),
                        "other_allocated_amount": _money_to_str(other_allocated),
                        "requested_category_limit": _money_to_str(clean_limit),
                    },
                )

            category.limit_amount = clean_limit

        if description is not None:
            category.description = _normalize_text(description)

        if metadata is not None:
            category.metadata.update(_safe_metadata(metadata))

        category.updated_at = _utc_now_iso()
        budget.updated_at = _utc_now_iso()
        self._set_budget(budget)

        verification_payload = self._prepare_verification_payload(
            action="update_category",
            context=context,
            resource_id=budget_id,
            data={"category_id": category_id, "before": before, "after": category.to_dict()},
        )

        self._log_audit_event(
            action="update_category",
            context=context,
            resource_id=budget_id,
            details={"category_id": category_id, "updated_fields": self._provided_fields(locals())},
        )
        self._emit_agent_event(
            event_type="budget.category_updated",
            context=context,
            payload={"budget_id": budget_id, "category_id": category_id},
        )

        return self._safe_result(
            message="Budget category updated successfully.",
            data={"budget": budget.to_dict(include_spend_records=False), "category": category.to_dict(), "verification_payload": verification_payload},
            metadata=self._result_metadata(context=context, action="update_category"),
        )

    def delete_category(
        self,
        context: Mapping[str, Any],
        budget_id: str,
        category_id: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        """
        Delete a category from a budget.

        A category with spend records is sensitive because it can change reporting.
        """

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        budget = self._get_budget_for_context(context, budget_id)
        if budget is None:
            return self._error_result("Budget not found for this user/workspace.", "BUDGET_NOT_FOUND")

        category = budget.categories.get(str(category_id))
        if category is None:
            return self._error_result("Category not found in this budget.", "CATEGORY_NOT_FOUND")

        related_spend_count = len([
            record for record in budget.spend_records.values()
            if record.category_id == category_id
        ])

        if self._requires_security_check(
            action="delete_category",
            context=context,
            payload={"budget_id": budget_id, "category_id": category_id, "related_spend_count": related_spend_count},
        ):
            approval = self._request_security_approval(
                action="delete_category",
                context=context,
                payload={
                    "budget_id": budget_id,
                    "category_id": category_id,
                    "category_name": category.name,
                    "related_spend_count": related_spend_count,
                    "reason": reason,
                },
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval is required before deleting this category.",
                    error="SECURITY_APPROVAL_REQUIRED",
                    data={"approval": approval},
                    metadata=self._result_metadata(context=context, action="delete_category"),
                )

        before = category.to_dict()

        for spend_id in list(budget.spend_records.keys()):
            if budget.spend_records[spend_id].category_id == category_id:
                del budget.spend_records[spend_id]

        del budget.categories[category_id]
        budget.updated_at = _utc_now_iso()
        self._set_budget(budget)

        verification_payload = self._prepare_verification_payload(
            action="delete_category",
            context=context,
            resource_id=budget_id,
            data={
                "deleted_category": before,
                "removed_spend_records": related_spend_count,
                "reason": reason,
            },
        )

        self._log_audit_event(
            action="delete_category",
            context=context,
            resource_id=budget_id,
            details={"category_id": category_id, "removed_spend_records": related_spend_count, "reason": reason},
        )
        self._emit_agent_event(
            event_type="budget.category_deleted",
            context=context,
            payload={"budget_id": budget_id, "category_id": category_id},
        )

        return self._safe_result(
            message="Budget category deleted successfully.",
            data={"budget": budget.to_dict(include_spend_records=False), "verification_payload": verification_payload},
            metadata=self._result_metadata(context=context, action="delete_category"),
        )

    # ---------------------------------------------------------------------
    # Public spend methods
    # ---------------------------------------------------------------------

    def record_spend(
        self,
        context: Mapping[str, Any],
        budget_id: str,
        category_id: str,
        amount: Union[str, int, float, Decimal],
        spend_type: Union[str, SpendType] = SpendType.EXPENSE,
        description: str = "",
        source_reference: Optional[str] = None,
        transaction_date: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record spend against a budget category.

        This only records a local tracking entry. It does not pay, transfer,
        charge, invoice, or contact any external provider.
        """

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        budget = self._get_budget_for_context(context, budget_id)
        if budget is None:
            return self._error_result("Budget not found for this user/workspace.", "BUDGET_NOT_FOUND")

        if budget.status != BudgetStatus.ACTIVE:
            return self._error_result(
                message="Spend can only be recorded against active budgets.",
                error="BUDGET_NOT_ACTIVE",
                data={"budget_status": budget.status.value},
            )

        category = budget.categories.get(str(category_id))
        if category is None:
            return self._error_result("Category not found in this budget.", "CATEGORY_NOT_FOUND")

        clean_amount = _safe_money(amount)
        if clean_amount <= Decimal("0"):
            return self._error_result("Spend amount must be greater than zero.", "INVALID_SPEND_AMOUNT")

        parsed_spend_type = _parse_spend_type(spend_type)
        clean_transaction_date = _date_or_none(transaction_date) or date.today().isoformat()

        if parsed_spend_type in {SpendType.REFUND, SpendType.REVERSAL}:
            effective_delta = -clean_amount
        else:
            effective_delta = clean_amount

        would_category_spend = _safe_money(category.spent_amount + effective_delta)
        would_budget_spend = _safe_money(budget.spent_amount + effective_delta)

        over_limit = would_category_spend > category.limit_amount or would_budget_spend > budget.total_limit

        if over_limit and self._requires_security_check(
            action="record_spend_over_limit",
            context=context,
            payload={
                "budget_id": budget_id,
                "category_id": category_id,
                "amount": _money_to_str(clean_amount),
                "would_category_spend": _money_to_str(would_category_spend),
                "category_limit": _money_to_str(category.limit_amount),
                "would_budget_spend": _money_to_str(would_budget_spend),
                "budget_limit": _money_to_str(budget.total_limit),
            },
        ):
            approval = self._request_security_approval(
                action="record_spend_over_limit",
                context=context,
                payload={
                    "budget_id": budget_id,
                    "budget_name": budget.name,
                    "category_id": category_id,
                    "category_name": category.name,
                    "amount": _money_to_str(clean_amount),
                    "currency": budget.currency,
                    "risk": "This spend record will exceed a category or total budget limit.",
                },
            )
            if not approval.get("approved", False):
                return self._error_result(
                    message="Security approval is required before recording spend that exceeds budget limits.",
                    error="SECURITY_APPROVAL_REQUIRED",
                    data={"approval": approval, "over_limit": True},
                    metadata=self._result_metadata(context=context, action="record_spend"),
                )

        before_budget = budget.to_dict(include_spend_records=False)
        spend_id = _new_id("spend")

        spend_record = BudgetSpendRecord(
            spend_id=spend_id,
            budget_id=budget.budget_id,
            category_id=category.category_id,
            amount=clean_amount,
            spend_type=parsed_spend_type,
            description=_normalize_text(description),
            source_reference=_normalize_text(source_reference) or None,
            transaction_date=clean_transaction_date,
            metadata=_safe_metadata(metadata),
            created_by=str(context.get("user_id")) if context.get("user_id") is not None else None,
        )

        category.spent_amount = max(Decimal("0.00"), would_category_spend)
        category.updated_at = _utc_now_iso()
        budget.spend_records[spend_id] = spend_record
        budget.updated_at = _utc_now_iso()
        self._set_budget(budget)

        after_budget = budget.to_dict(include_spend_records=False)

        verification_payload = self._prepare_verification_payload(
            action="record_spend",
            context=context,
            resource_id=budget_id,
            data={
                "spend_record": spend_record.to_dict(),
                "before_budget": before_budget,
                "after_budget": after_budget,
                "over_limit": over_limit,
            },
        )

        memory_payload = self._prepare_memory_payload(
            action="record_spend",
            context=context,
            data={
                "budget_id": budget_id,
                "budget_name": budget.name,
                "category_id": category_id,
                "category_name": category.name,
                "amount": _money_to_str(clean_amount),
                "currency": budget.currency,
                "spend_type": parsed_spend_type.value,
                "transaction_date": clean_transaction_date,
            },
        )

        self._log_audit_event(
            action="record_spend",
            context=context,
            resource_id=budget_id,
            details={
                "spend_id": spend_id,
                "category_id": category_id,
                "amount": _money_to_str(clean_amount),
                "spend_type": parsed_spend_type.value,
                "over_limit": over_limit,
            },
        )
        self._emit_agent_event(
            event_type="budget.spend_recorded",
            context=context,
            payload={"budget_id": budget_id, "category_id": category_id, "spend_id": spend_id, "over_limit": over_limit},
        )

        return self._safe_result(
            message="Spend recorded successfully.",
            data={
                "budget": budget.to_dict(include_spend_records=False),
                "category": category.to_dict(),
                "spend_record": spend_record.to_dict(),
                "over_limit": over_limit,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata=self._result_metadata(context=context, action="record_spend"),
        )

    def reverse_spend(
        self,
        context: Mapping[str, Any],
        budget_id: str,
        spend_id: str,
        reason: str = "",
    ) -> Dict[str, Any]:
        """
        Reverse a spend record.

        This creates a reversal entry and decreases category spend locally.
        It does not reverse an external bank/payment transaction.
        """

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        budget = self._get_budget_for_context(context, budget_id)
        if budget is None:
            return self._error_result("Budget not found for this user/workspace.", "BUDGET_NOT_FOUND")

        original = budget.spend_records.get(str(spend_id))
        if original is None:
            return self._error_result("Spend record not found in this budget.", "SPEND_RECORD_NOT_FOUND")

        if original.spend_type == SpendType.REVERSAL:
            return self._error_result("A reversal record cannot be reversed again.", "CANNOT_REVERSE_REVERSAL")

        existing_reversal = [
            record for record in budget.spend_records.values()
            if record.reversed_spend_id == spend_id
        ]
        if existing_reversal:
            return self._error_result(
                message="This spend record has already been reversed.",
                error="SPEND_ALREADY_REVERSED",
                data={"existing_reversal": existing_reversal[0].to_dict()},
            )

        category = budget.categories.get(original.category_id)
        if category is None:
            return self._error_result("Original spend category no longer exists.", "CATEGORY_NOT_FOUND")

        before_budget = budget.to_dict(include_spend_records=False)
        reversal_id = _new_id("spend")

        reversal_record = BudgetSpendRecord(
            spend_id=reversal_id,
            budget_id=budget.budget_id,
            category_id=category.category_id,
            amount=original.amount,
            spend_type=SpendType.REVERSAL,
            description=f"Reversal for {spend_id}. {reason}".strip(),
            source_reference=original.source_reference,
            transaction_date=date.today().isoformat(),
            metadata={"reason": reason, "original_spend_id": spend_id},
            created_by=str(context.get("user_id")) if context.get("user_id") is not None else None,
            reversed_spend_id=spend_id,
        )

        if original.spend_type in {SpendType.REFUND, SpendType.REVERSAL}:
            category.spent_amount = _safe_money(category.spent_amount + original.amount)
        else:
            category.spent_amount = max(Decimal("0.00"), _safe_money(category.spent_amount - original.amount))

        category.updated_at = _utc_now_iso()
        budget.spend_records[reversal_id] = reversal_record
        budget.updated_at = _utc_now_iso()
        self._set_budget(budget)

        verification_payload = self._prepare_verification_payload(
            action="reverse_spend",
            context=context,
            resource_id=budget_id,
            data={
                "original_spend": original.to_dict(),
                "reversal_record": reversal_record.to_dict(),
                "before_budget": before_budget,
                "after_budget": budget.to_dict(include_spend_records=False),
                "reason": reason,
            },
        )

        self._log_audit_event(
            action="reverse_spend",
            context=context,
            resource_id=budget_id,
            details={"spend_id": spend_id, "reversal_id": reversal_id, "reason": reason},
        )
        self._emit_agent_event(
            event_type="budget.spend_reversed",
            context=context,
            payload={"budget_id": budget_id, "spend_id": spend_id, "reversal_id": reversal_id},
        )

        return self._safe_result(
            message="Spend record reversed successfully.",
            data={
                "budget": budget.to_dict(include_spend_records=False),
                "original_spend": original.to_dict(),
                "reversal_record": reversal_record.to_dict(),
                "verification_payload": verification_payload,
            },
            metadata=self._result_metadata(context=context, action="reverse_spend"),
        )

    # ---------------------------------------------------------------------
    # Public analytics / burn-rate methods
    # ---------------------------------------------------------------------

    def get_budget_summary(
        self,
        context: Mapping[str, Any],
        budget_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return budget summary for one budget or all budgets in workspace."""

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        if budget_id:
            budget = self._get_budget_for_context(context, budget_id)
            if budget is None:
                return self._error_result("Budget not found for this user/workspace.", "BUDGET_NOT_FOUND")
            budgets = [budget]
        else:
            budgets = [
                budget for budget in self._workspace_budgets(context).values()
                if budget.status != BudgetStatus.ARCHIVED
            ]

        total_limit = _safe_money(sum((budget.total_limit for budget in budgets), Decimal("0")))
        total_spent = _safe_money(sum((budget.spent_amount for budget in budgets), Decimal("0")))
        remaining = _safe_money(total_limit - total_spent)

        usage_percent = Decimal("0.00")
        if total_limit > Decimal("0"):
            usage_percent = _safe_percent((total_spent / total_limit) * Decimal("100"))

        alert_counts: Dict[str, int] = {level.value: 0 for level in BudgetAlertLevel}
        for budget in budgets:
            alert_counts[budget.alert_level.value] += 1

        summary = {
            "budget_count": len(budgets),
            "total_limit": _money_to_str(total_limit),
            "total_spent": _money_to_str(total_spent),
            "remaining_amount": _money_to_str(remaining),
            "usage_percent": _decimal_to_str(usage_percent),
            "alert_counts": alert_counts,
            "budgets": [
                {
                    "budget_id": budget.budget_id,
                    "name": budget.name,
                    "currency": budget.currency,
                    "period": budget.period.value,
                    "status": budget.status.value,
                    "total_limit": _money_to_str(budget.total_limit),
                    "spent_amount": _money_to_str(budget.spent_amount),
                    "remaining_amount": _money_to_str(budget.remaining_amount),
                    "usage_percent": _decimal_to_str(budget.usage_percent),
                    "alert_level": budget.alert_level.value,
                }
                for budget in budgets
            ],
        }

        return self._safe_result(
            message="Budget summary prepared successfully.",
            data={"summary": summary},
            metadata=self._result_metadata(context=context, action="get_budget_summary"),
        )

    def get_burn_rate(
        self,
        context: Mapping[str, Any],
        budget_id: str,
        as_of_date: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Calculate burn rates for budget and categories.

        Burn rate includes:
            - daily_burn_rate
            - projected_total_spend
            - projected_remaining_amount
            - projected_over_under_budget
            - days_elapsed
            - total_days
        """

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        budget = self._get_budget_for_context(context, budget_id)
        if budget is None:
            return self._error_result("Budget not found for this user/workspace.", "BUDGET_NOT_FOUND")

        clean_as_of = _date_or_none(as_of_date) or date.today().isoformat()
        total_days = _days_between(budget.start_date, budget.end_date)
        days_elapsed = _days_elapsed(budget.start_date, clean_as_of)

        if total_days is None:
            total_days = self._period_to_days(budget.period)

        if days_elapsed is None:
            days_elapsed = self._estimate_days_elapsed_from_spend_records(budget, clean_as_of)

        safe_days_elapsed = max(int(days_elapsed or 1), 1)
        safe_total_days = max(int(total_days or safe_days_elapsed), safe_days_elapsed)

        daily_burn_rate = _safe_money(budget.spent_amount / Decimal(safe_days_elapsed))
        projected_total_spend = _safe_money(daily_burn_rate * Decimal(safe_total_days))
        projected_remaining_amount = _safe_money(budget.total_limit - projected_total_spend)
        projected_over_under_budget = _safe_money(budget.total_limit - projected_total_spend)

        category_burn_rates: Dict[str, Dict[str, Any]] = {}
        for category_id, category in budget.categories.items():
            category_daily = _safe_money(category.spent_amount / Decimal(safe_days_elapsed))
            category_projected = _safe_money(category_daily * Decimal(safe_total_days))
            category_burn_rates[category_id] = {
                "category_id": category_id,
                "name": category.name,
                "limit_amount": _money_to_str(category.limit_amount),
                "spent_amount": _money_to_str(category.spent_amount),
                "daily_burn_rate": _money_to_str(category_daily),
                "projected_total_spend": _money_to_str(category_projected),
                "projected_over_under_budget": _money_to_str(category.limit_amount - category_projected),
                "usage_percent": _decimal_to_str(category.usage_percent),
                "alert_level": category.alert_level.value,
            }

        burn_rate = {
            "budget_id": budget.budget_id,
            "name": budget.name,
            "currency": budget.currency,
            "period": budget.period.value,
            "as_of_date": clean_as_of,
            "start_date": budget.start_date,
            "end_date": budget.end_date,
            "days_elapsed": safe_days_elapsed,
            "total_days": safe_total_days,
            "total_limit": _money_to_str(budget.total_limit),
            "spent_amount": _money_to_str(budget.spent_amount),
            "remaining_amount": _money_to_str(budget.remaining_amount),
            "daily_burn_rate": _money_to_str(daily_burn_rate),
            "projected_total_spend": _money_to_str(projected_total_spend),
            "projected_remaining_amount": _money_to_str(projected_remaining_amount),
            "projected_over_under_budget": _money_to_str(projected_over_under_budget),
            "projected_alert_level": self._projected_alert_level(projected_total_spend, budget.total_limit).value,
            "categories": category_burn_rates,
        }

        return self._safe_result(
            message="Budget burn rate calculated successfully.",
            data={"burn_rate": burn_rate},
            metadata=self._result_metadata(context=context, action="get_burn_rate"),
        )

    def check_limits(
        self,
        context: Mapping[str, Any],
        budget_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Check budget and category limits.

        Returns warning/critical/exceeded alerts suitable for dashboard,
        notifications, or Verification Agent review.
        """

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        if budget_id:
            budget = self._get_budget_for_context(context, budget_id)
            if budget is None:
                return self._error_result("Budget not found for this user/workspace.", "BUDGET_NOT_FOUND")
            budgets = [budget]
        else:
            budgets = [
                budget for budget in self._workspace_budgets(context).values()
                if budget.status == BudgetStatus.ACTIVE
            ]

        alerts: List[Dict[str, Any]] = []

        for budget in budgets:
            if budget.alert_level != BudgetAlertLevel.OK:
                alerts.append({
                    "scope": "budget",
                    "budget_id": budget.budget_id,
                    "budget_name": budget.name,
                    "level": budget.alert_level.value,
                    "currency": budget.currency,
                    "limit_amount": _money_to_str(budget.total_limit),
                    "spent_amount": _money_to_str(budget.spent_amount),
                    "remaining_amount": _money_to_str(budget.remaining_amount),
                    "usage_percent": _decimal_to_str(budget.usage_percent),
                    "message": self._alert_message("budget", budget.name, budget.alert_level, budget.usage_percent),
                })

            for category in budget.categories.values():
                if category.alert_level != BudgetAlertLevel.OK:
                    alerts.append({
                        "scope": "category",
                        "budget_id": budget.budget_id,
                        "budget_name": budget.name,
                        "category_id": category.category_id,
                        "category_name": category.name,
                        "level": category.alert_level.value,
                        "currency": budget.currency,
                        "limit_amount": _money_to_str(category.limit_amount),
                        "spent_amount": _money_to_str(category.spent_amount),
                        "remaining_amount": _money_to_str(category.remaining_amount),
                        "usage_percent": _decimal_to_str(category.usage_percent),
                        "message": self._alert_message("category", category.name, category.alert_level, category.usage_percent),
                    })

        severity_order = {
            BudgetAlertLevel.EXCEEDED.value: 0,
            BudgetAlertLevel.CRITICAL.value: 1,
            BudgetAlertLevel.WARNING.value: 2,
            BudgetAlertLevel.OK.value: 3,
        }
        alerts.sort(key=lambda item: severity_order.get(str(item.get("level")), 99))

        return self._safe_result(
            message="Budget limits checked successfully.",
            data={
                "alerts": alerts,
                "alert_count": len(alerts),
                "has_exceeded": any(alert["level"] == BudgetAlertLevel.EXCEEDED.value for alert in alerts),
                "has_critical": any(alert["level"] == BudgetAlertLevel.CRITICAL.value for alert in alerts),
                "has_warning": any(alert["level"] == BudgetAlertLevel.WARNING.value for alert in alerts),
            },
            metadata=self._result_metadata(context=context, action="check_limits"),
        )

    def export_dashboard_payload(
        self,
        context: Mapping[str, Any],
        include_archived: bool = False,
    ) -> Dict[str, Any]:
        """
        Prepare a dashboard/API-friendly payload.

        This can be consumed by FastAPI routes, admin dashboards, analytics views,
        or Finance Agent reports.
        """

        valid_context = self._validate_task_context(context)
        if not valid_context["success"]:
            return valid_context

        budgets = list(self._workspace_budgets(context).values())
        if not include_archived:
            budgets = [budget for budget in budgets if budget.status != BudgetStatus.ARCHIVED]

        summary_result = self.get_budget_summary(context=context)
        limits_result = self.check_limits(context=context)

        dashboard_payload = {
            "user_id": str(context["user_id"]),
            "workspace_id": str(context["workspace_id"]),
            "generated_at": _utc_now_iso(),
            "summary": summary_result.get("data", {}).get("summary", {}),
            "alerts": limits_result.get("data", {}).get("alerts", []),
            "budgets": [budget.to_dict(include_spend_records=False) for budget in budgets],
            "charts": {
                "budget_usage": [
                    {
                        "label": budget.name,
                        "spent": float(budget.spent_amount),
                        "limit": float(budget.total_limit),
                        "remaining": float(budget.remaining_amount),
                        "usage_percent": float(budget.usage_percent),
                    }
                    for budget in budgets
                ],
                "category_usage": [
                    {
                        "budget_id": budget.budget_id,
                        "budget_name": budget.name,
                        "category_id": category.category_id,
                        "category_name": category.name,
                        "spent": float(category.spent_amount),
                        "limit": float(category.limit_amount),
                        "remaining": float(category.remaining_amount),
                        "usage_percent": float(category.usage_percent),
                    }
                    for budget in budgets
                    for category in budget.categories.values()
                ],
            },
        }

        return self._safe_result(
            message="Budget dashboard payload prepared successfully.",
            data={"dashboard": dashboard_payload},
            metadata=self._result_metadata(context=context, action="export_dashboard_payload"),
        )

    # ---------------------------------------------------------------------
    # Required compatibility hooks
    # ---------------------------------------------------------------------

    def _validate_task_context(self, context: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """
        Validate SaaS isolation context.

        Every user-specific operation must provide user_id and workspace_id.
        """

        if not isinstance(context, Mapping):
            return self._error_result(
                message="Task context is required and must be a dictionary.",
                error="INVALID_CONTEXT",
            )

        user_id = _normalize_text(context.get("user_id"))
        workspace_id = _normalize_text(context.get("workspace_id"))

        if not user_id:
            return self._error_result("user_id is required for budget tracking.", "USER_ID_REQUIRED")

        if not workspace_id:
            return self._error_result("workspace_id is required for budget tracking.", "WORKSPACE_ID_REQUIRED")

        return self._safe_result(
            message="Task context validated.",
            data={"user_id": user_id, "workspace_id": workspace_id},
            metadata={"agent": self.agent_name},
        )

    def _requires_security_check(
        self,
        action: str,
        context: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determine whether an action needs Security Agent approval.

        The Security Agent can later replace or enhance this policy.
        """

        sensitive_actions = set(
            getattr(
                self.config,
                "DEFAULT_SECURITY_REQUIRED_ACTIONS",
                {
                    "delete_budget",
                    "delete_category",
                    "record_spend_over_limit",
                    "reset_budget",
                    "bulk_import_budgets",
                },
            )
        )

        if action in sensitive_actions:
            return True

        payload = payload or {}
        if action == "record_spend" and payload.get("over_limit"):
            return True

        return False

    def _request_security_approval(
        self,
        action: str,
        context: Mapping[str, Any],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request approval from Security Agent if available.

        Fallback behavior:
            - Returns approved=False for sensitive actions.
            - This prevents risky operations from silently passing when Security
              Agent is not connected.
        """

        request = {
            "agent": self.agent_name,
            "action": action,
            "context": {
                "user_id": str(context.get("user_id")),
                "workspace_id": str(context.get("workspace_id")),
            },
            "payload": _safe_metadata(payload),
            "requested_at": _utc_now_iso(),
        }

        if self.security_agent is None:
            return {
                "approved": False,
                "reason": "Security Agent is not connected.",
                "request": request,
            }

        try:
            if hasattr(self.security_agent, "approve_action"):
                response = self.security_agent.approve_action(request)
                if isinstance(response, Mapping):
                    return dict(response)

            if hasattr(self.security_agent, "request_approval"):
                response = self.security_agent.request_approval(request)
                if isinstance(response, Mapping):
                    return dict(response)

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return {
                "approved": False,
                "reason": "Security approval request failed.",
                "error": str(exc),
                "request": request,
            }

        return {
            "approved": False,
            "reason": "Security Agent did not return a valid approval response.",
            "request": request,
        }

    def _prepare_verification_payload(
        self,
        action: str,
        context: Mapping[str, Any],
        resource_id: Optional[str] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        The Verification Agent can use this to validate budget mutations, reports,
        audit trails, or dashboard displays.
        """

        return {
            "agent": self.agent_name,
            "module": "finance_agent",
            "action": action,
            "resource_type": "budget",
            "resource_id": resource_id,
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "data": _safe_metadata(data),
            "created_at": _utc_now_iso(),
            "requires_human_review": action in {
                "delete_budget",
                "delete_category",
                "record_spend_over_limit",
            },
        }

    def _prepare_memory_payload(
        self,
        action: str,
        context: Mapping[str, Any],
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Budget memory should store only useful business context and never mix
        users or workspaces.
        """

        return {
            "agent": self.agent_name,
            "module": "finance_agent",
            "memory_type": "finance_budget_context",
            "action": action,
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "data": _safe_metadata(data),
            "created_at": _utc_now_iso(),
            "privacy_scope": "user_workspace",
        }

    def _emit_agent_event(
        self,
        event_type: str,
        context: Mapping[str, Any],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit a Finance Agent event for dashboard/task history/event bus.

        This is intentionally best-effort and never breaks core budget flow.
        """

        event = {
            "event_type": event_type,
            "agent": self.agent_name,
            "module": "finance_agent",
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "payload": _safe_metadata(payload),
            "created_at": _utc_now_iso(),
        }

        try:
            if self.event_bus is not None:
                if hasattr(self.event_bus, "emit"):
                    self.event_bus.emit(event_type, event)
                    return
                if hasattr(self.event_bus, "publish"):
                    self.event_bus.publish(event_type, event)
                    return

            self.logger.debug("Agent event emitted locally: %s", event)
        except Exception:
            self.logger.exception("Failed to emit agent event.")

    def _log_audit_event(
        self,
        action: str,
        context: Mapping[str, Any],
        resource_id: Optional[str] = None,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event for SaaS traceability.

        This is best-effort and scoped by user/workspace.
        """

        audit_event = {
            "agent": self.agent_name,
            "module": "finance_agent",
            "action": action,
            "resource_type": "budget",
            "resource_id": resource_id,
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "details": _safe_metadata(details),
            "created_at": _utc_now_iso(),
        }

        try:
            if self.audit_logger is not None:
                if hasattr(self.audit_logger, "log"):
                    self.audit_logger.log(audit_event)
                    return
                if hasattr(self.audit_logger, "info"):
                    self.audit_logger.info(audit_event)
                    return

            self.logger.info("AUDIT_EVENT %s", audit_event)
        except Exception:
            self.logger.exception("Failed to log audit event.")

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis success result."""

        return {
            "success": True,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": dict(metadata or {}),
        }

    def _error_result(
        self,
        message: str,
        error: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return standard William/Jarvis error result."""

        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": error,
            "metadata": dict(metadata or {}),
        }

    # ---------------------------------------------------------------------
    # Internal storage helpers
    # ---------------------------------------------------------------------

    def _workspace_budgets(self, context: Mapping[str, Any]) -> Dict[str, Budget]:
        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])
        return self.storage.setdefault(user_id, {}).setdefault(workspace_id, {})

    def _set_budget(self, budget: Budget) -> None:
        self.storage.setdefault(budget.user_id, {}).setdefault(budget.workspace_id, {})[budget.budget_id] = budget

    def _get_budget_for_context(self, context: Mapping[str, Any], budget_id: str) -> Optional[Budget]:
        clean_budget_id = _normalize_text(budget_id)
        if not clean_budget_id:
            return None

        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])
        return self.storage.get(user_id, {}).get(workspace_id, {}).get(clean_budget_id)

    def _delete_budget_from_storage(self, context: Mapping[str, Any], budget_id: str) -> None:
        user_id = str(context["user_id"])
        workspace_id = str(context["workspace_id"])
        self.storage.get(user_id, {}).get(workspace_id, {}).pop(str(budget_id), None)

    # ---------------------------------------------------------------------
    # Internal analytics helpers
    # ---------------------------------------------------------------------

    def _period_to_days(self, period: BudgetPeriod) -> int:
        if period == BudgetPeriod.DAILY:
            return 1
        if period == BudgetPeriod.WEEKLY:
            return 7
        if period == BudgetPeriod.MONTHLY:
            return 30
        if period == BudgetPeriod.QUARTERLY:
            return 90
        if period == BudgetPeriod.YEARLY:
            return 365
        return 30

    def _estimate_days_elapsed_from_spend_records(self, budget: Budget, as_of_date: str) -> int:
        if not budget.spend_records:
            return 1

        dates: List[date] = []
        for record in budget.spend_records.values():
            try:
                dates.append(date.fromisoformat(record.transaction_date))
            except ValueError:
                continue

        if not dates:
            return 1

        try:
            current = date.fromisoformat(as_of_date)
        except ValueError:
            current = date.today()

        earliest = min(dates)
        return max((current - earliest).days + 1, 1)

    def _projected_alert_level(self, projected_spend: Decimal, limit: Decimal) -> BudgetAlertLevel:
        if projected_spend > limit:
            return BudgetAlertLevel.EXCEEDED

        if limit <= Decimal("0"):
            return BudgetAlertLevel.OK

        projected_usage = _safe_percent((projected_spend / limit) * Decimal("100"))
        warning_threshold = _to_decimal(
            getattr(FinanceAgentConfig, "BUDGET_WARNING_THRESHOLD_PERCENT", Decimal("80")),
            default=Decimal("80"),
        )
        critical_threshold = _to_decimal(
            getattr(FinanceAgentConfig, "BUDGET_CRITICAL_THRESHOLD_PERCENT", Decimal("95")),
            default=Decimal("95"),
        )

        if projected_usage >= critical_threshold:
            return BudgetAlertLevel.CRITICAL
        if projected_usage >= warning_threshold:
            return BudgetAlertLevel.WARNING
        return BudgetAlertLevel.OK

    def _alert_message(
        self,
        scope: str,
        name: str,
        level: BudgetAlertLevel,
        usage_percent: Decimal,
    ) -> str:
        clean_scope = scope.capitalize()
        usage = _decimal_to_str(usage_percent)

        if level == BudgetAlertLevel.EXCEEDED:
            return f"{clean_scope} '{name}' has exceeded its limit at {usage}% usage."
        if level == BudgetAlertLevel.CRITICAL:
            return f"{clean_scope} '{name}' is near its limit at {usage}% usage."
        if level == BudgetAlertLevel.WARNING:
            return f"{clean_scope} '{name}' has reached warning level at {usage}% usage."
        return f"{clean_scope} '{name}' is within budget."

    def _provided_fields(self, local_vars: Mapping[str, Any]) -> List[str]:
        ignored = {"self", "context", "budget", "category", "old_budget", "before", "budget_id", "category_id"}
        fields: List[str] = []
        for key, value in local_vars.items():
            if key in ignored:
                continue
            if value is not None:
                fields.append(key)
        return sorted(fields)

    def _result_metadata(self, context: Mapping[str, Any], action: str) -> Dict[str, Any]:
        return {
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "module": "finance_agent",
            "action": action,
            "user_id": str(context.get("user_id")),
            "workspace_id": str(context.get("workspace_id")),
            "generated_at": _utc_now_iso(),
            "safe_import": True,
            "real_financial_action_executed": False,
        }


# ---------------------------------------------------------------------------
# Registry helper
# ---------------------------------------------------------------------------

def get_agent_registry_metadata() -> Dict[str, Any]:
    """
    Return registry metadata for Agent Loader / Agent Registry.

    This function is intentionally module-level for easy discovery.
    """

    return copy.deepcopy(BudgetTracker.registry_metadata)


def create_agent(*args: Any, **kwargs: Any) -> BudgetTracker:
    """
    Factory helper for Agent Loader compatibility.
    """

    return BudgetTracker(*args, **kwargs)


__all__ = [
    "BudgetTracker",
    "Budget",
    "BudgetCategory",
    "BudgetSpendRecord",
    "BudgetPeriod",
    "BudgetStatus",
    "BudgetAlertLevel",
    "SpendType",
    "create_agent",
    "get_agent_registry_metadata",
]


"""
Where to place it:
    agents/super_agents/finance_agent/budget_tracker.py

Required dependencies:
    - Python 3.10+
    - Standard library only:
        copy
        logging
        uuid
        dataclasses
        datetime
        decimal
        enum
        typing

How to test it:
    from agents.super_agents.finance_agent.budget_tracker import BudgetTracker

    tracker = BudgetTracker()
    ctx = {"user_id": "user_1", "workspace_id": "workspace_1"}

    result = tracker.create_budget(
        context=ctx,
        name="Marketing Budget",
        total_limit="1000",
        currency="USD",
        period="monthly",
        categories=[
            {"name": "Google Ads", "limit_amount": "600"},
            {"name": "SEO Tools", "limit_amount": "200"},
        ],
    )

    print(result)

    budget_id = result["data"]["budget"]["budget_id"]
    category_id = next(iter(result["data"]["budget"]["categories"].keys()))

    spend = tracker.record_spend(
        context=ctx,
        budget_id=budget_id,
        category_id=category_id,
        amount="150",
        description="Initial Google Ads spend",
    )

    print(spend)
    print(tracker.get_budget_summary(context=ctx))
    print(tracker.get_burn_rate(context=ctx, budget_id=budget_id))
    print(tracker.check_limits(context=ctx))

Agent/Module: Finance Agent
File Completed: budget_tracker.py
Completion: 33.3%
Completed Files: ['finance_agent.py', 'invoice_manager.py', 'transaction_preparer.py', 'budget_tracker.py']
Remaining Files: ['payment_guard.py', 'finance_reports.py', 'receipt_reader.py', 'tax_helper.py', 'subscription_tracker.py', 'expense_categorizer.py', 'finance_memory.py', 'config.py']
Next Recommended File: agents/super_agents/finance_agent/payment_guard.py

FILE COMPLETE
"""