"""
agents/super_agents/business_agent/analytics_engine.py

William / Jarvis Multi-Agent AI SaaS System
Business Agent - Analytics Engine

Purpose:
    Calculates KPIs, trends, conversion rates, lead sources, revenue, and
    dashboard-ready business analytics while enforcing SaaS user/workspace
    isolation.

Architecture compatibility:
    - BaseAgent compatible with safe fallback if BaseAgent is unavailable.
    - Master Agent / Agent Router compatible through clear public methods.
    - Agent Registry / Agent Loader safe import behavior.
    - Security Agent compatible through approval hook payloads.
    - Verification Agent compatible through structured verification payloads.
    - Memory Agent compatible through structured memory payloads.
    - Dashboard/API ready through structured dict results.

Important:
    This module performs analytics only. It does not execute destructive,
    financial, messaging, calling, browser, or external side effects directly.
"""

from __future__ import annotations

import logging
import math
import statistics
from collections import Counter, defaultdict
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
except Exception:  # pragma: no cover - fallback for import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps the file import-safe even when the full William/Jarvis
        codebase is not available yet. The real system should provide
        agents.base_agent.BaseAgent.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_type = kwargs.get("agent_type", "business")
            self.logger = logging.getLogger(self.agent_name)

        async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
            return {
                "success": False,
                "message": "Fallback BaseAgent run() is not implemented.",
                "data": None,
                "error": "BASE_AGENT_NOT_AVAILABLE",
                "metadata": {"agent": self.agent_name},
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants and enums
# ---------------------------------------------------------------------------

DEFAULT_CURRENCY = "USD"
DEFAULT_DECIMAL_PLACES = 2

LEAD_STATUS_NEW = "new"
LEAD_STATUS_CONTACTED = "contacted"
LEAD_STATUS_QUALIFIED = "qualified"
LEAD_STATUS_PROPOSAL = "proposal"
LEAD_STATUS_WON = "won"
LEAD_STATUS_LOST = "lost"
LEAD_STATUS_DISQUALIFIED = "disqualified"

DEFAULT_LEAD_STATUSES = {
    LEAD_STATUS_NEW,
    LEAD_STATUS_CONTACTED,
    LEAD_STATUS_QUALIFIED,
    LEAD_STATUS_PROPOSAL,
    LEAD_STATUS_WON,
    LEAD_STATUS_LOST,
    LEAD_STATUS_DISQUALIFIED,
}

REVENUE_KEYS = (
    "amount",
    "value",
    "revenue",
    "deal_value",
    "closed_value",
    "total",
    "price",
)

DATE_KEYS = (
    "created_at",
    "updated_at",
    "closed_at",
    "date",
    "timestamp",
    "created",
    "time",
)

SOURCE_KEYS = (
    "source",
    "lead_source",
    "channel",
    "utm_source",
    "origin",
)

STATUS_KEYS = (
    "status",
    "lead_status",
    "stage",
    "deal_stage",
)

OWNER_KEYS = (
    "owner_id",
    "assigned_to",
    "sales_rep",
    "agent_id",
    "created_by",
)


class AnalyticsWindow(str, Enum):
    """Supported dashboard analytics time windows."""

    TODAY = "today"
    LAST_7_DAYS = "last_7_days"
    LAST_30_DAYS = "last_30_days"
    LAST_90_DAYS = "last_90_days"
    MONTH_TO_DATE = "month_to_date"
    QUARTER_TO_DATE = "quarter_to_date"
    YEAR_TO_DATE = "year_to_date"
    ALL_TIME = "all_time"
    CUSTOM = "custom"


class TrendDirection(str, Enum):
    """Normalized trend direction labels."""

    UP = "up"
    DOWN = "down"
    FLAT = "flat"
    UNKNOWN = "unknown"


class MetricName(str, Enum):
    """Known metric names used by dashboard/API consumers."""

    TOTAL_LEADS = "total_leads"
    NEW_LEADS = "new_leads"
    QUALIFIED_LEADS = "qualified_leads"
    WON_DEALS = "won_deals"
    LOST_DEALS = "lost_deals"
    TOTAL_REVENUE = "total_revenue"
    PIPELINE_VALUE = "pipeline_value"
    CONVERSION_RATE = "conversion_rate"
    WIN_RATE = "win_rate"
    AVERAGE_DEAL_VALUE = "average_deal_value"
    LEAD_TO_QUALIFIED_RATE = "lead_to_qualified_rate"
    QUALIFIED_TO_WON_RATE = "qualified_to_won_rate"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AnalyticsContext:
    """
    SaaS isolation context.

    Every public operation must include user_id and workspace_id. This prevents
    accidental analytics mixing between users/workspaces.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    permissions: Sequence[str] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class DateRange:
    """Normalized inclusive date range for analytics calculations."""

    start: Optional[datetime]
    end: Optional[datetime]
    window: str = AnalyticsWindow.ALL_TIME.value

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": self.start.isoformat() if self.start else None,
            "end": self.end.isoformat() if self.end else None,
            "window": self.window,
        }


@dataclass
class AnalyticsRecord:
    """
    Normalized analytics record.

    Source records can be leads, deals, revenue events, campaign records, or CRM
    objects. This normalized structure lets the AnalyticsEngine calculate KPIs
    consistently while preserving raw data for future extensions.
    """

    record_id: str
    user_id: str
    workspace_id: str
    status: str = LEAD_STATUS_NEW
    source: str = "unknown"
    amount: Decimal = Decimal("0")
    created_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    owner_id: Optional[str] = None
    campaign_id: Optional[str] = None
    client_id: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def is_won(self) -> bool:
        return self.status.lower() in {"won", "closed_won", "closed won", "converted", "paid"}

    def is_lost(self) -> bool:
        return self.status.lower() in {"lost", "closed_lost", "closed lost", "dead", "disqualified"}

    def is_qualified(self) -> bool:
        return self.status.lower() in {
            "qualified",
            "proposal",
            "won",
            "closed_won",
            "closed won",
            "converted",
            "paid",
        }

    def is_open_pipeline(self) -> bool:
        return not self.is_won() and not self.is_lost()


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    """Return current timezone-aware UTC datetime."""

    return datetime.now(timezone.utc)


def _safe_str(value: Any, default: str = "") -> str:
    """Convert value to safe stripped string."""

    if value is None:
        return default
    try:
        text = str(value).strip()
        return text if text else default
    except Exception:
        return default


def _normalize_key(value: Any, default: str = "unknown") -> str:
    """Normalize source/status keys for grouping."""

    text = _safe_str(value, default=default).lower()
    text = text.replace("-", "_").replace(" ", "_")
    return text or default


def _decimal(value: Any, default: Decimal = Decimal("0")) -> Decimal:
    """Safely parse a numeric value into Decimal."""

    if value is None:
        return default

    if isinstance(value, Decimal):
        return value

    if isinstance(value, bool):
        return Decimal("1") if value else Decimal("0")

    if isinstance(value, (int, float)):
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return default
        try:
            return Decimal(str(value))
        except Exception:
            return default

    if isinstance(value, str):
        cleaned = (
            value.strip()
            .replace(",", "")
            .replace("$", "")
            .replace("€", "")
            .replace("£", "")
            .replace("PKR", "")
            .replace("USD", "")
            .strip()
        )
        if not cleaned:
            return default
        try:
            return Decimal(cleaned)
        except InvalidOperation:
            return default

    return default


def _round_money(value: Any, places: int = DEFAULT_DECIMAL_PLACES) -> float:
    """Round Decimal-compatible money values and return float for JSON."""

    amount = _decimal(value)
    quantizer = Decimal("1." + ("0" * places))
    return float(amount.quantize(quantizer, rounding=ROUND_HALF_UP))


def _round_percent(value: Any, places: int = 2) -> float:
    """Round percentage values."""

    amount = _decimal(value)
    quantizer = Decimal("1." + ("0" * places))
    return float(amount.quantize(quantizer, rounding=ROUND_HALF_UP))


def _safe_ratio(numerator: Union[int, float, Decimal], denominator: Union[int, float, Decimal]) -> Decimal:
    """Return safe Decimal ratio between 0 and 1 where possible."""

    num = _decimal(numerator)
    den = _decimal(denominator)
    if den == 0:
        return Decimal("0")
    return num / den


def _safe_percentage(numerator: Union[int, float, Decimal], denominator: Union[int, float, Decimal]) -> float:
    """Return safe percentage as float."""

    return _round_percent(_safe_ratio(numerator, denominator) * Decimal("100"))


def _first_present(mapping: Mapping[str, Any], keys: Sequence[str], default: Any = None) -> Any:
    """Return first non-empty value from mapping using candidate keys."""

    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return default


def _parse_datetime(value: Any) -> Optional[datetime]:
    """
    Parse common date/datetime inputs into timezone-aware UTC datetime.

    Accepted:
        - datetime
        - date
        - UNIX timestamp int/float
        - ISO-like strings
    """

    if value is None or value == "":
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)

    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except Exception:
            return None

    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        formats = (
            "%Y-%m-%d",
            "%Y/%m/%d",
            "%d-%m-%Y",
            "%m/%d/%Y",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S.%f",
        )

        try:
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except Exception:
            pass

        for fmt in formats:
            try:
                parsed = datetime.strptime(text, fmt)
                return parsed.replace(tzinfo=timezone.utc)
            except Exception:
                continue

    return None


def _period_key(dt: Optional[datetime], granularity: str = "day") -> str:
    """Return period grouping key for trend charts."""

    if dt is None:
        return "unknown"

    if granularity == "hour":
        return dt.strftime("%Y-%m-%d %H:00")
    if granularity == "week":
        year, week, _ = dt.isocalendar()
        return f"{year}-W{week:02d}"
    if granularity == "month":
        return dt.strftime("%Y-%m")
    if granularity == "quarter":
        quarter = ((dt.month - 1) // 3) + 1
        return f"{dt.year}-Q{quarter}"
    if granularity == "year":
        return dt.strftime("%Y")

    return dt.strftime("%Y-%m-%d")


def _daterange_from_window(
    window: Union[str, AnalyticsWindow] = AnalyticsWindow.ALL_TIME,
    start: Optional[Any] = None,
    end: Optional[Any] = None,
    now: Optional[datetime] = None,
) -> DateRange:
    """Build normalized date range from supported analytics window."""

    current = now or _utc_now()
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)

    window_value = window.value if isinstance(window, AnalyticsWindow) else str(window or AnalyticsWindow.ALL_TIME.value)

    custom_start = _parse_datetime(start)
    custom_end = _parse_datetime(end)

    if window_value == AnalyticsWindow.CUSTOM.value:
        return DateRange(start=custom_start, end=custom_end, window=window_value)

    if window_value == AnalyticsWindow.TODAY.value:
        range_start = datetime(current.year, current.month, current.day, tzinfo=timezone.utc)
        return DateRange(start=range_start, end=current, window=window_value)

    if window_value == AnalyticsWindow.LAST_7_DAYS.value:
        return DateRange(start=current - timedelta(days=7), end=current, window=window_value)

    if window_value == AnalyticsWindow.LAST_30_DAYS.value:
        return DateRange(start=current - timedelta(days=30), end=current, window=window_value)

    if window_value == AnalyticsWindow.LAST_90_DAYS.value:
        return DateRange(start=current - timedelta(days=90), end=current, window=window_value)

    if window_value == AnalyticsWindow.MONTH_TO_DATE.value:
        return DateRange(
            start=datetime(current.year, current.month, 1, tzinfo=timezone.utc),
            end=current,
            window=window_value,
        )

    if window_value == AnalyticsWindow.QUARTER_TO_DATE.value:
        quarter_start_month = (((current.month - 1) // 3) * 3) + 1
        return DateRange(
            start=datetime(current.year, quarter_start_month, 1, tzinfo=timezone.utc),
            end=current,
            window=window_value,
        )

    if window_value == AnalyticsWindow.YEAR_TO_DATE.value:
        return DateRange(
            start=datetime(current.year, 1, 1, tzinfo=timezone.utc),
            end=current,
            window=window_value,
        )

    return DateRange(start=custom_start, end=custom_end, window=AnalyticsWindow.ALL_TIME.value)


def _is_in_range(dt: Optional[datetime], date_range: DateRange) -> bool:
    """Return whether datetime is inside inclusive range."""

    if dt is None:
        return date_range.start is None and date_range.end is None

    if date_range.start and dt < date_range.start:
        return False

    if date_range.end and dt > date_range.end:
        return False

    return True


def _trend_direction(current_value: Decimal, previous_value: Decimal) -> str:
    """Determine trend direction from previous/current metric values."""

    if previous_value == 0 and current_value == 0:
        return TrendDirection.FLAT.value
    if previous_value == 0 and current_value > 0:
        return TrendDirection.UP.value
    if current_value > previous_value:
        return TrendDirection.UP.value
    if current_value < previous_value:
        return TrendDirection.DOWN.value
    return TrendDirection.FLAT.value


def _trend_change_percent(current_value: Decimal, previous_value: Decimal) -> float:
    """Calculate percent change from previous to current."""

    if previous_value == 0:
        if current_value == 0:
            return 0.0
        return 100.0
    return _round_percent(((current_value - previous_value) / previous_value) * Decimal("100"))


# ---------------------------------------------------------------------------
# Analytics Engine
# ---------------------------------------------------------------------------

class AnalyticsEngine(BaseAgent):
    """
    Calculates business KPIs, trends, conversion rates, lead sources, and revenue.

    This class is intentionally side-effect-light. It is suitable for:
        - Master Agent routed analytics tasks.
        - Business Agent internal KPI generation.
        - Dashboard/API endpoints.
        - Verification Agent post-action validation payloads.
        - Memory Agent context snapshots.
        - SaaS-safe user/workspace analytics.

    Public methods return structured dicts:
        {
            "success": bool,
            "message": str,
            "data": Any,
            "error": Optional[str],
            "metadata": dict
        }
    """

    agent_name = "AnalyticsEngine"
    agent_type = "business"
    version = "1.0.0"

    def __init__(
        self,
        *,
        security_client: Optional[Any] = None,
        memory_client: Optional[Any] = None,
        verification_client: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        currency: str = DEFAULT_CURRENCY,
        strict_workspace_filtering: bool = True,
        **kwargs: Any,
    ) -> None:
        """
        Initialize AnalyticsEngine.

        Args:
            security_client:
                Optional Security Agent/client adapter.
            memory_client:
                Optional Memory Agent/client adapter.
            verification_client:
                Optional Verification Agent/client adapter.
            event_emitter:
                Optional callback for agent events.
            audit_logger:
                Optional callback for audit logs.
            currency:
                Default dashboard currency.
            strict_workspace_filtering:
                If True, records missing matching user/workspace are excluded.
            **kwargs:
                Forward-compatible BaseAgent kwargs.
        """

        try:
            super().__init__(
                agent_name=self.agent_name,
                agent_type=self.agent_type,
                **kwargs,
            )
        except TypeError:
            super().__init__()

        self.security_client = security_client
        self.memory_client = memory_client
        self.verification_client = verification_client
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.currency = currency or DEFAULT_CURRENCY
        self.strict_workspace_filtering = strict_workspace_filtering
        self.logger = logging.getLogger(f"{__name__}.{self.agent_name}")

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _safe_result(
        self,
        *,
        success: bool = True,
        message: str = "OK",
        data: Any = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Return normalized successful/neutral result."""

        return {
            "success": bool(success),
            "message": message,
            "data": data,
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Union[str, Exception, Dict[str, Any]],
        metadata: Optional[Dict[str, Any]] = None,
        data: Any = None,
    ) -> Dict[str, Any]:
        """Return normalized error result."""

        if isinstance(error, Exception):
            error_payload: Union[str, Dict[str, Any]] = {
                "type": error.__class__.__name__,
                "detail": str(error),
            }
        else:
            error_payload = error

        return {
            "success": False,
            "message": message,
            "data": data,
            "error": error_payload,
            "metadata": metadata or {},
        }

    def _validate_task_context(self, task_context: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Required:
            - user_id
            - workspace_id

        This hook protects tenant isolation and is used by every public method.
        """

        if not isinstance(task_context, Mapping):
            return self._error_result(
                message="Invalid task context.",
                error="TASK_CONTEXT_MUST_BE_MAPPING",
            )

        user_id = _safe_str(task_context.get("user_id"))
        workspace_id = _safe_str(task_context.get("workspace_id"))

        if not user_id:
            return self._error_result(
                message="Missing required user_id for analytics context.",
                error="MISSING_USER_ID",
            )

        if not workspace_id:
            return self._error_result(
                message="Missing required workspace_id for analytics context.",
                error="MISSING_WORKSPACE_ID",
            )

        context = AnalyticsContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=_safe_str(task_context.get("role"), default="") or None,
            request_id=_safe_str(task_context.get("request_id"), default="") or None,
            session_id=_safe_str(task_context.get("session_id"), default="") or None,
            permissions=tuple(task_context.get("permissions") or ()),
        )

        return self._safe_result(
            message="Analytics context validated.",
            data=context,
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "agent": self.agent_name,
            },
        )

    def _requires_security_check(self, action: str, payload: Optional[Mapping[str, Any]] = None) -> bool:
        """
        Determine whether an analytics action needs Security Agent approval.

        Analytics reads are normally low-risk. Exporting sensitive detail,
        cross-workspace access, or raw record access should be protected.
        """

        action_key = _normalize_key(action)
        payload = payload or {}

        sensitive_actions = {
            "export_analytics",
            "raw_records",
            "cross_workspace_report",
            "financial_detail_report",
            "revenue_export",
            "client_level_export",
        }

        if action_key in sensitive_actions:
            return True

        if payload.get("include_raw_records") is True:
            return True

        if payload.get("include_client_details") is True:
            return True

        if payload.get("cross_workspace") is True:
            return True

        return False

    def _request_security_approval(
        self,
        *,
        action: str,
        task_context: Mapping[str, Any],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval when available.

        If no security client is attached, safe analytics reads continue, but
        sensitive actions are denied by default.
        """

        payload = dict(payload or {})
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        context: AnalyticsContext = context_result["data"]
        requires_check = self._requires_security_check(action, payload)

        if not requires_check:
            return self._safe_result(
                message="Security check not required for this analytics action.",
                data={"approved": True, "required": False},
                metadata=context.to_dict(),
            )

        approval_payload = {
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "risk": "medium",
            "reason": "Sensitive analytics access requires approval.",
            "context": context.to_dict(),
            "payload_summary": self._summarize_payload(payload),
            "timestamp": _utc_now().isoformat(),
        }

        if self.security_client is None:
            return self._error_result(
                message="Security approval is required but no Security Agent client is configured.",
                error="SECURITY_CLIENT_NOT_CONFIGURED",
                metadata={
                    **context.to_dict(),
                    "security_required": True,
                    "approval_payload": approval_payload,
                },
            )

        try:
            if hasattr(self.security_client, "request_approval"):
                approval = self.security_client.request_approval(approval_payload)
            elif hasattr(self.security_client, "approve"):
                approval = self.security_client.approve(approval_payload)
            else:
                return self._error_result(
                    message="Security client does not expose an approval method.",
                    error="SECURITY_CLIENT_INVALID",
                    metadata=context.to_dict(),
                )

            approved = bool(
                approval.get("approved")
                if isinstance(approval, Mapping)
                else getattr(approval, "approved", False)
            )

            if not approved:
                return self._error_result(
                    message="Security Agent denied analytics action.",
                    error="SECURITY_APPROVAL_DENIED",
                    metadata={
                        **context.to_dict(),
                        "approval": approval,
                    },
                )

            return self._safe_result(
                message="Security Agent approved analytics action.",
                data={"approved": True, "required": True, "approval": approval},
                metadata=context.to_dict(),
            )

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return self._error_result(
                message="Security approval request failed.",
                error=exc,
                metadata=context.to_dict(),
            )

    def _prepare_verification_payload(
        self,
        *,
        action: str,
        task_context: Mapping[str, Any],
        result: Mapping[str, Any],
        records_count: int = 0,
    ) -> Dict[str, Any]:
        """
        Prepare payload for Verification Agent.

        The Verification Agent can use this to confirm analytics output was
        scoped to the correct user/workspace and contains expected metrics.
        """

        context_result = self._validate_task_context(task_context)
        context_data = (
            context_result["data"].to_dict()
            if context_result.get("success") and hasattr(context_result.get("data"), "to_dict")
            else dict(task_context)
        )

        data = result.get("data") if isinstance(result, Mapping) else None
        metric_keys: List[str] = []

        if isinstance(data, Mapping):
            if isinstance(data.get("kpis"), Mapping):
                metric_keys.extend(data["kpis"].keys())
            if isinstance(data.get("summary"), Mapping):
                metric_keys.extend(data["summary"].keys())
            if isinstance(data.get("metrics"), Mapping):
                metric_keys.extend(data["metrics"].keys())

        return {
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "verification_type": "business_analytics",
            "context": context_data,
            "result_success": bool(result.get("success")) if isinstance(result, Mapping) else False,
            "records_count": records_count,
            "metric_keys": sorted(set(str(key) for key in metric_keys)),
            "checks": {
                "tenant_scope_enforced": True,
                "no_external_side_effects": True,
                "structured_result": isinstance(result, Mapping),
                "contains_success_field": isinstance(result, Mapping) and "success" in result,
                "contains_metadata": isinstance(result, Mapping) and "metadata" in result,
            },
            "timestamp": _utc_now().isoformat(),
        }

    def _prepare_memory_payload(
        self,
        *,
        action: str,
        task_context: Mapping[str, Any],
        result: Mapping[str, Any],
        memory_type: str = "business_analytics_snapshot",
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        This avoids storing raw sensitive records by default and stores only a
        compact analytics summary scoped to user/workspace.
        """

        context_result = self._validate_task_context(task_context)
        context_data = (
            context_result["data"].to_dict()
            if context_result.get("success") and hasattr(context_result.get("data"), "to_dict")
            else dict(task_context)
        )

        compact_summary = self._compact_result_summary(result)

        return {
            "memory_type": memory_type,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "action": action,
            "context": context_data,
            "summary": compact_summary,
            "sensitive_raw_records_included": False,
            "timestamp": _utc_now().isoformat(),
        }

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        task_context: Mapping[str, Any],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit Business Agent event.

        Used by dashboard, task history, registry observers, or future event bus.
        Fails safely without interrupting analytics calculation.
        """

        event = {
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "context": {
                "user_id": task_context.get("user_id"),
                "workspace_id": task_context.get("workspace_id"),
                "request_id": task_context.get("request_id"),
                "session_id": task_context.get("session_id"),
            },
            "payload": dict(payload or {}),
            "timestamp": _utc_now().isoformat(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                self.logger.debug("Agent event: %s", event)
        except Exception:
            self.logger.exception("Failed to emit agent event.")

    def _log_audit_event(
        self,
        *,
        action: str,
        task_context: Mapping[str, Any],
        success: bool,
        details: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event scoped to user/workspace.

        Analytics is read-only, but audit trails are still useful for dashboard
        history, SaaS compliance, and admin visibility.
        """

        audit_event = {
            "action": action,
            "agent": self.agent_name,
            "agent_type": self.agent_type,
            "success": bool(success),
            "user_id": task_context.get("user_id"),
            "workspace_id": task_context.get("workspace_id"),
            "request_id": task_context.get("request_id"),
            "session_id": task_context.get("session_id"),
            "details": dict(details or {}),
            "timestamp": _utc_now().isoformat(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_event)
            else:
                self.logger.info("Audit event: %s", audit_event)
        except Exception:
            self.logger.exception("Failed to log audit event.")

    # ------------------------------------------------------------------
    # Public Master Agent / Business Agent methods
    # ------------------------------------------------------------------

    async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Master Agent compatible task runner.

        Supported task actions:
            - dashboard_snapshot
            - calculate_kpis
            - lead_sources
            - conversion_rates
            - revenue_summary
            - trend_report
            - forecast
        """

        if not isinstance(task, Mapping):
            return self._error_result(
                message="Analytics task must be a mapping.",
                error="INVALID_TASK",
            )

        action = _normalize_key(task.get("action", "dashboard_snapshot"))
        task_context = task.get("context") or {
            "user_id": task.get("user_id"),
            "workspace_id": task.get("workspace_id"),
            "role": task.get("role"),
            "request_id": task.get("request_id"),
            "session_id": task.get("session_id"),
            "permissions": task.get("permissions") or (),
        }

        records = task.get("records") or task.get("data") or []
        window = task.get("window", AnalyticsWindow.ALL_TIME.value)
        start = task.get("start")
        end = task.get("end")
        granularity = task.get("granularity", "day")

        if action in {"dashboard_snapshot", "dashboard", "snapshot"}:
            return self.generate_dashboard_snapshot(
                records=records,
                task_context=task_context,
                window=window,
                start=start,
                end=end,
                granularity=granularity,
            )

        if action in {"calculate_kpis", "kpis", "kpi"}:
            return self.calculate_kpis(
                records=records,
                task_context=task_context,
                window=window,
                start=start,
                end=end,
            )

        if action in {"lead_sources", "source_performance", "sources"}:
            return self.calculate_lead_source_performance(
                records=records,
                task_context=task_context,
                window=window,
                start=start,
                end=end,
            )

        if action in {"conversion_rates", "conversions", "conversion"}:
            return self.calculate_conversion_rates(
                records=records,
                task_context=task_context,
                window=window,
                start=start,
                end=end,
            )

        if action in {"revenue_summary", "revenue", "sales_revenue"}:
            return self.calculate_revenue_summary(
                records=records,
                task_context=task_context,
                window=window,
                start=start,
                end=end,
                granularity=granularity,
            )

        if action in {"trend_report", "trends", "trend"}:
            metric = task.get("metric", "total_leads")
            return self.calculate_trends(
                records=records,
                task_context=task_context,
                metric=metric,
                window=window,
                start=start,
                end=end,
                granularity=granularity,
            )

        if action in {"forecast", "revenue_forecast", "sales_forecast"}:
            return self.forecast_revenue(
                records=records,
                task_context=task_context,
                window=window,
                start=start,
                end=end,
                granularity=granularity,
            )

        return self._error_result(
            message=f"Unsupported analytics action: {action}",
            error="UNSUPPORTED_ANALYTICS_ACTION",
            metadata={"action": action, "agent": self.agent_name},
        )

    def calculate_kpis(
        self,
        *,
        records: Sequence[Mapping[str, Any]],
        task_context: Mapping[str, Any],
        window: Union[str, AnalyticsWindow] = AnalyticsWindow.ALL_TIME,
        start: Optional[Any] = None,
        end: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Calculate primary business KPIs.

        KPIs:
            - total leads
            - new leads
            - qualified leads
            - won deals
            - lost deals
            - total revenue
            - pipeline value
            - conversion rate
            - win rate
            - average deal value
        """

        action = "calculate_kpis"
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        try:
            context: AnalyticsContext = context_result["data"]
            date_range = _daterange_from_window(window, start, end)
            normalized = self._normalize_records(records, context)
            filtered = self._filter_records(normalized, date_range)

            total_leads = len(filtered)
            new_leads = sum(1 for record in filtered if record.status == LEAD_STATUS_NEW)
            qualified_leads = sum(1 for record in filtered if record.is_qualified())
            won_deals = [record for record in filtered if record.is_won()]
            lost_deals = [record for record in filtered if record.is_lost()]
            open_pipeline = [record for record in filtered if record.is_open_pipeline()]

            total_revenue = sum((record.amount for record in won_deals), Decimal("0"))
            pipeline_value = sum((record.amount for record in open_pipeline), Decimal("0"))
            all_deal_value = sum((record.amount for record in filtered), Decimal("0"))
            avg_deal_value = _safe_ratio(total_revenue, len(won_deals)) if won_deals else Decimal("0")

            kpis = {
                MetricName.TOTAL_LEADS.value: total_leads,
                MetricName.NEW_LEADS.value: new_leads,
                MetricName.QUALIFIED_LEADS.value: qualified_leads,
                MetricName.WON_DEALS.value: len(won_deals),
                MetricName.LOST_DEALS.value: len(lost_deals),
                MetricName.TOTAL_REVENUE.value: _round_money(total_revenue),
                MetricName.PIPELINE_VALUE.value: _round_money(pipeline_value),
                "all_deal_value": _round_money(all_deal_value),
                MetricName.CONVERSION_RATE.value: _safe_percentage(len(won_deals), total_leads),
                MetricName.WIN_RATE.value: _safe_percentage(len(won_deals), len(won_deals) + len(lost_deals)),
                MetricName.AVERAGE_DEAL_VALUE.value: _round_money(avg_deal_value),
                MetricName.LEAD_TO_QUALIFIED_RATE.value: _safe_percentage(qualified_leads, total_leads),
                MetricName.QUALIFIED_TO_WON_RATE.value: _safe_percentage(len(won_deals), qualified_leads),
            }

            result = self._safe_result(
                message="Business KPIs calculated successfully.",
                data={
                    "kpis": kpis,
                    "date_range": date_range.to_dict(),
                    "currency": self.currency,
                    "records_count": len(filtered),
                },
                metadata={
                    **context.to_dict(),
                    "agent": self.agent_name,
                    "action": action,
                    "generated_at": _utc_now().isoformat(),
                },
            )

            self._emit_agent_event(
                event_name="business.analytics.kpis_calculated",
                task_context=task_context,
                payload={"records_count": len(filtered), "window": date_range.window},
            )
            self._log_audit_event(
                action=action,
                task_context=task_context,
                success=True,
                details={"records_count": len(filtered), "window": date_range.window},
            )

            return result

        except Exception as exc:
            self.logger.exception("Failed to calculate KPIs.")
            self._log_audit_event(action=action, task_context=task_context, success=False, details={"error": str(exc)})
            return self._error_result(
                message="Failed to calculate business KPIs.",
                error=exc,
                metadata={"agent": self.agent_name, "action": action},
            )

    def calculate_conversion_rates(
        self,
        *,
        records: Sequence[Mapping[str, Any]],
        task_context: Mapping[str, Any],
        window: Union[str, AnalyticsWindow] = AnalyticsWindow.ALL_TIME,
        start: Optional[Any] = None,
        end: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Calculate funnel and status conversion rates.

        Output is dashboard/API ready and can be used by report_builder.py later.
        """

        action = "calculate_conversion_rates"
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        try:
            context: AnalyticsContext = context_result["data"]
            date_range = _daterange_from_window(window, start, end)
            normalized = self._normalize_records(records, context)
            filtered = self._filter_records(normalized, date_range)

            status_counts: Counter[str] = Counter(record.status for record in filtered)
            total = len(filtered)
            won = sum(1 for record in filtered if record.is_won())
            lost = sum(1 for record in filtered if record.is_lost())
            qualified = sum(1 for record in filtered if record.is_qualified())
            contacted = status_counts.get(LEAD_STATUS_CONTACTED, 0)
            proposal = status_counts.get(LEAD_STATUS_PROPOSAL, 0)

            stage_rates = {
                "new_to_contacted_rate": _safe_percentage(contacted + qualified, total),
                "lead_to_qualified_rate": _safe_percentage(qualified, total),
                "qualified_to_proposal_rate": _safe_percentage(proposal + won, qualified),
                "proposal_to_won_rate": _safe_percentage(won, proposal + won),
                "overall_conversion_rate": _safe_percentage(won, total),
                "win_rate": _safe_percentage(won, won + lost),
                "loss_rate": _safe_percentage(lost, won + lost),
            }

            status_distribution = {
                status: {
                    "count": count,
                    "percentage": _safe_percentage(count, total),
                }
                for status, count in sorted(status_counts.items())
            }

            result = self._safe_result(
                message="Conversion rates calculated successfully.",
                data={
                    "conversion_rates": stage_rates,
                    "status_distribution": status_distribution,
                    "date_range": date_range.to_dict(),
                    "records_count": total,
                },
                metadata={
                    **context.to_dict(),
                    "agent": self.agent_name,
                    "action": action,
                    "generated_at": _utc_now().isoformat(),
                },
            )

            self._emit_agent_event(
                event_name="business.analytics.conversion_rates_calculated",
                task_context=task_context,
                payload={"records_count": total, "window": date_range.window},
            )
            self._log_audit_event(
                action=action,
                task_context=task_context,
                success=True,
                details={"records_count": total, "window": date_range.window},
            )

            return result

        except Exception as exc:
            self.logger.exception("Failed to calculate conversion rates.")
            self._log_audit_event(action=action, task_context=task_context, success=False, details={"error": str(exc)})
            return self._error_result(
                message="Failed to calculate conversion rates.",
                error=exc,
                metadata={"agent": self.agent_name, "action": action},
            )

    def calculate_lead_source_performance(
        self,
        *,
        records: Sequence[Mapping[str, Any]],
        task_context: Mapping[str, Any],
        window: Union[str, AnalyticsWindow] = AnalyticsWindow.ALL_TIME,
        start: Optional[Any] = None,
        end: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Calculate lead-source performance.

        Metrics per source:
            - leads
            - qualified leads
            - won deals
            - lost deals
            - revenue
            - pipeline value
            - conversion rate
            - average won deal value
        """

        action = "calculate_lead_source_performance"
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        try:
            context: AnalyticsContext = context_result["data"]
            date_range = _daterange_from_window(window, start, end)
            normalized = self._normalize_records(records, context)
            filtered = self._filter_records(normalized, date_range)

            grouped: Dict[str, List[AnalyticsRecord]] = defaultdict(list)
            for record in filtered:
                grouped[record.source or "unknown"].append(record)

            source_rows: List[Dict[str, Any]] = []
            for source, items in grouped.items():
                won_items = [item for item in items if item.is_won()]
                lost_items = [item for item in items if item.is_lost()]
                qualified_items = [item for item in items if item.is_qualified()]
                open_items = [item for item in items if item.is_open_pipeline()]

                revenue = sum((item.amount for item in won_items), Decimal("0"))
                pipeline = sum((item.amount for item in open_items), Decimal("0"))
                avg_won_value = _safe_ratio(revenue, len(won_items)) if won_items else Decimal("0")

                source_rows.append(
                    {
                        "source": source,
                        "leads": len(items),
                        "qualified_leads": len(qualified_items),
                        "won_deals": len(won_items),
                        "lost_deals": len(lost_items),
                        "revenue": _round_money(revenue),
                        "pipeline_value": _round_money(pipeline),
                        "conversion_rate": _safe_percentage(len(won_items), len(items)),
                        "win_rate": _safe_percentage(len(won_items), len(won_items) + len(lost_items)),
                        "lead_share": _safe_percentage(len(items), len(filtered)),
                        "average_won_deal_value": _round_money(avg_won_value),
                    }
                )

            source_rows.sort(key=lambda row: (row["revenue"], row["leads"]), reverse=True)

            best_source = source_rows[0]["source"] if source_rows else None

            result = self._safe_result(
                message="Lead source performance calculated successfully.",
                data={
                    "sources": source_rows,
                    "best_source": best_source,
                    "total_sources": len(source_rows),
                    "date_range": date_range.to_dict(),
                    "currency": self.currency,
                    "records_count": len(filtered),
                },
                metadata={
                    **context.to_dict(),
                    "agent": self.agent_name,
                    "action": action,
                    "generated_at": _utc_now().isoformat(),
                },
            )

            self._emit_agent_event(
                event_name="business.analytics.lead_sources_calculated",
                task_context=task_context,
                payload={"sources_count": len(source_rows), "records_count": len(filtered)},
            )
            self._log_audit_event(
                action=action,
                task_context=task_context,
                success=True,
                details={"sources_count": len(source_rows), "records_count": len(filtered)},
            )

            return result

        except Exception as exc:
            self.logger.exception("Failed to calculate lead source performance.")
            self._log_audit_event(action=action, task_context=task_context, success=False, details={"error": str(exc)})
            return self._error_result(
                message="Failed to calculate lead source performance.",
                error=exc,
                metadata={"agent": self.agent_name, "action": action},
            )

    def calculate_revenue_summary(
        self,
        *,
        records: Sequence[Mapping[str, Any]],
        task_context: Mapping[str, Any],
        window: Union[str, AnalyticsWindow] = AnalyticsWindow.ALL_TIME,
        start: Optional[Any] = None,
        end: Optional[Any] = None,
        granularity: str = "month",
    ) -> Dict[str, Any]:
        """
        Calculate revenue analytics.

        Revenue is counted from won/converted/paid records. Pipeline value is
        counted from open records.
        """

        action = "calculate_revenue_summary"
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        try:
            context: AnalyticsContext = context_result["data"]
            date_range = _daterange_from_window(window, start, end)
            normalized = self._normalize_records(records, context)
            filtered = self._filter_records(normalized, date_range)

            won_records = [record for record in filtered if record.is_won()]
            open_records = [record for record in filtered if record.is_open_pipeline()]

            total_revenue = sum((record.amount for record in won_records), Decimal("0"))
            pipeline_value = sum((record.amount for record in open_records), Decimal("0"))
            average_revenue = _safe_ratio(total_revenue, len(won_records)) if won_records else Decimal("0")
            highest_deal = max((record.amount for record in won_records), default=Decimal("0"))
            lowest_deal = min((record.amount for record in won_records), default=Decimal("0"))

            revenue_by_period: Dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
            pipeline_by_period: Dict[str, Decimal] = defaultdict(lambda: Decimal("0"))

            for record in won_records:
                key = _period_key(record.closed_at or record.created_at, granularity)
                revenue_by_period[key] += record.amount

            for record in open_records:
                key = _period_key(record.created_at, granularity)
                pipeline_by_period[key] += record.amount

            revenue_series = [
                {"period": key, "revenue": _round_money(value)}
                for key, value in sorted(revenue_by_period.items())
            ]
            pipeline_series = [
                {"period": key, "pipeline_value": _round_money(value)}
                for key, value in sorted(pipeline_by_period.items())
            ]

            result = self._safe_result(
                message="Revenue summary calculated successfully.",
                data={
                    "summary": {
                        "total_revenue": _round_money(total_revenue),
                        "pipeline_value": _round_money(pipeline_value),
                        "won_deals": len(won_records),
                        "open_deals": len(open_records),
                        "average_revenue_per_won_deal": _round_money(average_revenue),
                        "highest_won_deal": _round_money(highest_deal),
                        "lowest_won_deal": _round_money(lowest_deal),
                    },
                    "revenue_series": revenue_series,
                    "pipeline_series": pipeline_series,
                    "date_range": date_range.to_dict(),
                    "granularity": granularity,
                    "currency": self.currency,
                    "records_count": len(filtered),
                },
                metadata={
                    **context.to_dict(),
                    "agent": self.agent_name,
                    "action": action,
                    "generated_at": _utc_now().isoformat(),
                },
            )

            self._emit_agent_event(
                event_name="business.analytics.revenue_summary_calculated",
                task_context=task_context,
                payload={"records_count": len(filtered), "revenue": _round_money(total_revenue)},
            )
            self._log_audit_event(
                action=action,
                task_context=task_context,
                success=True,
                details={"records_count": len(filtered), "revenue": _round_money(total_revenue)},
            )

            return result

        except Exception as exc:
            self.logger.exception("Failed to calculate revenue summary.")
            self._log_audit_event(action=action, task_context=task_context, success=False, details={"error": str(exc)})
            return self._error_result(
                message="Failed to calculate revenue summary.",
                error=exc,
                metadata={"agent": self.agent_name, "action": action},
            )

    def calculate_trends(
        self,
        *,
        records: Sequence[Mapping[str, Any]],
        task_context: Mapping[str, Any],
        metric: str = MetricName.TOTAL_LEADS.value,
        window: Union[str, AnalyticsWindow] = AnalyticsWindow.ALL_TIME,
        start: Optional[Any] = None,
        end: Optional[Any] = None,
        granularity: str = "day",
    ) -> Dict[str, Any]:
        """
        Calculate trend series for a selected metric.

        Supported metrics:
            - total_leads
            - qualified_leads
            - won_deals
            - lost_deals
            - total_revenue
            - pipeline_value
            - conversion_rate
        """

        action = "calculate_trends"
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        try:
            context: AnalyticsContext = context_result["data"]
            metric_key = _normalize_key(metric)
            date_range = _daterange_from_window(window, start, end)
            normalized = self._normalize_records(records, context)
            filtered = self._filter_records(normalized, date_range)

            grouped: Dict[str, List[AnalyticsRecord]] = defaultdict(list)
            for record in filtered:
                dt = record.closed_at if metric_key == MetricName.TOTAL_REVENUE.value and record.closed_at else record.created_at
                grouped[_period_key(dt, granularity)].append(record)

            series: List[Dict[str, Any]] = []
            previous_value = Decimal("0")

            for period, items in sorted(grouped.items()):
                value = self._calculate_metric_value(items, metric_key)
                direction = _trend_direction(value, previous_value)
                change_percent = _trend_change_percent(value, previous_value)

                series.append(
                    {
                        "period": period,
                        "value": _round_money(value) if "revenue" in metric_key or "value" in metric_key else _round_percent(value),
                        "trend_direction": direction,
                        "change_percent": change_percent,
                    }
                )

                previous_value = value

            total_value = self._calculate_metric_value(filtered, metric_key)
            first_value = _decimal(series[0]["value"]) if series else Decimal("0")
            last_value = _decimal(series[-1]["value"]) if series else Decimal("0")

            result = self._safe_result(
                message="Trend report calculated successfully.",
                data={
                    "metric": metric_key,
                    "series": series,
                    "summary": {
                        "periods": len(series),
                        "total_or_current_value": (
                            _round_money(total_value)
                            if "revenue" in metric_key or "value" in metric_key
                            else _round_percent(total_value)
                        ),
                        "first_period_value": float(first_value),
                        "last_period_value": float(last_value),
                        "overall_direction": _trend_direction(last_value, first_value),
                        "overall_change_percent": _trend_change_percent(last_value, first_value),
                    },
                    "date_range": date_range.to_dict(),
                    "granularity": granularity,
                    "records_count": len(filtered),
                },
                metadata={
                    **context.to_dict(),
                    "agent": self.agent_name,
                    "action": action,
                    "generated_at": _utc_now().isoformat(),
                },
            )

            self._emit_agent_event(
                event_name="business.analytics.trends_calculated",
                task_context=task_context,
                payload={"metric": metric_key, "records_count": len(filtered)},
            )
            self._log_audit_event(
                action=action,
                task_context=task_context,
                success=True,
                details={"metric": metric_key, "records_count": len(filtered)},
            )

            return result

        except Exception as exc:
            self.logger.exception("Failed to calculate trends.")
            self._log_audit_event(action=action, task_context=task_context, success=False, details={"error": str(exc)})
            return self._error_result(
                message="Failed to calculate trends.",
                error=exc,
                metadata={"agent": self.agent_name, "action": action, "metric": metric},
            )

    def generate_dashboard_snapshot(
        self,
        *,
        records: Sequence[Mapping[str, Any]],
        task_context: Mapping[str, Any],
        window: Union[str, AnalyticsWindow] = AnalyticsWindow.LAST_30_DAYS,
        start: Optional[Any] = None,
        end: Optional[Any] = None,
        granularity: str = "day",
    ) -> Dict[str, Any]:
        """
        Generate a complete dashboard snapshot.

        Combines:
            - KPIs
            - conversion rates
            - lead source performance
            - revenue summary
            - lead trend
            - revenue trend
            - verification payload
            - memory payload
        """

        action = "generate_dashboard_snapshot"
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        security_result = self._request_security_approval(
            action=action,
            task_context=task_context,
            payload={"include_raw_records": False, "dashboard_snapshot": True},
        )
        if not security_result["success"]:
            return security_result

        try:
            context: AnalyticsContext = context_result["data"]
            date_range = _daterange_from_window(window, start, end)
            normalized = self._normalize_records(records, context)
            filtered_dicts = [record.raw for record in self._filter_records(normalized, date_range)]

            kpis = self.calculate_kpis(
                records=filtered_dicts,
                task_context=task_context,
                window=AnalyticsWindow.ALL_TIME.value,
            )
            conversions = self.calculate_conversion_rates(
                records=filtered_dicts,
                task_context=task_context,
                window=AnalyticsWindow.ALL_TIME.value,
            )
            sources = self.calculate_lead_source_performance(
                records=filtered_dicts,
                task_context=task_context,
                window=AnalyticsWindow.ALL_TIME.value,
            )
            revenue = self.calculate_revenue_summary(
                records=filtered_dicts,
                task_context=task_context,
                window=AnalyticsWindow.ALL_TIME.value,
                granularity=granularity,
            )
            lead_trend = self.calculate_trends(
                records=filtered_dicts,
                task_context=task_context,
                metric=MetricName.TOTAL_LEADS.value,
                window=AnalyticsWindow.ALL_TIME.value,
                granularity=granularity,
            )
            revenue_trend = self.calculate_trends(
                records=filtered_dicts,
                task_context=task_context,
                metric=MetricName.TOTAL_REVENUE.value,
                window=AnalyticsWindow.ALL_TIME.value,
                granularity=granularity,
            )

            snapshot_data = {
                "snapshot": {
                    "kpis": kpis.get("data", {}).get("kpis", {}),
                    "conversion_rates": conversions.get("data", {}).get("conversion_rates", {}),
                    "status_distribution": conversions.get("data", {}).get("status_distribution", {}),
                    "lead_sources": sources.get("data", {}).get("sources", []),
                    "revenue": revenue.get("data", {}).get("summary", {}),
                    "lead_trend": lead_trend.get("data", {}).get("series", []),
                    "revenue_trend": revenue_trend.get("data", {}).get("series", []),
                },
                "date_range": date_range.to_dict(),
                "granularity": granularity,
                "currency": self.currency,
                "records_count": len(filtered_dicts),
            }

            result = self._safe_result(
                message="Business analytics dashboard snapshot generated successfully.",
                data=snapshot_data,
                metadata={
                    **context.to_dict(),
                    "agent": self.agent_name,
                    "action": action,
                    "generated_at": _utc_now().isoformat(),
                    "security": security_result.get("data"),
                },
            )

            verification_payload = self._prepare_verification_payload(
                action=action,
                task_context=task_context,
                result=result,
                records_count=len(filtered_dicts),
            )
            memory_payload = self._prepare_memory_payload(
                action=action,
                task_context=task_context,
                result=result,
            )

            result["metadata"]["verification_payload"] = verification_payload
            result["metadata"]["memory_payload"] = memory_payload

            self._emit_agent_event(
                event_name="business.analytics.dashboard_snapshot_generated",
                task_context=task_context,
                payload={"records_count": len(filtered_dicts), "window": date_range.window},
            )
            self._log_audit_event(
                action=action,
                task_context=task_context,
                success=True,
                details={"records_count": len(filtered_dicts), "window": date_range.window},
            )

            return result

        except Exception as exc:
            self.logger.exception("Failed to generate dashboard snapshot.")
            self._log_audit_event(action=action, task_context=task_context, success=False, details={"error": str(exc)})
            return self._error_result(
                message="Failed to generate business analytics dashboard snapshot.",
                error=exc,
                metadata={"agent": self.agent_name, "action": action},
            )

    def forecast_revenue(
        self,
        *,
        records: Sequence[Mapping[str, Any]],
        task_context: Mapping[str, Any],
        window: Union[str, AnalyticsWindow] = AnalyticsWindow.LAST_90_DAYS,
        start: Optional[Any] = None,
        end: Optional[Any] = None,
        granularity: str = "month",
        periods_ahead: int = 3,
    ) -> Dict[str, Any]:
        """
        Produce a simple safe revenue forecast.

        This uses historical average period revenue and basic linear direction.
        It is intentionally conservative and does not perform financial actions.
        """

        action = "forecast_revenue"
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        try:
            context: AnalyticsContext = context_result["data"]
            trend_result = self.calculate_trends(
                records=records,
                task_context=task_context,
                metric=MetricName.TOTAL_REVENUE.value,
                window=window,
                start=start,
                end=end,
                granularity=granularity,
            )

            if not trend_result["success"]:
                return trend_result

            series = trend_result.get("data", {}).get("series", [])
            values = [_decimal(item.get("value")) for item in series if isinstance(item, Mapping)]

            if not values:
                forecast = []
                confidence = "low"
                average_value = Decimal("0")
                slope = Decimal("0")
            else:
                average_value = sum(values, Decimal("0")) / Decimal(len(values))
                slope = self._simple_slope(values)
                forecast = []
                last_value = values[-1]

                safe_periods = max(1, min(int(periods_ahead), 12))
                for index in range(1, safe_periods + 1):
                    predicted = last_value + (slope * Decimal(index))
                    if predicted < 0:
                        predicted = Decimal("0")

                    forecast.append(
                        {
                            "period_ahead": index,
                            "predicted_revenue": _round_money(predicted),
                            "method": "historical_average_with_linear_direction",
                        }
                    )

                confidence = self._forecast_confidence(values)

            result = self._safe_result(
                message="Revenue forecast calculated successfully.",
                data={
                    "forecast": forecast,
                    "historical_average_period_revenue": _round_money(average_value),
                    "estimated_period_slope": _round_money(slope),
                    "confidence": confidence,
                    "granularity": granularity,
                    "currency": self.currency,
                    "source_series": series,
                },
                metadata={
                    **context.to_dict(),
                    "agent": self.agent_name,
                    "action": action,
                    "generated_at": _utc_now().isoformat(),
                    "note": "Forecast is informational and does not perform financial actions.",
                },
            )

            self._emit_agent_event(
                event_name="business.analytics.revenue_forecast_calculated",
                task_context=task_context,
                payload={"periods_ahead": periods_ahead, "confidence": confidence},
            )
            self._log_audit_event(
                action=action,
                task_context=task_context,
                success=True,
                details={"periods_ahead": periods_ahead, "confidence": confidence},
            )

            return result

        except Exception as exc:
            self.logger.exception("Failed to forecast revenue.")
            self._log_audit_event(action=action, task_context=task_context, success=False, details={"error": str(exc)})
            return self._error_result(
                message="Failed to calculate revenue forecast.",
                error=exc,
                metadata={"agent": self.agent_name, "action": action},
            )

    # ------------------------------------------------------------------
    # Record normalization and filtering
    # ------------------------------------------------------------------

    def _normalize_records(
        self,
        records: Sequence[Mapping[str, Any]],
        context: AnalyticsContext,
    ) -> List[AnalyticsRecord]:
        """
        Normalize raw records and enforce user/workspace isolation.

        Records that do not belong to the active user/workspace are excluded
        when strict_workspace_filtering is enabled.
        """

        normalized: List[AnalyticsRecord] = []

        if not records:
            return normalized

        for index, raw_record in enumerate(records):
            if not isinstance(raw_record, Mapping):
                continue

            raw = dict(raw_record)

            record_user_id = _safe_str(raw.get("user_id"), default=context.user_id)
            record_workspace_id = _safe_str(raw.get("workspace_id"), default=context.workspace_id)

            if self.strict_workspace_filtering:
                if record_user_id != context.user_id or record_workspace_id != context.workspace_id:
                    continue

            record_id = _safe_str(
                raw.get("id")
                or raw.get("record_id")
                or raw.get("lead_id")
                or raw.get("deal_id")
                or raw.get("client_id")
                or f"analytics_record_{index}"
            )

            status = _normalize_key(_first_present(raw, STATUS_KEYS, default=LEAD_STATUS_NEW), LEAD_STATUS_NEW)
            source = _normalize_key(_first_present(raw, SOURCE_KEYS, default="unknown"), "unknown")
            amount = self._extract_amount(raw)

            created_at = _parse_datetime(_first_present(raw, DATE_KEYS, default=None))
            closed_at = _parse_datetime(raw.get("closed_at") or raw.get("won_at") or raw.get("paid_at"))

            owner_id = _safe_str(_first_present(raw, OWNER_KEYS, default=""), default="") or None
            campaign_id = _safe_str(raw.get("campaign_id") or raw.get("campaign") or raw.get("utm_campaign"), default="") or None
            client_id = _safe_str(raw.get("client_id") or raw.get("customer_id") or raw.get("account_id"), default="") or None

            normalized.append(
                AnalyticsRecord(
                    record_id=record_id,
                    user_id=record_user_id,
                    workspace_id=record_workspace_id,
                    status=status,
                    source=source,
                    amount=amount,
                    created_at=created_at,
                    closed_at=closed_at,
                    owner_id=owner_id,
                    campaign_id=campaign_id,
                    client_id=client_id,
                    raw=raw,
                )
            )

        return normalized

    def _filter_records(
        self,
        records: Sequence[AnalyticsRecord],
        date_range: DateRange,
    ) -> List[AnalyticsRecord]:
        """Filter records by created_at date range."""

        if date_range.start is None and date_range.end is None:
            return list(records)

        filtered: List[AnalyticsRecord] = []
        for record in records:
            dt = record.created_at or record.closed_at
            if _is_in_range(dt, date_range):
                filtered.append(record)

        return filtered

    def _extract_amount(self, raw: Mapping[str, Any]) -> Decimal:
        """Extract revenue/deal amount from common record keys."""

        for key in REVENUE_KEYS:
            if key in raw and raw[key] not in (None, ""):
                return _decimal(raw[key])

        nested_keys = ("deal", "revenue_info", "payment", "invoice", "opportunity")
        for nested_key in nested_keys:
            nested = raw.get(nested_key)
            if isinstance(nested, Mapping):
                for key in REVENUE_KEYS:
                    if key in nested and nested[key] not in (None, ""):
                        return _decimal(nested[key])

        return Decimal("0")

    # ------------------------------------------------------------------
    # Metric internals
    # ------------------------------------------------------------------

    def _calculate_metric_value(self, records: Sequence[AnalyticsRecord], metric_key: str) -> Decimal:
        """Calculate one metric value from normalized records."""

        metric_key = _normalize_key(metric_key)

        if metric_key == MetricName.TOTAL_LEADS.value:
            return Decimal(len(records))

        if metric_key == MetricName.NEW_LEADS.value:
            return Decimal(sum(1 for record in records if record.status == LEAD_STATUS_NEW))

        if metric_key == MetricName.QUALIFIED_LEADS.value:
            return Decimal(sum(1 for record in records if record.is_qualified()))

        if metric_key == MetricName.WON_DEALS.value:
            return Decimal(sum(1 for record in records if record.is_won()))

        if metric_key == MetricName.LOST_DEALS.value:
            return Decimal(sum(1 for record in records if record.is_lost()))

        if metric_key == MetricName.TOTAL_REVENUE.value:
            return sum((record.amount for record in records if record.is_won()), Decimal("0"))

        if metric_key == MetricName.PIPELINE_VALUE.value:
            return sum((record.amount for record in records if record.is_open_pipeline()), Decimal("0"))

        if metric_key == MetricName.CONVERSION_RATE.value:
            won = sum(1 for record in records if record.is_won())
            return _safe_ratio(won, len(records)) * Decimal("100")

        if metric_key == MetricName.WIN_RATE.value:
            won = sum(1 for record in records if record.is_won())
            lost = sum(1 for record in records if record.is_lost())
            return _safe_ratio(won, won + lost) * Decimal("100")

        if metric_key == MetricName.AVERAGE_DEAL_VALUE.value:
            won_amounts = [record.amount for record in records if record.is_won()]
            if not won_amounts:
                return Decimal("0")
            return sum(won_amounts, Decimal("0")) / Decimal(len(won_amounts))

        return Decimal(len(records))

    def _simple_slope(self, values: Sequence[Decimal]) -> Decimal:
        """
        Calculate simple slope from sequential values.

        Used only for conservative dashboard forecasting.
        """

        if len(values) < 2:
            return Decimal("0")

        diffs = [values[index] - values[index - 1] for index in range(1, len(values))]
        return sum(diffs, Decimal("0")) / Decimal(len(diffs))

    def _forecast_confidence(self, values: Sequence[Decimal]) -> str:
        """Return simple confidence label based on amount of data and variance."""

        if len(values) < 3:
            return "low"

        float_values = [float(value) for value in values]

        try:
            mean_value = statistics.mean(float_values)
            stdev_value = statistics.pstdev(float_values)
        except Exception:
            return "low"

        if mean_value == 0:
            return "low"

        coefficient = stdev_value / abs(mean_value)

        if len(values) >= 6 and coefficient < 0.35:
            return "medium"
        if len(values) >= 9 and coefficient < 0.2:
            return "high"
        return "low"

    # ------------------------------------------------------------------
    # Payload helpers
    # ------------------------------------------------------------------

    def _summarize_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Create safe payload summary without exposing raw records."""

        summary: Dict[str, Any] = {}
        for key, value in payload.items():
            if key in {"records", "raw_records", "data"}:
                if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                    summary[key] = {"type": "sequence", "count": len(value)}
                else:
                    summary[key] = {"type": type(value).__name__}
            elif isinstance(value, (str, int, float, bool)) or value is None:
                summary[key] = value
            else:
                summary[key] = {"type": type(value).__name__}
        return summary

    def _compact_result_summary(self, result: Mapping[str, Any]) -> Dict[str, Any]:
        """Compact result for Memory Agent safe storage."""

        data = result.get("data") if isinstance(result, Mapping) else None
        if not isinstance(data, Mapping):
            return {"success": bool(result.get("success")) if isinstance(result, Mapping) else False}

        snapshot = data.get("snapshot")
        if isinstance(snapshot, Mapping):
            return {
                "kpis": snapshot.get("kpis", {}),
                "revenue": snapshot.get("revenue", {}),
                "top_lead_sources": list(snapshot.get("lead_sources", []))[:5],
                "conversion_rates": snapshot.get("conversion_rates", {}),
                "records_count": data.get("records_count"),
                "date_range": data.get("date_range"),
            }

        return {
            "kpis": data.get("kpis", {}),
            "summary": data.get("summary", {}),
            "records_count": data.get("records_count"),
            "date_range": data.get("date_range"),
        }

    # ------------------------------------------------------------------
    # Extra dashboard/API helper methods
    # ------------------------------------------------------------------

    def get_supported_metrics(self) -> Dict[str, Any]:
        """Return metrics supported by this engine."""

        return self._safe_result(
            message="Supported analytics metrics loaded.",
            data={
                "metrics": [metric.value for metric in MetricName],
                "windows": [window.value for window in AnalyticsWindow],
                "trend_granularities": ["hour", "day", "week", "month", "quarter", "year"],
                "currency": self.currency,
            },
            metadata={
                "agent": self.agent_name,
                "version": self.version,
            },
        )

    def validate_records_for_dashboard(
        self,
        *,
        records: Sequence[Mapping[str, Any]],
        task_context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Validate records before dashboard/API usage.

        This is useful for FastAPI endpoints and tests.
        """

        action = "validate_records_for_dashboard"
        context_result = self._validate_task_context(task_context)
        if not context_result["success"]:
            return context_result

        try:
            context: AnalyticsContext = context_result["data"]
            normalized = self._normalize_records(records, context)

            invalid_count = 0
            missing_date_count = 0
            zero_amount_count = 0
            unknown_source_count = 0

            for record in normalized:
                if not record.record_id:
                    invalid_count += 1
                if record.created_at is None and record.closed_at is None:
                    missing_date_count += 1
                if record.amount == 0:
                    zero_amount_count += 1
                if record.source == "unknown":
                    unknown_source_count += 1

            return self._safe_result(
                message="Analytics records validated successfully.",
                data={
                    "input_count": len(records or []),
                    "usable_count": len(normalized),
                    "invalid_count": invalid_count,
                    "missing_date_count": missing_date_count,
                    "zero_amount_count": zero_amount_count,
                    "unknown_source_count": unknown_source_count,
                    "strict_workspace_filtering": self.strict_workspace_filtering,
                },
                metadata={
                    **context.to_dict(),
                    "agent": self.agent_name,
                    "action": action,
                },
            )

        except Exception as exc:
            return self._error_result(
                message="Failed to validate analytics records.",
                error=exc,
                metadata={"agent": self.agent_name, "action": action},
            )


# ---------------------------------------------------------------------------
# Module-level factory and test sample
# ---------------------------------------------------------------------------

def create_analytics_engine(**kwargs: Any) -> AnalyticsEngine:
    """
    Factory for Agent Loader / Registry compatibility.

    Example:
        engine = create_analytics_engine(currency="USD")
    """

    return AnalyticsEngine(**kwargs)


def get_agent_metadata() -> Dict[str, Any]:
    """
    Return registry-friendly metadata for this agent/helper module.
    """

    return {
        "agent_name": AnalyticsEngine.agent_name,
        "agent_type": AnalyticsEngine.agent_type,
        "class_name": "AnalyticsEngine",
        "version": AnalyticsEngine.version,
        "module": "agents.super_agents.business_agent.analytics_engine",
        "file_path": "agents/super_agents/business_agent/analytics_engine.py",
        "capabilities": [
            "calculate_kpis",
            "calculate_conversion_rates",
            "calculate_lead_source_performance",
            "calculate_revenue_summary",
            "calculate_trends",
            "generate_dashboard_snapshot",
            "forecast_revenue",
            "prepare_verification_payload",
            "prepare_memory_payload",
        ],
        "requires_user_context": True,
        "requires_workspace_context": True,
        "side_effects": "read_only_analytics",
        "safe_to_import": True,
    }


__all__ = [
    "AnalyticsEngine",
    "AnalyticsContext",
    "AnalyticsRecord",
    "AnalyticsWindow",
    "DateRange",
    "MetricName",
    "TrendDirection",
    "create_analytics_engine",
    "get_agent_metadata",
]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    sample_context = {
        "user_id": "demo_user",
        "workspace_id": "demo_workspace",
        "role": "owner",
        "request_id": "local_test",
    }

    sample_records = [
        {
            "id": "lead_1",
            "user_id": "demo_user",
            "workspace_id": "demo_workspace",
            "status": "won",
            "source": "google_ads",
            "amount": 1500,
            "created_at": "2026-06-01",
            "closed_at": "2026-06-05",
        },
        {
            "id": "lead_2",
            "user_id": "demo_user",
            "workspace_id": "demo_workspace",
            "status": "qualified",
            "source": "facebook",
            "amount": 900,
            "created_at": "2026-06-10",
        },
        {
            "id": "lead_3",
            "user_id": "demo_user",
            "workspace_id": "demo_workspace",
            "status": "lost",
            "source": "organic",
            "amount": 700,
            "created_at": "2026-06-12",
        },
    ]

    engine = AnalyticsEngine()
    output = engine.generate_dashboard_snapshot(
        records=sample_records,
        task_context=sample_context,
        window=AnalyticsWindow.ALL_TIME.value,
        granularity="day",
    )
    print(output)