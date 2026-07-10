"""
William / Jarvis Multi-Agent AI SaaS System
Business Agent - Report Builder

File: agents/super_agents/business_agent/report_builder.py
Class: BusinessReportBuilder

Purpose:
    Builds business reports, client reports, and weekly summaries for SaaS users
    and workspaces with strict user_id/workspace_id isolation.

Architecture Compatibility:
    - BaseAgent compatible with safe fallback if BaseAgent is unavailable.
    - Master Agent / Agent Router compatible through clear public methods.
    - Security Agent compatible through approval hook payloads.
    - Verification Agent compatible through verification payload generation.
    - Memory Agent compatible through memory-safe context payloads.
    - Dashboard/API ready through structured dict/JSON style responses.
    - Import-safe even when future William modules are not yet created.

Important Safety Rules:
    - Every user/workspace operation validates user_id and workspace_id.
    - No cross-workspace data mixing.
    - No destructive/system/financial/message/call/browser actions are executed.
    - Sensitive report actions can be routed through Security Agent hooks.
    - All outputs follow structured result format:
        success, message, data, error, metadata
"""

from __future__ import annotations

import copy
import csv
import io
import json
import logging
import statistics
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, date, timedelta, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe Optional BaseAgent Import
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for isolated import safety
    class BaseAgent:  # type: ignore
        """
        Safe fallback BaseAgent stub.

        This allows the file to import successfully even before the real William
        BaseAgent is available. The real system should provide agents.base_agent.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())

        def emit_event(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
            return {"success": True, "message": "Fallback event emitted.", "data": kwargs}

        def log(self, *args: Any, **kwargs: Any) -> None:
            return None


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger(__name__)
if not logger.handlers:
    logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_AGENT_NAME = "business_report_builder"
DEFAULT_AGENT_VERSION = "1.0.0"
DEFAULT_REPORT_CURRENCY = "USD"

SENSITIVE_REPORT_TYPES = {
    "financial",
    "revenue",
    "client",
    "executive",
    "export",
    "custom",
}

ALLOWED_EXPORT_FORMATS = {"json", "csv", "dict"}

DEFAULT_SUMMARY_LIMIT = 12
MAX_REPORT_ITEMS = 5000


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ReportType(str, Enum):
    """Supported report types."""

    BUSINESS = "business"
    CLIENT = "client"
    WEEKLY_SUMMARY = "weekly_summary"
    CAMPAIGN = "campaign"
    SALES = "sales"
    REVENUE = "revenue"
    LEADS = "leads"
    CUSTOM = "custom"


class ReportStatus(str, Enum):
    """Report generation status."""

    DRAFT = "draft"
    READY = "ready"
    NEEDS_REVIEW = "needs_review"
    BLOCKED = "blocked"
    FAILED = "failed"


class ReportFormat(str, Enum):
    """Supported report output formats."""

    DICT = "dict"
    JSON = "json"
    CSV = "csv"


class RiskLevel(str, Enum):
    """Security/audit risk levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class ReportContext:
    """
    SaaS-safe execution context.

    user_id and workspace_id are mandatory for any report involving user-specific
    business data. request_id and trace_id help connect Dashboard/API requests,
    Master Agent routing, audit logs, and Verification Agent payloads.
    """

    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    role: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    source_agent: Optional[str] = None
    locale: str = "en-US"
    timezone_name: str = "UTC"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReportPeriod:
    """Date range for a report."""

    start_date: Optional[str] = None
    end_date: Optional[str] = None
    label: Optional[str] = None


@dataclass
class ReportSection:
    """A structured report section."""

    title: str
    summary: str
    metrics: Dict[str, Any] = field(default_factory=dict)
    items: List[Dict[str, Any]] = field(default_factory=list)
    insights: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BusinessReport:
    """Final structured report object."""

    report_id: str
    report_type: str
    title: str
    status: str
    period: Dict[str, Any]
    sections: List[Dict[str, Any]]
    executive_summary: str
    highlights: List[str]
    risks: List[str]
    recommendations: List[str]
    generated_at: str
    generated_by: str
    user_id: str
    workspace_id: str
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def _utc_now_iso() -> str:
    """Return current UTC datetime as ISO string."""
    return _utc_now().isoformat()


def _safe_str(value: Any, default: str = "") -> str:
    """Safely convert a value to string."""
    if value is None:
        return default
    try:
        return str(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    """Safely convert value to float."""
    if value is None:
        return default
    try:
        if isinstance(value, bool):
            return float(int(value))
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    """Safely convert value to int."""
    if value is None:
        return default
    try:
        if isinstance(value, bool):
            return int(value)
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _safe_percent(numerator: Any, denominator: Any, precision: int = 2) -> float:
    """Calculate safe percentage."""
    den = _safe_float(denominator)
    if den == 0:
        return 0.0
    return round((_safe_float(numerator) / den) * 100, precision)


def _safe_divide(numerator: Any, denominator: Any, precision: int = 2) -> float:
    """Safely divide numbers."""
    den = _safe_float(denominator)
    if den == 0:
        return 0.0
    return round(_safe_float(numerator) / den, precision)


def _deepcopy_json_safe(value: Any) -> Any:
    """Deep copy a value and keep it JSON-safe where possible."""
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        try:
            return copy.deepcopy(value)
        except Exception:
            return str(value)


def _normalize_date(value: Any) -> Optional[str]:
    """
    Normalize date/datetime/string into YYYY-MM-DD where possible.

    Returns None if parsing fails.
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        return value.date().isoformat()

    if isinstance(value, date):
        return value.isoformat()

    text = _safe_str(value).strip()
    if not text:
        return None

    try:
        if "T" in text:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).date().isoformat()
        return date.fromisoformat(text[:10]).isoformat()
    except Exception:
        return None


def _parse_date(value: Any) -> Optional[date]:
    """Parse a date-like value into date."""
    normalized = _normalize_date(value)
    if not normalized:
        return None
    try:
        return date.fromisoformat(normalized)
    except Exception:
        return None


def _date_in_period(value: Any, period: ReportPeriod) -> bool:
    """Return True when value is inside the report period."""
    parsed = _parse_date(value)
    if parsed is None:
        return True

    start = _parse_date(period.start_date)
    end = _parse_date(period.end_date)

    if start and parsed < start:
        return False
    if end and parsed > end:
        return False
    return True


def _limit_items(items: Sequence[Dict[str, Any]], limit: int = MAX_REPORT_ITEMS) -> List[Dict[str, Any]]:
    """Limit report input size to avoid accidental large memory use."""
    safe_limit = max(0, min(_safe_int(limit, MAX_REPORT_ITEMS), MAX_REPORT_ITEMS))
    return [_deepcopy_json_safe(item) for item in list(items)[:safe_limit]]


def _extract_number(item: Mapping[str, Any], keys: Sequence[str], default: float = 0.0) -> float:
    """Extract first numeric value found from possible keys."""
    for key in keys:
        if key in item:
            return _safe_float(item.get(key), default)
    return default


def _extract_text(item: Mapping[str, Any], keys: Sequence[str], default: str = "") -> str:
    """Extract first non-empty text value found from possible keys."""
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return _safe_str(value, default)
    return default


def _group_count(items: Iterable[Mapping[str, Any]], key: str) -> Dict[str, int]:
    """Count items by key."""
    output: Dict[str, int] = {}
    for item in items:
        value = _safe_str(item.get(key), "unknown").strip() or "unknown"
        output[value] = output.get(value, 0) + 1
    return output


def _top_items(mapping: Mapping[str, Union[int, float]], limit: int = 5) -> List[Dict[str, Any]]:
    """Return top key/value pairs as list of dicts."""
    sorted_items = sorted(mapping.items(), key=lambda pair: _safe_float(pair[1]), reverse=True)
    return [{"name": key, "value": value} for key, value in sorted_items[:limit]]


def _format_money(value: Any, currency: str = DEFAULT_REPORT_CURRENCY) -> str:
    """Format a numeric value as simple currency text."""
    amount = _safe_float(value)
    return f"{currency} {amount:,.2f}"


def _infer_trend(current: float, previous: float) -> Dict[str, Any]:
    """Infer trend direction and percentage change."""
    change = current - previous
    pct = _safe_percent(change, previous) if previous else (100.0 if current > 0 else 0.0)
    if change > 0:
        direction = "up"
    elif change < 0:
        direction = "down"
    else:
        direction = "flat"
    return {
        "current": round(current, 2),
        "previous": round(previous, 2),
        "change": round(change, 2),
        "change_percent": round(pct, 2),
        "direction": direction,
    }


# ---------------------------------------------------------------------------
# Main Class
# ---------------------------------------------------------------------------

class BusinessReportBuilder(BaseAgent):
    """
    Builds business, client, and weekly reports for the William/Jarvis Business Agent.

    This class is intentionally self-contained and import-safe. In the full system,
    Business Agent or Master Agent can instantiate this class and call public methods:

        - build_business_report()
        - build_client_report()
        - build_weekly_summary()
        - build_custom_report()
        - export_report()

    Data should be passed in by the calling controller from CRM, Lead Tracker,
    Campaign Tracker, Sales Pipeline, Revenue Tracker, Client Manager, or Analytics
    Engine. This class does not fetch external systems directly and does not execute
    destructive actions.

    Security Agent Connection:
        _requires_security_check() detects sensitive report actions.
        _request_security_approval() returns a structured approval payload.

    Verification Agent Connection:
        _prepare_verification_payload() creates a payload that can be sent to the
        Verification Agent after report generation.

    Memory Agent Connection:
        _prepare_memory_payload() produces safe report context without leaking raw
        large datasets unless approved by caller.

    Dashboard/API Connection:
        Every public method returns a structured dict with success, message, data,
        error, and metadata keys.
    """

    def __init__(
        self,
        agent_name: str = DEFAULT_AGENT_NAME,
        agent_id: Optional[str] = None,
        config: Optional[Mapping[str, Any]] = None,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        logger_instance: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize BusinessReportBuilder.

        Args:
            agent_name: Registry-compatible agent name.
            agent_id: Optional unique agent ID.
            config: Optional configuration mapping.
            security_agent: Optional Security Agent adapter.
            verification_agent: Optional Verification Agent adapter.
            memory_agent: Optional Memory Agent adapter.
            event_bus: Optional event bus or dispatcher.
            audit_logger: Optional audit logger adapter.
            logger_instance: Optional custom logger.
            **kwargs: Extra args passed safely to BaseAgent when available.
        """
        self.config: Dict[str, Any] = dict(config or {})
        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger
        self.logger = logger_instance or logger

        self.agent_name = agent_name
        self.agent_id = agent_id or agent_name
        self.agent_version = _safe_str(
            self.config.get("agent_version"),
            DEFAULT_AGENT_VERSION,
        )

        try:
            super().__init__(agent_name=agent_name, agent_id=self.agent_id, **kwargs)
        except TypeError:
            try:
                super().__init__()
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # Public Report Methods
    # -----------------------------------------------------------------------

    def build_business_report(
        self,
        *,
        user_id: str,
        workspace_id: str,
        period: Optional[Mapping[str, Any]] = None,
        leads: Optional[Sequence[Mapping[str, Any]]] = None,
        clients: Optional[Sequence[Mapping[str, Any]]] = None,
        deals: Optional[Sequence[Mapping[str, Any]]] = None,
        campaigns: Optional[Sequence[Mapping[str, Any]]] = None,
        revenue: Optional[Sequence[Mapping[str, Any]]] = None,
        tasks: Optional[Sequence[Mapping[str, Any]]] = None,
        context: Optional[Mapping[str, Any]] = None,
        include_recommendations: bool = True,
        require_security_approval: bool = False,
    ) -> Dict[str, Any]:
        """
        Build an overall business report.

        Args:
            user_id: SaaS user ID.
            workspace_id: SaaS workspace ID.
            period: Optional report period dict with start_date, end_date, label.
            leads: Lead records from Lead Tracker.
            clients: Client records from Client Manager.
            deals: Deal records from CRM/Sales Pipeline.
            campaigns: Campaign records from Campaign Tracker.
            revenue: Revenue records from Revenue Tracker.
            tasks: Task records from Task Manager.
            context: Optional request context.
            include_recommendations: Include generated recommendations.
            require_security_approval: Force Security Agent approval workflow.

        Returns:
            Structured result dict.
        """
        task_context = self._make_report_context(
            user_id=user_id,
            workspace_id=workspace_id,
            context=context,
        )

        validation = self._validate_task_context(task_context)
        if not validation["success"]:
            return validation

        report_period = self._make_period(period)

        action = "build_business_report"
        if require_security_approval or self._requires_security_check(
            report_type=ReportType.BUSINESS.value,
            action=action,
            context=task_context,
        ):
            approval = self._request_security_approval(
                context=task_context,
                action=action,
                report_type=ReportType.BUSINESS.value,
                risk_level=RiskLevel.MEDIUM.value,
                payload={
                    "period": asdict(report_period),
                    "contains_financial_data": bool(revenue),
                    "contains_client_data": bool(clients),
                },
            )
            if not approval.get("success"):
                return approval

        try:
            safe_leads = self._filter_records_for_context(leads or [], task_context, report_period)
            safe_clients = self._filter_records_for_context(clients or [], task_context, report_period)
            safe_deals = self._filter_records_for_context(deals or [], task_context, report_period)
            safe_campaigns = self._filter_records_for_context(campaigns or [], task_context, report_period)
            safe_revenue = self._filter_records_for_context(revenue or [], task_context, report_period)
            safe_tasks = self._filter_records_for_context(tasks or [], task_context, report_period)

            lead_section = self._build_leads_section(safe_leads)
            client_section = self._build_clients_section(safe_clients)
            sales_section = self._build_sales_section(safe_deals)
            campaign_section = self._build_campaigns_section(safe_campaigns)
            revenue_section = self._build_revenue_section(safe_revenue)
            task_section = self._build_tasks_section(safe_tasks)

            sections = [
                lead_section,
                client_section,
                sales_section,
                campaign_section,
                revenue_section,
                task_section,
            ]

            highlights = self._generate_business_highlights(sections)
            risks = self._generate_business_risks(sections)
            recommendations = (
                self._generate_business_recommendations(sections)
                if include_recommendations
                else []
            )

            executive_summary = self._compose_executive_summary(
                report_type=ReportType.BUSINESS.value,
                sections=sections,
                highlights=highlights,
                risks=risks,
            )

            report = BusinessReport(
                report_id=str(uuid.uuid4()),
                report_type=ReportType.BUSINESS.value,
                title="Business Performance Report",
                status=ReportStatus.READY.value,
                period=asdict(report_period),
                sections=[asdict(section) for section in sections],
                executive_summary=executive_summary,
                highlights=highlights,
                risks=risks,
                recommendations=recommendations,
                generated_at=_utc_now_iso(),
                generated_by=self.agent_name,
                user_id=task_context.user_id,
                workspace_id=task_context.workspace_id,
                metadata={
                    "agent_id": self.agent_id,
                    "agent_version": self.agent_version,
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                    "source_agent": task_context.source_agent,
                    "record_counts": {
                        "leads": len(safe_leads),
                        "clients": len(safe_clients),
                        "deals": len(safe_deals),
                        "campaigns": len(safe_campaigns),
                        "revenue": len(safe_revenue),
                        "tasks": len(safe_tasks),
                    },
                },
            )

            verification_payload = self._prepare_verification_payload(
                context=task_context,
                action=action,
                result_data=asdict(report),
            )
            memory_payload = self._prepare_memory_payload(
                context=task_context,
                report=asdict(report),
            )

            self._emit_agent_event(
                context=task_context,
                event_name="business_report.generated",
                payload={
                    "report_id": report.report_id,
                    "report_type": report.report_type,
                    "status": report.status,
                },
            )
            self._log_audit_event(
                context=task_context,
                action=action,
                status="success",
                risk_level=RiskLevel.MEDIUM.value,
                metadata={
                    "report_id": report.report_id,
                    "report_type": report.report_type,
                },
            )

            return self._safe_result(
                message="Business report built successfully.",
                data={
                    "report": asdict(report),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                    "report_id": report.report_id,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to build business report.")
            self._log_audit_event(
                context=task_context,
                action=action,
                status="failed",
                risk_level=RiskLevel.MEDIUM.value,
                metadata={"error": str(exc)},
            )
            return self._error_result(
                message="Failed to build business report.",
                error=exc,
                metadata={
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                },
            )

    def build_client_report(
        self,
        *,
        user_id: str,
        workspace_id: str,
        client_id: str,
        client: Optional[Mapping[str, Any]] = None,
        projects: Optional[Sequence[Mapping[str, Any]]] = None,
        deliverables: Optional[Sequence[Mapping[str, Any]]] = None,
        campaigns: Optional[Sequence[Mapping[str, Any]]] = None,
        tasks: Optional[Sequence[Mapping[str, Any]]] = None,
        revenue: Optional[Sequence[Mapping[str, Any]]] = None,
        notes: Optional[Sequence[Mapping[str, Any]]] = None,
        period: Optional[Mapping[str, Any]] = None,
        context: Optional[Mapping[str, Any]] = None,
        include_recommendations: bool = True,
        require_security_approval: bool = True,
    ) -> Dict[str, Any]:
        """
        Build a client-specific report.

        Args:
            user_id: SaaS user ID.
            workspace_id: SaaS workspace ID.
            client_id: Target client ID.
            client: Client record.
            projects: Client project records.
            deliverables: Client deliverable records.
            campaigns: Client campaign records.
            tasks: Client task records.
            revenue: Client revenue records.
            notes: Client notes.
            period: Optional report period.
            context: Optional request context.
            include_recommendations: Include generated recommendations.
            require_security_approval: Whether client report requires Security Agent approval.

        Returns:
            Structured result dict.
        """
        task_context = self._make_report_context(
            user_id=user_id,
            workspace_id=workspace_id,
            context=context,
        )

        validation = self._validate_task_context(task_context)
        if not validation["success"]:
            return validation

        if not _safe_str(client_id).strip():
            return self._error_result(
                message="client_id is required to build a client report.",
                error="missing_client_id",
                metadata={
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                },
            )

        report_period = self._make_period(period)
        action = "build_client_report"

        if require_security_approval or self._requires_security_check(
            report_type=ReportType.CLIENT.value,
            action=action,
            context=task_context,
        ):
            approval = self._request_security_approval(
                context=task_context,
                action=action,
                report_type=ReportType.CLIENT.value,
                risk_level=RiskLevel.HIGH.value,
                payload={
                    "client_id": client_id,
                    "period": asdict(report_period),
                    "contains_client_notes": bool(notes),
                    "contains_revenue": bool(revenue),
                },
            )
            if not approval.get("success"):
                return approval

        try:
            client_record = self._sanitize_record_for_context(client or {}, task_context)
            client_projects = self._filter_client_records(projects or [], client_id, task_context, report_period)
            client_deliverables = self._filter_client_records(deliverables or [], client_id, task_context, report_period)
            client_campaigns = self._filter_client_records(campaigns or [], client_id, task_context, report_period)
            client_tasks = self._filter_client_records(tasks or [], client_id, task_context, report_period)
            client_revenue = self._filter_client_records(revenue or [], client_id, task_context, report_period)
            client_notes = self._filter_client_records(notes or [], client_id, task_context, report_period)

            overview_section = self._build_client_overview_section(client_record, client_id)
            project_section = self._build_projects_section(client_projects)
            deliverable_section = self._build_deliverables_section(client_deliverables)
            campaign_section = self._build_campaigns_section(client_campaigns)
            task_section = self._build_tasks_section(client_tasks)
            revenue_section = self._build_revenue_section(client_revenue)
            notes_section = self._build_notes_section(client_notes)

            sections = [
                overview_section,
                project_section,
                deliverable_section,
                campaign_section,
                task_section,
                revenue_section,
                notes_section,
            ]

            highlights = self._generate_client_highlights(sections)
            risks = self._generate_client_risks(sections)
            recommendations = (
                self._generate_client_recommendations(sections)
                if include_recommendations
                else []
            )

            client_name = _extract_text(
                client_record,
                ["name", "client_name", "company", "business_name"],
                default=f"Client {client_id}",
            )

            executive_summary = self._compose_executive_summary(
                report_type=ReportType.CLIENT.value,
                sections=sections,
                highlights=highlights,
                risks=risks,
            )

            report = BusinessReport(
                report_id=str(uuid.uuid4()),
                report_type=ReportType.CLIENT.value,
                title=f"Client Report - {client_name}",
                status=ReportStatus.READY.value,
                period=asdict(report_period),
                sections=[asdict(section) for section in sections],
                executive_summary=executive_summary,
                highlights=highlights,
                risks=risks,
                recommendations=recommendations,
                generated_at=_utc_now_iso(),
                generated_by=self.agent_name,
                user_id=task_context.user_id,
                workspace_id=task_context.workspace_id,
                metadata={
                    "agent_id": self.agent_id,
                    "agent_version": self.agent_version,
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                    "client_id": client_id,
                    "client_name": client_name,
                    "record_counts": {
                        "projects": len(client_projects),
                        "deliverables": len(client_deliverables),
                        "campaigns": len(client_campaigns),
                        "tasks": len(client_tasks),
                        "revenue": len(client_revenue),
                        "notes": len(client_notes),
                    },
                },
            )

            verification_payload = self._prepare_verification_payload(
                context=task_context,
                action=action,
                result_data=asdict(report),
            )
            memory_payload = self._prepare_memory_payload(
                context=task_context,
                report=asdict(report),
            )

            self._emit_agent_event(
                context=task_context,
                event_name="client_report.generated",
                payload={
                    "report_id": report.report_id,
                    "client_id": client_id,
                    "status": report.status,
                },
            )
            self._log_audit_event(
                context=task_context,
                action=action,
                status="success",
                risk_level=RiskLevel.HIGH.value,
                metadata={
                    "report_id": report.report_id,
                    "client_id": client_id,
                },
            )

            return self._safe_result(
                message="Client report built successfully.",
                data={
                    "report": asdict(report),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                    "report_id": report.report_id,
                    "client_id": client_id,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to build client report.")
            self._log_audit_event(
                context=task_context,
                action=action,
                status="failed",
                risk_level=RiskLevel.HIGH.value,
                metadata={
                    "client_id": client_id,
                    "error": str(exc),
                },
            )
            return self._error_result(
                message="Failed to build client report.",
                error=exc,
                metadata={
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                    "client_id": client_id,
                },
            )

    def build_weekly_summary(
        self,
        *,
        user_id: str,
        workspace_id: str,
        week_start: Optional[Union[str, date, datetime]] = None,
        leads: Optional[Sequence[Mapping[str, Any]]] = None,
        clients: Optional[Sequence[Mapping[str, Any]]] = None,
        deals: Optional[Sequence[Mapping[str, Any]]] = None,
        campaigns: Optional[Sequence[Mapping[str, Any]]] = None,
        revenue: Optional[Sequence[Mapping[str, Any]]] = None,
        tasks: Optional[Sequence[Mapping[str, Any]]] = None,
        context: Optional[Mapping[str, Any]] = None,
        include_next_week_actions: bool = True,
    ) -> Dict[str, Any]:
        """
        Build a weekly business summary.

        Args:
            user_id: SaaS user ID.
            workspace_id: SaaS workspace ID.
            week_start: Optional week start date. Defaults to current UTC Monday.
            leads: Lead records.
            clients: Client records.
            deals: Deal records.
            campaigns: Campaign records.
            revenue: Revenue records.
            tasks: Task records.
            context: Optional request context.
            include_next_week_actions: Include suggested next-week actions.

        Returns:
            Structured result dict.
        """
        task_context = self._make_report_context(
            user_id=user_id,
            workspace_id=workspace_id,
            context=context,
        )

        validation = self._validate_task_context(task_context)
        if not validation["success"]:
            return validation

        action = "build_weekly_summary"

        try:
            start = _parse_date(week_start)
            if start is None:
                today = _utc_now().date()
                start = today - timedelta(days=today.weekday())

            end = start + timedelta(days=6)
            report_period = ReportPeriod(
                start_date=start.isoformat(),
                end_date=end.isoformat(),
                label=f"Week of {start.isoformat()}",
            )

            safe_leads = self._filter_records_for_context(leads or [], task_context, report_period)
            safe_clients = self._filter_records_for_context(clients or [], task_context, report_period)
            safe_deals = self._filter_records_for_context(deals or [], task_context, report_period)
            safe_campaigns = self._filter_records_for_context(campaigns or [], task_context, report_period)
            safe_revenue = self._filter_records_for_context(revenue or [], task_context, report_period)
            safe_tasks = self._filter_records_for_context(tasks or [], task_context, report_period)

            weekly_metrics = self._calculate_weekly_metrics(
                leads=safe_leads,
                clients=safe_clients,
                deals=safe_deals,
                campaigns=safe_campaigns,
                revenue=safe_revenue,
                tasks=safe_tasks,
            )

            summary_section = ReportSection(
                title="Weekly Summary",
                summary=self._weekly_summary_text(weekly_metrics),
                metrics=weekly_metrics,
                insights=self._weekly_insights(weekly_metrics),
                recommendations=(
                    self._weekly_next_actions(weekly_metrics)
                    if include_next_week_actions
                    else []
                ),
            )

            lead_section = self._build_leads_section(safe_leads)
            sales_section = self._build_sales_section(safe_deals)
            revenue_section = self._build_revenue_section(safe_revenue)
            task_section = self._build_tasks_section(safe_tasks)

            sections = [
                summary_section,
                lead_section,
                sales_section,
                revenue_section,
                task_section,
            ]

            highlights = self._generate_business_highlights(sections)
            risks = self._generate_business_risks(sections)
            recommendations = self._weekly_next_actions(weekly_metrics) if include_next_week_actions else []

            report = BusinessReport(
                report_id=str(uuid.uuid4()),
                report_type=ReportType.WEEKLY_SUMMARY.value,
                title=f"Weekly Business Summary - {start.isoformat()} to {end.isoformat()}",
                status=ReportStatus.READY.value,
                period=asdict(report_period),
                sections=[asdict(section) for section in sections],
                executive_summary=self._compose_executive_summary(
                    report_type=ReportType.WEEKLY_SUMMARY.value,
                    sections=sections,
                    highlights=highlights,
                    risks=risks,
                ),
                highlights=highlights,
                risks=risks,
                recommendations=recommendations,
                generated_at=_utc_now_iso(),
                generated_by=self.agent_name,
                user_id=task_context.user_id,
                workspace_id=task_context.workspace_id,
                metadata={
                    "agent_id": self.agent_id,
                    "agent_version": self.agent_version,
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                    "week_start": start.isoformat(),
                    "week_end": end.isoformat(),
                },
            )

            verification_payload = self._prepare_verification_payload(
                context=task_context,
                action=action,
                result_data=asdict(report),
            )
            memory_payload = self._prepare_memory_payload(
                context=task_context,
                report=asdict(report),
            )

            self._emit_agent_event(
                context=task_context,
                event_name="weekly_summary.generated",
                payload={
                    "report_id": report.report_id,
                    "week_start": start.isoformat(),
                    "week_end": end.isoformat(),
                },
            )
            self._log_audit_event(
                context=task_context,
                action=action,
                status="success",
                risk_level=RiskLevel.MEDIUM.value,
                metadata={
                    "report_id": report.report_id,
                    "week_start": start.isoformat(),
                    "week_end": end.isoformat(),
                },
            )

            return self._safe_result(
                message="Weekly summary built successfully.",
                data={
                    "report": asdict(report),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                    "report_id": report.report_id,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to build weekly summary.")
            self._log_audit_event(
                context=task_context,
                action=action,
                status="failed",
                risk_level=RiskLevel.MEDIUM.value,
                metadata={"error": str(exc)},
            )
            return self._error_result(
                message="Failed to build weekly summary.",
                error=exc,
                metadata={
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                },
            )

    def build_custom_report(
        self,
        *,
        user_id: str,
        workspace_id: str,
        title: str,
        report_type: str = ReportType.CUSTOM.value,
        sections: Optional[Sequence[Mapping[str, Any]]] = None,
        metrics: Optional[Mapping[str, Any]] = None,
        period: Optional[Mapping[str, Any]] = None,
        context: Optional[Mapping[str, Any]] = None,
        require_security_approval: bool = True,
    ) -> Dict[str, Any]:
        """
        Build a custom report from caller-provided sections and metrics.

        This is useful for Dashboard/API or Master Agent composed reports where
        other modules have already prepared report-ready data.

        Args:
            user_id: SaaS user ID.
            workspace_id: SaaS workspace ID.
            title: Report title.
            report_type: Custom report type label.
            sections: Caller-provided sections.
            metrics: Optional top-level metrics.
            period: Optional report period.
            context: Optional request context.
            require_security_approval: Whether to request Security Agent approval.

        Returns:
            Structured result dict.
        """
        task_context = self._make_report_context(
            user_id=user_id,
            workspace_id=workspace_id,
            context=context,
        )

        validation = self._validate_task_context(task_context)
        if not validation["success"]:
            return validation

        clean_title = _safe_str(title).strip()
        if not clean_title:
            return self._error_result(
                message="title is required to build a custom report.",
                error="missing_title",
                metadata={
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                },
            )

        report_period = self._make_period(period)
        action = "build_custom_report"

        if require_security_approval or self._requires_security_check(
            report_type=report_type,
            action=action,
            context=task_context,
        ):
            approval = self._request_security_approval(
                context=task_context,
                action=action,
                report_type=report_type,
                risk_level=RiskLevel.MEDIUM.value,
                payload={
                    "title": clean_title,
                    "period": asdict(report_period),
                    "section_count": len(sections or []),
                },
            )
            if not approval.get("success"):
                return approval

        try:
            prepared_sections = self._normalize_custom_sections(sections or [])
            if metrics:
                prepared_sections.insert(
                    0,
                    ReportSection(
                        title="Report Metrics",
                        summary="Top-level report metrics provided by the calling module.",
                        metrics=_deepcopy_json_safe(dict(metrics)),
                    ),
                )

            highlights = self._generate_business_highlights(prepared_sections)
            risks = self._generate_business_risks(prepared_sections)
            recommendations = self._generate_business_recommendations(prepared_sections)

            report = BusinessReport(
                report_id=str(uuid.uuid4()),
                report_type=_safe_str(report_type, ReportType.CUSTOM.value),
                title=clean_title,
                status=ReportStatus.READY.value,
                period=asdict(report_period),
                sections=[asdict(section) for section in prepared_sections],
                executive_summary=self._compose_executive_summary(
                    report_type=report_type,
                    sections=prepared_sections,
                    highlights=highlights,
                    risks=risks,
                ),
                highlights=highlights,
                risks=risks,
                recommendations=recommendations,
                generated_at=_utc_now_iso(),
                generated_by=self.agent_name,
                user_id=task_context.user_id,
                workspace_id=task_context.workspace_id,
                metadata={
                    "agent_id": self.agent_id,
                    "agent_version": self.agent_version,
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                    "custom": True,
                },
            )

            verification_payload = self._prepare_verification_payload(
                context=task_context,
                action=action,
                result_data=asdict(report),
            )
            memory_payload = self._prepare_memory_payload(
                context=task_context,
                report=asdict(report),
            )

            self._emit_agent_event(
                context=task_context,
                event_name="custom_report.generated",
                payload={
                    "report_id": report.report_id,
                    "report_type": report.report_type,
                },
            )
            self._log_audit_event(
                context=task_context,
                action=action,
                status="success",
                risk_level=RiskLevel.MEDIUM.value,
                metadata={
                    "report_id": report.report_id,
                    "report_type": report.report_type,
                },
            )

            return self._safe_result(
                message="Custom report built successfully.",
                data={
                    "report": asdict(report),
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                },
                metadata={
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                    "report_id": report.report_id,
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to build custom report.")
            self._log_audit_event(
                context=task_context,
                action=action,
                status="failed",
                risk_level=RiskLevel.MEDIUM.value,
                metadata={"error": str(exc)},
            )
            return self._error_result(
                message="Failed to build custom report.",
                error=exc,
                metadata={
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                },
            )

    def export_report(
        self,
        *,
        user_id: str,
        workspace_id: str,
        report: Mapping[str, Any],
        export_format: str = ReportFormat.JSON.value,
        context: Optional[Mapping[str, Any]] = None,
        require_security_approval: bool = True,
    ) -> Dict[str, Any]:
        """
        Export a report as dict, JSON string, or CSV string.

        Args:
            user_id: SaaS user ID.
            workspace_id: SaaS workspace ID.
            report: Report dict.
            export_format: dict, json, or csv.
            context: Optional request context.
            require_security_approval: Whether Security Agent approval is required.

        Returns:
            Structured result dict with exported content.
        """
        task_context = self._make_report_context(
            user_id=user_id,
            workspace_id=workspace_id,
            context=context,
        )

        validation = self._validate_task_context(task_context)
        if not validation["success"]:
            return validation

        fmt = _safe_str(export_format, ReportFormat.JSON.value).lower().strip()
        if fmt not in ALLOWED_EXPORT_FORMATS:
            return self._error_result(
                message=f"Unsupported export format: {fmt}",
                error="unsupported_export_format",
                metadata={
                    "allowed_formats": sorted(ALLOWED_EXPORT_FORMATS),
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                },
            )

        action = "export_report"

        if require_security_approval or self._requires_security_check(
            report_type=_safe_str(report.get("report_type"), "export"),
            action=action,
            context=task_context,
        ):
            approval = self._request_security_approval(
                context=task_context,
                action=action,
                report_type="export",
                risk_level=RiskLevel.HIGH.value,
                payload={
                    "export_format": fmt,
                    "report_id": report.get("report_id"),
                    "report_type": report.get("report_type"),
                },
            )
            if not approval.get("success"):
                return approval

        try:
            report_copy = _deepcopy_json_safe(dict(report))

            report_user_id = _safe_str(report_copy.get("user_id"))
            report_workspace_id = _safe_str(report_copy.get("workspace_id"))

            if report_user_id and report_user_id != task_context.user_id:
                return self._error_result(
                    message="Report user_id does not match request context.",
                    error="user_context_mismatch",
                    metadata={
                        "request_id": task_context.request_id,
                        "trace_id": task_context.trace_id,
                    },
                )

            if report_workspace_id and report_workspace_id != task_context.workspace_id:
                return self._error_result(
                    message="Report workspace_id does not match request context.",
                    error="workspace_context_mismatch",
                    metadata={
                        "request_id": task_context.request_id,
                        "trace_id": task_context.trace_id,
                    },
                )

            if fmt == ReportFormat.DICT.value:
                exported: Any = report_copy
                content_type = "application/json-compatible-dict"
            elif fmt == ReportFormat.CSV.value:
                exported = self._report_to_csv(report_copy)
                content_type = "text/csv"
            else:
                exported = json.dumps(report_copy, indent=2, sort_keys=True, default=str)
                content_type = "application/json"

            self._emit_agent_event(
                context=task_context,
                event_name="report.exported",
                payload={
                    "report_id": report_copy.get("report_id"),
                    "format": fmt,
                },
            )
            self._log_audit_event(
                context=task_context,
                action=action,
                status="success",
                risk_level=RiskLevel.HIGH.value,
                metadata={
                    "report_id": report_copy.get("report_id"),
                    "format": fmt,
                },
            )

            return self._safe_result(
                message="Report exported successfully.",
                data={
                    "export_format": fmt,
                    "content_type": content_type,
                    "content": exported,
                },
                metadata={
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                    "report_id": report_copy.get("report_id"),
                },
            )

        except Exception as exc:
            self.logger.exception("Failed to export report.")
            self._log_audit_event(
                context=task_context,
                action=action,
                status="failed",
                risk_level=RiskLevel.HIGH.value,
                metadata={"error": str(exc)},
            )
            return self._error_result(
                message="Failed to export report.",
                error=exc,
                metadata={
                    "request_id": task_context.request_id,
                    "trace_id": task_context.trace_id,
                },
            )

    def get_capabilities(self) -> Dict[str, Any]:
        """
        Return registry/router friendly capability metadata.

        Master Agent, Agent Registry, or Dashboard can use this to discover
        available public actions.
        """
        return self._safe_result(
            message="BusinessReportBuilder capabilities loaded.",
            data={
                "agent_name": self.agent_name,
                "agent_id": self.agent_id,
                "agent_version": self.agent_version,
                "module": "business_agent",
                "class": self.__class__.__name__,
                "capabilities": [
                    "build_business_report",
                    "build_client_report",
                    "build_weekly_summary",
                    "build_custom_report",
                    "export_report",
                ],
                "supported_report_types": [item.value for item in ReportType],
                "supported_export_formats": sorted(ALLOWED_EXPORT_FORMATS),
                "requires_user_workspace_context": True,
                "security_hooks": [
                    "_requires_security_check",
                    "_request_security_approval",
                ],
                "verification_hooks": [
                    "_prepare_verification_payload",
                ],
                "memory_hooks": [
                    "_prepare_memory_payload",
                ],
            },
            metadata={
                "generated_at": _utc_now_iso(),
            },
        )

    # -----------------------------------------------------------------------
    # Section Builders
    # -----------------------------------------------------------------------

    def _build_leads_section(self, leads: Sequence[Mapping[str, Any]]) -> ReportSection:
        """Build lead performance section."""
        total = len(leads)
        qualified = sum(
            1 for item in leads
            if _safe_str(item.get("status") or item.get("qualification")).lower()
            in {"qualified", "hot", "warm", "converted"}
        )
        converted = sum(
            1 for item in leads
            if _safe_str(item.get("status")).lower() in {"converted", "won", "customer"}
        )
        hot = sum(
            1 for item in leads
            if _safe_str(item.get("temperature") or item.get("score_label")).lower() == "hot"
            or _safe_float(item.get("score")) >= 80
        )

        sources = _group_count(leads, "source")
        top_sources = _top_items(sources)

        metrics = {
            "total_leads": total,
            "qualified_leads": qualified,
            "converted_leads": converted,
            "hot_leads": hot,
            "qualification_rate_percent": _safe_percent(qualified, total),
            "conversion_rate_percent": _safe_percent(converted, total),
            "top_sources": top_sources,
        }

        insights = []
        if total == 0:
            insights.append("No leads were recorded for this report period.")
        else:
            insights.append(f"{total} leads were tracked during the report period.")
            if qualified:
                insights.append(f"{qualified} leads were qualified or sales-ready.")
            if converted:
                insights.append(f"{converted} leads converted into customers or won opportunities.")

        recommendations = []
        if total == 0:
            recommendations.append("Review lead capture channels and confirm forms, calls, ads, and imports are connected.")
        elif _safe_percent(converted, total) < 10:
            recommendations.append("Improve lead follow-up speed and qualification scripts to increase conversion rate.")
        if hot > 0:
            recommendations.append("Prioritize hot leads for immediate sales follow-up.")

        return ReportSection(
            title="Lead Performance",
            summary=self._section_summary("leads", metrics),
            metrics=metrics,
            items=_limit_items([dict(item) for item in leads], DEFAULT_SUMMARY_LIMIT),
            insights=insights,
            recommendations=recommendations,
        )

    def _build_clients_section(self, clients: Sequence[Mapping[str, Any]]) -> ReportSection:
        """Build client summary section."""
        total = len(clients)
        active = sum(
            1 for item in clients
            if _safe_str(item.get("status")).lower() in {"active", "onboarding", "in_progress"}
        )
        paused = sum(
            1 for item in clients
            if _safe_str(item.get("status")).lower() in {"paused", "hold", "inactive"}
        )
        at_risk = sum(
            1 for item in clients
            if _safe_str(item.get("risk_level")).lower() in {"high", "at_risk", "critical"}
        )

        industries = _group_count(clients, "industry")
        metrics = {
            "total_clients": total,
            "active_clients": active,
            "paused_or_inactive_clients": paused,
            "at_risk_clients": at_risk,
            "active_rate_percent": _safe_percent(active, total),
            "top_industries": _top_items(industries),
        }

        insights = []
        if total == 0:
            insights.append("No client records were included in this report period.")
        else:
            insights.append(f"{active} of {total} clients are currently active.")
            if at_risk:
                insights.append(f"{at_risk} client account(s) may require retention attention.")

        recommendations = []
        if at_risk:
            recommendations.append("Schedule retention reviews for at-risk client accounts.")
        if paused:
            recommendations.append("Review paused or inactive clients for reactivation opportunities.")

        return ReportSection(
            title="Client Portfolio",
            summary=self._section_summary("clients", metrics),
            metrics=metrics,
            items=_limit_items([dict(item) for item in clients], DEFAULT_SUMMARY_LIMIT),
            insights=insights,
            recommendations=recommendations,
        )

    def _build_sales_section(self, deals: Sequence[Mapping[str, Any]]) -> ReportSection:
        """Build sales pipeline section."""
        total = len(deals)
        won = sum(
            1 for item in deals
            if _safe_str(item.get("status") or item.get("stage")).lower() in {"won", "closed_won", "customer"}
        )
        lost = sum(
            1 for item in deals
            if _safe_str(item.get("status") or item.get("stage")).lower() in {"lost", "closed_lost"}
        )
        open_deals = max(0, total - won - lost)

        total_value = sum(_extract_number(item, ["value", "amount", "deal_value"]) for item in deals)
        won_value = sum(
            _extract_number(item, ["value", "amount", "deal_value"])
            for item in deals
            if _safe_str(item.get("status") or item.get("stage")).lower() in {"won", "closed_won", "customer"}
        )

        stages = _group_count(deals, "stage")

        metrics = {
            "total_deals": total,
            "open_deals": open_deals,
            "won_deals": won,
            "lost_deals": lost,
            "total_pipeline_value": round(total_value, 2),
            "won_value": round(won_value, 2),
            "win_rate_percent": _safe_percent(won, won + lost),
            "average_deal_value": _safe_divide(total_value, total),
            "stage_distribution": stages,
        }

        insights = []
        if total == 0:
            insights.append("No sales deals were included in this report period.")
        else:
            insights.append(f"The pipeline contains {open_deals} open deal(s).")
            insights.append(f"Won deal value is {_format_money(won_value, self._currency())}.")

        recommendations = []
        if open_deals > 0:
            recommendations.append("Review open deals and assign next actions for follow-up.")
        if total > 0 and _safe_percent(won, won + lost) < 20:
            recommendations.append("Analyze lost deals and improve qualification or proposal positioning.")

        return ReportSection(
            title="Sales Pipeline",
            summary=self._section_summary("sales", metrics),
            metrics=metrics,
            items=_limit_items([dict(item) for item in deals], DEFAULT_SUMMARY_LIMIT),
            insights=insights,
            recommendations=recommendations,
        )

    def _build_campaigns_section(self, campaigns: Sequence[Mapping[str, Any]]) -> ReportSection:
        """Build campaign performance section."""
        total = len(campaigns)
        spend = sum(_extract_number(item, ["spend", "cost", "ad_spend"]) for item in campaigns)
        impressions = sum(_extract_number(item, ["impressions"]) for item in campaigns)
        clicks = sum(_extract_number(item, ["clicks"]) for item in campaigns)
        leads = sum(_extract_number(item, ["leads", "conversions"]) for item in campaigns)
        revenue = sum(_extract_number(item, ["revenue", "conversion_value"]) for item in campaigns)

        channels = _group_count(campaigns, "channel")

        metrics = {
            "total_campaigns": total,
            "total_spend": round(spend, 2),
            "impressions": int(impressions),
            "clicks": int(clicks),
            "leads_or_conversions": int(leads),
            "revenue": round(revenue, 2),
            "ctr_percent": _safe_percent(clicks, impressions),
            "conversion_rate_percent": _safe_percent(leads, clicks),
            "cost_per_lead": _safe_divide(spend, leads),
            "roas": _safe_divide(revenue, spend),
            "channel_distribution": channels,
        }

        insights = []
        if total == 0:
            insights.append("No campaign data was included in this report period.")
        else:
            insights.append(f"{total} campaign(s) were included across {len(channels)} channel(s).")
            if spend:
                insights.append(f"Total campaign spend was {_format_money(spend, self._currency())}.")
            if leads:
                insights.append(f"Campaigns generated {int(leads)} lead(s) or conversion(s).")

        recommendations = []
        if spend > 0 and leads == 0:
            recommendations.append("Investigate campaign targeting, landing pages, tracking, and offer quality.")
        elif leads > 0 and _safe_divide(spend, leads) > _safe_float(self.config.get("target_cpl"), 100):
            recommendations.append("Optimize campaigns with high cost per lead by improving creative, audience, and landing page quality.")
        if _safe_percent(clicks, impressions) < 1 and impressions > 0:
            recommendations.append("Improve ad creatives and messaging to raise click-through rate.")

        return ReportSection(
            title="Campaign Performance",
            summary=self._section_summary("campaigns", metrics),
            metrics=metrics,
            items=_limit_items([dict(item) for item in campaigns], DEFAULT_SUMMARY_LIMIT),
            insights=insights,
            recommendations=recommendations,
        )

    def _build_revenue_section(self, revenue_records: Sequence[Mapping[str, Any]]) -> ReportSection:
        """Build revenue section."""
        total_records = len(revenue_records)
        total_revenue = sum(_extract_number(item, ["amount", "revenue", "value", "paid_amount"]) for item in revenue_records)
        paid = sum(
            _extract_number(item, ["amount", "revenue", "value", "paid_amount"])
            for item in revenue_records
            if _safe_str(item.get("status")).lower() in {"paid", "received", "completed", "settled"}
        )
        pending = sum(
            _extract_number(item, ["amount", "revenue", "value", "paid_amount"])
            for item in revenue_records
            if _safe_str(item.get("status")).lower() in {"pending", "unpaid", "due", "open"}
        )
        overdue = sum(
            _extract_number(item, ["amount", "revenue", "value", "paid_amount"])
            for item in revenue_records
            if _safe_str(item.get("status")).lower() in {"overdue", "late"}
        )

        by_source: Dict[str, float] = {}
        for item in revenue_records:
            source = _extract_text(item, ["source", "service", "category"], "unknown")
            by_source[source] = by_source.get(source, 0.0) + _extract_number(
                item,
                ["amount", "revenue", "value", "paid_amount"],
            )

        values = [
            _extract_number(item, ["amount", "revenue", "value", "paid_amount"])
            for item in revenue_records
        ]
        average = statistics.mean(values) if values else 0.0

        metrics = {
            "total_records": total_records,
            "total_revenue": round(total_revenue, 2),
            "paid_revenue": round(paid, 2),
            "pending_revenue": round(pending, 2),
            "overdue_revenue": round(overdue, 2),
            "average_transaction_value": round(average, 2),
            "collection_rate_percent": _safe_percent(paid, total_revenue),
            "top_revenue_sources": _top_items(by_source),
            "currency": self._currency(),
        }

        insights = []
        if total_records == 0:
            insights.append("No revenue records were included in this report period.")
        else:
            insights.append(f"Total recorded revenue is {_format_money(total_revenue, self._currency())}.")
            if paid:
                insights.append(f"Paid revenue is {_format_money(paid, self._currency())}.")
            if pending:
                insights.append(f"Pending revenue is {_format_money(pending, self._currency())}.")

        recommendations = []
        if overdue:
            recommendations.append("Follow up on overdue invoices and update payment status after collection.")
        if pending:
            recommendations.append("Review pending payments and prepare client reminders where appropriate.")
        if total_records == 0:
            recommendations.append("Confirm revenue tracker integration and invoice/payment data capture.")

        return ReportSection(
            title="Revenue Summary",
            summary=self._section_summary("revenue", metrics),
            metrics=metrics,
            items=_limit_items([dict(item) for item in revenue_records], DEFAULT_SUMMARY_LIMIT),
            insights=insights,
            recommendations=recommendations,
        )

    def _build_tasks_section(self, tasks: Sequence[Mapping[str, Any]]) -> ReportSection:
        """Build task progress section."""
        total = len(tasks)
        completed = sum(
            1 for item in tasks
            if _safe_str(item.get("status")).lower() in {"done", "completed", "closed"}
        )
        overdue = sum(
            1 for item in tasks
            if _safe_str(item.get("status")).lower() in {"overdue", "late"}
            or self._is_task_overdue(item)
        )
        open_tasks = max(0, total - completed)

        priorities = _group_count(tasks, "priority")

        metrics = {
            "total_tasks": total,
            "completed_tasks": completed,
            "open_tasks": open_tasks,
            "overdue_tasks": overdue,
            "completion_rate_percent": _safe_percent(completed, total),
            "priority_distribution": priorities,
        }

        insights = []
        if total == 0:
            insights.append("No tasks were included in this report period.")
        else:
            insights.append(f"{completed} of {total} task(s) were completed.")
            if overdue:
                insights.append(f"{overdue} task(s) are overdue or marked late.")

        recommendations = []
        if overdue:
            recommendations.append("Resolve overdue tasks or adjust timelines with owners.")
        if total > 0 and _safe_percent(completed, total) < 50:
            recommendations.append("Review workload and assign clear owners for open tasks.")

        return ReportSection(
            title="Task Progress",
            summary=self._section_summary("tasks", metrics),
            metrics=metrics,
            items=_limit_items([dict(item) for item in tasks], DEFAULT_SUMMARY_LIMIT),
            insights=insights,
            recommendations=recommendations,
        )

    def _build_client_overview_section(
        self,
        client: Mapping[str, Any],
        client_id: str,
    ) -> ReportSection:
        """Build client overview section."""
        client_name = _extract_text(
            client,
            ["name", "client_name", "company", "business_name"],
            default=f"Client {client_id}",
        )
        status = _extract_text(client, ["status"], default="unknown")
        owner = _extract_text(client, ["owner", "account_owner", "manager"], default="unassigned")
        industry = _extract_text(client, ["industry", "niche"], default="unknown")

        metrics = {
            "client_id": client_id,
            "client_name": client_name,
            "status": status,
            "owner": owner,
            "industry": industry,
            "risk_level": _extract_text(client, ["risk_level"], default="unknown"),
            "lifetime_value": _extract_number(client, ["lifetime_value", "ltv", "total_revenue"]),
        }

        insights = [
            f"{client_name} is currently marked as {status}.",
            f"Account owner: {owner}.",
        ]

        recommendations = []
        if _safe_str(metrics["risk_level"]).lower() in {"high", "critical", "at_risk"}:
            recommendations.append("Schedule a client success review because this account is marked as high risk.")

        return ReportSection(
            title="Client Overview",
            summary=f"Overview for {client_name}.",
            metrics=metrics,
            items=[_deepcopy_json_safe(dict(client))] if client else [],
            insights=insights,
            recommendations=recommendations,
        )

    def _build_projects_section(self, projects: Sequence[Mapping[str, Any]]) -> ReportSection:
        """Build project status section."""
        total = len(projects)
        active = sum(
            1 for item in projects
            if _safe_str(item.get("status")).lower() in {"active", "in_progress", "onboarding"}
        )
        completed = sum(
            1 for item in projects
            if _safe_str(item.get("status")).lower() in {"done", "completed", "closed"}
        )
        delayed = sum(
            1 for item in projects
            if _safe_str(item.get("status")).lower() in {"delayed", "blocked", "overdue"}
        )

        metrics = {
            "total_projects": total,
            "active_projects": active,
            "completed_projects": completed,
            "delayed_or_blocked_projects": delayed,
            "completion_rate_percent": _safe_percent(completed, total),
        }

        insights = []
        if total == 0:
            insights.append("No projects were included for this client report.")
        else:
            insights.append(f"{active} active project(s), {completed} completed project(s).")
            if delayed:
                insights.append(f"{delayed} project(s) may be delayed or blocked.")

        recommendations = []
        if delayed:
            recommendations.append("Review delayed or blocked projects with the delivery owner.")

        return ReportSection(
            title="Project Status",
            summary=self._section_summary("projects", metrics),
            metrics=metrics,
            items=_limit_items([dict(item) for item in projects], DEFAULT_SUMMARY_LIMIT),
            insights=insights,
            recommendations=recommendations,
        )

    def _build_deliverables_section(self, deliverables: Sequence[Mapping[str, Any]]) -> ReportSection:
        """Build deliverable status section."""
        total = len(deliverables)
        completed = sum(
            1 for item in deliverables
            if _safe_str(item.get("status")).lower() in {"done", "completed", "delivered", "approved"}
        )
        pending = max(0, total - completed)
        overdue = sum(
            1 for item in deliverables
            if _safe_str(item.get("status")).lower() in {"overdue", "late", "delayed"}
            or self._is_task_overdue(item)
        )

        metrics = {
            "total_deliverables": total,
            "completed_deliverables": completed,
            "pending_deliverables": pending,
            "overdue_deliverables": overdue,
            "delivery_rate_percent": _safe_percent(completed, total),
        }

        insights = []
        if total == 0:
            insights.append("No deliverables were included for this report.")
        else:
            insights.append(f"{completed} of {total} deliverable(s) are completed.")
            if overdue:
                insights.append(f"{overdue} deliverable(s) are overdue.")

        recommendations = []
        if overdue:
            recommendations.append("Prioritize overdue deliverables and notify stakeholders with revised timelines.")
        if pending:
            recommendations.append("Confirm owners and due dates for pending deliverables.")

        return ReportSection(
            title="Deliverables",
            summary=self._section_summary("deliverables", metrics),
            metrics=metrics,
            items=_limit_items([dict(item) for item in deliverables], DEFAULT_SUMMARY_LIMIT),
            insights=insights,
            recommendations=recommendations,
        )

    def _build_notes_section(self, notes: Sequence[Mapping[str, Any]]) -> ReportSection:
        """Build client notes section."""
        total = len(notes)
        important = sum(
            1 for item in notes
            if bool(item.get("important"))
            or _safe_str(item.get("priority")).lower() in {"high", "urgent"}
        )

        items = []
        for note in notes[:DEFAULT_SUMMARY_LIMIT]:
            items.append({
                "note_id": note.get("note_id") or note.get("id"),
                "created_at": note.get("created_at") or note.get("date"),
                "author": note.get("author") or note.get("created_by"),
                "summary": _safe_str(note.get("summary") or note.get("note") or note.get("content"))[:500],
                "important": bool(note.get("important")),
            })

        metrics = {
            "total_notes": total,
            "important_notes": important,
        }

        insights = []
        if total == 0:
            insights.append("No client notes were included in this report.")
        else:
            insights.append(f"{total} note(s) were included.")
            if important:
                insights.append(f"{important} note(s) are marked important or high priority.")

        recommendations = []
        if important:
            recommendations.append("Review important notes before the next client communication.")

        return ReportSection(
            title="Client Notes",
            summary=self._section_summary("notes", metrics),
            metrics=metrics,
            items=items,
            insights=insights,
            recommendations=recommendations,
        )

    # -----------------------------------------------------------------------
    # Metrics / Insights
    # -----------------------------------------------------------------------

    def _calculate_weekly_metrics(
        self,
        *,
        leads: Sequence[Mapping[str, Any]],
        clients: Sequence[Mapping[str, Any]],
        deals: Sequence[Mapping[str, Any]],
        campaigns: Sequence[Mapping[str, Any]],
        revenue: Sequence[Mapping[str, Any]],
        tasks: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """Calculate weekly summary metrics."""
        revenue_total = sum(_extract_number(item, ["amount", "revenue", "value", "paid_amount"]) for item in revenue)
        spend_total = sum(_extract_number(item, ["spend", "cost", "ad_spend"]) for item in campaigns)
        won_deals = sum(
            1 for item in deals
            if _safe_str(item.get("status") or item.get("stage")).lower() in {"won", "closed_won", "customer"}
        )
        completed_tasks = sum(
            1 for item in tasks
            if _safe_str(item.get("status")).lower() in {"done", "completed", "closed"}
        )

        return {
            "leads_created": len(leads),
            "clients_touched": len(clients),
            "deals_updated": len(deals),
            "deals_won": won_deals,
            "campaigns_tracked": len(campaigns),
            "campaign_spend": round(spend_total, 2),
            "revenue_recorded": round(revenue_total, 2),
            "tasks_total": len(tasks),
            "tasks_completed": completed_tasks,
            "task_completion_rate_percent": _safe_percent(completed_tasks, len(tasks)),
            "currency": self._currency(),
        }

    def _weekly_summary_text(self, metrics: Mapping[str, Any]) -> str:
        """Generate weekly summary text."""
        return (
            f"This week included {metrics.get('leads_created', 0)} lead(s), "
            f"{metrics.get('deals_updated', 0)} deal update(s), "
            f"{metrics.get('deals_won', 0)} won deal(s), and "
            f"{_format_money(metrics.get('revenue_recorded', 0), self._currency())} "
            "in recorded revenue."
        )

    def _weekly_insights(self, metrics: Mapping[str, Any]) -> List[str]:
        """Generate weekly insights."""
        insights = [
            f"Task completion rate was {metrics.get('task_completion_rate_percent', 0)}%.",
            f"Campaign spend was {_format_money(metrics.get('campaign_spend', 0), self._currency())}.",
        ]

        if _safe_int(metrics.get("leads_created")) == 0:
            insights.append("No new leads were recorded this week.")
        if _safe_int(metrics.get("deals_won")) > 0:
            insights.append("The sales pipeline produced closed-won activity this week.")
        if _safe_float(metrics.get("revenue_recorded")) > 0:
            insights.append("Revenue activity was recorded this week.")

        return insights

    def _weekly_next_actions(self, metrics: Mapping[str, Any]) -> List[str]:
        """Generate next-week action recommendations."""
        actions = []

        if _safe_int(metrics.get("leads_created")) == 0:
            actions.append("Check lead generation channels and tracking before next week starts.")
        else:
            actions.append("Follow up with new leads while intent is fresh.")

        if _safe_int(metrics.get("deals_won")) == 0:
            actions.append("Review open deals and define close plans for the highest-value opportunities.")
        else:
            actions.append("Prepare onboarding or fulfillment steps for won deals.")

        if _safe_float(metrics.get("task_completion_rate_percent")) < 70 and _safe_int(metrics.get("tasks_total")) > 0:
            actions.append("Reduce bottlenecks by assigning owners and priorities to incomplete tasks.")

        if _safe_float(metrics.get("campaign_spend")) > 0:
            actions.append("Review campaign spend, cost per lead, and conversion quality.")

        return actions

    def _generate_business_highlights(self, sections: Sequence[ReportSection]) -> List[str]:
        """Generate report highlights from sections."""
        highlights: List[str] = []

        for section in sections:
            metrics = section.metrics
            if "total_revenue" in metrics and _safe_float(metrics["total_revenue"]) > 0:
                highlights.append(
                    f"Revenue tracked: {_format_money(metrics['total_revenue'], self._currency())}."
                )
            if "converted_leads" in metrics and _safe_int(metrics["converted_leads"]) > 0:
                highlights.append(
                    f"Converted leads: {metrics['converted_leads']}."
                )
            if "won_deals" in metrics and _safe_int(metrics["won_deals"]) > 0:
                highlights.append(
                    f"Won deals: {metrics['won_deals']}."
                )
            if "completed_tasks" in metrics and _safe_int(metrics["completed_tasks"]) > 0:
                highlights.append(
                    f"Completed tasks: {metrics['completed_tasks']}."
                )

        if not highlights:
            highlights.append("Report generated successfully with available business data.")

        return self._unique_list(highlights, limit=8)

    def _generate_business_risks(self, sections: Sequence[ReportSection]) -> List[str]:
        """Generate report risks from sections."""
        risks: List[str] = []

        for section in sections:
            metrics = section.metrics
            if _safe_int(metrics.get("overdue_tasks")) > 0:
                risks.append(f"{metrics.get('overdue_tasks')} overdue task(s) need attention.")
            if _safe_float(metrics.get("overdue_revenue")) > 0:
                risks.append(
                    f"Overdue revenue detected: {_format_money(metrics.get('overdue_revenue'), self._currency())}."
                )
            if _safe_int(metrics.get("at_risk_clients")) > 0:
                risks.append(f"{metrics.get('at_risk_clients')} client account(s) are marked at risk.")
            if (
                "conversion_rate_percent" in metrics
                and _safe_float(metrics.get("conversion_rate_percent")) < 5
                and _safe_int(metrics.get("total_leads") or metrics.get("leads_or_conversions")) > 0
            ):
                risks.append("Conversion rate appears low and may need optimization.")

        if not risks:
            risks.append("No critical risks were detected from the supplied report data.")

        return self._unique_list(risks, limit=8)

    def _generate_business_recommendations(self, sections: Sequence[ReportSection]) -> List[str]:
        """Collect business recommendations from all sections."""
        recommendations: List[str] = []
        for section in sections:
            recommendations.extend(section.recommendations)

        if not recommendations:
            recommendations.append("Continue tracking leads, campaigns, revenue, tasks, and client activity for stronger reporting accuracy.")

        return self._unique_list(recommendations, limit=10)

    def _generate_client_highlights(self, sections: Sequence[ReportSection]) -> List[str]:
        """Generate client report highlights."""
        highlights = self._generate_business_highlights(sections)
        if not highlights:
            highlights = ["Client report generated with available account data."]
        return self._unique_list(highlights, limit=8)

    def _generate_client_risks(self, sections: Sequence[ReportSection]) -> List[str]:
        """Generate client report risks."""
        return self._generate_business_risks(sections)

    def _generate_client_recommendations(self, sections: Sequence[ReportSection]) -> List[str]:
        """Generate client report recommendations."""
        recommendations = self._generate_business_recommendations(sections)
        if not recommendations:
            recommendations.append("Prepare a client update with completed work, current blockers, and next milestones.")
        return self._unique_list(recommendations, limit=10)

    def _compose_executive_summary(
        self,
        *,
        report_type: str,
        sections: Sequence[ReportSection],
        highlights: Sequence[str],
        risks: Sequence[str],
    ) -> str:
        """Compose concise executive summary."""
        section_count = len(sections)
        highlight_text = highlights[0] if highlights else "No major highlights detected."
        risk_text = risks[0] if risks else "No major risks detected."

        readable_type = _safe_str(report_type).replace("_", " ").title()

        return (
            f"{readable_type} generated with {section_count} section(s). "
            f"Key highlight: {highlight_text} "
            f"Primary risk/attention point: {risk_text}"
        )

    def _section_summary(self, section_type: str, metrics: Mapping[str, Any]) -> str:
        """Generate simple section summary."""
        if section_type == "leads":
            return (
                f"{metrics.get('total_leads', 0)} leads tracked with "
                f"{metrics.get('conversion_rate_percent', 0)}% conversion rate."
            )
        if section_type == "clients":
            return (
                f"{metrics.get('active_clients', 0)} active clients out of "
                f"{metrics.get('total_clients', 0)} total clients."
            )
        if section_type == "sales":
            return (
                f"{metrics.get('open_deals', 0)} open deals and "
                f"{metrics.get('won_deals', 0)} won deals."
            )
        if section_type == "campaigns":
            return (
                f"{metrics.get('total_campaigns', 0)} campaigns tracked with "
                f"{metrics.get('leads_or_conversions', 0)} leads/conversions."
            )
        if section_type == "revenue":
            return (
                f"Total revenue recorded: "
                f"{_format_money(metrics.get('total_revenue', 0), self._currency())}."
            )
        if section_type == "tasks":
            return (
                f"{metrics.get('completed_tasks', 0)} completed tasks out of "
                f"{metrics.get('total_tasks', 0)} total tasks."
            )
        if section_type == "projects":
            return (
                f"{metrics.get('active_projects', 0)} active projects and "
                f"{metrics.get('completed_projects', 0)} completed projects."
            )
        if section_type == "deliverables":
            return (
                f"{metrics.get('completed_deliverables', 0)} completed deliverables out of "
                f"{metrics.get('total_deliverables', 0)} total deliverables."
            )
        if section_type == "notes":
            return f"{metrics.get('total_notes', 0)} notes included."
        return "Section generated from available report data."

    # -----------------------------------------------------------------------
    # Context / Validation / Isolation
    # -----------------------------------------------------------------------

    def _make_report_context(
        self,
        *,
        user_id: str,
        workspace_id: str,
        context: Optional[Mapping[str, Any]] = None,
    ) -> ReportContext:
        """Create ReportContext from required user/workspace fields and optional metadata."""
        ctx = dict(context or {})
        permissions_raw = ctx.get("permissions") or []
        if isinstance(permissions_raw, str):
            permissions = [permissions_raw]
        else:
            permissions = [_safe_str(item) for item in permissions_raw if _safe_str(item)]

        return ReportContext(
            user_id=_safe_str(user_id).strip(),
            workspace_id=_safe_str(workspace_id).strip(),
            request_id=_safe_str(ctx.get("request_id"), str(uuid.uuid4())),
            trace_id=_safe_str(ctx.get("trace_id"), str(uuid.uuid4())),
            role=_safe_str(ctx.get("role")) or None,
            permissions=permissions,
            source_agent=_safe_str(ctx.get("source_agent")) or None,
            locale=_safe_str(ctx.get("locale"), "en-US"),
            timezone_name=_safe_str(ctx.get("timezone_name"), "UTC"),
            metadata=_deepcopy_json_safe(ctx.get("metadata") or {}),
        )

    def _make_period(self, period: Optional[Mapping[str, Any]]) -> ReportPeriod:
        """Create a safe ReportPeriod."""
        raw = dict(period or {})
        return ReportPeriod(
            start_date=_normalize_date(raw.get("start_date") or raw.get("from")),
            end_date=_normalize_date(raw.get("end_date") or raw.get("to")),
            label=_safe_str(raw.get("label")) or None,
        )

    def _validate_task_context(self, context: Union[ReportContext, Mapping[str, Any]]) -> Dict[str, Any]:
        """
        Validate user/workspace context.

        Required compatibility hook.
        """
        if isinstance(context, Mapping):
            user_id = _safe_str(context.get("user_id")).strip()
            workspace_id = _safe_str(context.get("workspace_id")).strip()
            request_id = _safe_str(context.get("request_id"), str(uuid.uuid4()))
            trace_id = _safe_str(context.get("trace_id"), str(uuid.uuid4()))
        else:
            user_id = _safe_str(context.user_id).strip()
            workspace_id = _safe_str(context.workspace_id).strip()
            request_id = context.request_id
            trace_id = context.trace_id

        if not user_id:
            return self._error_result(
                message="user_id is required for BusinessReportBuilder operations.",
                error="missing_user_id",
                metadata={
                    "request_id": request_id,
                    "trace_id": trace_id,
                },
            )

        if not workspace_id:
            return self._error_result(
                message="workspace_id is required for BusinessReportBuilder operations.",
                error="missing_workspace_id",
                metadata={
                    "request_id": request_id,
                    "trace_id": trace_id,
                },
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
            },
            metadata={
                "request_id": request_id,
                "trace_id": trace_id,
            },
        )

    def _filter_records_for_context(
        self,
        records: Sequence[Mapping[str, Any]],
        context: ReportContext,
        period: Optional[ReportPeriod] = None,
    ) -> List[Dict[str, Any]]:
        """
        Enforce SaaS isolation and optional date filtering.

        Records with explicit user_id/workspace_id must match current context.
        Records without those fields are accepted because some internal modules may
        pre-filter data before calling this builder.
        """
        safe_records: List[Dict[str, Any]] = []
        for raw in list(records)[:MAX_REPORT_ITEMS]:
            item = self._sanitize_record_for_context(raw, context)

            item_user_id = _safe_str(item.get("user_id")).strip()
            item_workspace_id = _safe_str(item.get("workspace_id")).strip()

            if item_user_id and item_user_id != context.user_id:
                continue

            if item_workspace_id and item_workspace_id != context.workspace_id:
                continue

            if period:
                record_date = (
                    item.get("date")
                    or item.get("created_at")
                    or item.get("updated_at")
                    or item.get("timestamp")
                    or item.get("closed_at")
                    or item.get("due_date")
                )
                if not _date_in_period(record_date, period):
                    continue

            safe_records.append(item)

        return safe_records

    def _filter_client_records(
        self,
        records: Sequence[Mapping[str, Any]],
        client_id: str,
        context: ReportContext,
        period: Optional[ReportPeriod] = None,
    ) -> List[Dict[str, Any]]:
        """Filter records by SaaS context and client_id."""
        context_records = self._filter_records_for_context(records, context, period)
        safe_client_id = _safe_str(client_id).strip()

        output = []
        for item in context_records:
            item_client_id = _safe_str(item.get("client_id") or item.get("customer_id")).strip()
            if not item_client_id or item_client_id == safe_client_id:
                output.append(item)

        return output

    def _sanitize_record_for_context(
        self,
        record: Mapping[str, Any],
        context: ReportContext,
    ) -> Dict[str, Any]:
        """
        Sanitize record for reporting.

        This avoids mutating caller data and removes common secret-like fields.
        """
        item = _deepcopy_json_safe(dict(record or {}))

        blocked_keys = {
            "password",
            "secret",
            "api_key",
            "token",
            "access_token",
            "refresh_token",
            "private_key",
            "auth_key",
            "authorization",
        }

        for key in list(item.keys()):
            if key.lower() in blocked_keys or "secret" in key.lower() or "password" in key.lower():
                item[key] = "[REDACTED]"

        return item

    # -----------------------------------------------------------------------
    # Security / Verification / Memory / Events / Audit Hooks
    # -----------------------------------------------------------------------

    def _requires_security_check(
        self,
        *,
        report_type: str,
        action: str,
        context: Optional[ReportContext] = None,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> bool:
        """
        Determine whether this action should go through Security Agent.

        Required compatibility hook.
        """
        if bool(self.config.get("always_require_security_for_reports", False)):
            return True

        report_type_lower = _safe_str(report_type).lower()
        action_lower = _safe_str(action).lower()

        if report_type_lower in SENSITIVE_REPORT_TYPES:
            return True

        if "export" in action_lower:
            return True

        if context and "report:generate" in context.permissions:
            return False

        if payload:
            payload_text = json.dumps(_deepcopy_json_safe(dict(payload)), default=str).lower()
            if any(word in payload_text for word in ["revenue", "invoice", "client", "financial"]):
                return True

        return False

    def _request_security_approval(
        self,
        *,
        context: ReportContext,
        action: str,
        report_type: str,
        risk_level: str = RiskLevel.MEDIUM.value,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request or simulate Security Agent approval.

        Required compatibility hook.

        In production, if a Security Agent adapter is provided and exposes one of
        these methods, it will be called:
            - approve_action(payload)
            - validate_action(payload)
            - request_approval(payload)

        If no Security Agent exists, safe default allows low/medium report
        generation but blocks high-risk actions when config says so.
        """
        approval_payload = {
            "approval_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": action,
            "report_type": report_type,
            "risk_level": risk_level,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "trace_id": context.trace_id,
            "payload": _deepcopy_json_safe(dict(payload or {})),
            "requested_at": _utc_now_iso(),
        }

        try:
            if self.security_agent is not None:
                for method_name in ("approve_action", "validate_action", "request_approval"):
                    method = getattr(self.security_agent, method_name, None)
                    if callable(method):
                        response = method(approval_payload)
                        if isinstance(response, Mapping):
                            if response.get("success") is False or response.get("approved") is False:
                                return self._error_result(
                                    message="Security approval denied.",
                                    error=response.get("error") or "security_approval_denied",
                                    data={
                                        "security_payload": approval_payload,
                                        "security_response": _deepcopy_json_safe(dict(response)),
                                    },
                                    metadata={
                                        "request_id": context.request_id,
                                        "trace_id": context.trace_id,
                                    },
                                )
                            return self._safe_result(
                                message="Security approval granted.",
                                data={
                                    "security_payload": approval_payload,
                                    "security_response": _deepcopy_json_safe(dict(response)),
                                },
                                metadata={
                                    "request_id": context.request_id,
                                    "trace_id": context.trace_id,
                                },
                            )

            block_without_security = bool(
                self.config.get("block_high_risk_without_security_agent", False)
            )
            if block_without_security and risk_level == RiskLevel.HIGH.value:
                return self._error_result(
                    message="Security Agent approval required but Security Agent is unavailable.",
                    error="security_agent_unavailable",
                    data={"security_payload": approval_payload},
                    metadata={
                        "request_id": context.request_id,
                        "trace_id": context.trace_id,
                    },
                )

            return self._safe_result(
                message="Security approval simulated by safe local policy.",
                data={
                    "approved": True,
                    "mode": "local_policy",
                    "security_payload": approval_payload,
                },
                metadata={
                    "request_id": context.request_id,
                    "trace_id": context.trace_id,
                },
            )

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return self._error_result(
                message="Security approval request failed.",
                error=exc,
                data={"security_payload": approval_payload},
                metadata={
                    "request_id": context.request_id,
                    "trace_id": context.trace_id,
                },
            )

    def _prepare_verification_payload(
        self,
        *,
        context: ReportContext,
        action: str,
        result_data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Required compatibility hook.
        """
        report = dict(result_data or {})
        sections = report.get("sections") or []

        return {
            "verification_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "trace_id": context.trace_id,
            "created_at": _utc_now_iso(),
            "checks": {
                "has_report_id": bool(report.get("report_id")),
                "has_report_type": bool(report.get("report_type")),
                "has_sections": bool(sections),
                "has_user_id": report.get("user_id") == context.user_id,
                "has_workspace_id": report.get("workspace_id") == context.workspace_id,
                "status_ready": report.get("status") == ReportStatus.READY.value,
                "section_count": len(sections) if isinstance(sections, list) else 0,
            },
            "result_summary": {
                "report_id": report.get("report_id"),
                "report_type": report.get("report_type"),
                "title": report.get("title"),
                "status": report.get("status"),
                "generated_at": report.get("generated_at"),
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        context: ReportContext,
        report: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent compatible payload.

        Required compatibility hook.

        This stores only useful report context and summaries by default, not full
        raw report item lists.
        """
        safe_report = dict(report or {})
        sections = safe_report.get("sections") or []

        memory_sections = []
        if isinstance(sections, list):
            for section in sections:
                if not isinstance(section, Mapping):
                    continue
                memory_sections.append({
                    "title": section.get("title"),
                    "summary": section.get("summary"),
                    "metrics": section.get("metrics"),
                    "insights": section.get("insights"),
                    "recommendations": section.get("recommendations"),
                })

        return {
            "memory_id": str(uuid.uuid4()),
            "memory_type": "business_report_summary",
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "trace_id": context.trace_id,
            "created_at": _utc_now_iso(),
            "content": {
                "report_id": safe_report.get("report_id"),
                "report_type": safe_report.get("report_type"),
                "title": safe_report.get("title"),
                "period": safe_report.get("period"),
                "executive_summary": safe_report.get("executive_summary"),
                "highlights": safe_report.get("highlights"),
                "risks": safe_report.get("risks"),
                "recommendations": safe_report.get("recommendations"),
                "sections": memory_sections,
            },
            "metadata": {
                "safe_for_memory": True,
                "raw_items_included": False,
                "source": "BusinessReportBuilder",
            },
        }

    def _emit_agent_event(
        self,
        *,
        context: ReportContext,
        event_name: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Emit agent event for Dashboard/API/Event Bus.

        Required compatibility hook.
        """
        event = {
            "event_id": str(uuid.uuid4()),
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "trace_id": context.trace_id,
            "payload": _deepcopy_json_safe(dict(payload or {})),
            "created_at": _utc_now_iso(),
        }

        try:
            if self.event_bus is not None:
                for method_name in ("emit", "publish", "send"):
                    method = getattr(self.event_bus, method_name, None)
                    if callable(method):
                        method(event_name, event)
                        break
            elif hasattr(super(), "emit_event"):
                try:
                    super().emit_event(event_name=event_name, payload=event)
                except Exception:
                    pass

            return self._safe_result(
                message="Agent event emitted.",
                data={"event": event},
                metadata={
                    "request_id": context.request_id,
                    "trace_id": context.trace_id,
                },
            )

        except Exception as exc:
            self.logger.warning("Failed to emit agent event: %s", exc)
            return self._error_result(
                message="Failed to emit agent event.",
                error=exc,
                data={"event": event},
                metadata={
                    "request_id": context.request_id,
                    "trace_id": context.trace_id,
                },
            )

    def _log_audit_event(
        self,
        *,
        context: ReportContext,
        action: str,
        status: str,
        risk_level: str = RiskLevel.LOW.value,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log audit event.

        Required compatibility hook.
        """
        event = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": action,
            "status": status,
            "risk_level": risk_level,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "trace_id": context.trace_id,
            "metadata": _deepcopy_json_safe(dict(metadata or {})),
            "created_at": _utc_now_iso(),
        }

        try:
            if self.audit_logger is not None:
                for method_name in ("log", "write", "record"):
                    method = getattr(self.audit_logger, method_name, None)
                    if callable(method):
                        method(event)
                        break

            self.logger.info(
                "Audit event: action=%s status=%s user_id=%s workspace_id=%s",
                action,
                status,
                context.user_id,
                context.workspace_id,
            )

            return self._safe_result(
                message="Audit event logged.",
                data={"audit_event": event},
                metadata={
                    "request_id": context.request_id,
                    "trace_id": context.trace_id,
                },
            )

        except Exception as exc:
            self.logger.warning("Failed to log audit event: %s", exc)
            return self._error_result(
                message="Failed to log audit event.",
                error=exc,
                data={"audit_event": event},
                metadata={
                    "request_id": context.request_id,
                    "trace_id": context.trace_id,
                },
            )

    # -----------------------------------------------------------------------
    # Result Helpers
    # -----------------------------------------------------------------------

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard successful result.

        Required compatibility hook.
        """
        return {
            "success": True,
            "message": message,
            "data": _deepcopy_json_safe(dict(data or {})),
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "agent_version": self.agent_version,
                "timestamp": _utc_now_iso(),
                **_deepcopy_json_safe(dict(metadata or {})),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Any,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard error result.

        Required compatibility hook.
        """
        if isinstance(error, Exception):
            error_payload: Any = {
                "type": error.__class__.__name__,
                "message": str(error),
            }
        else:
            error_payload = error

        return {
            "success": False,
            "message": message,
            "data": _deepcopy_json_safe(dict(data or {})),
            "error": _deepcopy_json_safe(error_payload),
            "metadata": {
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "agent_version": self.agent_version,
                "timestamp": _utc_now_iso(),
                **_deepcopy_json_safe(dict(metadata or {})),
            },
        }

    # -----------------------------------------------------------------------
    # Export Helpers
    # -----------------------------------------------------------------------

    def _report_to_csv(self, report: Mapping[str, Any]) -> str:
        """
        Convert report sections into CSV.

        CSV contains section title, summary, metric key/value, insights,
        recommendations, and item counts.
        """
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            "report_id",
            "report_type",
            "title",
            "section",
            "metric_key",
            "metric_value",
            "summary",
            "insights",
            "recommendations",
            "item_count",
        ])

        report_id = report.get("report_id")
        report_type = report.get("report_type")
        title = report.get("title")
        sections = report.get("sections") or []

        if not isinstance(sections, list):
            sections = []

        for section in sections:
            if not isinstance(section, Mapping):
                continue

            section_title = section.get("title")
            summary = section.get("summary")
            insights = " | ".join(_safe_str(item) for item in section.get("insights") or [])
            recommendations = " | ".join(_safe_str(item) for item in section.get("recommendations") or [])
            items = section.get("items") or []
            item_count = len(items) if isinstance(items, list) else 0

            metrics = section.get("metrics") or {}
            if isinstance(metrics, Mapping) and metrics:
                for key, value in metrics.items():
                    writer.writerow([
                        report_id,
                        report_type,
                        title,
                        section_title,
                        key,
                        json.dumps(value, default=str) if isinstance(value, (dict, list)) else value,
                        summary,
                        insights,
                        recommendations,
                        item_count,
                    ])
            else:
                writer.writerow([
                    report_id,
                    report_type,
                    title,
                    section_title,
                    "",
                    "",
                    summary,
                    insights,
                    recommendations,
                    item_count,
                ])

        return output.getvalue()

    # -----------------------------------------------------------------------
    # Custom Section Helpers
    # -----------------------------------------------------------------------

    def _normalize_custom_sections(
        self,
        sections: Sequence[Mapping[str, Any]],
    ) -> List[ReportSection]:
        """Normalize caller-provided section mappings into ReportSection objects."""
        normalized: List[ReportSection] = []

        for index, raw in enumerate(list(sections)[:100]):
            item = dict(raw or {})
            normalized.append(
                ReportSection(
                    title=_safe_str(item.get("title"), f"Section {index + 1}"),
                    summary=_safe_str(item.get("summary"), "Custom report section."),
                    metrics=_deepcopy_json_safe(dict(item.get("metrics") or {})),
                    items=_limit_items(
                        [
                            dict(value)
                            for value in item.get("items", [])
                            if isinstance(value, Mapping)
                        ],
                        DEFAULT_SUMMARY_LIMIT,
                    ),
                    insights=[
                        _safe_str(value)
                        for value in item.get("insights", [])
                        if _safe_str(value)
                    ],
                    recommendations=[
                        _safe_str(value)
                        for value in item.get("recommendations", [])
                        if _safe_str(value)
                    ],
                    metadata=_deepcopy_json_safe(dict(item.get("metadata") or {})),
                )
            )

        if not normalized:
            normalized.append(
                ReportSection(
                    title="Custom Report",
                    summary="No custom sections were provided.",
                    metrics={},
                    insights=["Custom report was created without section-level data."],
                    recommendations=["Add report sections and metrics for a more useful report."],
                )
            )

        return normalized

    # -----------------------------------------------------------------------
    # Misc Helpers
    # -----------------------------------------------------------------------

    def _currency(self) -> str:
        """Return configured report currency."""
        return _safe_str(self.config.get("currency"), DEFAULT_REPORT_CURRENCY).upper()

    def _is_task_overdue(self, item: Mapping[str, Any]) -> bool:
        """Infer whether a task/deliverable is overdue."""
        due = _parse_date(item.get("due_date") or item.get("deadline"))
        if due is None:
            return False

        status = _safe_str(item.get("status")).lower()
        if status in {"done", "completed", "closed", "approved", "delivered"}:
            return False

        return due < _utc_now().date()

    def _unique_list(self, values: Sequence[str], limit: int = 10) -> List[str]:
        """Return unique string list while preserving order."""
        seen = set()
        output: List[str] = []

        for value in values:
            clean = _safe_str(value).strip()
            if not clean:
                continue
            key = clean.lower()
            if key in seen:
                continue
            seen.add(key)
            output.append(clean)
            if len(output) >= limit:
                break

        return output


# ---------------------------------------------------------------------------
# Registry-Friendly Factory
# ---------------------------------------------------------------------------

def create_business_report_builder(
    config: Optional[Mapping[str, Any]] = None,
    **kwargs: Any,
) -> BusinessReportBuilder:
    """
    Factory helper for Agent Loader / Agent Registry.

    Args:
        config: Optional report builder config.
        **kwargs: Optional adapters such as security_agent, memory_agent,
            verification_agent, event_bus, audit_logger.

    Returns:
        BusinessReportBuilder instance.
    """
    return BusinessReportBuilder(config=config, **kwargs)


# ---------------------------------------------------------------------------
# Module Metadata
# ---------------------------------------------------------------------------

AGENT_MODULE_METADATA: Dict[str, Any] = {
    "module": "business_agent",
    "file": "report_builder.py",
    "class": "BusinessReportBuilder",
    "purpose": "Builds business reports, client reports, and weekly summaries.",
    "agent_name": DEFAULT_AGENT_NAME,
    "agent_version": DEFAULT_AGENT_VERSION,
    "compatible_with": [
        "BaseAgent",
        "Agent Registry",
        "Agent Loader",
        "Agent Router",
        "Master Agent",
        "Security Agent",
        "Verification Agent",
        "Memory Agent",
        "Dashboard/API",
    ],
    "public_methods": [
        "build_business_report",
        "build_client_report",
        "build_weekly_summary",
        "build_custom_report",
        "export_report",
        "get_capabilities",
    ],
    "required_context": [
        "user_id",
        "workspace_id",
    ],
    "safe_to_import": True,
}


__all__ = [
    "BusinessReportBuilder",
    "ReportContext",
    "ReportPeriod",
    "ReportSection",
    "BusinessReport",
    "ReportType",
    "ReportStatus",
    "ReportFormat",
    "RiskLevel",
    "create_business_report_builder",
    "AGENT_MODULE_METADATA",
]