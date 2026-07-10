"""
agents/super_agents/business_agent/business_agent.py

BusinessAgent for William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    Main business controller for CRM, leads, analytics, clients, and reports.

This file is intentionally import-safe:
    - It uses optional imports and fallback stubs if future William modules do not exist yet.
    - It never executes real external, financial, message, browser, call, or destructive actions directly.
    - It enforces SaaS user/workspace isolation for every user-specific task.
    - It prepares Security Agent, Verification Agent, Memory Agent, Dashboard, Audit, Registry,
      Router, and Master Agent compatible payloads.

Expected path:
    agents/super_agents/business_agent/business_agent.py
"""

from __future__ import annotations

import asyncio
import dataclasses
import enum
import logging
import time
import traceback
import uuid
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ======================================================================================
# Safe optional imports
# ======================================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:
    try:
        from core.base_agent import BaseAgent  # type: ignore
    except Exception:
        class BaseAgent:  # type: ignore
            """
            Fallback BaseAgent stub.

            This keeps the file import-safe during early project scaffolding.
            The real William/Jarvis BaseAgent should replace this automatically
            when available in the project.
            """

            def __init__(self, *args: Any, **kwargs: Any) -> None:
                self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
                self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
                self.logger = logging.getLogger(self.agent_name)

            async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
                raise NotImplementedError("Fallback BaseAgent.run is not implemented.")


try:
    from agents.super_agents.business_agent.config import BusinessAgentConfig  # type: ignore
except Exception:
    @dataclasses.dataclass
    class BusinessAgentConfig:
        """
        Fallback config until business_agent/config.py is generated.
        """

        agent_name: str = "BusinessAgent"
        agent_id: str = "business_agent"
        version: str = "1.0.0"
        require_security_for_exports: bool = True
        require_security_for_deletes: bool = True
        require_security_for_revenue: bool = True
        require_security_for_bulk_updates: bool = True
        max_page_size: int = 100
        default_page_size: int = 25
        audit_enabled: bool = True
        memory_enabled: bool = True
        verification_enabled: bool = True
        dashboard_events_enabled: bool = True
        allow_in_memory_store: bool = True


try:
    from agents.super_agents.business_agent.crm_manager import CRMManager  # type: ignore
except Exception:
    CRMManager = None  # type: ignore

try:
    from agents.super_agents.business_agent.lead_tracker import LeadTracker  # type: ignore
except Exception:
    LeadTracker = None  # type: ignore

try:
    from agents.super_agents.business_agent.analytics_engine import AnalyticsEngine  # type: ignore
except Exception:
    AnalyticsEngine = None  # type: ignore

try:
    from agents.super_agents.business_agent.client_manager import ClientManager  # type: ignore
except Exception:
    ClientManager = None  # type: ignore

try:
    from agents.super_agents.business_agent.sales_pipeline import SalesPipeline  # type: ignore
except Exception:
    SalesPipeline = None  # type: ignore

try:
    from agents.super_agents.business_agent.campaign_tracker import CampaignTracker  # type: ignore
except Exception:
    CampaignTracker = None  # type: ignore

try:
    from agents.super_agents.business_agent.revenue_tracker import RevenueTracker  # type: ignore
except Exception:
    RevenueTracker = None  # type: ignore

try:
    from agents.super_agents.business_agent.report_builder import ReportBuilder  # type: ignore
except Exception:
    ReportBuilder = None  # type: ignore

try:
    from agents.super_agents.business_agent.task_manager import BusinessTaskManager  # type: ignore
except Exception:
    BusinessTaskManager = None  # type: ignore

try:
    from agents.super_agents.business_agent.business_memory import BusinessMemory  # type: ignore
except Exception:
    BusinessMemory = None  # type: ignore


# ======================================================================================
# Logging
# ======================================================================================

logger = logging.getLogger("BusinessAgent")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)


# ======================================================================================
# Enums and constants
# ======================================================================================

class BusinessAction(str, enum.Enum):
    """
    Supported high-level Business Agent actions.

    These action names are intentionally plain strings so the Master Agent,
    Agent Router, dashboard/API, and future registry can route tasks easily.
    """

    HEALTH_CHECK = "health_check"

    CRM_CREATE_RECORD = "crm_create_record"
    CRM_UPDATE_RECORD = "crm_update_record"
    CRM_GET_RECORD = "crm_get_record"
    CRM_SEARCH_RECORDS = "crm_search_records"
    CRM_DELETE_RECORD = "crm_delete_record"

    LEAD_CREATE = "lead_create"
    LEAD_UPDATE = "lead_update"
    LEAD_QUALIFY = "lead_qualify"
    LEAD_SCORE = "lead_score"
    LEAD_SEARCH = "lead_search"
    LEAD_CONVERT_TO_CLIENT = "lead_convert_to_client"

    CLIENT_CREATE = "client_create"
    CLIENT_UPDATE = "client_update"
    CLIENT_GET = "client_get"
    CLIENT_SEARCH = "client_search"
    CLIENT_ARCHIVE = "client_archive"

    PIPELINE_CREATE_DEAL = "pipeline_create_deal"
    PIPELINE_UPDATE_DEAL = "pipeline_update_deal"
    PIPELINE_MOVE_STAGE = "pipeline_move_stage"
    PIPELINE_GET_DEALS = "pipeline_get_deals"

    CAMPAIGN_CREATE = "campaign_create"
    CAMPAIGN_UPDATE = "campaign_update"
    CAMPAIGN_PERFORMANCE = "campaign_performance"

    REVENUE_RECORD = "revenue_record"
    REVENUE_SUMMARY = "revenue_summary"
    REVENUE_FORECAST = "revenue_forecast"

    ANALYTICS_SUMMARY = "analytics_summary"
    ANALYTICS_DASHBOARD = "analytics_dashboard"
    ANALYTICS_FUNNEL = "analytics_funnel"

    REPORT_BUILD = "report_build"
    REPORT_EXPORT = "report_export"

    BUSINESS_TASK_CREATE = "business_task_create"
    BUSINESS_TASK_UPDATE = "business_task_update"
    BUSINESS_TASK_SEARCH = "business_task_search"

    ROUTE_BUSINESS_TASK = "route_business_task"


SENSITIVE_ACTIONS = {
    BusinessAction.CRM_DELETE_RECORD,
    BusinessAction.CLIENT_ARCHIVE,
    BusinessAction.REPORT_EXPORT,
    BusinessAction.REVENUE_RECORD,
    BusinessAction.REVENUE_SUMMARY,
    BusinessAction.REVENUE_FORECAST,
}

BULK_ACTIONS = {
    BusinessAction.CRM_SEARCH_RECORDS,
    BusinessAction.LEAD_SEARCH,
    BusinessAction.CLIENT_SEARCH,
    BusinessAction.PIPELINE_GET_DEALS,
    BusinessAction.ANALYTICS_SUMMARY,
    BusinessAction.ANALYTICS_DASHBOARD,
    BusinessAction.REPORT_BUILD,
    BusinessAction.REPORT_EXPORT,
}


# ======================================================================================
# Data structures
# ======================================================================================

@dataclasses.dataclass
class TaskContext:
    """
    SaaS-safe execution context.

    Every user/workspace scoped task must include user_id and workspace_id.
    This prevents mixing CRM, leads, reports, revenue, memory, logs, analytics,
    or audit data between tenants.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    subscription_plan: Optional[str] = None
    request_id: str = dataclasses.field(default_factory=lambda: str(uuid.uuid4()))
    session_id: Optional[str] = None
    source: str = "business_agent"
    metadata: Dict[str, Any] = dataclasses.field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class BusinessRecord:
    """
    Generic in-memory business record used only as a safe fallback
    until dedicated managers/database layers are generated.
    """

    id: str
    user_id: str
    workspace_id: str
    record_type: str
    payload: Dict[str, Any]
    created_at: str
    updated_at: str
    archived: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class InMemoryBusinessStore:
    """
    Safe fallback data store.

    This is not intended to replace production database repositories.
    It exists so BusinessAgent remains testable and import-safe before
    crm_manager.py, lead_tracker.py, client_manager.py, and other files exist.

    Tenant isolation is enforced on every read/write.
    """

    def __init__(self) -> None:
        self._records: Dict[str, BusinessRecord] = {}

    def create(
        self,
        *,
        context: TaskContext,
        record_type: str,
        payload: Mapping[str, Any],
    ) -> BusinessRecord:
        now = utc_now_iso()
        record = BusinessRecord(
            id=str(uuid.uuid4()),
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            record_type=record_type,
            payload=dict(payload),
            created_at=now,
            updated_at=now,
        )
        self._records[record.id] = record
        return record

    def update(
        self,
        *,
        context: TaskContext,
        record_id: str,
        updates: Mapping[str, Any],
    ) -> Optional[BusinessRecord]:
        record = self._records.get(record_id)
        if not record or not self._matches_context(record, context):
            return None
        safe_updates = dict(updates)
        safe_updates.pop("user_id", None)
        safe_updates.pop("workspace_id", None)
        safe_updates.pop("id", None)
        record.payload.update(safe_updates)
        record.updated_at = utc_now_iso()
        return record

    def get(
        self,
        *,
        context: TaskContext,
        record_id: str,
        include_archived: bool = False,
    ) -> Optional[BusinessRecord]:
        record = self._records.get(record_id)
        if not record or not self._matches_context(record, context):
            return None
        if record.archived and not include_archived:
            return None
        return record

    def search(
        self,
        *,
        context: TaskContext,
        record_type: Optional[str] = None,
        query: Optional[str] = None,
        filters: Optional[Mapping[str, Any]] = None,
        include_archived: bool = False,
        limit: int = 25,
        offset: int = 0,
    ) -> Tuple[List[BusinessRecord], int]:
        filters = dict(filters or {})
        query_lower = (query or "").lower().strip()

        matched: List[BusinessRecord] = []
        for record in self._records.values():
            if not self._matches_context(record, context):
                continue
            if record_type and record.record_type != record_type:
                continue
            if record.archived and not include_archived:
                continue
            if query_lower and query_lower not in str(record.payload).lower():
                continue
            if not self._matches_filters(record.payload, filters):
                continue
            matched.append(record)

        total = len(matched)
        paged = matched[offset: offset + limit]
        return paged, total

    def archive(self, *, context: TaskContext, record_id: str) -> Optional[BusinessRecord]:
        record = self._records.get(record_id)
        if not record or not self._matches_context(record, context):
            return None
        record.archived = True
        record.updated_at = utc_now_iso()
        return record

    def delete(self, *, context: TaskContext, record_id: str) -> bool:
        record = self._records.get(record_id)
        if not record or not self._matches_context(record, context):
            return False
        del self._records[record_id]
        return True

    @staticmethod
    def _matches_context(record: BusinessRecord, context: TaskContext) -> bool:
        return record.user_id == context.user_id and record.workspace_id == context.workspace_id

    @staticmethod
    def _matches_filters(payload: Mapping[str, Any], filters: Mapping[str, Any]) -> bool:
        for key, expected in filters.items():
            if expected is None:
                continue
            actual = payload.get(key)
            if isinstance(expected, (list, tuple, set)):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True


# ======================================================================================
# Utility helpers
# ======================================================================================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_action(action: Union[str, BusinessAction, None]) -> Optional[BusinessAction]:
    if isinstance(action, BusinessAction):
        return action
    if not action:
        return None
    raw = str(action).strip().lower()
    for item in BusinessAction:
        if item.value == raw:
            return item
    return None


def ensure_mapping(value: Any, default: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return dict(default or {})


def safe_str(value: Any, fallback: str = "") -> str:
    if value is None:
        return fallback
    return str(value).strip()


def clamp_int(value: Any, minimum: int, maximum: int, default: int) -> int:
    try:
        parsed = int(value)
    except Exception:
        return default
    return max(minimum, min(maximum, parsed))


async def maybe_await(value: Union[Any, Awaitable[Any]]) -> Any:
    if asyncio.iscoroutine(value) or isinstance(value, Awaitable):
        return await value
    return value


# ======================================================================================
# BusinessAgent
# ======================================================================================

class BusinessAgent(BaseAgent):
    """
    Main Business Agent controller.

    Responsibilities:
        - CRM orchestration
        - Lead tracking and qualification
        - Client management
        - Sales pipeline routing
        - Campaign tracking
        - Revenue summaries and forecasting
        - Business analytics
        - Report generation/export preparation
        - Business task management
        - Memory, audit, verification, and dashboard event payload preparation

    System connections:
        - Master Agent:
            Routes business tasks here using action names.
        - Agent Registry / Loader:
            Can discover this class through registry_metadata().
        - Agent Router:
            Calls run(), handle_task(), or public methods directly.
        - Security Agent:
            Sensitive actions call _requires_security_check() and _request_security_approval().
        - Memory Agent:
            Useful business context is prepared through _prepare_memory_payload().
        - Verification Agent:
            Every completed action prepares _prepare_verification_payload().
        - Dashboard/API:
            Structured results and _emit_agent_event() payloads are dashboard-ready.
    """

    def __init__(
        self,
        config: Optional[BusinessAgentConfig] = None,
        *,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_bus: Optional[Any] = None,
        audit_logger: Optional[Any] = None,
        crm_manager: Optional[Any] = None,
        lead_tracker: Optional[Any] = None,
        analytics_engine: Optional[Any] = None,
        client_manager: Optional[Any] = None,
        sales_pipeline: Optional[Any] = None,
        campaign_tracker: Optional[Any] = None,
        revenue_tracker: Optional[Any] = None,
        report_builder: Optional[Any] = None,
        task_manager: Optional[Any] = None,
        business_memory: Optional[Any] = None,
        store: Optional[InMemoryBusinessStore] = None,
        **kwargs: Any,
    ) -> None:
        self.config = config or BusinessAgentConfig()

        try:
            super().__init__(
                agent_name=getattr(self.config, "agent_name", "BusinessAgent"),
                agent_id=getattr(self.config, "agent_id", "business_agent"),
                **kwargs,
            )
        except TypeError:
            try:
                super().__init__(**kwargs)
            except TypeError:
                super().__init__()

        self.agent_name = getattr(self.config, "agent_name", "BusinessAgent")
        self.agent_id = getattr(self.config, "agent_id", "business_agent")
        self.version = getattr(self.config, "version", "1.0.0")
        self.logger = logging.getLogger(self.agent_name)

        self.security_agent = security_agent
        self.verification_agent = verification_agent
        self.memory_agent = memory_agent
        self.event_bus = event_bus
        self.audit_logger = audit_logger

        self.store = store or InMemoryBusinessStore()

        self.crm_manager = crm_manager or self._build_optional_component(CRMManager)
        self.lead_tracker = lead_tracker or self._build_optional_component(LeadTracker)
        self.analytics_engine = analytics_engine or self._build_optional_component(AnalyticsEngine)
        self.client_manager = client_manager or self._build_optional_component(ClientManager)
        self.sales_pipeline = sales_pipeline or self._build_optional_component(SalesPipeline)
        self.campaign_tracker = campaign_tracker or self._build_optional_component(CampaignTracker)
        self.revenue_tracker = revenue_tracker or self._build_optional_component(RevenueTracker)
        self.report_builder = report_builder or self._build_optional_component(ReportBuilder)
        self.task_manager = task_manager or self._build_optional_component(BusinessTaskManager)
        self.business_memory = business_memory or self._build_optional_component(BusinessMemory)

        self._action_handlers: Dict[BusinessAction, Callable[..., Awaitable[Dict[str, Any]]]] = {
            BusinessAction.HEALTH_CHECK: self.health_check,

            BusinessAction.CRM_CREATE_RECORD: self.create_crm_record,
            BusinessAction.CRM_UPDATE_RECORD: self.update_crm_record,
            BusinessAction.CRM_GET_RECORD: self.get_crm_record,
            BusinessAction.CRM_SEARCH_RECORDS: self.search_crm_records,
            BusinessAction.CRM_DELETE_RECORD: self.delete_crm_record,

            BusinessAction.LEAD_CREATE: self.create_lead,
            BusinessAction.LEAD_UPDATE: self.update_lead,
            BusinessAction.LEAD_QUALIFY: self.qualify_lead,
            BusinessAction.LEAD_SCORE: self.score_lead,
            BusinessAction.LEAD_SEARCH: self.search_leads,
            BusinessAction.LEAD_CONVERT_TO_CLIENT: self.convert_lead_to_client,

            BusinessAction.CLIENT_CREATE: self.create_client,
            BusinessAction.CLIENT_UPDATE: self.update_client,
            BusinessAction.CLIENT_GET: self.get_client,
            BusinessAction.CLIENT_SEARCH: self.search_clients,
            BusinessAction.CLIENT_ARCHIVE: self.archive_client,

            BusinessAction.PIPELINE_CREATE_DEAL: self.create_deal,
            BusinessAction.PIPELINE_UPDATE_DEAL: self.update_deal,
            BusinessAction.PIPELINE_MOVE_STAGE: self.move_deal_stage,
            BusinessAction.PIPELINE_GET_DEALS: self.get_deals,

            BusinessAction.CAMPAIGN_CREATE: self.create_campaign,
            BusinessAction.CAMPAIGN_UPDATE: self.update_campaign,
            BusinessAction.CAMPAIGN_PERFORMANCE: self.get_campaign_performance,

            BusinessAction.REVENUE_RECORD: self.record_revenue,
            BusinessAction.REVENUE_SUMMARY: self.get_revenue_summary,
            BusinessAction.REVENUE_FORECAST: self.get_revenue_forecast,

            BusinessAction.ANALYTICS_SUMMARY: self.get_analytics_summary,
            BusinessAction.ANALYTICS_DASHBOARD: self.get_dashboard_analytics,
            BusinessAction.ANALYTICS_FUNNEL: self.get_funnel_analytics,

            BusinessAction.REPORT_BUILD: self.build_report,
            BusinessAction.REPORT_EXPORT: self.export_report,

            BusinessAction.BUSINESS_TASK_CREATE: self.create_business_task,
            BusinessAction.BUSINESS_TASK_UPDATE: self.update_business_task,
            BusinessAction.BUSINESS_TASK_SEARCH: self.search_business_tasks,

            BusinessAction.ROUTE_BUSINESS_TASK: self.route_business_task,
        }

    # ==================================================================================
    # Registry and routing compatibility
    # ==================================================================================

    @classmethod
    def registry_metadata(cls) -> Dict[str, Any]:
        """
        Agent Registry / Agent Loader discovery metadata.
        """
        return {
            "agent_name": "BusinessAgent",
            "agent_id": "business_agent",
            "module": "agents.super_agents.business_agent.business_agent",
            "class_name": "BusinessAgent",
            "category": "super_agent",
            "version": "1.0.0",
            "description": "Main business controller for CRM, leads, analytics, clients, reports.",
            "capabilities": [
                "crm",
                "leads",
                "clients",
                "sales_pipeline",
                "campaign_tracking",
                "revenue_tracking",
                "analytics",
                "reports",
                "business_tasks",
                "audit_payloads",
                "memory_payloads",
                "verification_payloads",
            ],
            "requires_context": ["user_id", "workspace_id"],
            "safe_to_import": True,
            "sensitive_actions": [item.value for item in SENSITIVE_ACTIONS],
            "public_methods": [
                "run",
                "handle_task",
                "route_business_task",
                "create_lead",
                "qualify_lead",
                "create_client",
                "get_analytics_summary",
                "build_report",
            ],
        }

    async def run(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        BaseAgent-compatible entry point.
        """
        return await self.handle_task(task)

    async def handle_task(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Master Agent / Router-compatible task handler.

        Expected task shape:
            {
                "action": "lead_create",
                "user_id": "...",
                "workspace_id": "...",
                "payload": {...},
                "metadata": {...}
            }
        """
        started_at = time.time()
        raw_task = ensure_mapping(task)
        action = normalize_action(raw_task.get("action") or raw_task.get("type"))

        if not action:
            return self._error_result(
                message="Unsupported or missing business action.",
                error_code="INVALID_ACTION",
                details={"received_action": raw_task.get("action") or raw_task.get("type")},
            )

        context_result = self._validate_task_context(raw_task)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]["context"]
        payload = ensure_mapping(raw_task.get("payload"), default=raw_task)

        await self._emit_agent_event(
            "business_task_received",
            context=context,
            data={"action": action.value},
        )

        try:
            if self._requires_security_check(action=action, payload=payload, context=context):
                approval = await self._request_security_approval(
                    action=action,
                    payload=payload,
                    context=context,
                )
                if not approval.get("success"):
                    return self._error_result(
                        message="Security approval denied or unavailable.",
                        error_code="SECURITY_APPROVAL_REQUIRED",
                        details={
                            "action": action.value,
                            "approval": approval,
                        },
                        context=context,
                    )

            handler = self._action_handlers.get(action)
            if not handler:
                return self._error_result(
                    message="Business action exists but has no handler.",
                    error_code="HANDLER_NOT_FOUND",
                    details={"action": action.value},
                    context=context,
                )

            result = await handler(context=context, payload=payload)

            verification_payload = self._prepare_verification_payload(
                action=action,
                context=context,
                result=result,
                started_at=started_at,
            )

            memory_payload = self._prepare_memory_payload(
                action=action,
                context=context,
                result=result,
                payload=payload,
            )

            await self._log_audit_event(
                action=action.value,
                context=context,
                success=result.get("success", False),
                data={
                    "result_message": result.get("message"),
                    "verification": verification_payload,
                },
            )

            if getattr(self.config, "memory_enabled", True):
                await self._send_to_memory_agent(memory_payload)

            if getattr(self.config, "verification_enabled", True):
                await self._send_to_verification_agent(verification_payload)

            await self._emit_agent_event(
                "business_task_completed",
                context=context,
                data={
                    "action": action.value,
                    "success": result.get("success", False),
                    "duration_ms": round((time.time() - started_at) * 1000, 2),
                },
            )

            metadata = ensure_mapping(result.get("metadata"))
            metadata.update(
                {
                    "agent": self.agent_name,
                    "agent_id": self.agent_id,
                    "version": self.version,
                    "action": action.value,
                    "request_id": context.request_id,
                    "duration_ms": round((time.time() - started_at) * 1000, 2),
                    "verification_payload": verification_payload,
                    "memory_payload_prepared": bool(memory_payload),
                }
            )
            result["metadata"] = metadata
            return result

        except Exception as exc:
            self.logger.exception("BusinessAgent task failed: %s", exc)
            await self._log_audit_event(
                action=action.value,
                context=context,
                success=False,
                data={"exception": str(exc)},
            )
            return self._error_result(
                message="Business task failed unexpectedly.",
                error_code="BUSINESS_AGENT_EXCEPTION",
                details={
                    "action": action.value,
                    "exception": str(exc),
                    "traceback": traceback.format_exc(),
                },
                context=context,
            )

    # ==================================================================================
    # Health
    # ==================================================================================

    async def health_check(
        self,
        *,
        context: TaskContext,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        components = {
            "crm_manager": self.crm_manager is not None,
            "lead_tracker": self.lead_tracker is not None,
            "analytics_engine": self.analytics_engine is not None,
            "client_manager": self.client_manager is not None,
            "sales_pipeline": self.sales_pipeline is not None,
            "campaign_tracker": self.campaign_tracker is not None,
            "revenue_tracker": self.revenue_tracker is not None,
            "report_builder": self.report_builder is not None,
            "task_manager": self.task_manager is not None,
            "business_memory": self.business_memory is not None,
            "security_agent": self.security_agent is not None,
            "verification_agent": self.verification_agent is not None,
            "memory_agent": self.memory_agent is not None,
            "event_bus": self.event_bus is not None,
            "audit_logger": self.audit_logger is not None,
            "fallback_store": self.store is not None,
        }
        return self._safe_result(
            message="BusinessAgent is healthy and import-safe.",
            data={
                "agent": self.agent_name,
                "agent_id": self.agent_id,
                "version": self.version,
                "components": components,
                "supported_actions": [action.value for action in BusinessAction],
            },
            context=context,
        )

    # ==================================================================================
    # CRM methods
    # ==================================================================================

    async def create_crm_record(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        data = ensure_mapping(payload.get("record") or payload.get("data") or payload)
        record_type = safe_str(payload.get("record_type"), "crm")
        if not data:
            return self._error_result("CRM record data is required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.crm_manager,
            ["create_record", "create_crm_record", "create"],
            context=context,
            payload={"record_type": record_type, "data": data},
        )
        if delegated:
            return delegated

        record = self.store.create(context=context, record_type=record_type, payload=data)
        return self._safe_result(
            message="CRM record created.",
            data={"record": record.to_dict()},
            context=context,
        )

    async def update_crm_record(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        record_id = safe_str(payload.get("record_id") or payload.get("id"))
        updates = ensure_mapping(payload.get("updates") or payload.get("data"))
        if not record_id or not updates:
            return self._error_result("record_id and updates are required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.crm_manager,
            ["update_record", "update_crm_record", "update"],
            context=context,
            payload={"record_id": record_id, "updates": updates},
        )
        if delegated:
            return delegated

        record = self.store.update(context=context, record_id=record_id, updates=updates)
        if not record:
            return self._error_result("CRM record not found in this workspace.", "NOT_FOUND", context=context)
        return self._safe_result("CRM record updated.", {"record": record.to_dict()}, context=context)

    async def get_crm_record(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        record_id = safe_str(payload.get("record_id") or payload.get("id"))
        if not record_id:
            return self._error_result("record_id is required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.crm_manager,
            ["get_record", "get_crm_record", "get"],
            context=context,
            payload={"record_id": record_id},
        )
        if delegated:
            return delegated

        record = self.store.get(context=context, record_id=record_id)
        if not record:
            return self._error_result("CRM record not found in this workspace.", "NOT_FOUND", context=context)
        return self._safe_result("CRM record found.", {"record": record.to_dict()}, context=context)

    async def search_crm_records(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        record_type = payload.get("record_type")
        query = payload.get("query")
        filters = ensure_mapping(payload.get("filters"))
        limit, offset = self._pagination(payload)

        delegated = await self._try_component_call(
            self.crm_manager,
            ["search_records", "search_crm_records", "search"],
            context=context,
            payload={
                "record_type": record_type,
                "query": query,
                "filters": filters,
                "limit": limit,
                "offset": offset,
            },
        )
        if delegated:
            return delegated

        records, total = self.store.search(
            context=context,
            record_type=safe_str(record_type) if record_type else None,
            query=safe_str(query) if query else None,
            filters=filters,
            limit=limit,
            offset=offset,
        )
        return self._safe_result(
            "CRM records searched.",
            {
                "records": [record.to_dict() for record in records],
                "pagination": {"limit": limit, "offset": offset, "total": total},
            },
            context=context,
        )

    async def delete_crm_record(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        record_id = safe_str(payload.get("record_id") or payload.get("id"))
        if not record_id:
            return self._error_result("record_id is required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.crm_manager,
            ["delete_record", "delete_crm_record", "delete"],
            context=context,
            payload={"record_id": record_id},
        )
        if delegated:
            return delegated

        deleted = self.store.delete(context=context, record_id=record_id)
        if not deleted:
            return self._error_result("CRM record not found in this workspace.", "NOT_FOUND", context=context)
        return self._safe_result("CRM record deleted after security approval.", {"record_id": record_id}, context=context)

    # ==================================================================================
    # Lead methods
    # ==================================================================================

    async def create_lead(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        lead = ensure_mapping(payload.get("lead") or payload.get("data") or payload)
        if not lead:
            return self._error_result("Lead data is required.", "VALIDATION_ERROR", context=context)

        normalized = self._normalize_lead(lead)

        delegated = await self._try_component_call(
            self.lead_tracker,
            ["create_lead", "create", "add_lead"],
            context=context,
            payload={"lead": normalized},
        )
        if delegated:
            return delegated

        record = self.store.create(context=context, record_type="lead", payload=normalized)
        return self._safe_result("Lead created.", {"lead": record.to_dict()}, context=context)

    async def update_lead(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        lead_id = safe_str(payload.get("lead_id") or payload.get("record_id") or payload.get("id"))
        updates = ensure_mapping(payload.get("updates") or payload.get("lead") or payload.get("data"))
        if not lead_id or not updates:
            return self._error_result("lead_id and updates are required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.lead_tracker,
            ["update_lead", "update"],
            context=context,
            payload={"lead_id": lead_id, "updates": updates},
        )
        if delegated:
            return delegated

        record = self.store.update(context=context, record_id=lead_id, updates=updates)
        if not record:
            return self._error_result("Lead not found in this workspace.", "NOT_FOUND", context=context)
        return self._safe_result("Lead updated.", {"lead": record.to_dict()}, context=context)

    async def qualify_lead(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        lead = ensure_mapping(payload.get("lead") or payload.get("data"))
        lead_id = safe_str(payload.get("lead_id") or payload.get("id"))
        if lead_id and not lead:
            found = self.store.get(context=context, record_id=lead_id)
            lead = found.payload if found else {}
        if not lead:
            return self._error_result("Lead data or lead_id is required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.lead_tracker,
            ["qualify_lead", "qualify"],
            context=context,
            payload={"lead_id": lead_id, "lead": lead},
        )
        if delegated:
            return delegated

        score_data = self._score_lead_locally(lead)
        qualification = {
            "lead_id": lead_id or None,
            "qualified": score_data["score"] >= 60,
            "score": score_data["score"],
            "grade": score_data["grade"],
            "reasons": score_data["reasons"],
            "recommended_next_action": self._next_action_for_score(score_data["score"]),
        }
        return self._safe_result("Lead qualification completed.", {"qualification": qualification}, context=context)

    async def score_lead(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        lead = ensure_mapping(payload.get("lead") or payload.get("data"))
        lead_id = safe_str(payload.get("lead_id") or payload.get("id"))
        if lead_id and not lead:
            found = self.store.get(context=context, record_id=lead_id)
            lead = found.payload if found else {}
        if not lead:
            return self._error_result("Lead data or lead_id is required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.lead_tracker,
            ["score_lead", "score"],
            context=context,
            payload={"lead_id": lead_id, "lead": lead},
        )
        if delegated:
            return delegated

        return self._safe_result("Lead score calculated.", {"score": self._score_lead_locally(lead)}, context=context)

    async def search_leads(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        delegated = await self._try_component_call(
            self.lead_tracker,
            ["search_leads", "search"],
            context=context,
            payload=dict(payload),
        )
        if delegated:
            return delegated

        limit, offset = self._pagination(payload)
        records, total = self.store.search(
            context=context,
            record_type="lead",
            query=safe_str(payload.get("query")) if payload.get("query") else None,
            filters=ensure_mapping(payload.get("filters")),
            limit=limit,
            offset=offset,
        )
        return self._safe_result(
            "Leads searched.",
            {
                "leads": [record.to_dict() for record in records],
                "pagination": {"limit": limit, "offset": offset, "total": total},
            },
            context=context,
        )

    async def convert_lead_to_client(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        lead_id = safe_str(payload.get("lead_id") or payload.get("id"))
        if not lead_id:
            return self._error_result("lead_id is required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.lead_tracker,
            ["convert_to_client", "convert_lead_to_client"],
            context=context,
            payload={"lead_id": lead_id, **dict(payload)},
        )
        if delegated:
            return delegated

        lead_record = self.store.get(context=context, record_id=lead_id)
        if not lead_record:
            return self._error_result("Lead not found in this workspace.", "NOT_FOUND", context=context)

        client_payload = dict(lead_record.payload)
        client_payload.update(
            {
                "source_lead_id": lead_id,
                "client_status": "active",
                "converted_at": utc_now_iso(),
            }
        )
        client_record = self.store.create(context=context, record_type="client", payload=client_payload)
        self.store.update(context=context, record_id=lead_id, updates={"status": "converted", "client_id": client_record.id})
        return self._safe_result(
            "Lead converted to client.",
            {"lead_id": lead_id, "client": client_record.to_dict()},
            context=context,
        )

    # ==================================================================================
    # Client methods
    # ==================================================================================

    async def create_client(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        client = ensure_mapping(payload.get("client") or payload.get("data") or payload)
        if not client:
            return self._error_result("Client data is required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.client_manager,
            ["create_client", "create"],
            context=context,
            payload={"client": client},
        )
        if delegated:
            return delegated

        record = self.store.create(context=context, record_type="client", payload=client)
        return self._safe_result("Client created.", {"client": record.to_dict()}, context=context)

    async def update_client(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        client_id = safe_str(payload.get("client_id") or payload.get("record_id") or payload.get("id"))
        updates = ensure_mapping(payload.get("updates") or payload.get("client") or payload.get("data"))
        if not client_id or not updates:
            return self._error_result("client_id and updates are required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.client_manager,
            ["update_client", "update"],
            context=context,
            payload={"client_id": client_id, "updates": updates},
        )
        if delegated:
            return delegated

        record = self.store.update(context=context, record_id=client_id, updates=updates)
        if not record:
            return self._error_result("Client not found in this workspace.", "NOT_FOUND", context=context)
        return self._safe_result("Client updated.", {"client": record.to_dict()}, context=context)

    async def get_client(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        client_id = safe_str(payload.get("client_id") or payload.get("record_id") or payload.get("id"))
        if not client_id:
            return self._error_result("client_id is required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.client_manager,
            ["get_client", "get"],
            context=context,
            payload={"client_id": client_id},
        )
        if delegated:
            return delegated

        record = self.store.get(context=context, record_id=client_id)
        if not record or record.record_type != "client":
            return self._error_result("Client not found in this workspace.", "NOT_FOUND", context=context)
        return self._safe_result("Client found.", {"client": record.to_dict()}, context=context)

    async def search_clients(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        delegated = await self._try_component_call(
            self.client_manager,
            ["search_clients", "search"],
            context=context,
            payload=dict(payload),
        )
        if delegated:
            return delegated

        limit, offset = self._pagination(payload)
        records, total = self.store.search(
            context=context,
            record_type="client",
            query=safe_str(payload.get("query")) if payload.get("query") else None,
            filters=ensure_mapping(payload.get("filters")),
            limit=limit,
            offset=offset,
        )
        return self._safe_result(
            "Clients searched.",
            {
                "clients": [record.to_dict() for record in records],
                "pagination": {"limit": limit, "offset": offset, "total": total},
            },
            context=context,
        )

    async def archive_client(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        client_id = safe_str(payload.get("client_id") or payload.get("record_id") or payload.get("id"))
        if not client_id:
            return self._error_result("client_id is required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.client_manager,
            ["archive_client", "archive"],
            context=context,
            payload={"client_id": client_id},
        )
        if delegated:
            return delegated

        record = self.store.archive(context=context, record_id=client_id)
        if not record or record.record_type != "client":
            return self._error_result("Client not found in this workspace.", "NOT_FOUND", context=context)
        return self._safe_result("Client archived after security approval.", {"client": record.to_dict()}, context=context)

    # ==================================================================================
    # Pipeline methods
    # ==================================================================================

    async def create_deal(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        deal = ensure_mapping(payload.get("deal") or payload.get("data") or payload)
        if not deal:
            return self._error_result("Deal data is required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.sales_pipeline,
            ["create_deal", "create"],
            context=context,
            payload={"deal": deal},
        )
        if delegated:
            return delegated

        deal.setdefault("stage", "new")
        record = self.store.create(context=context, record_type="deal", payload=deal)
        return self._safe_result("Deal created.", {"deal": record.to_dict()}, context=context)

    async def update_deal(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        deal_id = safe_str(payload.get("deal_id") or payload.get("record_id") or payload.get("id"))
        updates = ensure_mapping(payload.get("updates") or payload.get("deal") or payload.get("data"))
        if not deal_id or not updates:
            return self._error_result("deal_id and updates are required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.sales_pipeline,
            ["update_deal", "update"],
            context=context,
            payload={"deal_id": deal_id, "updates": updates},
        )
        if delegated:
            return delegated

        record = self.store.update(context=context, record_id=deal_id, updates=updates)
        if not record:
            return self._error_result("Deal not found in this workspace.", "NOT_FOUND", context=context)
        return self._safe_result("Deal updated.", {"deal": record.to_dict()}, context=context)

    async def move_deal_stage(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        deal_id = safe_str(payload.get("deal_id") or payload.get("record_id") or payload.get("id"))
        stage = safe_str(payload.get("stage") or payload.get("new_stage"))
        if not deal_id or not stage:
            return self._error_result("deal_id and stage are required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.sales_pipeline,
            ["move_stage", "move_deal_stage"],
            context=context,
            payload={"deal_id": deal_id, "stage": stage},
        )
        if delegated:
            return delegated

        record = self.store.update(
            context=context,
            record_id=deal_id,
            updates={"stage": stage, "stage_updated_at": utc_now_iso()},
        )
        if not record:
            return self._error_result("Deal not found in this workspace.", "NOT_FOUND", context=context)
        return self._safe_result("Deal moved to new stage.", {"deal": record.to_dict()}, context=context)

    async def get_deals(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        delegated = await self._try_component_call(
            self.sales_pipeline,
            ["get_deals", "search_deals", "search"],
            context=context,
            payload=dict(payload),
        )
        if delegated:
            return delegated

        limit, offset = self._pagination(payload)
        records, total = self.store.search(
            context=context,
            record_type="deal",
            query=safe_str(payload.get("query")) if payload.get("query") else None,
            filters=ensure_mapping(payload.get("filters")),
            limit=limit,
            offset=offset,
        )
        return self._safe_result(
            "Deals retrieved.",
            {
                "deals": [record.to_dict() for record in records],
                "pagination": {"limit": limit, "offset": offset, "total": total},
            },
            context=context,
        )

    # ==================================================================================
    # Campaign methods
    # ==================================================================================

    async def create_campaign(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        campaign = ensure_mapping(payload.get("campaign") or payload.get("data") or payload)
        if not campaign:
            return self._error_result("Campaign data is required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.campaign_tracker,
            ["create_campaign", "create"],
            context=context,
            payload={"campaign": campaign},
        )
        if delegated:
            return delegated

        record = self.store.create(context=context, record_type="campaign", payload=campaign)
        return self._safe_result("Campaign created.", {"campaign": record.to_dict()}, context=context)

    async def update_campaign(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        campaign_id = safe_str(payload.get("campaign_id") or payload.get("record_id") or payload.get("id"))
        updates = ensure_mapping(payload.get("updates") or payload.get("campaign") or payload.get("data"))
        if not campaign_id or not updates:
            return self._error_result("campaign_id and updates are required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.campaign_tracker,
            ["update_campaign", "update"],
            context=context,
            payload={"campaign_id": campaign_id, "updates": updates},
        )
        if delegated:
            return delegated

        record = self.store.update(context=context, record_id=campaign_id, updates=updates)
        if not record:
            return self._error_result("Campaign not found in this workspace.", "NOT_FOUND", context=context)
        return self._safe_result("Campaign updated.", {"campaign": record.to_dict()}, context=context)

    async def get_campaign_performance(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        delegated = await self._try_component_call(
            self.campaign_tracker,
            ["get_performance", "campaign_performance", "performance"],
            context=context,
            payload=dict(payload),
        )
        if delegated:
            return delegated

        records, total = self.store.search(
            context=context,
            record_type="campaign",
            filters=ensure_mapping(payload.get("filters")),
            limit=getattr(self.config, "max_page_size", 100),
            offset=0,
        )
        campaigns = [record.payload for record in records]
        summary = self._calculate_campaign_summary(campaigns)
        return self._safe_result(
            "Campaign performance calculated.",
            {"summary": summary, "campaign_count": total},
            context=context,
        )

    # ==================================================================================
    # Revenue methods
    # ==================================================================================

    async def record_revenue(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        revenue = ensure_mapping(payload.get("revenue") or payload.get("data") or payload)
        amount = revenue.get("amount")
        try:
            amount_float = float(amount)
        except Exception:
            return self._error_result("Valid revenue amount is required.", "VALIDATION_ERROR", context=context)

        revenue["amount"] = amount_float
        revenue.setdefault("recorded_at", utc_now_iso())

        delegated = await self._try_component_call(
            self.revenue_tracker,
            ["record_revenue", "record", "create"],
            context=context,
            payload={"revenue": revenue},
        )
        if delegated:
            return delegated

        record = self.store.create(context=context, record_type="revenue", payload=revenue)
        return self._safe_result("Revenue recorded after security approval.", {"revenue": record.to_dict()}, context=context)

    async def get_revenue_summary(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        delegated = await self._try_component_call(
            self.revenue_tracker,
            ["get_summary", "revenue_summary", "summary"],
            context=context,
            payload=dict(payload),
        )
        if delegated:
            return delegated

        records, total = self.store.search(
            context=context,
            record_type="revenue",
            filters=ensure_mapping(payload.get("filters")),
            limit=getattr(self.config, "max_page_size", 100),
            offset=0,
        )
        amounts = [float(record.payload.get("amount", 0) or 0) for record in records]
        summary = {
            "total_revenue": round(sum(amounts), 2),
            "record_count": total,
            "average_revenue": round(sum(amounts) / len(amounts), 2) if amounts else 0.0,
            "currency": payload.get("currency") or "USD",
        }
        return self._safe_result("Revenue summary prepared after security approval.", {"summary": summary}, context=context)

    async def get_revenue_forecast(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        delegated = await self._try_component_call(
            self.revenue_tracker,
            ["forecast", "get_forecast", "revenue_forecast"],
            context=context,
            payload=dict(payload),
        )
        if delegated:
            return delegated

        summary_result = await self.get_revenue_summary(context=context, payload=payload)
        total = float(summary_result.get("data", {}).get("summary", {}).get("total_revenue", 0.0))
        months = clamp_int(payload.get("months"), 1, 24, 3)
        conservative_growth = float(payload.get("conservative_growth_rate", 0.05))
        forecast = []
        running = total
        for month in range(1, months + 1):
            running = running * (1 + conservative_growth)
            forecast.append(
                {
                    "month_index": month,
                    "forecast_revenue": round(running, 2),
                    "growth_rate": conservative_growth,
                }
            )
        return self._safe_result(
            "Revenue forecast prepared after security approval.",
            {"forecast": forecast, "basis_total_revenue": total},
            context=context,
        )

    # ==================================================================================
    # Analytics methods
    # ==================================================================================

    async def get_analytics_summary(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        delegated = await self._try_component_call(
            self.analytics_engine,
            ["summary", "get_summary", "analytics_summary"],
            context=context,
            payload=dict(payload),
        )
        if delegated:
            return delegated

        lead_records, lead_total = self.store.search(context=context, record_type="lead", limit=100, offset=0)
        client_records, client_total = self.store.search(context=context, record_type="client", limit=100, offset=0)
        deal_records, deal_total = self.store.search(context=context, record_type="deal", limit=100, offset=0)
        campaign_records, campaign_total = self.store.search(context=context, record_type="campaign", limit=100, offset=0)
        revenue_records, revenue_total = self.store.search(context=context, record_type="revenue", limit=100, offset=0)

        revenue_sum = sum(float(record.payload.get("amount", 0) or 0) for record in revenue_records)
        converted_leads = sum(1 for record in lead_records if record.payload.get("status") == "converted")
        conversion_rate = round((converted_leads / lead_total) * 100, 2) if lead_total else 0.0

        summary = {
            "lead_count": lead_total,
            "client_count": client_total,
            "deal_count": deal_total,
            "campaign_count": campaign_total,
            "revenue_record_count": revenue_total,
            "total_revenue": round(revenue_sum, 2),
            "lead_to_client_conversion_rate": conversion_rate,
            "generated_at": utc_now_iso(),
        }
        return self._safe_result("Business analytics summary prepared.", {"summary": summary}, context=context)

    async def get_dashboard_analytics(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        delegated = await self._try_component_call(
            self.analytics_engine,
            ["dashboard", "get_dashboard", "dashboard_analytics"],
            context=context,
            payload=dict(payload),
        )
        if delegated:
            return delegated

        summary_result = await self.get_analytics_summary(context=context, payload=payload)
        summary = summary_result.get("data", {}).get("summary", {})
        dashboard = {
            "cards": [
                {"label": "Leads", "value": summary.get("lead_count", 0)},
                {"label": "Clients", "value": summary.get("client_count", 0)},
                {"label": "Deals", "value": summary.get("deal_count", 0)},
                {"label": "Revenue", "value": summary.get("total_revenue", 0)},
            ],
            "charts": {
                "funnel": {
                    "leads": summary.get("lead_count", 0),
                    "clients": summary.get("client_count", 0),
                    "deals": summary.get("deal_count", 0),
                },
                "conversion_rate": summary.get("lead_to_client_conversion_rate", 0.0),
            },
            "generated_at": utc_now_iso(),
        }
        return self._safe_result("Dashboard analytics prepared.", {"dashboard": dashboard}, context=context)

    async def get_funnel_analytics(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        delegated = await self._try_component_call(
            self.analytics_engine,
            ["funnel", "get_funnel", "funnel_analytics"],
            context=context,
            payload=dict(payload),
        )
        if delegated:
            return delegated

        summary_result = await self.get_analytics_summary(context=context, payload=payload)
        summary = summary_result.get("data", {}).get("summary", {})
        funnel = [
            {"stage": "leads", "count": summary.get("lead_count", 0)},
            {"stage": "qualified", "count": self._count_local_records(context, "lead", {"qualified": True})},
            {"stage": "clients", "count": summary.get("client_count", 0)},
            {"stage": "deals", "count": summary.get("deal_count", 0)},
        ]
        return self._safe_result("Funnel analytics prepared.", {"funnel": funnel}, context=context)

    # ==================================================================================
    # Reports
    # ==================================================================================

    async def build_report(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        report_type = safe_str(payload.get("report_type"), "business_summary")
        delegated = await self._try_component_call(
            self.report_builder,
            ["build_report", "build", "create_report"],
            context=context,
            payload=dict(payload),
        )
        if delegated:
            return delegated

        analytics = await self.get_analytics_summary(context=context, payload=payload)
        report = {
            "report_id": str(uuid.uuid4()),
            "report_type": report_type,
            "title": payload.get("title") or "Business Summary Report",
            "workspace_id": context.workspace_id,
            "generated_for_user_id": context.user_id,
            "generated_at": utc_now_iso(),
            "sections": [
                {
                    "name": "Executive Summary",
                    "data": analytics.get("data", {}).get("summary", {}),
                },
                {
                    "name": "Notes",
                    "data": {
                        "message": "Fallback report generated by BusinessAgent. Dedicated report_builder.py can enhance formatting later."
                    },
                },
            ],
            "export_ready": False,
        }
        return self._safe_result("Business report built.", {"report": report}, context=context)

    async def export_report(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Prepares export metadata only.

        This method does not write files or send reports directly. Actual file generation,
        email sending, drive upload, or destructive export behavior must be handled by
        dedicated agents/services with Security Agent approval.
        """
        delegated = await self._try_component_call(
            self.report_builder,
            ["export_report", "export"],
            context=context,
            payload=dict(payload),
        )
        if delegated:
            return delegated

        report = ensure_mapping(payload.get("report"))
        if not report:
            build_result = await self.build_report(context=context, payload=payload)
            report = ensure_mapping(build_result.get("data", {}).get("report"))

        export_format = safe_str(payload.get("format"), "json").lower()
        if export_format not in {"json", "csv", "pdf", "xlsx"}:
            return self._error_result("Unsupported export format.", "VALIDATION_ERROR", context=context)

        export_payload = {
            "export_id": str(uuid.uuid4()),
            "report_id": report.get("report_id"),
            "format": export_format,
            "status": "prepared",
            "requires_downstream_export_service": True,
            "prepared_at": utc_now_iso(),
        }
        return self._safe_result(
            "Report export prepared after security approval.",
            {"export": export_payload, "report": report},
            context=context,
        )

    # ==================================================================================
    # Business tasks
    # ==================================================================================

    async def create_business_task(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        task_data = ensure_mapping(payload.get("task") or payload.get("data") or payload)
        if not task_data:
            return self._error_result("Business task data is required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.task_manager,
            ["create_task", "create_business_task", "create"],
            context=context,
            payload={"task": task_data},
        )
        if delegated:
            return delegated

        task_data.setdefault("status", "open")
        record = self.store.create(context=context, record_type="business_task", payload=task_data)
        return self._safe_result("Business task created.", {"task": record.to_dict()}, context=context)

    async def update_business_task(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        task_id = safe_str(payload.get("task_id") or payload.get("record_id") or payload.get("id"))
        updates = ensure_mapping(payload.get("updates") or payload.get("task") or payload.get("data"))
        if not task_id or not updates:
            return self._error_result("task_id and updates are required.", "VALIDATION_ERROR", context=context)

        delegated = await self._try_component_call(
            self.task_manager,
            ["update_task", "update_business_task", "update"],
            context=context,
            payload={"task_id": task_id, "updates": updates},
        )
        if delegated:
            return delegated

        record = self.store.update(context=context, record_id=task_id, updates=updates)
        if not record:
            return self._error_result("Business task not found in this workspace.", "NOT_FOUND", context=context)
        return self._safe_result("Business task updated.", {"task": record.to_dict()}, context=context)

    async def search_business_tasks(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        delegated = await self._try_component_call(
            self.task_manager,
            ["search_tasks", "search_business_tasks", "search"],
            context=context,
            payload=dict(payload),
        )
        if delegated:
            return delegated

        limit, offset = self._pagination(payload)
        records, total = self.store.search(
            context=context,
            record_type="business_task",
            query=safe_str(payload.get("query")) if payload.get("query") else None,
            filters=ensure_mapping(payload.get("filters")),
            limit=limit,
            offset=offset,
        )
        return self._safe_result(
            "Business tasks searched.",
            {
                "tasks": [record.to_dict() for record in records],
                "pagination": {"limit": limit, "offset": offset, "total": total},
            },
            context=context,
        )

    # ==================================================================================
    # Smart business routing
    # ==================================================================================

    async def route_business_task(self, *, context: TaskContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Lightweight task router for business-domain requests.

        The Master Agent can either call specific actions directly or send a vague
        business task here. This method infers the best supported action without
        executing sensitive side effects directly.
        """
        intent = safe_str(payload.get("intent") or payload.get("goal") or payload.get("query")).lower()
        target_action: BusinessAction

        if "lead" in intent and ("qualify" in intent or "score" in intent):
            target_action = BusinessAction.LEAD_QUALIFY
        elif "lead" in intent and ("search" in intent or "find" in intent):
            target_action = BusinessAction.LEAD_SEARCH
        elif "lead" in intent:
            target_action = BusinessAction.LEAD_CREATE
        elif "client" in intent and ("search" in intent or "find" in intent):
            target_action = BusinessAction.CLIENT_SEARCH
        elif "client" in intent:
            target_action = BusinessAction.CLIENT_CREATE
        elif "report" in intent and "export" in intent:
            target_action = BusinessAction.REPORT_EXPORT
        elif "report" in intent:
            target_action = BusinessAction.REPORT_BUILD
        elif "revenue" in intent and "forecast" in intent:
            target_action = BusinessAction.REVENUE_FORECAST
        elif "revenue" in intent:
            target_action = BusinessAction.REVENUE_SUMMARY
        elif "analytics" in intent or "dashboard" in intent:
            target_action = BusinessAction.ANALYTICS_DASHBOARD
        elif "deal" in intent or "pipeline" in intent:
            target_action = BusinessAction.PIPELINE_GET_DEALS
        elif "campaign" in intent:
            target_action = BusinessAction.CAMPAIGN_PERFORMANCE
        else:
            target_action = BusinessAction.ANALYTICS_SUMMARY

        handler = self._action_handlers[target_action]
        result = await handler(context=context, payload=payload)
        metadata = ensure_mapping(result.get("metadata"))
        metadata["routed_from"] = BusinessAction.ROUTE_BUSINESS_TASK.value
        metadata["routed_to"] = target_action.value
        result["metadata"] = metadata
        return result

    # ==================================================================================
    # Required compatibility hooks
    # ==================================================================================

    def _validate_task_context(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validates SaaS tenant context.

        Required by project rules:
            - Every user-specific execution must include user_id and workspace_id.
            - Never mix data between users/workspaces.
        """
        user_id = safe_str(task.get("user_id") or task.get("userId"))
        workspace_id = safe_str(task.get("workspace_id") or task.get("workspaceId"))

        payload = ensure_mapping(task.get("payload"))
        if not user_id:
            user_id = safe_str(payload.get("user_id") or payload.get("userId"))
        if not workspace_id:
            workspace_id = safe_str(payload.get("workspace_id") or payload.get("workspaceId"))

        if not user_id or not workspace_id:
            return self._error_result(
                message="user_id and workspace_id are required for BusinessAgent tasks.",
                error_code="MISSING_TENANT_CONTEXT",
                details={
                    "has_user_id": bool(user_id),
                    "has_workspace_id": bool(workspace_id),
                },
            )

        context = TaskContext(
            user_id=user_id,
            workspace_id=workspace_id,
            role=safe_str(task.get("role") or payload.get("role")) or None,
            subscription_plan=safe_str(task.get("subscription_plan") or payload.get("subscription_plan")) or None,
            request_id=safe_str(task.get("request_id") or payload.get("request_id")) or str(uuid.uuid4()),
            session_id=safe_str(task.get("session_id") or payload.get("session_id")) or None,
            source=safe_str(task.get("source"), "business_agent"),
            metadata=ensure_mapping(task.get("metadata")),
        )
        return self._safe_result("Task context validated.", {"context": context})

    def _requires_security_check(
        self,
        *,
        action: Union[BusinessAction, str],
        payload: Optional[Mapping[str, Any]] = None,
        context: Optional[TaskContext] = None,
    ) -> bool:
        """
        Decides if Security Agent approval is required.

        Sensitive examples:
            - Deleting CRM records
            - Archiving clients
            - Revenue actions
            - Report exports
            - Bulk updates/exports
        """
        normalized = normalize_action(action)
        payload = ensure_mapping(payload)

        if not normalized:
            return True

        if normalized in SENSITIVE_ACTIONS:
            return True

        if normalized == BusinessAction.REPORT_EXPORT and getattr(self.config, "require_security_for_exports", True):
            return True

        if normalized == BusinessAction.CRM_DELETE_RECORD and getattr(self.config, "require_security_for_deletes", True):
            return True

        if normalized.value.startswith("revenue_") and getattr(self.config, "require_security_for_revenue", True):
            return True

        if payload.get("bulk") and getattr(self.config, "require_security_for_bulk_updates", True):
            return True

        if payload.get("contains_sensitive_data") is True:
            return True

        return False

    async def _request_security_approval(
        self,
        *,
        action: Union[BusinessAction, str],
        payload: Optional[Mapping[str, Any]] = None,
        context: Optional[TaskContext] = None,
    ) -> Dict[str, Any]:
        """
        Requests Security Agent approval.

        Fallback behavior:
            - If no Security Agent is connected, safe non-destructive tasks proceed.
            - Sensitive tasks fail closed unless payload includes an explicit test-mode
              permission override approved by the caller.
        """
        normalized = normalize_action(action)
        payload_dict = ensure_mapping(payload)

        security_payload = {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": normalized.value if normalized else str(action),
            "user_id": context.user_id if context else None,
            "workspace_id": context.workspace_id if context else None,
            "request_id": context.request_id if context else None,
            "payload_summary": self._summarize_payload(payload_dict),
            "requested_at": utc_now_iso(),
        }

        if self.security_agent is not None:
            for method_name in ("approve_action", "check_permission", "authorize", "request_approval"):
                method = getattr(self.security_agent, method_name, None)
                if callable(method):
                    try:
                        response = await maybe_await(method(security_payload))
                        if isinstance(response, Mapping):
                            approved = bool(response.get("success", response.get("approved", False)))
                            return {
                                "success": approved,
                                "message": response.get("message") or ("Approved." if approved else "Denied."),
                                "data": dict(response),
                                "error": None if approved else response.get("error", "SECURITY_DENIED"),
                                "metadata": {"security_method": method_name},
                            }
                    except Exception as exc:
                        return self._error_result(
                            "Security Agent approval failed.",
                            "SECURITY_AGENT_ERROR",
                            {"exception": str(exc)},
                            context=context,
                        )

        if payload_dict.get("security_approved") is True and payload_dict.get("test_mode") is True:
            return self._safe_result(
                "Security approval accepted from explicit test-mode override.",
                {"approval": security_payload},
                context=context,
            )

        if normalized and normalized not in SENSITIVE_ACTIONS:
            return self._safe_result(
                "Security approval not required for this non-sensitive action.",
                {"approval": security_payload},
                context=context,
            )

        return self._error_result(
            "Security Agent is not connected for sensitive action.",
            "SECURITY_AGENT_UNAVAILABLE",
            {"approval_request": security_payload},
            context=context,
        )

    def _prepare_verification_payload(
        self,
        *,
        action: Union[BusinessAction, str],
        context: TaskContext,
        result: Mapping[str, Any],
        started_at: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Prepares Verification Agent payload after completed action.
        """
        normalized = normalize_action(action)
        duration_ms = round((time.time() - started_at) * 1000, 2) if started_at else None
        return {
            "verification_type": "business_action_result",
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": normalized.value if normalized else str(action),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "success": bool(result.get("success")),
            "message": result.get("message"),
            "result_keys": list(ensure_mapping(result.get("data")).keys()),
            "duration_ms": duration_ms,
            "created_at": utc_now_iso(),
            "checks": {
                "tenant_context_present": bool(context.user_id and context.workspace_id),
                "structured_result": all(key in result for key in ("success", "message", "data", "error", "metadata")),
                "no_cross_workspace_data_claimed": True,
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        action: Union[BusinessAction, str],
        context: TaskContext,
        result: Mapping[str, Any],
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepares useful business context for Memory Agent.

        This does not directly store secrets or raw sensitive payloads. It creates
        a compact memory event that a dedicated Memory Agent can accept/reject.
        """
        normalized = normalize_action(action)
        payload = ensure_mapping(payload)
        data = ensure_mapping(result.get("data"))

        memory_event = {
            "memory_type": "business_context",
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": normalized.value if normalized else str(action),
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "summary": result.get("message"),
            "created_at": utc_now_iso(),
            "safe_context": {
                "result_success": bool(result.get("success")),
                "data_keys": list(data.keys()),
                "payload_keys": list(payload.keys()),
            },
            "retention_hint": "workspace_business_history",
        }

        if normalized in {
            BusinessAction.LEAD_CREATE,
            BusinessAction.LEAD_QUALIFY,
            BusinessAction.LEAD_CONVERT_TO_CLIENT,
            BusinessAction.CLIENT_CREATE,
            BusinessAction.REPORT_BUILD,
            BusinessAction.ANALYTICS_SUMMARY,
        }:
            memory_event["importance"] = "medium"
        else:
            memory_event["importance"] = "low"

        return memory_event

    async def _emit_agent_event(
        self,
        event_name: str,
        *,
        context: Optional[TaskContext] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emits dashboard/API/event-bus compatible events.

        This method fails softly because business task success must not depend on
        dashboard telemetry availability.
        """
        if not getattr(self.config, "dashboard_events_enabled", True):
            return

        event = {
            "event_id": str(uuid.uuid4()),
            "event_name": event_name,
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "user_id": context.user_id if context else None,
            "workspace_id": context.workspace_id if context else None,
            "request_id": context.request_id if context else None,
            "data": dict(data or {}),
            "created_at": utc_now_iso(),
        }

        try:
            if self.event_bus is not None:
                for method_name in ("emit", "publish", "send", "dispatch"):
                    method = getattr(self.event_bus, method_name, None)
                    if callable(method):
                        await maybe_await(method(event_name, event))
                        return
            self.logger.debug("BusinessAgent event: %s", event)
        except Exception as exc:
            self.logger.warning("Failed to emit BusinessAgent event %s: %s", event_name, exc)

    async def _log_audit_event(
        self,
        action: str,
        *,
        context: Optional[TaskContext] = None,
        success: bool,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Logs audit events without mixing tenant data.
        """
        if not getattr(self.config, "audit_enabled", True):
            return

        event = {
            "audit_id": str(uuid.uuid4()),
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "action": action,
            "user_id": context.user_id if context else None,
            "workspace_id": context.workspace_id if context else None,
            "request_id": context.request_id if context else None,
            "success": success,
            "data": dict(data or {}),
            "created_at": utc_now_iso(),
        }

        try:
            if self.audit_logger is not None:
                for method_name in ("log", "write", "record", "audit"):
                    method = getattr(self.audit_logger, method_name, None)
                    if callable(method):
                        await maybe_await(method(event))
                        return
            self.logger.info("Business audit event: %s", event)
        except Exception as exc:
            self.logger.warning("Failed to write audit event: %s", exc)

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        *,
        context: Optional[TaskContext] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured success result.
        """
        result_metadata = {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "version": self.version,
            "timestamp": utc_now_iso(),
        }
        if context:
            result_metadata.update(
                {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                }
            )
        result_metadata.update(dict(metadata or {}))

        return {
            "success": True,
            "message": message,
            "data": dict(data or {}),
            "error": None,
            "metadata": result_metadata,
        }

    def _error_result(
        self,
        message: str,
        error_code: str,
        details: Optional[Mapping[str, Any]] = None,
        *,
        context: Optional[TaskContext] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Standard William/Jarvis structured error result.
        """
        result_metadata = {
            "agent": self.agent_name,
            "agent_id": self.agent_id,
            "version": self.version,
            "timestamp": utc_now_iso(),
        }
        if context:
            result_metadata.update(
                {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "request_id": context.request_id,
                }
            )
        result_metadata.update(dict(metadata or {}))

        return {
            "success": False,
            "message": message,
            "data": {},
            "error": {
                "code": error_code,
                "message": message,
                "details": dict(details or {}),
            },
            "metadata": result_metadata,
        }

    # ==================================================================================
    # Internal component helpers
    # ==================================================================================

    def _build_optional_component(self, component_cls: Optional[Any]) -> Optional[Any]:
        if component_cls is None:
            return None
        try:
            return component_cls()
        except TypeError:
            try:
                return component_cls(config=self.config)
            except Exception:
                return None
        except Exception:
            return None

    async def _try_component_call(
        self,
        component: Optional[Any],
        method_names: Sequence[str],
        *,
        context: TaskContext,
        payload: Mapping[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Attempts to delegate to dedicated business submodules when available.

        Compatible method shapes:
            method(context=context, payload=payload)
            method(user_id=..., workspace_id=..., **payload)
            method(payload)
        """
        if component is None:
            return None

        for method_name in method_names:
            method = getattr(component, method_name, None)
            if not callable(method):
                continue

            try:
                try:
                    response = await maybe_await(method(context=context, payload=dict(payload)))
                except TypeError:
                    try:
                        response = await maybe_await(
                            method(
                                user_id=context.user_id,
                                workspace_id=context.workspace_id,
                                **dict(payload),
                            )
                        )
                    except TypeError:
                        response = await maybe_await(method(dict(payload)))

                if isinstance(response, Mapping):
                    normalized = dict(response)
                    if all(key in normalized for key in ("success", "message", "data", "error", "metadata")):
                        return normalized
                    return self._safe_result(
                        message=normalized.get("message", f"Delegated to {component.__class__.__name__}.{method_name}."),
                        data=ensure_mapping(normalized.get("data"), default=normalized),
                        context=context,
                        metadata={"delegated_component": component.__class__.__name__, "delegated_method": method_name},
                    )

                return self._safe_result(
                    message=f"Delegated to {component.__class__.__name__}.{method_name}.",
                    data={"response": response},
                    context=context,
                    metadata={"delegated_component": component.__class__.__name__, "delegated_method": method_name},
                )
            except NotImplementedError:
                continue
            except Exception as exc:
                return self._error_result(
                    message=f"Delegated component {component.__class__.__name__}.{method_name} failed.",
                    error_code="COMPONENT_DELEGATION_ERROR",
                    details={"exception": str(exc)},
                    context=context,
                )

        return None

    async def _send_to_memory_agent(self, memory_payload: Mapping[str, Any]) -> None:
        if not memory_payload:
            return

        targets = [self.business_memory, self.memory_agent]
        for target in targets:
            if target is None:
                continue
            for method_name in ("store", "remember", "save_memory", "add_memory", "handle_memory"):
                method = getattr(target, method_name, None)
                if callable(method):
                    try:
                        await maybe_await(method(dict(memory_payload)))
                        return
                    except Exception as exc:
                        self.logger.warning("Failed to send memory payload via %s: %s", method_name, exc)

    async def _send_to_verification_agent(self, verification_payload: Mapping[str, Any]) -> None:
        if not verification_payload or self.verification_agent is None:
            return

        for method_name in ("verify", "submit", "record", "prepare_verification", "handle_verification"):
            method = getattr(self.verification_agent, method_name, None)
            if callable(method):
                try:
                    await maybe_await(method(dict(verification_payload)))
                    return
                except Exception as exc:
                    self.logger.warning("Failed to send verification payload via %s: %s", method_name, exc)

    # ==================================================================================
    # Local business calculations
    # ==================================================================================

    def _normalize_lead(self, lead: Mapping[str, Any]) -> Dict[str, Any]:
        normalized = dict(lead)
        normalized.setdefault("status", "new")
        normalized.setdefault("created_at", utc_now_iso())
        normalized.setdefault("source", normalized.get("lead_source") or "unknown")
        if "email" in normalized and isinstance(normalized["email"], str):
            normalized["email"] = normalized["email"].strip().lower()
        if "phone" in normalized and isinstance(normalized["phone"], str):
            normalized["phone"] = normalized["phone"].strip()
        return normalized

    def _score_lead_locally(self, lead: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Simple deterministic lead scoring fallback.

        Dedicated lead_tracker.py can replace this with advanced scoring later.
        """
        score = 0
        reasons: List[str] = []

        if lead.get("company") or lead.get("business_name"):
            score += 15
            reasons.append("Business/company provided.")

        if lead.get("email"):
            score += 10
            reasons.append("Email provided.")

        if lead.get("phone"):
            score += 10
            reasons.append("Phone provided.")

        budget = lead.get("budget") or lead.get("estimated_budget")
        try:
            budget_float = float(str(budget).replace("$", "").replace(",", ""))
            if budget_float >= 1000:
                score += 25
                reasons.append("Budget indicates mature buying intent.")
            elif budget_float >= 300:
                score += 15
                reasons.append("Budget is workable.")
            elif budget_float > 0:
                score += 5
                reasons.append("Budget exists but may be low.")
        except Exception:
            pass

        urgency = safe_str(lead.get("urgency") or lead.get("timeline")).lower()
        if urgency in {"urgent", "asap", "now", "this week"}:
            score += 20
            reasons.append("High urgency.")
        elif urgency in {"this month", "soon", "2 weeks", "two weeks"}:
            score += 12
            reasons.append("Moderate urgency.")

        service = safe_str(lead.get("service") or lead.get("interest")).lower()
        high_value_terms = ("seo", "ppc", "google ads", "automation", "ai", "crm", "website", "web development")
        if any(term in service for term in high_value_terms):
            score += 15
            reasons.append("Service interest matches agency offer.")

        decision_maker = lead.get("decision_maker")
        if decision_maker is True or safe_str(decision_maker).lower() in {"yes", "owner", "founder", "ceo"}:
            score += 15
            reasons.append("Decision maker signal present.")

        score = min(100, score)
        grade = "A" if score >= 80 else "B" if score >= 60 else "C" if score >= 40 else "D"

        if not reasons:
            reasons.append("Insufficient qualification data.")

        return {
            "score": score,
            "grade": grade,
            "reasons": reasons,
        }

    @staticmethod
    def _next_action_for_score(score: int) -> str:
        if score >= 80:
            return "Book strategy call immediately."
        if score >= 60:
            return "Send offer details and request discovery call."
        if score >= 40:
            return "Nurture with proof, portfolio, and clear pricing."
        return "Collect missing qualification details before sales follow-up."

    def _calculate_campaign_summary(self, campaigns: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
        spend = 0.0
        leads = 0
        clicks = 0
        impressions = 0

        for campaign in campaigns:
            spend += self._float(campaign.get("spend"))
            leads += int(self._float(campaign.get("leads")))
            clicks += int(self._float(campaign.get("clicks")))
            impressions += int(self._float(campaign.get("impressions")))

        return {
            "total_spend": round(spend, 2),
            "total_leads": leads,
            "total_clicks": clicks,
            "total_impressions": impressions,
            "cost_per_lead": round(spend / leads, 2) if leads else 0.0,
            "click_through_rate": round((clicks / impressions) * 100, 2) if impressions else 0.0,
        }

    def _count_local_records(self, context: TaskContext, record_type: str, filters: Mapping[str, Any]) -> int:
        _, total = self.store.search(
            context=context,
            record_type=record_type,
            filters=filters,
            limit=1,
            offset=0,
        )
        return total

    @staticmethod
    def _float(value: Any) -> float:
        try:
            return float(value or 0)
        except Exception:
            return 0.0

    def _pagination(self, payload: Mapping[str, Any]) -> Tuple[int, int]:
        max_page = getattr(self.config, "max_page_size", 100)
        default_page = getattr(self.config, "default_page_size", 25)
        limit = clamp_int(payload.get("limit"), 1, max_page, default_page)
        offset = clamp_int(payload.get("offset"), 0, 10_000_000, 0)
        return limit, offset

    @staticmethod
    def _summarize_payload(payload: Mapping[str, Any]) -> Dict[str, Any]:
        sensitive_keys = {"password", "token", "secret", "api_key", "authorization", "auth"}
        summary: Dict[str, Any] = {
            "keys": list(payload.keys()),
            "size": len(str(payload)),
        }

        safe_preview: Dict[str, Any] = {}
        for key, value in payload.items():
            lower_key = str(key).lower()
            if any(sensitive in lower_key for sensitive in sensitive_keys):
                safe_preview[key] = "[REDACTED]"
            elif isinstance(value, (str, int, float, bool)) or value is None:
                safe_preview[key] = value
            elif isinstance(value, Mapping):
                safe_preview[key] = {"type": "object", "keys": list(value.keys())}
            elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
                safe_preview[key] = {"type": "list", "length": len(value)}
            else:
                safe_preview[key] = {"type": type(value).__name__}

        summary["safe_preview"] = safe_preview
        return summary


# ======================================================================================
# Module-level exports
# ======================================================================================

__all__ = [
    "BusinessAgent",
    "BusinessAgentConfig",
    "BusinessAction",
    "TaskContext",
    "BusinessRecord",
    "InMemoryBusinessStore",
]