"""
agents/super_agents/business_agent/sales_pipeline.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Purpose:
    Sales stages, follow-up tasks, hot/cold scoring, and next actions for the
    Business Agent module.

This file is designed to be:
    - Production-level and import-safe.
    - Compatible with BaseAgent, Agent Registry, Agent Loader, Agent Router,
      Master Agent routing, Security Agent, Memory Agent, Verification Agent,
      Dashboard/API, and future FastAPI integration.
    - SaaS-safe with strict user_id/workspace_id isolation.
    - Testable without requiring the rest of the William/Jarvis codebase.

Important:
    This file does NOT execute real external actions such as sending messages,
    making calls, charging customers, or mutating external CRMs. It only prepares
    safe structured payloads and local pipeline state unless external adapters
    are injected later through the constructor.
"""

from __future__ import annotations

import copy
import logging
import math
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for isolated import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        Used only when the real William/Jarvis BaseAgent is unavailable.
        Keeps this file import-safe during early development or unit testing.
        """

        agent_name: str = "base_agent"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_id = kwargs.get("agent_id", self.__class__.__name__)
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.logger = logging.getLogger(self.agent_name)


try:
    from agents.shared.types import AgentResult  # type: ignore
except Exception:  # pragma: no cover
    AgentResult = Dict[str, Any]  # type: ignore


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("william.business.sales_pipeline")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# ---------------------------------------------------------------------------
# Enums and constants
# ---------------------------------------------------------------------------

class SalesStage(str, Enum):
    """
    Default sales pipeline stages.

    These are intentionally generic so the Business Agent can serve multiple
    workspace types and later support configurable pipelines from config.py.
    """

    NEW = "new"
    CONTACTED = "contacted"
    QUALIFYING = "qualifying"
    QUALIFIED = "qualified"
    PROPOSAL = "proposal"
    NEGOTIATION = "negotiation"
    WON = "won"
    LOST = "lost"
    NURTURE = "nurture"


class LeadTemperature(str, Enum):
    """Lead temperature classification based on sales score."""

    HOT = "hot"
    WARM = "warm"
    COLD = "cold"


class FollowUpStatus(str, Enum):
    """Follow-up task status."""

    PENDING = "pending"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    OVERDUE = "overdue"


class Priority(str, Enum):
    """Task/deal priority."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class SalesEventType(str, Enum):
    """Sales pipeline event types emitted for dashboard/audit integrations."""

    DEAL_CREATED = "deal_created"
    DEAL_UPDATED = "deal_updated"
    DEAL_STAGE_CHANGED = "deal_stage_changed"
    DEAL_SCORED = "deal_scored"
    FOLLOW_UP_CREATED = "follow_up_created"
    FOLLOW_UP_UPDATED = "follow_up_updated"
    NEXT_ACTION_RECOMMENDED = "next_action_recommended"
    PIPELINE_SUMMARY_GENERATED = "pipeline_summary_generated"


DEFAULT_STAGE_ORDER: List[SalesStage] = [
    SalesStage.NEW,
    SalesStage.CONTACTED,
    SalesStage.QUALIFYING,
    SalesStage.QUALIFIED,
    SalesStage.PROPOSAL,
    SalesStage.NEGOTIATION,
    SalesStage.WON,
    SalesStage.LOST,
    SalesStage.NURTURE,
]

CLOSED_STAGES = {SalesStage.WON.value, SalesStage.LOST.value}
ACTIVE_STAGES = {
    SalesStage.NEW.value,
    SalesStage.CONTACTED.value,
    SalesStage.QUALIFYING.value,
    SalesStage.QUALIFIED.value,
    SalesStage.PROPOSAL.value,
    SalesStage.NEGOTIATION.value,
    SalesStage.NURTURE.value,
}

DEFAULT_PROBABILITY_BY_STAGE: Dict[str, float] = {
    SalesStage.NEW.value: 0.05,
    SalesStage.CONTACTED.value: 0.15,
    SalesStage.QUALIFYING.value: 0.25,
    SalesStage.QUALIFIED.value: 0.40,
    SalesStage.PROPOSAL.value: 0.60,
    SalesStage.NEGOTIATION.value: 0.75,
    SalesStage.WON.value: 1.0,
    SalesStage.LOST.value: 0.0,
    SalesStage.NURTURE.value: 0.10,
}

DEFAULT_ALLOWED_STAGE_TRANSITIONS: Dict[str, List[str]] = {
    SalesStage.NEW.value: [
        SalesStage.CONTACTED.value,
        SalesStage.QUALIFYING.value,
        SalesStage.NURTURE.value,
        SalesStage.LOST.value,
    ],
    SalesStage.CONTACTED.value: [
        SalesStage.QUALIFYING.value,
        SalesStage.QUALIFIED.value,
        SalesStage.NURTURE.value,
        SalesStage.LOST.value,
    ],
    SalesStage.QUALIFYING.value: [
        SalesStage.QUALIFIED.value,
        SalesStage.PROPOSAL.value,
        SalesStage.NURTURE.value,
        SalesStage.LOST.value,
    ],
    SalesStage.QUALIFIED.value: [
        SalesStage.PROPOSAL.value,
        SalesStage.NEGOTIATION.value,
        SalesStage.NURTURE.value,
        SalesStage.LOST.value,
    ],
    SalesStage.PROPOSAL.value: [
        SalesStage.NEGOTIATION.value,
        SalesStage.WON.value,
        SalesStage.NURTURE.value,
        SalesStage.LOST.value,
    ],
    SalesStage.NEGOTIATION.value: [
        SalesStage.WON.value,
        SalesStage.LOST.value,
        SalesStage.NURTURE.value,
        SalesStage.PROPOSAL.value,
    ],
    SalesStage.NURTURE.value: [
        SalesStage.CONTACTED.value,
        SalesStage.QUALIFYING.value,
        SalesStage.QUALIFIED.value,
        SalesStage.LOST.value,
    ],
    SalesStage.WON.value: [],
    SalesStage.LOST.value: [SalesStage.NURTURE.value],
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class SalesContext:
    """
    SaaS isolation context.

    Every user/workspace-specific operation must include this context.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    request_id: Optional[str] = None
    source: Optional[str] = None
    permissions: List[str] = field(default_factory=list)

    def key(self) -> Tuple[str, str]:
        return self.user_id, self.workspace_id


@dataclass
class FollowUpTask:
    """
    Follow-up task owned by a user/workspace.

    The Business Agent can expose this to dashboard/API. A future Task Manager
    can persist or schedule these tasks after proper Security Agent approval.
    """

    task_id: str
    user_id: str
    workspace_id: str
    deal_id: str
    title: str
    description: str = ""
    due_at: Optional[str] = None
    priority: str = Priority.MEDIUM.value
    status: str = FollowUpStatus.PENDING.value
    assigned_to: Optional[str] = None
    channel: Optional[str] = None
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())
    completed_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SalesDeal:
    """
    Sales pipeline record.

    A deal may be created from CRM Manager, Lead Tracker, Call Agent, Workflow
    Agent, imported forms, dashboard/API, or future external CRM connectors.
    """

    deal_id: str
    user_id: str
    workspace_id: str
    title: str
    contact_name: Optional[str] = None
    contact_id: Optional[str] = None
    company: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    source: Optional[str] = None
    service_interest: Optional[str] = None
    stage: str = SalesStage.NEW.value
    value: float = 0.0
    currency: str = "USD"
    probability: float = DEFAULT_PROBABILITY_BY_STAGE[SalesStage.NEW.value]
    score: int = 0
    temperature: str = LeadTemperature.COLD.value
    priority: str = Priority.MEDIUM.value
    assigned_to: Optional[str] = None
    expected_close_date: Optional[str] = None
    last_touch_at: Optional[str] = None
    next_action: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    custom_fields: Dict[str, Any] = field(default_factory=dict)
    score_breakdown: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())
    closed_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """Return current UTC time as ISO string."""
    return utc_now().isoformat()


def parse_iso_datetime(value: Optional[str]) -> Optional[datetime]:
    """Parse ISO datetime safely."""
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def clamp(value: Union[int, float], minimum: Union[int, float], maximum: Union[int, float]) -> Union[int, float]:
    """Clamp numeric value."""
    return max(minimum, min(maximum, value))


def safe_float(value: Any, default: float = 0.0) -> float:
    """Convert value to float safely."""
    try:
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def normalize_text(value: Any) -> str:
    """Normalize text for comparisons."""
    if value is None:
        return ""
    return str(value).strip().lower()


def dedupe_preserve_order(items: Iterable[Any]) -> List[Any]:
    """Deduplicate items while preserving order."""
    seen = set()
    output = []
    for item in items:
        marker = str(item).lower()
        if marker not in seen:
            seen.add(marker)
            output.append(item)
    return output


def make_id(prefix: str) -> str:
    """Create stable readable IDs for local records."""
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


def dataclass_to_dict(instance: Any) -> Dict[str, Any]:
    """Convert dataclass to dictionary with deep copy safety."""
    if hasattr(instance, "__dataclass_fields__"):
        return copy.deepcopy(asdict(instance))
    if isinstance(instance, dict):
        return copy.deepcopy(instance)
    return copy.deepcopy(getattr(instance, "__dict__", {}))


# ---------------------------------------------------------------------------
# SalesPipeline
# ---------------------------------------------------------------------------

class SalesPipeline(BaseAgent):
    """
    Business Agent sales pipeline helper.

    Responsibilities:
        - Create and update sales deals.
        - Move deals through sales stages.
        - Calculate hot/warm/cold lead score.
        - Create and manage follow-up tasks.
        - Recommend next actions.
        - Generate structured payloads for Verification Agent and Memory Agent.
        - Emit audit/event payloads for future Dashboard/API/Agent Registry.

    Integration notes:
        - Master Agent can route business.sales_pipeline tasks to public methods.
        - Security Agent is consulted through hook methods before sensitive actions.
        - Memory Agent can store approved summaries from _prepare_memory_payload().
        - Verification Agent can verify completed changes from
          _prepare_verification_payload().
        - Dashboard/API can consume _safe_result() structures.
        - Agent Registry/Loader can import this class without requiring other files.
    """

    agent_name = "business_sales_pipeline"
    agent_type = "business_agent_helper"
    public_methods = [
        "create_deal",
        "get_deal",
        "list_deals",
        "update_deal",
        "move_stage",
        "score_deal",
        "create_follow_up",
        "update_follow_up",
        "complete_follow_up",
        "list_follow_ups",
        "recommend_next_action",
        "get_pipeline_summary",
        "handle_task",
        "health_check",
    ]

    def __init__(
        self,
        *,
        security_adapter: Optional[Any] = None,
        memory_adapter: Optional[Any] = None,
        verification_adapter: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], Any]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], Any]] = None,
        storage: Optional[Dict[str, Any]] = None,
        stage_order: Optional[List[Union[str, SalesStage]]] = None,
        allowed_transitions: Optional[Dict[str, List[str]]] = None,
        logger: Optional[logging.Logger] = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.logger = logger or getattr(self, "logger", LOGGER)

        self.security_adapter = security_adapter
        self.memory_adapter = memory_adapter
        self.verification_adapter = verification_adapter
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger

        self.stage_order = [self._normalize_stage(stage) for stage in (stage_order or DEFAULT_STAGE_ORDER)]
        self.allowed_transitions = copy.deepcopy(allowed_transitions or DEFAULT_ALLOWED_STAGE_TRANSITIONS)

        # Import-safe in-memory storage. Future persistence can replace this by
        # injecting a repository adapter without changing public method contracts.
        self.storage: Dict[str, Any] = storage if storage is not None else {}
        self.storage.setdefault("deals", {})
        self.storage.setdefault("follow_ups", {})
        self.storage.setdefault("events", [])
        self.storage.setdefault("audit_logs", [])

    # ------------------------------------------------------------------
    # Required compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: Union[SalesContext, Dict[str, Any]]) -> Tuple[bool, Optional[SalesContext], Optional[str]]:
        """
        Validate SaaS user/workspace isolation context.

        Every operation that reads/writes user data must pass this check.
        """

        try:
            if isinstance(context, SalesContext):
                ctx = context
            elif isinstance(context, dict):
                ctx = SalesContext(
                    user_id=str(context.get("user_id", "")).strip(),
                    workspace_id=str(context.get("workspace_id", "")).strip(),
                    role=context.get("role"),
                    request_id=context.get("request_id"),
                    source=context.get("source"),
                    permissions=list(context.get("permissions") or []),
                )
            else:
                return False, None, "Invalid context type. Expected SalesContext or dict."

            if not ctx.user_id:
                return False, None, "Missing required user_id."
            if not ctx.workspace_id:
                return False, None, "Missing required workspace_id."

            return True, ctx, None
        except Exception as exc:
            return False, None, f"Context validation failed: {exc}"

    def _requires_security_check(self, action: str, payload: Optional[Dict[str, Any]] = None) -> bool:
        """
        Decide whether Security Agent approval is required.

        This class does not perform external destructive actions, but sensitive
        transitions and bulk operations still require protection hooks.
        """

        sensitive_actions = {
            "move_to_won",
            "move_to_lost",
            "delete_deal",
            "bulk_update",
            "export_pipeline",
            "external_sync",
            "send_follow_up",
            "assign_owner",
        }

        if action in sensitive_actions:
            return True

        payload = payload or {}
        new_stage = normalize_text(payload.get("new_stage"))
        if new_stage in {SalesStage.WON.value, SalesStage.LOST.value}:
            return True

        if payload.get("external_action") is True:
            return True

        return False

    def _request_security_approval(
        self,
        *,
        context: SalesContext,
        action: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Request/prepare Security Agent approval.

        If a real security_adapter is injected and exposes approve_action(), it
        will be used. Otherwise, this returns a safe local approval for internal
        non-external state changes only.
        """

        approval_payload = {
            "agent": self.agent_name,
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "payload": payload or {},
            "timestamp": utc_now_iso(),
        }

        try:
            if self.security_adapter and hasattr(self.security_adapter, "approve_action"):
                approval = self.security_adapter.approve_action(approval_payload)
                if isinstance(approval, dict):
                    return approval

            if payload and payload.get("external_action") is True:
                return {
                    "approved": False,
                    "reason": "External action requires real Security Agent approval.",
                    "approval_payload": approval_payload,
                }

            return {
                "approved": True,
                "reason": "Local internal pipeline update approved by fallback security policy.",
                "approval_payload": approval_payload,
            }
        except Exception as exc:
            self.logger.exception("Security approval failed")
            return {
                "approved": False,
                "reason": f"Security approval failed: {exc}",
                "approval_payload": approval_payload,
            }

    def _prepare_verification_payload(
        self,
        *,
        context: SalesContext,
        action: str,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload after completed actions.

        The payload is intentionally structured and side-effect free.
        """

        return {
            "agent": self.agent_name,
            "verification_type": "business_sales_pipeline_change",
            "action": action,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "before": before,
            "after": after,
            "metadata": metadata or {},
            "created_at": utc_now_iso(),
            "checks": {
                "context_isolated": True,
                "has_user_id": bool(context.user_id),
                "has_workspace_id": bool(context.workspace_id),
                "safe_import": True,
            },
        }

    def _prepare_memory_payload(
        self,
        *,
        context: SalesContext,
        action: str,
        entity_type: str,
        entity_id: str,
        summary: str,
        data: Optional[Dict[str, Any]] = None,
        importance: str = "normal",
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        This payload can be stored only after workspace/user-safe approval by the
        Memory Agent. This class does not write permanent memory by itself.
        """

        return {
            "agent": self.agent_name,
            "memory_type": "business_sales_pipeline",
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "summary": summary,
            "data": data or {},
            "importance": importance,
            "created_at": utc_now_iso(),
            "privacy": {
                "scope": "workspace",
                "requires_user_workspace_isolation": True,
            },
        }

    def _emit_agent_event(self, event_type: Union[str, SalesEventType], payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Emit event for Dashboard/API/Agent Registry observers.

        If no event emitter is injected, events are stored locally in memory.
        """

        event = {
            "event_id": make_id("evt"),
            "agent": self.agent_name,
            "event_type": event_type.value if isinstance(event_type, SalesEventType) else str(event_type),
            "payload": copy.deepcopy(payload),
            "created_at": utc_now_iso(),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            self.storage["events"].append(event)
            return event
        except Exception as exc:
            self.logger.exception("Failed to emit sales pipeline event")
            event["emit_error"] = str(exc)
            self.storage["events"].append(event)
            return event

    def _log_audit_event(
        self,
        *,
        context: SalesContext,
        action: str,
        entity_type: str,
        entity_id: Optional[str] = None,
        before: Optional[Dict[str, Any]] = None,
        after: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Log audit event.

        Future Audit Log service can replace local storage by injecting
        audit_logger.
        """

        audit_event = {
            "audit_id": make_id("audit"),
            "agent": self.agent_name,
            "action": action,
            "entity_type": entity_type,
            "entity_id": entity_id,
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "before": before,
            "after": after,
            "metadata": metadata or {},
            "created_at": utc_now_iso(),
        }

        try:
            if self.audit_logger:
                self.audit_logger(audit_event)
            self.storage["audit_logs"].append(audit_event)
            return audit_event
        except Exception as exc:
            self.logger.exception("Failed to write sales pipeline audit event")
            audit_event["audit_error"] = str(exc)
            self.storage["audit_logs"].append(audit_event)
            return audit_event

    def _safe_result(
        self,
        *,
        success: bool = True,
        message: str = "",
        data: Optional[Dict[str, Any]] = None,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        """Return standard William/Jarvis structured result."""
        return {
            "success": success,
            "message": message,
            "data": data or {},
            "error": error,
            "metadata": metadata or {},
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Optional[Union[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        """Return standard error result."""
        return self._safe_result(
            success=False,
            message=message,
            data={},
            error=error or message,
            metadata=metadata or {},
        )

    # ------------------------------------------------------------------
    # Public routing entrypoint
    # ------------------------------------------------------------------

    def handle_task(self, task: Dict[str, Any]) -> AgentResult:
        """
        Master Agent / Agent Router compatible task entrypoint.

        Expected task format:
            {
                "action": "create_deal" | "move_stage" | ...,
                "context": {"user_id": "...", "workspace_id": "..."},
                "payload": {...}
            }
        """

        if not isinstance(task, dict):
            return self._error_result(message="Task must be a dictionary.")

        action = str(task.get("action") or "").strip()
        context = task.get("context") or {}
        payload = task.get("payload") or {}

        if not action:
            return self._error_result(message="Missing task action.")
        if not isinstance(payload, dict):
            return self._error_result(message="Task payload must be a dictionary.")

        route_map: Dict[str, Callable[..., AgentResult]] = {
            "create_deal": self.create_deal,
            "get_deal": self.get_deal,
            "list_deals": self.list_deals,
            "update_deal": self.update_deal,
            "move_stage": self.move_stage,
            "score_deal": self.score_deal,
            "create_follow_up": self.create_follow_up,
            "update_follow_up": self.update_follow_up,
            "complete_follow_up": self.complete_follow_up,
            "list_follow_ups": self.list_follow_ups,
            "recommend_next_action": self.recommend_next_action,
            "get_pipeline_summary": self.get_pipeline_summary,
            "health_check": self.health_check,
        }

        handler = route_map.get(action)
        if not handler:
            return self._error_result(
                message=f"Unsupported SalesPipeline action: {action}",
                metadata={"supported_actions": sorted(route_map.keys())},
            )

        try:
            if action == "health_check":
                return handler()

            return handler(context=context, **payload)
        except TypeError as exc:
            return self._error_result(
                message=f"Invalid payload for action '{action}'.",
                error=str(exc),
            )
        except Exception as exc:
            self.logger.exception("SalesPipeline task failed")
            return self._error_result(
                message=f"SalesPipeline action '{action}' failed.",
                error=str(exc),
            )

    # ------------------------------------------------------------------
    # Deal methods
    # ------------------------------------------------------------------

    def create_deal(
        self,
        *,
        context: Union[SalesContext, Dict[str, Any]],
        title: str,
        contact_name: Optional[str] = None,
        contact_id: Optional[str] = None,
        company: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        source: Optional[str] = None,
        service_interest: Optional[str] = None,
        stage: Union[str, SalesStage] = SalesStage.NEW,
        value: Union[int, float, str] = 0.0,
        currency: str = "USD",
        assigned_to: Optional[str] = None,
        expected_close_date: Optional[str] = None,
        notes: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        auto_score: bool = True,
    ) -> AgentResult:
        """
        Create a new sales deal in the workspace-local pipeline.
        """

        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        if not str(title).strip():
            return self._error_result(message="Deal title is required.")

        normalized_stage = self._normalize_stage(stage)
        if normalized_stage not in self._known_stages():
            return self._error_result(
                message=f"Invalid stage '{normalized_stage}'.",
                metadata={"known_stages": self._known_stages()},
            )

        deal_id = make_id("deal")
        now = utc_now_iso()

        deal = SalesDeal(
            deal_id=deal_id,
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            title=str(title).strip(),
            contact_name=contact_name,
            contact_id=contact_id,
            company=company,
            email=email,
            phone=phone,
            source=source,
            service_interest=service_interest,
            stage=normalized_stage,
            value=max(0.0, safe_float(value)),
            currency=str(currency or "USD").upper(),
            probability=DEFAULT_PROBABILITY_BY_STAGE.get(normalized_stage, 0.0),
            assigned_to=assigned_to,
            expected_close_date=expected_close_date,
            notes=list(notes or []),
            tags=dedupe_preserve_order(tags or []),
            custom_fields=copy.deepcopy(custom_fields or {}),
            created_at=now,
            updated_at=now,
            metadata=copy.deepcopy(metadata or {}),
        )

        if auto_score:
            score, temperature, breakdown = self._calculate_score(deal)
            deal.score = score
            deal.temperature = temperature
            deal.score_breakdown = breakdown
            deal.priority = self._priority_from_score(score)

        self._save_deal(deal)
        deal_dict = dataclass_to_dict(deal)

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action="create_deal",
            before=None,
            after=deal_dict,
            metadata={"auto_score": auto_score},
        )

        memory_payload = self._prepare_memory_payload(
            context=ctx,
            action="create_deal",
            entity_type="sales_deal",
            entity_id=deal_id,
            summary=f"Created sales deal '{deal.title}' at stage '{deal.stage}'.",
            data={
                "deal_id": deal_id,
                "title": deal.title,
                "stage": deal.stage,
                "score": deal.score,
                "temperature": deal.temperature,
            },
            importance="normal" if deal.temperature != LeadTemperature.HOT.value else "high",
        )

        audit_event = self._log_audit_event(
            context=ctx,
            action="create_deal",
            entity_type="sales_deal",
            entity_id=deal_id,
            before=None,
            after=deal_dict,
        )

        agent_event = self._emit_agent_event(
            SalesEventType.DEAL_CREATED,
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "deal": deal_dict,
            },
        )

        return self._safe_result(
            message="Sales deal created successfully.",
            data={
                "deal": deal_dict,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "audit_id": audit_event.get("audit_id"),
                "event_id": agent_event.get("event_id"),
            },
        )

    def get_deal(
        self,
        *,
        context: Union[SalesContext, Dict[str, Any]],
        deal_id: str,
    ) -> AgentResult:
        """Get a single deal by ID with strict workspace isolation."""
        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        deal = self._get_deal_or_none(ctx, deal_id)
        if not deal:
            return self._error_result(message="Deal not found.", metadata={"deal_id": deal_id})

        return self._safe_result(
            message="Deal retrieved successfully.",
            data={"deal": dataclass_to_dict(deal)},
        )

    def list_deals(
        self,
        *,
        context: Union[SalesContext, Dict[str, Any]],
        stage: Optional[Union[str, SalesStage]] = None,
        temperature: Optional[Union[str, LeadTemperature]] = None,
        assigned_to: Optional[str] = None,
        source: Optional[str] = None,
        include_closed: bool = True,
        limit: int = 100,
        offset: int = 0,
        sort_by: str = "updated_at",
        sort_desc: bool = True,
    ) -> AgentResult:
        """List workspace deals with safe filters."""
        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        deals = self._list_context_deals(ctx)

        if stage:
            normalized_stage = self._normalize_stage(stage)
            deals = [deal for deal in deals if deal.stage == normalized_stage]

        if temperature:
            normalized_temp = normalize_text(temperature.value if isinstance(temperature, LeadTemperature) else temperature)
            deals = [deal for deal in deals if deal.temperature == normalized_temp]

        if assigned_to:
            deals = [deal for deal in deals if deal.assigned_to == assigned_to]

        if source:
            source_normalized = normalize_text(source)
            deals = [deal for deal in deals if normalize_text(deal.source) == source_normalized]

        if not include_closed:
            deals = [deal for deal in deals if deal.stage not in CLOSED_STAGES]

        allowed_sort = {
            "created_at",
            "updated_at",
            "score",
            "value",
            "probability",
            "expected_close_date",
            "stage",
            "temperature",
            "priority",
        }
        if sort_by not in allowed_sort:
            sort_by = "updated_at"

        deals = sorted(
            deals,
            key=lambda item: self._sort_value(item, sort_by),
            reverse=sort_desc,
        )

        safe_limit = int(clamp(limit, 1, 500))
        safe_offset = max(0, int(offset))
        sliced = deals[safe_offset:safe_offset + safe_limit]

        return self._safe_result(
            message="Deals listed successfully.",
            data={
                "deals": [dataclass_to_dict(deal) for deal in sliced],
                "total": len(deals),
                "limit": safe_limit,
                "offset": safe_offset,
            },
        )

    def update_deal(
        self,
        *,
        context: Union[SalesContext, Dict[str, Any]],
        deal_id: str,
        updates: Dict[str, Any],
        rescore: bool = True,
    ) -> AgentResult:
        """
        Update allowed deal fields.

        Stage changes should normally use move_stage(), but stage is accepted
        here and protected by transition/security checks.
        """

        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        if not isinstance(updates, dict) or not updates:
            return self._error_result(message="Updates must be a non-empty dictionary.")

        deal = self._get_deal_or_none(ctx, deal_id)
        if not deal:
            return self._error_result(message="Deal not found.", metadata={"deal_id": deal_id})

        before = dataclass_to_dict(deal)

        allowed_fields = {
            "title",
            "contact_name",
            "contact_id",
            "company",
            "email",
            "phone",
            "source",
            "service_interest",
            "value",
            "currency",
            "assigned_to",
            "expected_close_date",
            "last_touch_at",
            "next_action",
            "notes",
            "tags",
            "custom_fields",
            "metadata",
        }

        blocked = sorted(set(updates.keys()) - allowed_fields - {"stage"})
        if blocked:
            return self._error_result(
                message="One or more update fields are not allowed.",
                metadata={"blocked_fields": blocked, "allowed_fields": sorted(allowed_fields)},
            )

        if "stage" in updates:
            return self.move_stage(
                context=ctx,
                deal_id=deal_id,
                new_stage=updates["stage"],
                reason=updates.get("reason", "Stage update requested through update_deal."),
                rescore=rescore,
            )

        for field_name, value in updates.items():
            if field_name == "value":
                setattr(deal, field_name, max(0.0, safe_float(value)))
            elif field_name == "currency":
                setattr(deal, field_name, str(value or "USD").upper())
            elif field_name == "notes":
                setattr(deal, field_name, [str(item) for item in (value or [])])
            elif field_name == "tags":
                setattr(deal, field_name, dedupe_preserve_order([str(item) for item in (value or [])]))
            elif field_name in {"custom_fields", "metadata"}:
                setattr(deal, field_name, copy.deepcopy(value or {}))
            elif field_name == "title":
                if not str(value).strip():
                    return self._error_result(message="Deal title cannot be empty.")
                setattr(deal, field_name, str(value).strip())
            else:
                setattr(deal, field_name, value)

        deal.updated_at = utc_now_iso()

        if rescore:
            score, temperature, breakdown = self._calculate_score(deal)
            deal.score = score
            deal.temperature = temperature
            deal.score_breakdown = breakdown
            deal.priority = self._priority_from_score(score)

        self._save_deal(deal)
        after = dataclass_to_dict(deal)

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action="update_deal",
            before=before,
            after=after,
            metadata={"rescore": rescore},
        )

        memory_payload = self._prepare_memory_payload(
            context=ctx,
            action="update_deal",
            entity_type="sales_deal",
            entity_id=deal_id,
            summary=f"Updated sales deal '{deal.title}'.",
            data={"changed_fields": sorted(updates.keys()), "deal": after},
        )

        audit_event = self._log_audit_event(
            context=ctx,
            action="update_deal",
            entity_type="sales_deal",
            entity_id=deal_id,
            before=before,
            after=after,
        )

        agent_event = self._emit_agent_event(
            SalesEventType.DEAL_UPDATED,
            {"user_id": ctx.user_id, "workspace_id": ctx.workspace_id, "deal": after},
        )

        return self._safe_result(
            message="Deal updated successfully.",
            data={
                "deal": after,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "audit_id": audit_event.get("audit_id"),
                "event_id": agent_event.get("event_id"),
            },
        )

    def move_stage(
        self,
        *,
        context: Union[SalesContext, Dict[str, Any]],
        deal_id: str,
        new_stage: Union[str, SalesStage],
        reason: Optional[str] = None,
        force: bool = False,
        rescore: bool = True,
    ) -> AgentResult:
        """
        Move deal to a new stage with transition validation.

        Moving to WON or LOST requires Security Agent approval hook.
        """

        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        deal = self._get_deal_or_none(ctx, deal_id)
        if not deal:
            return self._error_result(message="Deal not found.", metadata={"deal_id": deal_id})

        target_stage = self._normalize_stage(new_stage)
        if target_stage not in self._known_stages():
            return self._error_result(
                message=f"Invalid target stage '{target_stage}'.",
                metadata={"known_stages": self._known_stages()},
            )

        current_stage = deal.stage
        if current_stage == target_stage:
            return self._safe_result(
                message="Deal is already in the requested stage.",
                data={"deal": dataclass_to_dict(deal)},
                metadata={"unchanged": True},
            )

        if not force and not self._is_transition_allowed(current_stage, target_stage):
            return self._error_result(
                message=f"Transition from '{current_stage}' to '{target_stage}' is not allowed.",
                metadata={
                    "current_stage": current_stage,
                    "target_stage": target_stage,
                    "allowed_next_stages": self.allowed_transitions.get(current_stage, []),
                },
            )

        security_payload = {
            "deal_id": deal_id,
            "current_stage": current_stage,
            "new_stage": target_stage,
            "reason": reason,
            "force": force,
        }

        if self._requires_security_check("move_stage", security_payload):
            approval = self._request_security_approval(
                context=ctx,
                action=f"move_to_{target_stage}",
                payload=security_payload,
            )
            if not approval.get("approved"):
                return self._error_result(
                    message="Security approval denied for stage change.",
                    error=approval.get("reason"),
                    metadata={"approval": approval},
                )

        before = dataclass_to_dict(deal)

        deal.stage = target_stage
        deal.probability = DEFAULT_PROBABILITY_BY_STAGE.get(target_stage, deal.probability)
        deal.updated_at = utc_now_iso()

        if target_stage in CLOSED_STAGES:
            deal.closed_at = utc_now_iso()
        else:
            deal.closed_at = None

        stage_note = f"Stage changed from '{current_stage}' to '{target_stage}'."
        if reason:
            stage_note = f"{stage_note} Reason: {reason}"
        deal.notes.append(stage_note)

        if rescore:
            score, temperature, breakdown = self._calculate_score(deal)
            deal.score = score
            deal.temperature = temperature
            deal.score_breakdown = breakdown
            deal.priority = self._priority_from_score(score)

        next_action = self._build_next_action(deal)
        deal.next_action = next_action.get("action")

        self._save_deal(deal)
        after = dataclass_to_dict(deal)

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action="move_stage",
            before=before,
            after=after,
            metadata={
                "from_stage": current_stage,
                "to_stage": target_stage,
                "reason": reason,
                "force": force,
            },
        )

        memory_payload = self._prepare_memory_payload(
            context=ctx,
            action="move_stage",
            entity_type="sales_deal",
            entity_id=deal_id,
            summary=f"Moved deal '{deal.title}' from '{current_stage}' to '{target_stage}'.",
            data={
                "deal_id": deal_id,
                "from_stage": current_stage,
                "to_stage": target_stage,
                "score": deal.score,
                "temperature": deal.temperature,
            },
            importance="high" if target_stage in CLOSED_STAGES else "normal",
        )

        audit_event = self._log_audit_event(
            context=ctx,
            action="move_stage",
            entity_type="sales_deal",
            entity_id=deal_id,
            before=before,
            after=after,
            metadata={"reason": reason, "force": force},
        )

        agent_event = self._emit_agent_event(
            SalesEventType.DEAL_STAGE_CHANGED,
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "deal_id": deal_id,
                "from_stage": current_stage,
                "to_stage": target_stage,
                "deal": after,
            },
        )

        return self._safe_result(
            message="Deal stage changed successfully.",
            data={
                "deal": after,
                "next_action": next_action,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "audit_id": audit_event.get("audit_id"),
                "event_id": agent_event.get("event_id"),
            },
        )

    # ------------------------------------------------------------------
    # Scoring methods
    # ------------------------------------------------------------------

    def score_deal(
        self,
        *,
        context: Union[SalesContext, Dict[str, Any]],
        deal_id: str,
        save: bool = True,
    ) -> AgentResult:
        """
        Calculate and optionally persist hot/warm/cold score for a deal.
        """

        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        deal = self._get_deal_or_none(ctx, deal_id)
        if not deal:
            return self._error_result(message="Deal not found.", metadata={"deal_id": deal_id})

        before = dataclass_to_dict(deal)
        score, temperature, breakdown = self._calculate_score(deal)

        scoring_data = {
            "deal_id": deal_id,
            "score": score,
            "temperature": temperature,
            "priority": self._priority_from_score(score),
            "breakdown": breakdown,
        }

        verification_payload = None
        memory_payload = None
        audit_event = None

        if save:
            deal.score = score
            deal.temperature = temperature
            deal.priority = self._priority_from_score(score)
            deal.score_breakdown = breakdown
            deal.updated_at = utc_now_iso()
            self._save_deal(deal)

            after = dataclass_to_dict(deal)
            verification_payload = self._prepare_verification_payload(
                context=ctx,
                action="score_deal",
                before=before,
                after=after,
                metadata={"save": save},
            )

            memory_payload = self._prepare_memory_payload(
                context=ctx,
                action="score_deal",
                entity_type="sales_deal",
                entity_id=deal_id,
                summary=f"Scored deal '{deal.title}' as {temperature} with score {score}.",
                data=scoring_data,
                importance="high" if temperature == LeadTemperature.HOT.value else "normal",
            )

            audit_event = self._log_audit_event(
                context=ctx,
                action="score_deal",
                entity_type="sales_deal",
                entity_id=deal_id,
                before=before,
                after=after,
            )

        agent_event = self._emit_agent_event(
            SalesEventType.DEAL_SCORED,
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "deal_id": deal_id,
                "scoring": scoring_data,
            },
        )

        return self._safe_result(
            message="Deal scored successfully.",
            data={
                "scoring": scoring_data,
                "deal": dataclass_to_dict(deal),
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "saved": save,
                "audit_id": audit_event.get("audit_id") if audit_event else None,
                "event_id": agent_event.get("event_id"),
            },
        )

    # ------------------------------------------------------------------
    # Follow-up methods
    # ------------------------------------------------------------------

    def create_follow_up(
        self,
        *,
        context: Union[SalesContext, Dict[str, Any]],
        deal_id: str,
        title: str,
        description: str = "",
        due_at: Optional[str] = None,
        priority: Union[str, Priority] = Priority.MEDIUM,
        assigned_to: Optional[str] = None,
        channel: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentResult:
        """
        Create a follow-up task for a deal.

        This does not send messages or create calendar tasks directly.
        Future Workflow/Task Agent can consume the returned payload.
        """

        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        deal = self._get_deal_or_none(ctx, deal_id)
        if not deal:
            return self._error_result(message="Deal not found.", metadata={"deal_id": deal_id})

        if not str(title).strip():
            return self._error_result(message="Follow-up title is required.")

        normalized_priority = self._normalize_priority(priority)
        parsed_due = parse_iso_datetime(due_at)
        if due_at and not parsed_due:
            return self._error_result(
                message="Invalid due_at datetime. Use ISO-8601 format.",
                metadata={"due_at": due_at},
            )

        task = FollowUpTask(
            task_id=make_id("followup"),
            user_id=ctx.user_id,
            workspace_id=ctx.workspace_id,
            deal_id=deal_id,
            title=str(title).strip(),
            description=str(description or ""),
            due_at=parsed_due.isoformat() if parsed_due else None,
            priority=normalized_priority,
            assigned_to=assigned_to,
            channel=channel,
            metadata=copy.deepcopy(metadata or {}),
        )

        self._save_follow_up(task)

        before_deal = dataclass_to_dict(deal)
        deal.next_action = task.title
        deal.updated_at = utc_now_iso()
        self._save_deal(deal)

        task_dict = dataclass_to_dict(task)
        deal_dict = dataclass_to_dict(deal)

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action="create_follow_up",
            before={"deal": before_deal},
            after={"deal": deal_dict, "follow_up": task_dict},
        )

        memory_payload = self._prepare_memory_payload(
            context=ctx,
            action="create_follow_up",
            entity_type="follow_up_task",
            entity_id=task.task_id,
            summary=f"Created follow-up '{task.title}' for deal '{deal.title}'.",
            data={"follow_up": task_dict, "deal_id": deal_id},
            importance="high" if normalized_priority in {Priority.HIGH.value, Priority.URGENT.value} else "normal",
        )

        audit_event = self._log_audit_event(
            context=ctx,
            action="create_follow_up",
            entity_type="follow_up_task",
            entity_id=task.task_id,
            before=None,
            after=task_dict,
            metadata={"deal_id": deal_id},
        )

        agent_event = self._emit_agent_event(
            SalesEventType.FOLLOW_UP_CREATED,
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "deal_id": deal_id,
                "follow_up": task_dict,
            },
        )

        return self._safe_result(
            message="Follow-up task created successfully.",
            data={
                "follow_up": task_dict,
                "deal": deal_dict,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "audit_id": audit_event.get("audit_id"),
                "event_id": agent_event.get("event_id"),
            },
        )

    def update_follow_up(
        self,
        *,
        context: Union[SalesContext, Dict[str, Any]],
        task_id: str,
        updates: Dict[str, Any],
    ) -> AgentResult:
        """Update a follow-up task with SaaS isolation."""
        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        task = self._get_follow_up_or_none(ctx, task_id)
        if not task:
            return self._error_result(message="Follow-up task not found.", metadata={"task_id": task_id})

        if not isinstance(updates, dict) or not updates:
            return self._error_result(message="Updates must be a non-empty dictionary.")

        allowed = {
            "title",
            "description",
            "due_at",
            "priority",
            "status",
            "assigned_to",
            "channel",
            "metadata",
        }
        blocked = sorted(set(updates.keys()) - allowed)
        if blocked:
            return self._error_result(
                message="One or more follow-up update fields are not allowed.",
                metadata={"blocked_fields": blocked, "allowed_fields": sorted(allowed)},
            )

        before = dataclass_to_dict(task)

        for field_name, value in updates.items():
            if field_name == "title":
                if not str(value).strip():
                    return self._error_result(message="Follow-up title cannot be empty.")
                task.title = str(value).strip()
            elif field_name == "due_at":
                parsed_due = parse_iso_datetime(value)
                if value and not parsed_due:
                    return self._error_result(message="Invalid due_at datetime. Use ISO-8601 format.")
                task.due_at = parsed_due.isoformat() if parsed_due else None
            elif field_name == "priority":
                task.priority = self._normalize_priority(value)
            elif field_name == "status":
                task.status = self._normalize_follow_up_status(value)
                if task.status == FollowUpStatus.COMPLETED.value and not task.completed_at:
                    task.completed_at = utc_now_iso()
            elif field_name == "metadata":
                task.metadata = copy.deepcopy(value or {})
            else:
                setattr(task, field_name, value)

        task.updated_at = utc_now_iso()
        self._save_follow_up(task)

        after = dataclass_to_dict(task)

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action="update_follow_up",
            before=before,
            after=after,
        )

        memory_payload = self._prepare_memory_payload(
            context=ctx,
            action="update_follow_up",
            entity_type="follow_up_task",
            entity_id=task_id,
            summary=f"Updated follow-up task '{task.title}'.",
            data={"changed_fields": sorted(updates.keys()), "follow_up": after},
        )

        audit_event = self._log_audit_event(
            context=ctx,
            action="update_follow_up",
            entity_type="follow_up_task",
            entity_id=task_id,
            before=before,
            after=after,
        )

        agent_event = self._emit_agent_event(
            SalesEventType.FOLLOW_UP_UPDATED,
            {"user_id": ctx.user_id, "workspace_id": ctx.workspace_id, "follow_up": after},
        )

        return self._safe_result(
            message="Follow-up task updated successfully.",
            data={
                "follow_up": after,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "audit_id": audit_event.get("audit_id"),
                "event_id": agent_event.get("event_id"),
            },
        )

    def complete_follow_up(
        self,
        *,
        context: Union[SalesContext, Dict[str, Any]],
        task_id: str,
        completion_note: Optional[str] = None,
    ) -> AgentResult:
        """Mark a follow-up task as completed."""
        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        task = self._get_follow_up_or_none(ctx, task_id)
        if not task:
            return self._error_result(message="Follow-up task not found.", metadata={"task_id": task_id})

        updates = {
            "status": FollowUpStatus.COMPLETED.value,
            "metadata": {
                **copy.deepcopy(task.metadata),
                "completion_note": completion_note,
                "completed_by_user_id": ctx.user_id,
            },
        }

        return self.update_follow_up(context=ctx, task_id=task_id, updates=updates)

    def list_follow_ups(
        self,
        *,
        context: Union[SalesContext, Dict[str, Any]],
        deal_id: Optional[str] = None,
        status: Optional[Union[str, FollowUpStatus]] = None,
        include_overdue_marking: bool = True,
        limit: int = 100,
        offset: int = 0,
    ) -> AgentResult:
        """List follow-ups for the current workspace/user."""
        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        tasks = self._list_context_follow_ups(ctx)

        if deal_id:
            tasks = [task for task in tasks if task.deal_id == deal_id]

        if include_overdue_marking:
            tasks = [self._with_overdue_status(task) for task in tasks]

        if status:
            normalized_status = self._normalize_follow_up_status(status)
            tasks = [task for task in tasks if task.status == normalized_status]

        tasks = sorted(
            tasks,
            key=lambda task: (
                parse_iso_datetime(task.due_at) or datetime.max.replace(tzinfo=timezone.utc),
                task.priority,
                task.created_at,
            ),
        )

        safe_limit = int(clamp(limit, 1, 500))
        safe_offset = max(0, int(offset))
        sliced = tasks[safe_offset:safe_offset + safe_limit]

        return self._safe_result(
            message="Follow-up tasks listed successfully.",
            data={
                "follow_ups": [dataclass_to_dict(task) for task in sliced],
                "total": len(tasks),
                "limit": safe_limit,
                "offset": safe_offset,
            },
        )

    # ------------------------------------------------------------------
    # Next action and summary methods
    # ------------------------------------------------------------------

    def recommend_next_action(
        self,
        *,
        context: Union[SalesContext, Dict[str, Any]],
        deal_id: str,
        save_to_deal: bool = False,
    ) -> AgentResult:
        """
        Recommend next action based on stage, score, follow-ups, and timeline.
        """

        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        deal = self._get_deal_or_none(ctx, deal_id)
        if not deal:
            return self._error_result(message="Deal not found.", metadata={"deal_id": deal_id})

        before = dataclass_to_dict(deal)
        recommendation = self._build_next_action(deal)

        verification_payload = None
        memory_payload = None
        audit_event = None

        if save_to_deal:
            deal.next_action = recommendation.get("action")
            deal.updated_at = utc_now_iso()
            self._save_deal(deal)
            after = dataclass_to_dict(deal)

            verification_payload = self._prepare_verification_payload(
                context=ctx,
                action="recommend_next_action",
                before=before,
                after=after,
                metadata={"saved_to_deal": True},
            )

            memory_payload = self._prepare_memory_payload(
                context=ctx,
                action="recommend_next_action",
                entity_type="sales_deal",
                entity_id=deal_id,
                summary=f"Recommended next action for deal '{deal.title}': {recommendation.get('action')}",
                data={"recommendation": recommendation},
            )

            audit_event = self._log_audit_event(
                context=ctx,
                action="recommend_next_action",
                entity_type="sales_deal",
                entity_id=deal_id,
                before=before,
                after=after,
            )

        agent_event = self._emit_agent_event(
            SalesEventType.NEXT_ACTION_RECOMMENDED,
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "deal_id": deal_id,
                "recommendation": recommendation,
            },
        )

        return self._safe_result(
            message="Next action recommended successfully.",
            data={
                "deal": dataclass_to_dict(deal),
                "recommendation": recommendation,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
            },
            metadata={
                "saved_to_deal": save_to_deal,
                "audit_id": audit_event.get("audit_id") if audit_event else None,
                "event_id": agent_event.get("event_id"),
            },
        )

    def get_pipeline_summary(
        self,
        *,
        context: Union[SalesContext, Dict[str, Any]],
        include_deals: bool = False,
        include_follow_ups: bool = False,
    ) -> AgentResult:
        """
        Generate dashboard-ready sales pipeline summary.
        """

        valid, ctx, error = self._validate_task_context(context)
        if not valid or ctx is None:
            return self._error_result(message="Invalid task context.", error=error)

        deals = self._list_context_deals(ctx)
        follow_ups = [self._with_overdue_status(task) for task in self._list_context_follow_ups(ctx)]

        by_stage: Dict[str, Dict[str, Any]] = {}
        for stage in self._known_stages():
            stage_deals = [deal for deal in deals if deal.stage == stage]
            by_stage[stage] = {
                "count": len(stage_deals),
                "total_value": round(sum(deal.value for deal in stage_deals), 2),
                "weighted_value": round(sum(deal.value * deal.probability for deal in stage_deals), 2),
                "average_score": round(
                    sum(deal.score for deal in stage_deals) / len(stage_deals), 2
                ) if stage_deals else 0,
            }

        active_deals = [deal for deal in deals if deal.stage in ACTIVE_STAGES]
        won_deals = [deal for deal in deals if deal.stage == SalesStage.WON.value]
        lost_deals = [deal for deal in deals if deal.stage == SalesStage.LOST.value]
        hot_deals = [deal for deal in deals if deal.temperature == LeadTemperature.HOT.value]
        warm_deals = [deal for deal in deals if deal.temperature == LeadTemperature.WARM.value]
        cold_deals = [deal for deal in deals if deal.temperature == LeadTemperature.COLD.value]

        pending_follow_ups = [task for task in follow_ups if task.status == FollowUpStatus.PENDING.value]
        overdue_follow_ups = [task for task in follow_ups if task.status == FollowUpStatus.OVERDUE.value]

        total_closed = len(won_deals) + len(lost_deals)
        win_rate = round((len(won_deals) / total_closed) * 100, 2) if total_closed else 0.0

        summary = {
            "user_id": ctx.user_id,
            "workspace_id": ctx.workspace_id,
            "generated_at": utc_now_iso(),
            "totals": {
                "deals": len(deals),
                "active_deals": len(active_deals),
                "won_deals": len(won_deals),
                "lost_deals": len(lost_deals),
                "pipeline_value": round(sum(deal.value for deal in active_deals), 2),
                "weighted_pipeline_value": round(sum(deal.value * deal.probability for deal in active_deals), 2),
                "won_value": round(sum(deal.value for deal in won_deals), 2),
                "win_rate_percent": win_rate,
            },
            "temperature": {
                "hot": len(hot_deals),
                "warm": len(warm_deals),
                "cold": len(cold_deals),
            },
            "follow_ups": {
                "total": len(follow_ups),
                "pending": len(pending_follow_ups),
                "overdue": len(overdue_follow_ups),
                "completed": len([task for task in follow_ups if task.status == FollowUpStatus.COMPLETED.value]),
            },
            "by_stage": by_stage,
            "top_next_actions": self._top_next_actions(active_deals),
        }

        if include_deals:
            summary["deals"] = [dataclass_to_dict(deal) for deal in active_deals]
        if include_follow_ups:
            summary["follow_up_items"] = [dataclass_to_dict(task) for task in follow_ups]

        verification_payload = self._prepare_verification_payload(
            context=ctx,
            action="get_pipeline_summary",
            before=None,
            after=summary,
        )

        self._emit_agent_event(
            SalesEventType.PIPELINE_SUMMARY_GENERATED,
            {
                "user_id": ctx.user_id,
                "workspace_id": ctx.workspace_id,
                "summary": summary,
            },
        )

        return self._safe_result(
            message="Pipeline summary generated successfully.",
            data={
                "summary": summary,
                "verification_payload": verification_payload,
            },
        )

    def health_check(self, *args: Any, **kwargs: Any) -> AgentResult:
        """Return import/runtime health info for registry/loader checks."""
        return self._safe_result(
            message="SalesPipeline is healthy.",
            data={
                "agent_name": self.agent_name,
                "agent_type": self.agent_type,
                "public_methods": self.public_methods,
                "known_stages": self._known_stages(),
                "storage_counts": {
                    "deals": len(self.storage.get("deals", {})),
                    "follow_ups": len(self.storage.get("follow_ups", {})),
                    "events": len(self.storage.get("events", [])),
                    "audit_logs": len(self.storage.get("audit_logs", [])),
                },
            },
            metadata={"timestamp": utc_now_iso()},
        )

    # ------------------------------------------------------------------
    # Internal scoring logic
    # ------------------------------------------------------------------

    def _calculate_score(self, deal: SalesDeal) -> Tuple[int, str, Dict[str, Any]]:
        """
        Calculate sales score from 0-100.

        Scoring factors:
            - Stage strength.
            - Deal value.
            - Contact completeness.
            - Recency of touch.
            - Expected close date.
            - Positive/negative tags.
            - Service intent and source quality.
        """

        breakdown: Dict[str, Any] = {}

        stage_points_map = {
            SalesStage.NEW.value: 5,
            SalesStage.CONTACTED.value: 12,
            SalesStage.QUALIFYING.value: 20,
            SalesStage.QUALIFIED.value: 30,
            SalesStage.PROPOSAL.value: 40,
            SalesStage.NEGOTIATION.value: 50,
            SalesStage.WON.value: 100,
            SalesStage.LOST.value: 0,
            SalesStage.NURTURE.value: 10,
        }
        stage_points = stage_points_map.get(deal.stage, 0)
        breakdown["stage_points"] = stage_points

        value = max(0.0, deal.value)
        if value >= 10000:
            value_points = 15
        elif value >= 5000:
            value_points = 12
        elif value >= 2000:
            value_points = 9
        elif value >= 500:
            value_points = 6
        elif value > 0:
            value_points = 3
        else:
            value_points = 0
        breakdown["value_points"] = value_points

        contact_points = 0
        contact_fields = {
            "contact_name": deal.contact_name,
            "email": deal.email,
            "phone": deal.phone,
            "company": deal.company,
        }
        for field_name, field_value in contact_fields.items():
            if str(field_value or "").strip():
                contact_points += 4
        contact_points = int(clamp(contact_points, 0, 16))
        breakdown["contact_points"] = contact_points
        breakdown["contact_fields_present"] = [
            name for name, value in contact_fields.items() if str(value or "").strip()
        ]

        last_touch = parse_iso_datetime(deal.last_touch_at)
        if last_touch:
            days_since_touch = max(0, (utc_now() - last_touch).days)
            if days_since_touch <= 1:
                recency_points = 10
            elif days_since_touch <= 3:
                recency_points = 8
            elif days_since_touch <= 7:
                recency_points = 5
            elif days_since_touch <= 14:
                recency_points = 2
            else:
                recency_points = -5
        else:
            days_since_touch = None
            recency_points = 0
        breakdown["recency_points"] = recency_points
        breakdown["days_since_last_touch"] = days_since_touch

        close_date = parse_iso_datetime(deal.expected_close_date)
        if close_date:
            days_to_close = (close_date - utc_now()).days
            if 0 <= days_to_close <= 7:
                close_points = 10
            elif 8 <= days_to_close <= 30:
                close_points = 7
            elif 31 <= days_to_close <= 90:
                close_points = 3
            elif days_to_close < 0:
                close_points = -4
            else:
                close_points = 1
        else:
            days_to_close = None
            close_points = 0
        breakdown["close_date_points"] = close_points
        breakdown["days_to_expected_close"] = days_to_close

        source_quality_map = {
            "referral": 8,
            "inbound": 7,
            "website": 6,
            "call": 5,
            "form": 5,
            "seo": 5,
            "google_ads": 4,
            "meta_ads": 4,
            "paid_ads": 4,
            "import": 2,
            "cold_call": 1,
            "cold_email": 1,
        }
        source_key = normalize_text(deal.source).replace(" ", "_").replace("-", "_")
        source_points = source_quality_map.get(source_key, 0)
        breakdown["source_points"] = source_points

        intent_points = 0
        if deal.service_interest:
            service = normalize_text(deal.service_interest)
            high_intent_terms = [
                "proposal",
                "quote",
                "pricing",
                "website",
                "seo",
                "google ads",
                "automation",
                "crm",
                "call agent",
                "ai agent",
                "ready",
            ]
            if any(term in service for term in high_intent_terms):
                intent_points = 7
            else:
                intent_points = 3
        breakdown["intent_points"] = intent_points

        tags = [normalize_text(tag) for tag in deal.tags]
        positive_tags = {
            "hot",
            "urgent",
            "decision-maker",
            "decision maker",
            "budget-approved",
            "budget approved",
            "qualified",
            "high-ticket",
            "high ticket",
            "enterprise",
            "ready-to-buy",
            "ready to buy",
        }
        negative_tags = {
            "cold",
            "low-budget",
            "low budget",
            "not-interested",
            "not interested",
            "spam",
            "student",
            "competitor",
            "wrong-number",
            "wrong number",
        }

        positive_tag_hits = [tag for tag in tags if tag in positive_tags]
        negative_tag_hits = [tag for tag in tags if tag in negative_tags]

        tag_points = min(12, len(positive_tag_hits) * 4) - min(12, len(negative_tag_hits) * 4)
        breakdown["tag_points"] = tag_points
        breakdown["positive_tag_hits"] = positive_tag_hits
        breakdown["negative_tag_hits"] = negative_tag_hits

        custom_score_adjustment = safe_float(deal.custom_fields.get("score_adjustment"), 0.0)
        custom_score_adjustment = float(clamp(custom_score_adjustment, -15, 15))
        breakdown["custom_score_adjustment"] = custom_score_adjustment

        raw_score = (
            stage_points
            + value_points
            + contact_points
            + recency_points
            + close_points
            + source_points
            + intent_points
            + tag_points
            + custom_score_adjustment
        )

        if deal.stage == SalesStage.WON.value:
            score = 100
        elif deal.stage == SalesStage.LOST.value:
            score = 0
        else:
            score = int(clamp(round(raw_score), 0, 100))

        if score >= 70:
            temperature = LeadTemperature.HOT.value
        elif score >= 40:
            temperature = LeadTemperature.WARM.value
        else:
            temperature = LeadTemperature.COLD.value

        breakdown["raw_score"] = raw_score
        breakdown["final_score"] = score
        breakdown["temperature"] = temperature

        return score, temperature, breakdown

    def _priority_from_score(self, score: int) -> str:
        """Map score to priority."""
        if score >= 85:
            return Priority.URGENT.value
        if score >= 70:
            return Priority.HIGH.value
        if score >= 40:
            return Priority.MEDIUM.value
        return Priority.LOW.value

    # ------------------------------------------------------------------
    # Internal next action logic
    # ------------------------------------------------------------------

    def _build_next_action(self, deal: SalesDeal) -> Dict[str, Any]:
        """Build next-action recommendation for a deal."""
        follow_ups = self._list_context_follow_ups(
            SalesContext(user_id=deal.user_id, workspace_id=deal.workspace_id)
        )
        deal_follow_ups = [
            self._with_overdue_status(task)
            for task in follow_ups
            if task.deal_id == deal.deal_id
        ]
        pending = [task for task in deal_follow_ups if task.status == FollowUpStatus.PENDING.value]
        overdue = [task for task in deal_follow_ups if task.status == FollowUpStatus.OVERDUE.value]

        if deal.stage == SalesStage.WON.value:
            return {
                "action": "Start onboarding and request review/referral.",
                "priority": Priority.HIGH.value,
                "reason": "Deal is won; handoff to fulfillment/client success is the next step.",
                "suggested_due_at": (utc_now() + timedelta(days=1)).isoformat(),
            }

        if deal.stage == SalesStage.LOST.value:
            return {
                "action": "Add to nurture list and schedule future reactivation.",
                "priority": Priority.LOW.value,
                "reason": "Deal is lost; avoid direct pressure and prepare long-term nurture.",
                "suggested_due_at": (utc_now() + timedelta(days=30)).isoformat(),
            }

        if overdue:
            task = sorted(
                overdue,
                key=lambda item: parse_iso_datetime(item.due_at) or utc_now(),
            )[0]
            return {
                "action": f"Complete overdue follow-up: {task.title}",
                "priority": Priority.URGENT.value,
                "reason": "There is an overdue follow-up task for this deal.",
                "follow_up_task_id": task.task_id,
                "suggested_due_at": utc_now().isoformat(),
            }

        if pending:
            task = sorted(
                pending,
                key=lambda item: parse_iso_datetime(item.due_at) or datetime.max.replace(tzinfo=timezone.utc),
            )[0]
            return {
                "action": f"Complete scheduled follow-up: {task.title}",
                "priority": task.priority,
                "reason": "There is already a pending follow-up task.",
                "follow_up_task_id": task.task_id,
                "suggested_due_at": task.due_at,
            }

        stage = deal.stage
        temperature = deal.temperature

        if stage == SalesStage.NEW.value:
            return {
                "action": "Make first contact and confirm need, budget, timeline, and decision maker.",
                "priority": Priority.HIGH.value if temperature == LeadTemperature.HOT.value else Priority.MEDIUM.value,
                "reason": "New deal has no completed contact step yet.",
                "suggested_due_at": (utc_now() + timedelta(days=1)).isoformat(),
            }

        if stage == SalesStage.CONTACTED.value:
            return {
                "action": "Qualify the opportunity and capture budget, service fit, urgency, and authority.",
                "priority": Priority.HIGH.value if deal.score >= 60 else Priority.MEDIUM.value,
                "reason": "Deal has been contacted but not fully qualified.",
                "suggested_due_at": (utc_now() + timedelta(days=2)).isoformat(),
            }

        if stage == SalesStage.QUALIFYING.value:
            return {
                "action": "Move qualified prospects forward or place weak leads into nurture.",
                "priority": Priority.HIGH.value if deal.score >= 65 else Priority.MEDIUM.value,
                "reason": "Qualification is in progress and needs a decision.",
                "suggested_due_at": (utc_now() + timedelta(days=2)).isoformat(),
            }

        if stage == SalesStage.QUALIFIED.value:
            return {
                "action": "Prepare proposal or book a strategy call.",
                "priority": Priority.HIGH.value,
                "reason": "Qualified opportunities should receive a concrete offer.",
                "suggested_due_at": (utc_now() + timedelta(days=2)).isoformat(),
            }

        if stage == SalesStage.PROPOSAL.value:
            return {
                "action": "Follow up on proposal, answer objections, and confirm decision timeline.",
                "priority": Priority.HIGH.value,
                "reason": "Proposal stage requires timely follow-up to avoid deal decay.",
                "suggested_due_at": (utc_now() + timedelta(days=3)).isoformat(),
            }

        if stage == SalesStage.NEGOTIATION.value:
            return {
                "action": "Resolve final objections and ask for close.",
                "priority": Priority.URGENT.value if deal.score >= 75 else Priority.HIGH.value,
                "reason": "Negotiation stage is close to revenue and needs direct next step.",
                "suggested_due_at": (utc_now() + timedelta(days=1)).isoformat(),
            }

        if stage == SalesStage.NURTURE.value:
            return {
                "action": "Send value-based nurture touchpoint and check if timing has changed.",
                "priority": Priority.LOW.value if deal.score < 40 else Priority.MEDIUM.value,
                "reason": "Nurture deals should be followed without pressure.",
                "suggested_due_at": (utc_now() + timedelta(days=14)).isoformat(),
            }

        return {
            "action": "Review deal manually and choose next sales step.",
            "priority": Priority.MEDIUM.value,
            "reason": "No stage-specific recommendation was available.",
            "suggested_due_at": (utc_now() + timedelta(days=3)).isoformat(),
        }

    def _top_next_actions(self, deals: List[SalesDeal], limit: int = 10) -> List[Dict[str, Any]]:
        """Return top next actions for active deals."""
        recommendations = []
        for deal in deals:
            rec = self._build_next_action(deal)
            urgency_weight = {
                Priority.URGENT.value: 4,
                Priority.HIGH.value: 3,
                Priority.MEDIUM.value: 2,
                Priority.LOW.value: 1,
            }.get(rec.get("priority"), 0)

            recommendations.append({
                "deal_id": deal.deal_id,
                "title": deal.title,
                "stage": deal.stage,
                "score": deal.score,
                "temperature": deal.temperature,
                "action": rec.get("action"),
                "priority": rec.get("priority"),
                "reason": rec.get("reason"),
                "suggested_due_at": rec.get("suggested_due_at"),
                "_rank": urgency_weight * 1000 + deal.score,
            })

        recommendations.sort(key=lambda item: item["_rank"], reverse=True)
        for item in recommendations:
            item.pop("_rank", None)
        return recommendations[:limit]

    # ------------------------------------------------------------------
    # Internal storage and isolation helpers
    # ------------------------------------------------------------------

    def _storage_key(self, user_id: str, workspace_id: str, entity_id: str) -> str:
        """Build isolation-safe storage key."""
        return f"{user_id}::{workspace_id}::{entity_id}"

    def _save_deal(self, deal: SalesDeal) -> None:
        """Save deal to local storage."""
        key = self._storage_key(deal.user_id, deal.workspace_id, deal.deal_id)
        self.storage["deals"][key] = copy.deepcopy(deal)

    def _save_follow_up(self, task: FollowUpTask) -> None:
        """Save follow-up to local storage."""
        key = self._storage_key(task.user_id, task.workspace_id, task.task_id)
        self.storage["follow_ups"][key] = copy.deepcopy(task)

    def _get_deal_or_none(self, context: SalesContext, deal_id: str) -> Optional[SalesDeal]:
        """Get deal safely by user/workspace/deal_id."""
        key = self._storage_key(context.user_id, context.workspace_id, deal_id)
        deal = self.storage["deals"].get(key)
        return copy.deepcopy(deal) if deal else None

    def _get_follow_up_or_none(self, context: SalesContext, task_id: str) -> Optional[FollowUpTask]:
        """Get follow-up safely by user/workspace/task_id."""
        key = self._storage_key(context.user_id, context.workspace_id, task_id)
        task = self.storage["follow_ups"].get(key)
        return copy.deepcopy(task) if task else None

    def _list_context_deals(self, context: SalesContext) -> List[SalesDeal]:
        """List only deals belonging to the provided user/workspace."""
        prefix = f"{context.user_id}::{context.workspace_id}::"
        return [
            copy.deepcopy(deal)
            for key, deal in self.storage["deals"].items()
            if key.startswith(prefix)
        ]

    def _list_context_follow_ups(self, context: SalesContext) -> List[FollowUpTask]:
        """List only follow-ups belonging to the provided user/workspace."""
        prefix = f"{context.user_id}::{context.workspace_id}::"
        return [
            copy.deepcopy(task)
            for key, task in self.storage["follow_ups"].items()
            if key.startswith(prefix)
        ]

    # ------------------------------------------------------------------
    # Normalization and validation helpers
    # ------------------------------------------------------------------

    def _known_stages(self) -> List[str]:
        """Return known stage values."""
        return [self._normalize_stage(stage) for stage in self.stage_order]

    def _normalize_stage(self, stage: Union[str, SalesStage]) -> str:
        """Normalize sales stage."""
        if isinstance(stage, SalesStage):
            return stage.value
        text = normalize_text(stage).replace(" ", "_").replace("-", "_")
        aliases = {
            "lead": SalesStage.NEW.value,
            "new_lead": SalesStage.NEW.value,
            "first_contact": SalesStage.CONTACTED.value,
            "contact": SalesStage.CONTACTED.value,
            "qualification": SalesStage.QUALIFYING.value,
            "qualified_lead": SalesStage.QUALIFIED.value,
            "quote": SalesStage.PROPOSAL.value,
            "proposal_sent": SalesStage.PROPOSAL.value,
            "negotiating": SalesStage.NEGOTIATION.value,
            "closed_won": SalesStage.WON.value,
            "closed_lost": SalesStage.LOST.value,
            "follow_up_later": SalesStage.NURTURE.value,
        }
        return aliases.get(text, text)

    def _normalize_priority(self, priority: Union[str, Priority]) -> str:
        """Normalize priority."""
        if isinstance(priority, Priority):
            return priority.value
        text = normalize_text(priority)
        if text in {item.value for item in Priority}:
            return text
        return Priority.MEDIUM.value

    def _normalize_follow_up_status(self, status: Union[str, FollowUpStatus]) -> str:
        """Normalize follow-up status."""
        if isinstance(status, FollowUpStatus):
            return status.value
        text = normalize_text(status)
        if text in {item.value for item in FollowUpStatus}:
            return text
        return FollowUpStatus.PENDING.value

    def _is_transition_allowed(self, current_stage: str, target_stage: str) -> bool:
        """Check if stage transition is allowed."""
        if current_stage == target_stage:
            return True
        allowed = self.allowed_transitions.get(current_stage, [])
        return target_stage in allowed

    def _with_overdue_status(self, task: FollowUpTask) -> FollowUpTask:
        """Return task copy with overdue status if due date passed."""
        copied = copy.deepcopy(task)
        if copied.status != FollowUpStatus.PENDING.value:
            return copied

        due = parse_iso_datetime(copied.due_at)
        if due and due < utc_now():
            copied.status = FollowUpStatus.OVERDUE.value
        return copied

    def _sort_value(self, deal: SalesDeal, sort_by: str) -> Any:
        """Sort helper for deals."""
        value = getattr(deal, sort_by, None)
        if sort_by in {"created_at", "updated_at", "expected_close_date"}:
            return parse_iso_datetime(value) or datetime.min.replace(tzinfo=timezone.utc)
        if isinstance(value, (int, float)):
            return value
        if value is None:
            return ""
        return str(value)


# ---------------------------------------------------------------------------
# Optional factory helpers for Agent Loader / Registry
# ---------------------------------------------------------------------------

def create_sales_pipeline(**kwargs: Any) -> SalesPipeline:
    """
    Factory for Agent Loader / Agent Registry.

    Example:
        pipeline = create_sales_pipeline()
    """
    return SalesPipeline(**kwargs)


def get_agent_class() -> type:
    """
    Return class reference for dynamic loaders.
    """
    return SalesPipeline


def get_agent_metadata() -> Dict[str, Any]:
    """
    Registry-friendly metadata.
    """
    return {
        "agent_name": SalesPipeline.agent_name,
        "agent_type": SalesPipeline.agent_type,
        "class_name": "SalesPipeline",
        "module": "agents.super_agents.business_agent.sales_pipeline",
        "public_methods": SalesPipeline.public_methods,
        "purpose": "Sales stages, follow-up tasks, hot/cold scoring, next actions.",
        "requires_user_workspace_context": True,
        "safe_to_import": True,
        "external_side_effects": False,
        "compatible_with": [
            "BaseAgent",
            "Agent Registry",
            "Agent Loader",
            "Agent Router",
            "Master Agent",
            "Security Agent",
            "Memory Agent",
            "Verification Agent",
            "Dashboard/API",
        ],
    }


__all__ = [
    "SalesPipeline",
    "SalesDeal",
    "FollowUpTask",
    "SalesContext",
    "SalesStage",
    "LeadTemperature",
    "FollowUpStatus",
    "Priority",
    "SalesEventType",
    "create_sales_pipeline",
    "get_agent_class",
    "get_agent_metadata",
]