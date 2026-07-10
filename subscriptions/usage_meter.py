"""
William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Subscription System - Usage Meter

File: subscriptions/usage_meter.py
Class: UsageMeter

Purpose:
    Counts tasks, tokens, agent runs, workflows, storage, API requests, memory,
    calls, invoices, and finance drafts per user/workspace.

Safety:
    - Every usage event must include user_id and workspace_id.
    - Never mixes usage across users or workspaces.
    - Does not execute agents, billing, payments, calls, browser actions, or workflows.
    - Only records/counts usage and checks plan limits.
    - Uses PlanRules when available to enforce subscription limits.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple


try:
    from subscriptions.plan_rules import PlanRules
except Exception:
    class PlanRules:  # type: ignore[no-redef]
        """Fallback stub so usage_meter.py remains import-safe."""

        def get_default_plan_name(self) -> str:
            return "free"

        def check_usage(
            self,
            plan_name: str,
            usage_key: str,
            current_usage: int,
            requested_amount: int = 1,
            user_id: Optional[str] = None,
            workspace_id: Optional[str] = None,
        ) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback usage check allowed.",
                "data": {
                    "allowed": True,
                    "status": "ok",
                    "plan_name": plan_name,
                    "usage_key": usage_key,
                    "current_usage": current_usage,
                    "requested_amount": requested_amount,
                    "projected_usage": current_usage + requested_amount,
                    "limit": None,
                    "remaining": None,
                    "reason": "fallback_plan_rules",
                    "metadata": {
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                },
                "error": None,
                "metadata": {},
            }

        def get_usage_limits(self, plan_name: str) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback usage limits.",
                "data": {
                    "plan_name": plan_name,
                    "usage_limits": {},
                },
                "error": None,
                "metadata": {},
            }


class UsageMetric(str, Enum):
    """Supported usage counters."""

    AGENT_RUNS = "agent_runs"
    TASK_RECORDS = "task_records"
    TOKENS_INPUT = "tokens_input"
    TOKENS_OUTPUT = "tokens_output"
    TOKENS_TOTAL = "tokens_total"
    WORKFLOW_RUNS = "workflow_runs"
    API_REQUESTS = "api_requests"
    MEMORY_ITEMS = "memory_items"
    STORAGE_MB = "storage_mb"
    TEAM_MEMBERS = "team_members"
    INVOICES = "invoices"
    CALL_MINUTES = "call_minutes"
    FINANCE_DRAFTS = "finance_drafts"
    BROWSER_ACTIONS = "browser_actions"
    CODE_RUNS = "code_runs"
    VERIFICATION_REPORTS = "verification_reports"


class UsageEventType(str, Enum):
    """Usage event type."""

    INCREMENT = "increment"
    DECREMENT = "decrement"
    SET = "set"
    RESET = "reset"


class UsageScope(str, Enum):
    """Usage scope level."""

    USER = "user"
    WORKSPACE = "workspace"


class UsageDecisionStatus(str, Enum):
    """Usage decision status."""

    ALLOWED = "allowed"
    WARNING = "warning"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class UsageContext:
    """Required SaaS usage context."""

    user_id: str
    workspace_id: str
    plan_name: str = "free"
    role: str = "member"
    request_id: Optional[str] = None
    source: str = "subscriptions.usage_meter"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class UsageEvent:
    """One usage event record."""

    event_id: str
    user_id: str
    workspace_id: str
    metric: UsageMetric
    amount: int
    event_type: UsageEventType = UsageEventType.INCREMENT
    scope: UsageScope = UsageScope.WORKSPACE
    agent_key: Optional[str] = None
    task_id: Optional[str] = None
    request_id: Optional[str] = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["metric"] = self.metric.value
        data["event_type"] = self.event_type.value
        data["scope"] = self.scope.value
        data["metadata"] = dict(self.metadata)
        return data


@dataclass(frozen=True)
class UsageSnapshot:
    """Current usage snapshot for one user/workspace."""

    user_id: str
    workspace_id: str
    plan_name: str
    counters: Mapping[str, int]
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "plan_name": self.plan_name,
            "counters": dict(self.counters),
            "updated_at": self.updated_at,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class UsageDecision:
    """Usage decision after checking plan rules."""

    allowed: bool
    status: UsageDecisionStatus
    metric: UsageMetric
    current_usage: int
    requested_amount: int
    projected_usage: int
    plan_name: str
    reason: str
    limit: Optional[int] = None
    remaining: Optional[int] = None
    percent_used: Optional[float] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["metric"] = self.metric.value
        data["metadata"] = dict(self.metadata)
        return data


class UsageMeter:
    """
    Usage meter for William/Jarvis subscription enforcement.

    This class can be used by:
        - Master Agent before routing tasks
        - Agent Router before running agent chains
        - FastAPI dashboard/API routes
        - Billing dashboard
        - AccessControl
        - Usage analytics
        - Security Agent audit flows

    This file does not persist to a database by itself. It is import-safe and can
    work with optional in-memory snapshots/events during early development.
    """

    STANDARD_METRICS: Tuple[UsageMetric, ...] = (
        UsageMetric.AGENT_RUNS,
        UsageMetric.TASK_RECORDS,
        UsageMetric.TOKENS_INPUT,
        UsageMetric.TOKENS_OUTPUT,
        UsageMetric.TOKENS_TOTAL,
        UsageMetric.WORKFLOW_RUNS,
        UsageMetric.API_REQUESTS,
        UsageMetric.MEMORY_ITEMS,
        UsageMetric.STORAGE_MB,
        UsageMetric.TEAM_MEMBERS,
        UsageMetric.INVOICES,
        UsageMetric.CALL_MINUTES,
        UsageMetric.FINANCE_DRAFTS,
        UsageMetric.BROWSER_ACTIONS,
        UsageMetric.CODE_RUNS,
        UsageMetric.VERIFICATION_REPORTS,
    )

    PLAN_RULE_METRIC_MAP: Mapping[UsageMetric, str] = {
        UsageMetric.AGENT_RUNS: "agent_runs",
        UsageMetric.TASK_RECORDS: "task_records",
        UsageMetric.WORKFLOW_RUNS: "workflow_runs",
        UsageMetric.API_REQUESTS: "api_requests",
        UsageMetric.MEMORY_ITEMS: "memory_items",
        UsageMetric.STORAGE_MB: "storage_mb",
        UsageMetric.TEAM_MEMBERS: "team_members",
        UsageMetric.INVOICES: "invoices",
        UsageMetric.CALL_MINUTES: "call_minutes",
        UsageMetric.FINANCE_DRAFTS: "finance_drafts",
    }

    def __init__(
        self,
        plan_rules: Optional[PlanRules] = None,
        initial_snapshots: Optional[Iterable[UsageSnapshot]] = None,
        initial_events: Optional[Iterable[UsageEvent]] = None,
    ) -> None:
        self.plan_rules = plan_rules or PlanRules()
        self._snapshots: Dict[str, UsageSnapshot] = {}
        self._events: List[UsageEvent] = []

        for snapshot in initial_snapshots or []:
            self._snapshots[self._snapshot_key(snapshot.user_id, snapshot.workspace_id)] = snapshot

        for event in initial_events or []:
            self._events.append(event)

    # ------------------------------------------------------------------
    # Public usage APIs
    # ------------------------------------------------------------------

    def get_empty_counters(self) -> Dict[str, int]:
        """Return zeroed counters for all standard metrics."""

        return {metric.value: 0 for metric in self.STANDARD_METRICS}

    def get_snapshot(
        self,
        user_id: str,
        workspace_id: str,
        plan_name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Return current usage snapshot for a user/workspace."""

        context = {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "plan_name": plan_name or self.plan_rules.get_default_plan_name(),
        }
        context_result = self._validate_task_context(context)
        if not context_result["success"]:
            return context_result

        key = self._snapshot_key(user_id, workspace_id)
        snapshot = self._snapshots.get(key)

        if snapshot is None:
            snapshot = UsageSnapshot(
                user_id=user_id,
                workspace_id=workspace_id,
                plan_name=plan_name or self.plan_rules.get_default_plan_name(),
                counters=self.get_empty_counters(),
                metadata={"source": "generated_empty_snapshot"},
            )

        return self._safe_result(
            message="Usage snapshot loaded successfully.",
            data={"snapshot": snapshot.to_dict()},
            metadata=self._metadata(user_id, workspace_id, "get_snapshot"),
        )

    def set_snapshot(
        self,
        user_id: str,
        workspace_id: str,
        plan_name: str,
        counters: Mapping[str, int],
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Set usage snapshot safely for one user/workspace."""

        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "plan_name": plan_name,
                "action": "set_snapshot",
            }
        )
        if not context_result["success"]:
            return context_result

        normalized_counters_result = self._normalize_counters(counters)
        if not normalized_counters_result["success"]:
            return normalized_counters_result

        snapshot = UsageSnapshot(
            user_id=user_id,
            workspace_id=workspace_id,
            plan_name=plan_name,
            counters=normalized_counters_result["data"]["counters"],
            metadata=dict(metadata or {}),
        )

        self._snapshots[self._snapshot_key(user_id, workspace_id)] = snapshot

        decision = {
            "snapshot": snapshot.to_dict(),
            "operation": "set_snapshot",
        }

        return self._safe_result(
            message="Usage snapshot set successfully.",
            data={
                **decision,
                "audit_event": self._log_audit_event("set_usage_snapshot", decision)["data"],
                "verification_payload": self._prepare_verification_payload(decision)["data"],
            },
            metadata=self._metadata(user_id, workspace_id, "set_snapshot"),
        )

    def record_usage(
        self,
        user_id: str,
        workspace_id: str,
        plan_name: str,
        metric: str,
        amount: int = 1,
        event_type: UsageEventType = UsageEventType.INCREMENT,
        scope: UsageScope = UsageScope.WORKSPACE,
        agent_key: Optional[str] = None,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        enforce_plan_limit: bool = True,
    ) -> Dict[str, Any]:
        """
        Record a usage event and update counters.

        This does not execute any agent. It only increments/decrements/sets usage.
        """

        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "plan_name": plan_name,
                "action": "record_usage",
                "request_id": request_id,
            }
        )
        if not context_result["success"]:
            return context_result

        metric_result = self._parse_metric(metric)
        if not metric_result["success"]:
            return metric_result

        metric_enum = metric_result["data"]["metric"]

        if amount < 0:
            return self._error_result(
                message="Usage amount cannot be negative.",
                error="invalid_usage_amount",
                metadata={"amount": amount},
            )

        current_snapshot_result = self.get_snapshot(user_id, workspace_id, plan_name)
        if not current_snapshot_result["success"]:
            return current_snapshot_result

        snapshot_data = current_snapshot_result["data"]["snapshot"]
        counters = dict(snapshot_data["counters"])
        current_value = int(counters.get(metric_enum.value, 0))

        requested_amount = amount if event_type == UsageEventType.INCREMENT else 0

        if enforce_plan_limit and event_type == UsageEventType.INCREMENT:
            decision_result = self.check_usage_allowed(
                user_id=user_id,
                workspace_id=workspace_id,
                plan_name=plan_name,
                metric=metric_enum.value,
                requested_amount=requested_amount,
            )
            if not decision_result["success"]:
                return decision_result

            decision = decision_result["data"]["decision"]
            if not decision["allowed"]:
                return self._safe_result(
                    message="Usage event blocked by plan limit.",
                    data={
                        "recorded": False,
                        "decision": decision,
                        "snapshot": snapshot_data,
                    },
                    metadata=self._metadata(user_id, workspace_id, "record_usage_blocked", metric_enum.value),
                )

        new_value = self._apply_event_to_value(
            current_value=current_value,
            amount=amount,
            event_type=event_type,
        )

        counters[metric_enum.value] = new_value

        event = UsageEvent(
            event_id=self._generate_reference("USE"),
            user_id=user_id,
            workspace_id=workspace_id,
            metric=metric_enum,
            amount=amount,
            event_type=event_type,
            scope=scope,
            agent_key=agent_key,
            task_id=task_id,
            request_id=request_id,
            metadata=dict(metadata or {}),
        )

        snapshot = UsageSnapshot(
            user_id=user_id,
            workspace_id=workspace_id,
            plan_name=plan_name,
            counters=counters,
            metadata={
                "last_event_id": event.event_id,
                "last_metric": metric_enum.value,
            },
        )

        self._events.append(event)
        self._snapshots[self._snapshot_key(user_id, workspace_id)] = snapshot

        decision_payload = {
            "recorded": True,
            "event": event.to_dict(),
            "snapshot": snapshot.to_dict(),
        }

        return self._safe_result(
            message="Usage recorded successfully.",
            data={
                **decision_payload,
                "audit_event": self._log_audit_event("record_usage", decision_payload)["data"],
                "verification_payload": self._prepare_verification_payload(decision_payload)["data"],
            },
            metadata=self._metadata(user_id, workspace_id, "record_usage", metric_enum.value),
        )

    def check_usage_allowed(
        self,
        user_id: str,
        workspace_id: str,
        plan_name: str,
        metric: str,
        requested_amount: int = 1,
    ) -> Dict[str, Any]:
        """Check if usage is allowed by current plan limits."""

        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "plan_name": plan_name,
                "action": "check_usage_allowed",
            }
        )
        if not context_result["success"]:
            return context_result

        metric_result = self._parse_metric(metric)
        if not metric_result["success"]:
            return metric_result

        if requested_amount < 0:
            return self._error_result(
                message="Requested amount cannot be negative.",
                error="invalid_requested_amount",
            )

        metric_enum = metric_result["data"]["metric"]

        snapshot_result = self.get_snapshot(user_id, workspace_id, plan_name)
        if not snapshot_result["success"]:
            return snapshot_result

        counters = snapshot_result["data"]["snapshot"]["counters"]
        current_usage = int(counters.get(metric_enum.value, 0))

        plan_metric_key = self.PLAN_RULE_METRIC_MAP.get(metric_enum)

        if not plan_metric_key:
            decision = UsageDecision(
                allowed=True,
                status=UsageDecisionStatus.ALLOWED,
                metric=metric_enum,
                current_usage=current_usage,
                requested_amount=requested_amount,
                projected_usage=current_usage + requested_amount,
                plan_name=plan_name,
                reason="metric_not_plan_gated",
                metadata=self._metadata(user_id, workspace_id, "check_usage_allowed", metric_enum.value),
            )

            return self._safe_result(
                message="Usage metric is not plan-gated.",
                data={"decision": decision.to_dict()},
            )

        plan_check = self.plan_rules.check_usage(
            plan_name=plan_name,
            usage_key=plan_metric_key,
            current_usage=current_usage,
            requested_amount=requested_amount,
            user_id=user_id,
            workspace_id=workspace_id,
        )

        if not plan_check.get("success"):
            return plan_check

        plan_data = plan_check["data"]
        status = self._map_plan_status_to_decision_status(plan_data.get("status"))

        decision = UsageDecision(
            allowed=bool(plan_data.get("allowed")),
            status=status,
            metric=metric_enum,
            current_usage=current_usage,
            requested_amount=requested_amount,
            projected_usage=int(plan_data.get("projected_usage", current_usage + requested_amount)),
            plan_name=plan_name,
            reason=str(plan_data.get("reason", "plan_check_completed")),
            limit=plan_data.get("limit"),
            remaining=plan_data.get("remaining"),
            percent_used=plan_data.get("percent_used"),
            metadata={
                **self._metadata(user_id, workspace_id, "check_usage_allowed", metric_enum.value),
                "plan_metric_key": plan_metric_key,
                "plan_status": plan_data.get("status"),
            },
        )

        return self._safe_result(
            message="Usage decision created.",
            data={
                "decision": decision.to_dict(),
                "plan_check": plan_data,
            },
        )

    def record_agent_run(
        self,
        user_id: str,
        workspace_id: str,
        plan_name: str,
        agent_key: str,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
        tokens_input: int = 0,
        tokens_output: int = 0,
    ) -> Dict[str, Any]:
        """Record a complete agent run and optional token usage."""

        if tokens_input < 0 or tokens_output < 0:
            return self._error_result(
                message="Token usage cannot be negative.",
                error="invalid_token_usage",
            )

        recorded: List[Dict[str, Any]] = []

        agent_result = self.record_usage(
            user_id=user_id,
            workspace_id=workspace_id,
            plan_name=plan_name,
            metric=UsageMetric.AGENT_RUNS.value,
            amount=1,
            agent_key=agent_key,
            task_id=task_id,
            request_id=request_id,
            metadata={"agent_key": agent_key},
        )
        if not agent_result["success"]:
            return agent_result
        recorded.append(agent_result["data"]["event"])

        if tokens_input:
            result = self.record_usage(
                user_id=user_id,
                workspace_id=workspace_id,
                plan_name=plan_name,
                metric=UsageMetric.TOKENS_INPUT.value,
                amount=tokens_input,
                agent_key=agent_key,
                task_id=task_id,
                request_id=request_id,
                enforce_plan_limit=False,
            )
            if not result["success"]:
                return result
            recorded.append(result["data"]["event"])

        if tokens_output:
            result = self.record_usage(
                user_id=user_id,
                workspace_id=workspace_id,
                plan_name=plan_name,
                metric=UsageMetric.TOKENS_OUTPUT.value,
                amount=tokens_output,
                agent_key=agent_key,
                task_id=task_id,
                request_id=request_id,
                enforce_plan_limit=False,
            )
            if not result["success"]:
                return result
            recorded.append(result["data"]["event"])

        total_tokens = tokens_input + tokens_output
        if total_tokens:
            result = self.record_usage(
                user_id=user_id,
                workspace_id=workspace_id,
                plan_name=plan_name,
                metric=UsageMetric.TOKENS_TOTAL.value,
                amount=total_tokens,
                agent_key=agent_key,
                task_id=task_id,
                request_id=request_id,
                enforce_plan_limit=False,
            )
            if not result["success"]:
                return result
            recorded.append(result["data"]["event"])

        snapshot = self.get_snapshot(user_id, workspace_id, plan_name)["data"]["snapshot"]

        payload = {
            "recorded_events": recorded,
            "snapshot": snapshot,
            "agent_key": agent_key,
            "task_id": task_id,
            "request_id": request_id,
        }

        return self._safe_result(
            message="Agent run usage recorded.",
            data={
                **payload,
                "verification_payload": self._prepare_verification_payload(payload)["data"],
            },
            metadata=self._metadata(user_id, workspace_id, "record_agent_run", agent_key),
        )

    def record_task_created(
        self,
        user_id: str,
        workspace_id: str,
        plan_name: str,
        task_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record task creation usage."""

        return self.record_usage(
            user_id=user_id,
            workspace_id=workspace_id,
            plan_name=plan_name,
            metric=UsageMetric.TASK_RECORDS.value,
            amount=1,
            task_id=task_id,
            request_id=request_id,
            metadata={"usage_helper": "record_task_created"},
        )

    def record_workflow_run(
        self,
        user_id: str,
        workspace_id: str,
        plan_name: str,
        workflow_id: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record workflow run usage."""

        return self.record_usage(
            user_id=user_id,
            workspace_id=workspace_id,
            plan_name=plan_name,
            metric=UsageMetric.WORKFLOW_RUNS.value,
            amount=1,
            request_id=request_id,
            metadata={"workflow_id": workflow_id},
        )

    def record_storage_mb(
        self,
        user_id: str,
        workspace_id: str,
        plan_name: str,
        storage_mb: int,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Set current storage MB usage."""

        return self.record_usage(
            user_id=user_id,
            workspace_id=workspace_id,
            plan_name=plan_name,
            metric=UsageMetric.STORAGE_MB.value,
            amount=storage_mb,
            event_type=UsageEventType.SET,
            request_id=request_id,
            metadata={"usage_helper": "record_storage_mb"},
        )

    def get_events(
        self,
        user_id: str,
        workspace_id: str,
        metric: Optional[str] = None,
        limit: int = 100,
    ) -> Dict[str, Any]:
        """Return usage events scoped to one user/workspace."""

        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "action": "get_events",
            }
        )
        if not context_result["success"]:
            return context_result

        if limit <= 0:
            return self._error_result(
                message="Limit must be greater than zero.",
                error="invalid_limit",
            )

        metric_enum: Optional[UsageMetric] = None
        if metric:
            metric_result = self._parse_metric(metric)
            if not metric_result["success"]:
                return metric_result
            metric_enum = metric_result["data"]["metric"]

        events = [
            event
            for event in self._events
            if event.user_id == user_id
            and event.workspace_id == workspace_id
            and (metric_enum is None or event.metric == metric_enum)
        ]

        events = events[-limit:]

        return self._safe_result(
            message="Usage events loaded successfully.",
            data={
                "count": len(events),
                "events": [event.to_dict() for event in events],
                "metric": metric_enum.value if metric_enum else None,
            },
            metadata=self._metadata(user_id, workspace_id, "get_events", metric),
        )

    def get_dashboard_usage_summary(
        self,
        user_id: str,
        workspace_id: str,
        plan_name: str,
    ) -> Dict[str, Any]:
        """Return dashboard-ready usage summary with plan checks."""

        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "plan_name": plan_name,
                "action": "get_dashboard_usage_summary",
            }
        )
        if not context_result["success"]:
            return context_result

        snapshot_result = self.get_snapshot(user_id, workspace_id, plan_name)
        if not snapshot_result["success"]:
            return snapshot_result

        snapshot = snapshot_result["data"]["snapshot"]
        counters = snapshot["counters"]

        checks: Dict[str, Any] = {}
        for metric in self.STANDARD_METRICS:
            check_result = self.check_usage_allowed(
                user_id=user_id,
                workspace_id=workspace_id,
                plan_name=plan_name,
                metric=metric.value,
                requested_amount=0,
            )
            checks[metric.value] = check_result.get("data", {}).get("decision")

        warning_metrics = [
            key for key, decision in checks.items()
            if decision and decision.get("status") == UsageDecisionStatus.WARNING.value
        ]

        blocked_metrics = [
            key for key, decision in checks.items()
            if decision and decision.get("status") == UsageDecisionStatus.BLOCKED.value
        ]

        return self._safe_result(
            message="Dashboard usage summary created.",
            data={
                "snapshot": snapshot,
                "plan_name": plan_name,
                "usage_checks": checks,
                "warning_metrics": warning_metrics,
                "blocked_metrics": blocked_metrics,
                "event_count": len(
                    [
                        event for event in self._events
                        if event.user_id == user_id and event.workspace_id == workspace_id
                    ]
                ),
                "metadata": self._metadata(
                    user_id,
                    workspace_id,
                    "get_dashboard_usage_summary",
                    plan_name,
                ),
            },
        )

    # ------------------------------------------------------------------
    # William compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """Validate SaaS context for usage operations."""

        if context is None:
            return self._error_result(
                message="Usage context is required.",
                error="missing_context",
            )

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if not user_id or not workspace_id:
            return self._error_result(
                message="Usage operations require user_id and workspace_id.",
                error="missing_saas_isolation_fields",
                metadata={
                    "has_user_id": bool(user_id),
                    "has_workspace_id": bool(workspace_id),
                },
            )

        return self._safe_result(
            message="Usage context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "plan_name": context.get("plan_name"),
                "action": context.get("action"),
                "request_id": context.get("request_id"),
            },
        )

    def _requires_security_check(
        self,
        metric: Optional[str] = None,
        amount: Optional[int] = None,
        action: Optional[str] = None,
    ) -> bool:
        """Return whether usage operation needs Security Agent approval."""

        normalized_metric = str(metric or "").strip().lower()
        normalized_action = str(action or "").strip().lower()

        sensitive_metrics = {
            UsageMetric.FINANCE_DRAFTS.value,
            UsageMetric.CALL_MINUTES.value,
            UsageMetric.STORAGE_MB.value,
            UsageMetric.MEMORY_ITEMS.value,
        }

        sensitive_actions = {
            "reset",
            "delete_usage",
            "export_usage",
            "set_snapshot",
            "manual_override",
        }

        if normalized_metric in sensitive_metrics:
            return True

        if normalized_action in sensitive_actions:
            return True

        if amount is not None and amount > 100000:
            return True

        return False

    def _request_security_approval(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare Security Agent approval payload."""

        return self._safe_result(
            message="Security approval payload prepared.",
            data={
                "requires_approval": True,
                "approval_type": "usage_meter_action",
                "recommended_agent": "security_agent",
                "payload": dict(payload),
            },
        )

    def _prepare_verification_payload(self, decision: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare Verification Agent payload for usage changes."""

        return self._safe_result(
            message="Verification payload prepared.",
            data={
                "verification_type": "usage_meter_decision",
                "expected_state": "usage_recorded_or_checked",
                "recommended_agent": "verification_agent",
                "decision": dict(decision),
            },
        )

    def _prepare_memory_payload(self, decision: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare Memory Agent payload for useful usage context."""

        return self._safe_result(
            message="Memory payload prepared.",
            data={
                "memory_type": "usage_context",
                "privacy": "workspace",
                "importance": "low",
                "recommended_agent": "memory_agent",
                "content": dict(decision),
            },
        )

    def _emit_agent_event(self, event_name: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare event payload for future agent event bus."""

        return self._safe_result(
            message="Agent event payload prepared.",
            data={
                "event_name": event_name,
                "source": "subscriptions.usage_meter",
                "payload": dict(payload),
            },
        )

    def _log_audit_event(self, action: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare audit payload for future audit logger."""

        return self._safe_result(
            message="Audit event payload prepared.",
            data={
                "action": action,
                "source": "subscriptions.usage_meter",
                "payload": dict(payload),
                "created_at": self._now_iso(),
            },
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _parse_metric(self, metric: str) -> Dict[str, Any]:
        """Parse metric string into UsageMetric."""

        normalized = str(metric or "").strip().lower().replace(" ", "_").replace("-", "_")

        try:
            metric_enum = UsageMetric(normalized)
        except ValueError:
            return self._error_result(
                message="Unknown usage metric.",
                error="unknown_usage_metric",
                metadata={
                    "metric": metric,
                    "supported_metrics": [item.value for item in self.STANDARD_METRICS],
                },
            )

        return self._safe_result(
            message="Usage metric parsed.",
            data={"metric": metric_enum},
        )

    def _normalize_counters(self, counters: Mapping[str, int]) -> Dict[str, Any]:
        """Normalize and validate usage counters."""

        normalized = self.get_empty_counters()

        for key, value in counters.items():
            metric_result = self._parse_metric(key)
            if not metric_result["success"]:
                return metric_result

            metric = metric_result["data"]["metric"]

            try:
                int_value = int(value)
            except Exception:
                return self._error_result(
                    message="Usage counter values must be integers.",
                    error="invalid_counter_value",
                    metadata={"metric": key, "value": value},
                )

            if int_value < 0:
                return self._error_result(
                    message="Usage counter values cannot be negative.",
                    error="negative_counter_value",
                    metadata={"metric": key, "value": value},
                )

            normalized[metric.value] = int_value

        return self._safe_result(
            message="Usage counters normalized.",
            data={"counters": normalized},
        )

    def _apply_event_to_value(
        self,
        current_value: int,
        amount: int,
        event_type: UsageEventType,
    ) -> int:
        """Apply usage event to current counter value."""

        if event_type == UsageEventType.INCREMENT:
            return current_value + amount

        if event_type == UsageEventType.DECREMENT:
            return max(0, current_value - amount)

        if event_type == UsageEventType.SET:
            return amount

        if event_type == UsageEventType.RESET:
            return 0

        return current_value

    def _map_plan_status_to_decision_status(self, status: Optional[str]) -> UsageDecisionStatus:
        """Map PlanRules usage status into UsageMeter decision status."""

        normalized = str(status or "").strip().lower()

        if normalized in {"ok", "unlimited"}:
            return UsageDecisionStatus.ALLOWED

        if normalized == "warning":
            return UsageDecisionStatus.WARNING

        if normalized in {"exceeded", "unknown_limit"}:
            return UsageDecisionStatus.BLOCKED

        return UsageDecisionStatus.UNKNOWN

    def _snapshot_key(self, user_id: str, workspace_id: str) -> str:
        """Create isolation-safe snapshot key."""

        return f"{workspace_id}::{user_id}"

    def _generate_reference(self, prefix: str) -> str:
        """Generate local unique-ish reference without external dependencies."""

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        return f"{prefix}-{timestamp}"

    @staticmethod
    def _now_iso() -> str:
        """Return current UTC timestamp."""

        return datetime.now(timezone.utc).isoformat()

    def _metadata(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "action": action,
            "resource_key": resource_key,
            "source": "subscriptions.usage_meter",
        }

    def _safe_result(
        self,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
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
        return {
            "success": False,
            "message": message,
            "data": dict(data or {}),
            "error": error,
            "metadata": dict(metadata or {}),
        }


__all__ = [
    "UsageMeter",
    "UsageMetric",
    "UsageEventType",
    "UsageScope",
    "UsageDecisionStatus",
    "UsageContext",
    "UsageEvent",
    "UsageSnapshot",
    "UsageDecision",
]