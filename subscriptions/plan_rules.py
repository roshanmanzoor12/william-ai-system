"""
William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Subscription System - Plan Rules

File: subscriptions/plan_rules.py
Class: PlanRules

Purpose:
    Defines SaaS subscription plans, allowed agents, feature gates, usage limits,
    role restrictions, and structured access decisions.

This file is intentionally import-safe and has no external dependencies.
It does not charge users, process payments, execute agents, or modify billing data.
It only answers questions like:

    - Is this plan valid?
    - Is this agent allowed on this plan?
    - Is this feature enabled?
    - What usage limit applies?
    - Should the user upgrade?
    - What plan data should the API/dashboard show?

Safety Rules:
    - Never mix workspace data.
    - Every access decision accepts user_id/workspace_id metadata when provided.
    - Sensitive agents/actions are flagged for Security Agent approval.
    - Finance actions are draft-only unless explicitly approved elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple


class PlanName(str, Enum):
    """Known subscription plan identifiers."""

    FREE = "free"
    STARTER = "starter"
    GROWTH = "growth"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


class AgentAccessStatus(str, Enum):
    """Agent access result status."""

    ALLOWED = "allowed"
    LIMITED = "limited"
    APPROVAL_REQUIRED = "approval_required"
    BLOCKED = "blocked"


class FeatureAccessStatus(str, Enum):
    """Feature gate result status."""

    ENABLED = "enabled"
    LIMITED = "limited"
    DISABLED = "disabled"
    APPROVAL_REQUIRED = "approval_required"


class UsageStatus(str, Enum):
    """Usage limit result status."""

    OK = "ok"
    WARNING = "warning"
    EXCEEDED = "exceeded"
    UNLIMITED = "unlimited"
    UNKNOWN_LIMIT = "unknown_limit"


class RiskLevel(str, Enum):
    """Risk level for plan/agent/feature access decisions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class UsageLimit:
    """Defines a usage limit for a plan."""

    key: str
    label: str
    limit: Optional[int]
    unit: str
    warning_threshold_percent: int = 80
    hard_limit: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FeatureGate:
    """Defines feature access behavior."""

    key: str
    label: str
    enabled: bool
    description: str
    approval_required: bool = False
    minimum_role: str = "member"
    risk_level: RiskLevel = RiskLevel.LOW

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["risk_level"] = self.risk_level.value
        return data


@dataclass(frozen=True)
class AgentRule:
    """Defines agent access behavior for a plan."""

    agent_key: str
    label: str
    access: AgentAccessStatus
    description: str
    approval_required_actions: Tuple[str, ...] = ()
    blocked_actions: Tuple[str, ...] = ()
    risk_level: RiskLevel = RiskLevel.MEDIUM

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["access"] = self.access.value
        data["risk_level"] = self.risk_level.value
        data["approval_required_actions"] = list(self.approval_required_actions)
        data["blocked_actions"] = list(self.blocked_actions)
        return data


@dataclass(frozen=True)
class PlanDefinition:
    """Complete subscription plan definition."""

    name: PlanName
    display_name: str
    monthly_price_usd: Optional[int]
    description: str
    max_users: Optional[int]
    allowed_roles: Tuple[str, ...]
    agent_rules: Mapping[str, AgentRule]
    feature_gates: Mapping[str, FeatureGate]
    usage_limits: Mapping[str, UsageLimit]
    support_level: str
    recommended_for: str
    is_public: bool = True
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name.value,
            "display_name": self.display_name,
            "monthly_price_usd": self.monthly_price_usd,
            "description": self.description,
            "max_users": self.max_users,
            "allowed_roles": list(self.allowed_roles),
            "agent_rules": {
                key: value.to_dict() for key, value in self.agent_rules.items()
            },
            "feature_gates": {
                key: value.to_dict() for key, value in self.feature_gates.items()
            },
            "usage_limits": {
                key: value.to_dict() for key, value in self.usage_limits.items()
            },
            "support_level": self.support_level,
            "recommended_for": self.recommended_for,
            "is_public": self.is_public,
            "metadata": dict(self.metadata),
        }


class PlanRules:
    """
    Subscription plan rules for William/Jarvis SaaS.

    This class is intentionally read-only. It does not process payments and does
    not mutate user/workspace subscriptions. Use it from:

        - subscriptions/access_control.py
        - subscriptions/usage_meter.py
        - subscriptions/billing_manager.py
        - apps/api/subscription_routes.py
        - dashboard billing/settings pages
        - Master Agent before routing plan-gated tasks

    Every public method returns a structured dict so API routes and agents can
    safely consume decisions.
    """

    ALL_AGENT_KEYS: Tuple[str, ...] = (
        "master_agent",
        "voice_agent",
        "system_agent",
        "browser_agent",
        "code_agent",
        "memory_agent",
        "security_agent",
        "verification_agent",
        "visual_agent",
        "workflow_agent",
        "hologram_agent",
        "call_agent",
        "business_agent",
        "finance_agent",
        "creator_agent",
    )

    SENSITIVE_AGENT_KEYS: Tuple[str, ...] = (
        "system_agent",
        "browser_agent",
        "code_agent",
        "memory_agent",
        "security_agent",
        "visual_agent",
        "workflow_agent",
        "call_agent",
        "finance_agent",
        "hologram_agent",
    )

    ROLE_ORDER: Tuple[str, ...] = ("viewer", "member", "manager", "admin", "owner")

    def __init__(self, custom_plans: Optional[Mapping[str, PlanDefinition]] = None) -> None:
        self._plans: Dict[str, PlanDefinition] = self._build_default_plans()

        if custom_plans:
            for key, plan in custom_plans.items():
                normalized_key = self._normalize_plan_name(key)
                self._plans[normalized_key] = plan

    # -------------------------------------------------------------------------
    # Public plan APIs
    # -------------------------------------------------------------------------

    def list_plans(self, include_private: bool = False) -> Dict[str, Any]:
        """Return all available subscription plans."""

        plans = [
            plan.to_dict()
            for plan in self._plans.values()
            if include_private or plan.is_public
        ]

        return self._safe_result(
            message="Subscription plans loaded successfully.",
            data={
                "plans": plans,
                "count": len(plans),
                "include_private": include_private,
            },
        )

    def get_plan(self, plan_name: str) -> Dict[str, Any]:
        """Return one plan definition."""

        plan = self._get_plan_or_none(plan_name)
        if not plan:
            return self._error_result(
                message="Plan not found.",
                error="unknown_plan",
                metadata={"plan_name": plan_name},
            )

        return self._safe_result(
            message="Plan loaded successfully.",
            data={"plan": plan.to_dict()},
        )

    def get_plan_names(self, include_private: bool = False) -> Dict[str, Any]:
        """Return plan names only."""

        names = [
            plan.name.value
            for plan in self._plans.values()
            if include_private or plan.is_public
        ]

        return self._safe_result(
            message="Plan names loaded successfully.",
            data={"plan_names": names},
        )

    def plan_exists(self, plan_name: str) -> bool:
        """Check if a plan exists."""

        return self._normalize_plan_name(plan_name) in self._plans

    def get_default_plan_name(self) -> str:
        """Default fallback plan for unknown/free users."""

        return PlanName.FREE.value

    # -------------------------------------------------------------------------
    # Agent access APIs
    # -------------------------------------------------------------------------

    def is_agent_allowed(
        self,
        plan_name: str,
        agent_key: str,
        action: Optional[str] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        role: str = "member",
    ) -> Dict[str, Any]:
        """
        Check whether a plan allows a specific agent and optional action.

        This does not execute the agent. It only returns an access decision.
        Sensitive actions should still be sent to Security Agent.
        """

        context_error = self._validate_optional_context(user_id, workspace_id)
        if context_error:
            return context_error

        plan = self._get_plan_or_none(plan_name)
        if not plan:
            return self._error_result(
                message="Plan not found. Agent access denied.",
                error="unknown_plan",
                metadata=self._metadata(user_id, workspace_id, plan_name, agent_key),
            )

        normalized_agent = self._normalize_key(agent_key)
        rule = plan.agent_rules.get(normalized_agent)

        if not rule:
            return self._safe_result(
                message="Agent is not available on this plan.",
                data=self._agent_decision_payload(
                    allowed=False,
                    status=AgentAccessStatus.BLOCKED,
                    plan=plan,
                    agent_key=normalized_agent,
                    action=action,
                    reason="agent_not_in_plan",
                    requires_security_check=False,
                    rule=None,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                ),
            )

        if not self._role_is_allowed(role, "member"):
            return self._safe_result(
                message="Role is not allowed to use this agent.",
                data=self._agent_decision_payload(
                    allowed=False,
                    status=AgentAccessStatus.BLOCKED,
                    plan=plan,
                    agent_key=normalized_agent,
                    action=action,
                    reason="role_not_allowed",
                    requires_security_check=False,
                    rule=rule,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                ),
            )

        normalized_action = self._normalize_key(action) if action else None

        if normalized_action and normalized_action in rule.blocked_actions:
            return self._safe_result(
                message="Action is blocked by plan policy.",
                data=self._agent_decision_payload(
                    allowed=False,
                    status=AgentAccessStatus.BLOCKED,
                    plan=plan,
                    agent_key=normalized_agent,
                    action=normalized_action,
                    reason="action_blocked_by_plan",
                    requires_security_check=True,
                    rule=rule,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                ),
            )

        if rule.access == AgentAccessStatus.BLOCKED:
            return self._safe_result(
                message="Agent is blocked on this plan.",
                data=self._agent_decision_payload(
                    allowed=False,
                    status=AgentAccessStatus.BLOCKED,
                    plan=plan,
                    agent_key=normalized_agent,
                    action=normalized_action,
                    reason="agent_blocked_by_plan",
                    requires_security_check=False,
                    rule=rule,
                    user_id=user_id,
                    workspace_id=workspace_id,
                    role=role,
                ),
            )

        requires_approval = (
            rule.access == AgentAccessStatus.APPROVAL_REQUIRED
            or normalized_agent in self.SENSITIVE_AGENT_KEYS
            or (
                normalized_action is not None
                and normalized_action in rule.approval_required_actions
            )
        )

        status = (
            AgentAccessStatus.APPROVAL_REQUIRED
            if requires_approval
            else rule.access
        )

        return self._safe_result(
            message="Agent access decision created.",
            data=self._agent_decision_payload(
                allowed=True,
                status=status,
                plan=plan,
                agent_key=normalized_agent,
                action=normalized_action,
                reason="allowed_with_security_policy"
                if requires_approval
                else "allowed_by_plan",
                requires_security_check=requires_approval,
                rule=rule,
                user_id=user_id,
                workspace_id=workspace_id,
                role=role,
            ),
        )

    def get_allowed_agents(self, plan_name: str) -> Dict[str, Any]:
        """Return all agents available on a plan."""

        plan = self._get_plan_or_none(plan_name)
        if not plan:
            return self._error_result(
                message="Plan not found.",
                error="unknown_plan",
                metadata={"plan_name": plan_name},
            )

        allowed = []
        limited = []
        approval_required = []
        blocked = []

        for key, rule in plan.agent_rules.items():
            if rule.access == AgentAccessStatus.ALLOWED:
                allowed.append(key)
            elif rule.access == AgentAccessStatus.LIMITED:
                limited.append(key)
            elif rule.access == AgentAccessStatus.APPROVAL_REQUIRED:
                approval_required.append(key)
            elif rule.access == AgentAccessStatus.BLOCKED:
                blocked.append(key)

        return self._safe_result(
            message="Allowed agents loaded successfully.",
            data={
                "plan_name": plan.name.value,
                "allowed_agents": allowed,
                "limited_agents": limited,
                "approval_required_agents": approval_required,
                "blocked_agents": blocked,
                "agent_rules": {
                    key: rule.to_dict() for key, rule in plan.agent_rules.items()
                },
            },
        )

    # -------------------------------------------------------------------------
    # Feature gate APIs
    # -------------------------------------------------------------------------

    def is_feature_enabled(
        self,
        plan_name: str,
        feature_key: str,
        role: str = "member",
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Check whether a feature is enabled for a plan and role."""

        context_error = self._validate_optional_context(user_id, workspace_id)
        if context_error:
            return context_error

        plan = self._get_plan_or_none(plan_name)
        if not plan:
            return self._error_result(
                message="Plan not found. Feature disabled.",
                error="unknown_plan",
                metadata=self._metadata(user_id, workspace_id, plan_name, feature_key),
            )

        normalized_feature = self._normalize_key(feature_key)
        gate = plan.feature_gates.get(normalized_feature)

        if not gate:
            return self._safe_result(
                message="Feature is not available on this plan.",
                data=self._feature_decision_payload(
                    enabled=False,
                    status=FeatureAccessStatus.DISABLED,
                    plan=plan,
                    feature_key=normalized_feature,
                    gate=None,
                    reason="feature_not_in_plan",
                    role=role,
                    user_id=user_id,
                    workspace_id=workspace_id,
                ),
            )

        if not gate.enabled:
            return self._safe_result(
                message="Feature is disabled on this plan.",
                data=self._feature_decision_payload(
                    enabled=False,
                    status=FeatureAccessStatus.DISABLED,
                    plan=plan,
                    feature_key=normalized_feature,
                    gate=gate,
                    reason="disabled_by_plan",
                    role=role,
                    user_id=user_id,
                    workspace_id=workspace_id,
                ),
            )

        if not self._role_is_allowed(role, gate.minimum_role):
            return self._safe_result(
                message="Role is not allowed to use this feature.",
                data=self._feature_decision_payload(
                    enabled=False,
                    status=FeatureAccessStatus.DISABLED,
                    plan=plan,
                    feature_key=normalized_feature,
                    gate=gate,
                    reason="role_not_allowed",
                    role=role,
                    user_id=user_id,
                    workspace_id=workspace_id,
                ),
            )

        status = (
            FeatureAccessStatus.APPROVAL_REQUIRED
            if gate.approval_required
            else FeatureAccessStatus.ENABLED
        )

        return self._safe_result(
            message="Feature access decision created.",
            data=self._feature_decision_payload(
                enabled=True,
                status=status,
                plan=plan,
                feature_key=normalized_feature,
                gate=gate,
                reason="approval_required"
                if gate.approval_required
                else "enabled_by_plan",
                role=role,
                user_id=user_id,
                workspace_id=workspace_id,
            ),
        )

    def get_feature_gates(self, plan_name: str) -> Dict[str, Any]:
        """Return feature gates for a plan."""

        plan = self._get_plan_or_none(plan_name)
        if not plan:
            return self._error_result(
                message="Plan not found.",
                error="unknown_plan",
                metadata={"plan_name": plan_name},
            )

        return self._safe_result(
            message="Feature gates loaded successfully.",
            data={
                "plan_name": plan.name.value,
                "feature_gates": {
                    key: gate.to_dict() for key, gate in plan.feature_gates.items()
                },
            },
        )

    # -------------------------------------------------------------------------
    # Usage limit APIs
    # -------------------------------------------------------------------------

    def get_usage_limit(self, plan_name: str, usage_key: str) -> Dict[str, Any]:
        """Return one usage limit for a plan."""

        plan = self._get_plan_or_none(plan_name)
        if not plan:
            return self._error_result(
                message="Plan not found.",
                error="unknown_plan",
                metadata={"plan_name": plan_name, "usage_key": usage_key},
            )

        normalized_usage = self._normalize_key(usage_key)
        usage_limit = plan.usage_limits.get(normalized_usage)

        if not usage_limit:
            return self._safe_result(
                message="Usage limit not defined for this plan.",
                data={
                    "plan_name": plan.name.value,
                    "usage_key": normalized_usage,
                    "status": UsageStatus.UNKNOWN_LIMIT.value,
                    "limit": None,
                    "unit": None,
                },
            )

        return self._safe_result(
            message="Usage limit loaded successfully.",
            data={
                "plan_name": plan.name.value,
                "usage_key": normalized_usage,
                "usage_limit": usage_limit.to_dict(),
            },
        )

    def get_usage_limits(self, plan_name: str) -> Dict[str, Any]:
        """Return all usage limits for a plan."""

        plan = self._get_plan_or_none(plan_name)
        if not plan:
            return self._error_result(
                message="Plan not found.",
                error="unknown_plan",
                metadata={"plan_name": plan_name},
            )

        return self._safe_result(
            message="Usage limits loaded successfully.",
            data={
                "plan_name": plan.name.value,
                "usage_limits": {
                    key: limit.to_dict() for key, limit in plan.usage_limits.items()
                },
            },
        )

    def check_usage(
        self,
        plan_name: str,
        usage_key: str,
        current_usage: int,
        requested_amount: int = 1,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Check if a requested usage amount fits within the plan limit.

        Example:
            check_usage("growth", "agent_runs", 720, 1)
        """

        context_error = self._validate_optional_context(user_id, workspace_id)
        if context_error:
            return context_error

        if current_usage < 0:
            return self._error_result(
                message="Current usage cannot be negative.",
                error="invalid_current_usage",
            )

        if requested_amount < 0:
            return self._error_result(
                message="Requested amount cannot be negative.",
                error="invalid_requested_amount",
            )

        plan = self._get_plan_or_none(plan_name)
        if not plan:
            return self._error_result(
                message="Plan not found. Usage check denied.",
                error="unknown_plan",
                metadata=self._metadata(user_id, workspace_id, plan_name, usage_key),
            )

        normalized_usage = self._normalize_key(usage_key)
        usage_limit = plan.usage_limits.get(normalized_usage)

        if not usage_limit:
            return self._safe_result(
                message="Usage limit is not defined. Treating as restricted.",
                data={
                    "allowed": False,
                    "status": UsageStatus.UNKNOWN_LIMIT.value,
                    "plan_name": plan.name.value,
                    "usage_key": normalized_usage,
                    "current_usage": current_usage,
                    "requested_amount": requested_amount,
                    "limit": None,
                    "reason": "usage_limit_not_defined",
                    "metadata": self._metadata(
                        user_id, workspace_id, plan.name.value, normalized_usage
                    ),
                },
            )

        if usage_limit.limit is None:
            return self._safe_result(
                message="Usage is unlimited for this plan.",
                data={
                    "allowed": True,
                    "status": UsageStatus.UNLIMITED.value,
                    "plan_name": plan.name.value,
                    "usage_key": normalized_usage,
                    "current_usage": current_usage,
                    "requested_amount": requested_amount,
                    "limit": None,
                    "remaining": None,
                    "percent_used": None,
                    "reason": "unlimited_usage",
                    "metadata": self._metadata(
                        user_id, workspace_id, plan.name.value, normalized_usage
                    ),
                },
            )

        projected_usage = current_usage + requested_amount
        percent_used = round((projected_usage / usage_limit.limit) * 100, 2)
        remaining = max(0, usage_limit.limit - projected_usage)

        if projected_usage > usage_limit.limit:
            status = UsageStatus.EXCEEDED
            allowed = not usage_limit.hard_limit
            reason = "usage_limit_exceeded"
        elif percent_used >= usage_limit.warning_threshold_percent:
            status = UsageStatus.WARNING
            allowed = True
            reason = "usage_near_limit"
        else:
            status = UsageStatus.OK
            allowed = True
            reason = "usage_allowed"

        return self._safe_result(
            message="Usage decision created.",
            data={
                "allowed": allowed,
                "status": status.value,
                "plan_name": plan.name.value,
                "usage_key": normalized_usage,
                "current_usage": current_usage,
                "requested_amount": requested_amount,
                "projected_usage": projected_usage,
                "limit": usage_limit.limit,
                "remaining": remaining,
                "percent_used": percent_used,
                "unit": usage_limit.unit,
                "hard_limit": usage_limit.hard_limit,
                "reason": reason,
                "metadata": self._metadata(
                    user_id, workspace_id, plan.name.value, normalized_usage
                ),
            },
        )

    # -------------------------------------------------------------------------
    # Dashboard/API helper APIs
    # -------------------------------------------------------------------------

    def get_subscription_snapshot(
        self,
        plan_name: str,
        usage: Optional[Mapping[str, int]] = None,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        role: str = "member",
    ) -> Dict[str, Any]:
        """
        Return plan, usage, feature, and agent snapshot for dashboard/API.

        This is useful for apps/api/subscription_routes.py and the dashboard
        billing/settings pages.
        """

        context_error = self._validate_optional_context(user_id, workspace_id)
        if context_error:
            return context_error

        plan = self._get_plan_or_none(plan_name)
        if not plan:
            return self._error_result(
                message="Plan not found.",
                error="unknown_plan",
                metadata=self._metadata(user_id, workspace_id, plan_name),
            )

        usage = usage or {}
        usage_summary: Dict[str, Any] = {}

        for key, limit in plan.usage_limits.items():
            current_value = int(usage.get(key, 0))
            usage_summary[key] = self.check_usage(
                plan_name=plan.name.value,
                usage_key=key,
                current_usage=current_value,
                requested_amount=0,
                user_id=user_id,
                workspace_id=workspace_id,
            )["data"]

        return self._safe_result(
            message="Subscription snapshot created.",
            data={
                "plan": plan.to_dict(),
                "usage_summary": usage_summary,
                "agent_access": {
                    key: self.is_agent_allowed(
                        plan_name=plan.name.value,
                        agent_key=key,
                        user_id=user_id,
                        workspace_id=workspace_id,
                        role=role,
                    )["data"]
                    for key in plan.agent_rules.keys()
                },
                "feature_access": {
                    key: self.is_feature_enabled(
                        plan_name=plan.name.value,
                        feature_key=key,
                        role=role,
                        user_id=user_id,
                        workspace_id=workspace_id,
                    )["data"]
                    for key in plan.feature_gates.keys()
                },
                "metadata": self._metadata(user_id, workspace_id, plan.name.value),
            },
        )

    def recommend_upgrade(
        self,
        current_plan_name: str,
        required_agent: Optional[str] = None,
        required_feature: Optional[str] = None,
        usage_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Recommend the next plan that supports a missing need."""

        current_plan = self._get_plan_or_none(current_plan_name)
        if not current_plan:
            return self._error_result(
                message="Current plan not found.",
                error="unknown_plan",
                metadata={"current_plan_name": current_plan_name},
            )

        plan_order = [
            PlanName.FREE.value,
            PlanName.STARTER.value,
            PlanName.GROWTH.value,
            PlanName.BUSINESS.value,
            PlanName.ENTERPRISE.value,
        ]
        current_index = plan_order.index(current_plan.name.value)

        candidates = [
            self._plans[name]
            for name in plan_order[current_index + 1 :]
            if name in self._plans
        ]

        normalized_agent = self._normalize_key(required_agent) if required_agent else None
        normalized_feature = (
            self._normalize_key(required_feature) if required_feature else None
        )
        normalized_usage = self._normalize_key(usage_key) if usage_key else None

        for plan in candidates:
            agent_ok = True
            feature_ok = True
            usage_ok = True

            if normalized_agent:
                rule = plan.agent_rules.get(normalized_agent)
                agent_ok = bool(rule and rule.access != AgentAccessStatus.BLOCKED)

            if normalized_feature:
                gate = plan.feature_gates.get(normalized_feature)
                feature_ok = bool(gate and gate.enabled)

            if normalized_usage:
                usage_ok = normalized_usage in plan.usage_limits

            if agent_ok and feature_ok and usage_ok:
                return self._safe_result(
                    message="Upgrade recommendation created.",
                    data={
                        "recommended_plan": plan.to_dict(),
                        "current_plan": current_plan.name.value,
                        "required_agent": normalized_agent,
                        "required_feature": normalized_feature,
                        "usage_key": normalized_usage,
                        "reason": "next_plan_supports_required_access",
                    },
                )

        return self._safe_result(
            message="No higher public plan matched the requirement.",
            data={
                "recommended_plan": None,
                "current_plan": current_plan.name.value,
                "required_agent": normalized_agent,
                "required_feature": normalized_feature,
                "usage_key": normalized_usage,
                "reason": "contact_enterprise_or_custom_policy_required",
            },
        )

    # -------------------------------------------------------------------------
    # Compatibility hooks requested by William architecture
    # -------------------------------------------------------------------------

    def _validate_task_context(self, context: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """
        Validate task context shape for future Master Agent/API integration.

        This method is intentionally permissive for import-safety, but it clearly
        reports missing SaaS isolation fields.
        """

        if context is None:
            return self._error_result(
                message="Task context is required.",
                error="missing_task_context",
            )

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if not user_id or not workspace_id:
            return self._error_result(
                message="Task context must include user_id and workspace_id.",
                error="missing_saas_isolation_fields",
                metadata={
                    "has_user_id": bool(user_id),
                    "has_workspace_id": bool(workspace_id),
                },
            )

        return self._safe_result(
            message="Task context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "role": context.get("role", "member"),
                "plan": context.get("plan", self.get_default_plan_name()),
            },
        )

    def _requires_security_check(
        self,
        agent_key: Optional[str] = None,
        feature_key: Optional[str] = None,
        action: Optional[str] = None,
    ) -> bool:
        """Return whether an access request should pass Security Agent."""

        normalized_agent = self._normalize_key(agent_key) if agent_key else ""
        normalized_feature = self._normalize_key(feature_key) if feature_key else ""
        normalized_action = self._normalize_key(action) if action else ""

        sensitive_keywords = (
            "delete",
            "payment",
            "transfer",
            "terminal",
            "system",
            "browser_submit",
            "external_form",
            "memory_export",
            "call_recording",
            "send_message",
            "deploy",
            "secret",
            "credential",
            "billing",
        )

        if normalized_agent in self.SENSITIVE_AGENT_KEYS:
            return True

        if any(keyword in normalized_feature for keyword in sensitive_keywords):
            return True

        if any(keyword in normalized_action for keyword in sensitive_keywords):
            return True

        return False

    def _request_security_approval(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Prepare a Security Agent approval payload.

        This does not contact Security Agent yet. It returns a structured object
        that future SecurityBridge/SecurityAgent can consume.
        """

        return self._safe_result(
            message="Security approval payload prepared.",
            data={
                "requires_approval": True,
                "approval_type": "subscription_access",
                "payload": dict(payload),
                "recommended_agent": "security_agent",
            },
        )

    def _prepare_verification_payload(self, decision: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare a Verification Agent payload for plan/access decisions."""

        return self._safe_result(
            message="Verification payload prepared.",
            data={
                "verification_type": "subscription_rule_decision",
                "expected_state": "decision_created",
                "decision": dict(decision),
                "recommended_agent": "verification_agent",
            },
        )

    def _prepare_memory_payload(self, decision: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare a Memory Agent payload for useful subscription context."""

        return self._safe_result(
            message="Memory payload prepared.",
            data={
                "memory_type": "subscription_context",
                "importance": "medium",
                "privacy": "workspace",
                "content": dict(decision),
                "recommended_agent": "memory_agent",
            },
        )

    def _emit_agent_event(self, event_name: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare an event payload for future AgentEvents integration."""

        return self._safe_result(
            message="Agent event payload prepared.",
            data={
                "event_name": event_name,
                "source": "subscriptions.plan_rules",
                "payload": dict(payload),
            },
        )

    def _log_audit_event(self, action: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare audit event payload for future Security Agent/Audit Logger."""

        return self._safe_result(
            message="Audit event payload prepared.",
            data={
                "action": action,
                "source": "subscriptions.plan_rules",
                "payload": dict(payload),
            },
        )

    # -------------------------------------------------------------------------
    # Internal plan builders
    # -------------------------------------------------------------------------

    def _build_default_plans(self) -> Dict[str, PlanDefinition]:
        """Build all default William/Jarvis SaaS plan definitions."""

        plans = [
            self._free_plan(),
            self._starter_plan(),
            self._growth_plan(),
            self._business_plan(),
            self._enterprise_plan(),
        ]

        return {plan.name.value: plan for plan in plans}

    def _free_plan(self) -> PlanDefinition:
        return PlanDefinition(
            name=PlanName.FREE,
            display_name="Free",
            monthly_price_usd=0,
            description="For testing the William dashboard with very limited access.",
            max_users=1,
            allowed_roles=("owner",),
            support_level="community",
            recommended_for="Early testing and local development.",
            agent_rules=self._agent_rules(
                allowed=("master_agent", "security_agent", "verification_agent"),
                limited=("memory_agent", "creator_agent"),
                approval_required=(),
                blocked=(
                    "voice_agent",
                    "system_agent",
                    "browser_agent",
                    "code_agent",
                    "visual_agent",
                    "workflow_agent",
                    "hologram_agent",
                    "call_agent",
                    "business_agent",
                    "finance_agent",
                ),
            ),
            feature_gates=self._feature_gates(
                enabled=(
                    "ai_console",
                    "basic_task_history",
                    "basic_security_logs",
                ),
                approval_required=(),
                disabled=(
                    "workspace_memory",
                    "team_roles",
                    "workflow_automation",
                    "billing_invoices",
                    "client_memory",
                    "api_access",
                    "websocket_events",
                    "advanced_verification",
                    "finance_drafts",
                    "call_receptionist",
                ),
            ),
            usage_limits=self._usage_limits(
                agent_runs=50,
                task_records=50,
                memory_items=10,
                workflow_runs=0,
                api_requests=100,
                storage_mb=100,
                team_members=1,
                invoices=0,
                call_minutes=0,
                finance_drafts=0,
            ),
        )

    def _starter_plan(self) -> PlanDefinition:
        return PlanDefinition(
            name=PlanName.STARTER,
            display_name="Starter",
            monthly_price_usd=29,
            description="For small users who need core AI console, basic memory, and task tracking.",
            max_users=2,
            allowed_roles=("owner", "admin", "member", "viewer"),
            support_level="standard",
            recommended_for="Solo operators and small teams.",
            agent_rules=self._agent_rules(
                allowed=(
                    "master_agent",
                    "memory_agent",
                    "security_agent",
                    "verification_agent",
                    "creator_agent",
                    "business_agent",
                ),
                limited=("browser_agent", "code_agent", "workflow_agent"),
                approval_required=("system_agent", "finance_agent"),
                blocked=(
                    "voice_agent",
                    "visual_agent",
                    "hologram_agent",
                    "call_agent",
                ),
            ),
            feature_gates=self._feature_gates(
                enabled=(
                    "ai_console",
                    "basic_task_history",
                    "basic_security_logs",
                    "private_user_memory",
                    "project_memory",
                    "basic_verification",
                    "billing_invoices",
                ),
                approval_required=(
                    "code_file_edits",
                    "finance_drafts",
                    "browser_research",
                ),
                disabled=(
                    "team_memory",
                    "advanced_workflows",
                    "call_receptionist",
                    "voice_mode",
                    "visual_screen_analysis",
                    "hologram_overlay",
                    "enterprise_audit_export",
                ),
            ),
            usage_limits=self._usage_limits(
                agent_runs=300,
                task_records=250,
                memory_items=100,
                workflow_runs=25,
                api_requests=1000,
                storage_mb=500,
                team_members=2,
                invoices=12,
                call_minutes=0,
                finance_drafts=10,
            ),
        )

    def _growth_plan(self) -> PlanDefinition:
        return PlanDefinition(
            name=PlanName.GROWTH,
            display_name="Growth",
            monthly_price_usd=99,
            description="For active businesses using agents, memory, workflows, reports, and approval queues.",
            max_users=5,
            allowed_roles=("owner", "admin", "manager", "member", "viewer"),
            support_level="priority",
            recommended_for="Growing businesses and Digital Promotix client workspaces.",
            agent_rules=self._agent_rules(
                allowed=(
                    "master_agent",
                    "browser_agent",
                    "memory_agent",
                    "security_agent",
                    "verification_agent",
                    "business_agent",
                    "creator_agent",
                ),
                limited=(
                    "voice_agent",
                    "visual_agent",
                    "workflow_agent",
                    "call_agent",
                    "finance_agent",
                ),
                approval_required=("system_agent", "code_agent"),
                blocked=("hologram_agent",),
            ),
            feature_gates=self._feature_gates(
                enabled=(
                    "ai_console",
                    "task_history",
                    "security_approvals",
                    "audit_logs",
                    "private_user_memory",
                    "project_memory",
                    "client_memory",
                    "workspace_memory",
                    "basic_workflows",
                    "billing_invoices",
                    "dashboard_analytics",
                    "verification_reports",
                    "browser_research",
                    "creator_tools",
                ),
                approval_required=(
                    "code_file_edits",
                    "terminal_commands",
                    "finance_drafts",
                    "call_summaries",
                    "external_form_handling",
                    "memory_export",
                ),
                disabled=(
                    "hologram_overlay",
                    "unlimited_workflows",
                    "enterprise_audit_export",
                    "custom_sso",
                ),
            ),
            usage_limits=self._usage_limits(
                agent_runs=1000,
                task_records=1000,
                memory_items=500,
                workflow_runs=250,
                api_requests=10000,
                storage_mb=2500,
                team_members=5,
                invoices=100,
                call_minutes=100,
                finance_drafts=50,
            ),
        )

    def _business_plan(self) -> PlanDefinition:
        return PlanDefinition(
            name=PlanName.BUSINESS,
            display_name="Business",
            monthly_price_usd=249,
            description="For teams needing advanced workflows, higher usage, stronger approvals, and client operations.",
            max_users=15,
            allowed_roles=("owner", "admin", "manager", "member", "viewer"),
            support_level="priority_plus",
            recommended_for="Agencies, sales teams, and operational workspaces.",
            agent_rules=self._agent_rules(
                allowed=(
                    "master_agent",
                    "voice_agent",
                    "browser_agent",
                    "code_agent",
                    "memory_agent",
                    "security_agent",
                    "verification_agent",
                    "visual_agent",
                    "workflow_agent",
                    "call_agent",
                    "business_agent",
                    "finance_agent",
                    "creator_agent",
                ),
                limited=("system_agent",),
                approval_required=("system_agent", "finance_agent", "call_agent"),
                blocked=("hologram_agent",),
            ),
            feature_gates=self._feature_gates(
                enabled=(
                    "ai_console",
                    "task_history",
                    "security_approvals",
                    "audit_logs",
                    "private_user_memory",
                    "project_memory",
                    "client_memory",
                    "team_memory",
                    "workspace_memory",
                    "advanced_workflows",
                    "billing_invoices",
                    "dashboard_analytics",
                    "verification_reports",
                    "browser_research",
                    "creator_tools",
                    "call_receptionist",
                    "visual_screen_analysis",
                    "api_access",
                    "websocket_events",
                    "usage_analytics",
                ),
                approval_required=(
                    "system_actions",
                    "terminal_commands",
                    "finance_drafts",
                    "external_form_handling",
                    "memory_export",
                    "call_recording",
                    "bulk_message_drafts",
                ),
                disabled=("hologram_overlay", "custom_sso"),
            ),
            usage_limits=self._usage_limits(
                agent_runs=5000,
                task_records=5000,
                memory_items=2500,
                workflow_runs=1500,
                api_requests=50000,
                storage_mb=10000,
                team_members=15,
                invoices=500,
                call_minutes=1000,
                finance_drafts=300,
            ),
        )

    def _enterprise_plan(self) -> PlanDefinition:
        return PlanDefinition(
            name=PlanName.ENTERPRISE,
            display_name="Enterprise",
            monthly_price_usd=None,
            description="For large teams requiring custom limits, advanced security, SSO, and dedicated configuration.",
            max_users=None,
            allowed_roles=("owner", "admin", "manager", "member", "viewer"),
            support_level="dedicated",
            recommended_for="Enterprise teams, advanced SaaS deployments, and private infrastructure.",
            agent_rules=self._agent_rules(
                allowed=self.ALL_AGENT_KEYS,
                limited=(),
                approval_required=(
                    "system_agent",
                    "finance_agent",
                    "call_agent",
                    "hologram_agent",
                    "code_agent",
                ),
                blocked=(),
            ),
            feature_gates=self._feature_gates(
                enabled=(
                    "ai_console",
                    "task_history",
                    "security_approvals",
                    "audit_logs",
                    "private_user_memory",
                    "project_memory",
                    "client_memory",
                    "team_memory",
                    "workspace_memory",
                    "advanced_workflows",
                    "billing_invoices",
                    "dashboard_analytics",
                    "verification_reports",
                    "browser_research",
                    "creator_tools",
                    "call_receptionist",
                    "visual_screen_analysis",
                    "api_access",
                    "websocket_events",
                    "usage_analytics",
                    "enterprise_audit_export",
                    "custom_sso",
                    "hologram_overlay",
                    "unlimited_workflows",
                    "custom_agent_permissions",
                ),
                approval_required=(
                    "system_actions",
                    "terminal_commands",
                    "finance_drafts",
                    "external_form_handling",
                    "memory_export",
                    "call_recording",
                    "bulk_message_drafts",
                    "hologram_device_bridge",
                    "custom_deployments",
                ),
                disabled=(),
            ),
            usage_limits=self._usage_limits(
                agent_runs=None,
                task_records=None,
                memory_items=None,
                workflow_runs=None,
                api_requests=None,
                storage_mb=None,
                team_members=None,
                invoices=None,
                call_minutes=None,
                finance_drafts=None,
            ),
            metadata={"requires_contract": True, "custom_limits": True},
        )

    def _agent_rules(
        self,
        allowed: Iterable[str],
        limited: Iterable[str],
        approval_required: Iterable[str],
        blocked: Iterable[str],
    ) -> Dict[str, AgentRule]:
        """Create agent rules for all known agents."""

        allowed_set = {self._normalize_key(item) for item in allowed}
        limited_set = {self._normalize_key(item) for item in limited}
        approval_set = {self._normalize_key(item) for item in approval_required}
        blocked_set = {self._normalize_key(item) for item in blocked}

        rules: Dict[str, AgentRule] = {}

        for agent_key in self.ALL_AGENT_KEYS:
            if agent_key in blocked_set:
                access = AgentAccessStatus.BLOCKED
            elif agent_key in approval_set:
                access = AgentAccessStatus.APPROVAL_REQUIRED
            elif agent_key in limited_set:
                access = AgentAccessStatus.LIMITED
            elif agent_key in allowed_set:
                access = AgentAccessStatus.ALLOWED
            else:
                access = AgentAccessStatus.BLOCKED

            rules[agent_key] = AgentRule(
                agent_key=agent_key,
                label=self._label_from_key(agent_key),
                access=access,
                description=self._agent_description(agent_key),
                approval_required_actions=self._approval_actions_for_agent(agent_key),
                blocked_actions=self._blocked_actions_for_agent(agent_key, access),
                risk_level=self._risk_for_agent(agent_key),
            )

        return rules

    def _feature_gates(
        self,
        enabled: Iterable[str],
        approval_required: Iterable[str],
        disabled: Iterable[str],
    ) -> Dict[str, FeatureGate]:
        """Create feature gate mapping."""

        enabled_set = {self._normalize_key(item) for item in enabled}
        approval_set = {self._normalize_key(item) for item in approval_required}
        disabled_set = {self._normalize_key(item) for item in disabled}

        all_features = sorted(enabled_set | approval_set | disabled_set)
        gates: Dict[str, FeatureGate] = {}

        for feature_key in all_features:
            is_enabled = feature_key in enabled_set or feature_key in approval_set
            requires_approval = feature_key in approval_set

            gates[feature_key] = FeatureGate(
                key=feature_key,
                label=self._label_from_key(feature_key),
                enabled=is_enabled,
                description=f"{self._label_from_key(feature_key)} feature gate.",
                approval_required=requires_approval,
                minimum_role=self._minimum_role_for_feature(feature_key),
                risk_level=self._risk_for_feature(feature_key),
            )

        return gates

    def _usage_limits(
        self,
        agent_runs: Optional[int],
        task_records: Optional[int],
        memory_items: Optional[int],
        workflow_runs: Optional[int],
        api_requests: Optional[int],
        storage_mb: Optional[int],
        team_members: Optional[int],
        invoices: Optional[int],
        call_minutes: Optional[int],
        finance_drafts: Optional[int],
    ) -> Dict[str, UsageLimit]:
        """Create standard usage limit mapping."""

        definitions = {
            "agent_runs": ("Agent Runs", agent_runs, "runs"),
            "task_records": ("Task Records", task_records, "records"),
            "memory_items": ("Memory Items", memory_items, "items"),
            "workflow_runs": ("Workflow Runs", workflow_runs, "runs"),
            "api_requests": ("API Requests", api_requests, "requests"),
            "storage_mb": ("Storage", storage_mb, "MB"),
            "team_members": ("Team Members", team_members, "members"),
            "invoices": ("Invoices", invoices, "invoices"),
            "call_minutes": ("Call Minutes", call_minutes, "minutes"),
            "finance_drafts": ("Finance Drafts", finance_drafts, "drafts"),
        }

        return {
            key: UsageLimit(
                key=key,
                label=label,
                limit=limit,
                unit=unit,
                warning_threshold_percent=80,
                hard_limit=True,
            )
            for key, (label, limit, unit) in definitions.items()
        }

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _get_plan_or_none(self, plan_name: str) -> Optional[PlanDefinition]:
        return self._plans.get(self._normalize_plan_name(plan_name))

    def _normalize_plan_name(self, value: str) -> str:
        if not value:
            return self.get_default_plan_name()
        return str(value).strip().lower().replace(" ", "_").replace("-", "_")

    def _normalize_key(self, value: Optional[str]) -> str:
        if not value:
            return ""
        return str(value).strip().lower().replace(" ", "_").replace("-", "_")

    def _label_from_key(self, key: str) -> str:
        return self._normalize_key(key).replace("_", " ").title()

    def _role_is_allowed(self, actual_role: str, minimum_role: str) -> bool:
        actual = self._normalize_key(actual_role)
        minimum = self._normalize_key(minimum_role)

        if actual not in self.ROLE_ORDER:
            return False

        if minimum not in self.ROLE_ORDER:
            return False

        return self.ROLE_ORDER.index(actual) >= self.ROLE_ORDER.index(minimum)

    def _validate_optional_context(
        self,
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> Optional[Dict[str, Any]]:
        """
        Optional context validator.

        If both values are absent, this method allows import-time/local checks.
        If one is provided without the other, it blocks to avoid SaaS data mixing.
        """

        if user_id is None and workspace_id is None:
            return None

        if not user_id or not workspace_id:
            return self._error_result(
                message="Both user_id and workspace_id are required when context is provided.",
                error="partial_saas_context",
                metadata={
                    "has_user_id": bool(user_id),
                    "has_workspace_id": bool(workspace_id),
                },
            )

        return None

    def _metadata(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        plan_name: Optional[str] = None,
        resource_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "user_id": user_id,
            "workspace_id": workspace_id,
            "plan_name": plan_name,
            "resource_key": resource_key,
            "source": "subscriptions.plan_rules",
        }

    def _agent_decision_payload(
        self,
        allowed: bool,
        status: AgentAccessStatus,
        plan: PlanDefinition,
        agent_key: str,
        action: Optional[str],
        reason: str,
        requires_security_check: bool,
        rule: Optional[AgentRule],
        user_id: Optional[str],
        workspace_id: Optional[str],
        role: str,
    ) -> Dict[str, Any]:
        return {
            "allowed": allowed,
            "status": status.value,
            "plan_name": plan.name.value,
            "agent_key": agent_key,
            "action": action,
            "reason": reason,
            "requires_security_check": requires_security_check,
            "risk_level": rule.risk_level.value if rule else RiskLevel.MEDIUM.value,
            "rule": rule.to_dict() if rule else None,
            "metadata": self._metadata(user_id, workspace_id, plan.name.value, agent_key),
            "role": role,
        }

    def _feature_decision_payload(
        self,
        enabled: bool,
        status: FeatureAccessStatus,
        plan: PlanDefinition,
        feature_key: str,
        gate: Optional[FeatureGate],
        reason: str,
        role: str,
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> Dict[str, Any]:
        return {
            "enabled": enabled,
            "status": status.value,
            "plan_name": plan.name.value,
            "feature_key": feature_key,
            "reason": reason,
            "requires_security_check": gate.approval_required if gate else False,
            "risk_level": gate.risk_level.value if gate else RiskLevel.LOW.value,
            "gate": gate.to_dict() if gate else None,
            "metadata": self._metadata(user_id, workspace_id, plan.name.value, feature_key),
            "role": role,
        }

    def _agent_description(self, agent_key: str) -> str:
        descriptions = {
            "master_agent": "Main planning, routing, orchestration, and response brain.",
            "voice_agent": "Wake word, speech-to-text, text-to-speech, voice sessions.",
            "system_agent": "Apps, files, OS commands, device settings, and automation.",
            "browser_agent": "Search, scraping, page analysis, SEO, competitors, forms.",
            "code_agent": "Project building, file generation, code edits, tests, deployments.",
            "memory_agent": "Short-term, long-term, project, client, team, and preference memory.",
            "security_agent": "Permission checks, approvals, audit logs, risk scoring, emergency lock.",
            "verification_agent": "Proof, validation, state checks, screenshots, reports.",
            "visual_agent": "Screenshots, OCR, UI detection, visual validation, privacy filtering.",
            "workflow_agent": "Automations, webhooks, forms, CRM, notifications, schedules.",
            "hologram_agent": "AR overlays, spatial mapping, gestures, real-world context.",
            "call_agent": "Receptionist mode, call summaries, lead qualification, booking.",
            "business_agent": "CRM, leads, clients, analytics, reports, revenue tracking.",
            "finance_agent": "Invoices, budgets, receipts, finance reports, draft-only transactions.",
            "creator_agent": "Scripts, content, thumbnails, captions, VEO prompts, creative assets.",
        }
        return descriptions.get(agent_key, "William agent.")

    def _risk_for_agent(self, agent_key: str) -> RiskLevel:
        if agent_key in {"system_agent", "finance_agent", "call_agent", "hologram_agent"}:
            return RiskLevel.CRITICAL
        if agent_key in {"code_agent", "browser_agent", "memory_agent", "visual_agent", "workflow_agent"}:
            return RiskLevel.HIGH
        if agent_key in {"security_agent", "master_agent", "business_agent"}:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _risk_for_feature(self, feature_key: str) -> RiskLevel:
        critical_keywords = ("payment", "finance", "system", "terminal", "call_recording", "hologram")
        high_keywords = ("memory_export", "external_form", "workflow", "browser", "api", "sso")

        if any(keyword in feature_key for keyword in critical_keywords):
            return RiskLevel.CRITICAL

        if any(keyword in feature_key for keyword in high_keywords):
            return RiskLevel.HIGH

        if "security" in feature_key or "audit" in feature_key:
            return RiskLevel.MEDIUM

        return RiskLevel.LOW

    def _minimum_role_for_feature(self, feature_key: str) -> str:
        owner_features = (
            "billing",
            "custom_sso",
            "enterprise_audit_export",
            "memory_export",
            "system_actions",
            "terminal_commands",
        )
        admin_features = (
            "security_approvals",
            "audit_logs",
            "advanced_workflows",
            "api_access",
            "websocket_events",
            "finance_drafts",
        )

        if any(key in feature_key for key in owner_features):
            return "owner"

        if any(key in feature_key for key in admin_features):
            return "admin"

        return "member"

    def _approval_actions_for_agent(self, agent_key: str) -> Tuple[str, ...]:
        mapping = {
            "system_agent": (
                "delete_file",
                "move_file",
                "run_os_command",
                "change_device_setting",
                "shutdown",
                "restart",
                "install_app",
            ),
            "browser_agent": (
                "submit_form",
                "login",
                "download_file",
                "scrape_large_site",
                "use_cookies",
            ),
            "code_agent": (
                "edit_file",
                "run_terminal_command",
                "install_dependency",
                "git_commit",
                "deploy",
            ),
            "memory_agent": (
                "save_sensitive_memory",
                "export_memory",
                "forget_memory",
                "share_team_memory",
            ),
            "finance_agent": (
                "create_invoice",
                "prepare_transaction",
                "export_finance_report",
                "read_receipt",
            ),
            "call_agent": (
                "record_call",
                "transcribe_call",
                "dial_number",
                "send_voicemail",
            ),
            "workflow_agent": (
                "send_email",
                "send_whatsapp",
                "activate_webhook",
                "run_external_workflow",
            ),
            "visual_agent": (
                "capture_screen",
                "analyze_private_screen",
                "export_screenshot",
            ),
            "hologram_agent": (
                "activate_device_bridge",
                "show_private_overlay",
                "capture_spatial_map",
            ),
        }
        return mapping.get(agent_key, ())

    def _blocked_actions_for_agent(
        self,
        agent_key: str,
        access: AgentAccessStatus,
    ) -> Tuple[str, ...]:
        if access == AgentAccessStatus.BLOCKED:
            return ("all_actions",)

        if agent_key == "finance_agent":
            return ("auto_pay", "auto_transfer", "submit_payment", "send_money")

        if agent_key == "call_agent":
            return ("record_without_consent", "dial_without_approval")

        if agent_key == "system_agent":
            return ("delete_protected_folder", "wipe_drive", "disable_security")

        return ()

    # -------------------------------------------------------------------------
    # Result helpers
    # -------------------------------------------------------------------------

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
    "PlanRules",
    "PlanName",
    "PlanDefinition",
    "UsageLimit",
    "FeatureGate",
    "AgentRule",
    "AgentAccessStatus",
    "FeatureAccessStatus",
    "UsageStatus",
    "RiskLevel",
]