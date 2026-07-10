"""
William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Subscription System - Access Control

File: subscriptions/access_control.py
Class: AccessControl

Purpose:
    Checks plan, role, user_agent_access, workspace_agent_access, and usage
    limits before agent execution.

Safety:
    - Requires user_id and workspace_id for all execution checks.
    - Never mixes user/workspace access decisions.
    - Does not execute agents.
    - Sensitive agents/actions are routed to Security Agent approval.
    - Every decision is structured for Master Agent, Agent Router, Security Agent,
      Verification Agent, Memory Agent, Dashboard API, and Audit Logger.
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
        """Fallback stub so this file stays import-safe before plan_rules.py exists."""

        def get_default_plan_name(self) -> str:
            return "free"

        def is_agent_allowed(
            self,
            plan_name: str,
            agent_key: str,
            action: Optional[str] = None,
            user_id: Optional[str] = None,
            workspace_id: Optional[str] = None,
            role: str = "member",
        ) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback agent access decision.",
                "data": {
                    "allowed": True,
                    "status": "allowed",
                    "plan_name": plan_name,
                    "agent_key": agent_key,
                    "action": action,
                    "reason": "fallback_plan_rules",
                    "requires_security_check": False,
                    "risk_level": "medium",
                    "metadata": {
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                    "role": role,
                },
                "error": None,
                "metadata": {},
            }

        def is_feature_enabled(
            self,
            plan_name: str,
            feature_key: str,
            role: str = "member",
            user_id: Optional[str] = None,
            workspace_id: Optional[str] = None,
        ) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback feature access decision.",
                "data": {
                    "enabled": True,
                    "status": "enabled",
                    "plan_name": plan_name,
                    "feature_key": feature_key,
                    "reason": "fallback_plan_rules",
                    "requires_security_check": False,
                    "risk_level": "low",
                    "metadata": {
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                    },
                    "role": role,
                },
                "error": None,
                "metadata": {},
            }


try:
    from subscriptions.usage_meter import UsageMeter
except Exception:
    class UsageMeter:  # type: ignore[no-redef]
        """Fallback stub so this file stays import-safe before usage_meter.py exists."""

        def check_usage_allowed(
            self,
            user_id: str,
            workspace_id: str,
            plan_name: str,
            metric: str,
            requested_amount: int = 1,
        ) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback usage allowed.",
                "data": {
                    "decision": {
                        "allowed": True,
                        "status": "allowed",
                        "metric": metric,
                        "current_usage": 0,
                        "requested_amount": requested_amount,
                        "projected_usage": requested_amount,
                        "plan_name": plan_name,
                        "reason": "fallback_usage_meter",
                    }
                },
                "error": None,
                "metadata": {},
            }


class AccessDecisionStatus(str, Enum):
    """Final access decision status."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"
    APPROVAL_REQUIRED = "approval_required"
    LIMITED = "limited"
    USAGE_EXCEEDED = "usage_exceeded"
    ROLE_DENIED = "role_denied"
    PLAN_DENIED = "plan_denied"
    USER_DENIED = "user_denied"
    WORKSPACE_DENIED = "workspace_denied"
    ERROR = "error"


class AccessScope(str, Enum):
    """Access override scope."""

    USER = "user"
    WORKSPACE = "workspace"
    PLAN = "plan"
    ROLE = "role"
    SECURITY = "security"
    USAGE = "usage"


class OverrideMode(str, Enum):
    """User/workspace override behavior."""

    ALLOW = "allow"
    BLOCK = "block"
    APPROVAL_REQUIRED = "approval_required"
    LIMITED = "limited"


class RoleName(str, Enum):
    """Supported SaaS role names."""

    VIEWER = "viewer"
    MEMBER = "member"
    MANAGER = "manager"
    ADMIN = "admin"
    OWNER = "owner"


class RiskLevel(str, Enum):
    """Access decision risk level."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class AccessContext:
    """Required execution context before an agent can run."""

    user_id: str
    workspace_id: str
    plan_name: str
    role: str = "member"
    request_id: Optional[str] = None
    task_id: Optional[str] = None
    source: str = "subscriptions.access_control"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AgentAccessOverride:
    """User-level or workspace-level agent access override."""

    scope: AccessScope
    subject_id: str
    agent_key: str
    mode: OverrideMode
    reason: str
    action: Optional[str] = None
    expires_at: Optional[str] = None
    created_by: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["scope"] = self.scope.value
        data["mode"] = self.mode.value
        data["metadata"] = dict(self.metadata)
        return data


@dataclass(frozen=True)
class AgentExecutionRequest:
    """Agent execution request to be evaluated before routing."""

    user_id: str
    workspace_id: str
    plan_name: str
    role: str
    agent_key: str
    action: Optional[str] = None
    feature_key: Optional[str] = None
    requested_usage_metric: str = "agent_runs"
    requested_usage_amount: int = 1
    request_id: Optional[str] = None
    task_id: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["metadata"] = dict(self.metadata)
        return data


@dataclass(frozen=True)
class AccessDecision:
    """Final access decision returned before agent execution."""

    allowed: bool
    status: AccessDecisionStatus
    message: str
    user_id: str
    workspace_id: str
    plan_name: str
    role: str
    agent_key: str
    action: Optional[str]
    feature_key: Optional[str]
    requires_security_check: bool
    risk_level: RiskLevel
    reason: str
    checks: Mapping[str, Any] = field(default_factory=dict)
    request_id: Optional[str] = None
    task_id: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["risk_level"] = self.risk_level.value
        data["checks"] = dict(self.checks)
        data["metadata"] = dict(self.metadata)
        return data


class AccessControl:
    """
    Access control layer for William/Jarvis.

    This should be called before Master Agent, Agent Router, or Agent Loader
    executes an agent.

    Decision order:
        1. Validate SaaS context
        2. Check role
        3. Check workspace/user overrides
        4. Check plan agent access
        5. Check optional feature gate
        6. Check usage limit
        7. Decide whether Security Agent approval is required
        8. Prepare verification, memory, event, and audit payloads
    """

    ROLE_ORDER: Tuple[str, ...] = (
        RoleName.VIEWER.value,
        RoleName.MEMBER.value,
        RoleName.MANAGER.value,
        RoleName.ADMIN.value,
        RoleName.OWNER.value,
    )

    SENSITIVE_AGENTS: Tuple[str, ...] = (
        "system_agent",
        "browser_agent",
        "code_agent",
        "memory_agent",
        "security_agent",
        "visual_agent",
        "workflow_agent",
        "hologram_agent",
        "call_agent",
        "finance_agent",
    )

    SENSITIVE_ACTION_KEYWORDS: Tuple[str, ...] = (
        "delete",
        "terminal",
        "system",
        "payment",
        "transfer",
        "invoice",
        "billing",
        "cancel",
        "call",
        "record",
        "send",
        "message",
        "email",
        "whatsapp",
        "browser_submit",
        "external_form",
        "login",
        "download",
        "upload",
        "deploy",
        "memory_export",
        "forget_memory",
        "secret",
        "credential",
        "webhook",
    )

    def __init__(
        self,
        plan_rules: Optional[PlanRules] = None,
        usage_meter: Optional[UsageMeter] = None,
        user_agent_overrides: Optional[Iterable[AgentAccessOverride]] = None,
        workspace_agent_overrides: Optional[Iterable[AgentAccessOverride]] = None,
    ) -> None:
        self.plan_rules = plan_rules or PlanRules()
        self.usage_meter = usage_meter or UsageMeter(plan_rules=self.plan_rules)

        self._user_agent_overrides: List[AgentAccessOverride] = list(
            user_agent_overrides or []
        )
        self._workspace_agent_overrides: List[AgentAccessOverride] = list(
            workspace_agent_overrides or []
        )

    # ------------------------------------------------------------------
    # Public access APIs
    # ------------------------------------------------------------------

    def can_execute_agent(
        self,
        request: AgentExecutionRequest,
    ) -> Dict[str, Any]:
        """
        Main access check before agent execution.

        This method does not execute the agent. It only creates a decision.
        """

        context_result = self._validate_task_context(request.to_dict())
        if not context_result["success"]:
            return context_result

        normalized_agent = self._normalize_key(request.agent_key)
        normalized_action = self._normalize_key(request.action) if request.action else None
        normalized_feature = (
            self._normalize_key(request.feature_key) if request.feature_key else None
        )

        checks: Dict[str, Any] = {
            "context": context_result["data"],
            "role": None,
            "workspace_override": None,
            "user_override": None,
            "plan_agent": None,
            "feature_gate": None,
            "usage": None,
            "security": None,
        }

        role_check = self.check_role_access(
            role=request.role,
            minimum_role="member",
            user_id=request.user_id,
            workspace_id=request.workspace_id,
        )
        checks["role"] = role_check.get("data")

        if not role_check["success"] or not role_check["data"]["allowed"]:
            decision = self._build_decision(
                request=request,
                allowed=False,
                status=AccessDecisionStatus.ROLE_DENIED,
                message="Role is not allowed to execute agents.",
                reason="role_not_allowed",
                requires_security_check=False,
                risk_level=RiskLevel.MEDIUM,
                checks=checks,
            )
            return self._finalize_decision(decision)

        workspace_override = self._find_workspace_override(
            workspace_id=request.workspace_id,
            agent_key=normalized_agent,
            action=normalized_action,
        )
        checks["workspace_override"] = (
            workspace_override.to_dict() if workspace_override else None
        )

        workspace_override_decision = self._decision_from_override(
            request=request,
            override=workspace_override,
            denied_status=AccessDecisionStatus.WORKSPACE_DENIED,
            checks=checks,
        )
        if workspace_override_decision is not None:
            return self._finalize_decision(workspace_override_decision)

        user_override = self._find_user_override(
            user_id=request.user_id,
            agent_key=normalized_agent,
            action=normalized_action,
        )
        checks["user_override"] = user_override.to_dict() if user_override else None

        user_override_decision = self._decision_from_override(
            request=request,
            override=user_override,
            denied_status=AccessDecisionStatus.USER_DENIED,
            checks=checks,
        )
        if user_override_decision is not None:
            return self._finalize_decision(user_override_decision)

        plan_agent_check = self.plan_rules.is_agent_allowed(
            plan_name=request.plan_name,
            agent_key=normalized_agent,
            action=normalized_action,
            user_id=request.user_id,
            workspace_id=request.workspace_id,
            role=request.role,
        )
        checks["plan_agent"] = plan_agent_check.get("data")

        if not plan_agent_check.get("success"):
            decision = self._build_decision(
                request=request,
                allowed=False,
                status=AccessDecisionStatus.ERROR,
                message="Plan agent access check failed.",
                reason=str(plan_agent_check.get("error") or "plan_agent_check_failed"),
                requires_security_check=False,
                risk_level=RiskLevel.MEDIUM,
                checks=checks,
            )
            return self._finalize_decision(decision)

        plan_agent_data = plan_agent_check["data"]

        if not plan_agent_data.get("allowed"):
            decision = self._build_decision(
                request=request,
                allowed=False,
                status=AccessDecisionStatus.PLAN_DENIED,
                message="Plan does not allow this agent/action.",
                reason=str(plan_agent_data.get("reason", "plan_denied")),
                requires_security_check=bool(
                    plan_agent_data.get("requires_security_check", False)
                ),
                risk_level=self._risk_from_string(plan_agent_data.get("risk_level")),
                checks=checks,
            )
            return self._finalize_decision(decision)

        if normalized_feature:
            feature_check = self.plan_rules.is_feature_enabled(
                plan_name=request.plan_name,
                feature_key=normalized_feature,
                role=request.role,
                user_id=request.user_id,
                workspace_id=request.workspace_id,
            )
            checks["feature_gate"] = feature_check.get("data")

            if not feature_check.get("success"):
                decision = self._build_decision(
                    request=request,
                    allowed=False,
                    status=AccessDecisionStatus.ERROR,
                    message="Feature access check failed.",
                    reason=str(feature_check.get("error") or "feature_check_failed"),
                    requires_security_check=False,
                    risk_level=RiskLevel.MEDIUM,
                    checks=checks,
                )
                return self._finalize_decision(decision)

            feature_data = feature_check["data"]
            if not feature_data.get("enabled"):
                decision = self._build_decision(
                    request=request,
                    allowed=False,
                    status=AccessDecisionStatus.PLAN_DENIED,
                    message="Plan or role does not allow this feature.",
                    reason=str(feature_data.get("reason", "feature_denied")),
                    requires_security_check=bool(
                        feature_data.get("requires_security_check", False)
                    ),
                    risk_level=self._risk_from_string(feature_data.get("risk_level")),
                    checks=checks,
                )
                return self._finalize_decision(decision)

        usage_check = self.usage_meter.check_usage_allowed(
            user_id=request.user_id,
            workspace_id=request.workspace_id,
            plan_name=request.plan_name,
            metric=request.requested_usage_metric,
            requested_amount=request.requested_usage_amount,
        )
        checks["usage"] = usage_check.get("data", {}).get("decision")

        if not usage_check.get("success"):
            decision = self._build_decision(
                request=request,
                allowed=False,
                status=AccessDecisionStatus.ERROR,
                message="Usage check failed.",
                reason=str(usage_check.get("error") or "usage_check_failed"),
                requires_security_check=False,
                risk_level=RiskLevel.MEDIUM,
                checks=checks,
            )
            return self._finalize_decision(decision)

        usage_decision = usage_check["data"]["decision"]
        if not usage_decision.get("allowed"):
            decision = self._build_decision(
                request=request,
                allowed=False,
                status=AccessDecisionStatus.USAGE_EXCEEDED,
                message="Usage limit blocks this execution.",
                reason=str(usage_decision.get("reason", "usage_exceeded")),
                requires_security_check=False,
                risk_level=RiskLevel.MEDIUM,
                checks=checks,
            )
            return self._finalize_decision(decision)

        security_required = bool(plan_agent_data.get("requires_security_check")) or self._requires_security_check(
            agent_key=normalized_agent,
            action=normalized_action,
            feature_key=normalized_feature,
        )

        if normalized_feature and checks["feature_gate"]:
            security_required = security_required or bool(
                checks["feature_gate"].get("requires_security_check")
            )

        checks["security"] = {
            "requires_security_check": security_required,
            "reason": "sensitive_agent_or_action" if security_required else "not_required",
        }

        if security_required:
            decision = self._build_decision(
                request=request,
                allowed=False,
                status=AccessDecisionStatus.APPROVAL_REQUIRED,
                message="Security Agent approval is required before execution.",
                reason="security_approval_required",
                requires_security_check=True,
                risk_level=max(
                    self._risk_from_string(plan_agent_data.get("risk_level")),
                    self._risk_for_agent_action(normalized_agent, normalized_action),
                    key=lambda risk: self._risk_rank(risk),
                ),
                checks=checks,
            )
            return self._finalize_decision(decision)

        plan_status = str(plan_agent_data.get("status", "allowed"))
        status = (
            AccessDecisionStatus.LIMITED
            if plan_status == "limited"
            else AccessDecisionStatus.ALLOWED
        )

        decision = self._build_decision(
            request=request,
            allowed=True,
            status=status,
            message="Agent execution is allowed.",
            reason="all_access_checks_passed",
            requires_security_check=False,
            risk_level=self._risk_from_string(plan_agent_data.get("risk_level")),
            checks=checks,
        )

        return self._finalize_decision(decision)

    def can_execute(
        self,
        user_id: str,
        workspace_id: str,
        plan_name: str,
        role: str,
        agent_key: str,
        action: Optional[str] = None,
        feature_key: Optional[str] = None,
        requested_usage_metric: str = "agent_runs",
        requested_usage_amount: int = 1,
        request_id: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Convenience wrapper for can_execute_agent()."""

        request = AgentExecutionRequest(
            user_id=user_id,
            workspace_id=workspace_id,
            plan_name=plan_name,
            role=role,
            agent_key=agent_key,
            action=action,
            feature_key=feature_key,
            requested_usage_metric=requested_usage_metric,
            requested_usage_amount=requested_usage_amount,
            request_id=request_id,
            task_id=task_id,
            metadata=dict(metadata or {}),
        )

        return self.can_execute_agent(request)

    def check_role_access(
        self,
        role: str,
        minimum_role: str,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Check role hierarchy."""

        actual = self._normalize_key(role)
        minimum = self._normalize_key(minimum_role)

        if actual not in self.ROLE_ORDER:
            return self._safe_result(
                message="Role is not recognized.",
                data={
                    "allowed": False,
                    "role": role,
                    "minimum_role": minimum_role,
                    "reason": "unknown_role",
                },
                metadata=self._metadata(user_id, workspace_id, "check_role_access"),
            )

        if minimum not in self.ROLE_ORDER:
            return self._safe_result(
                message="Minimum role is not recognized.",
                data={
                    "allowed": False,
                    "role": role,
                    "minimum_role": minimum_role,
                    "reason": "unknown_minimum_role",
                },
                metadata=self._metadata(user_id, workspace_id, "check_role_access"),
            )

        allowed = self.ROLE_ORDER.index(actual) >= self.ROLE_ORDER.index(minimum)

        return self._safe_result(
            message="Role access decision created.",
            data={
                "allowed": allowed,
                "role": actual,
                "minimum_role": minimum,
                "reason": "role_allowed" if allowed else "role_below_required_level",
            },
            metadata=self._metadata(user_id, workspace_id, "check_role_access"),
        )

    def add_user_agent_override(
        self,
        user_id: str,
        workspace_id: str,
        agent_key: str,
        mode: OverrideMode,
        reason: str,
        action: Optional[str] = None,
        created_by: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Add user-specific agent access override."""

        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "action": "add_user_agent_override",
            }
        )
        if not context_result["success"]:
            return context_result

        override = AgentAccessOverride(
            scope=AccessScope.USER,
            subject_id=user_id,
            agent_key=self._normalize_key(agent_key),
            mode=mode,
            reason=reason,
            action=self._normalize_key(action) if action else None,
            created_by=created_by,
            metadata={
                **dict(metadata or {}),
                "workspace_id": workspace_id,
            },
        )

        self._user_agent_overrides.append(override)

        payload = {"override": override.to_dict()}

        return self._safe_result(
            message="User agent override added.",
            data={
                **payload,
                "audit_event": self._log_audit_event("add_user_agent_override", payload)["data"],
                "verification_payload": self._prepare_verification_payload(payload)["data"],
            },
            metadata=self._metadata(user_id, workspace_id, "add_user_agent_override", agent_key),
        )

    def add_workspace_agent_override(
        self,
        workspace_id: str,
        user_id: str,
        agent_key: str,
        mode: OverrideMode,
        reason: str,
        action: Optional[str] = None,
        created_by: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Add workspace-specific agent access override."""

        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "action": "add_workspace_agent_override",
            }
        )
        if not context_result["success"]:
            return context_result

        override = AgentAccessOverride(
            scope=AccessScope.WORKSPACE,
            subject_id=workspace_id,
            agent_key=self._normalize_key(agent_key),
            mode=mode,
            reason=reason,
            action=self._normalize_key(action) if action else None,
            created_by=created_by,
            metadata=dict(metadata or {}),
        )

        self._workspace_agent_overrides.append(override)

        payload = {"override": override.to_dict()}

        return self._safe_result(
            message="Workspace agent override added.",
            data={
                **payload,
                "audit_event": self._log_audit_event("add_workspace_agent_override", payload)["data"],
                "verification_payload": self._prepare_verification_payload(payload)["data"],
            },
            metadata=self._metadata(user_id, workspace_id, "add_workspace_agent_override", agent_key),
        )

    def list_overrides(
        self,
        user_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """List overrides scoped to one user and workspace."""

        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "action": "list_overrides",
            }
        )
        if not context_result["success"]:
            return context_result

        user_overrides = [
            override.to_dict()
            for override in self._user_agent_overrides
            if override.subject_id == user_id
            and override.metadata.get("workspace_id") == workspace_id
        ]

        workspace_overrides = [
            override.to_dict()
            for override in self._workspace_agent_overrides
            if override.subject_id == workspace_id
        ]

        return self._safe_result(
            message="Access overrides loaded.",
            data={
                "user_overrides": user_overrides,
                "workspace_overrides": workspace_overrides,
                "count": len(user_overrides) + len(workspace_overrides),
            },
            metadata=self._metadata(user_id, workspace_id, "list_overrides"),
        )

    def get_access_dashboard_snapshot(
        self,
        user_id: str,
        workspace_id: str,
        plan_name: str,
        role: str,
        agent_keys: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        """Return dashboard-ready access snapshot for agents."""

        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "plan_name": plan_name,
                "role": role,
                "action": "get_access_dashboard_snapshot",
            }
        )
        if not context_result["success"]:
            return context_result

        if agent_keys is None:
            agent_keys = getattr(self.plan_rules, "ALL_AGENT_KEYS", ())

        decisions: Dict[str, Any] = {}

        for agent_key in agent_keys:
            result = self.can_execute(
                user_id=user_id,
                workspace_id=workspace_id,
                plan_name=plan_name,
                role=role,
                agent_key=agent_key,
                requested_usage_amount=0,
            )
            decisions[self._normalize_key(agent_key)] = result.get("data", {}).get("decision")

        overrides = self.list_overrides(user_id=user_id, workspace_id=workspace_id)

        return self._safe_result(
            message="Access dashboard snapshot created.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "plan_name": plan_name,
                "role": role,
                "agent_decisions": decisions,
                "overrides": overrides.get("data", {}),
            },
            metadata=self._metadata(user_id, workspace_id, "get_access_dashboard_snapshot"),
        )

    # ------------------------------------------------------------------
    # William compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """Validate SaaS context before access checks."""

        if context is None:
            return self._error_result(
                message="Access context is required.",
                error="missing_context",
            )

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")

        if not user_id or not workspace_id:
            return self._error_result(
                message="Access checks require user_id and workspace_id.",
                error="missing_saas_isolation_fields",
                metadata={
                    "has_user_id": bool(user_id),
                    "has_workspace_id": bool(workspace_id),
                },
            )

        if context.get("requested_usage_amount") is not None:
            try:
                amount = int(context["requested_usage_amount"])
            except Exception:
                return self._error_result(
                    message="requested_usage_amount must be an integer.",
                    error="invalid_requested_usage_amount",
                )
            if amount < 0:
                return self._error_result(
                    message="requested_usage_amount cannot be negative.",
                    error="negative_requested_usage_amount",
                )

        return self._safe_result(
            message="Access context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "plan_name": context.get("plan_name"),
                "role": context.get("role", "member"),
                "agent_key": context.get("agent_key"),
                "action": context.get("action"),
                "request_id": context.get("request_id"),
                "task_id": context.get("task_id"),
            },
        )

    def _requires_security_check(
        self,
        agent_key: Optional[str] = None,
        action: Optional[str] = None,
        feature_key: Optional[str] = None,
    ) -> bool:
        """Return whether access decision requires Security Agent approval."""

        normalized_agent = self._normalize_key(agent_key)
        normalized_action = self._normalize_key(action)
        normalized_feature = self._normalize_key(feature_key)

        if normalized_agent in self.SENSITIVE_AGENTS:
            return True

        for keyword in self.SENSITIVE_ACTION_KEYWORDS:
            if keyword in normalized_action or keyword in normalized_feature:
                return True

        return False

    def _request_security_approval(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare Security Agent approval payload."""

        return self._safe_result(
            message="Security approval payload prepared.",
            data={
                "requires_approval": True,
                "approval_type": "agent_execution_access",
                "recommended_agent": "security_agent",
                "payload": dict(payload),
            },
        )

    def _prepare_verification_payload(self, decision: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare Verification Agent payload for access decisions."""

        return self._safe_result(
            message="Verification payload prepared.",
            data={
                "verification_type": "access_control_decision",
                "expected_state": "agent_execution_access_checked",
                "recommended_agent": "verification_agent",
                "decision": dict(decision),
            },
        )

    def _prepare_memory_payload(self, decision: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare Memory Agent payload for useful access context."""

        return self._safe_result(
            message="Memory payload prepared.",
            data={
                "memory_type": "access_control_context",
                "privacy": "workspace",
                "importance": "medium",
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
                "source": "subscriptions.access_control",
                "payload": dict(payload),
            },
        )

    def _log_audit_event(self, action: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare audit payload for future audit logger."""

        return self._safe_result(
            message="Audit event payload prepared.",
            data={
                "action": action,
                "source": "subscriptions.access_control",
                "payload": dict(payload),
                "created_at": self._now_iso(),
            },
        )

    # ------------------------------------------------------------------
    # Internal decision helpers
    # ------------------------------------------------------------------

    def _decision_from_override(
        self,
        request: AgentExecutionRequest,
        override: Optional[AgentAccessOverride],
        denied_status: AccessDecisionStatus,
        checks: Mapping[str, Any],
    ) -> Optional[AccessDecision]:
        """Convert an override into a final decision when relevant."""

        if override is None:
            return None

        if override.mode == OverrideMode.BLOCK:
            return self._build_decision(
                request=request,
                allowed=False,
                status=denied_status,
                message="Agent execution blocked by access override.",
                reason=override.reason,
                requires_security_check=False,
                risk_level=RiskLevel.HIGH,
                checks=checks,
            )

        if override.mode == OverrideMode.APPROVAL_REQUIRED:
            return self._build_decision(
                request=request,
                allowed=False,
                status=AccessDecisionStatus.APPROVAL_REQUIRED,
                message="Agent execution requires approval by access override.",
                reason=override.reason,
                requires_security_check=True,
                risk_level=RiskLevel.HIGH,
                checks=checks,
            )

        if override.mode == OverrideMode.LIMITED:
            return None

        if override.mode == OverrideMode.ALLOW:
            return None

        return None

    def _build_decision(
        self,
        request: AgentExecutionRequest,
        allowed: bool,
        status: AccessDecisionStatus,
        message: str,
        reason: str,
        requires_security_check: bool,
        risk_level: RiskLevel,
        checks: Mapping[str, Any],
    ) -> AccessDecision:
        """Build a consistent AccessDecision object."""

        return AccessDecision(
            allowed=allowed,
            status=status,
            message=message,
            user_id=request.user_id,
            workspace_id=request.workspace_id,
            plan_name=request.plan_name,
            role=request.role,
            agent_key=self._normalize_key(request.agent_key),
            action=self._normalize_key(request.action) if request.action else None,
            feature_key=self._normalize_key(request.feature_key) if request.feature_key else None,
            requires_security_check=requires_security_check,
            risk_level=risk_level,
            reason=reason,
            checks=dict(checks),
            request_id=request.request_id,
            task_id=request.task_id,
            metadata={
                **dict(request.metadata),
                "source": "subscriptions.access_control",
            },
        )

    def _finalize_decision(self, decision: AccessDecision) -> Dict[str, Any]:
        """Attach security, verification, memory, event, and audit payloads."""

        decision_data = decision.to_dict()

        security_approval = None
        if decision.requires_security_check:
            security_approval = self._request_security_approval(decision_data)["data"]

        verification_payload = self._prepare_verification_payload(decision_data)["data"]
        memory_payload = self._prepare_memory_payload(decision_data)["data"]
        event_payload = self._emit_agent_event(
            "access_control.decision_created",
            decision_data,
        )["data"]
        audit_event = self._log_audit_event(
            "agent_execution_access_checked",
            decision_data,
        )["data"]

        return self._safe_result(
            message=decision.message,
            data={
                "decision": decision_data,
                "security_approval": security_approval,
                "verification_payload": verification_payload,
                "memory_payload": memory_payload,
                "event": event_payload,
                "audit_event": audit_event,
            },
            metadata=self._metadata(
                user_id=decision.user_id,
                workspace_id=decision.workspace_id,
                action="finalize_access_decision",
                resource_key=decision.agent_key,
            ),
        )

    def _find_user_override(
        self,
        user_id: str,
        agent_key: str,
        action: Optional[str],
    ) -> Optional[AgentAccessOverride]:
        """Find matching user-level override."""

        for override in reversed(self._user_agent_overrides):
            if override.subject_id != user_id:
                continue
            if override.agent_key != agent_key:
                continue
            if override.action and override.action != action:
                continue
            if self._is_expired(override.expires_at):
                continue
            return override

        return None

    def _find_workspace_override(
        self,
        workspace_id: str,
        agent_key: str,
        action: Optional[str],
    ) -> Optional[AgentAccessOverride]:
        """Find matching workspace-level override."""

        for override in reversed(self._workspace_agent_overrides):
            if override.subject_id != workspace_id:
                continue
            if override.agent_key != agent_key:
                continue
            if override.action and override.action != action:
                continue
            if self._is_expired(override.expires_at):
                continue
            return override

        return None

    def _is_expired(self, expires_at: Optional[str]) -> bool:
        """Check ISO timestamp expiration safely."""

        if not expires_at:
            return False

        try:
            expires = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except Exception:
            return True

        return datetime.now(timezone.utc) > expires.astimezone(timezone.utc)

    def _risk_for_agent_action(
        self,
        agent_key: Optional[str],
        action: Optional[str],
    ) -> RiskLevel:
        """Calculate conservative risk level for agent/action."""

        normalized_agent = self._normalize_key(agent_key)
        normalized_action = self._normalize_key(action)

        if normalized_agent in {"system_agent", "finance_agent", "call_agent", "hologram_agent"}:
            return RiskLevel.CRITICAL

        if normalized_agent in {
            "browser_agent",
            "code_agent",
            "memory_agent",
            "visual_agent",
            "workflow_agent",
        }:
            return RiskLevel.HIGH

        if any(keyword in normalized_action for keyword in self.SENSITIVE_ACTION_KEYWORDS):
            return RiskLevel.HIGH

        if normalized_agent in {"master_agent", "security_agent", "business_agent"}:
            return RiskLevel.MEDIUM

        return RiskLevel.LOW

    def _risk_from_string(self, value: Optional[str]) -> RiskLevel:
        """Parse risk level safely."""

        normalized = self._normalize_key(value)

        try:
            return RiskLevel(normalized)
        except ValueError:
            return RiskLevel.MEDIUM

    def _risk_rank(self, risk: RiskLevel) -> int:
        """Risk ordering helper."""

        order = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }
        return order.get(risk, 2)

    def _normalize_key(self, value: Optional[str]) -> str:
        if not value:
            return ""
        return str(value).strip().lower().replace(" ", "_").replace("-", "_")

    def _now_iso(self) -> str:
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
            "source": "subscriptions.access_control",
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
    "AccessControl",
    "AccessDecisionStatus",
    "AccessScope",
    "OverrideMode",
    "RoleName",
    "RiskLevel",
    "AccessContext",
    "AgentAccessOverride",
    "AgentExecutionRequest",
    "AccessDecision",
]