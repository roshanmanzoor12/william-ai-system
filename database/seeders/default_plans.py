"""
database/seeders/default_plans.py

Default SaaS plan, role, permission, and agent-access seeder for the
William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
    - Define starter SaaS plans.
    - Define workspace roles.
    - Define permissions.
    - Define default agent availability per plan.
    - Provide safe seeding helpers for future database integration.
    - Emit audit, memory, security, and verification-ready payloads.

Design goals:
    - Import safely even when future database model files do not exist.
    - Never hardcode secrets.
    - Keep all user/workspace actions isolated.
    - Route sensitive/state-changing actions through security approval hooks.
    - Return structured responses instead of raising unsafe raw errors.
"""

from __future__ import annotations

import copy
import os
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from sqlalchemy import DateTime


ISODateTime = str
JSONDict = Dict[str, Any]


class SeederStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    NEEDS_APPROVAL = "needs_approval"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BillingInterval(str, Enum):
    MONTHLY = "monthly"
    YEARLY = "yearly"


class PlanTier(str, Enum):
    FREE = "free"
    STARTER = "starter"
    GROWTH = "growth"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


@dataclass(frozen=True)
class PermissionDefinition:
    key: str
    name: str
    description: str
    category: str
    sensitive: bool = False

    def to_dict(self) -> JSONDict:
        return asdict(self)


@dataclass(frozen=True)
class RoleDefinition:
    key: str
    name: str
    description: str
    permissions: Tuple[str, ...]
    system_role: bool = True
    workspace_scoped: bool = True

    def to_dict(self) -> JSONDict:
        data = asdict(self)
        data["permissions"] = list(self.permissions)
        return data


@dataclass(frozen=True)
class AgentDefinition:
    key: str
    name: str
    description: str
    enabled_by_default: bool
    requires_security_review: bool
    permissions_required: Tuple[str, ...]
    risk_level: RiskLevel = RiskLevel.LOW

    def to_dict(self) -> JSONDict:
        data = asdict(self)
        data["risk_level"] = self.risk_level.value
        data["permissions_required"] = list(self.permissions_required)
        # database.models.agent_registry.AgentRegistry's real columns are
        # agent_key/agent_name/display_name, not this dataclass's shorter
        # key/name -- _make_model_instance() passes this dict straight into
        # AgentRegistry(**record), and a plain TypeError-catching fallback
        # silently left agent_key/agent_name/display_name as None (NOT NULL
        # constraint failure) rather than raising a clear error. Add the
        # DB-column-named aliases without removing key/name, which other
        # seed-summary/permission-building code in this file still reads.
        data["agent_key"] = self.key
        data["agent_name"] = self.key
        data["display_name"] = self.name
        return data


@dataclass(frozen=True)
class PlanDefinition:
    key: str
    name: str
    tier: PlanTier
    description: str
    monthly_price_cents: int
    yearly_price_cents: int
    currency: str
    billing_intervals: Tuple[BillingInterval, ...]
    included_roles: Tuple[str, ...]
    included_permissions: Tuple[str, ...]
    included_agents: Tuple[str, ...]
    limits: Mapping[str, int]
    features: Tuple[str, ...]
    is_public: bool = True
    is_default: bool = False
    requires_sales_contact: bool = False

    def to_dict(self) -> JSONDict:
        return {
            "key": self.key,
            "name": self.name,
            "tier": self.tier.value,
            "description": self.description,
            "monthly_price_cents": self.monthly_price_cents,
            "yearly_price_cents": self.yearly_price_cents,
            "currency": self.currency,
            "billing_intervals": [interval.value for interval in self.billing_intervals],
            "included_roles": list(self.included_roles),
            "included_permissions": list(self.included_permissions),
            "included_agents": list(self.included_agents),
            "limits": dict(self.limits),
            "features": list(self.features),
            "is_public": self.is_public,
            "is_default": self.is_default,
            "requires_sales_contact": self.requires_sales_contact,
        }


@dataclass
class SeederContext:
    actor_user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = "database.seeders.default_plans"
    dry_run: bool = False
    force: bool = False
    approved_by_security: bool = False
    metadata: JSONDict = field(default_factory=dict)

    def validate(self) -> None:
        if not self.actor_user_id or not isinstance(self.actor_user_id, str):
            raise ValueError("actor_user_id is required for seeding actions.")
        if not self.workspace_id or not isinstance(self.workspace_id, str):
            raise ValueError("workspace_id is required for seeding actions.")


@dataclass
class SeederResponse:
    status: SeederStatus
    message: str
    request_id: str
    workspace_id: str
    actor_user_id: str
    seeded: JSONDict = field(default_factory=dict)
    skipped: JSONDict = field(default_factory=dict)
    errors: List[JSONDict] = field(default_factory=list)
    audit_event: Optional[JSONDict] = None
    memory_payload: Optional[JSONDict] = None
    verification_payload: Optional[JSONDict] = None
    security_payload: Optional[JSONDict] = None

    def to_dict(self) -> JSONDict:
        return {
            "status": self.status.value,
            "message": self.message,
            "request_id": self.request_id,
            "workspace_id": self.workspace_id,
            "actor_user_id": self.actor_user_id,
            "seeded": self.seeded,
            "skipped": self.skipped,
            "errors": self.errors,
            "audit_event": self.audit_event,
            "memory_payload": self.memory_payload,
            "verification_payload": self.verification_payload,
            "security_payload": self.security_payload,
        }


class DefaultPlans:
    """
    Seeder for starter SaaS plans, roles, permissions, and agents.

    This class can be used in three modes:

    1. Pure payload mode:
        DefaultPlans.build_seed_payload()

    2. Dry-run mode:
        DefaultPlans.seed(context=SeederContext(..., dry_run=True))

    3. Database mode:
        DefaultPlans.seed(session=db_session, context=SeederContext(...))

    Database mode is intentionally duck-typed. If model classes are not available,
    the seeder returns a safe skipped response instead of breaking imports.
    """

    MODULE_NAME = "DefaultPlans"
    VERSION = "1.0.0"

    DEFAULT_CURRENCY = os.getenv("WILLIAM_DEFAULT_CURRENCY", "USD").upper()
    ENTERPRISE_CONTACT_URL = os.getenv("WILLIAM_ENTERPRISE_CONTACT_URL", "")

    PERMISSIONS: Tuple[PermissionDefinition, ...] = (
        PermissionDefinition(
            key="workspace.read",
            name="Read Workspace",
            description="View workspace profile, settings, members, and safe metadata.",
            category="workspace",
        ),
        PermissionDefinition(
            key="workspace.update",
            name="Update Workspace",
            description="Update workspace settings and non-sensitive configuration.",
            category="workspace",
            sensitive=True,
        ),
        PermissionDefinition(
            key="members.invite",
            name="Invite Members",
            description="Invite users to a workspace with role-based access.",
            category="workspace",
            sensitive=True,
        ),
        PermissionDefinition(
            key="members.manage",
            name="Manage Members",
            description="Update member roles, deactivate access, and review permissions.",
            category="workspace",
            sensitive=True,
        ),
        PermissionDefinition(
            key="tasks.create",
            name="Create Tasks",
            description="Create user/workspace-isolated AI tasks.",
            category="tasks",
        ),
        PermissionDefinition(
            key="tasks.run",
            name="Run Tasks",
            description="Execute approved AI tasks through Master Agent routing.",
            category="tasks",
        ),
        PermissionDefinition(
            key="tasks.cancel",
            name="Cancel Tasks",
            description="Cancel running or queued tasks within the same workspace.",
            category="tasks",
        ),
        PermissionDefinition(
            key="tasks.history.read",
            name="Read Task History",
            description="View isolated task history and progress events.",
            category="tasks",
        ),
        PermissionDefinition(
            key="memory.read",
            name="Read Memory",
            description="Read workspace-scoped Memory Agent context.",
            category="memory",
            sensitive=True,
        ),
        PermissionDefinition(
            key="memory.write",
            name="Write Memory",
            description="Save useful workspace-scoped context to Memory Agent.",
            category="memory",
            sensitive=True,
        ),
        PermissionDefinition(
            key="files.read",
            name="Read Files",
            description="Read files belonging to the same user and workspace.",
            category="files",
            sensitive=True,
        ),
        PermissionDefinition(
            key="files.write",
            name="Write Files",
            description="Create or update files inside the same user/workspace boundary.",
            category="files",
            sensitive=True,
        ),
        PermissionDefinition(
            key="analytics.read",
            name="Read Analytics",
            description="View dashboard analytics for the current workspace.",
            category="analytics",
        ),
        PermissionDefinition(
            key="billing.read",
            name="Read Billing",
            description="View plan, subscription, and usage status.",
            category="billing",
            sensitive=True,
        ),
        PermissionDefinition(
            key="billing.manage",
            name="Manage Billing",
            description="Change plans, update billing state, and manage subscription access.",
            category="billing",
            sensitive=True,
        ),
        PermissionDefinition(
            key="security.audit.read",
            name="Read Audit Logs",
            description="View security audit events and risk decisions.",
            category="security",
            sensitive=True,
        ),
        PermissionDefinition(
            key="security.approve",
            name="Approve Sensitive Actions",
            description="Approve or reject sensitive actions routed through Security Agent.",
            category="security",
            sensitive=True,
        ),
        PermissionDefinition(
            key="agents.master.use",
            name="Use Master Agent",
            description="Route tasks through the Master Agent.",
            category="agents",
        ),
        PermissionDefinition(
            key="agents.voice.use",
            name="Use Voice Agent",
            description="Use voice-based input and output workflows.",
            category="agents",
        ),
        PermissionDefinition(
            key="agents.system.use",
            name="Use System Agent",
            description="Request system-level automation with strict approval checks.",
            category="agents",
            sensitive=True,
        ),
        PermissionDefinition(
            key="agents.browser.use",
            name="Use Browser Agent",
            description="Use browser workflows and safe web navigation tasks.",
            category="agents",
        ),
        PermissionDefinition(
            key="agents.code.use",
            name="Use Code Agent",
            description="Generate, inspect, and refactor code safely.",
            category="agents",
        ),
        PermissionDefinition(
            key="agents.memory.use",
            name="Use Memory Agent",
            description="Use contextual memory features within workspace isolation.",
            category="agents",
            sensitive=True,
        ),
        PermissionDefinition(
            key="agents.security.use",
            name="Use Security Agent",
            description="Request risk checks, approvals, and policy decisions.",
            category="agents",
            sensitive=True,
        ),
        PermissionDefinition(
            key="agents.verification.use",
            name="Use Verification Agent",
            description="Confirm completed actions and produce verification payloads.",
            category="agents",
        ),
        PermissionDefinition(
            key="agents.visual.use",
            name="Use Visual Agent",
            description="Analyze or generate visual content within safe limits.",
            category="agents",
        ),
        PermissionDefinition(
            key="agents.workflow.use",
            name="Use Workflow Agent",
            description="Build and run multi-step workflow automations.",
            category="agents",
        ),
        PermissionDefinition(
            key="agents.hologram.use",
            name="Use Hologram Agent",
            description="Use futuristic avatar, visual assistant, or hologram features.",
            category="agents",
        ),
        PermissionDefinition(
            key="agents.call.use",
            name="Use Call Agent",
            description="Manage call workflows with consent and audit requirements.",
            category="agents",
            sensitive=True,
        ),
        PermissionDefinition(
            key="agents.business.use",
            name="Use Business Agent",
            description="Use CRM, leads, clients, deals, and campaign workflows.",
            category="agents",
        ),
        PermissionDefinition(
            key="agents.finance.use",
            name="Use Finance Agent",
            description="Use invoices, expenses, receipts, and subscription workflows.",
            category="agents",
            sensitive=True,
        ),
        PermissionDefinition(
            key="agents.creator.use",
            name="Use Creator Agent",
            description="Create marketing content, campaigns, scripts, and assets.",
            category="agents",
        ),
        PermissionDefinition(
            key="integrations.manage",
            name="Manage Integrations",
            description="Connect or disconnect external integrations after approval.",
            category="integrations",
            sensitive=True,
        ),
        PermissionDefinition(
            key="plugins.manage",
            name="Manage Plugins",
            description="Enable, disable, or configure registry/plugin-loaded agents.",
            category="plugins",
            sensitive=True,
        ),
    )

    AGENTS: Tuple[AgentDefinition, ...] = (
        AgentDefinition(
            key="master",
            name="Master Agent",
            description="Central router and orchestrator for all workspace-safe tasks.",
            enabled_by_default=True,
            requires_security_review=False,
            permissions_required=("agents.master.use",),
            risk_level=RiskLevel.LOW,
        ),
        AgentDefinition(
            key="voice",
            name="Voice Agent",
            description="Voice input, voice output, and conversational execution layer.",
            enabled_by_default=True,
            requires_security_review=False,
            permissions_required=("agents.voice.use",),
            risk_level=RiskLevel.LOW,
        ),
        AgentDefinition(
            key="system",
            name="System Agent",
            description="Device/system automation with strict approval and worker checks.",
            enabled_by_default=False,
            requires_security_review=True,
            permissions_required=("agents.system.use", "security.approve"),
            risk_level=RiskLevel.CRITICAL,
        ),
        AgentDefinition(
            key="browser",
            name="Browser Agent",
            description="Browser-based research, navigation, and web workflow execution.",
            enabled_by_default=True,
            requires_security_review=False,
            permissions_required=("agents.browser.use",),
            risk_level=RiskLevel.MEDIUM,
        ),
        AgentDefinition(
            key="code",
            name="Code Agent",
            description="Code generation, debugging, refactoring, and repo assistance.",
            enabled_by_default=True,
            requires_security_review=False,
            permissions_required=("agents.code.use",),
            risk_level=RiskLevel.MEDIUM,
        ),
        AgentDefinition(
            key="memory",
            name="Memory Agent",
            description="Workspace-isolated memory storage and retrieval.",
            enabled_by_default=True,
            requires_security_review=True,
            permissions_required=("agents.memory.use", "memory.read", "memory.write"),
            risk_level=RiskLevel.HIGH,
        ),
        AgentDefinition(
            key="security",
            name="Security Agent",
            description="Approval, risk, policy, permission, and audit decision agent.",
            enabled_by_default=True,
            requires_security_review=False,
            permissions_required=("agents.security.use",),
            risk_level=RiskLevel.HIGH,
        ),
        AgentDefinition(
            key="verification",
            name="Verification Agent",
            description="Confirms completed actions and produces final verification payloads.",
            enabled_by_default=True,
            requires_security_review=False,
            permissions_required=("agents.verification.use",),
            risk_level=RiskLevel.LOW,
        ),
        AgentDefinition(
            key="visual",
            name="Visual Agent",
            description="Image, UI, screenshot, visual analysis, and creative asset workflows.",
            enabled_by_default=True,
            requires_security_review=False,
            permissions_required=("agents.visual.use",),
            risk_level=RiskLevel.MEDIUM,
        ),
        AgentDefinition(
            key="workflow",
            name="Workflow Agent",
            description="Multi-step automation, scheduling, pipelines, and process execution.",
            enabled_by_default=True,
            requires_security_review=True,
            permissions_required=("agents.workflow.use",),
            risk_level=RiskLevel.HIGH,
        ),
        AgentDefinition(
            key="hologram",
            name="Hologram Agent",
            description="Avatar, holographic assistant, and futuristic visual presence features.",
            enabled_by_default=False,
            requires_security_review=False,
            permissions_required=("agents.hologram.use",),
            risk_level=RiskLevel.MEDIUM,
        ),
        AgentDefinition(
            key="call",
            name="Call Agent",
            description="Calling workflows with consent, logging, and compliance controls.",
            enabled_by_default=False,
            requires_security_review=True,
            permissions_required=("agents.call.use", "security.approve"),
            risk_level=RiskLevel.CRITICAL,
        ),
        AgentDefinition(
            key="business",
            name="Business Agent",
            description="CRM, leads, clients, campaigns, proposals, and growth workflows.",
            enabled_by_default=True,
            requires_security_review=False,
            permissions_required=("agents.business.use",),
            risk_level=RiskLevel.MEDIUM,
        ),
        AgentDefinition(
            key="finance",
            name="Finance Agent",
            description="Invoices, expenses, receipts, subscriptions, and billing workflows.",
            enabled_by_default=False,
            requires_security_review=True,
            permissions_required=("agents.finance.use", "billing.read"),
            risk_level=RiskLevel.HIGH,
        ),
        AgentDefinition(
            key="creator",
            name="Creator Agent",
            description="Content, scripts, ads, videos, social posts, and creative workflows.",
            enabled_by_default=True,
            requires_security_review=False,
            permissions_required=("agents.creator.use",),
            risk_level=RiskLevel.LOW,
        ),
    )

    ROLES: Tuple[RoleDefinition, ...] = (
        RoleDefinition(
            key="owner",
            name="Owner",
            description="Full workspace owner with billing, security, and member control.",
            permissions=tuple(permission.key for permission in PERMISSIONS),
        ),
        RoleDefinition(
            key="admin",
            name="Admin",
            description="Workspace admin with broad management access except ownership transfer.",
            permissions=(
                "workspace.read",
                "workspace.update",
                "members.invite",
                "members.manage",
                "tasks.create",
                "tasks.run",
                "tasks.cancel",
                "tasks.history.read",
                "memory.read",
                "memory.write",
                "files.read",
                "files.write",
                "analytics.read",
                "billing.read",
                "security.audit.read",
                "security.approve",
                "agents.master.use",
                "agents.voice.use",
                "agents.browser.use",
                "agents.code.use",
                "agents.memory.use",
                "agents.security.use",
                "agents.verification.use",
                "agents.visual.use",
                "agents.workflow.use",
                "agents.business.use",
                "agents.creator.use",
                "integrations.manage",
            ),
        ),
        RoleDefinition(
            key="manager",
            name="Manager",
            description="Operational manager for team tasks, agents, analytics, and files.",
            permissions=(
                "workspace.read",
                "tasks.create",
                "tasks.run",
                "tasks.cancel",
                "tasks.history.read",
                "memory.read",
                "memory.write",
                "files.read",
                "files.write",
                "analytics.read",
                "agents.master.use",
                "agents.voice.use",
                "agents.browser.use",
                "agents.code.use",
                "agents.memory.use",
                "agents.verification.use",
                "agents.visual.use",
                "agents.workflow.use",
                "agents.business.use",
                "agents.creator.use",
            ),
        ),
        RoleDefinition(
            key="member",
            name="Member",
            description="Standard workspace user with safe task and agent access.",
            permissions=(
                "workspace.read",
                "tasks.create",
                "tasks.run",
                "tasks.history.read",
                "files.read",
                "analytics.read",
                "agents.master.use",
                "agents.voice.use",
                "agents.browser.use",
                "agents.code.use",
                "agents.verification.use",
                "agents.visual.use",
                "agents.business.use",
                "agents.creator.use",
            ),
        ),
        RoleDefinition(
            key="viewer",
            name="Viewer",
            description="Read-only workspace user for analytics, task history, and reports.",
            permissions=(
                "workspace.read",
                "tasks.history.read",
                "files.read",
                "analytics.read",
            ),
        ),
        RoleDefinition(
            key="billing_manager",
            name="Billing Manager",
            description="Billing-focused role for subscription and usage review.",
            permissions=(
                "workspace.read",
                "billing.read",
                "billing.manage",
                "analytics.read",
                "security.audit.read",
            ),
        ),
        RoleDefinition(
            key="security_reviewer",
            name="Security Reviewer",
            description="Security-focused role for audit logs and sensitive approvals.",
            permissions=(
                "workspace.read",
                "tasks.history.read",
                "security.audit.read",
                "security.approve",
                "agents.security.use",
                "agents.verification.use",
            ),
        ),
    )

    PLANS: Tuple[PlanDefinition, ...] = (
        PlanDefinition(
            key="free",
            name="Free",
            tier=PlanTier.FREE,
            description="Safe entry plan for testing core William/Jarvis workflows.",
            monthly_price_cents=0,
            yearly_price_cents=0,
            currency=DEFAULT_CURRENCY,
            billing_intervals=(BillingInterval.MONTHLY,),
            included_roles=("owner", "member", "viewer"),
            included_permissions=(
                "workspace.read",
                "tasks.create",
                "tasks.run",
                "tasks.history.read",
                "files.read",
                "analytics.read",
                "agents.master.use",
                "agents.voice.use",
                "agents.browser.use",
                "agents.code.use",
                "agents.verification.use",
                "agents.creator.use",
            ),
            included_agents=("master", "voice", "browser", "code", "verification", "creator"),
            limits={
                "workspace_members": 2,
                "monthly_tasks": 100,
                "monthly_agent_runs": 150,
                "monthly_browser_runs": 20,
                "monthly_code_runs": 30,
                "memory_items": 50,
                "storage_mb": 250,
                "active_workflows": 0,
                "api_keys": 0,
            },
            features=(
                "Core Master Agent routing",
                "Basic Voice Agent access",
                "Basic Browser Agent access",
                "Basic Code Agent access",
                "Verification payloads",
                "Limited workspace analytics",
            ),
            is_default=True,
        ),
        PlanDefinition(
            key="starter",
            name="Starter",
            tier=PlanTier.STARTER,
            description="For solo founders and small teams building reliable AI workflows.",
            monthly_price_cents=2900,
            yearly_price_cents=29000,
            currency=DEFAULT_CURRENCY,
            billing_intervals=(BillingInterval.MONTHLY, BillingInterval.YEARLY),
            included_roles=("owner", "admin", "member", "viewer"),
            included_permissions=(
                "workspace.read",
                "workspace.update",
                "members.invite",
                "tasks.create",
                "tasks.run",
                "tasks.cancel",
                "tasks.history.read",
                "memory.read",
                "memory.write",
                "files.read",
                "files.write",
                "analytics.read",
                "billing.read",
                "agents.master.use",
                "agents.voice.use",
                "agents.browser.use",
                "agents.code.use",
                "agents.memory.use",
                "agents.verification.use",
                "agents.visual.use",
                "agents.business.use",
                "agents.creator.use",
            ),
            included_agents=(
                "master",
                "voice",
                "browser",
                "code",
                "memory",
                "verification",
                "visual",
                "business",
                "creator",
            ),
            limits={
                "workspace_members": 5,
                "monthly_tasks": 1000,
                "monthly_agent_runs": 1500,
                "monthly_browser_runs": 200,
                "monthly_code_runs": 250,
                "memory_items": 1000,
                "storage_mb": 5000,
                "active_workflows": 3,
                "api_keys": 1,
            },
            features=(
                "Workspace memory",
                "Visual Agent access",
                "Business Agent access",
                "Creator Agent access",
                "Task cancellation",
                "File write access",
                "Basic workflow capacity",
            ),
        ),
        PlanDefinition(
            # database.models.subscription.PlanKey / apps/api/routes/*.py's
            # Plan enum (the vocabulary actually enforced on live routes)
            # both use "pro" for this tier, not "growth" -- "growth" made
            # the subscription_plan_before_insert event listener crash with
            # "Unknown plan: growth" via Subscription.normalize_plan(). Keep
            # the friendlier PlanTier.GROWTH categorization for this
            # seeder's own internal metadata; only the DB plan_key changes.
            key="pro",
            name="Pro",
            tier=PlanTier.GROWTH,
            description="For growing businesses that need automation, memory, and team control.",
            monthly_price_cents=7900,
            yearly_price_cents=79000,
            currency=DEFAULT_CURRENCY,
            billing_intervals=(BillingInterval.MONTHLY, BillingInterval.YEARLY),
            included_roles=("owner", "admin", "manager", "member", "viewer", "billing_manager"),
            included_permissions=(
                "workspace.read",
                "workspace.update",
                "members.invite",
                "members.manage",
                "tasks.create",
                "tasks.run",
                "tasks.cancel",
                "tasks.history.read",
                "memory.read",
                "memory.write",
                "files.read",
                "files.write",
                "analytics.read",
                "billing.read",
                "security.audit.read",
                "agents.master.use",
                "agents.voice.use",
                "agents.browser.use",
                "agents.code.use",
                "agents.memory.use",
                "agents.security.use",
                "agents.verification.use",
                "agents.visual.use",
                "agents.workflow.use",
                "agents.business.use",
                "agents.creator.use",
                "integrations.manage",
            ),
            included_agents=(
                "master",
                "voice",
                "browser",
                "code",
                "memory",
                "security",
                "verification",
                "visual",
                "workflow",
                "business",
                "creator",
            ),
            limits={
                "workspace_members": 15,
                "monthly_tasks": 7500,
                "monthly_agent_runs": 10000,
                "monthly_browser_runs": 1500,
                "monthly_code_runs": 1500,
                "memory_items": 15000,
                "storage_mb": 25000,
                "active_workflows": 25,
                "api_keys": 5,
            },
            features=(
                "Workflow Agent access",
                "Security Agent access",
                "Audit log visibility",
                "Team role management",
                "Integration management",
                "Expanded analytics",
                "Higher memory and storage limits",
            ),
        ),
        PlanDefinition(
            key="business",
            name="Business",
            tier=PlanTier.BUSINESS,
            description="For serious teams needing finance, call, system, and advanced controls.",
            monthly_price_cents=19900,
            yearly_price_cents=199000,
            currency=DEFAULT_CURRENCY,
            billing_intervals=(BillingInterval.MONTHLY, BillingInterval.YEARLY),
            included_roles=(
                "owner",
                "admin",
                "manager",
                "member",
                "viewer",
                "billing_manager",
                "security_reviewer",
            ),
            included_permissions=tuple(permission.key for permission in PERMISSIONS if permission.key != "plugins.manage"),
            included_agents=(
                "master",
                "voice",
                "system",
                "browser",
                "code",
                "memory",
                "security",
                "verification",
                "visual",
                "workflow",
                "hologram",
                "call",
                "business",
                "finance",
                "creator",
            ),
            limits={
                "workspace_members": 50,
                "monthly_tasks": 50000,
                "monthly_agent_runs": 75000,
                "monthly_browser_runs": 10000,
                "monthly_code_runs": 10000,
                "memory_items": 100000,
                "storage_mb": 150000,
                "active_workflows": 150,
                "api_keys": 20,
            },
            features=(
                "All 14 agents",
                "Finance Agent access",
                "Call Agent access with approval routing",
                "System Agent access with security review",
                "Hologram Agent access",
                "Security reviewer role",
                "Advanced audit visibility",
                "High-volume workflow execution",
            ),
        ),
        PlanDefinition(
            key="enterprise",
            name="Enterprise",
            tier=PlanTier.ENTERPRISE,
            description="Custom deployment, compliance, limits, integrations, and support.",
            monthly_price_cents=0,
            yearly_price_cents=0,
            currency=DEFAULT_CURRENCY,
            billing_intervals=(BillingInterval.MONTHLY, BillingInterval.YEARLY),
            included_roles=tuple(role.key for role in ROLES),
            included_permissions=tuple(permission.key for permission in PERMISSIONS),
            included_agents=tuple(agent.key for agent in AGENTS),
            limits={
                "workspace_members": 100000,
                "monthly_tasks": 100000000,
                "monthly_agent_runs": 100000000,
                "monthly_browser_runs": 100000000,
                "monthly_code_runs": 100000000,
                "memory_items": 100000000,
                "storage_mb": 100000000,
                "active_workflows": 100000,
                "api_keys": 10000,
            },
            features=(
                "Custom limits",
                "Private deployment support",
                "Advanced compliance options",
                "Custom agent/plugin registry",
                "Dedicated onboarding",
                "Custom security approval policies",
                "Enterprise support workflow",
            ),
            is_public=False,
            requires_sales_contact=True,
        ),
    )

    @classmethod
    def now(cls) -> ISODateTime:
        return datetime.now(timezone.utc).isoformat()

    @classmethod
    def build_seed_payload(cls) -> JSONDict:
        return {
            "module": cls.MODULE_NAME,
            "version": cls.VERSION,
            "generated_at": cls.now(),
            "permissions": [permission.to_dict() for permission in cls.PERMISSIONS],
            "roles": [role.to_dict() for role in cls.ROLES],
            "agents": [agent.to_dict() for agent in cls.AGENTS],
            "plans": [plan.to_dict() for plan in cls.PLANS],
            "defaults": {
                "default_plan": cls.get_default_plan_key(),
                "default_owner_role": "owner",
                "default_member_role": "member",
                "security_agent": "security",
                "verification_agent": "verification",
                "memory_agent": "memory",
                "master_agent": "master",
            },
        }

    @classmethod
    def get_default_plan_key(cls) -> str:
        for plan in cls.PLANS:
            if plan.is_default:
                return plan.key
        return cls.PLANS[0].key

    @classmethod
    def get_plan(cls, plan_key: str) -> Optional[PlanDefinition]:
        normalized = cls._normalize_key(plan_key)
        for plan in cls.PLANS:
            if plan.key == normalized:
                return plan
        return None

    @classmethod
    def get_role(cls, role_key: str) -> Optional[RoleDefinition]:
        normalized = cls._normalize_key(role_key)
        for role in cls.ROLES:
            if role.key == normalized:
                return role
        return None

    @classmethod
    def get_agent(cls, agent_key: str) -> Optional[AgentDefinition]:
        normalized = cls._normalize_key(agent_key)
        for agent in cls.AGENTS:
            if agent.key == normalized:
                return agent
        return None

    @classmethod
    def permissions_for_plan(cls, plan_key: str) -> Tuple[str, ...]:
        plan = cls.get_plan(plan_key)
        return tuple(plan.included_permissions) if plan else tuple()

    @classmethod
    def agents_for_plan(cls, plan_key: str) -> Tuple[str, ...]:
        plan = cls.get_plan(plan_key)
        return tuple(plan.included_agents) if plan else tuple()

    @classmethod
    def roles_for_plan(cls, plan_key: str) -> Tuple[str, ...]:
        plan = cls.get_plan(plan_key)
        return tuple(plan.included_roles) if plan else tuple()

    @classmethod
    def can_plan_use_agent(cls, plan_key: str, agent_key: str) -> bool:
        plan = cls.get_plan(plan_key)
        agent = cls.get_agent(agent_key)
        if not plan or not agent:
            return False
        return agent.key in plan.included_agents

    @classmethod
    def role_has_permission(cls, role_key: str, permission_key: str) -> bool:
        role = cls.get_role(role_key)
        if not role:
            return False
        return cls._normalize_key(permission_key) in role.permissions

    @classmethod
    def plan_has_permission(cls, plan_key: str, permission_key: str) -> bool:
        plan = cls.get_plan(plan_key)
        if not plan:
            return False
        return cls._normalize_key(permission_key) in plan.included_permissions

    @classmethod
    def validate_seed_data(cls) -> List[JSONDict]:
        errors: List[JSONDict] = []

        permission_keys = cls._collect_unique_keys(cls.PERMISSIONS, "permissions", errors)
        role_keys = cls._collect_unique_keys(cls.ROLES, "roles", errors)
        agent_keys = cls._collect_unique_keys(cls.AGENTS, "agents", errors)
        plan_keys = cls._collect_unique_keys(cls.PLANS, "plans", errors)

        for role in cls.ROLES:
            missing_permissions = sorted(set(role.permissions) - permission_keys)
            if missing_permissions:
                errors.append(
                    {
                        "entity": "role",
                        "key": role.key,
                        "error": "role_references_unknown_permissions",
                        "missing_permissions": missing_permissions,
                    }
                )

        for agent in cls.AGENTS:
            missing_permissions = sorted(set(agent.permissions_required) - permission_keys)
            if missing_permissions:
                errors.append(
                    {
                        "entity": "agent",
                        "key": agent.key,
                        "error": "agent_references_unknown_permissions",
                        "missing_permissions": missing_permissions,
                    }
                )

        default_plans = [plan.key for plan in cls.PLANS if plan.is_default]
        if len(default_plans) != 1:
            errors.append(
                {
                    "entity": "plans",
                    "error": "exactly_one_default_plan_required",
                    "default_plans": default_plans,
                }
            )

        for plan in cls.PLANS:
            missing_roles = sorted(set(plan.included_roles) - role_keys)
            missing_permissions = sorted(set(plan.included_permissions) - permission_keys)
            missing_agents = sorted(set(plan.included_agents) - agent_keys)

            if missing_roles:
                errors.append(
                    {
                        "entity": "plan",
                        "key": plan.key,
                        "error": "plan_references_unknown_roles",
                        "missing_roles": missing_roles,
                    }
                )

            if missing_permissions:
                errors.append(
                    {
                        "entity": "plan",
                        "key": plan.key,
                        "error": "plan_references_unknown_permissions",
                        "missing_permissions": missing_permissions,
                    }
                )

            if missing_agents:
                errors.append(
                    {
                        "entity": "plan",
                        "key": plan.key,
                        "error": "plan_references_unknown_agents",
                        "missing_agents": missing_agents,
                    }
                )

            for agent_key in plan.included_agents:
                agent = cls.get_agent(agent_key)
                if agent:
                    missing_agent_permissions = sorted(
                        set(agent.permissions_required) - set(plan.included_permissions)
                    )
                    if missing_agent_permissions:
                        errors.append(
                            {
                                "entity": "plan",
                                "key": plan.key,
                                "agent": agent_key,
                                "error": "plan_includes_agent_without_required_permissions",
                                "missing_permissions": missing_agent_permissions,
                            }
                        )

        if not plan_keys:
            errors.append({"entity": "plans", "error": "no_plans_defined"})

        return errors

    @classmethod
    def seed(
        cls,
        session: Optional[Any] = None,
        context: Optional[SeederContext] = None,
        audit_logger: Optional[Callable[[JSONDict], Any]] = None,
        security_checker: Optional[Callable[[JSONDict], Any]] = None,
        memory_hook: Optional[Callable[[JSONDict], Any]] = None,
        verification_hook: Optional[Callable[[JSONDict], Any]] = None,
    ) -> JSONDict:
        safe_context = context or SeederContext(
            actor_user_id="system",
            workspace_id=os.getenv("WILLIAM_SYSTEM_WORKSPACE_ID", "system")
        )

        try:
            safe_context.validate()
        except ValueError as exc:
            response = SeederResponse(
                status=SeederStatus.FAILED,
                message="Seeder context validation failed.",
                request_id=safe_context.request_id,
                workspace_id=getattr(safe_context, "workspace_id", "unknown"),
                actor_user_id=getattr(safe_context, "actor_user_id", "unknown"),
                errors=[{"error": "invalid_context", "detail": str(exc)}],
            )
            return response.to_dict()

        validation_errors = cls.validate_seed_data()

        audit_event = cls.build_audit_event(
            context=safe_context,
            action="default_plans.seed.requested",
            risk_level=RiskLevel.HIGH,
            details={
                "dry_run": safe_context.dry_run,
                "force": safe_context.force,
                "validation_errors": validation_errors,
            },
        )

        cls._safe_call_hook(audit_logger, audit_event)

        security_payload = cls.build_security_payload(
            context=safe_context,
            action="seed_default_saas_plans_roles_permissions_agents",
            risk_level=RiskLevel.HIGH,
            reason="Seeding plan, role, permission, and agent defaults changes SaaS access behavior.",
        )

        if security_checker:
            security_decision = cls._safe_call_hook(security_checker, security_payload)
            if cls._security_denied(security_decision):
                response = SeederResponse(
                    status=SeederStatus.NEEDS_APPROVAL,
                    message="Security approval is required before seeding default plans.",
                    request_id=safe_context.request_id,
                    workspace_id=safe_context.workspace_id,
                    actor_user_id=safe_context.actor_user_id,
                    errors=validation_errors,
                    audit_event=audit_event,
                    security_payload=security_payload,
                )
                return response.to_dict()

        if validation_errors:
            response = SeederResponse(
                status=SeederStatus.FAILED,
                message="Default plan seed data failed validation.",
                request_id=safe_context.request_id,
                workspace_id=safe_context.workspace_id,
                actor_user_id=safe_context.actor_user_id,
                errors=validation_errors,
                audit_event=audit_event,
                security_payload=security_payload,
            )
            return response.to_dict()

        seed_payload = cls.build_seed_payload()

        if safe_context.dry_run:
            verification_payload = cls.build_verification_payload(
                context=safe_context,
                status=SeederStatus.SKIPPED,
                seeded=seed_payload,
                skipped={"reason": "dry_run_enabled"},
                errors=[],
            )
            memory_payload = cls.build_memory_payload(
                context=safe_context,
                summary="Default SaaS plan seed dry-run completed.",
                payload=seed_payload,
            )
            cls._safe_call_hook(memory_hook, memory_payload)
            cls._safe_call_hook(verification_hook, verification_payload)

            response = SeederResponse(
                status=SeederStatus.SKIPPED,
                message="Dry run completed. No database changes were made.",
                request_id=safe_context.request_id,
                workspace_id=safe_context.workspace_id,
                actor_user_id=safe_context.actor_user_id,
                seeded={},
                skipped=seed_payload,
                audit_event=audit_event,
                memory_payload=memory_payload,
                verification_payload=verification_payload,
                security_payload=security_payload,
            )
            return response.to_dict()

        if session is None:
            verification_payload = cls.build_verification_payload(
                context=safe_context,
                status=SeederStatus.SKIPPED,
                seeded={},
                skipped={"reason": "no_database_session_provided", "payload": seed_payload},
                errors=[],
            )
            response = SeederResponse(
                status=SeederStatus.SKIPPED,
                message="No database session provided. Returned seed payload only.",
                request_id=safe_context.request_id,
                workspace_id=safe_context.workspace_id,
                actor_user_id=safe_context.actor_user_id,
                seeded={},
                skipped={"reason": "no_database_session_provided", "payload": seed_payload},
                audit_event=audit_event,
                verification_payload=verification_payload,
                security_payload=security_payload,
            )
            return response.to_dict()

        db_result = cls._seed_database_duck_typed(session=session, context=safe_context)

        verification_payload = cls.build_verification_payload(
            context=safe_context,
            status=SeederStatus.SUCCESS if not db_result["errors"] else SeederStatus.FAILED,
            seeded=db_result["seeded"],
            skipped=db_result["skipped"],
            errors=db_result["errors"],
        )

        memory_payload = cls.build_memory_payload(
            context=safe_context,
            summary="Default SaaS plans, roles, permissions, and agents were seeded.",
            payload={
                "seeded_counts": {
                    "permissions": len(db_result["seeded"].get("permissions", [])),
                    "roles": len(db_result["seeded"].get("roles", [])),
                    "agents": len(db_result["seeded"].get("agents", [])),
                    "plans": len(db_result["seeded"].get("plans", [])),
                },
                "skipped_counts": {
                    "permissions": len(db_result["skipped"].get("permissions", [])),
                    "roles": len(db_result["skipped"].get("roles", [])),
                    "agents": len(db_result["skipped"].get("agents", [])),
                    "plans": len(db_result["skipped"].get("plans", [])),
                },
            },
        )

        cls._safe_call_hook(memory_hook, memory_payload)
        cls._safe_call_hook(verification_hook, verification_payload)

        status = SeederStatus.SUCCESS if not db_result["errors"] else SeederStatus.FAILED
        message = (
            "Default SaaS plans, roles, permissions, and agents seeded successfully."
            if status == SeederStatus.SUCCESS
            else "Default SaaS seeding finished with errors."
        )

        response = SeederResponse(
            status=status,
            message=message,
            request_id=safe_context.request_id,
            workspace_id=safe_context.workspace_id,
            actor_user_id=safe_context.actor_user_id,
            seeded=db_result["seeded"],
            skipped=db_result["skipped"],
            errors=db_result["errors"],
            audit_event=audit_event,
            memory_payload=memory_payload,
            verification_payload=verification_payload,
            security_payload=security_payload,
        )
        return response.to_dict()

    @classmethod
    def build_audit_event(
        cls,
        context: SeederContext,
        action: str,
        risk_level: RiskLevel,
        details: Optional[JSONDict] = None,
    ) -> JSONDict:
        return {
            "event_id": str(uuid.uuid4()),
            "event_type": "audit",
            "source": context.source,
            "module": cls.MODULE_NAME,
            "version": cls.VERSION,
            "action": action,
            "risk_level": risk_level.value,
            "actor_user_id": context.actor_user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "created_at": cls.now(),
            "details": details or {},
            "metadata": copy.deepcopy(context.metadata),
        }

    @classmethod
    def build_security_payload(
        cls,
        context: SeederContext,
        action: str,
        risk_level: RiskLevel,
        reason: str,
    ) -> JSONDict:
        return {
            "security_request_id": str(uuid.uuid4()),
            "source": context.source,
            "module": cls.MODULE_NAME,
            "action": action,
            "risk_level": risk_level.value,
            "reason": reason,
            "actor_user_id": context.actor_user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "requires_approval": True,
            "approved_by_security": context.approved_by_security,
            "created_at": cls.now(),
            "recommended_agent": "security",
        }

    @classmethod
    def build_memory_payload(
        cls,
        context: SeederContext,
        summary: str,
        payload: JSONDict,
    ) -> JSONDict:
        return {
            "memory_event_id": str(uuid.uuid4()),
            "source": context.source,
            "module": cls.MODULE_NAME,
            "summary": summary,
            "actor_user_id": context.actor_user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "created_at": cls.now(),
            "memory_scope": "workspace",
            "safe_to_store": True,
            "payload": payload,
            "recommended_agent": "memory",
        }

    @classmethod
    def build_verification_payload(
        cls,
        context: SeederContext,
        status: SeederStatus,
        seeded: JSONDict,
        skipped: JSONDict,
        errors: List[JSONDict],
    ) -> JSONDict:
        return {
            "verification_id": str(uuid.uuid4()),
            "source": context.source,
            "module": cls.MODULE_NAME,
            "status": status.value,
            "actor_user_id": context.actor_user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "created_at": cls.now(),
            "checks": {
                "user_id_present": bool(context.actor_user_id),
                "workspace_id_present": bool(context.workspace_id),
                "seed_data_valid": not bool(errors),
                "workspace_isolated": True,
                "audit_payload_prepared": True,
                "security_payload_prepared": True,
                "memory_payload_compatible": True,
            },
            "seeded": seeded,
            "skipped": skipped,
            "errors": errors,
            "recommended_agent": "verification",
        }

    @classmethod
    def _seed_database_duck_typed(cls, session: Any, context: SeederContext) -> JSONDict:
        models = cls._resolve_optional_models()

        result: JSONDict = {
            "seeded": {
                "permissions": [],
                "roles": [],
                "agents": [],
                "plans": [],
            },
            "skipped": {
                "permissions": [],
                "roles": [],
                "agents": [],
                "plans": [],
            },
            "errors": [],
        }

        if not models:
            result["skipped"]["models"] = [
                "No compatible model classes found. Seeder payload is valid but database writes were skipped."
            ]
            return result

        try:
            cls._seed_collection(
                session=session,
                model=models.get("Permission"),
                records=[permission.to_dict() for permission in cls.PERMISSIONS],
                unique_field="key",
                bucket="permissions",
                result=result,
                context=context,
            )
            cls._seed_collection(
                session=session,
                model=models.get("Role"),
                records=[role.to_dict() for role in cls.ROLES],
                unique_field="key",
                bucket="roles",
                result=result,
                context=context,
            )
            cls._seed_collection(
                session=session,
                model=models.get("Agent"),
                # database.models.agent_registry.AgentRegistry has no "key"
                # column (it's agent_key) -- using "key" here made
                # _find_existing() never match an already-seeded row, so a
                # second run always attempted a fresh INSERT and hit the
                # (user_id, workspace_id, agent_key, version) UNIQUE
                # constraint instead of skipping/updating. "agent_key" is
                # the real column name (aliased onto this dict by
                # AgentDefinition.to_dict()).
                records=[agent.to_dict() for agent in cls.AGENTS],
                unique_field="agent_key",
                bucket="agents",
                result=result,
                context=context,
            )
            cls._seed_collection(
                session=session,
                model=models.get("Plan"),
                records=[plan.to_dict() for plan in cls.PLANS],
                unique_field="key",
                bucket="plans",
                result=result,
                context=context,
            )

            if hasattr(session, "commit"):
                session.commit()

        except Exception as exc:
            if hasattr(session, "rollback"):
                cls._safe_session_rollback(session)

            result["errors"].append(
                {
                    "error": "database_seed_failed",
                    "detail": cls._safe_error_message(exc),
                }
            )

        return result

    @classmethod
    def _seed_collection(
        cls,
        session: Any,
        model: Optional[type],
        records: Sequence[JSONDict],
        unique_field: str,
        bucket: str,
        result: JSONDict,
        context: SeederContext,
    ) -> None:
        if model is None:
            result["skipped"][bucket].extend(
                [
                    {
                        unique_field: record.get(unique_field),
                        "reason": "model_not_available",
                    }
                    for record in records
                ]
            )
            return

        for record in records:
            scoped_record = cls._with_seed_metadata(record, context)
            existing = cls._find_existing(session, model, unique_field, record.get(unique_field))

            if existing and not context.force:
                result["skipped"][bucket].append(
                    {
                        unique_field: record.get(unique_field),
                        "reason": "already_exists",
                    }
                )
                continue

            if existing and context.force:
                cls._update_model_instance(existing, scoped_record)
                result["seeded"][bucket].append(
                    {
                        unique_field: record.get(unique_field),
                        "operation": "updated",
                    }
                )
                continue

            instance = cls._make_model_instance(model, scoped_record)
            if hasattr(session, "add"):
                session.add(instance)
                result["seeded"][bucket].append(
                    {
                        unique_field: record.get(unique_field),
                        "operation": "created",
                    }
                )
            else:
                result["skipped"][bucket].append(
                    {
                        unique_field: record.get(unique_field),
                        "reason": "session_missing_add_method",
                    }
                )

    @classmethod
    def _with_seed_metadata(cls, record: JSONDict, context: SeederContext) -> JSONDict:
        enriched = copy.deepcopy(record)
        enriched.setdefault("workspace_id", context.workspace_id)
        enriched.setdefault("created_by_user_id", context.actor_user_id)
        enriched.setdefault("updated_by_user_id", context.actor_user_id)
        enriched.setdefault("seed_source", context.source)
        enriched.setdefault("seed_version", cls.VERSION)
        enriched.setdefault("created_at", cls.now())
        enriched.setdefault("updated_at", cls.now())
        return enriched

    @classmethod
    def _resolve_optional_models(cls) -> Dict[str, type]:
        resolved: Dict[str, type] = {}

        candidate_paths: Tuple[Tuple[str, str], ...] = (
            ("database.models.subscription", "SubscriptionPlan"),
            ("database.models.role_permission", "Permission"),
            ("database.models.role_permission", "Role"),
            ("database.models.agent_registry", "AgentRegistry"),
        )

        for module_path, class_name in candidate_paths:
            model_class = cls._import_optional_class(module_path, class_name)
            if model_class is None:
                continue

            canonical_name = cls._canonical_model_name(class_name)
            if canonical_name not in resolved:
                resolved[canonical_name] = model_class

        return resolved

    @classmethod
    def _canonical_model_name(cls, class_name: str) -> str:
        mapping = {
            "SubscriptionPlan": "Plan",
            "Permission": "Permission",
            "Role": "Role",
            "AgentRegistry": "Agent",
        }
        return mapping.get(class_name, class_name)

    @classmethod
    def _import_optional_class(cls, module_path: str, class_name: str) -> Optional[type]:
        try:
            module = __import__(module_path, fromlist=[class_name])
            model_class = getattr(module, class_name, None)
            return model_class if isinstance(model_class, type) else None
        except Exception:
            return None

    @classmethod
    def _find_existing(
        cls,
        session: Any,
        model: type,
        unique_field: str,
        unique_value: Any,
    ) -> Optional[Any]:
        if unique_value is None:
            return None

        try:
            if hasattr(session, "query"):
                query = session.query(model)
                model_field = getattr(model, unique_field, None)
                if model_field is not None and hasattr(query, "filter"):
                    filtered = query.filter(model_field == unique_value)
                    if hasattr(filtered, "first"):
                        return filtered.first()

            if hasattr(session, "execute") and hasattr(model, "__table__"):
                table = getattr(model, "__table__")
                columns = getattr(table, "c", None)
                column = getattr(columns, unique_field, None) if columns is not None else None
                if column is not None:
                    statement = table.select().where(column == unique_value)
                    executed = session.execute(statement)
                    if hasattr(executed, "first"):
                        row = executed.first()
                        if row:
                            return row[0] if isinstance(row, tuple) else row

        except Exception:
            return None

        return None

    @classmethod
    def _make_model_instance(cls, model: type, record: JSONDict) -> Any:
        record = cls._coerce_datetime_fields(model, record)
        try:
            return model(**record)
        except TypeError:
            instance = model()
            cls._update_model_instance(instance, record)
            return instance

    @classmethod
    def _coerce_datetime_fields(cls, model: type, record: JSONDict) -> JSONDict:
        """
        _with_seed_metadata() stamps created_at/updated_at (and callers may
        supply other *_at fields) as ISO strings via cls.now(). That is the
        right shape for models with String-typed timestamp columns, but
        models with a real SQLAlchemy DateTime column (e.g.
        database.models.agent_registry.AgentRegistry) reject a raw string at
        insert time: "SQLite DateTime type only accepts Python datetime and
        date objects as input." Convert ISO-string values to real datetime
        objects, but only for columns actually typed as DateTime on this
        specific model -- leave String-typed timestamp columns untouched.
        """
        table = getattr(model, "__table__", None)
        if table is None:
            return record

        coerced = dict(record)
        for column in table.columns:
            value = coerced.get(column.name)
            if not isinstance(value, str):
                continue
            if not isinstance(column.type, DateTime):
                continue
            try:
                coerced[column.name] = datetime.fromisoformat(value)
            except ValueError:
                continue

        return coerced

    @classmethod
    def _update_model_instance(cls, instance: Any, record: JSONDict) -> None:
        for key, value in record.items():
            if hasattr(instance, key):
                try:
                    setattr(instance, key, value)
                except Exception:
                    continue

    @classmethod
    def _collect_unique_keys(
        cls,
        records: Iterable[Any],
        entity_name: str,
        errors: List[JSONDict],
    ) -> set:
        keys: set = set()
        duplicates: set = set()

        for record in records:
            key = getattr(record, "key", None)
            if not key:
                errors.append(
                    {
                        "entity": entity_name,
                        "error": "missing_key",
                        "record": str(record),
                    }
                )
                continue

            if key in keys:
                duplicates.add(key)
            keys.add(key)

        if duplicates:
            errors.append(
                {
                    "entity": entity_name,
                    "error": "duplicate_keys",
                    "duplicates": sorted(duplicates),
                }
            )

        return keys

    @classmethod
    def _normalize_key(cls, value: str) -> str:
        return str(value or "").strip().lower().replace(" ", "_")

    @classmethod
    def _safe_call_hook(cls, hook: Optional[Callable[[JSONDict], Any]], payload: JSONDict) -> Any:
        if hook is None:
            return None
        try:
            return hook(copy.deepcopy(payload))
        except Exception as exc:
            return {
                "hook_failed": True,
                "error": cls._safe_error_message(exc),
            }

    @classmethod
    def _security_denied(cls, decision: Any) -> bool:
        if decision is None:
            return False

        if isinstance(decision, Mapping):
            status = str(decision.get("status", "")).lower()
            approved = decision.get("approved")
            allowed = decision.get("allowed")

            if status in {"denied", "rejected", "blocked"}:
                return True
            if approved is False:
                return True
            if allowed is False:
                return True

        return False

    @classmethod
    def _safe_session_rollback(cls, session: Any) -> None:
        try:
            session.rollback()
        except Exception:
            return

    @classmethod
    def _safe_error_message(cls, exc: Exception) -> str:
        message = str(exc).strip()
        if not message:
            return exc.__class__.__name__
        blocked_terms = ("password", "secret", "token", "api_key", "apikey", "authorization")
        sanitized = message
        for term in blocked_terms:
            sanitized = sanitized.replace(term, "[redacted]")
            sanitized = sanitized.replace(term.upper(), "[redacted]")
        return sanitized


def seed_default_plans(
    session: Optional[Any] = None,
    actor_user_id: str = "system",
    workspace_id: Optional[str] = None,
    dry_run: bool = False,
    force: bool = False,
) -> JSONDict:
    """
    Convenience function for migrations, scripts, tests, or CLI commands.
    """
    context = SeederContext(
        actor_user_id=actor_user_id,
        workspace_id=workspace_id or os.getenv("WILLIAM_SYSTEM_WORKSPACE_ID", "system"),
        dry_run=dry_run,
        force=force,
    )
    return DefaultPlans.seed(session=session, context=context)


__all__ = [
    "DefaultPlans",
    "SeederContext",
    "SeederResponse",
    "SeederStatus",
    "RiskLevel",
    "BillingInterval",
    "PlanTier",
    "PermissionDefinition",
    "RoleDefinition",
    "AgentDefinition",
    "PlanDefinition",
    "seed_default_plans",
]