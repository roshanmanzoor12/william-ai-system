"""
database/models/subscription.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Agent/Module: Database Prompt Bible
Purpose: plans, subscriptions, usage limits, billing state

This file is intentionally import-safe:
- It depends only on database.db Base and scope helpers.
- It does not hardcode secrets.
- It keeps every subscription, usage, invoice, and billing state scoped by workspace_id.
- It supports plan management, workspace subscription state, usage limits,
  billing state, invoice tracking, and agent access control.
- It includes compatibility aliases for older draft model names:
  SubscriptionPlanModel, WorkspaceSubscriptionModel, UsageTrackingModel,
  AgentAccessModel, SubscriptionModels.

Critical SaaS rule:
Every limit and billing record is scoped per workspace_id.
No cross-workspace subscription, billing, usage, memory, task, file, analytics,
or agent access leakage is allowed.

Security rule:
Upgrades, downgrades, cancellation, billing provider changes, invoice changes,
and manual usage changes should be routed to Security Agent at the service/API layer.
This model provides audit, verification, and memory payload helpers.
"""

from __future__ import annotations

import enum
import os
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

try:
    from sqlalchemy import (
        Boolean,
        DateTime,
        Enum,
        ForeignKey,
        Index,
        Integer,
        String,
        Text,
        UniqueConstraint,
        event,
    )
    from sqlalchemy.orm import Mapped, mapped_column, relationship
    from sqlalchemy.types import JSON
except Exception:  # pragma: no cover - import-safe fallback
    Boolean = DateTime = Enum = ForeignKey = Index = Integer = String = Text = UniqueConstraint = JSON = object  # type: ignore

    def event_listens_for_fallback(*args: Any, **kwargs: Any):
        def decorator(fn: Any) -> Any:
            return fn
        return decorator

    class _EventFallback:
        listens_for = staticmethod(event_listens_for_fallback)

    event = _EventFallback()  # type: ignore

    class Mapped:  # type: ignore
        def __class_getitem__(cls, item: Any) -> Any:
            return Any

    def mapped_column(*args: Any, **kwargs: Any) -> Any:
        return None

    def relationship(*args: Any, **kwargs: Any) -> Any:
        return None

try:
    from database.db import Base, DbScope, validate_scope_id
except Exception:  # pragma: no cover - emergency import-safe fallback
    class Base:  # type: ignore
        pass

    class DbScope:  # type: ignore
        def __init__(self, user_id: str, workspace_id: str) -> None:
            self.user_id = user_id
            self.workspace_id = workspace_id

        def as_filter_kwargs(self) -> Dict[str, str]:
            return {"user_id": self.user_id, "workspace_id": self.workspace_id}

    def validate_scope_id(value: str, field_name: str) -> str:
        cleaned = str(value).strip()
        if not cleaned:
            raise ValueError(f"{field_name} is required.")
        if len(cleaned) > 140:
            raise ValueError(f"{field_name} is too long.")
        if not re.match(r"^[a-zA-Z0-9_\\-:.@]+$", cleaned):
            raise ValueError(f"{field_name} contains unsafe characters.")
        return cleaned


# =============================================================================
# Safe config
# =============================================================================

DEFAULT_CURRENCY = os.getenv("WILLIAM_BILLING_CURRENCY", "USD").upper()

FREE_PRICE_CENTS = int(os.getenv("WILLIAM_PLAN_FREE_PRICE_CENTS", "0"))
PRO_PRICE_CENTS = int(os.getenv("WILLIAM_PLAN_PRO_PRICE_CENTS", "2900"))
BUSINESS_PRICE_CENTS = int(os.getenv("WILLIAM_PLAN_BUSINESS_PRICE_CENTS", "9900"))
ENTERPRISE_PRICE_CENTS = int(os.getenv("WILLIAM_PLAN_ENTERPRISE_PRICE_CENTS", "29900"))


# =============================================================================
# Time / ID helpers
# =============================================================================

def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def generate_id(prefix: str) -> str:
    cleaned_prefix = re.sub(r"[^a-zA-Z0-9_]", "", str(prefix)).lower()
    cleaned_prefix = cleaned_prefix or "id"
    return f"{cleaned_prefix}_{uuid.uuid4().hex}"


def normalize_key(value: str, field_name: str = "key") -> str:
    cleaned = str(value or "").strip().lower()
    cleaned = cleaned.replace(" ", "_")
    cleaned = re.sub(r"[^a-z0-9_.:\\-]", "", cleaned)
    cleaned = re.sub(r"_+", "_", cleaned)
    cleaned = re.sub(r"\\.+", ".", cleaned)
    cleaned = cleaned.strip("._:-")

    if not cleaned:
        raise ValueError(f"{field_name} is required.")

    if len(cleaned) > 160:
        raise ValueError(f"{field_name} is too long.")

    return cleaned


def normalize_currency(value: str) -> str:
    cleaned = str(value or DEFAULT_CURRENCY).strip().upper()
    if not re.match(r"^[A-Z]{3}$", cleaned):
        raise ValueError("currency must be a valid 3-letter currency code.")
    return cleaned


def enum_value(value: Any) -> str:
    return value.value if hasattr(value, "value") else str(value)


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


# =============================================================================
# Enums
# =============================================================================

class PlanKey(str, enum.Enum):
    FREE = "free"
    PRO = "pro"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


class PlanStatus(str, enum.Enum):
    ACTIVE = "active"
    DISABLED = "disabled"
    ARCHIVED = "archived"


class BillingInterval(str, enum.Enum):
    MONTHLY = "monthly"
    YEARLY = "yearly"
    LIFETIME = "lifetime"
    CUSTOM = "custom"


class SubscriptionStatus(str, enum.Enum):
    ACTIVE = "active"
    TRIALING = "trialing"
    PAST_DUE = "past_due"
    UNPAID = "unpaid"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    SUSPENDED = "suspended"
    INACTIVE = "inactive"


class UsageMetric(str, enum.Enum):
    TASKS = "tasks"
    AGENT_RUNS = "agent_runs"
    MEMORY_RECORDS = "memory_records"
    MEMORY_STORAGE_MB = "memory_storage_mb"
    WORKFLOW_RUNS = "workflow_runs"
    WEBHOOKS = "webhooks"
    FILES = "files"
    STORAGE_MB = "storage_mb"
    API_CALLS = "api_calls"
    TEAM_MEMBERS = "team_members"
    DEVICE_WORKERS = "device_workers"
    DASHBOARD_SEATS = "dashboard_seats"


class UsagePeriod(str, enum.Enum):
    DAILY = "daily"
    MONTHLY = "monthly"
    YEARLY = "yearly"
    LIFETIME = "lifetime"


class AgentAccessStatus(str, enum.Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    LIMITED = "limited"


class BillingProvider(str, enum.Enum):
    INTERNAL = "internal"
    STRIPE = "stripe"
    PAYPAL = "paypal"
    MANUAL = "manual"
    OTHER = "other"


class InvoiceStatus(str, enum.Enum):
    DRAFT = "draft"
    OPEN = "open"
    PAID = "paid"
    VOID = "void"
    UNCOLLECTIBLE = "uncollectible"
    REFUNDED = "refunded"


class BillingEventType(str, enum.Enum):
    PLAN_CREATED = "plan.created"
    PLAN_UPDATED = "plan.updated"
    SUBSCRIPTION_CREATED = "subscription.created"
    SUBSCRIPTION_UPDATED = "subscription.updated"
    SUBSCRIPTION_CANCELLED = "subscription.cancelled"
    SUBSCRIPTION_REACTIVATED = "subscription.reactivated"
    USAGE_INCREMENTED = "usage.incremented"
    USAGE_LIMIT_REACHED = "usage.limit_reached"
    INVOICE_CREATED = "invoice.created"
    INVOICE_UPDATED = "invoice.updated"
    PAYMENT_SUCCEEDED = "payment.succeeded"
    PAYMENT_FAILED = "payment.failed"
    AGENT_ACCESS_CHANGED = "agent_access.changed"


# =============================================================================
# Default plan limits / features
# =============================================================================

ALL_AGENT_NAMES: List[str] = [
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
]


def default_limits_for_plan(plan_key: PlanKey) -> Dict[str, int]:
    if plan_key == PlanKey.FREE:
        return {
            UsageMetric.TASKS.value: 100,
            UsageMetric.AGENT_RUNS.value: 250,
            UsageMetric.MEMORY_RECORDS.value: 250,
            UsageMetric.MEMORY_STORAGE_MB.value: 100,
            UsageMetric.WORKFLOW_RUNS.value: 25,
            UsageMetric.WEBHOOKS.value: 0,
            UsageMetric.FILES.value: 50,
            UsageMetric.STORAGE_MB.value: 500,
            UsageMetric.API_CALLS.value: 1000,
            UsageMetric.TEAM_MEMBERS.value: 1,
            UsageMetric.DEVICE_WORKERS.value: 0,
            UsageMetric.DASHBOARD_SEATS.value: 1,
        }

    if plan_key == PlanKey.PRO:
        return {
            UsageMetric.TASKS.value: 5000,
            UsageMetric.AGENT_RUNS.value: 10000,
            UsageMetric.MEMORY_RECORDS.value: 5000,
            UsageMetric.MEMORY_STORAGE_MB.value: 2500,
            UsageMetric.WORKFLOW_RUNS.value: 1000,
            UsageMetric.WEBHOOKS.value: 20,
            UsageMetric.FILES.value: 2000,
            UsageMetric.STORAGE_MB.value: 25000,
            UsageMetric.API_CALLS.value: 50000,
            UsageMetric.TEAM_MEMBERS.value: 5,
            UsageMetric.DEVICE_WORKERS.value: 2,
            UsageMetric.DASHBOARD_SEATS.value: 5,
        }

    if plan_key == PlanKey.BUSINESS:
        return {
            UsageMetric.TASKS.value: 25000,
            UsageMetric.AGENT_RUNS.value: 100000,
            UsageMetric.MEMORY_RECORDS.value: 25000,
            UsageMetric.MEMORY_STORAGE_MB.value: 25000,
            UsageMetric.WORKFLOW_RUNS.value: 10000,
            UsageMetric.WEBHOOKS.value: 200,
            UsageMetric.FILES.value: 10000,
            UsageMetric.STORAGE_MB.value: 250000,
            UsageMetric.API_CALLS.value: 500000,
            UsageMetric.TEAM_MEMBERS.value: 25,
            UsageMetric.DEVICE_WORKERS.value: 10,
            UsageMetric.DASHBOARD_SEATS.value: 25,
        }

    return {
        UsageMetric.TASKS.value: 1000000,
        UsageMetric.AGENT_RUNS.value: 1000000,
        UsageMetric.MEMORY_RECORDS.value: 100000,
        UsageMetric.MEMORY_STORAGE_MB.value: 500000,
        UsageMetric.WORKFLOW_RUNS.value: 100000,
        UsageMetric.WEBHOOKS.value: 10000,
        UsageMetric.FILES.value: 100000,
        UsageMetric.STORAGE_MB.value: 5000000,
        UsageMetric.API_CALLS.value: 10000000,
        UsageMetric.TEAM_MEMBERS.value: 1000,
        UsageMetric.DEVICE_WORKERS.value: 1000,
        UsageMetric.DASHBOARD_SEATS.value: 1000,
    }


def default_features_for_plan(plan_key: PlanKey) -> Dict[str, Any]:
    if plan_key == PlanKey.FREE:
        return {
            "master_agent": True,
            "memory_agent": True,
            "verification_agent": True,
            "security_agent": False,
            "workflow_automation": False,
            "webhooks": False,
            "device_workers": False,
            "advanced_analytics": False,
            "priority_support": False,
        }

    if plan_key == PlanKey.PRO:
        return {
            "master_agent": True,
            "all_core_agents": True,
            "memory_agent": True,
            "verification_agent": True,
            "security_agent": True,
            "workflow_automation": True,
            "webhooks": True,
            "device_workers": True,
            "advanced_analytics": False,
            "priority_support": True,
        }

    if plan_key == PlanKey.BUSINESS:
        return {
            "master_agent": True,
            "all_core_agents": True,
            "memory_agent": True,
            "verification_agent": True,
            "security_agent": True,
            "workflow_automation": True,
            "webhooks": True,
            "device_workers": True,
            "advanced_analytics": True,
            "priority_support": True,
            "team_controls": True,
        }

    return {
        "master_agent": True,
        "all_core_agents": True,
        "memory_agent": True,
        "verification_agent": True,
        "security_agent": True,
        "workflow_automation": True,
        "webhooks": True,
        "device_workers": True,
        "advanced_analytics": True,
        "priority_support": True,
        "team_controls": True,
        "custom_integrations": True,
        "dedicated_support": True,
    }


def default_agent_access_for_plan(plan_key: PlanKey) -> Dict[str, bool]:
    if plan_key == PlanKey.FREE:
        allowed = {"master", "memory", "verification"}
        return {agent: agent in allowed for agent in ALL_AGENT_NAMES}

    return {agent: True for agent in ALL_AGENT_NAMES}


def default_price_cents(plan_key: PlanKey) -> int:
    prices = {
        PlanKey.FREE: FREE_PRICE_CENTS,
        PlanKey.PRO: PRO_PRICE_CENTS,
        PlanKey.BUSINESS: BUSINESS_PRICE_CENTS,
        PlanKey.ENTERPRISE: ENTERPRISE_PRICE_CENTS,
    }
    return prices.get(plan_key, 0)


def plan_rank(plan_key: PlanKey) -> int:
    ranks = {
        PlanKey.FREE: 1,
        PlanKey.PRO: 2,
        PlanKey.BUSINESS: 3,
        PlanKey.ENTERPRISE: 4,
    }
    return ranks.get(plan_key, 0)


def plan_at_least(current_plan: PlanKey, required_plan: PlanKey) -> bool:
    return plan_rank(current_plan) >= plan_rank(required_plan)


def invoice_number() -> str:
    return f"WJ-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"


# =============================================================================
# Required component
# =============================================================================

class Subscription:
    """
    Required class/component name: Subscription

    Utility component for evaluating plan, subscription, usage, and agent access.

    Safe to use inside:
    - FastAPI dependencies
    - Master Agent routing
    - Security Agent approval checks
    - workflow execution checks
    - dashboard feature gates
    - tests
    """

    @staticmethod
    def normalize_plan(plan: str | PlanKey) -> PlanKey:
        if isinstance(plan, PlanKey):
            return plan

        key = normalize_key(str(plan), "plan")
        for item in PlanKey:
            if item.value == key:
                return item

        raise ValueError(f"Unknown plan: {plan}")

    @staticmethod
    def limits(plan: str | PlanKey) -> Dict[str, int]:
        return default_limits_for_plan(Subscription.normalize_plan(plan))

    @staticmethod
    def features(plan: str | PlanKey) -> Dict[str, Any]:
        return default_features_for_plan(Subscription.normalize_plan(plan))

    @staticmethod
    def agent_access(plan: str | PlanKey) -> Dict[str, bool]:
        return default_agent_access_for_plan(Subscription.normalize_plan(plan))

    @staticmethod
    def has_feature(plan: str | PlanKey, feature_key: str) -> bool:
        key = normalize_key(feature_key, "feature_key")
        return bool(Subscription.features(plan).get(key, False))

    @staticmethod
    def can_use_agent(plan: str | PlanKey, agent_name: str) -> bool:
        agent = normalize_key(agent_name, "agent_name")
        return bool(Subscription.agent_access(plan).get(agent, False))

    @staticmethod
    def usage_allowed(plan: str | PlanKey, metric: str | UsageMetric, used: int, requested: int = 1) -> bool:
        metric_key = enum_value(metric)
        limit = Subscription.limits(plan).get(metric_key, 0)
        return safe_int(used) + safe_int(requested, 1) <= limit

    @staticmethod
    def safe_error(code: str, message: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "code": code,
                "message": message,
                "details": details or {},
            },
        }


# =============================================================================
# Models
# =============================================================================

class SubscriptionPlan(Base):
    """
    Defines available SaaS subscription plans.
    """

    __tablename__ = "subscription_plans"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("plan"))

    key: Mapped[str] = mapped_column(String(100), nullable=False, unique=True, index=True)
    name: Mapped[str] = mapped_column(String(140), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    status: Mapped[PlanStatus] = mapped_column(
        Enum(PlanStatus, name="subscription_plan_status"),
        nullable=False,
        default=PlanStatus.ACTIVE,
        index=True,
    )

    currency: Mapped[str] = mapped_column(String(3), nullable=False, default=DEFAULT_CURRENCY)
    price_monthly_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    price_yearly_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    max_agents: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    max_requests: Mapped[int] = mapped_column(Integer, nullable=False, default=1000)
    max_memory_storage: Mapped[int] = mapped_column(Integer, nullable=False, default=100)

    features: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    limits: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    agent_access: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    is_public: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    is_recommended: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)

    created_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    def __repr__(self) -> str:
        return f"SubscriptionPlan(id={self.id!r}, key={self.key!r}, status={enum_value(self.status)!r})"

    @classmethod
    def create(
        cls,
        plan_key: PlanKey,
        name: Optional[str] = None,
        description: Optional[str] = None,
        currency: str = DEFAULT_CURRENCY,
        price_monthly_cents: Optional[int] = None,
        price_yearly_cents: Optional[int] = None,
        is_recommended: bool = False,
        created_by: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "SubscriptionPlan":
        limits = default_limits_for_plan(plan_key)
        features = default_features_for_plan(plan_key)
        agent_access = default_agent_access_for_plan(plan_key)
        monthly_price = default_price_cents(plan_key) if price_monthly_cents is None else price_monthly_cents

        return cls(
            key=plan_key.value,
            name=name or plan_key.value.title(),
            description=description,
            status=PlanStatus.ACTIVE,
            currency=normalize_currency(currency),
            price_monthly_cents=monthly_price,
            price_yearly_cents=price_yearly_cents if price_yearly_cents is not None else monthly_price * 10,
            max_agents=limits.get(UsageMetric.AGENT_RUNS.value, 0),
            max_requests=limits.get(UsageMetric.API_CALLS.value, 0),
            max_memory_storage=limits.get(UsageMetric.MEMORY_STORAGE_MB.value, 0),
            features=features,
            limits=limits,
            agent_access=agent_access,
            is_public=True,
            is_recommended=is_recommended,
            is_active=True,
            sort_order=plan_rank(plan_key),
            created_by=validate_scope_id(created_by, "created_by") if created_by else None,
            metadata_json=metadata or {},
        )

    @property
    def plan_key(self) -> PlanKey:
        return Subscription.normalize_plan(self.key)

    def has_feature(self, feature_key: str) -> bool:
        return bool((self.features or {}).get(normalize_key(feature_key, "feature_key"), False))

    def can_use_agent(self, agent_name: str) -> bool:
        return bool((self.agent_access or {}).get(normalize_key(agent_name, "agent_name"), False))

    def get_limit(self, metric: str | UsageMetric) -> int:
        return safe_int((self.limits or {}).get(enum_value(metric), 0))

    def disable(self, updated_by: str) -> None:
        self.status = PlanStatus.DISABLED
        self.is_active = False
        self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()

    def activate(self, updated_by: str) -> None:
        self.status = PlanStatus.ACTIVE
        self.is_active = True
        self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()

    def safe_dict(self, include_metadata: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "key": self.key,
            "name": self.name,
            "description": self.description,
            "status": enum_value(self.status),
            "currency": self.currency,
            "price_monthly_cents": self.price_monthly_cents,
            "price_yearly_cents": self.price_yearly_cents,
            "price_monthly": self.price_monthly_cents,
            "max_agents": self.max_agents,
            "max_requests": self.max_requests,
            "max_memory_storage": self.max_memory_storage,
            "features": self.features or {},
            "limits": self.limits or {},
            "agent_access": self.agent_access or {},
            "is_public": self.is_public,
            "is_recommended": self.is_recommended,
            "is_active": self.is_active,
            "sort_order": self.sort_order,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

        if include_metadata:
            data["metadata"] = self.metadata_json or {}

        return data

    def to_dict(self) -> Dict[str, Any]:
        return self.safe_dict(include_metadata=True)


class WorkspaceSubscription(Base):
    """
    Tracks subscription state for each workspace.

    Every record is workspace-scoped.
    """

    __tablename__ = "workspace_subscriptions"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("sub"))

    user_id: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    workspace_id: Mapped[str] = mapped_column(String(140), nullable=False, index=True)

    plan_id: Mapped[Optional[str]] = mapped_column(
        String(140),
        ForeignKey("subscription_plans.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    plan_name: Mapped[str] = mapped_column(String(100), nullable=False, default=PlanKey.FREE.value, index=True)
    plan_key: Mapped[str] = mapped_column(String(100), nullable=False, default=PlanKey.FREE.value, index=True)

    status: Mapped[SubscriptionStatus] = mapped_column(
        Enum(SubscriptionStatus, name="workspace_subscription_status_model"),
        nullable=False,
        default=SubscriptionStatus.ACTIVE,
        index=True,
    )

    interval: Mapped[BillingInterval] = mapped_column(
        Enum(BillingInterval, name="billing_interval"),
        nullable=False,
        default=BillingInterval.MONTHLY,
    )

    currency: Mapped[str] = mapped_column(String(3), nullable=False, default=DEFAULT_CURRENCY)
    amount_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    provider: Mapped[BillingProvider] = mapped_column(
        Enum(BillingProvider, name="billing_provider"),
        nullable=False,
        default=BillingProvider.INTERNAL,
        index=True,
    )

    provider_customer_id: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)
    provider_subscription_id: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)

    start_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    end_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    current_period_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    trial_ends_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    auto_renew: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cancelled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    usage_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    billing_state: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)

    created_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    plan: Mapped[Optional["SubscriptionPlan"]] = relationship("SubscriptionPlan", lazy="selectin")

    __table_args__ = (
        Index("ix_workspace_subscriptions_workspace_status", "workspace_id", "status"),
        Index("ix_workspace_subscriptions_workspace_plan", "workspace_id", "plan_key"),
        Index("ix_workspace_subscriptions_provider_sub_id", "provider", "provider_subscription_id"),
    )

    def __repr__(self) -> str:
        return (
            f"WorkspaceSubscription(id={self.id!r}, workspace_id={self.workspace_id!r}, "
            f"plan_key={self.plan_key!r}, status={enum_value(self.status)!r})"
        )

    @classmethod
    def create(
        cls,
        workspace_id: str,
        plan_key: PlanKey = PlanKey.FREE,
        user_id: Optional[str] = None,
        plan_id: Optional[str] = None,
        interval: BillingInterval = BillingInterval.MONTHLY,
        provider: BillingProvider = BillingProvider.INTERNAL,
        created_by: Optional[str] = None,
        provider_customer_id: Optional[str] = None,
        provider_subscription_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "WorkspaceSubscription":
        price = default_price_cents(plan_key)

        return cls(
            user_id=validate_scope_id(user_id, "user_id") if user_id else None,
            workspace_id=validate_scope_id(workspace_id, "workspace_id"),
            plan_id=validate_scope_id(plan_id, "plan_id") if plan_id else None,
            plan_name=plan_key.value,
            plan_key=plan_key.value,
            status=SubscriptionStatus.ACTIVE,
            interval=interval,
            currency=DEFAULT_CURRENCY,
            amount_cents=price,
            provider=provider,
            provider_customer_id=provider_customer_id,
            provider_subscription_id=provider_subscription_id,
            start_date=utc_now(),
            current_period_start=utc_now(),
            auto_renew=True,
            cancel_at_period_end=False,
            usage_data={},
            billing_state={},
            metadata_json=metadata or {},
            created_by=validate_scope_id(created_by, "created_by") if created_by else None,
        )

    @property
    def subscription_active(self) -> bool:
        if self.status not in {SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING}:
            return False

        if self.end_date and utc_now() > self.end_date:
            return False

        return True

    @property
    def is_active(self) -> bool:
        return self.subscription_active

    @property
    def scope(self) -> DbScope:
        return DbScope(user_id=self.user_id or self.workspace_id, workspace_id=self.workspace_id)

    def current_plan(self) -> PlanKey:
        return Subscription.normalize_plan(self.plan_key or self.plan_name or PlanKey.FREE.value)

    def has_plan_at_least(self, required_plan: PlanKey) -> bool:
        return plan_at_least(self.current_plan(), required_plan)

    def get_limit(self, metric: str | UsageMetric) -> int:
        if self.plan is not None:
            return self.plan.get_limit(metric)
        return default_limits_for_plan(self.current_plan()).get(enum_value(metric), 0)

    def has_feature(self, feature_key: str) -> bool:
        if self.plan is not None:
            return self.plan.has_feature(feature_key)
        return Subscription.has_feature(self.current_plan(), feature_key)

    def can_use_agent(self, agent_name: str) -> bool:
        if not self.subscription_active:
            return False

        if self.plan is not None:
            return self.plan.can_use_agent(agent_name)

        return Subscription.can_use_agent(self.current_plan(), agent_name)

    def change_plan(
        self,
        plan_key: PlanKey,
        updated_by: str,
        plan_id: Optional[str] = None,
        amount_cents: Optional[int] = None,
        reason: Optional[str] = None,
    ) -> None:
        old_plan = self.plan_key
        self.plan_key = plan_key.value
        self.plan_name = plan_key.value
        self.plan_id = validate_scope_id(plan_id, "plan_id") if plan_id else self.plan_id
        self.amount_cents = default_price_cents(plan_key) if amount_cents is None else int(amount_cents)
        self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()
        self.billing_state = {
            **(self.billing_state or {}),
            "last_plan_change": {
                "old_plan": old_plan,
                "new_plan": plan_key.value,
                "reason": reason,
                "changed_by": self.updated_by,
                "changed_at": utc_now().isoformat(),
            },
        }

    def cancel(self, updated_by: str, at_period_end: bool = True, reason: Optional[str] = None) -> None:
        self.cancel_at_period_end = at_period_end
        self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()

        if not at_period_end:
            self.status = SubscriptionStatus.CANCELLED
            self.cancelled_at = utc_now()
            self.end_date = utc_now()

        self.billing_state = {
            **(self.billing_state or {}),
            "cancel_reason": reason,
            "cancel_requested_at": utc_now().isoformat(),
            "cancel_requested_by": self.updated_by,
        }

    def reactivate(self, updated_by: str, reason: Optional[str] = None) -> None:
        self.status = SubscriptionStatus.ACTIVE
        self.cancel_at_period_end = False
        self.cancelled_at = None
        self.end_date = None
        self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()
        self.billing_state = {
            **(self.billing_state or {}),
            "reactivated_reason": reason,
            "reactivated_at": utc_now().isoformat(),
            "reactivated_by": self.updated_by,
        }

    def suspend(self, updated_by: str, reason: Optional[str] = None) -> None:
        self.status = SubscriptionStatus.SUSPENDED
        self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()
        self.billing_state = {
            **(self.billing_state or {}),
            "suspension_reason": reason,
            "suspended_at": utc_now().isoformat(),
            "suspended_by": self.updated_by,
        }

    def safe_dict(self, include_metadata: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "plan_id": self.plan_id,
            "plan_name": self.plan_name,
            "plan_key": self.plan_key,
            "status": enum_value(self.status),
            "interval": enum_value(self.interval),
            "currency": self.currency,
            "amount_cents": self.amount_cents,
            "provider": enum_value(self.provider),
            "provider_customer_id": self.provider_customer_id,
            "provider_subscription_id": self.provider_subscription_id,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "current_period_start": self.current_period_start.isoformat() if self.current_period_start else None,
            "current_period_end": self.current_period_end.isoformat() if self.current_period_end else None,
            "trial_ends_at": self.trial_ends_at.isoformat() if self.trial_ends_at else None,
            "auto_renew": self.auto_renew,
            "cancel_at_period_end": self.cancel_at_period_end,
            "cancelled_at": self.cancelled_at.isoformat() if self.cancelled_at else None,
            "subscription_active": self.subscription_active,
            "usage_data": self.usage_data or {},
            "billing_state": self.billing_state or {},
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

        if include_metadata:
            data["metadata"] = self.metadata_json or {}

        return data

    def to_dict(self) -> Dict[str, Any]:
        return self.safe_dict(include_metadata=True)

    def _prepare_memory_payload(self) -> Dict[str, Any]:
        return {
            "entity": "workspace_subscription",
            "subscription_id": self.id,
            "workspace_id": self.workspace_id,
            "plan_key": self.plan_key,
            "status": enum_value(self.status),
            "subscription_active": self.subscription_active,
        }

    def _prepare_verification_payload(self) -> Dict[str, Any]:
        return {
            "entity": "workspace_subscription",
            "subscription_id": self.id,
            "workspace_id": self.workspace_id,
            "plan_key": self.plan_key,
            "status": enum_value(self.status),
            "timestamp": utc_now().isoformat(),
        }

    def _log_audit_event(self, action: str, actor_user_id: Optional[str] = None) -> Dict[str, Any]:
        return {
            "action": action,
            "entity": "workspace_subscription",
            "subscription_id": self.id,
            "workspace_id": self.workspace_id,
            "actor_user_id": actor_user_id,
            "timestamp": utc_now().isoformat(),
        }


class UsageLimit(Base):
    """
    Defines a limit for a plan and metric.
    """

    __tablename__ = "usage_limits"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("ul"))

    plan_key: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    metric_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    limit_value: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    period: Mapped[UsagePeriod] = mapped_column(
        Enum(UsagePeriod, name="usage_period"),
        nullable=False,
        default=UsagePeriod.MONTHLY,
        index=True,
    )

    is_hard_limit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    overage_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    overage_price_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    metadata_json: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    __table_args__ = (
        UniqueConstraint("plan_key", "metric_name", "period", name="uq_usage_limit_plan_metric_period"),
        Index("ix_usage_limits_plan_metric", "plan_key", "metric_name"),
    )

    @classmethod
    def create(
        cls,
        plan_key: PlanKey,
        metric: UsageMetric,
        limit_value: int,
        period: UsagePeriod = UsagePeriod.MONTHLY,
        is_hard_limit: bool = True,
        overage_allowed: bool = False,
        overage_price_cents: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "UsageLimit":
        return cls(
            plan_key=plan_key.value,
            metric_name=metric.value,
            limit_value=int(limit_value),
            period=period,
            is_hard_limit=is_hard_limit,
            overage_allowed=overage_allowed,
            overage_price_cents=int(overage_price_cents),
            metadata_json=metadata or {},
        )

    def safe_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "plan_key": self.plan_key,
            "metric_name": self.metric_name,
            "limit_value": self.limit_value,
            "period": enum_value(self.period),
            "is_hard_limit": self.is_hard_limit,
            "overage_allowed": self.overage_allowed,
            "overage_price_cents": self.overage_price_cents,
            "metadata": self.metadata_json or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.safe_dict()


class UsageTracking(Base):
    """
    Tracks usage per workspace for billing enforcement.

    Every usage counter is scoped by workspace_id and metric_name.
    """

    __tablename__ = "usage_tracking"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("usage"))

    user_id: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    workspace_id: Mapped[str] = mapped_column(String(140), nullable=False, index=True)

    metric_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    usage_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    limit_value: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    period: Mapped[UsagePeriod] = mapped_column(
        Enum(UsagePeriod, name="usage_tracking_period"),
        nullable=False,
        default=UsagePeriod.MONTHLY,
        index=True,
    )

    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    period_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    last_updated: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)

    __table_args__ = (
        UniqueConstraint("workspace_id", "metric_name", "period", name="uq_usage_workspace_metric_period"),
        Index("ix_usage_tracking_workspace_metric", "workspace_id", "metric_name"),
        Index("ix_usage_tracking_user_workspace", "user_id", "workspace_id"),
    )

    @classmethod
    def create(
        cls,
        workspace_id: str,
        metric: UsageMetric,
        limit_value: int,
        user_id: Optional[str] = None,
        period: UsagePeriod = UsagePeriod.MONTHLY,
        usage_count: int = 0,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "UsageTracking":
        return cls(
            user_id=validate_scope_id(user_id, "user_id") if user_id else None,
            workspace_id=validate_scope_id(workspace_id, "workspace_id"),
            metric_name=metric.value,
            usage_count=int(usage_count),
            limit_value=int(limit_value),
            period=period,
            period_start=utc_now(),
            last_updated=utc_now(),
            metadata_json=metadata or {},
        )

    @property
    def remaining(self) -> int:
        return max(int(self.limit_value) - int(self.usage_count), 0)

    @property
    def is_limit_reached(self) -> bool:
        return int(self.usage_count) >= int(self.limit_value)

    def scope(self) -> DbScope:
        return DbScope(user_id=self.user_id or self.workspace_id, workspace_id=self.workspace_id)

    def can_increment(self, amount: int = 1) -> bool:
        return int(self.usage_count) + int(amount) <= int(self.limit_value)

    def increment(self, amount: int = 1, allow_over_limit: bool = False) -> None:
        amount_int = int(amount)
        if amount_int < 1:
            raise ValueError("amount must be greater than zero.")

        if not allow_over_limit and not self.can_increment(amount_int):
            raise PermissionError(f"Usage limit exceeded for metric: {self.metric_name}")

        self.usage_count += amount_int
        self.last_updated = utc_now()

    def reset(self, limit_value: Optional[int] = None) -> None:
        self.usage_count = 0
        if limit_value is not None:
            self.limit_value = int(limit_value)
        self.period_start = utc_now()
        self.period_end = None
        self.last_updated = utc_now()

    def safe_dict(self, include_metadata: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "metric_name": self.metric_name,
            "usage_count": self.usage_count,
            "limit_value": self.limit_value,
            "remaining": self.remaining,
            "is_limit_reached": self.is_limit_reached,
            "period": enum_value(self.period),
            "period_start": self.period_start.isoformat() if self.period_start else None,
            "period_end": self.period_end.isoformat() if self.period_end else None,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
        }

        if include_metadata:
            data["metadata"] = self.metadata_json or {}

        return data

    def to_dict(self) -> Dict[str, Any]:
        return self.safe_dict(include_metadata=True)

    def _prepare_memory_payload(self) -> Dict[str, Any]:
        return {
            "entity": "usage_tracking",
            "usage_id": self.id,
            "workspace_id": self.workspace_id,
            "metric_name": self.metric_name,
            "usage_count": self.usage_count,
            "limit_value": self.limit_value,
            "remaining": self.remaining,
        }

    def _prepare_verification_payload(self) -> Dict[str, Any]:
        return {
            "entity": "usage_tracking",
            "usage_id": self.id,
            "workspace_id": self.workspace_id,
            "metric_name": self.metric_name,
            "usage_count": self.usage_count,
            "limit_value": self.limit_value,
            "timestamp": utc_now().isoformat(),
        }


class AgentAccess(Base):
    """
    Controls which agents are available per subscription plan.
    """

    __tablename__ = "agent_access"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("aa"))

    plan_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    plan_key: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    agent_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    status: Mapped[AgentAccessStatus] = mapped_column(
        Enum(AgentAccessStatus, name="agent_access_status"),
        nullable=False,
        default=AgentAccessStatus.ALLOWED,
        index=True,
    )

    is_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    monthly_limit: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    permissions: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    requires_security_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    __table_args__ = (
        UniqueConstraint("plan_key", "agent_name", name="uq_agent_access_plan_agent"),
        Index("ix_agent_access_plan_allowed", "plan_key", "is_allowed"),
    )

    @classmethod
    def create(
        cls,
        plan_key: PlanKey,
        agent_name: str,
        is_allowed: Optional[bool] = None,
        monthly_limit: Optional[int] = None,
        permissions: Optional[Dict[str, Any]] = None,
        requires_security_approval: bool = False,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "AgentAccess":
        agent = normalize_key(agent_name, "agent_name")
        allowed = default_agent_access_for_plan(plan_key).get(agent, False) if is_allowed is None else bool(is_allowed)

        return cls(
            plan_name=plan_key.value,
            plan_key=plan_key.value,
            agent_name=agent,
            status=AgentAccessStatus.ALLOWED if allowed else AgentAccessStatus.BLOCKED,
            is_allowed=allowed,
            monthly_limit=monthly_limit,
            permissions=permissions or {},
            requires_security_approval=requires_security_approval,
            metadata_json=metadata or {},
        )

    def allow(self) -> None:
        self.status = AgentAccessStatus.ALLOWED
        self.is_allowed = True
        self.updated_at = utc_now()

    def block(self) -> None:
        self.status = AgentAccessStatus.BLOCKED
        self.is_allowed = False
        self.updated_at = utc_now()

    def safe_dict(self, include_metadata: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "plan_name": self.plan_name,
            "plan_key": self.plan_key,
            "agent_name": self.agent_name,
            "status": enum_value(self.status),
            "is_allowed": self.is_allowed,
            "monthly_limit": self.monthly_limit,
            "permissions": self.permissions or {},
            "requires_security_approval": self.requires_security_approval,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

        if include_metadata:
            data["metadata"] = self.metadata_json or {}

        return data

    def to_dict(self) -> Dict[str, Any]:
        return self.safe_dict(include_metadata=True)


class Invoice(Base):
    """
    Invoice and billing state record.

    Every invoice is scoped to workspace_id.
    """

    __tablename__ = "invoices"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("inv"))

    user_id: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    workspace_id: Mapped[str] = mapped_column(String(140), nullable=False, index=True)
    subscription_id: Mapped[Optional[str]] = mapped_column(
        String(140),
        ForeignKey("workspace_subscriptions.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    invoice_number: Mapped[str] = mapped_column(String(80), nullable=False, unique=True, index=True)
    status: Mapped[InvoiceStatus] = mapped_column(
        Enum(InvoiceStatus, name="invoice_status"),
        nullable=False,
        default=InvoiceStatus.OPEN,
        index=True,
    )

    currency: Mapped[str] = mapped_column(String(3), nullable=False, default=DEFAULT_CURRENCY)
    subtotal_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tax_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    discount_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    line_items: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)

    provider: Mapped[BillingProvider] = mapped_column(
        Enum(BillingProvider, name="invoice_billing_provider"),
        nullable=False,
        default=BillingProvider.INTERNAL,
        index=True,
    )

    provider_invoice_id: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)
    hosted_invoice_url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    invoice_pdf_url: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)

    due_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    paid_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    voided_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    metadata_json: Mapped[Dict[str, Any]] = mapped_column("metadata", JSON, nullable=False, default=dict)

    created_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    subscription: Mapped[Optional["WorkspaceSubscription"]] = relationship("WorkspaceSubscription", lazy="selectin")

    __table_args__ = (
        Index("ix_invoices_workspace_status", "workspace_id", "status"),
        Index("ix_invoices_user_workspace", "user_id", "workspace_id"),
        Index("ix_invoices_provider_invoice", "provider", "provider_invoice_id"),
    )

    @classmethod
    def create(
        cls,
        workspace_id: str,
        line_items: List[Dict[str, Any]],
        user_id: Optional[str] = None,
        subscription_id: Optional[str] = None,
        currency: str = DEFAULT_CURRENCY,
        tax_cents: int = 0,
        discount_cents: int = 0,
        status: InvoiceStatus = InvoiceStatus.OPEN,
        provider: BillingProvider = BillingProvider.INTERNAL,
        created_by: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "Invoice":
        subtotal = sum(safe_int(item.get("amount_cents"), 0) for item in line_items)
        total = max(subtotal + int(tax_cents) - int(discount_cents), 0)

        return cls(
            user_id=validate_scope_id(user_id, "user_id") if user_id else None,
            workspace_id=validate_scope_id(workspace_id, "workspace_id"),
            subscription_id=validate_scope_id(subscription_id, "subscription_id") if subscription_id else None,
            invoice_number=invoice_number(),
            status=status,
            currency=normalize_currency(currency),
            subtotal_cents=subtotal,
            tax_cents=int(tax_cents),
            discount_cents=int(discount_cents),
            total_cents=total,
            line_items=line_items,
            provider=provider,
            paid_at=utc_now() if status == InvoiceStatus.PAID else None,
            created_by=validate_scope_id(created_by, "created_by") if created_by else None,
            metadata_json=metadata or {},
        )

    def mark_paid(self, updated_by: Optional[str] = None) -> None:
        self.status = InvoiceStatus.PAID
        self.paid_at = utc_now()
        if updated_by:
            self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()

    def mark_void(self, updated_by: Optional[str] = None) -> None:
        self.status = InvoiceStatus.VOID
        self.voided_at = utc_now()
        if updated_by:
            self.updated_by = validate_scope_id(updated_by, "updated_by")
        self.updated_at = utc_now()

    def safe_dict(self, include_metadata: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "subscription_id": self.subscription_id,
            "invoice_number": self.invoice_number,
            "status": enum_value(self.status),
            "currency": self.currency,
            "subtotal_cents": self.subtotal_cents,
            "tax_cents": self.tax_cents,
            "discount_cents": self.discount_cents,
            "total_cents": self.total_cents,
            "line_items": self.line_items or [],
            "provider": enum_value(self.provider),
            "provider_invoice_id": self.provider_invoice_id,
            "hosted_invoice_url": self.hosted_invoice_url,
            "invoice_pdf_url": self.invoice_pdf_url,
            "due_at": self.due_at.isoformat() if self.due_at else None,
            "paid_at": self.paid_at.isoformat() if self.paid_at else None,
            "voided_at": self.voided_at.isoformat() if self.voided_at else None,
            "created_by": self.created_by,
            "updated_by": self.updated_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

        if include_metadata:
            data["metadata"] = self.metadata_json or {}

        return data

    def to_dict(self) -> Dict[str, Any]:
        return self.safe_dict(include_metadata=True)


class BillingEvent(Base):
    """
    Billing event/audit trail for subscription state changes.

    This is not a replacement for audit logs. It is a billing-specific timeline.
    """

    __tablename__ = "billing_events"

    id: Mapped[str] = mapped_column(String(140), primary_key=True, default=lambda: generate_id("be"))

    user_id: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    workspace_id: Mapped[str] = mapped_column(String(140), nullable=False, index=True)

    event_type: Mapped[BillingEventType] = mapped_column(
        Enum(BillingEventType, name="billing_event_type"),
        nullable=False,
        index=True,
    )

    entity_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    entity_id: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)

    payload: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    provider: Mapped[BillingProvider] = mapped_column(
        Enum(BillingProvider, name="billing_event_provider"),
        nullable=False,
        default=BillingProvider.INTERNAL,
        index=True,
    )

    provider_event_id: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(140), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    __table_args__ = (
        Index("ix_billing_events_workspace_type", "workspace_id", "event_type"),
        Index("ix_billing_events_user_workspace", "user_id", "workspace_id"),
    )

    @classmethod
    def create(
        cls,
        workspace_id: str,
        event_type: BillingEventType,
        entity_type: str,
        entity_id: Optional[str] = None,
        user_id: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
        provider: BillingProvider = BillingProvider.INTERNAL,
        provider_event_id: Optional[str] = None,
        request_id: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> "BillingEvent":
        return cls(
            user_id=validate_scope_id(user_id, "user_id") if user_id else None,
            workspace_id=validate_scope_id(workspace_id, "workspace_id"),
            event_type=event_type,
            entity_type=normalize_key(entity_type, "entity_type"),
            entity_id=validate_scope_id(entity_id, "entity_id") if entity_id else None,
            payload=payload or {},
            provider=provider,
            provider_event_id=provider_event_id,
            request_id=request_id,
            created_by=validate_scope_id(created_by, "created_by") if created_by else None,
        )

    def safe_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "event_type": enum_value(self.event_type),
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "payload": self.payload or {},
            "provider": enum_value(self.provider),
            "provider_event_id": self.provider_event_id,
            "request_id": self.request_id,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

    def to_dict(self) -> Dict[str, Any]:
        return self.safe_dict()


# =============================================================================
# Helper functions
# =============================================================================

def require_subscription_active(subscription: WorkspaceSubscription) -> WorkspaceSubscription:
    if not subscription.subscription_active:
        raise PermissionError("Workspace subscription is not active.")
    return subscription


def require_plan_at_least(subscription: WorkspaceSubscription, required_plan: PlanKey) -> WorkspaceSubscription:
    require_subscription_active(subscription)

    if not subscription.has_plan_at_least(required_plan):
        raise PermissionError(f"Plan {required_plan.value} or higher is required.")

    return subscription


def require_agent_allowed(subscription: WorkspaceSubscription, agent_name: str) -> bool:
    require_subscription_active(subscription)

    if not subscription.can_use_agent(agent_name):
        raise PermissionError(f"Agent is not allowed for this subscription plan: {agent_name}")

    return True


def require_usage_available(usage: UsageTracking, amount: int = 1) -> bool:
    if not usage.can_increment(amount):
        raise PermissionError(f"Usage limit exceeded for metric: {usage.metric_name}")
    return True


def subscription_scope_filter(workspace_id: str) -> Dict[str, str]:
    return {"workspace_id": validate_scope_id(workspace_id, "workspace_id")}


def user_subscription_scope_filter(user_id: str, workspace_id: str) -> Dict[str, str]:
    return {
        "user_id": validate_scope_id(user_id, "user_id"),
        "workspace_id": validate_scope_id(workspace_id, "workspace_id"),
    }


def usage_scope_filter(workspace_id: str, metric_name: Optional[str] = None) -> Dict[str, str]:
    data = {"workspace_id": validate_scope_id(workspace_id, "workspace_id")}
    if metric_name:
        data["metric_name"] = normalize_key(metric_name, "metric_name")
    return data


def build_default_plan_models(created_by: Optional[str] = None) -> List[SubscriptionPlan]:
    return [
        SubscriptionPlan.create(
            PlanKey.FREE,
            name="Free",
            description="Starter plan for testing William/Jarvis with limited usage.",
            created_by=created_by,
        ),
        SubscriptionPlan.create(
            PlanKey.PRO,
            name="Pro",
            description="Professional plan with all core agents and workflow automation.",
            is_recommended=True,
            created_by=created_by,
        ),
        SubscriptionPlan.create(
            PlanKey.BUSINESS,
            name="Business",
            description="Business plan for teams, higher limits, analytics, and security workflows.",
            created_by=created_by,
        ),
        SubscriptionPlan.create(
            PlanKey.ENTERPRISE,
            name="Enterprise",
            description="Enterprise plan for high-scale usage, custom integrations, and dedicated support.",
            created_by=created_by,
        ),
    ]


def build_default_usage_limit_models() -> List[UsageLimit]:
    limits: List[UsageLimit] = []

    for plan_key in PlanKey:
        plan_limits = default_limits_for_plan(plan_key)
        for metric_name, limit_value in plan_limits.items():
            metric = UsageMetric(metric_name)
            limits.append(
                UsageLimit.create(
                    plan_key=plan_key,
                    metric=metric,
                    limit_value=limit_value,
                    period=UsagePeriod.MONTHLY,
                    is_hard_limit=True,
                    overage_allowed=plan_key in {PlanKey.BUSINESS, PlanKey.ENTERPRISE},
                )
            )

    return limits


def build_default_agent_access_models() -> List[AgentAccess]:
    access_records: List[AgentAccess] = []

    for plan_key in PlanKey:
        access_map = default_agent_access_for_plan(plan_key)
        for agent_name, is_allowed in access_map.items():
            access_records.append(
                AgentAccess.create(
                    plan_key=plan_key,
                    agent_name=agent_name,
                    is_allowed=is_allowed,
                    requires_security_approval=agent_name in {"system", "browser", "security"},
                )
            )

    return access_records


# =============================================================================
# SQLAlchemy events
# =============================================================================

@event.listens_for(SubscriptionPlan, "before_insert")
def subscription_plan_before_insert(mapper: Any, connection: Any, target: SubscriptionPlan) -> None:
    if not target.id:
        target.id = generate_id("plan")

    target.key = normalize_key(target.key, "plan_key")
    target.name = str(target.name or target.key.title()).strip()[:140]
    target.currency = normalize_currency(target.currency)

    plan_key = Subscription.normalize_plan(target.key)

    if target.features is None:
        target.features = default_features_for_plan(plan_key)

    if target.limits is None:
        target.limits = default_limits_for_plan(plan_key)

    if target.agent_access is None:
        target.agent_access = default_agent_access_for_plan(plan_key)

    if target.metadata_json is None:
        target.metadata_json = {}

    target.max_agents = target.max_agents or target.limits.get(UsageMetric.AGENT_RUNS.value, 0)
    target.max_requests = target.max_requests or target.limits.get(UsageMetric.API_CALLS.value, 0)
    target.max_memory_storage = target.max_memory_storage or target.limits.get(UsageMetric.MEMORY_STORAGE_MB.value, 0)

    if target.created_by:
        target.created_by = validate_scope_id(target.created_by, "created_by")

    if target.updated_by:
        target.updated_by = validate_scope_id(target.updated_by, "updated_by")

    now = utc_now()
    target.created_at = target.created_at or now
    target.updated_at = now


@event.listens_for(SubscriptionPlan, "before_update")
def subscription_plan_before_update(mapper: Any, connection: Any, target: SubscriptionPlan) -> None:
    target.key = normalize_key(target.key, "plan_key")
    target.currency = normalize_currency(target.currency)
    target.is_active = target.status == PlanStatus.ACTIVE
    target.updated_at = utc_now()


@event.listens_for(WorkspaceSubscription, "before_insert")
def workspace_subscription_before_insert(mapper: Any, connection: Any, target: WorkspaceSubscription) -> None:
    if not target.id:
        target.id = generate_id("sub")

    if target.user_id:
        target.user_id = validate_scope_id(target.user_id, "user_id")

    target.workspace_id = validate_scope_id(target.workspace_id, "workspace_id")
    target.plan_key = normalize_key(target.plan_key or target.plan_name or PlanKey.FREE.value, "plan_key")
    target.plan_name = target.plan_key
    target.currency = normalize_currency(target.currency)

    if target.plan_id:
        target.plan_id = validate_scope_id(target.plan_id, "plan_id")

    if target.created_by:
        target.created_by = validate_scope_id(target.created_by, "created_by")

    if target.updated_by:
        target.updated_by = validate_scope_id(target.updated_by, "updated_by")

    if target.usage_data is None:
        target.usage_data = {}

    if target.billing_state is None:
        target.billing_state = {}

    if target.metadata_json is None:
        target.metadata_json = {}

    now = utc_now()
    target.start_date = target.start_date or now
    target.current_period_start = target.current_period_start or now
    target.created_at = target.created_at or now
    target.updated_at = now


@event.listens_for(WorkspaceSubscription, "before_update")
def workspace_subscription_before_update(mapper: Any, connection: Any, target: WorkspaceSubscription) -> None:
    target.plan_key = normalize_key(target.plan_key or target.plan_name or PlanKey.FREE.value, "plan_key")
    target.plan_name = target.plan_key
    target.currency = normalize_currency(target.currency)
    target.updated_at = utc_now()

    if target.status == SubscriptionStatus.ACTIVE and target.end_date and utc_now() > target.end_date:
        target.status = SubscriptionStatus.EXPIRED


@event.listens_for(UsageLimit, "before_insert")
def usage_limit_before_insert(mapper: Any, connection: Any, target: UsageLimit) -> None:
    if not target.id:
        target.id = generate_id("ul")

    target.plan_key = normalize_key(target.plan_key, "plan_key")
    target.metric_name = normalize_key(target.metric_name, "metric_name")
    target.limit_value = int(target.limit_value)

    if target.metadata_json is None:
        target.metadata_json = {}

    now = utc_now()
    target.created_at = target.created_at or now
    target.updated_at = now


@event.listens_for(UsageLimit, "before_update")
def usage_limit_before_update(mapper: Any, connection: Any, target: UsageLimit) -> None:
    target.plan_key = normalize_key(target.plan_key, "plan_key")
    target.metric_name = normalize_key(target.metric_name, "metric_name")
    target.limit_value = int(target.limit_value)
    target.updated_at = utc_now()


@event.listens_for(UsageTracking, "before_insert")
def usage_tracking_before_insert(mapper: Any, connection: Any, target: UsageTracking) -> None:
    if not target.id:
        target.id = generate_id("usage")

    if target.user_id:
        target.user_id = validate_scope_id(target.user_id, "user_id")

    target.workspace_id = validate_scope_id(target.workspace_id, "workspace_id")
    target.metric_name = normalize_key(target.metric_name, "metric_name")
    target.usage_count = int(target.usage_count or 0)
    target.limit_value = int(target.limit_value or 0)

    if target.metadata_json is None:
        target.metadata_json = {}

    now = utc_now()
    target.period_start = target.period_start or now
    target.last_updated = now


@event.listens_for(UsageTracking, "before_update")
def usage_tracking_before_update(mapper: Any, connection: Any, target: UsageTracking) -> None:
    target.metric_name = normalize_key(target.metric_name, "metric_name")
    target.usage_count = int(target.usage_count or 0)
    target.limit_value = int(target.limit_value or 0)
    target.last_updated = utc_now()


@event.listens_for(AgentAccess, "before_insert")
def agent_access_before_insert(mapper: Any, connection: Any, target: AgentAccess) -> None:
    if not target.id:
        target.id = generate_id("aa")

    target.plan_key = normalize_key(target.plan_key or target.plan_name, "plan_key")
    target.plan_name = target.plan_key
    target.agent_name = normalize_key(target.agent_name, "agent_name")
    target.is_allowed = target.status == AgentAccessStatus.ALLOWED if target.status else bool(target.is_allowed)

    if target.permissions is None:
        target.permissions = {}

    if target.metadata_json is None:
        target.metadata_json = {}

    now = utc_now()
    target.created_at = target.created_at or now
    target.updated_at = now


@event.listens_for(AgentAccess, "before_update")
def agent_access_before_update(mapper: Any, connection: Any, target: AgentAccess) -> None:
    target.plan_key = normalize_key(target.plan_key or target.plan_name, "plan_key")
    target.plan_name = target.plan_key
    target.agent_name = normalize_key(target.agent_name, "agent_name")
    target.is_allowed = target.status == AgentAccessStatus.ALLOWED
    target.updated_at = utc_now()


@event.listens_for(Invoice, "before_insert")
def invoice_before_insert(mapper: Any, connection: Any, target: Invoice) -> None:
    if not target.id:
        target.id = generate_id("inv")

    if target.user_id:
        target.user_id = validate_scope_id(target.user_id, "user_id")

    target.workspace_id = validate_scope_id(target.workspace_id, "workspace_id")

    if target.subscription_id:
        target.subscription_id = validate_scope_id(target.subscription_id, "subscription_id")

    if not target.invoice_number:
        target.invoice_number = invoice_number()

    target.currency = normalize_currency(target.currency)
    target.subtotal_cents = int(target.subtotal_cents or 0)
    target.tax_cents = int(target.tax_cents or 0)
    target.discount_cents = int(target.discount_cents or 0)
    target.total_cents = max(target.subtotal_cents + target.tax_cents - target.discount_cents, 0)

    if target.line_items is None:
        target.line_items = []

    if target.metadata_json is None:
        target.metadata_json = {}

    if target.created_by:
        target.created_by = validate_scope_id(target.created_by, "created_by")

    if target.updated_by:
        target.updated_by = validate_scope_id(target.updated_by, "updated_by")

    now = utc_now()
    target.created_at = target.created_at or now
    target.updated_at = now


@event.listens_for(Invoice, "before_update")
def invoice_before_update(mapper: Any, connection: Any, target: Invoice) -> None:
    target.currency = normalize_currency(target.currency)
    target.subtotal_cents = int(target.subtotal_cents or 0)
    target.tax_cents = int(target.tax_cents or 0)
    target.discount_cents = int(target.discount_cents or 0)
    target.total_cents = max(target.subtotal_cents + target.tax_cents - target.discount_cents, 0)
    target.updated_at = utc_now()


@event.listens_for(BillingEvent, "before_insert")
def billing_event_before_insert(mapper: Any, connection: Any, target: BillingEvent) -> None:
    if not target.id:
        target.id = generate_id("be")

    if target.user_id:
        target.user_id = validate_scope_id(target.user_id, "user_id")

    target.workspace_id = validate_scope_id(target.workspace_id, "workspace_id")
    target.entity_type = normalize_key(target.entity_type, "entity_type")

    if target.entity_id:
        target.entity_id = validate_scope_id(target.entity_id, "entity_id")

    if target.created_by:
        target.created_by = validate_scope_id(target.created_by, "created_by")

    if target.payload is None:
        target.payload = {}

    target.created_at = target.created_at or utc_now()


# =============================================================================
# Backward compatibility aliases
# =============================================================================

SubscriptionPlanModel = SubscriptionPlan
WorkspaceSubscriptionModel = WorkspaceSubscription
UsageLimitModel = UsageLimit
UsageTrackingModel = UsageTracking
AgentAccessModel = AgentAccess
InvoiceModel = Invoice
BillingEventModel = BillingEvent


class SubscriptionModels:
    """
    Compatibility wrapper for Master Agent / Billing system.
    """

    Plan = SubscriptionPlan
    Workspace = WorkspaceSubscription
    UsageLimit = UsageLimit
    Usage = UsageTracking
    Access = AgentAccess
    Invoice = Invoice
    Event = BillingEvent


__all__ = [
    "Subscription",
    "SubscriptionPlan",
    "SubscriptionPlanModel",
    "WorkspaceSubscription",
    "WorkspaceSubscriptionModel",
    "UsageLimit",
    "UsageLimitModel",
    "UsageTracking",
    "UsageTrackingModel",
    "AgentAccess",
    "AgentAccessModel",
    "Invoice",
    "InvoiceModel",
    "BillingEvent",
    "BillingEventModel",
    "SubscriptionModels",
    "PlanKey",
    "PlanStatus",
    "BillingInterval",
    "SubscriptionStatus",
    "UsageMetric",
    "UsagePeriod",
    "AgentAccessStatus",
    "BillingProvider",
    "InvoiceStatus",
    "BillingEventType",
    "ALL_AGENT_NAMES",
    "default_limits_for_plan",
    "default_features_for_plan",
    "default_agent_access_for_plan",
    "default_price_cents",
    "plan_rank",
    "plan_at_least",
    "require_subscription_active",
    "require_plan_at_least",
    "require_agent_allowed",
    "require_usage_available",
    "subscription_scope_filter",
    "user_subscription_scope_filter",
    "usage_scope_filter",
    "build_default_plan_models",
    "build_default_usage_limit_models",
    "build_default_agent_access_models",
]