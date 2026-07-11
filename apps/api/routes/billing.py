"""
apps/api/routes/billing.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Agent/Module: API Prompt Bible
Purpose: plans, subscription status, usage limits, invoices

This module is intentionally import-safe:
- It does not require future project files to exist.
- It provides in-memory fallback repositories for early development.
- It avoids hardcoded secrets.
- It reads safe defaults from environment variables.
- It enforces user_id and workspace_id isolation for every billing operation.
- It includes hooks for Security Agent, Audit Logs, Memory Agent, Master Agent,
  Verification Agent, and future payment providers such as Stripe.

Core responsibilities:
- List SaaS plans and plan limits.
- Get scoped subscription status.
- Create/update/cancel/reactivate scoped subscriptions.
- Track and check usage limits.
- Create/list/get invoices.
- Prepare Verification Agent payloads.
- Route sensitive billing changes through Security Agent.
"""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Any, Callable, Dict, List, Literal, Optional, Sequence, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator


# =============================================================================
# Optional future project integrations
# =============================================================================

try:
    from apps.api.dependencies.auth import get_current_user as project_get_current_user  # type: ignore
except Exception:
    project_get_current_user = None

try:
    from apps.api.dependencies.workspace import get_current_workspace as project_get_current_workspace  # type: ignore
except Exception:
    project_get_current_workspace = None

try:
    from apps.api.routes.security import audit_log as project_audit_log  # type: ignore
except Exception:
    project_audit_log = None

try:
    from apps.api.routes.security import require_security_approval as project_security_approval  # type: ignore
except Exception:
    project_security_approval = None

try:
    from apps.api.services.verification import prepare_verification_payload as project_prepare_verification  # type: ignore
except Exception:
    project_prepare_verification = None

try:
    from apps.api.services.memory_agent import memory_agent_index as project_memory_agent_index  # type: ignore
except Exception:
    project_memory_agent_index = None

try:
    from apps.api.services.master_agent import notify_master_agent as project_notify_master_agent  # type: ignore
except Exception:
    project_notify_master_agent = None


# =============================================================================
# Router
# =============================================================================

router = APIRouter(tags=["Billing"])
# No self-prefix -- apps/api/main.py's OPTIONAL_ROUTERS already applies
# "/billing" as this router's default_prefix (see routes/memory.py).


# =============================================================================
# Environment safe defaults
# =============================================================================

APP_NAME = os.getenv("WILLIAM_APP_NAME", "William Jarvis")
DEFAULT_CURRENCY = os.getenv("WILLIAM_BILLING_CURRENCY", "USD").upper()
FREE_PRICE_CENTS = int(os.getenv("WILLIAM_PLAN_FREE_PRICE_CENTS", "0"))
PRO_PRICE_CENTS = int(os.getenv("WILLIAM_PLAN_PRO_PRICE_CENTS", "2900"))
BUSINESS_PRICE_CENTS = int(os.getenv("WILLIAM_PLAN_BUSINESS_PRICE_CENTS", "9900"))
ENTERPRISE_PRICE_CENTS = int(os.getenv("WILLIAM_PLAN_ENTERPRISE_PRICE_CENTS", "29900"))
MAX_INVOICE_SEARCH_LIMIT = int(os.getenv("WILLIAM_BILLING_MAX_INVOICE_SEARCH_LIMIT", "100"))
REQUIRE_SECURITY_FOR_PLAN_CHANGE = os.getenv("WILLIAM_REQUIRE_SECURITY_FOR_PLAN_CHANGE", "true").lower() == "true"
REQUIRE_SECURITY_FOR_CANCEL = os.getenv("WILLIAM_REQUIRE_SECURITY_FOR_CANCEL", "true").lower() == "true"
REQUIRE_SECURITY_FOR_MANUAL_INVOICE = os.getenv("WILLIAM_REQUIRE_SECURITY_FOR_MANUAL_INVOICE", "true").lower() == "true"


# =============================================================================
# Enums
# =============================================================================

class UserRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MANAGER = "manager"
    MEMBER = "member"
    VIEWER = "viewer"


class SubscriptionPlan(str, Enum):
    FREE = "free"
    PRO = "pro"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


class SubscriptionStatus(str, Enum):
    ACTIVE = "active"
    TRIALING = "trialing"
    PAST_DUE = "past_due"
    CANCELLED = "cancelled"
    INACTIVE = "inactive"


class BillingInterval(str, Enum):
    MONTHLY = "monthly"
    YEARLY = "yearly"


class InvoiceStatus(str, Enum):
    DRAFT = "draft"
    OPEN = "open"
    PAID = "paid"
    VOID = "void"
    UNCOLLECTIBLE = "uncollectible"


class UsageMetric(str, Enum):
    TASKS = "tasks"
    AGENT_RUNS = "agent_runs"
    MEMORY_RECORDS = "memory_records"
    WORKFLOW_RUNS = "workflow_runs"
    WEBHOOKS = "webhooks"
    FILES = "files"
    STORAGE_MB = "storage_mb"
    API_CALLS = "api_calls"
    TEAM_MEMBERS = "team_members"


class AuditStatus(str, Enum):
    SUCCESS = "success"
    DENIED = "denied"
    ERROR = "error"
    PENDING = "pending"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class ActorContext:
    user_id: str
    workspace_id: str
    role: UserRole = UserRole.MEMBER
    plan: SubscriptionPlan = SubscriptionPlan.FREE
    subscription_active: bool = True
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None


@dataclass
class PlanRecord:
    id: str
    name: str
    plan: SubscriptionPlan
    price_cents: int
    currency: str
    interval: BillingInterval
    features: List[str]
    limits: Dict[str, int]
    recommended: bool
    active: bool

    def visible_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SubscriptionRecord:
    id: str
    user_id: str
    workspace_id: str
    plan: SubscriptionPlan
    status: SubscriptionStatus
    interval: BillingInterval
    currency: str
    current_period_start: str
    current_period_end: Optional[str]
    cancel_at_period_end: bool
    provider: str
    provider_customer_id: Optional[str]
    provider_subscription_id: Optional[str]
    metadata: Dict[str, Any]
    created_by: str
    updated_by: str
    created_at: str
    updated_at: str
    cancelled_at: Optional[str] = None

    def visible_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UsageRecord:
    id: str
    user_id: str
    workspace_id: str
    metric: UsageMetric
    used: int
    limit: int
    period_start: str
    period_end: Optional[str]
    updated_at: str

    def visible_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvoiceRecord:
    id: str
    user_id: str
    workspace_id: str
    subscription_id: Optional[str]
    invoice_number: str
    status: InvoiceStatus
    currency: str
    subtotal_cents: int
    tax_cents: int
    total_cents: int
    line_items: List[Dict[str, Any]]
    provider: str
    provider_invoice_id: Optional[str]
    hosted_invoice_url: Optional[str]
    invoice_pdf_url: Optional[str]
    due_at: Optional[str]
    paid_at: Optional[str]
    created_by: str
    created_at: str
    updated_at: str
    metadata: Dict[str, Any]

    def visible_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================================
# Schemas
# =============================================================================

class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class BillingResponse(BaseModel):
    ok: bool
    message: str
    data: Dict[str, Any] = Field(default_factory=dict)
    verification: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


class PlanListResponse(BaseModel):
    ok: bool
    message: str
    plans: List[Dict[str, Any]]
    request_id: Optional[str] = None


class SubscriptionCreateRequest(BaseModel):
    plan: SubscriptionPlan
    interval: BillingInterval = BillingInterval.MONTHLY
    provider: str = Field(default="internal", max_length=80)
    provider_customer_id: Optional[str] = Field(default=None, max_length=180)
    provider_subscription_id: Optional[str] = Field(default=None, max_length=180)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        validate_json_size(value, 25000, "Metadata is too large.")
        return value


class SubscriptionUpdateRequest(BaseModel):
    plan: Optional[SubscriptionPlan] = None
    status: Optional[SubscriptionStatus] = None
    interval: Optional[BillingInterval] = None
    cancel_at_period_end: Optional[bool] = None
    provider_customer_id: Optional[str] = Field(default=None, max_length=180)
    provider_subscription_id: Optional[str] = Field(default=None, max_length=180)
    metadata: Optional[Dict[str, Any]] = None
    reason: Optional[str] = Field(default=None, max_length=1000)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if value is not None:
            validate_json_size(value, 25000, "Metadata is too large.")
        return value


class UsageIncrementRequest(BaseModel):
    metric: UsageMetric
    amount: int = Field(default=1, ge=1, le=1_000_000)
    idempotency_key: Optional[str] = Field(default=None, max_length=180)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class UsageCheckRequest(BaseModel):
    metric: UsageMetric
    requested_amount: int = Field(default=1, ge=1, le=1_000_000)


class InvoiceCreateRequest(BaseModel):
    subscription_id: Optional[str] = Field(default=None, max_length=140)
    status: InvoiceStatus = InvoiceStatus.OPEN
    currency: str = Field(default=DEFAULT_CURRENCY, min_length=3, max_length=3)
    line_items: List[Dict[str, Any]] = Field(..., min_length=1, max_length=100)
    tax_cents: int = Field(default=0, ge=0)
    provider: str = Field(default="internal", max_length=80)
    provider_invoice_id: Optional[str] = Field(default=None, max_length=180)
    hosted_invoice_url: Optional[str] = Field(default=None, max_length=1000)
    invoice_pdf_url: Optional[str] = Field(default=None, max_length=1000)
    due_at: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("currency")
    @classmethod
    def clean_currency(cls, value: str) -> str:
        cleaned = value.strip().upper()
        if not re.match(r"^[A-Z]{3}$", cleaned):
            raise ValueError("Currency must be a valid 3-letter code.")
        return cleaned

    @field_validator("line_items")
    @classmethod
    def validate_line_items(cls, value: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        for item in value:
            if "description" not in item:
                raise ValueError("Each invoice line item requires description.")
            if "amount_cents" not in item:
                raise ValueError("Each invoice line item requires amount_cents.")
            amount = int(item["amount_cents"])
            if amount < 0:
                raise ValueError("Line item amount_cents cannot be negative.")
        validate_json_size(value, 50000, "Line items are too large.")
        return value

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        validate_json_size(value, 25000, "Metadata is too large.")
        return value


class InvoiceUpdateRequest(BaseModel):
    status: Optional[InvoiceStatus] = None
    hosted_invoice_url: Optional[str] = Field(default=None, max_length=1000)
    invoice_pdf_url: Optional[str] = Field(default=None, max_length=1000)
    paid_at: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if value is not None:
            validate_json_size(value, 25000, "Metadata is too large.")
        return value


class InvoiceSearchResponse(BaseModel):
    ok: bool
    message: str
    invoices: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int
    request_id: Optional[str] = None


# =============================================================================
# Utility helpers
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_json_size(value: Any, max_bytes: int, message: str) -> None:
    serialized = json.dumps(value, default=str)
    if len(serialized.encode("utf-8")) > max_bytes:
        raise ValueError(message)


def raise_safe_error(
    status_code: int,
    code: str,
    message: str,
    request_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    raise HTTPException(
        status_code=status_code,
        detail=ErrorDetail(
            code=code,
            message=message,
            request_id=request_id,
            details=details or {},
        ).model_dump(),
    )


def normalize_id(value: Optional[str], field_name: str, request_id: Optional[str] = None) -> str:
    if value is None:
        raise_safe_error(status.HTTP_400_BAD_REQUEST, f"missing_{field_name}", f"{field_name} is required.", request_id)

    cleaned = str(value).strip()
    if not cleaned:
        raise_safe_error(status.HTTP_400_BAD_REQUEST, f"empty_{field_name}", f"{field_name} cannot be empty.", request_id)

    if len(cleaned) > 180:
        raise_safe_error(status.HTTP_400_BAD_REQUEST, f"invalid_{field_name}", f"{field_name} is too long.", request_id)

    if not re.match(r"^[a-zA-Z0-9_\-:.@]+$", cleaned):
        raise_safe_error(
            status.HTTP_400_BAD_REQUEST,
            f"invalid_{field_name}",
            f"{field_name} contains unsafe characters.",
            request_id,
        )

    return cleaned


def parse_role(value: Optional[str]) -> UserRole:
    if not value:
        return UserRole.MEMBER

    normalized = value.strip().lower()
    for role in UserRole:
        if role.value == normalized:
            return role

    return UserRole.MEMBER


def parse_plan(value: Optional[str]) -> SubscriptionPlan:
    if not value:
        return SubscriptionPlan.FREE

    normalized = value.strip().lower()
    for plan in SubscriptionPlan:
        if plan.value == normalized:
            return plan

    return SubscriptionPlan.FREE


def safe_json(data: Any) -> Any:
    try:
        json.dumps(data, default=str)
        return data
    except Exception:
        return {"serialization_warning": "Original value could not be serialized safely."}


def can_manage_billing(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN}


def can_view_billing(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER}


def can_track_usage(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER, UserRole.MEMBER}


def plan_price_cents(plan: SubscriptionPlan) -> int:
    prices = {
        SubscriptionPlan.FREE: FREE_PRICE_CENTS,
        SubscriptionPlan.PRO: PRO_PRICE_CENTS,
        SubscriptionPlan.BUSINESS: BUSINESS_PRICE_CENTS,
        SubscriptionPlan.ENTERPRISE: ENTERPRISE_PRICE_CENTS,
    }
    return prices[plan]


def limits_for_plan(plan: SubscriptionPlan) -> Dict[str, int]:
    if plan == SubscriptionPlan.FREE:
        return {
            UsageMetric.TASKS.value: 100,
            UsageMetric.AGENT_RUNS.value: 250,
            UsageMetric.MEMORY_RECORDS.value: 250,
            UsageMetric.WORKFLOW_RUNS.value: 25,
            UsageMetric.WEBHOOKS.value: 0,
            UsageMetric.FILES.value: 50,
            UsageMetric.STORAGE_MB.value: 500,
            UsageMetric.API_CALLS.value: 1000,
            UsageMetric.TEAM_MEMBERS.value: 1,
        }

    if plan == SubscriptionPlan.PRO:
        return {
            UsageMetric.TASKS.value: 5000,
            UsageMetric.AGENT_RUNS.value: 10000,
            UsageMetric.MEMORY_RECORDS.value: 5000,
            UsageMetric.WORKFLOW_RUNS.value: 1000,
            UsageMetric.WEBHOOKS.value: 20,
            UsageMetric.FILES.value: 2000,
            UsageMetric.STORAGE_MB.value: 25000,
            UsageMetric.API_CALLS.value: 50000,
            UsageMetric.TEAM_MEMBERS.value: 5,
        }

    if plan == SubscriptionPlan.BUSINESS:
        return {
            UsageMetric.TASKS.value: 25000,
            UsageMetric.AGENT_RUNS.value: 100000,
            UsageMetric.MEMORY_RECORDS.value: 25000,
            UsageMetric.WORKFLOW_RUNS.value: 10000,
            UsageMetric.WEBHOOKS.value: 200,
            UsageMetric.FILES.value: 10000,
            UsageMetric.STORAGE_MB.value: 250000,
            UsageMetric.API_CALLS.value: 500000,
            UsageMetric.TEAM_MEMBERS.value: 25,
        }

    return {
        UsageMetric.TASKS.value: 1000000,
        UsageMetric.AGENT_RUNS.value: 1000000,
        UsageMetric.MEMORY_RECORDS.value: 100000,
        UsageMetric.WORKFLOW_RUNS.value: 100000,
        UsageMetric.WEBHOOKS.value: 10000,
        UsageMetric.FILES.value: 100000,
        UsageMetric.STORAGE_MB.value: 5000000,
        UsageMetric.API_CALLS.value: 10000000,
        UsageMetric.TEAM_MEMBERS.value: 1000,
    }


def default_plans() -> List[PlanRecord]:
    return [
        PlanRecord(
            id="plan_free_monthly",
            name="Free",
            plan=SubscriptionPlan.FREE,
            price_cents=plan_price_cents(SubscriptionPlan.FREE),
            currency=DEFAULT_CURRENCY,
            interval=BillingInterval.MONTHLY,
            features=[
                "Basic Master Agent access",
                "Limited task history",
                "Starter memory",
                "Community support",
            ],
            limits=limits_for_plan(SubscriptionPlan.FREE),
            recommended=False,
            active=True,
        ),
        PlanRecord(
            id="plan_pro_monthly",
            name="Pro",
            plan=SubscriptionPlan.PRO,
            price_cents=plan_price_cents(SubscriptionPlan.PRO),
            currency=DEFAULT_CURRENCY,
            interval=BillingInterval.MONTHLY,
            features=[
                "All core agents",
                "Larger memory limits",
                "Workflow automation",
                "Webhook support",
                "Priority dashboard features",
            ],
            limits=limits_for_plan(SubscriptionPlan.PRO),
            recommended=True,
            active=True,
        ),
        PlanRecord(
            id="plan_business_monthly",
            name="Business",
            plan=SubscriptionPlan.BUSINESS,
            price_cents=plan_price_cents(SubscriptionPlan.BUSINESS),
            currency=DEFAULT_CURRENCY,
            interval=BillingInterval.MONTHLY,
            features=[
                "Team workspace support",
                "Advanced workflow usage",
                "Higher API limits",
                "Audit and security dashboard",
                "Business support",
            ],
            limits=limits_for_plan(SubscriptionPlan.BUSINESS),
            recommended=False,
            active=True,
        ),
        PlanRecord(
            id="plan_enterprise_monthly",
            name="Enterprise",
            plan=SubscriptionPlan.ENTERPRISE,
            price_cents=plan_price_cents(SubscriptionPlan.ENTERPRISE),
            currency=DEFAULT_CURRENCY,
            interval=BillingInterval.MONTHLY,
            features=[
                "Enterprise-scale limits",
                "Custom approvals",
                "Advanced security controls",
                "Dedicated support",
                "Custom integrations",
            ],
            limits=limits_for_plan(SubscriptionPlan.ENTERPRISE),
            recommended=False,
            active=True,
        ),
    ]


def invoice_number() -> str:
    return f"WJ-{datetime.now(timezone.utc).strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"


# =============================================================================
# Fallback repositories
# =============================================================================

class InMemorySubscriptionRepository:
    def __init__(self) -> None:
        self._items: Dict[str, SubscriptionRecord] = {}
        self._lock = RLock()

    def save(self, record: SubscriptionRecord) -> SubscriptionRecord:
        with self._lock:
            self._items[record.id] = record
            return record

    def update(self, record: SubscriptionRecord) -> SubscriptionRecord:
        with self._lock:
            self._items[record.id] = record
            return record

    def get_current(self, user_id: str, workspace_id: str) -> Optional[SubscriptionRecord]:
        with self._lock:
            scoped = [
                item
                for item in self._items.values()
                if item.user_id == user_id and item.workspace_id == workspace_id
            ]
            if not scoped:
                return None
            scoped.sort(key=lambda item: item.updated_at, reverse=True)
            return scoped[0]

    def get_scoped(self, subscription_id: str, user_id: str, workspace_id: str) -> Optional[SubscriptionRecord]:
        with self._lock:
            record = self._items.get(subscription_id)
            if record is None:
                return None
            if record.user_id != user_id or record.workspace_id != workspace_id:
                return None
            return record


class InMemoryUsageRepository:
    def __init__(self) -> None:
        self._items: Dict[Tuple[str, str, str], UsageRecord] = {}
        self._idempotency_keys: set[str] = set()
        self._lock = RLock()

    def get_or_create(
        self,
        user_id: str,
        workspace_id: str,
        metric: UsageMetric,
        limit: int,
    ) -> UsageRecord:
        key = (user_id, workspace_id, metric.value)
        with self._lock:
            existing = self._items.get(key)
            if existing:
                existing.limit = limit
                existing.updated_at = utc_now()
                return existing

            now = utc_now()
            record = UsageRecord(
                id=str(uuid.uuid4()),
                user_id=user_id,
                workspace_id=workspace_id,
                metric=metric,
                used=0,
                limit=limit,
                period_start=now,
                period_end=None,
                updated_at=now,
            )
            self._items[key] = record
            return record

    def list_scoped(self, user_id: str, workspace_id: str, limits: Dict[str, int]) -> List[UsageRecord]:
        with self._lock:
            records: List[UsageRecord] = []
            for metric in UsageMetric:
                records.append(self.get_or_create(user_id, workspace_id, metric, limits.get(metric.value, 0)))
            records.sort(key=lambda item: item.metric.value)
            return records

    def increment(
        self,
        user_id: str,
        workspace_id: str,
        metric: UsageMetric,
        amount: int,
        limit: int,
        idempotency_key: Optional[str],
    ) -> Tuple[UsageRecord, bool]:
        with self._lock:
            if idempotency_key:
                scoped_key = f"{user_id}:{workspace_id}:{metric.value}:{idempotency_key}"
                if scoped_key in self._idempotency_keys:
                    return self.get_or_create(user_id, workspace_id, metric, limit), False
                self._idempotency_keys.add(scoped_key)

            record = self.get_or_create(user_id, workspace_id, metric, limit)
            record.used += amount
            record.limit = limit
            record.updated_at = utc_now()

            return record, True


class InMemoryInvoiceRepository:
    def __init__(self) -> None:
        self._items: Dict[str, InvoiceRecord] = {}
        self._lock = RLock()

    def save(self, record: InvoiceRecord) -> InvoiceRecord:
        with self._lock:
            self._items[record.id] = record
            return record

    def update(self, record: InvoiceRecord) -> InvoiceRecord:
        with self._lock:
            self._items[record.id] = record
            return record

    def get_scoped(self, invoice_id: str, user_id: str, workspace_id: str) -> Optional[InvoiceRecord]:
        with self._lock:
            record = self._items.get(invoice_id)
            if record is None:
                return None
            if record.user_id != user_id or record.workspace_id != workspace_id:
                return None
            return record

    def query(
        self,
        user_id: str,
        workspace_id: str,
        status_filter: Optional[InvoiceStatus] = None,
        subscription_id: Optional[str] = None,
    ) -> List[InvoiceRecord]:
        with self._lock:
            records: List[InvoiceRecord] = []

            for record in self._items.values():
                if record.user_id != user_id or record.workspace_id != workspace_id:
                    continue

                if status_filter and record.status != status_filter:
                    continue

                if subscription_id and record.subscription_id != subscription_id:
                    continue

                records.append(record)

            records.sort(key=lambda item: item.created_at, reverse=True)
            return records


_subscription_repository = InMemorySubscriptionRepository()
_usage_repository = InMemoryUsageRepository()
_invoice_repository = InMemoryInvoiceRepository()


# =============================================================================
# Main Billing component
# =============================================================================

class Billing:
    """
    Required class/component name: Billing

    Central billing API component for:
    - SaaS plan definitions
    - Subscription status
    - Usage limits
    - Usage increments/checks
    - Invoices
    - Future payment provider integration
    """

    def __init__(
        self,
        subscription_repository: Optional[InMemorySubscriptionRepository] = None,
        usage_repository: Optional[InMemoryUsageRepository] = None,
        invoice_repository: Optional[InMemoryInvoiceRepository] = None,
        audit_hook: Optional[Callable[..., Any]] = None,
        security_hook: Optional[Callable[..., Any]] = None,
        verification_hook: Optional[Callable[..., Any]] = None,
        memory_agent_hook: Optional[Callable[..., Any]] = None,
        master_agent_hook: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.subscription_repository = subscription_repository or _subscription_repository
        self.usage_repository = usage_repository or _usage_repository
        self.invoice_repository = invoice_repository or _invoice_repository
        self.audit_hook = audit_hook or project_audit_log
        self.security_hook = security_hook or project_security_approval
        self.verification_hook = verification_hook or project_prepare_verification
        self.memory_agent_hook = memory_agent_hook or project_memory_agent_index
        self.master_agent_hook = master_agent_hook or project_notify_master_agent

    def enforce_subscription_read_access(self, actor: ActorContext) -> None:
        if not can_view_billing(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_view_billing",
                "Your role does not allow viewing billing information.",
                actor.request_id,
                {"role": actor.role.value},
            )

    def enforce_billing_manage_access(self, actor: ActorContext) -> None:
        if not can_manage_billing(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_manage_billing",
                "Your role does not allow managing billing.",
                actor.request_id,
                {"role": actor.role.value},
            )

    def enforce_usage_access(self, actor: ActorContext) -> None:
        if not can_track_usage(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_track_usage",
                "Your role does not allow usage operations.",
                actor.request_id,
                {"role": actor.role.value},
            )

    async def audit(
        self,
        actor: ActorContext,
        action: str,
        event_status: AuditStatus,
        target_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        risk_level: Optional[RiskLevel] = None,
    ) -> None:
        payload = {
            "app": APP_NAME,
            "action": action,
            "category": "billing",
            "status": event_status.value,
            "target_type": "billing",
            "target_id": target_id,
            "risk_level": risk_level.value if risk_level else None,
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "role": actor.role.value,
            "plan": actor.plan.value,
            "request_id": actor.request_id,
            "ip_address": actor.ip_address,
            "user_agent": actor.user_agent,
            "details": safe_json(details or {}),
            "created_at": utc_now(),
        }

        if callable(self.audit_hook):
            try:
                result = self.audit_hook(payload)
                if hasattr(result, "__await__"):
                    await result
            except Exception:
                return

    async def require_security(
        self,
        actor: ActorContext,
        action: str,
        risk_level: RiskLevel,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        request_payload = {
            "action": action,
            "risk_level": risk_level.value,
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "role": actor.role.value,
            "plan": actor.plan.value,
            "request_id": actor.request_id,
            "payload": safe_json(payload),
        }

        if callable(self.security_hook):
            try:
                result = self.security_hook(request_payload)
                if hasattr(result, "__await__"):
                    result = await result

                if isinstance(result, dict):
                    if not bool(result.get("approved", False)):
                        raise_safe_error(
                            status.HTTP_403_FORBIDDEN,
                            "security_agent_denied",
                            "Security Agent did not approve this billing action.",
                            actor.request_id,
                            {"security_result": safe_json(result)},
                        )
                    return result
            except HTTPException:
                raise
            except Exception:
                raise_safe_error(
                    status.HTTP_503_SERVICE_UNAVAILABLE,
                    "security_agent_unavailable",
                    "Security Agent could not validate this billing action.",
                    actor.request_id,
                )

        return {
            "approved": True,
            "mode": "fallback",
            "reason": "No external Security Agent hook configured.",
            "risk_level": risk_level.value,
        }

    async def prepare_verification(
        self,
        actor: ActorContext,
        action: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload = {
            "agent": "Verification Agent",
            "module": "billing",
            "action": action,
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "request_id": actor.request_id,
            "result": safe_json(result),
            "prepared_at": utc_now(),
        }

        if callable(self.verification_hook):
            try:
                maybe_result = self.verification_hook(payload)
                if hasattr(maybe_result, "__await__"):
                    maybe_result = await maybe_result
                if isinstance(maybe_result, dict):
                    return maybe_result
            except Exception:
                return payload

        return payload

    async def index_for_memory_agent(
        self,
        actor: ActorContext,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        message = {
            "agent": "Memory Agent",
            "module": "billing",
            "event_type": event_type,
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "request_id": actor.request_id,
            "payload": safe_json(payload),
            "created_at": utc_now(),
        }

        if callable(self.memory_agent_hook):
            try:
                result = self.memory_agent_hook(message)
                if hasattr(result, "__await__"):
                    await result
            except Exception:
                return

    async def notify_master_agent(
        self,
        actor: ActorContext,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        message = {
            "agent": "Master Agent",
            "module": "billing",
            "event_type": event_type,
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "request_id": actor.request_id,
            "payload": safe_json(payload),
            "created_at": utc_now(),
        }

        if callable(self.master_agent_hook):
            try:
                result = self.master_agent_hook(message)
                if hasattr(result, "__await__"):
                    await result
            except Exception:
                return

    def list_plans(self) -> List[PlanRecord]:
        return default_plans()

    def get_plan_record(self, plan: SubscriptionPlan, interval: BillingInterval = BillingInterval.MONTHLY) -> PlanRecord:
        for item in self.list_plans():
            if item.plan == plan and item.interval == interval:
                return item

        raise_safe_error(
            status.HTTP_404_NOT_FOUND,
            "plan_not_found",
            "Requested plan was not found.",
            details={"plan": plan.value, "interval": interval.value},
        )

    def get_or_create_subscription(self, actor: ActorContext) -> SubscriptionRecord:
        existing = self.subscription_repository.get_current(actor.user_id, actor.workspace_id)
        if existing:
            return existing

        now = utc_now()
        record = SubscriptionRecord(
            id=str(uuid.uuid4()),
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            plan=actor.plan,
            status=SubscriptionStatus.ACTIVE if actor.subscription_active else SubscriptionStatus.INACTIVE,
            interval=BillingInterval.MONTHLY,
            currency=DEFAULT_CURRENCY,
            current_period_start=now,
            current_period_end=None,
            cancel_at_period_end=False,
            provider="internal",
            provider_customer_id=None,
            provider_subscription_id=None,
            metadata={"created_by_fallback": True},
            created_by=actor.user_id,
            updated_by=actor.user_id,
            created_at=now,
            updated_at=now,
        )

        return self.subscription_repository.save(record)

    async def create_subscription(
        self,
        actor: ActorContext,
        payload: SubscriptionCreateRequest,
    ) -> Tuple[SubscriptionRecord, Dict[str, Any]]:
        self.enforce_billing_manage_access(actor)

        if REQUIRE_SECURITY_FOR_PLAN_CHANGE:
            await self.require_security(
                actor=actor,
                action="billing.subscription.create",
                risk_level=RiskLevel.HIGH,
                payload=payload.model_dump(),
            )

        now = utc_now()
        record = SubscriptionRecord(
            id=str(uuid.uuid4()),
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            plan=payload.plan,
            status=SubscriptionStatus.ACTIVE,
            interval=payload.interval,
            currency=DEFAULT_CURRENCY,
            current_period_start=now,
            current_period_end=None,
            cancel_at_period_end=False,
            provider=payload.provider,
            provider_customer_id=payload.provider_customer_id,
            provider_subscription_id=payload.provider_subscription_id,
            metadata=payload.metadata,
            created_by=actor.user_id,
            updated_by=actor.user_id,
            created_at=now,
            updated_at=now,
        )

        saved = self.subscription_repository.save(record)

        await self.audit(
            actor,
            "billing.subscription.create",
            AuditStatus.SUCCESS,
            target_id=saved.id,
            details={"subscription_id": saved.id, "plan": saved.plan.value},
            risk_level=RiskLevel.HIGH,
        )

        await self.index_for_memory_agent(
            actor,
            "subscription_created",
            {"subscription_id": saved.id, "plan": saved.plan.value, "status": saved.status.value},
        )

        await self.notify_master_agent(
            actor,
            "subscription_created",
            {"subscription_id": saved.id, "plan": saved.plan.value, "workspace_id": actor.workspace_id},
        )

        verification = await self.prepare_verification(
            actor,
            "billing.subscription.create",
            {"subscription_id": saved.id, "plan": saved.plan.value, "status": saved.status.value},
        )

        return saved, verification

    async def update_subscription(
        self,
        actor: ActorContext,
        payload: SubscriptionUpdateRequest,
    ) -> Tuple[SubscriptionRecord, Dict[str, Any]]:
        self.enforce_billing_manage_access(actor)

        current = self.get_or_create_subscription(actor)
        update_data = payload.model_dump(exclude_none=True)

        plan_change = payload.plan is not None and payload.plan != current.plan
        cancellation_change = payload.status == SubscriptionStatus.CANCELLED or payload.cancel_at_period_end is True

        if (plan_change and REQUIRE_SECURITY_FOR_PLAN_CHANGE) or (cancellation_change and REQUIRE_SECURITY_FOR_CANCEL):
            await self.require_security(
                actor=actor,
                action="billing.subscription.update_sensitive",
                risk_level=RiskLevel.HIGH,
                payload={"subscription_id": current.id, "update": update_data},
            )

        if payload.plan is not None:
            current.plan = payload.plan
        if payload.status is not None:
            current.status = payload.status
            if payload.status == SubscriptionStatus.CANCELLED:
                current.cancelled_at = utc_now()
        if payload.interval is not None:
            current.interval = payload.interval
        if payload.cancel_at_period_end is not None:
            current.cancel_at_period_end = payload.cancel_at_period_end
        if payload.provider_customer_id is not None:
            current.provider_customer_id = payload.provider_customer_id
        if payload.provider_subscription_id is not None:
            current.provider_subscription_id = payload.provider_subscription_id
        if payload.metadata is not None:
            current.metadata = payload.metadata

        current.updated_by = actor.user_id
        current.updated_at = utc_now()

        updated = self.subscription_repository.update(current)

        await self.audit(
            actor,
            "billing.subscription.update",
            AuditStatus.SUCCESS,
            target_id=updated.id,
            details={"subscription_id": updated.id, "fields": list(update_data.keys()), "reason": payload.reason},
            risk_level=RiskLevel.HIGH if plan_change or cancellation_change else RiskLevel.MEDIUM,
        )

        await self.index_for_memory_agent(
            actor,
            "subscription_updated",
            {"subscription_id": updated.id, "plan": updated.plan.value, "status": updated.status.value},
        )

        verification = await self.prepare_verification(
            actor,
            "billing.subscription.update",
            {"subscription_id": updated.id, "plan": updated.plan.value, "status": updated.status.value},
        )

        return updated, verification

    async def cancel_subscription(
        self,
        actor: ActorContext,
        cancel_at_period_end: bool,
        reason: Optional[str],
    ) -> Tuple[SubscriptionRecord, Dict[str, Any]]:
        payload = SubscriptionUpdateRequest(
            status=None if cancel_at_period_end else SubscriptionStatus.CANCELLED,
            cancel_at_period_end=cancel_at_period_end,
            reason=reason,
        )
        return await self.update_subscription(actor, payload)

    async def reactivate_subscription(
        self,
        actor: ActorContext,
        reason: Optional[str],
    ) -> Tuple[SubscriptionRecord, Dict[str, Any]]:
        payload = SubscriptionUpdateRequest(
            status=SubscriptionStatus.ACTIVE,
            cancel_at_period_end=False,
            reason=reason,
        )
        return await self.update_subscription(actor, payload)

    def usage_limits_for_actor(self, actor: ActorContext) -> Dict[str, int]:
        subscription = self.subscription_repository.get_current(actor.user_id, actor.workspace_id)
        plan = subscription.plan if subscription else actor.plan
        return limits_for_plan(plan)

    async def list_usage(self, actor: ActorContext) -> List[UsageRecord]:
        self.enforce_subscription_read_access(actor)
        limits = self.usage_limits_for_actor(actor)
        return self.usage_repository.list_scoped(actor.user_id, actor.workspace_id, limits)

    async def check_usage(
        self,
        actor: ActorContext,
        metric: UsageMetric,
        requested_amount: int,
    ) -> Dict[str, Any]:
        self.enforce_usage_access(actor)
        limits = self.usage_limits_for_actor(actor)
        limit = limits.get(metric.value, 0)

        record = self.usage_repository.get_or_create(actor.user_id, actor.workspace_id, metric, limit)
        projected = record.used + requested_amount
        allowed = projected <= record.limit

        return {
            "metric": metric.value,
            "used": record.used,
            "limit": record.limit,
            "requested_amount": requested_amount,
            "projected": projected,
            "allowed": allowed,
            "remaining": max(record.limit - record.used, 0),
            "plan": self.get_or_create_subscription(actor).plan.value,
        }

    async def increment_usage(
        self,
        actor: ActorContext,
        payload: UsageIncrementRequest,
    ) -> Tuple[UsageRecord, Dict[str, Any]]:
        self.enforce_usage_access(actor)

        limits = self.usage_limits_for_actor(actor)
        limit = limits.get(payload.metric.value, 0)
        check = await self.check_usage(actor, payload.metric, payload.amount)

        if not check["allowed"]:
            await self.audit(
                actor,
                "billing.usage.limit_denied",
                AuditStatus.DENIED,
                details=check,
                risk_level=RiskLevel.MEDIUM,
            )
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "usage_limit_exceeded",
                "Usage limit exceeded for this subscription plan.",
                actor.request_id,
                check,
            )

        record, changed = self.usage_repository.increment(
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            metric=payload.metric,
            amount=payload.amount,
            limit=limit,
            idempotency_key=payload.idempotency_key,
        )

        await self.audit(
            actor,
            "billing.usage.increment",
            AuditStatus.SUCCESS,
            target_id=record.id,
            details={
                "metric": record.metric.value,
                "amount": payload.amount,
                "used": record.used,
                "limit": record.limit,
                "changed": changed,
                "idempotency_key_present": bool(payload.idempotency_key),
            },
            risk_level=RiskLevel.LOW,
        )

        verification = await self.prepare_verification(
            actor,
            "billing.usage.increment",
            {"usage_id": record.id, "metric": record.metric.value, "used": record.used, "limit": record.limit},
        )

        return record, verification

    async def create_invoice(
        self,
        actor: ActorContext,
        payload: InvoiceCreateRequest,
    ) -> Tuple[InvoiceRecord, Dict[str, Any]]:
        self.enforce_billing_manage_access(actor)

        if REQUIRE_SECURITY_FOR_MANUAL_INVOICE:
            await self.require_security(
                actor=actor,
                action="billing.invoice.create",
                risk_level=RiskLevel.HIGH,
                payload=payload.model_dump(),
            )

        subtotal = sum(int(item["amount_cents"]) for item in payload.line_items)
        total = subtotal + payload.tax_cents
        now = utc_now()

        record = InvoiceRecord(
            id=str(uuid.uuid4()),
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            subscription_id=payload.subscription_id,
            invoice_number=invoice_number(),
            status=payload.status,
            currency=payload.currency,
            subtotal_cents=subtotal,
            tax_cents=payload.tax_cents,
            total_cents=total,
            line_items=payload.line_items,
            provider=payload.provider,
            provider_invoice_id=payload.provider_invoice_id,
            hosted_invoice_url=payload.hosted_invoice_url,
            invoice_pdf_url=payload.invoice_pdf_url,
            due_at=payload.due_at,
            paid_at=utc_now() if payload.status == InvoiceStatus.PAID else None,
            created_by=actor.user_id,
            created_at=now,
            updated_at=now,
            metadata=payload.metadata,
        )

        saved = self.invoice_repository.save(record)

        await self.audit(
            actor,
            "billing.invoice.create",
            AuditStatus.SUCCESS,
            target_id=saved.id,
            details={"invoice_id": saved.id, "invoice_number": saved.invoice_number, "total_cents": saved.total_cents},
            risk_level=RiskLevel.HIGH,
        )

        verification = await self.prepare_verification(
            actor,
            "billing.invoice.create",
            {"invoice_id": saved.id, "invoice_number": saved.invoice_number, "status": saved.status.value},
        )

        return saved, verification

    async def update_invoice(
        self,
        actor: ActorContext,
        invoice_id: str,
        payload: InvoiceUpdateRequest,
    ) -> Tuple[InvoiceRecord, Dict[str, Any]]:
        self.enforce_billing_manage_access(actor)

        record = self.invoice_repository.get_scoped(invoice_id, actor.user_id, actor.workspace_id)
        if record is None:
            raise_safe_error(
                status.HTTP_404_NOT_FOUND,
                "invoice_not_found",
                "Invoice was not found in this user/workspace scope.",
                actor.request_id,
            )

        if payload.status is not None:
            record.status = payload.status
            if payload.status == InvoiceStatus.PAID and not payload.paid_at:
                record.paid_at = utc_now()
        if payload.hosted_invoice_url is not None:
            record.hosted_invoice_url = payload.hosted_invoice_url
        if payload.invoice_pdf_url is not None:
            record.invoice_pdf_url = payload.invoice_pdf_url
        if payload.paid_at is not None:
            record.paid_at = payload.paid_at
        if payload.metadata is not None:
            record.metadata = payload.metadata

        record.updated_at = utc_now()
        updated = self.invoice_repository.update(record)

        await self.audit(
            actor,
            "billing.invoice.update",
            AuditStatus.SUCCESS,
            target_id=updated.id,
            details={"invoice_id": updated.id, "status": updated.status.value},
            risk_level=RiskLevel.MEDIUM,
        )

        verification = await self.prepare_verification(
            actor,
            "billing.invoice.update",
            {"invoice_id": updated.id, "status": updated.status.value},
        )

        return updated, verification

    async def list_invoices(
        self,
        actor: ActorContext,
        status_filter: Optional[InvoiceStatus],
        subscription_id: Optional[str],
        limit: int,
        offset: int,
    ) -> Tuple[List[InvoiceRecord], int]:
        self.enforce_subscription_read_access(actor)

        records = self.invoice_repository.query(
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            status_filter=status_filter,
            subscription_id=subscription_id,
        )

        total = len(records)
        page = records[offset : offset + limit]

        await self.audit(
            actor,
            "billing.invoice.list",
            AuditStatus.SUCCESS,
            details={"total": total, "status": status_filter.value if status_filter else None},
            risk_level=RiskLevel.LOW,
        )

        return page, total

    async def get_invoice(self, actor: ActorContext, invoice_id: str) -> InvoiceRecord:
        self.enforce_subscription_read_access(actor)

        record = self.invoice_repository.get_scoped(invoice_id, actor.user_id, actor.workspace_id)
        if record is None:
            raise_safe_error(
                status.HTTP_404_NOT_FOUND,
                "invoice_not_found",
                "Invoice was not found in this user/workspace scope.",
                actor.request_id,
            )

        return record


billing_service = Billing()


# =============================================================================
# Dependencies
# =============================================================================

async def get_actor_context(
    request: Request,
    x_user_id: Optional[str] = Header(default=None, alias="X-User-Id"),
    x_workspace_id: Optional[str] = Header(default=None, alias="X-Workspace-Id"),
    x_user_role: Optional[str] = Header(default=None, alias="X-User-Role"),
    x_subscription_plan: Optional[str] = Header(default=None, alias="X-Subscription-Plan"),
    x_subscription_active: Optional[str] = Header(default="true", alias="X-Subscription-Active"),
    x_request_id: Optional[str] = Header(default=None, alias="X-Request-Id"),
) -> ActorContext:
    """
    Import-safe auth/workspace adapter.

    Production can replace header fallback with:
    - apps.api.dependencies.auth.get_current_user
    - apps.api.dependencies.workspace.get_current_workspace

    Until then, use headers:
    - X-User-Id
    - X-Workspace-Id
    - X-User-Role
    - X-Subscription-Plan
    - X-Subscription-Active
    """

    current_user: Optional[Any] = None
    current_workspace: Optional[Any] = None

    if callable(project_get_current_user):
        try:
            maybe_user = project_get_current_user()
            if hasattr(maybe_user, "__await__"):
                current_user = await maybe_user
            else:
                current_user = maybe_user
        except Exception:
            current_user = None

    if callable(project_get_current_workspace):
        try:
            maybe_workspace = project_get_current_workspace()
            if hasattr(maybe_workspace, "__await__"):
                current_workspace = await maybe_workspace
            else:
                current_workspace = maybe_workspace
        except Exception:
            current_workspace = None

    resolved_user_id = (
        getattr(current_user, "user_id", None)
        or getattr(current_user, "id", None)
        or (current_user.get("user_id") if isinstance(current_user, dict) else None)
        or (current_user.get("id") if isinstance(current_user, dict) else None)
        or x_user_id
    )

    resolved_workspace_id = (
        getattr(current_workspace, "workspace_id", None)
        or getattr(current_workspace, "id", None)
        or (current_workspace.get("workspace_id") if isinstance(current_workspace, dict) else None)
        or (current_workspace.get("id") if isinstance(current_workspace, dict) else None)
        or x_workspace_id
    )

    user_id = normalize_id(str(resolved_user_id) if resolved_user_id is not None else None, "user_id")
    workspace_id = normalize_id(str(resolved_workspace_id) if resolved_workspace_id is not None else None, "workspace_id")

    role_value = (
        getattr(current_user, "role", None)
        or (current_user.get("role") if isinstance(current_user, dict) else None)
        or x_user_role
    )

    plan_value = (
        getattr(current_user, "plan", None)
        or getattr(current_user, "subscription_plan", None)
        or (current_user.get("plan") if isinstance(current_user, dict) else None)
        or (current_user.get("subscription_plan") if isinstance(current_user, dict) else None)
        or x_subscription_plan
    )

    subscription_active_raw = getattr(current_user, "subscription_active", None) if current_user is not None else None

    if subscription_active_raw is None and isinstance(current_user, dict):
        subscription_active_raw = current_user.get("subscription_active")

    if subscription_active_raw is None:
        subscription_active_raw = x_subscription_active

    subscription_active = str(subscription_active_raw).strip().lower() not in {
        "false",
        "0",
        "no",
        "inactive",
        "cancelled",
        "canceled",
    }

    return ActorContext(
        user_id=user_id,
        workspace_id=workspace_id,
        role=parse_role(str(role_value) if role_value is not None else None),
        plan=parse_plan(str(plan_value) if plan_value is not None else None),
        subscription_active=subscription_active,
        request_id=x_request_id or str(uuid.uuid4()),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("User-Agent"),
    )


def get_billing_service() -> Billing:
    return billing_service


# =============================================================================
# Plan routes
# =============================================================================

@router.get("/plans", response_model=PlanListResponse)
async def list_plans(
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> PlanListResponse:
    plans = service.list_plans()

    return PlanListResponse(
        ok=True,
        message="Plans retrieved successfully.",
        plans=[plan.visible_dict() for plan in plans],
        request_id=actor.request_id,
    )


@router.get("/plans/{plan}", response_model=BillingResponse)
async def get_plan(
    plan: SubscriptionPlan,
    interval: BillingInterval = Query(default=BillingInterval.MONTHLY),
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> BillingResponse:
    plan_record = service.get_plan_record(plan, interval)

    return BillingResponse(
        ok=True,
        message="Plan retrieved successfully.",
        data={"plan": plan_record.visible_dict()},
        request_id=actor.request_id,
    )


# =============================================================================
# Subscription routes
# =============================================================================

@router.get("/subscription", response_model=BillingResponse)
async def get_subscription_status(
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> BillingResponse:
    service.enforce_subscription_read_access(actor)
    subscription = service.get_or_create_subscription(actor)

    return BillingResponse(
        ok=True,
        message="Subscription status retrieved successfully.",
        data={
            "subscription": subscription.visible_dict(),
            "limits": limits_for_plan(subscription.plan),
        },
        request_id=actor.request_id,
    )


@router.post("/subscription", response_model=BillingResponse, status_code=status.HTTP_201_CREATED)
async def create_subscription(
    payload: SubscriptionCreateRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> BillingResponse:
    subscription, verification = await service.create_subscription(actor, payload)

    return BillingResponse(
        ok=True,
        message="Subscription created successfully.",
        data={"subscription": subscription.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


@router.patch("/subscription", response_model=BillingResponse)
async def update_subscription(
    payload: SubscriptionUpdateRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> BillingResponse:
    subscription, verification = await service.update_subscription(actor, payload)

    return BillingResponse(
        ok=True,
        message="Subscription updated successfully.",
        data={"subscription": subscription.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


@router.post("/subscription/cancel", response_model=BillingResponse)
async def cancel_subscription(
    cancel_at_period_end: bool = Query(default=True),
    reason: Optional[str] = Query(default=None, max_length=1000),
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> BillingResponse:
    subscription, verification = await service.cancel_subscription(actor, cancel_at_period_end, reason)

    return BillingResponse(
        ok=True,
        message="Subscription cancellation updated successfully.",
        data={"subscription": subscription.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


@router.post("/subscription/reactivate", response_model=BillingResponse)
async def reactivate_subscription(
    reason: Optional[str] = Query(default=None, max_length=1000),
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> BillingResponse:
    subscription, verification = await service.reactivate_subscription(actor, reason)

    return BillingResponse(
        ok=True,
        message="Subscription reactivated successfully.",
        data={"subscription": subscription.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


# =============================================================================
# Usage routes
# =============================================================================

@router.get("/usage", response_model=BillingResponse)
async def get_usage(
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> BillingResponse:
    usage = await service.list_usage(actor)
    subscription = service.get_or_create_subscription(actor)

    return BillingResponse(
        ok=True,
        message="Usage retrieved successfully.",
        data={
            "plan": subscription.plan.value,
            "usage": [item.visible_dict() for item in usage],
        },
        request_id=actor.request_id,
    )


@router.post("/usage/check", response_model=BillingResponse)
async def check_usage(
    payload: UsageCheckRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> BillingResponse:
    result = await service.check_usage(actor, payload.metric, payload.requested_amount)

    return BillingResponse(
        ok=True,
        message="Usage check completed successfully.",
        data={"usage_check": result},
        request_id=actor.request_id,
    )


@router.post("/usage/increment", response_model=BillingResponse)
async def increment_usage(
    payload: UsageIncrementRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> BillingResponse:
    usage, verification = await service.increment_usage(actor, payload)

    return BillingResponse(
        ok=True,
        message="Usage incremented successfully.",
        data={"usage": usage.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


# =============================================================================
# Invoice routes
# =============================================================================

@router.post("/invoices", response_model=BillingResponse, status_code=status.HTTP_201_CREATED)
async def create_invoice(
    payload: InvoiceCreateRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> BillingResponse:
    invoice, verification = await service.create_invoice(actor, payload)

    return BillingResponse(
        ok=True,
        message="Invoice created successfully.",
        data={"invoice": invoice.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


@router.get("/invoices", response_model=InvoiceSearchResponse)
async def list_invoices(
    status_filter: Optional[InvoiceStatus] = Query(default=None, alias="status"),
    subscription_id: Optional[str] = Query(default=None, max_length=140),
    limit: int = Query(default=25, ge=1, le=MAX_INVOICE_SEARCH_LIMIT),
    offset: int = Query(default=0, ge=0),
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> InvoiceSearchResponse:
    invoices, total = await service.list_invoices(actor, status_filter, subscription_id, limit, offset)

    return InvoiceSearchResponse(
        ok=True,
        message="Invoices retrieved successfully.",
        invoices=[invoice.visible_dict() for invoice in invoices],
        total=total,
        limit=limit,
        offset=offset,
        request_id=actor.request_id,
    )


@router.get("/invoices/{invoice_id}", response_model=BillingResponse)
async def get_invoice(
    invoice_id: str,
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> BillingResponse:
    safe_invoice_id = normalize_id(invoice_id, "invoice_id", actor.request_id)
    invoice = await service.get_invoice(actor, safe_invoice_id)

    return BillingResponse(
        ok=True,
        message="Invoice retrieved successfully.",
        data={"invoice": invoice.visible_dict()},
        request_id=actor.request_id,
    )


@router.patch("/invoices/{invoice_id}", response_model=BillingResponse)
async def update_invoice(
    invoice_id: str,
    payload: InvoiceUpdateRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> BillingResponse:
    safe_invoice_id = normalize_id(invoice_id, "invoice_id", actor.request_id)
    invoice, verification = await service.update_invoice(actor, safe_invoice_id, payload)

    return BillingResponse(
        ok=True,
        message="Invoice updated successfully.",
        data={"invoice": invoice.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


# =============================================================================
# Billing summary / health routes
# =============================================================================

@router.get("/summary", response_model=BillingResponse)
async def billing_summary(
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> BillingResponse:
    service.enforce_subscription_read_access(actor)

    subscription = service.get_or_create_subscription(actor)
    usage = await service.list_usage(actor)
    invoices, total_invoices = await service.list_invoices(
        actor=actor,
        status_filter=None,
        subscription_id=subscription.id,
        limit=10,
        offset=0,
    )

    return BillingResponse(
        ok=True,
        message="Billing summary retrieved successfully.",
        data={
            "subscription": subscription.visible_dict(),
            "limits": limits_for_plan(subscription.plan),
            "usage": [item.visible_dict() for item in usage],
            "recent_invoices": [invoice.visible_dict() for invoice in invoices],
            "invoice_count": total_invoices,
        },
        request_id=actor.request_id,
    )


@router.get("/health/status", response_model=BillingResponse)
async def billing_health(
    actor: ActorContext = Depends(get_actor_context),
    service: Billing = Depends(get_billing_service),
) -> BillingResponse:
    subscription = service.get_or_create_subscription(actor)
    limits = limits_for_plan(subscription.plan)

    return BillingResponse(
        ok=True,
        message="Billing module is available.",
        data={
            "module": "billing",
            "status": "healthy",
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "role": actor.role.value,
            "plan": subscription.plan.value,
            "subscription_status": subscription.status.value,
            "subscription_active": subscription.status in {SubscriptionStatus.ACTIVE, SubscriptionStatus.TRIALING},
            "currency": subscription.currency,
            "limits": limits,
            "settings": {
                "default_currency": DEFAULT_CURRENCY,
                "require_security_for_plan_change": REQUIRE_SECURITY_FOR_PLAN_CHANGE,
                "require_security_for_cancel": REQUIRE_SECURITY_FOR_CANCEL,
                "require_security_for_manual_invoice": REQUIRE_SECURITY_FOR_MANUAL_INVOICE,
            },
        },
        request_id=actor.request_id,
    )


# =============================================================================
# Service-compatible helper functions
# =============================================================================

async def check_usage_limit(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compatibility hook for other modules.

    Expected payload:
    {
        "user_id": "...",
        "workspace_id": "...",
        "role": "member",
        "plan": "pro",
        "request_id": "...",
        "metric": "tasks",
        "requested_amount": 1
    }
    """

    actor = ActorContext(
        user_id=normalize_id(str(payload.get("user_id")), "user_id"),
        workspace_id=normalize_id(str(payload.get("workspace_id")), "workspace_id"),
        role=parse_role(str(payload.get("role") or "member")),
        plan=parse_plan(str(payload.get("plan") or "free")),
        subscription_active=True,
        request_id=str(payload.get("request_id") or uuid.uuid4()),
    )

    metric_value = str(payload.get("metric") or UsageMetric.TASKS.value)
    metric = UsageMetric.TASKS
    for item in UsageMetric:
        if item.value == metric_value:
            metric = item

    requested_amount = int(payload.get("requested_amount") or 1)
    result = await billing_service.check_usage(actor, metric, requested_amount)
    return result


async def increment_usage_limit(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compatibility hook for other modules.
    """

    actor = ActorContext(
        user_id=normalize_id(str(payload.get("user_id")), "user_id"),
        workspace_id=normalize_id(str(payload.get("workspace_id")), "workspace_id"),
        role=parse_role(str(payload.get("role") or "member")),
        plan=parse_plan(str(payload.get("plan") or "free")),
        subscription_active=True,
        request_id=str(payload.get("request_id") or uuid.uuid4()),
    )

    metric_value = str(payload.get("metric") or UsageMetric.TASKS.value)
    metric = UsageMetric.TASKS
    for item in UsageMetric:
        if item.value == metric_value:
            metric = item

    request = UsageIncrementRequest(
        metric=metric,
        amount=int(payload.get("amount") or 1),
        idempotency_key=payload.get("idempotency_key"),
        metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
    )

    usage, _ = await billing_service.increment_usage(actor, request)

    return {
        "ok": True,
        "usage": usage.visible_dict(),
        "request_id": actor.request_id,
    }


__all__ = [
    "router",
    "Billing",
    "ActorContext",
    "SubscriptionPlan",
    "SubscriptionStatus",
    "BillingInterval",
    "InvoiceStatus",
    "UsageMetric",
    "PlanRecord",
    "SubscriptionRecord",
    "UsageRecord",
    "InvoiceRecord",
    "BillingResponse",
    "PlanListResponse",
    "InvoiceSearchResponse",
    "SubscriptionCreateRequest",
    "SubscriptionUpdateRequest",
    "UsageIncrementRequest",
    "UsageCheckRequest",
    "InvoiceCreateRequest",
    "InvoiceUpdateRequest",
    "check_usage_limit",
    "increment_usage_limit",
]