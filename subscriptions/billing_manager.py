"""
William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Subscription System - Billing Manager

File: subscriptions/billing_manager.py
Class: BillingManager

Purpose:
    Handles billing status, invoices, subscription snapshots, payment provider
    abstraction, and safe payment rules for the William/Jarvis SaaS system.

Safety:
    - Does not charge cards.
    - Does not submit payments.
    - Does not cancel subscriptions directly.
    - Does not store real card numbers or secrets.
    - Any sensitive billing operation prepares a Security Agent approval payload.
    - Every billing decision supports user_id and workspace_id isolation.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Protocol, Tuple


try:
    from subscriptions.plan_rules import PlanRules
except Exception:
    class PlanRules:  # type: ignore[no-redef]
        """Fallback stub so this file remains import-safe before plan_rules.py exists."""

        def get_default_plan_name(self) -> str:
            return "free"

        def get_plan(self, plan_name: str) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback plan loaded.",
                "data": {
                    "plan": {
                        "name": plan_name,
                        "display_name": str(plan_name).title(),
                        "monthly_price_usd": 0,
                    }
                },
                "error": None,
                "metadata": {},
            }

        def get_subscription_snapshot(
            self,
            plan_name: str,
            usage: Optional[Mapping[str, int]] = None,
            user_id: Optional[str] = None,
            workspace_id: Optional[str] = None,
            role: str = "member",
        ) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback subscription snapshot created.",
                "data": {
                    "plan": {
                        "name": plan_name,
                        "display_name": str(plan_name).title(),
                    },
                    "usage_summary": dict(usage or {}),
                    "agent_access": {},
                    "feature_access": {},
                    "metadata": {
                        "user_id": user_id,
                        "workspace_id": workspace_id,
                        "role": role,
                    },
                },
                "error": None,
                "metadata": {},
            }


class BillingStatus(str, Enum):
    """Workspace subscription billing status."""

    ACTIVE = "active"
    TRIALING = "trialing"
    PAST_DUE = "past_due"
    CANCELED = "canceled"
    INCOMPLETE = "incomplete"
    SUSPENDED = "suspended"
    UNKNOWN = "unknown"


class InvoiceStatus(str, Enum):
    """Invoice lifecycle status."""

    DRAFT = "draft"
    OPEN = "open"
    PAID = "paid"
    VOID = "void"
    FAILED = "failed"
    UNCOLLECTIBLE = "uncollectible"
    PENDING_REVIEW = "pending_review"


class PaymentProviderName(str, Enum):
    """Supported provider abstraction names."""

    NONE = "none"
    STRIPE = "stripe"
    PAYPAL = "paypal"
    MANUAL = "manual"
    CUSTOM = "custom"


class BillingAction(str, Enum):
    """Billing action names used for safety checks."""

    VIEW_STATUS = "view_status"
    LIST_INVOICES = "list_invoices"
    CREATE_INVOICE_DRAFT = "create_invoice_draft"
    PREPARE_CHECKOUT = "prepare_checkout"
    UPDATE_PAYMENT_METHOD = "update_payment_method"
    CANCEL_SUBSCRIPTION = "cancel_subscription"
    CHANGE_PLAN = "change_plan"
    EXPORT_INVOICES = "export_invoices"
    RECORD_MANUAL_PAYMENT = "record_manual_payment"


class BillingRiskLevel(str, Enum):
    """Risk level for billing actions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class BillingContext:
    """SaaS billing context for one user/workspace request."""

    user_id: str
    workspace_id: str
    role: str = "member"
    request_id: Optional[str] = None
    source: str = "subscriptions.billing_manager"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class SubscriptionRecord:
    """Safe subscription record for one workspace."""

    workspace_id: str
    plan_name: str
    status: BillingStatus
    provider: PaymentProviderName = PaymentProviderName.NONE
    provider_customer_id: Optional[str] = None
    provider_subscription_id: Optional[str] = None
    current_period_start: Optional[str] = None
    current_period_end: Optional[str] = None
    cancel_at_period_end: bool = False
    trial_end: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["provider"] = self.provider.value
        data["metadata"] = dict(self.metadata)
        return data


@dataclass(frozen=True)
class InvoiceLineItem:
    """Invoice line item."""

    description: str
    quantity: int
    unit_amount_cents: int
    currency: str = "usd"
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def total_cents(self) -> int:
        return self.quantity * self.unit_amount_cents

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["total_cents"] = self.total_cents
        data["metadata"] = dict(self.metadata)
        return data


@dataclass(frozen=True)
class InvoiceRecord:
    """Safe invoice record."""

    invoice_id: str
    workspace_id: str
    user_id: Optional[str]
    plan_name: str
    status: InvoiceStatus
    line_items: Tuple[InvoiceLineItem, ...]
    currency: str = "usd"
    issued_at: Optional[str] = None
    due_at: Optional[str] = None
    paid_at: Optional[str] = None
    provider: PaymentProviderName = PaymentProviderName.NONE
    provider_invoice_id: Optional[str] = None
    hosted_invoice_url: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    @property
    def amount_due_cents(self) -> int:
        return sum(item.total_cents for item in self.line_items)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["provider"] = self.provider.value
        data["line_items"] = [item.to_dict() for item in self.line_items]
        data["amount_due_cents"] = self.amount_due_cents
        data["amount_due_display"] = BillingManager.format_money(
            self.amount_due_cents,
            self.currency,
        )
        data["metadata"] = dict(self.metadata)
        return data


@dataclass(frozen=True)
class PaymentProviderRequest:
    """Provider abstraction request. No real secret or card data should be included."""

    provider: PaymentProviderName
    action: BillingAction
    workspace_id: str
    user_id: str
    plan_name: Optional[str] = None
    amount_cents: Optional[int] = None
    currency: str = "usd"
    success_url: Optional[str] = None
    cancel_url: Optional[str] = None
    provider_customer_id: Optional[str] = None
    provider_subscription_id: Optional[str] = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["provider"] = self.provider.value
        data["action"] = self.action.value
        data["metadata"] = dict(self.metadata)
        return data


class PaymentProviderAdapter(Protocol):
    """
    Protocol for future payment providers.

    Real Stripe/PayPal/custom providers should implement this interface later.
    """

    provider_name: PaymentProviderName

    def prepare_checkout(self, request: PaymentProviderRequest) -> Dict[str, Any]:
        ...

    def prepare_payment_method_update(self, request: PaymentProviderRequest) -> Dict[str, Any]:
        ...

    def prepare_cancellation(self, request: PaymentProviderRequest) -> Dict[str, Any]:
        ...


class SafeNoopPaymentProvider:
    """
    Safe provider adapter used by default.

    It never contacts a real payment processor. It only returns structured payloads
    showing what would be sent after Security Agent approval.
    """

    provider_name = PaymentProviderName.NONE

    def prepare_checkout(self, request: PaymentProviderRequest) -> Dict[str, Any]:
        return {
            "provider": self.provider_name.value,
            "action": "prepare_checkout",
            "would_create_checkout_session": True,
            "request": request.to_dict(),
            "external_call_executed": False,
        }

    def prepare_payment_method_update(self, request: PaymentProviderRequest) -> Dict[str, Any]:
        return {
            "provider": self.provider_name.value,
            "action": "prepare_payment_method_update",
            "would_create_billing_portal_session": True,
            "request": request.to_dict(),
            "external_call_executed": False,
        }

    def prepare_cancellation(self, request: PaymentProviderRequest) -> Dict[str, Any]:
        return {
            "provider": self.provider_name.value,
            "action": "prepare_cancellation",
            "would_prepare_cancel_subscription": True,
            "request": request.to_dict(),
            "external_call_executed": False,
        }


class BillingManager:
    """
    Billing manager for William/Jarvis SaaS subscriptions.

    This class is backend logic, not frontend demo UI.

    It can be used by:
        - FastAPI subscription routes
        - Dashboard billing page API
        - AccessControl before allowing plan-gated features
        - UsageMeter when checking subscription usage
        - Security Agent when reviewing payment-related requests
        - Verification Agent after billing-safe decisions

    It intentionally does not store data permanently. Database persistence should
    be added later in repository/service files.
    """

    OWNER_ONLY_ACTIONS: Tuple[BillingAction, ...] = (
        BillingAction.UPDATE_PAYMENT_METHOD,
        BillingAction.CANCEL_SUBSCRIPTION,
        BillingAction.CHANGE_PLAN,
        BillingAction.RECORD_MANUAL_PAYMENT,
    )

    SENSITIVE_ACTIONS: Tuple[BillingAction, ...] = (
        BillingAction.PREPARE_CHECKOUT,
        BillingAction.UPDATE_PAYMENT_METHOD,
        BillingAction.CANCEL_SUBSCRIPTION,
        BillingAction.CHANGE_PLAN,
        BillingAction.RECORD_MANUAL_PAYMENT,
    )

    def __init__(
        self,
        plan_rules: Optional[PlanRules] = None,
        payment_provider: Optional[PaymentProviderAdapter] = None,
    ) -> None:
        self.plan_rules = plan_rules or PlanRules()
        self.payment_provider = payment_provider or SafeNoopPaymentProvider()

    # ------------------------------------------------------------------
    # Public billing APIs
    # ------------------------------------------------------------------

    def get_billing_status(
        self,
        subscription: Optional[SubscriptionRecord],
        user_id: str,
        workspace_id: str,
        role: str = "member",
    ) -> Dict[str, Any]:
        """Return current billing status for a workspace."""

        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "role": role,
                "action": BillingAction.VIEW_STATUS.value,
            }
        )
        if not context_result["success"]:
            return context_result

        if subscription is None:
            default_plan = self.plan_rules.get_default_plan_name()
            subscription = SubscriptionRecord(
                workspace_id=workspace_id,
                plan_name=default_plan,
                status=BillingStatus.UNKNOWN,
                provider=PaymentProviderName.NONE,
                metadata={"reason": "subscription_not_provided"},
            )

        if subscription.workspace_id != workspace_id:
            return self._error_result(
                message="Subscription workspace_id does not match request workspace_id.",
                error="workspace_mismatch",
                metadata={
                    "request_workspace_id": workspace_id,
                    "subscription_workspace_id": subscription.workspace_id,
                },
            )

        plan_result = self.plan_rules.get_plan(subscription.plan_name)

        return self._safe_result(
            message="Billing status loaded successfully.",
            data={
                "subscription": subscription.to_dict(),
                "plan": plan_result.get("data", {}).get("plan"),
                "is_active": subscription.status
                in (BillingStatus.ACTIVE, BillingStatus.TRIALING),
                "requires_attention": subscription.status
                in (
                    BillingStatus.PAST_DUE,
                    BillingStatus.INCOMPLETE,
                    BillingStatus.SUSPENDED,
                    BillingStatus.UNKNOWN,
                ),
                "metadata": self._metadata(
                    user_id=user_id,
                    workspace_id=workspace_id,
                    action=BillingAction.VIEW_STATUS.value,
                ),
            },
        )

    def create_invoice_draft(
        self,
        user_id: str,
        workspace_id: str,
        plan_name: str,
        line_items: List[Mapping[str, Any]],
        role: str = "member",
        invoice_id: Optional[str] = None,
        currency: str = "usd",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a safe local invoice draft.

        This does not send an invoice, charge a customer, or contact a provider.
        """

        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "role": role,
                "action": BillingAction.CREATE_INVOICE_DRAFT.value,
            }
        )
        if not context_result["success"]:
            return context_result

        if not self._role_is_allowed(role, "admin"):
            return self._error_result(
                message="Only admin or owner can create invoice drafts.",
                error="role_not_allowed",
                metadata=self._metadata(user_id, workspace_id, BillingAction.CREATE_INVOICE_DRAFT.value),
            )

        parsed_items_result = self._parse_invoice_line_items(line_items, currency)
        if not parsed_items_result["success"]:
            return parsed_items_result

        parsed_items = tuple(parsed_items_result["data"]["line_items"])
        if not parsed_items:
            return self._error_result(
                message="Invoice draft requires at least one line item.",
                error="empty_invoice",
            )

        invoice = InvoiceRecord(
            invoice_id=invoice_id or self._generate_reference("INV"),
            workspace_id=workspace_id,
            user_id=user_id,
            plan_name=plan_name,
            status=InvoiceStatus.DRAFT,
            line_items=parsed_items,
            currency=currency.lower(),
            issued_at=self._now_iso(),
            provider=PaymentProviderName.NONE,
            metadata=dict(metadata or {}),
        )

        decision = {
            "invoice": invoice.to_dict(),
            "safe_payment_rule": "draft_only_no_charge_executed",
        }

        return self._safe_result(
            message="Invoice draft created safely.",
            data={
                **decision,
                "verification_payload": self._prepare_verification_payload(decision)["data"],
                "memory_payload": self._prepare_memory_payload(decision)["data"],
                "audit_event": self._log_audit_event(
                    BillingAction.CREATE_INVOICE_DRAFT.value,
                    decision,
                )["data"],
            },
        )

    def list_invoices(
        self,
        user_id: str,
        workspace_id: str,
        invoices: List[InvoiceRecord],
        role: str = "member",
        status_filter: Optional[InvoiceStatus] = None,
    ) -> Dict[str, Any]:
        """Return invoices for one workspace only."""

        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "role": role,
                "action": BillingAction.LIST_INVOICES.value,
            }
        )
        if not context_result["success"]:
            return context_result

        scoped_invoices = [
            invoice
            for invoice in invoices
            if invoice.workspace_id == workspace_id
            and (status_filter is None or invoice.status == status_filter)
        ]

        return self._safe_result(
            message="Invoices loaded successfully.",
            data={
                "workspace_id": workspace_id,
                "count": len(scoped_invoices),
                "invoices": [invoice.to_dict() for invoice in scoped_invoices],
                "status_filter": status_filter.value if status_filter else None,
            },
            metadata=self._metadata(user_id, workspace_id, BillingAction.LIST_INVOICES.value),
        )

    def prepare_checkout(
        self,
        user_id: str,
        workspace_id: str,
        plan_name: str,
        role: str = "owner",
        provider: PaymentProviderName = PaymentProviderName.NONE,
        success_url: Optional[str] = None,
        cancel_url: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare checkout payload safely.

        Does not create a real checkout session unless a real provider is injected,
        and even then this method returns approval-required payload first.
        """

        action = BillingAction.PREPARE_CHECKOUT
        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "role": role,
                "action": action.value,
            }
        )
        if not context_result["success"]:
            return context_result

        permission = self._check_billing_action_permission(action, role)
        if not permission["success"]:
            return permission

        plan_result = self.plan_rules.get_plan(plan_name)
        if not plan_result.get("success"):
            return self._error_result(
                message="Cannot prepare checkout for an unknown plan.",
                error="unknown_plan",
                metadata=self._metadata(user_id, workspace_id, action.value, plan_name),
            )

        plan = plan_result["data"]["plan"]
        amount = plan.get("monthly_price_usd")
        amount_cents = None if amount is None else int(amount) * 100

        request = PaymentProviderRequest(
            provider=provider,
            action=action,
            workspace_id=workspace_id,
            user_id=user_id,
            plan_name=plan_name,
            amount_cents=amount_cents,
            currency="usd",
            success_url=success_url,
            cancel_url=cancel_url,
            metadata=dict(metadata or {}),
        )

        approval = self._request_security_approval(
            {
                "action": action.value,
                "risk_level": BillingRiskLevel.HIGH.value,
                "request": request.to_dict(),
                "reason": "checkout_preparation_can_affect_subscription_and_payment_method",
            }
        )

        provider_payload = self.payment_provider.prepare_checkout(request)

        return self._safe_result(
            message="Checkout preparation requires Security Agent approval before real provider execution.",
            data={
                "requires_security_approval": True,
                "provider_payload": provider_payload,
                "security_approval": approval["data"],
                "external_call_executed": False,
                "metadata": self._metadata(user_id, workspace_id, action.value, plan_name),
            },
        )

    def prepare_payment_method_update(
        self,
        user_id: str,
        workspace_id: str,
        subscription: SubscriptionRecord,
        role: str = "owner",
    ) -> Dict[str, Any]:
        """Prepare payment method update safely."""

        action = BillingAction.UPDATE_PAYMENT_METHOD

        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "role": role,
                "action": action.value,
            }
        )
        if not context_result["success"]:
            return context_result

        if subscription.workspace_id != workspace_id:
            return self._error_result(
                message="Subscription workspace_id does not match request workspace_id.",
                error="workspace_mismatch",
            )

        permission = self._check_billing_action_permission(action, role)
        if not permission["success"]:
            return permission

        request = PaymentProviderRequest(
            provider=subscription.provider,
            action=action,
            workspace_id=workspace_id,
            user_id=user_id,
            plan_name=subscription.plan_name,
            provider_customer_id=subscription.provider_customer_id,
            provider_subscription_id=subscription.provider_subscription_id,
        )

        approval = self._request_security_approval(
            {
                "action": action.value,
                "risk_level": BillingRiskLevel.CRITICAL.value,
                "request": request.to_dict(),
                "reason": "payment_method_update_is_sensitive",
            }
        )

        provider_payload = self.payment_provider.prepare_payment_method_update(request)

        return self._safe_result(
            message="Payment method update prepared and requires approval.",
            data={
                "requires_security_approval": True,
                "provider_payload": provider_payload,
                "security_approval": approval["data"],
                "external_call_executed": False,
            },
            metadata=self._metadata(user_id, workspace_id, action.value, subscription.plan_name),
        )

    def prepare_subscription_cancellation(
        self,
        user_id: str,
        workspace_id: str,
        subscription: SubscriptionRecord,
        role: str = "owner",
        cancel_at_period_end: bool = True,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Prepare cancellation payload safely. Does not cancel directly."""

        action = BillingAction.CANCEL_SUBSCRIPTION

        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "role": role,
                "action": action.value,
            }
        )
        if not context_result["success"]:
            return context_result

        if subscription.workspace_id != workspace_id:
            return self._error_result(
                message="Subscription workspace_id does not match request workspace_id.",
                error="workspace_mismatch",
            )

        permission = self._check_billing_action_permission(action, role)
        if not permission["success"]:
            return permission

        request = PaymentProviderRequest(
            provider=subscription.provider,
            action=action,
            workspace_id=workspace_id,
            user_id=user_id,
            plan_name=subscription.plan_name,
            provider_customer_id=subscription.provider_customer_id,
            provider_subscription_id=subscription.provider_subscription_id,
            metadata={
                "cancel_at_period_end": cancel_at_period_end,
                "reason": reason,
            },
        )

        approval = self._request_security_approval(
            {
                "action": action.value,
                "risk_level": BillingRiskLevel.CRITICAL.value,
                "request": request.to_dict(),
                "reason": "subscription_cancellation_changes_workspace_access",
            }
        )

        provider_payload = self.payment_provider.prepare_cancellation(request)

        return self._safe_result(
            message="Subscription cancellation prepared and requires approval.",
            data={
                "requires_security_approval": True,
                "provider_payload": provider_payload,
                "security_approval": approval["data"],
                "external_call_executed": False,
            },
            metadata=self._metadata(user_id, workspace_id, action.value, subscription.plan_name),
        )

    def get_billing_dashboard_snapshot(
        self,
        user_id: str,
        workspace_id: str,
        subscription: Optional[SubscriptionRecord],
        invoices: Optional[List[InvoiceRecord]] = None,
        usage: Optional[Mapping[str, int]] = None,
        role: str = "member",
    ) -> Dict[str, Any]:
        """Create a dashboard-ready billing snapshot."""

        context_result = self._validate_task_context(
            {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "role": role,
                "action": "billing_dashboard_snapshot",
            }
        )
        if not context_result["success"]:
            return context_result

        invoices = invoices or []

        if subscription is None:
            plan_name = self.plan_rules.get_default_plan_name()
            subscription = SubscriptionRecord(
                workspace_id=workspace_id,
                plan_name=plan_name,
                status=BillingStatus.UNKNOWN,
                provider=PaymentProviderName.NONE,
            )

        if subscription.workspace_id != workspace_id:
            return self._error_result(
                message="Subscription workspace_id does not match request workspace_id.",
                error="workspace_mismatch",
            )

        billing_status = self.get_billing_status(
            subscription=subscription,
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
        )

        scoped_invoice_result = self.list_invoices(
            user_id=user_id,
            workspace_id=workspace_id,
            invoices=invoices,
            role=role,
        )

        subscription_snapshot = self.plan_rules.get_subscription_snapshot(
            plan_name=subscription.plan_name,
            usage=usage or {},
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
        )

        invoice_data = scoped_invoice_result.get("data", {}).get("invoices", [])
        paid_total_cents = sum(
            invoice.get("amount_due_cents", 0)
            for invoice in invoice_data
            if invoice.get("status") == InvoiceStatus.PAID.value
        )
        open_total_cents = sum(
            invoice.get("amount_due_cents", 0)
            for invoice in invoice_data
            if invoice.get("status") in (InvoiceStatus.OPEN.value, InvoiceStatus.PENDING_REVIEW.value)
        )

        return self._safe_result(
            message="Billing dashboard snapshot created.",
            data={
                "billing_status": billing_status.get("data", {}),
                "subscription_snapshot": subscription_snapshot.get("data", {}),
                "invoice_summary": {
                    "invoice_count": len(invoice_data),
                    "paid_total_cents": paid_total_cents,
                    "paid_total_display": self.format_money(paid_total_cents),
                    "open_total_cents": open_total_cents,
                    "open_total_display": self.format_money(open_total_cents),
                },
                "invoices": invoice_data,
                "safe_payment_rules": self.get_safe_payment_rules()["data"],
                "metadata": self._metadata(user_id, workspace_id, "billing_dashboard_snapshot", subscription.plan_name),
            },
        )

    def get_safe_payment_rules(self) -> Dict[str, Any]:
        """Return safe payment rules for dashboard/API display."""

        rules = [
            "Never auto-charge a user.",
            "Never auto-transfer money.",
            "Never store raw card numbers.",
            "Never hardcode payment secrets.",
            "Plan changes require owner-level permission.",
            "Payment method updates require Security Agent approval.",
            "Subscription cancellation requires Security Agent approval.",
            "Finance Agent may create drafts only, not submit payments.",
            "Invoices must stay scoped to workspace_id.",
            "Provider calls should be made only through approved backend routes.",
        ]

        return self._safe_result(
            message="Safe payment rules loaded.",
            data={
                "rules": rules,
                "sensitive_actions": [action.value for action in self.SENSITIVE_ACTIONS],
                "owner_only_actions": [action.value for action in self.OWNER_ONLY_ACTIONS],
            },
        )

    # ------------------------------------------------------------------
    # William compatibility hooks
    # ------------------------------------------------------------------

    def _validate_task_context(self, context: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """Validate user/workspace context for SaaS-safe billing operations."""

        if context is None:
            return self._error_result(
                message="Billing context is required.",
                error="missing_context",
            )

        user_id = context.get("user_id")
        workspace_id = context.get("workspace_id")
        role = context.get("role", "member")

        if not user_id or not workspace_id:
            return self._error_result(
                message="Billing operations require user_id and workspace_id.",
                error="missing_saas_isolation_fields",
                metadata={
                    "has_user_id": bool(user_id),
                    "has_workspace_id": bool(workspace_id),
                },
            )

        return self._safe_result(
            message="Billing context validated.",
            data={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "role": role,
                "action": context.get("action"),
                "request_id": context.get("request_id"),
            },
        )

    def _requires_security_check(
        self,
        action: Optional[str] = None,
        amount_cents: Optional[int] = None,
        provider: Optional[str] = None,
    ) -> bool:
        """Return whether a billing operation requires Security Agent approval."""

        normalized_action = str(action or "").strip().lower()

        if normalized_action in {item.value for item in self.SENSITIVE_ACTIONS}:
            return True

        if amount_cents is not None and amount_cents > 0:
            return True

        if provider and provider != PaymentProviderName.NONE.value:
            return True

        return False

    def _request_security_approval(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare Security Agent approval payload without executing anything."""

        return self._safe_result(
            message="Security approval payload prepared.",
            data={
                "requires_approval": True,
                "approval_type": "billing_action",
                "recommended_agent": "security_agent",
                "payload": dict(payload),
            },
        )

    def _prepare_verification_payload(self, decision: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare Verification Agent payload for billing actions."""

        return self._safe_result(
            message="Verification payload prepared.",
            data={
                "verification_type": "billing_decision",
                "expected_state": "billing_payload_prepared_no_payment_executed",
                "recommended_agent": "verification_agent",
                "decision": dict(decision),
            },
        )

    def _prepare_memory_payload(self, decision: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare Memory Agent payload for useful billing context."""

        return self._safe_result(
            message="Memory payload prepared.",
            data={
                "memory_type": "billing_context",
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
                "source": "subscriptions.billing_manager",
                "payload": dict(payload),
            },
        )

    def _log_audit_event(self, action: str, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Prepare audit payload for future Security Agent/Audit Logger."""

        return self._safe_result(
            message="Audit event payload prepared.",
            data={
                "action": action,
                "source": "subscriptions.billing_manager",
                "risk_level": self._risk_for_action(action).value,
                "payload": dict(payload),
                "created_at": self._now_iso(),
            },
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _check_billing_action_permission(
        self,
        action: BillingAction,
        role: str,
    ) -> Dict[str, Any]:
        """Check role-level permission for billing action."""

        minimum_role = "owner" if action in self.OWNER_ONLY_ACTIONS else "admin"

        if not self._role_is_allowed(role, minimum_role):
            return self._error_result(
                message=f"{action.value} requires {minimum_role} role.",
                error="role_not_allowed",
                metadata={
                    "action": action.value,
                    "role": role,
                    "required_role": minimum_role,
                },
            )

        return self._safe_result(
            message="Billing action permission granted.",
            data={
                "action": action.value,
                "role": role,
                "required_role": minimum_role,
            },
        )

    def _parse_invoice_line_items(
        self,
        line_items: List[Mapping[str, Any]],
        currency: str = "usd",
    ) -> Dict[str, Any]:
        """Validate and parse invoice line items."""

        parsed: List[InvoiceLineItem] = []

        for index, item in enumerate(line_items):
            description = str(item.get("description", "")).strip()
            quantity_raw = item.get("quantity", 1)
            amount_raw = item.get("unit_amount_cents")

            if not description:
                return self._error_result(
                    message="Invoice line item description is required.",
                    error="invalid_line_item_description",
                    metadata={"index": index},
                )

            try:
                quantity = int(quantity_raw)
                unit_amount_cents = int(amount_raw)
            except Exception:
                return self._error_result(
                    message="Invoice line item quantity and unit_amount_cents must be integers.",
                    error="invalid_line_item_amount",
                    metadata={"index": index},
                )

            if quantity <= 0:
                return self._error_result(
                    message="Invoice line item quantity must be greater than zero.",
                    error="invalid_line_item_quantity",
                    metadata={"index": index},
                )

            if unit_amount_cents < 0:
                return self._error_result(
                    message="Invoice line item unit_amount_cents cannot be negative.",
                    error="invalid_line_item_unit_amount",
                    metadata={"index": index},
                )

            parsed.append(
                InvoiceLineItem(
                    description=description,
                    quantity=quantity,
                    unit_amount_cents=unit_amount_cents,
                    currency=currency.lower(),
                    metadata=dict(item.get("metadata", {}) or {}),
                )
            )

        return self._safe_result(
            message="Invoice line items parsed.",
            data={"line_items": parsed},
        )

    def _risk_for_action(self, action: str) -> BillingRiskLevel:
        """Return risk level for a billing action."""

        normalized = str(action).strip().lower()

        if normalized in {
            BillingAction.UPDATE_PAYMENT_METHOD.value,
            BillingAction.CANCEL_SUBSCRIPTION.value,
            BillingAction.CHANGE_PLAN.value,
            BillingAction.RECORD_MANUAL_PAYMENT.value,
        }:
            return BillingRiskLevel.CRITICAL

        if normalized in {
            BillingAction.PREPARE_CHECKOUT.value,
            BillingAction.CREATE_INVOICE_DRAFT.value,
            BillingAction.EXPORT_INVOICES.value,
        }:
            return BillingRiskLevel.HIGH

        if normalized in {
            BillingAction.VIEW_STATUS.value,
            BillingAction.LIST_INVOICES.value,
        }:
            return BillingRiskLevel.MEDIUM

        return BillingRiskLevel.LOW

    def _role_is_allowed(self, actual_role: str, minimum_role: str) -> bool:
        """Simple role hierarchy check."""

        order = ("viewer", "member", "manager", "admin", "owner")
        actual = str(actual_role or "").strip().lower()
        minimum = str(minimum_role or "").strip().lower()

        if actual not in order or minimum not in order:
            return False

        return order.index(actual) >= order.index(minimum)

    def _generate_reference(self, prefix: str) -> str:
        """Generate deterministic-ish local reference without external dependencies."""

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        return f"{prefix}-{timestamp}"

    @staticmethod
    def _now_iso() -> str:
        """Return current UTC time in ISO format."""

        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def format_money(amount_cents: int, currency: str = "usd") -> str:
        """Format cents into a simple display string."""

        currency_symbol = "$" if currency.lower() == "usd" else f"{currency.upper()} "
        return f"{currency_symbol}{amount_cents / 100:,.2f}"

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
            "source": "subscriptions.billing_manager",
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
    "BillingManager",
    "BillingStatus",
    "InvoiceStatus",
    "PaymentProviderName",
    "BillingAction",
    "BillingRiskLevel",
    "BillingContext",
    "SubscriptionRecord",
    "InvoiceLineItem",
    "InvoiceRecord",
    "PaymentProviderRequest",
    "PaymentProviderAdapter",
    "SafeNoopPaymentProvider",
]