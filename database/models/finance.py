"""
database/models/finance.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix

Purpose:
    Invoices, expenses, receipts, subscriptions, and safe finance records.

Design goals:
    - Strict SaaS isolation using user_id and workspace_id
    - No secrets or payment credentials stored directly
    - Money stored as integer minor units, never floats
    - Audit-friendly payloads for finance actions
    - Security Agent approval routing for sensitive finance actions
    - Verification Agent payloads after completed financial actions
    - Memory Agent compatible finance summaries
    - Dashboard/API-safe structured responses
    - Safe imports even when future project files do not exist yet
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, ClassVar, Dict, Iterable, Mapping, Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum as SAEnum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, validates

try:
    from sqlalchemy.dialects.postgresql import JSONB
except Exception:  # pragma: no cover
    JSONB = None

try:
    from sqlalchemy import JSON
except Exception as exc:  # pragma: no cover
    raise RuntimeError("SQLAlchemy JSON support is required for finance.py") from exc

try:
    from database.base import Base
except Exception:
    try:
        from database.models.base import Base
    except Exception:
        from sqlalchemy.orm import DeclarativeBase

        class Base(DeclarativeBase):
            """Fallback SQLAlchemy base so this model imports before project Base exists."""


JsonColumn = JSONB if JSONB is not None and os.getenv("WILLIAM_DB_DIALECT", "").lower() == "postgresql" else JSON


def utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def generate_uuid() -> str:
    """Return a string UUID for database portability."""
    return str(uuid.uuid4())


class FinanceRecordType(str, Enum):
    """Main finance record type."""

    INVOICE = "invoice"
    EXPENSE = "expense"
    RECEIPT = "receipt"
    SUBSCRIPTION = "subscription"
    PAYMENT = "payment"
    REFUND = "refund"
    CREDIT_NOTE = "credit_note"
    ADJUSTMENT = "adjustment"


class FinanceStatus(str, Enum):
    """Generic finance status."""

    DRAFT = "draft"
    PENDING = "pending"
    WAITING_SECURITY = "waiting_security"
    APPROVED = "approved"
    REJECTED = "rejected"
    SENT = "sent"
    PARTIALLY_PAID = "partially_paid"
    PAID = "paid"
    OVERDUE = "overdue"
    CANCELLED = "cancelled"
    FAILED = "failed"
    REFUNDED = "refunded"
    ARCHIVED = "archived"


class InvoiceStatus(str, Enum):
    """Invoice lifecycle status."""

    DRAFT = "draft"
    WAITING_SECURITY = "waiting_security"
    APPROVED = "approved"
    SENT = "sent"
    PARTIALLY_PAID = "partially_paid"
    PAID = "paid"
    OVERDUE = "overdue"
    VOID = "void"
    CANCELLED = "cancelled"
    FAILED = "failed"


class ExpenseStatus(str, Enum):
    """Expense lifecycle status."""

    DRAFT = "draft"
    SUBMITTED = "submitted"
    WAITING_SECURITY = "waiting_security"
    APPROVED = "approved"
    REJECTED = "rejected"
    REIMBURSED = "reimbursed"
    CANCELLED = "cancelled"
    ARCHIVED = "archived"


class ReceiptStatus(str, Enum):
    """Receipt lifecycle status."""

    CAPTURED = "captured"
    VERIFIED = "verified"
    REJECTED = "rejected"
    REFUNDED = "refunded"
    ARCHIVED = "archived"


class FinanceSubscriptionStatus(str, Enum):
    """Finance subscription lifecycle status."""

    TRIALING = "trialing"
    ACTIVE = "active"
    PAST_DUE = "past_due"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    FAILED = "failed"


class PaymentStatus(str, Enum):
    """Payment lifecycle status."""

    PENDING = "pending"
    PROCESSING = "processing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    REFUNDED = "refunded"
    PARTIALLY_REFUNDED = "partially_refunded"


class PaymentMethodType(str, Enum):
    """Safe payment method labels. Never store raw card/bank credentials."""

    UNKNOWN = "unknown"
    CARD = "card"
    BANK_TRANSFER = "bank_transfer"
    CASH = "cash"
    CHECK = "check"
    WALLET = "wallet"
    STRIPE = "stripe"
    PAYPAL = "paypal"
    MANUAL = "manual"
    OTHER = "other"


class FinanceActorType(str, Enum):
    """Actor responsible for a finance action."""

    USER = "user"
    AGENT = "agent"
    MASTER_AGENT = "master_agent"
    FINANCE_AGENT = "finance_agent"
    SECURITY_AGENT = "security_agent"
    VERIFICATION_AGENT = "verification_agent"
    SYSTEM = "system"
    API = "api"
    WORKER = "worker"


class FinanceLogLevel(str, Enum):
    """Audit log levels."""

    DEBUG = "debug"
    INFO = "info"
    NOTICE = "notice"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class FinanceVisibility(str, Enum):
    """Dashboard/API visibility."""

    PRIVATE = "private"
    WORKSPACE = "workspace"
    ADMIN_ONLY = "admin_only"
    FINANCE_ONLY = "finance_only"
    SECURITY_ONLY = "security_only"


class FinanceAccessDecision(str, Enum):
    """Access decision result."""

    ALLOW = "allow"
    DENY = "deny"
    SECURITY_REVIEW = "security_review"
    SUBSCRIPTION_REQUIRED = "subscription_required"


class FinanceMixin:
    """
    Shared safe helpers for finance models.

    This mixin intentionally stores no SQLAlchemy columns.
    """

    SECRET_REDACTION: ClassVar[str] = "[REDACTED]"
    DEFAULT_PAYLOAD_LIMIT: ClassVar[int] = 96_000
    DEFAULT_CURRENCY: ClassVar[str] = os.getenv("WILLIAM_DEFAULT_CURRENCY", "USD").upper()

    SENSITIVE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "password",
            "passwd",
            "pwd",
            "secret",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "token",
            "authorization",
            "auth",
            "cookie",
            "session",
            "private_key",
            "client_secret",
            "stripe_secret",
            "paypal_secret",
            "openai_api_key",
            "database_url",
            "dsn",
            "connection_string",
            "card_number",
            "card_cvc",
            "cvc",
            "cvv",
            "ssn",
            "tax_id_raw",
            "iban",
            "routing_number",
            "account_number",
            "bank_account",
        }
    )

    @staticmethod
    def clean_identifier(value: Any, field_name: str = "identifier", max_length: int = 128) -> str:
        if value is None:
            return ""
        cleaned = str(value).strip()
        if not cleaned:
            return ""
        if len(cleaned) > max_length:
            raise ValueError(f"{field_name} is too long.")
        return cleaned

    @classmethod
    def coerce_enum(cls, value: Any, enum_cls: type[Enum]) -> Enum:
        if isinstance(value, enum_cls):
            return value
        if isinstance(value, str):
            normalized = value.strip()
            for item in enum_cls:
                if item.value == normalized or item.name.lower() == normalized.lower():
                    return item
        raise ValueError(f"Invalid {enum_cls.__name__}: {value!r}")

    @staticmethod
    def normalize_currency(currency: Optional[str]) -> str:
        value = str(currency or FinanceMixin.DEFAULT_CURRENCY).strip().upper()
        if len(value) != 3 or not value.isalpha():
            raise ValueError("currency must be a 3-letter ISO-style currency code.")
        return value

    @staticmethod
    def money(value_minor: Any, field_name: str = "amount") -> int:
        """
        Normalize an amount in minor units.

        Example:
            USD $10.99 should be stored as 1099, not 10.99.
        """
        if value_minor is None:
            return 0
        amount = int(value_minor)
        if amount < 0:
            raise ValueError(f"{field_name} cannot be negative.")
        return amount

    @classmethod
    def safe_json_value(cls, value: Any, depth: int = 0) -> Any:
        if depth > 8:
            return "[MAX_DEPTH_REACHED]"

        if value is None or isinstance(value, (str, int, float, bool)):
            return value

        if isinstance(value, datetime):
            return value.isoformat()

        if isinstance(value, Enum):
            return value.value

        if isinstance(value, Mapping):
            safe_dict: Dict[str, Any] = {}
            for raw_key, raw_value in value.items():
                key = str(raw_key)
                normalized_key = key.lower().replace("-", "_").replace(" ", "_")
                if normalized_key in cls.SENSITIVE_KEYS or any(
                    sensitive in normalized_key for sensitive in cls.SENSITIVE_KEYS
                ):
                    safe_dict[key] = cls.SECRET_REDACTION
                else:
                    safe_dict[key] = cls.safe_json_value(raw_value, depth + 1)
            return safe_dict

        if isinstance(value, (list, tuple, set, frozenset)):
            return [cls.safe_json_value(item, depth + 1) for item in value]

        return str(value)

    @classmethod
    def sanitize_payload(cls, payload: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """Return JSON-safe payload with secrets and raw payment data redacted."""
        if not payload:
            return {}

        safe_payload = cls.safe_json_value(dict(payload))
        serialized = json.dumps(safe_payload, sort_keys=True, default=str)

        max_size = int(os.getenv("WILLIAM_FINANCE_PAYLOAD_LIMIT", cls.DEFAULT_PAYLOAD_LIMIT))
        size_bytes = len(serialized.encode("utf-8"))

        if size_bytes > max_size:
            return {
                "payload_truncated": True,
                "payload_size_bytes": size_bytes,
                "payload_preview": serialized[: max_size // 2],
            }

        return safe_payload

    @classmethod
    def compute_hash(cls, payload: Optional[Mapping[str, Any]]) -> str:
        safe_payload = cls.sanitize_payload(payload)
        serialized = json.dumps(safe_payload, sort_keys=True, default=str)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def build_scope_key(cls, user_id: str, workspace_id: str) -> str:
        safe_user_id = cls.clean_identifier(user_id, "user_id")
        safe_workspace_id = cls.clean_identifier(workspace_id, "workspace_id")
        if not safe_user_id or not safe_workspace_id:
            raise ValueError("Both user_id and workspace_id are required.")
        return f"{safe_workspace_id}:{safe_user_id}"

    @classmethod
    def safe_error_response(
        cls,
        *,
        code: str,
        message: str,
        correlation_id: Optional[str] = None,
        resource_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "ok": False,
            "error": {
                "code": str(code),
                "message": str(message),
                "correlation_id": correlation_id,
                "resource_id": resource_id,
            },
        }

    @classmethod
    def success_response(
        cls,
        *,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "ok": True,
            "message": message,
            "data": cls.sanitize_payload(data or {}),
        }

    @classmethod
    def format_minor_units(cls, amount_minor: int, currency: str) -> str:
        safe_currency = cls.normalize_currency(currency)
        sign = "-" if amount_minor < 0 else ""
        absolute = abs(int(amount_minor))
        whole = absolute // 100
        cents = absolute % 100
        return f"{sign}{safe_currency} {whole}.{cents:02d}"


class Finance(Base, FinanceMixin):
    """
    Main normalized finance record.

    Use this as the parent finance ledger-style record for invoices, expenses,
    receipts, payments, refunds, and subscription financial events.

    Required isolation:
        - user_id
        - workspace_id
    """

    __tablename__ = "finance_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    finance_uid: Mapped[str] = mapped_column(
        String(80),
        unique=True,
        nullable=False,
        default=lambda: f"fin_{uuid.uuid4().hex}",
        index=True,
    )

    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    record_type: Mapped[FinanceRecordType] = mapped_column(
        SAEnum(FinanceRecordType, name="finance_record_type"),
        nullable=False,
        index=True,
    )

    status: Mapped[FinanceStatus] = mapped_column(
        SAEnum(FinanceStatus, name="finance_status"),
        nullable=False,
        default=FinanceStatus.DRAFT,
        index=True,
    )

    visibility: Mapped[FinanceVisibility] = mapped_column(
        SAEnum(FinanceVisibility, name="finance_visibility"),
        nullable=False,
        default=FinanceVisibility.FINANCE_ONLY,
        index=True,
    )

    title: Mapped[str] = mapped_column(String(220), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    customer_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    vendor_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    client_name: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)
    vendor_name: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)

    currency: Mapped[str] = mapped_column(String(3), nullable=False, default=FinanceMixin.DEFAULT_CURRENCY, index=True)
    subtotal_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tax_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    discount_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    fee_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)
    paid_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    balance_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0, index=True)

    actor_type: Mapped[FinanceActorType] = mapped_column(
        SAEnum(FinanceActorType, name="finance_actor_type"),
        nullable=False,
        default=FinanceActorType.USER,
        index=True,
    )
    actor_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    actor_role: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)
    subscription_plan: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)

    source: Mapped[str] = mapped_column(String(120), nullable=False, default="william.finance", index=True)
    external_provider: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)
    external_reference_id: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)

    task_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    correlation_id: Mapped[str] = mapped_column(
        String(96),
        nullable=False,
        default=lambda: f"corr_{uuid.uuid4().hex}",
        index=True,
    )

    payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    audit_payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    memory_context: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    verification_payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)

    requires_security_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    security_reviewed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    security_approved: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True, index=True)
    security_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    verification_required: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    verification_ready: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    verification_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)

    record_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True, index=True)

    issued_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    due_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    paid_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    cancelled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utc_now,
        onupdate=utc_now,
        index=True,
    )

    invoices: Mapped[list["FinanceInvoice"]] = relationship(
        "FinanceInvoice",
        back_populates="finance_record",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    expenses: Mapped[list["FinanceExpense"]] = relationship(
        "FinanceExpense",
        back_populates="finance_record",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    receipts: Mapped[list["FinanceReceipt"]] = relationship(
        "FinanceReceipt",
        back_populates="finance_record",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    subscriptions: Mapped[list["FinanceSubscription"]] = relationship(
        "FinanceSubscription",
        back_populates="finance_record",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    payments: Mapped[list["FinancePayment"]] = relationship(
        "FinancePayment",
        back_populates="finance_record",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    logs: Mapped[list["FinanceLog"]] = relationship(
        "FinanceLog",
        back_populates="finance_record",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        UniqueConstraint("workspace_id", "finance_uid", name="uq_finance_records_workspace_uid"),
        Index("ix_finance_records_scope_status", "workspace_id", "user_id", "status"),
        Index("ix_finance_records_scope_type", "workspace_id", "user_id", "record_type"),
        Index("ix_finance_records_customer", "workspace_id", "customer_id", "record_type"),
        Index("ix_finance_records_vendor", "workspace_id", "vendor_id", "record_type"),
        Index("ix_finance_records_security_queue", "workspace_id", "requires_security_review", "security_reviewed"),
        Index("ix_finance_records_verification_queue", "workspace_id", "verification_required", "verification_ready"),
    )

    def __repr__(self) -> str:
        return (
            "Finance("
            f"id={self.id!r}, finance_uid={self.finance_uid!r}, "
            f"user_id={self.user_id!r}, workspace_id={self.workspace_id!r}, "
            f"record_type={self.record_type.value!r}, status={self.status.value!r}, "
            f"total_minor={self.total_minor!r}, currency={self.currency!r})"
        )

    @validates("user_id", "workspace_id")
    def validate_scope(self, key: str, value: str) -> str:
        cleaned = self.clean_identifier(value, key)
        if not cleaned:
            raise ValueError(f"{key} is required for Finance isolation.")
        return cleaned

    @validates("currency")
    def validate_currency(self, key: str, value: str) -> str:
        return self.normalize_currency(value)

    @validates("subtotal_minor", "tax_minor", "discount_minor", "fee_minor", "total_minor", "paid_minor", "balance_minor")
    def validate_money(self, key: str, value: int) -> int:
        return self.money(value, key)

    @validates("title")
    def validate_title(self, key: str, value: str) -> str:
        cleaned = str(value or "").strip()
        if not cleaned:
            raise ValueError("Finance record title is required.")
        return cleaned[:220]

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        record_type: FinanceRecordType | str,
        title: str,
        description: Optional[str] = None,
        currency: Optional[str] = None,
        subtotal_minor: int = 0,
        tax_minor: int = 0,
        discount_minor: int = 0,
        fee_minor: int = 0,
        paid_minor: int = 0,
        customer_id: Optional[str] = None,
        vendor_id: Optional[str] = None,
        client_name: Optional[str] = None,
        vendor_name: Optional[str] = None,
        actor_type: FinanceActorType | str = FinanceActorType.USER,
        actor_id: Optional[str] = None,
        actor_role: Optional[str] = None,
        subscription_plan: Optional[str] = None,
        source: str = "william.finance",
        external_provider: Optional[str] = None,
        external_reference_id: Optional[str] = None,
        task_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
        payload: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        requires_security_review: bool = False,
        verification_required: bool = False,
        visibility: FinanceVisibility | str = FinanceVisibility.FINANCE_ONLY,
        issued_at: Optional[datetime] = None,
        due_at: Optional[datetime] = None,
    ) -> "Finance":
        safe_currency = cls.normalize_currency(currency)
        safe_subtotal = cls.money(subtotal_minor, "subtotal_minor")
        safe_tax = cls.money(tax_minor, "tax_minor")
        safe_discount = cls.money(discount_minor, "discount_minor")
        safe_fee = cls.money(fee_minor, "fee_minor")
        safe_paid = cls.money(paid_minor, "paid_minor")
        total_minor = max(safe_subtotal + safe_tax + safe_fee - safe_discount, 0)
        balance_minor = max(total_minor - safe_paid, 0)

        finance = cls(
            user_id=cls.clean_identifier(user_id, "user_id"),
            workspace_id=cls.clean_identifier(workspace_id, "workspace_id"),
            record_type=cls.coerce_enum(record_type, FinanceRecordType),
            status=FinanceStatus.WAITING_SECURITY if requires_security_review else FinanceStatus.DRAFT,
            visibility=cls.coerce_enum(visibility, FinanceVisibility),
            title=title,
            description=description,
            customer_id=str(customer_id)[:120] if customer_id else None,
            vendor_id=str(vendor_id)[:120] if vendor_id else None,
            client_name=str(client_name)[:180] if client_name else None,
            vendor_name=str(vendor_name)[:180] if vendor_name else None,
            currency=safe_currency,
            subtotal_minor=safe_subtotal,
            tax_minor=safe_tax,
            discount_minor=safe_discount,
            fee_minor=safe_fee,
            total_minor=total_minor,
            paid_minor=safe_paid,
            balance_minor=balance_minor,
            actor_type=cls.coerce_enum(actor_type, FinanceActorType),
            actor_id=str(actor_id)[:120] if actor_id else None,
            actor_role=str(actor_role)[:80] if actor_role else None,
            subscription_plan=str(subscription_plan)[:80] if subscription_plan else None,
            source=str(source or "william.finance")[:120],
            external_provider=str(external_provider)[:80] if external_provider else None,
            external_reference_id=str(external_reference_id)[:180] if external_reference_id else None,
            task_id=cls.clean_identifier(task_id, "task_id") if task_id else None,
            correlation_id=correlation_id or f"corr_{uuid.uuid4().hex}",
            payload=cls.sanitize_payload(payload),
            metadata_json={
                **cls.sanitize_payload(metadata),
                "scope_key": cls.build_scope_key(user_id, workspace_id),
                "schema_version": "1.0",
                "created_by_model": "Finance",
            },
            requires_security_review=bool(requires_security_review),
            verification_required=bool(verification_required),
            issued_at=issued_at,
            due_at=due_at,
        )
        finance.record_hash = finance.compute_record_hash()
        finance.audit_payload = finance.to_audit_payload()
        finance.memory_context = finance.prepare_memory_context()
        if finance.verification_required:
            finance.verification_payload = finance.prepare_verification_payload()
        return finance

    @property
    def scope_key(self) -> str:
        return self.build_scope_key(self.user_id, self.workspace_id)

    @property
    def needs_security_agent(self) -> bool:
        return self.requires_security_review and not self.security_reviewed

    @property
    def needs_verification_agent(self) -> bool:
        return self.verification_required and self.verification_ready and bool(self.verification_payload)

    @property
    def is_paid(self) -> bool:
        return self.balance_minor == 0 and self.total_minor > 0

    @property
    def display_total(self) -> str:
        return self.format_minor_units(self.total_minor, self.currency)

    @property
    def display_balance(self) -> str:
        return self.format_minor_units(self.balance_minor, self.currency)

    def compute_record_hash(self) -> str:
        return self.compute_hash(
            {
                "finance_uid": self.finance_uid,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "record_type": self.record_type.value,
                "status": self.status.value,
                "currency": self.currency,
                "subtotal_minor": self.subtotal_minor,
                "tax_minor": self.tax_minor,
                "discount_minor": self.discount_minor,
                "fee_minor": self.fee_minor,
                "total_minor": self.total_minor,
                "paid_minor": self.paid_minor,
                "balance_minor": self.balance_minor,
                "external_provider": self.external_provider,
                "external_reference_id": self.external_reference_id,
            }
        )

    def assert_same_scope(self, *, user_id: str, workspace_id: str) -> None:
        if self.user_id != str(user_id).strip() or self.workspace_id != str(workspace_id).strip():
            raise PermissionError("Finance access denied for this user/workspace scope.")

    def recalculate_totals(self) -> None:
        self.total_minor = max(self.subtotal_minor + self.tax_minor + self.fee_minor - self.discount_minor, 0)
        self.balance_minor = max(self.total_minor - self.paid_minor, 0)
        if self.is_paid:
            self.status = FinanceStatus.PAID
            self.paid_at = self.paid_at or utc_now()
        elif self.paid_minor > 0:
            self.status = FinanceStatus.PARTIALLY_PAID
        self.record_hash = self.compute_record_hash()
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()
        self.memory_context = self.prepare_memory_context()

    def approve(self) -> None:
        if self.needs_security_agent:
            raise PermissionError("Finance record requires Security Agent approval first.")
        self.status = FinanceStatus.APPROVED
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def mark_security_decision(self, *, approved: bool, reason: Optional[str] = None) -> None:
        self.security_reviewed = True
        self.security_approved = bool(approved)
        self.security_reason = reason
        self.status = FinanceStatus.APPROVED if approved else FinanceStatus.REJECTED
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def mark_sent(self) -> None:
        if self.needs_security_agent:
            self.status = FinanceStatus.WAITING_SECURITY
            raise PermissionError("Finance record requires Security Agent approval before sending.")
        self.status = FinanceStatus.SENT
        self.issued_at = self.issued_at or utc_now()
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def apply_payment(self, *, amount_minor: int, paid_at: Optional[datetime] = None) -> None:
        amount = self.money(amount_minor, "amount_minor")
        self.paid_minor = min(self.paid_minor + amount, self.total_minor)
        self.balance_minor = max(self.total_minor - self.paid_minor, 0)
        self.paid_at = paid_at or utc_now() if self.balance_minor == 0 else self.paid_at
        self.status = FinanceStatus.PAID if self.balance_minor == 0 else FinanceStatus.PARTIALLY_PAID
        self.verification_required = True
        self.verification_ready = True
        self.verification_id = self.verification_id or f"ver_{uuid.uuid4().hex}"
        self.verification_payload = self.prepare_verification_payload()
        self.record_hash = self.compute_record_hash()
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()
        self.memory_context = self.prepare_memory_context()

    def cancel(self, *, reason: Optional[str] = None) -> None:
        self.status = FinanceStatus.CANCELLED
        self.cancelled_at = utc_now()
        if reason:
            self.metadata_json = {**self.metadata_json, "cancel_reason": reason}
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def archive(self) -> None:
        self.status = FinanceStatus.ARCHIVED
        self.archived_at = utc_now()
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def prepare_memory_context(self) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "type": "finance_record",
                "finance_uid": self.finance_uid,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "record_type": self.record_type.value,
                "status": self.status.value,
                "title": self.title,
                "client_name": self.client_name,
                "vendor_name": self.vendor_name,
                "currency": self.currency,
                "total_minor": self.total_minor,
                "paid_minor": self.paid_minor,
                "balance_minor": self.balance_minor,
                "display_total": self.display_total,
                "display_balance": self.display_balance,
                "task_id": self.task_id,
                "scope_key": self.scope_key,
                "updated_at": self.updated_at,
            }
        )

    def prepare_verification_payload(self) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "verification_id": self.verification_id or f"ver_{uuid.uuid4().hex}",
                "type": "finance_record",
                "finance_uid": self.finance_uid,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "record_type": self.record_type.value,
                "status": self.status.value,
                "currency": self.currency,
                "total_minor": self.total_minor,
                "paid_minor": self.paid_minor,
                "balance_minor": self.balance_minor,
                "record_hash": self.record_hash,
                "audit_payload": self.audit_payload,
                "security_reviewed": self.security_reviewed,
                "security_approved": self.security_approved,
                "prepared_at": utc_now(),
            }
        )

    def to_audit_payload(self) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "finance_uid": self.finance_uid,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "record_type": self.record_type.value,
                "status": self.status.value,
                "visibility": self.visibility.value,
                "title": self.title,
                "customer_id": self.customer_id,
                "vendor_id": self.vendor_id,
                "currency": self.currency,
                "subtotal_minor": self.subtotal_minor,
                "tax_minor": self.tax_minor,
                "discount_minor": self.discount_minor,
                "fee_minor": self.fee_minor,
                "total_minor": self.total_minor,
                "paid_minor": self.paid_minor,
                "balance_minor": self.balance_minor,
                "actor_type": self.actor_type.value,
                "actor_id": self.actor_id,
                "actor_role": self.actor_role,
                "subscription_plan": self.subscription_plan,
                "source": self.source,
                "external_provider": self.external_provider,
                "external_reference_id": self.external_reference_id,
                "task_id": self.task_id,
                "correlation_id": self.correlation_id,
                "requires_security_review": self.requires_security_review,
                "security_reviewed": self.security_reviewed,
                "security_approved": self.security_approved,
                "security_reason": self.security_reason,
                "verification_required": self.verification_required,
                "verification_ready": self.verification_ready,
                "verification_id": self.verification_id,
                "record_hash": self.record_hash,
                "issued_at": self.issued_at,
                "due_at": self.due_at,
                "paid_at": self.paid_at,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
            }
        )

    def can_be_seen_by_role(self, role: Optional[str]) -> bool:
        normalized = (role or "").lower().strip()

        if self.visibility == FinanceVisibility.PRIVATE:
            return normalized in {"owner", "admin", "finance", "user"}

        if self.visibility == FinanceVisibility.WORKSPACE:
            return normalized in {"owner", "admin", "finance", "member", "viewer", "user"}

        if self.visibility == FinanceVisibility.ADMIN_ONLY:
            return normalized in {"owner", "admin", "super_admin"}

        if self.visibility == FinanceVisibility.FINANCE_ONLY:
            return normalized in {"owner", "admin", "finance", "super_admin"}

        if self.visibility == FinanceVisibility.SECURITY_ONLY:
            return normalized in {"owner", "admin", "security", "finance", "super_admin"}

        return False

    def check_access(
        self,
        *,
        role: Optional[str],
        subscription_plan: Optional[str] = None,
        require_active_plan: bool = False,
    ) -> Dict[str, Any]:
        if not self.can_be_seen_by_role(role):
            return {
                "decision": FinanceAccessDecision.DENY.value,
                "reason": "Role cannot access this finance record.",
            }

        if require_active_plan and not subscription_plan:
            return {
                "decision": FinanceAccessDecision.SUBSCRIPTION_REQUIRED.value,
                "reason": "Active subscription plan is required.",
            }

        if self.needs_security_agent:
            return {
                "decision": FinanceAccessDecision.SECURITY_REVIEW.value,
                "reason": "Security Agent review is required.",
            }

        return {
            "decision": FinanceAccessDecision.ALLOW.value,
            "reason": "Access allowed.",
        }

    def to_dashboard_payload(self, *, viewer_role: Optional[str] = None) -> Dict[str, Any]:
        can_view_internal = (viewer_role or "").lower().strip() in {
            "owner",
            "admin",
            "finance",
            "security",
            "developer",
            "super_admin",
        }

        data = {
            "id": self.id,
            "finance_uid": self.finance_uid,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "record_type": self.record_type.value,
            "status": self.status.value,
            "visibility": self.visibility.value,
            "title": self.title,
            "description": self.description,
            "client_name": self.client_name,
            "vendor_name": self.vendor_name,
            "currency": self.currency,
            "subtotal_minor": self.subtotal_minor,
            "tax_minor": self.tax_minor,
            "discount_minor": self.discount_minor,
            "fee_minor": self.fee_minor,
            "total_minor": self.total_minor,
            "paid_minor": self.paid_minor,
            "balance_minor": self.balance_minor,
            "display_total": self.display_total,
            "display_balance": self.display_balance,
            "task_id": self.task_id,
            "correlation_id": self.correlation_id,
            "security": {
                "requires_review": self.requires_security_review,
                "reviewed": self.security_reviewed,
                "approved": self.security_approved,
                "reason": self.security_reason if can_view_internal else None,
            },
            "verification": {
                "required": self.verification_required,
                "ready": self.verification_ready,
                "verification_id": self.verification_id,
            },
            "record_hash": self.record_hash,
            "issued_at": self.issued_at.isoformat() if self.issued_at else None,
            "due_at": self.due_at.isoformat() if self.due_at else None,
            "paid_at": self.paid_at.isoformat() if self.paid_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

        if can_view_internal:
            data["customer_id"] = self.customer_id
            data["vendor_id"] = self.vendor_id
            data["external_provider"] = self.external_provider
            data["external_reference_id"] = self.external_reference_id
            data["payload"] = self.sanitize_payload(self.payload)
            data["metadata"] = self.sanitize_payload(self.metadata_json)

        return data

    def to_dict(self) -> Dict[str, Any]:
        return {
            **self.to_dashboard_payload(viewer_role="admin"),
            "actor_type": self.actor_type.value,
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "subscription_plan": self.subscription_plan,
            "source": self.source,
            "audit_payload": self.sanitize_payload(self.audit_payload),
            "memory_context": self.sanitize_payload(self.memory_context),
            "verification_payload": self.sanitize_payload(self.verification_payload),
            "cancelled_at": self.cancelled_at.isoformat() if self.cancelled_at else None,
            "archived_at": self.archived_at.isoformat() if self.archived_at else None,
        }

    @classmethod
    def query_scope_filters(cls, *, user_id: str, workspace_id: str) -> tuple[Any, Any]:
        return (
            cls.user_id == cls.clean_identifier(user_id, "user_id"),
            cls.workspace_id == cls.clean_identifier(workspace_id, "workspace_id"),
        )


class FinanceInvoice(Base, FinanceMixin):
    """Invoice header model."""

    __tablename__ = "finance_invoices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    invoice_uid: Mapped[str] = mapped_column(
        String(80),
        unique=True,
        nullable=False,
        default=lambda: f"inv_{uuid.uuid4().hex}",
        index=True,
    )

    finance_record_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("finance_records.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    invoice_number: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    status: Mapped[InvoiceStatus] = mapped_column(
        SAEnum(InvoiceStatus, name="finance_invoice_status"),
        nullable=False,
        default=InvoiceStatus.DRAFT,
        index=True,
    )

    customer_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    customer_name: Mapped[str] = mapped_column(String(180), nullable=False, index=True)
    customer_email: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)

    currency: Mapped[str] = mapped_column(String(3), nullable=False, default=FinanceMixin.DEFAULT_CURRENCY, index=True)
    subtotal_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tax_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    discount_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    paid_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    balance_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    terms: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    issued_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    due_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    paid_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)

    payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    audit_payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)

    requires_security_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    security_reviewed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    security_approved: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    finance_record: Mapped["Finance"] = relationship("Finance", back_populates="invoices")

    line_items: Mapped[list["FinanceInvoiceLineItem"]] = relationship(
        "FinanceInvoiceLineItem",
        back_populates="invoice",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    __table_args__ = (
        UniqueConstraint("workspace_id", "invoice_uid", name="uq_finance_invoices_workspace_uid"),
        UniqueConstraint("workspace_id", "invoice_number", name="uq_finance_invoices_workspace_number"),
        Index("ix_finance_invoices_scope_status", "workspace_id", "user_id", "status"),
        Index("ix_finance_invoices_customer_status", "workspace_id", "customer_id", "status"),
    )

    @validates("user_id", "workspace_id")
    def validate_scope(self, key: str, value: str) -> str:
        cleaned = self.clean_identifier(value, key)
        if not cleaned:
            raise ValueError(f"{key} is required for FinanceInvoice isolation.")
        return cleaned

    @validates("currency")
    def validate_currency(self, key: str, value: str) -> str:
        return self.normalize_currency(value)

    @classmethod
    def create(
        cls,
        *,
        finance_record: Finance,
        invoice_number: str,
        customer_name: str,
        user_id: str,
        workspace_id: str,
        customer_id: Optional[str] = None,
        customer_email: Optional[str] = None,
        currency: Optional[str] = None,
        subtotal_minor: int = 0,
        tax_minor: int = 0,
        discount_minor: int = 0,
        paid_minor: int = 0,
        notes: Optional[str] = None,
        terms: Optional[str] = None,
        issued_at: Optional[datetime] = None,
        due_at: Optional[datetime] = None,
        payload: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        requires_security_review: bool = False,
    ) -> "FinanceInvoice":
        finance_record.assert_same_scope(user_id=user_id, workspace_id=workspace_id)

        safe_subtotal = cls.money(subtotal_minor, "subtotal_minor")
        safe_tax = cls.money(tax_minor, "tax_minor")
        safe_discount = cls.money(discount_minor, "discount_minor")
        safe_paid = cls.money(paid_minor, "paid_minor")
        total_minor = max(safe_subtotal + safe_tax - safe_discount, 0)
        balance_minor = max(total_minor - safe_paid, 0)

        invoice = cls(
            finance_record_id=finance_record.id,
            user_id=cls.clean_identifier(user_id, "user_id"),
            workspace_id=cls.clean_identifier(workspace_id, "workspace_id"),
            invoice_number=str(invoice_number).strip()[:80],
            status=InvoiceStatus.WAITING_SECURITY if requires_security_review else InvoiceStatus.DRAFT,
            customer_id=str(customer_id)[:120] if customer_id else None,
            customer_name=str(customer_name).strip()[:180],
            customer_email=str(customer_email).strip()[:180] if customer_email else None,
            currency=cls.normalize_currency(currency or finance_record.currency),
            subtotal_minor=safe_subtotal,
            tax_minor=safe_tax,
            discount_minor=safe_discount,
            total_minor=total_minor,
            paid_minor=safe_paid,
            balance_minor=balance_minor,
            notes=notes,
            terms=terms,
            issued_at=issued_at,
            due_at=due_at,
            payload=cls.sanitize_payload(payload),
            metadata_json={
                **cls.sanitize_payload(metadata),
                "finance_uid": finance_record.finance_uid,
                "scope_key": cls.build_scope_key(user_id, workspace_id),
                "schema_version": "1.0",
                "created_by_model": "FinanceInvoice",
            },
            requires_security_review=bool(requires_security_review),
        )
        invoice.audit_payload = invoice.to_audit_payload()
        return invoice

    @property
    def is_paid(self) -> bool:
        return self.balance_minor == 0 and self.total_minor > 0

    def mark_sent(self) -> None:
        if self.requires_security_review and not self.security_approved:
            self.status = InvoiceStatus.WAITING_SECURITY
            raise PermissionError("Invoice requires Security Agent approval before sending.")
        self.status = InvoiceStatus.SENT
        self.issued_at = self.issued_at or utc_now()
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def apply_payment(self, *, amount_minor: int, paid_at: Optional[datetime] = None) -> None:
        amount = self.money(amount_minor, "amount_minor")
        self.paid_minor = min(self.paid_minor + amount, self.total_minor)
        self.balance_minor = max(self.total_minor - self.paid_minor, 0)
        self.status = InvoiceStatus.PAID if self.balance_minor == 0 else InvoiceStatus.PARTIALLY_PAID
        self.paid_at = paid_at or utc_now() if self.balance_minor == 0 else self.paid_at
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def mark_security_decision(self, *, approved: bool) -> None:
        self.security_reviewed = True
        self.security_approved = bool(approved)
        self.status = InvoiceStatus.APPROVED if approved else InvoiceStatus.CANCELLED
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def to_audit_payload(self) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "invoice_uid": self.invoice_uid,
                "finance_record_id": self.finance_record_id,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "invoice_number": self.invoice_number,
                "status": self.status.value,
                "customer_id": self.customer_id,
                "customer_name": self.customer_name,
                "customer_email": self.customer_email,
                "currency": self.currency,
                "subtotal_minor": self.subtotal_minor,
                "tax_minor": self.tax_minor,
                "discount_minor": self.discount_minor,
                "total_minor": self.total_minor,
                "paid_minor": self.paid_minor,
                "balance_minor": self.balance_minor,
                "requires_security_review": self.requires_security_review,
                "security_reviewed": self.security_reviewed,
                "security_approved": self.security_approved,
                "issued_at": self.issued_at,
                "due_at": self.due_at,
                "paid_at": self.paid_at,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "invoice_uid": self.invoice_uid,
            "finance_record_id": self.finance_record_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "invoice_number": self.invoice_number,
            "status": self.status.value,
            "customer_id": self.customer_id,
            "customer_name": self.customer_name,
            "customer_email": self.customer_email,
            "currency": self.currency,
            "subtotal_minor": self.subtotal_minor,
            "tax_minor": self.tax_minor,
            "discount_minor": self.discount_minor,
            "total_minor": self.total_minor,
            "paid_minor": self.paid_minor,
            "balance_minor": self.balance_minor,
            "notes": self.notes,
            "terms": self.terms,
            "payload": self.sanitize_payload(self.payload),
            "audit_payload": self.sanitize_payload(self.audit_payload),
            "metadata": self.sanitize_payload(self.metadata_json),
            "requires_security_review": self.requires_security_review,
            "security_reviewed": self.security_reviewed,
            "security_approved": self.security_approved,
            "issued_at": self.issued_at.isoformat() if self.issued_at else None,
            "due_at": self.due_at.isoformat() if self.due_at else None,
            "paid_at": self.paid_at.isoformat() if self.paid_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class FinanceInvoiceLineItem(Base, FinanceMixin):
    """Invoice line item model."""

    __tablename__ = "finance_invoice_line_items"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    line_uid: Mapped[str] = mapped_column(
        String(80),
        nullable=False,
        default=lambda: f"ili_{uuid.uuid4().hex}",
        index=True,
    )

    invoice_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("finance_invoices.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(220), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    quantity: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    unit_amount_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tax_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    discount_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    invoice: Mapped["FinanceInvoice"] = relationship("FinanceInvoice", back_populates="line_items")

    __table_args__ = (
        Index("ix_finance_invoice_line_items_scope", "workspace_id", "user_id"),
        Index("ix_finance_invoice_line_items_invoice", "workspace_id", "invoice_id"),
    )

    @classmethod
    def create(
        cls,
        *,
        invoice: FinanceInvoice,
        user_id: str,
        workspace_id: str,
        name: str,
        description: Optional[str] = None,
        quantity: int = 1,
        unit_amount_minor: int = 0,
        tax_minor: int = 0,
        discount_minor: int = 0,
        sort_order: int = 0,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "FinanceInvoiceLineItem":
        if invoice.user_id != str(user_id).strip() or invoice.workspace_id != str(workspace_id).strip():
            raise PermissionError("Invoice line item access denied for this user/workspace scope.")

        safe_quantity = max(int(quantity or 1), 1)
        safe_unit = cls.money(unit_amount_minor, "unit_amount_minor")
        safe_tax = cls.money(tax_minor, "tax_minor")
        safe_discount = cls.money(discount_minor, "discount_minor")
        total = max((safe_quantity * safe_unit) + safe_tax - safe_discount, 0)

        return cls(
            invoice_id=invoice.id,
            user_id=cls.clean_identifier(user_id, "user_id"),
            workspace_id=cls.clean_identifier(workspace_id, "workspace_id"),
            name=str(name).strip()[:220],
            description=description,
            quantity=safe_quantity,
            unit_amount_minor=safe_unit,
            tax_minor=safe_tax,
            discount_minor=safe_discount,
            total_minor=total,
            sort_order=max(int(sort_order or 0), 0),
            metadata_json={
                **cls.sanitize_payload(metadata),
                "invoice_uid": invoice.invoice_uid,
                "scope_key": cls.build_scope_key(user_id, workspace_id),
                "schema_version": "1.0",
                "created_by_model": "FinanceInvoiceLineItem",
            },
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "line_uid": self.line_uid,
            "invoice_id": self.invoice_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "name": self.name,
            "description": self.description,
            "quantity": self.quantity,
            "unit_amount_minor": self.unit_amount_minor,
            "tax_minor": self.tax_minor,
            "discount_minor": self.discount_minor,
            "total_minor": self.total_minor,
            "sort_order": self.sort_order,
            "metadata": self.sanitize_payload(self.metadata_json),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class FinanceExpense(Base, FinanceMixin):
    """Expense record model."""

    __tablename__ = "finance_expenses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    expense_uid: Mapped[str] = mapped_column(
        String(80),
        unique=True,
        nullable=False,
        default=lambda: f"exp_{uuid.uuid4().hex}",
        index=True,
    )

    finance_record_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("finance_records.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    status: Mapped[ExpenseStatus] = mapped_column(
        SAEnum(ExpenseStatus, name="finance_expense_status"),
        nullable=False,
        default=ExpenseStatus.DRAFT,
        index=True,
    )

    category: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    vendor_name: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    currency: Mapped[str] = mapped_column(String(3), nullable=False, default=FinanceMixin.DEFAULT_CURRENCY, index=True)
    amount_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    tax_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    reimbursed_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    incurred_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    submitted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    reimbursed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    receipt_file_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)

    payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    audit_payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)

    requires_security_review: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    security_reviewed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, index=True)
    security_approved: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True, index=True)
    security_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    finance_record: Mapped["Finance"] = relationship("Finance", back_populates="expenses")

    __table_args__ = (
        UniqueConstraint("workspace_id", "expense_uid", name="uq_finance_expenses_workspace_uid"),
        Index("ix_finance_expenses_scope_status", "workspace_id", "user_id", "status"),
        Index("ix_finance_expenses_category", "workspace_id", "category", "status"),
    )

    @classmethod
    def create(
        cls,
        *,
        finance_record: Finance,
        user_id: str,
        workspace_id: str,
        category: str,
        amount_minor: int,
        vendor_name: Optional[str] = None,
        description: Optional[str] = None,
        currency: Optional[str] = None,
        tax_minor: int = 0,
        incurred_at: Optional[datetime] = None,
        receipt_file_id: Optional[str] = None,
        payload: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        requires_security_review: bool = False,
    ) -> "FinanceExpense":
        finance_record.assert_same_scope(user_id=user_id, workspace_id=workspace_id)

        expense = cls(
            finance_record_id=finance_record.id,
            user_id=cls.clean_identifier(user_id, "user_id"),
            workspace_id=cls.clean_identifier(workspace_id, "workspace_id"),
            status=ExpenseStatus.WAITING_SECURITY if requires_security_review else ExpenseStatus.DRAFT,
            category=str(category).strip()[:120],
            vendor_name=str(vendor_name)[:180] if vendor_name else None,
            description=description,
            currency=cls.normalize_currency(currency or finance_record.currency),
            amount_minor=cls.money(amount_minor, "amount_minor"),
            tax_minor=cls.money(tax_minor, "tax_minor"),
            incurred_at=incurred_at,
            receipt_file_id=str(receipt_file_id)[:120] if receipt_file_id else None,
            payload=cls.sanitize_payload(payload),
            metadata_json={
                **cls.sanitize_payload(metadata),
                "finance_uid": finance_record.finance_uid,
                "scope_key": cls.build_scope_key(user_id, workspace_id),
                "schema_version": "1.0",
                "created_by_model": "FinanceExpense",
            },
            requires_security_review=bool(requires_security_review),
        )
        expense.audit_payload = expense.to_audit_payload()
        return expense

    def submit(self) -> None:
        self.status = ExpenseStatus.SUBMITTED
        self.submitted_at = utc_now()
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def approve(self) -> None:
        if self.requires_security_review and not self.security_approved:
            self.status = ExpenseStatus.WAITING_SECURITY
            raise PermissionError("Expense requires Security Agent approval before approval.")
        self.status = ExpenseStatus.APPROVED
        self.approved_at = utc_now()
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def reject(self, *, reason: Optional[str] = None) -> None:
        self.status = ExpenseStatus.REJECTED
        self.security_reason = reason or self.security_reason
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def reimburse(self, *, amount_minor: Optional[int] = None) -> None:
        amount = self.money(amount_minor if amount_minor is not None else self.amount_minor, "amount_minor")
        self.reimbursed_minor = min(self.reimbursed_minor + amount, self.amount_minor)
        self.status = ExpenseStatus.REIMBURSED if self.reimbursed_minor >= self.amount_minor else ExpenseStatus.APPROVED
        self.reimbursed_at = utc_now() if self.status == ExpenseStatus.REIMBURSED else self.reimbursed_at
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def mark_security_decision(self, *, approved: bool, reason: Optional[str] = None) -> None:
        self.security_reviewed = True
        self.security_approved = bool(approved)
        self.security_reason = reason
        self.status = ExpenseStatus.APPROVED if approved else ExpenseStatus.REJECTED
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def to_audit_payload(self) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "expense_uid": self.expense_uid,
                "finance_record_id": self.finance_record_id,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "status": self.status.value,
                "category": self.category,
                "vendor_name": self.vendor_name,
                "currency": self.currency,
                "amount_minor": self.amount_minor,
                "tax_minor": self.tax_minor,
                "reimbursed_minor": self.reimbursed_minor,
                "receipt_file_id": self.receipt_file_id,
                "requires_security_review": self.requires_security_review,
                "security_reviewed": self.security_reviewed,
                "security_approved": self.security_approved,
                "security_reason": self.security_reason,
                "incurred_at": self.incurred_at,
                "submitted_at": self.submitted_at,
                "approved_at": self.approved_at,
                "reimbursed_at": self.reimbursed_at,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "expense_uid": self.expense_uid,
            "finance_record_id": self.finance_record_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "status": self.status.value,
            "category": self.category,
            "vendor_name": self.vendor_name,
            "description": self.description,
            "currency": self.currency,
            "amount_minor": self.amount_minor,
            "tax_minor": self.tax_minor,
            "reimbursed_minor": self.reimbursed_minor,
            "receipt_file_id": self.receipt_file_id,
            "payload": self.sanitize_payload(self.payload),
            "audit_payload": self.sanitize_payload(self.audit_payload),
            "metadata": self.sanitize_payload(self.metadata_json),
            "requires_security_review": self.requires_security_review,
            "security_reviewed": self.security_reviewed,
            "security_approved": self.security_approved,
            "security_reason": self.security_reason,
            "incurred_at": self.incurred_at.isoformat() if self.incurred_at else None,
            "submitted_at": self.submitted_at.isoformat() if self.submitted_at else None,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "reimbursed_at": self.reimbursed_at.isoformat() if self.reimbursed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class FinanceReceipt(Base, FinanceMixin):
    """Receipt record model for payments or expenses."""

    __tablename__ = "finance_receipts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    receipt_uid: Mapped[str] = mapped_column(
        String(80),
        unique=True,
        nullable=False,
        default=lambda: f"rcp_{uuid.uuid4().hex}",
        index=True,
    )

    finance_record_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("finance_records.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    status: Mapped[ReceiptStatus] = mapped_column(
        SAEnum(ReceiptStatus, name="finance_receipt_status"),
        nullable=False,
        default=ReceiptStatus.CAPTURED,
        index=True,
    )

    receipt_number: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)
    payer_name: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)
    payee_name: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)

    currency: Mapped[str] = mapped_column(String(3), nullable=False, default=FinanceMixin.DEFAULT_CURRENCY)
    amount_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    payment_method_type: Mapped[PaymentMethodType] = mapped_column(
        SAEnum(PaymentMethodType, name="finance_receipt_payment_method_type"),
        nullable=False,
        default=PaymentMethodType.UNKNOWN,
        index=True,
    )

    payment_reference: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)
    file_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)

    received_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    audit_payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    finance_record: Mapped["Finance"] = relationship("Finance", back_populates="receipts")

    __table_args__ = (
        UniqueConstraint("workspace_id", "receipt_uid", name="uq_finance_receipts_workspace_uid"),
        Index("ix_finance_receipts_scope_status", "workspace_id", "user_id", "status"),
        Index("ix_finance_receipts_reference", "workspace_id", "payment_reference"),
    )

    @classmethod
    def create(
        cls,
        *,
        finance_record: Finance,
        user_id: str,
        workspace_id: str,
        amount_minor: int,
        receipt_number: Optional[str] = None,
        payer_name: Optional[str] = None,
        payee_name: Optional[str] = None,
        currency: Optional[str] = None,
        payment_method_type: PaymentMethodType | str = PaymentMethodType.UNKNOWN,
        payment_reference: Optional[str] = None,
        file_id: Optional[str] = None,
        received_at: Optional[datetime] = None,
        payload: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "FinanceReceipt":
        finance_record.assert_same_scope(user_id=user_id, workspace_id=workspace_id)

        receipt = cls(
            finance_record_id=finance_record.id,
            user_id=cls.clean_identifier(user_id, "user_id"),
            workspace_id=cls.clean_identifier(workspace_id, "workspace_id"),
            receipt_number=str(receipt_number)[:80] if receipt_number else None,
            payer_name=str(payer_name)[:180] if payer_name else None,
            payee_name=str(payee_name)[:180] if payee_name else None,
            currency=cls.normalize_currency(currency or finance_record.currency),
            amount_minor=cls.money(amount_minor, "amount_minor"),
            payment_method_type=cls.coerce_enum(payment_method_type, PaymentMethodType),
            payment_reference=str(payment_reference)[:180] if payment_reference else None,
            file_id=str(file_id)[:120] if file_id else None,
            received_at=received_at or utc_now(),
            payload=cls.sanitize_payload(payload),
            metadata_json={
                **cls.sanitize_payload(metadata),
                "finance_uid": finance_record.finance_uid,
                "scope_key": cls.build_scope_key(user_id, workspace_id),
                "schema_version": "1.0",
                "created_by_model": "FinanceReceipt",
            },
        )
        receipt.audit_payload = receipt.to_audit_payload()
        return receipt

    def verify(self) -> None:
        self.status = ReceiptStatus.VERIFIED
        self.verified_at = utc_now()
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def reject(self, *, reason: Optional[str] = None) -> None:
        self.status = ReceiptStatus.REJECTED
        if reason:
            self.metadata_json = {**self.metadata_json, "reject_reason": reason}
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def to_audit_payload(self) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "receipt_uid": self.receipt_uid,
                "finance_record_id": self.finance_record_id,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "status": self.status.value,
                "receipt_number": self.receipt_number,
                "payer_name": self.payer_name,
                "payee_name": self.payee_name,
                "currency": self.currency,
                "amount_minor": self.amount_minor,
                "payment_method_type": self.payment_method_type.value,
                "payment_reference": self.payment_reference,
                "file_id": self.file_id,
                "received_at": self.received_at,
                "verified_at": self.verified_at,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "receipt_uid": self.receipt_uid,
            "finance_record_id": self.finance_record_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "status": self.status.value,
            "receipt_number": self.receipt_number,
            "payer_name": self.payer_name,
            "payee_name": self.payee_name,
            "currency": self.currency,
            "amount_minor": self.amount_minor,
            "payment_method_type": self.payment_method_type.value,
            "payment_reference": self.payment_reference,
            "file_id": self.file_id,
            "payload": self.sanitize_payload(self.payload),
            "audit_payload": self.sanitize_payload(self.audit_payload),
            "metadata": self.sanitize_payload(self.metadata_json),
            "received_at": self.received_at.isoformat() if self.received_at else None,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class FinanceSubscription(Base, FinanceMixin):
    """Safe finance subscription model. Does not store raw provider secrets."""

    __tablename__ = "finance_subscriptions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    subscription_uid: Mapped[str] = mapped_column(
        String(80),
        unique=True,
        nullable=False,
        default=lambda: f"fsub_{uuid.uuid4().hex}",
        index=True,
    )

    finance_record_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("finance_records.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    status: Mapped[FinanceSubscriptionStatus] = mapped_column(
        SAEnum(FinanceSubscriptionStatus, name="finance_subscription_status"),
        nullable=False,
        default=FinanceSubscriptionStatus.ACTIVE,
        index=True,
    )

    plan_code: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    plan_name: Mapped[str] = mapped_column(String(180), nullable=False)
    billing_interval: Mapped[str] = mapped_column(String(40), nullable=False, default="monthly", index=True)

    currency: Mapped[str] = mapped_column(String(3), nullable=False, default=FinanceMixin.DEFAULT_CURRENCY)
    amount_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    provider: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)
    provider_customer_id: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)
    provider_subscription_id: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)

    current_period_start: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    trial_end: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    cancelled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    usage_limits: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    audit_payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    finance_record: Mapped["Finance"] = relationship("Finance", back_populates="subscriptions")

    __table_args__ = (
        UniqueConstraint("workspace_id", "subscription_uid", name="uq_finance_subscriptions_workspace_uid"),
        Index("ix_finance_subscriptions_scope_status", "workspace_id", "user_id", "status"),
        Index("ix_finance_subscriptions_provider", "workspace_id", "provider", "provider_subscription_id"),
    )

    @classmethod
    def create(
        cls,
        *,
        finance_record: Finance,
        user_id: str,
        workspace_id: str,
        plan_code: str,
        plan_name: str,
        amount_minor: int,
        billing_interval: str = "monthly",
        currency: Optional[str] = None,
        status: FinanceSubscriptionStatus | str = FinanceSubscriptionStatus.ACTIVE,
        provider: Optional[str] = None,
        provider_customer_id: Optional[str] = None,
        provider_subscription_id: Optional[str] = None,
        current_period_start: Optional[datetime] = None,
        current_period_end: Optional[datetime] = None,
        trial_end: Optional[datetime] = None,
        usage_limits: Optional[Mapping[str, Any]] = None,
        payload: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "FinanceSubscription":
        finance_record.assert_same_scope(user_id=user_id, workspace_id=workspace_id)

        subscription = cls(
            finance_record_id=finance_record.id,
            user_id=cls.clean_identifier(user_id, "user_id"),
            workspace_id=cls.clean_identifier(workspace_id, "workspace_id"),
            status=cls.coerce_enum(status, FinanceSubscriptionStatus),
            plan_code=str(plan_code).strip()[:120],
            plan_name=str(plan_name).strip()[:180],
            billing_interval=str(billing_interval or "monthly").strip()[:40],
            currency=cls.normalize_currency(currency or finance_record.currency),
            amount_minor=cls.money(amount_minor, "amount_minor"),
            provider=str(provider)[:80] if provider else None,
            provider_customer_id=str(provider_customer_id)[:180] if provider_customer_id else None,
            provider_subscription_id=str(provider_subscription_id)[:180] if provider_subscription_id else None,
            current_period_start=current_period_start,
            current_period_end=current_period_end,
            trial_end=trial_end,
            usage_limits=cls.sanitize_payload(usage_limits),
            payload=cls.sanitize_payload(payload),
            metadata_json={
                **cls.sanitize_payload(metadata),
                "finance_uid": finance_record.finance_uid,
                "scope_key": cls.build_scope_key(user_id, workspace_id),
                "schema_version": "1.0",
                "created_by_model": "FinanceSubscription",
            },
        )
        subscription.audit_payload = subscription.to_audit_payload()
        return subscription

    @property
    def is_active(self) -> bool:
        return self.status in {FinanceSubscriptionStatus.ACTIVE, FinanceSubscriptionStatus.TRIALING}

    def pause(self) -> None:
        self.status = FinanceSubscriptionStatus.PAUSED
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def activate(self) -> None:
        self.status = FinanceSubscriptionStatus.ACTIVE
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def cancel(self) -> None:
        self.status = FinanceSubscriptionStatus.CANCELLED
        self.cancelled_at = utc_now()
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def to_audit_payload(self) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "subscription_uid": self.subscription_uid,
                "finance_record_id": self.finance_record_id,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "status": self.status.value,
                "plan_code": self.plan_code,
                "plan_name": self.plan_name,
                "billing_interval": self.billing_interval,
                "currency": self.currency,
                "amount_minor": self.amount_minor,
                "provider": self.provider,
                "provider_customer_id": self.provider_customer_id,
                "provider_subscription_id": self.provider_subscription_id,
                "current_period_start": self.current_period_start,
                "current_period_end": self.current_period_end,
                "trial_end": self.trial_end,
                "cancelled_at": self.cancelled_at,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "subscription_uid": self.subscription_uid,
            "finance_record_id": self.finance_record_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "status": self.status.value,
            "plan_code": self.plan_code,
            "plan_name": self.plan_name,
            "billing_interval": self.billing_interval,
            "currency": self.currency,
            "amount_minor": self.amount_minor,
            "provider": self.provider,
            "provider_customer_id": self.provider_customer_id,
            "provider_subscription_id": self.provider_subscription_id,
            "usage_limits": self.sanitize_payload(self.usage_limits),
            "payload": self.sanitize_payload(self.payload),
            "audit_payload": self.sanitize_payload(self.audit_payload),
            "metadata": self.sanitize_payload(self.metadata_json),
            "current_period_start": self.current_period_start.isoformat() if self.current_period_start else None,
            "current_period_end": self.current_period_end.isoformat() if self.current_period_end else None,
            "trial_end": self.trial_end.isoformat() if self.trial_end else None,
            "cancelled_at": self.cancelled_at.isoformat() if self.cancelled_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class FinancePayment(Base, FinanceMixin):
    """Payment/refund-safe tracking model."""

    __tablename__ = "finance_payments"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    payment_uid: Mapped[str] = mapped_column(
        String(80),
        unique=True,
        nullable=False,
        default=lambda: f"pay_{uuid.uuid4().hex}",
        index=True,
    )

    finance_record_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("finance_records.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    status: Mapped[PaymentStatus] = mapped_column(
        SAEnum(PaymentStatus, name="finance_payment_status"),
        nullable=False,
        default=PaymentStatus.PENDING,
        index=True,
    )

    payment_method_type: Mapped[PaymentMethodType] = mapped_column(
        SAEnum(PaymentMethodType, name="finance_payment_method_type"),
        nullable=False,
        default=PaymentMethodType.UNKNOWN,
        index=True,
    )

    currency: Mapped[str] = mapped_column(String(3), nullable=False, default=FinanceMixin.DEFAULT_CURRENCY)
    amount_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    refunded_minor: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    provider: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, index=True)
    provider_payment_id: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)
    provider_customer_id: Mapped[Optional[str]] = mapped_column(String(180), nullable=True, index=True)

    safe_payment_label: Mapped[Optional[str]] = mapped_column(
        String(180),
        nullable=True,
        doc="Safe display label only, e.g. Visa ending 4242. Never raw card data.",
    )

    paid_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    failed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    refunded_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    error_code: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    audit_payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    finance_record: Mapped["Finance"] = relationship("Finance", back_populates="payments")

    __table_args__ = (
        UniqueConstraint("workspace_id", "payment_uid", name="uq_finance_payments_workspace_uid"),
        Index("ix_finance_payments_scope_status", "workspace_id", "user_id", "status"),
        Index("ix_finance_payments_provider", "workspace_id", "provider", "provider_payment_id"),
    )

    @classmethod
    def create(
        cls,
        *,
        finance_record: Finance,
        user_id: str,
        workspace_id: str,
        amount_minor: int,
        payment_method_type: PaymentMethodType | str = PaymentMethodType.UNKNOWN,
        currency: Optional[str] = None,
        status: PaymentStatus | str = PaymentStatus.PENDING,
        provider: Optional[str] = None,
        provider_payment_id: Optional[str] = None,
        provider_customer_id: Optional[str] = None,
        safe_payment_label: Optional[str] = None,
        payload: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "FinancePayment":
        finance_record.assert_same_scope(user_id=user_id, workspace_id=workspace_id)

        payment = cls(
            finance_record_id=finance_record.id,
            user_id=cls.clean_identifier(user_id, "user_id"),
            workspace_id=cls.clean_identifier(workspace_id, "workspace_id"),
            status=cls.coerce_enum(status, PaymentStatus),
            payment_method_type=cls.coerce_enum(payment_method_type, PaymentMethodType),
            currency=cls.normalize_currency(currency or finance_record.currency),
            amount_minor=cls.money(amount_minor, "amount_minor"),
            provider=str(provider)[:80] if provider else None,
            provider_payment_id=str(provider_payment_id)[:180] if provider_payment_id else None,
            provider_customer_id=str(provider_customer_id)[:180] if provider_customer_id else None,
            safe_payment_label=str(safe_payment_label)[:180] if safe_payment_label else None,
            payload=cls.sanitize_payload(payload),
            metadata_json={
                **cls.sanitize_payload(metadata),
                "finance_uid": finance_record.finance_uid,
                "scope_key": cls.build_scope_key(user_id, workspace_id),
                "schema_version": "1.0",
                "created_by_model": "FinancePayment",
            },
        )
        payment.audit_payload = payment.to_audit_payload()
        return payment

    def succeed(self) -> None:
        self.status = PaymentStatus.SUCCEEDED
        self.paid_at = utc_now()
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def fail(self, *, error_code: str, error_message: str) -> None:
        self.status = PaymentStatus.FAILED
        self.error_code = str(error_code)[:120]
        self.error_message = str(error_message)
        self.failed_at = utc_now()
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def refund(self, *, amount_minor: Optional[int] = None) -> None:
        amount = self.money(amount_minor if amount_minor is not None else self.amount_minor, "amount_minor")
        self.refunded_minor = min(self.refunded_minor + amount, self.amount_minor)
        self.status = PaymentStatus.REFUNDED if self.refunded_minor >= self.amount_minor else PaymentStatus.PARTIALLY_REFUNDED
        self.refunded_at = utc_now()
        self.updated_at = utc_now()
        self.audit_payload = self.to_audit_payload()

    def to_audit_payload(self) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "payment_uid": self.payment_uid,
                "finance_record_id": self.finance_record_id,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "status": self.status.value,
                "payment_method_type": self.payment_method_type.value,
                "currency": self.currency,
                "amount_minor": self.amount_minor,
                "refunded_minor": self.refunded_minor,
                "provider": self.provider,
                "provider_payment_id": self.provider_payment_id,
                "provider_customer_id": self.provider_customer_id,
                "safe_payment_label": self.safe_payment_label,
                "paid_at": self.paid_at,
                "failed_at": self.failed_at,
                "refunded_at": self.refunded_at,
                "error_code": self.error_code,
                "error_message": self.error_message,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "payment_uid": self.payment_uid,
            "finance_record_id": self.finance_record_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "status": self.status.value,
            "payment_method_type": self.payment_method_type.value,
            "currency": self.currency,
            "amount_minor": self.amount_minor,
            "refunded_minor": self.refunded_minor,
            "provider": self.provider,
            "provider_payment_id": self.provider_payment_id,
            "provider_customer_id": self.provider_customer_id,
            "safe_payment_label": self.safe_payment_label,
            "payload": self.sanitize_payload(self.payload),
            "audit_payload": self.sanitize_payload(self.audit_payload),
            "metadata": self.sanitize_payload(self.metadata_json),
            "paid_at": self.paid_at.isoformat() if self.paid_at else None,
            "failed_at": self.failed_at.isoformat() if self.failed_at else None,
            "refunded_at": self.refunded_at.isoformat() if self.refunded_at else None,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class FinanceLog(Base, FinanceMixin):
    """Audit-friendly finance log record."""

    __tablename__ = "finance_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=generate_uuid)
    log_uid: Mapped[str] = mapped_column(
        String(80),
        nullable=False,
        default=lambda: f"flog_{uuid.uuid4().hex}",
        index=True,
    )

    finance_record_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        ForeignKey("finance_records.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    level: Mapped[FinanceLogLevel] = mapped_column(
        SAEnum(FinanceLogLevel, name="finance_log_level"),
        nullable=False,
        default=FinanceLogLevel.INFO,
        index=True,
    )

    event_name: Mapped[str] = mapped_column(String(160), nullable=False, index=True)
    message: Mapped[str] = mapped_column(Text, nullable=False)

    actor_type: Mapped[FinanceActorType] = mapped_column(
        SAEnum(FinanceActorType, name="finance_log_actor_type"),
        nullable=False,
        default=FinanceActorType.SYSTEM,
        index=True,
    )
    actor_id: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    action: Mapped[Optional[str]] = mapped_column(String(160), nullable=True, index=True)
    correlation_id: Mapped[Optional[str]] = mapped_column(String(96), nullable=True, index=True)

    payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    audit_payload: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JsonColumn, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)

    finance_record: Mapped[Optional["Finance"]] = relationship("Finance", back_populates="logs")

    __table_args__ = (
        Index("ix_finance_logs_scope_time", "workspace_id", "user_id", "created_at"),
        Index("ix_finance_logs_record_time", "workspace_id", "finance_record_id", "created_at"),
        Index("ix_finance_logs_level_time", "workspace_id", "level", "created_at"),
    )

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        event_name: str,
        message: str,
        finance_record_id: Optional[str] = None,
        level: FinanceLogLevel | str = FinanceLogLevel.INFO,
        actor_type: FinanceActorType | str = FinanceActorType.SYSTEM,
        actor_id: Optional[str] = None,
        action: Optional[str] = None,
        correlation_id: Optional[str] = None,
        payload: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> "FinanceLog":
        log = cls(
            finance_record_id=finance_record_id,
            user_id=cls.clean_identifier(user_id, "user_id"),
            workspace_id=cls.clean_identifier(workspace_id, "workspace_id"),
            level=cls.coerce_enum(level, FinanceLogLevel),
            event_name=str(event_name)[:160],
            message=str(message),
            actor_type=cls.coerce_enum(actor_type, FinanceActorType),
            actor_id=str(actor_id)[:120] if actor_id else None,
            action=str(action)[:160] if action else None,
            correlation_id=str(correlation_id)[:96] if correlation_id else None,
            payload=cls.sanitize_payload(payload),
            metadata_json={
                **cls.sanitize_payload(metadata),
                "scope_key": cls.build_scope_key(user_id, workspace_id),
                "schema_version": "1.0",
                "created_by_model": "FinanceLog",
            },
        )
        log.audit_payload = log.to_audit_payload()
        return log

    def to_audit_payload(self) -> Dict[str, Any]:
        return self.sanitize_payload(
            {
                "log_uid": self.log_uid,
                "finance_record_id": self.finance_record_id,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "level": self.level.value,
                "event_name": self.event_name,
                "message": self.message,
                "actor_type": self.actor_type.value,
                "actor_id": self.actor_id,
                "action": self.action,
                "correlation_id": self.correlation_id,
                "payload_hash": self.compute_hash(self.payload),
                "created_at": self.created_at,
            }
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "log_uid": self.log_uid,
            "finance_record_id": self.finance_record_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "level": self.level.value,
            "event_name": self.event_name,
            "message": self.message,
            "actor_type": self.actor_type.value,
            "actor_id": self.actor_id,
            "action": self.action,
            "correlation_id": self.correlation_id,
            "payload": self.sanitize_payload(self.payload),
            "audit_payload": self.sanitize_payload(self.audit_payload),
            "metadata": self.sanitize_payload(self.metadata_json),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


def summarize_finance_records(records: Iterable[Finance]) -> Dict[str, Any]:
    """Build dashboard-safe finance summary from records."""
    total_records = 0
    by_status: Dict[str, int] = {}
    by_type: Dict[str, int] = {}
    by_currency: Dict[str, Dict[str, int]] = {}
    security_pending = 0
    verification_ready = 0

    for record in records:
        total_records += 1
        by_status[record.status.value] = by_status.get(record.status.value, 0) + 1
        by_type[record.record_type.value] = by_type.get(record.record_type.value, 0) + 1

        currency_summary = by_currency.setdefault(
            record.currency,
            {
                "total_minor": 0,
                "paid_minor": 0,
                "balance_minor": 0,
            },
        )
        currency_summary["total_minor"] += int(record.total_minor or 0)
        currency_summary["paid_minor"] += int(record.paid_minor or 0)
        currency_summary["balance_minor"] += int(record.balance_minor or 0)

        if record.needs_security_agent:
            security_pending += 1
        if record.needs_verification_agent:
            verification_ready += 1

    return {
        "total_records": total_records,
        "by_status": by_status,
        "by_type": by_type,
        "by_currency": by_currency,
        "security_pending": security_pending,
        "verification_ready": verification_ready,
    }


__all__ = [
    "Finance",
    "FinanceInvoice",
    "FinanceInvoiceLineItem",
    "FinanceExpense",
    "FinanceReceipt",
    "FinanceSubscription",
    "FinancePayment",
    "FinanceLog",
    "FinanceRecordType",
    "FinanceStatus",
    "InvoiceStatus",
    "ExpenseStatus",
    "ReceiptStatus",
    "FinanceSubscriptionStatus",
    "PaymentStatus",
    "PaymentMethodType",
    "FinanceActorType",
    "FinanceLogLevel",
    "FinanceVisibility",
    "FinanceAccessDecision",
    "summarize_finance_records",
]