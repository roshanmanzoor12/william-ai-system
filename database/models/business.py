"""
William / Jarvis Multi-Agent AI SaaS System
Database Model: Business
File: database/models/business.py

Purpose:
    Business and CRM database models for:
    - Business profiles
    - Clients
    - Leads
    - CRM contacts
    - Deals
    - Pipelines
    - Campaigns
    - Invoices
    - Payments
    - Business analytics

Critical SaaS Rules:
    - Every user-owned record must carry user_id and workspace_id.
    - Never mix clients, leads, contacts, deals, campaigns, billing, analytics,
      or CRM activity between users/workspaces.
    - Sensitive actions prepare Security Agent approval payloads.
    - Completed state-changing actions prepare Verification Agent payloads.
    - Useful CRM context can be consumed by Memory Agent.
    - This file imports safely even when future files are not created yet.
"""

from __future__ import annotations

import enum
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

try:
    from database.core.base import Base
except Exception:
    try:
        from database.base import Base
    except Exception:
        try:
            from database.db import Base
        except Exception:
            from sqlalchemy.orm import declarative_base

            Base = declarative_base()


def utc_now() -> datetime:
    """
    Return timezone-aware UTC datetime.
    """
    return datetime.now(timezone.utc)


def generate_uuid() -> str:
    """
    Generate UUID string.
    """
    return str(uuid.uuid4())


def normalize_text(value: Optional[Any]) -> str:
    """
    Normalize text for safe storage and predictable comparisons.
    """
    if value is None:
        return ""
    return " ".join(str(value).strip().split())


def safe_json_dumps(value: Any) -> str:
    """
    Safely serialize any value to JSON string.
    """
    try:
        return json.dumps(value, default=str, ensure_ascii=False, sort_keys=True)
    except Exception:
        return json.dumps({"value": str(value)}, ensure_ascii=False, sort_keys=True)


def stable_hash(*parts: Any) -> str:
    """
    Create deterministic hash for dedupe/integrity.
    """
    raw = "::".join(normalize_text(part) for part in parts if part is not None)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def normalize_string_list(values: Optional[Sequence[Any]]) -> List[str]:
    """
    Normalize a sequence into a clean unique string list.
    """
    if not values:
        return []

    cleaned: List[str] = []
    seen = set()

    for value in values:
        item = normalize_text(value)
        key = item.lower()
        if item and key not in seen:
            cleaned.append(item)
            seen.add(key)

    return cleaned


def safe_metadata(metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Redact obvious secrets from metadata.
    """
    if not metadata:
        return {}

    blocked_terms = {
        "password",
        "secret",
        "api_key",
        "apikey",
        "token",
        "access_token",
        "refresh_token",
        "private_key",
        "authorization",
        "cookie",
        "session",
    }

    safe: Dict[str, Any] = {}

    for key, value in metadata.items():
        clean_key = normalize_text(key)
        lowered = clean_key.lower()

        if any(term in lowered for term in blocked_terms):
            safe[clean_key] = "[REDACTED]"
        else:
            safe[clean_key] = value

    return safe


class BusinessEntityType(str, enum.Enum):
    BUSINESS_PROFILE = "business_profile"
    CLIENT = "client"
    CONTACT = "contact"
    LEAD = "lead"
    PIPELINE = "pipeline"
    DEAL = "deal"
    CAMPAIGN = "campaign"
    INVOICE = "invoice"
    PAYMENT = "payment"
    ANALYTICS = "analytics"


class BusinessStatus(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"
    DELETED = "deleted"
    PENDING_REVIEW = "pending_review"
    REJECTED = "rejected"


class LeadStatus(str, enum.Enum):
    NEW = "new"
    CONTACTED = "contacted"
    QUALIFIED = "qualified"
    PROPOSAL_SENT = "proposal_sent"
    NEGOTIATION = "negotiation"
    WON = "won"
    LOST = "lost"
    ARCHIVED = "archived"


class DealStatus(str, enum.Enum):
    OPEN = "open"
    WON = "won"
    LOST = "lost"
    PAUSED = "paused"
    ARCHIVED = "archived"


class ContactType(str, enum.Enum):
    PRIMARY = "primary"
    BILLING = "billing"
    TECHNICAL = "technical"
    DECISION_MAKER = "decision_maker"
    INFLUENCER = "influencer"
    OTHER = "other"


class CampaignStatus(str, enum.Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    ARCHIVED = "archived"


class CampaignChannel(str, enum.Enum):
    GOOGLE_ADS = "google_ads"
    META_ADS = "meta_ads"
    TIKTOK_ADS = "tiktok_ads"
    LINKEDIN_ADS = "linkedin_ads"
    SEO = "seo"
    EMAIL = "email"
    SMS = "sms"
    SOCIAL = "social"
    WEBSITE = "website"
    OTHER = "other"


class InvoiceStatus(str, enum.Enum):
    DRAFT = "draft"
    SENT = "sent"
    PARTIALLY_PAID = "partially_paid"
    PAID = "paid"
    OVERDUE = "overdue"
    VOID = "void"
    CANCELLED = "cancelled"


class PaymentStatus(str, enum.Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    PAID = "paid"
    FAILED = "failed"
    REFUNDED = "refunded"
    CANCELLED = "cancelled"


class Priority(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class Sensitivity(str, enum.Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


class BusinessMixin:
    """
    Shared safe helpers for all business/CRM models.
    """

    def assert_same_tenant(self, *, user_id: str, workspace_id: str) -> None:
        """
        Enforce strict SaaS user/workspace isolation.
        """
        if getattr(self, "user_id", None) != normalize_text(user_id):
            raise PermissionError("Business access denied: user_id mismatch.")
        if getattr(self, "workspace_id", None) != normalize_text(workspace_id):
            raise PermissionError("Business access denied: workspace_id mismatch.")

    def can_be_accessed_by(
        self,
        *,
        user_id: str,
        workspace_id: str,
        role: Optional[str] = None,
        plan: Optional[str] = None,
    ) -> bool:
        """
        Lightweight local access check. Service/API layer can extend this.
        """
        if getattr(self, "user_id", None) != normalize_text(user_id):
            return False

        if getattr(self, "workspace_id", None) != normalize_text(workspace_id):
            return False

        if getattr(self, "status", None) == BusinessStatus.DELETED:
            return False

        normalized_role = normalize_text(role).lower()
        normalized_plan = normalize_text(plan).lower()

        sensitivity = getattr(self, "sensitivity", Sensitivity.INTERNAL)
        if sensitivity == Sensitivity.RESTRICTED and normalized_role not in {
            "owner",
            "admin",
            "security_admin",
        }:
            return False

        entity_type = getattr(self, "entity_type", None)
        if entity_type in {BusinessEntityType.ANALYTICS, BusinessEntityType.CAMPAIGN}:
            if normalized_plan in {"free", "starter_limited"}:
                return False

        return True

    def build_audit_payload(
        self,
        *,
        action: str,
        actor_user_id: str,
        reason: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build audit-friendly payload for future Audit Log / Agent Event models.
        """
        payload = {
            "event": "business.audit",
            "action": normalize_text(action),
            "actor_user_id": normalize_text(actor_user_id),
            "user_id": getattr(self, "user_id", None),
            "workspace_id": getattr(self, "workspace_id", None),
            "entity_type": getattr(getattr(self, "entity_type", None), "value", None),
            "entity_id": getattr(self, "id", None),
            "content_hash": self.content_hash(),
            "reason": normalize_text(reason) if reason else None,
            "timestamp": utc_now().isoformat(),
        }

        if extra:
            payload["extra"] = safe_metadata(extra)

        return payload

    def build_security_agent_payload(
        self,
        *,
        requested_action: str,
        actor_user_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build payload for future Security Agent approval.
        """
        return {
            "event": "security.review.business",
            "requested_action": normalize_text(requested_action),
            "actor_user_id": normalize_text(actor_user_id),
            "user_id": getattr(self, "user_id", None),
            "workspace_id": getattr(self, "workspace_id", None),
            "entity_type": getattr(getattr(self, "entity_type", None), "value", None),
            "entity_id": getattr(self, "id", None),
            "status": self.enum_value(getattr(self, "status", None)),
            "sensitivity": self.enum_value(getattr(self, "sensitivity", None)),
            "title": self.display_name(),
            "content_hash": self.content_hash(),
            "requires_security_review": self.requires_security_review(
                action=requested_action
            ),
            "reason": normalize_text(reason) if reason else None,
            "metadata": safe_metadata(getattr(self, "metadata_json", None)),
            "timestamp": utc_now().isoformat(),
        }

    def build_verification_payload(
        self,
        *,
        action: str,
        actor_user_id: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build payload for future Verification Agent confirmation.
        """
        payload = {
            "event": "verification.business",
            "action": normalize_text(action),
            "actor_user_id": normalize_text(actor_user_id),
            "user_id": getattr(self, "user_id", None),
            "workspace_id": getattr(self, "workspace_id", None),
            "entity_type": getattr(getattr(self, "entity_type", None), "value", None),
            "entity_id": getattr(self, "id", None),
            "title": self.display_name(),
            "status": self.enum_value(getattr(self, "status", None)),
            "content_hash": self.content_hash(),
            "timestamp": utc_now().isoformat(),
        }

        if extra:
            payload["extra"] = safe_metadata(extra)

        return payload

    def build_memory_agent_payload(self) -> Dict[str, Any]:
        """
        Build compact memory payload for future Memory Agent.
        """
        return {
            "source": "business_model",
            "entity_type": getattr(getattr(self, "entity_type", None), "value", None),
            "entity_id": getattr(self, "id", None),
            "user_id": getattr(self, "user_id", None),
            "workspace_id": getattr(self, "workspace_id", None),
            "title": self.display_name(),
            "summary": self.memory_summary(),
            "tags": getattr(self, "tags", None) or [],
            "metadata": safe_metadata(getattr(self, "metadata_json", None)),
            "content_hash": self.content_hash(),
            "created_at": self.iso_datetime(getattr(self, "created_at", None)),
            "updated_at": self.iso_datetime(getattr(self, "updated_at", None)),
        }

    def structured_response(
        self,
        *,
        message: str,
        action: str,
        success: bool = True,
    ) -> Dict[str, Any]:
        """
        Return safe structured response for APIs/services/agents.
        """
        return {
            "success": success,
            "message": normalize_text(message),
            "action": normalize_text(action),
            "data": {
                "id": getattr(self, "id", None),
                "user_id": getattr(self, "user_id", None),
                "workspace_id": getattr(self, "workspace_id", None),
                "entity_type": getattr(getattr(self, "entity_type", None), "value", None),
                "title": self.display_name(),
                "status": self.enum_value(getattr(self, "status", None)),
                "updated_at": self.iso_datetime(getattr(self, "updated_at", None)),
            },
            "error": None,
        }

    def mark_archived(
        self,
        *,
        actor_user_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Archive entity safely.
        """
        actor = normalize_text(actor_user_id)
        if not actor:
            raise ValueError("actor_user_id is required.")

        if hasattr(self, "status"):
            self.status = BusinessStatus.ARCHIVED

        if hasattr(self, "archived_at"):
            self.archived_at = utc_now()

        if hasattr(self, "archived_by"):
            self.archived_by = actor

        if hasattr(self, "updated_by"):
            self.updated_by = actor

        if hasattr(self, "updated_at"):
            self.updated_at = utc_now()

        if hasattr(self, "verification_status"):
            self.verification_status = "pending"

        if hasattr(self, "verification_payload_json"):
            self.verification_payload_json = self.build_verification_payload(
                action="business.archived",
                actor_user_id=actor,
                extra={"reason": reason},
            )

        return self.structured_response(
            message="Business entity archived successfully.",
            action="business.archived",
        )

    def mark_deleted(
        self,
        *,
        actor_user_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Soft-delete entity safely.
        """
        actor = normalize_text(actor_user_id)
        if not actor:
            raise ValueError("actor_user_id is required.")

        if hasattr(self, "status"):
            self.status = BusinessStatus.DELETED

        if hasattr(self, "deleted_at"):
            self.deleted_at = utc_now()

        if hasattr(self, "deleted_by"):
            self.deleted_by = actor

        if hasattr(self, "updated_by"):
            self.updated_by = actor

        if hasattr(self, "updated_at"):
            self.updated_at = utc_now()

        if hasattr(self, "verification_status"):
            self.verification_status = "pending"

        if hasattr(self, "verification_payload_json"):
            self.verification_payload_json = self.build_verification_payload(
                action="business.deleted",
                actor_user_id=actor,
                extra={"reason": reason},
            )

        return self.structured_response(
            message="Business entity deleted safely.",
            action="business.deleted",
        )

    def requires_security_review(self, *, action: str) -> bool:
        """
        Decide whether action should be reviewed by Security Agent.
        """
        action_key = normalize_text(action).lower()

        high_risk_actions = {
            "delete",
            "remove",
            "archive",
            "refund",
            "payment_refund",
            "invoice_void",
            "invoice_delete",
            "client_delete",
            "deal_delete",
            "campaign_delete",
            "business_delete",
            "settings_update",
            "export",
            "bulk_export",
        }

        sensitivity = getattr(self, "sensitivity", Sensitivity.INTERNAL)

        if sensitivity in {
            Sensitivity.CONFIDENTIAL,
            Sensitivity.SENSITIVE,
            Sensitivity.RESTRICTED,
        }:
            return True

        return action_key in high_risk_actions

    def display_name(self) -> str:
        """
        Human-readable entity name.
        """
        for field in (
            "business_name",
            "company",
            "full_name",
            "contact_name",
            "title",
            "name",
            "campaign_name",
            "invoice_number",
            "metric_name",
        ):
            value = normalize_text(getattr(self, field, None))
            if value:
                return value

        return f"{self.__class__.__name__}:{getattr(self, 'id', 'unknown')}"

    def memory_summary(self) -> str:
        """
        Safe summary for Memory Agent.
        """
        fields = {
            "entity": self.display_name(),
            "type": getattr(getattr(self, "entity_type", None), "value", None),
            "status": self.enum_value(getattr(self, "status", None)),
            "description": normalize_text(getattr(self, "description", None)),
            "notes": normalize_text(getattr(self, "notes", None)),
            "industry": normalize_text(getattr(self, "industry", None)),
            "source": normalize_text(getattr(self, "source", None)),
        }
        return safe_json_dumps({k: v for k, v in fields.items() if v})

    def content_hash(self) -> str:
        """
        Stable hash for integrity and dedupe.
        """
        return stable_hash(
            getattr(self, "workspace_id", None),
            getattr(self, "user_id", None),
            getattr(getattr(self, "entity_type", None), "value", None),
            getattr(self, "id", None),
            self.display_name(),
            self.memory_summary(),
        )

    @staticmethod
    def enum_value(value: Any) -> Any:
        """
        Return enum value safely.
        """
        if hasattr(value, "value"):
            return value.value
        return value

    @staticmethod
    def iso_datetime(value: Optional[datetime]) -> Optional[str]:
        """
        Convert datetime to ISO string safely.
        """
        if value is None:
            return None
        try:
            return value.isoformat()
        except Exception:
            return str(value)


class BusinessProfile(Base, BusinessMixin):
    """
    Primary company profile for a workspace.
    """

    __tablename__ = "business_profiles"

    entity_type = BusinessEntityType.BUSINESS_PROFILE

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    business_name: Mapped[str] = mapped_column(String(255), nullable=False)
    legal_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    phone: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    website: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    industry: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)

    timezone_name: Mapped[str] = mapped_column(String(100), nullable=False, default="UTC")
    currency: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default=lambda: os.getenv("WILLIAM_DEFAULT_CURRENCY", "USD"),
    )

    country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    logo_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    status: Mapped[BusinessStatus] = mapped_column(
        Enum(BusinessStatus, name="business_profile_status_enum"),
        nullable=False,
        default=BusinessStatus.ACTIVE,
        index=True,
    )
    sensitivity: Mapped[Sensitivity] = mapped_column(
        Enum(Sensitivity, name="business_profile_sensitivity_enum"),
        nullable=False,
        default=Sensitivity.INTERNAL,
        index=True,
    )

    settings_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    archived_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    deleted_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    verification_status: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, default="pending")
    verification_payload_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        UniqueConstraint("workspace_id", "business_name", name="uq_business_profile_workspace_name"),
        Index("ix_business_profiles_user_workspace_status", "user_id", "workspace_id", "status"),
    )

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        business_name: str,
        created_by: Optional[str] = None,
        **kwargs: Any,
    ) -> "BusinessProfile":
        safe_user_id = normalize_text(user_id)
        safe_workspace_id = normalize_text(workspace_id)
        safe_name = normalize_text(business_name)

        if not safe_user_id:
            raise ValueError("BusinessProfile requires user_id.")
        if not safe_workspace_id:
            raise ValueError("BusinessProfile requires workspace_id.")
        if not safe_name:
            raise ValueError("BusinessProfile requires business_name.")

        actor = normalize_text(created_by) or safe_user_id

        item = cls(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            business_name=safe_name,
            legal_name=normalize_text(kwargs.get("legal_name")) or None,
            email=normalize_text(kwargs.get("email")) or None,
            phone=normalize_text(kwargs.get("phone")) or None,
            website=normalize_text(kwargs.get("website")) or None,
            industry=normalize_text(kwargs.get("industry")) or None,
            timezone_name=normalize_text(kwargs.get("timezone_name")) or "UTC",
            currency=normalize_text(kwargs.get("currency")) or os.getenv("WILLIAM_DEFAULT_CURRENCY", "USD"),
            country=normalize_text(kwargs.get("country")) or None,
            city=normalize_text(kwargs.get("city")) or None,
            address=normalize_text(kwargs.get("address")) or None,
            logo_url=normalize_text(kwargs.get("logo_url")) or None,
            settings_json=safe_metadata(kwargs.get("settings_json")),
            metadata_json=safe_metadata(kwargs.get("metadata_json")),
            created_by=actor,
            updated_by=actor,
        )

        item.verification_payload_json = item.build_verification_payload(
            action="business_profile.created",
            actor_user_id=actor,
        )

        return item

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "business_name": self.business_name,
            "legal_name": self.legal_name,
            "email": self.email,
            "phone": self.phone,
            "website": self.website,
            "industry": self.industry,
            "timezone_name": self.timezone_name,
            "currency": self.currency,
            "country": self.country,
            "city": self.city,
            "address": self.address,
            "logo_url": self.logo_url,
            "status": self.status.value,
            "sensitivity": self.sensitivity.value,
            "settings_json": safe_metadata(self.settings_json),
            "metadata_json": safe_metadata(self.metadata_json),
            "verification_status": self.verification_status,
            "created_at": self.iso_datetime(self.created_at),
            "updated_at": self.iso_datetime(self.updated_at),
        }


class Client(Base, BusinessMixin):
    """
    CRM client/account record.
    """

    __tablename__ = "clients"

    entity_type = BusinessEntityType.CLIENT

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    company: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    contact_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    phone: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    website: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    industry: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    address: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    status: Mapped[BusinessStatus] = mapped_column(
        Enum(BusinessStatus, name="client_status_enum"),
        nullable=False,
        default=BusinessStatus.ACTIVE,
        index=True,
    )
    sensitivity: Mapped[Sensitivity] = mapped_column(
        Enum(Sensitivity, name="client_sensitivity_enum"),
        nullable=False,
        default=Sensitivity.CONFIDENTIAL,
        index=True,
    )

    lifetime_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    currency: Mapped[str] = mapped_column(String(20), nullable=False, default="USD")

    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    archived_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    deleted_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    verification_status: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, default="pending")
    verification_payload_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)
    archived_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_clients_workspace_user_status", "workspace_id", "user_id", "status"),
        Index("ix_clients_workspace_company", "workspace_id", "company"),
    )

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        company: str,
        created_by: Optional[str] = None,
        **kwargs: Any,
    ) -> "Client":
        safe_user_id = normalize_text(user_id)
        safe_workspace_id = normalize_text(workspace_id)
        safe_company = normalize_text(company)

        if not safe_user_id:
            raise ValueError("Client requires user_id.")
        if not safe_workspace_id:
            raise ValueError("Client requires workspace_id.")
        if not safe_company:
            raise ValueError("Client requires company.")

        actor = normalize_text(created_by) or safe_user_id

        item = cls(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            company=safe_company,
            contact_name=normalize_text(kwargs.get("contact_name")) or None,
            email=normalize_text(kwargs.get("email")) or None,
            phone=normalize_text(kwargs.get("phone")) or None,
            website=normalize_text(kwargs.get("website")) or None,
            industry=normalize_text(kwargs.get("industry")) or None,
            country=normalize_text(kwargs.get("country")) or None,
            city=normalize_text(kwargs.get("city")) or None,
            address=normalize_text(kwargs.get("address")) or None,
            lifetime_value=float(kwargs.get("lifetime_value") or 0.0),
            currency=normalize_text(kwargs.get("currency")) or "USD",
            notes=normalize_text(kwargs.get("notes")) or None,
            tags=normalize_string_list(kwargs.get("tags")),
            metadata_json=safe_metadata(kwargs.get("metadata_json")),
            created_by=actor,
            updated_by=actor,
        )

        item.verification_payload_json = item.build_verification_payload(
            action="client.created",
            actor_user_id=actor,
        )

        return item

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "company": self.company,
            "contact_name": self.contact_name,
            "email": self.email,
            "phone": self.phone,
            "website": self.website,
            "industry": self.industry,
            "country": self.country,
            "city": self.city,
            "address": self.address,
            "status": self.status.value,
            "sensitivity": self.sensitivity.value,
            "lifetime_value": self.lifetime_value,
            "currency": self.currency,
            "notes": self.notes,
            "tags": self.tags or [],
            "metadata_json": safe_metadata(self.metadata_json),
            "verification_status": self.verification_status,
            "created_at": self.iso_datetime(self.created_at),
            "updated_at": self.iso_datetime(self.updated_at),
        }


class CRMContact(Base, BusinessMixin):
    """
    CRM contact linked to a client, lead, deal, or campaign.
    """

    __tablename__ = "crm_contacts"

    entity_type = BusinessEntityType.CONTACT

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    lead_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    deal_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    full_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    job_title: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    company: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)

    email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    phone: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    linkedin_url: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    contact_type: Mapped[ContactType] = mapped_column(
        Enum(ContactType, name="crm_contact_type_enum"),
        nullable=False,
        default=ContactType.OTHER,
        index=True,
    )
    status: Mapped[BusinessStatus] = mapped_column(
        Enum(BusinessStatus, name="crm_contact_status_enum"),
        nullable=False,
        default=BusinessStatus.ACTIVE,
        index=True,
    )
    sensitivity: Mapped[Sensitivity] = mapped_column(
        Enum(Sensitivity, name="crm_contact_sensitivity_enum"),
        nullable=False,
        default=Sensitivity.CONFIDENTIAL,
        index=True,
    )

    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    verification_status: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, default="pending")
    verification_payload_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    __table_args__ = (
        Index("ix_crm_contacts_workspace_user_status", "workspace_id", "user_id", "status"),
        Index("ix_crm_contacts_client_contact_type", "client_id", "contact_type"),
    )

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        full_name: str,
        created_by: Optional[str] = None,
        **kwargs: Any,
    ) -> "CRMContact":
        safe_user_id = normalize_text(user_id)
        safe_workspace_id = normalize_text(workspace_id)
        safe_name = normalize_text(full_name)

        if not safe_user_id:
            raise ValueError("CRMContact requires user_id.")
        if not safe_workspace_id:
            raise ValueError("CRMContact requires workspace_id.")
        if not safe_name:
            raise ValueError("CRMContact requires full_name.")

        actor = normalize_text(created_by) or safe_user_id

        item = cls(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            client_id=normalize_text(kwargs.get("client_id")) or None,
            lead_id=normalize_text(kwargs.get("lead_id")) or None,
            deal_id=normalize_text(kwargs.get("deal_id")) or None,
            full_name=safe_name,
            job_title=normalize_text(kwargs.get("job_title")) or None,
            company=normalize_text(kwargs.get("company")) or None,
            email=normalize_text(kwargs.get("email")) or None,
            phone=normalize_text(kwargs.get("phone")) or None,
            linkedin_url=normalize_text(kwargs.get("linkedin_url")) or None,
            contact_type=kwargs.get("contact_type") or ContactType.OTHER,
            notes=normalize_text(kwargs.get("notes")) or None,
            tags=normalize_string_list(kwargs.get("tags")),
            metadata_json=safe_metadata(kwargs.get("metadata_json")),
            created_by=actor,
            updated_by=actor,
        )

        item.verification_payload_json = item.build_verification_payload(
            action="crm_contact.created",
            actor_user_id=actor,
        )

        return item

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "client_id": self.client_id,
            "lead_id": self.lead_id,
            "deal_id": self.deal_id,
            "full_name": self.full_name,
            "job_title": self.job_title,
            "company": self.company,
            "email": self.email,
            "phone": self.phone,
            "linkedin_url": self.linkedin_url,
            "contact_type": self.contact_type.value,
            "status": self.status.value,
            "sensitivity": self.sensitivity.value,
            "notes": self.notes,
            "tags": self.tags or [],
            "metadata_json": safe_metadata(self.metadata_json),
            "verification_status": self.verification_status,
            "created_at": self.iso_datetime(self.created_at),
            "updated_at": self.iso_datetime(self.updated_at),
        }


class Lead(Base, BusinessMixin):
    """
    Sales lead tracked through CRM pipeline.
    """

    __tablename__ = "leads"

    entity_type = BusinessEntityType.LEAD

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    campaign_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    source: Mapped[str] = mapped_column(String(120), nullable=False, default="manual", index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    status: Mapped[LeadStatus] = mapped_column(
        Enum(LeadStatus, name="lead_status_enum"),
        nullable=False,
        default=LeadStatus.NEW,
        index=True,
    )
    priority: Mapped[Priority] = mapped_column(
        Enum(Priority, name="lead_priority_enum"),
        nullable=False,
        default=Priority.MEDIUM,
        index=True,
    )
    sensitivity: Mapped[Sensitivity] = mapped_column(
        Enum(Sensitivity, name="lead_sensitivity_enum"),
        nullable=False,
        default=Sensitivity.CONFIDENTIAL,
        index=True,
    )

    estimated_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    probability: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    currency: Mapped[str] = mapped_column(String(20), nullable=False, default="USD")

    assigned_agent: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    assigned_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    expected_close_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_contacted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    verification_status: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, default="pending")
    verification_payload_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    __table_args__ = (
        Index("ix_leads_workspace_user_status", "workspace_id", "user_id", "status"),
        Index("ix_leads_workspace_source", "workspace_id", "source"),
        Index("ix_leads_campaign_status", "campaign_id", "status"),
    )

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        title: str,
        created_by: Optional[str] = None,
        **kwargs: Any,
    ) -> "Lead":
        safe_user_id = normalize_text(user_id)
        safe_workspace_id = normalize_text(workspace_id)
        safe_title = normalize_text(title)

        if not safe_user_id:
            raise ValueError("Lead requires user_id.")
        if not safe_workspace_id:
            raise ValueError("Lead requires workspace_id.")
        if not safe_title:
            raise ValueError("Lead requires title.")

        actor = normalize_text(created_by) or safe_user_id
        probability = int(kwargs.get("probability") or 0)
        probability = max(0, min(100, probability))

        item = cls(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            client_id=normalize_text(kwargs.get("client_id")) or None,
            campaign_id=normalize_text(kwargs.get("campaign_id")) or None,
            source=normalize_text(kwargs.get("source")) or "manual",
            title=safe_title,
            description=normalize_text(kwargs.get("description")) or None,
            status=kwargs.get("status") or LeadStatus.NEW,
            priority=kwargs.get("priority") or Priority.MEDIUM,
            estimated_value=float(kwargs.get("estimated_value") or 0.0),
            probability=probability,
            currency=normalize_text(kwargs.get("currency")) or "USD",
            assigned_agent=normalize_text(kwargs.get("assigned_agent")) or None,
            assigned_user_id=normalize_text(kwargs.get("assigned_user_id")) or None,
            expected_close_date=kwargs.get("expected_close_date"),
            last_contacted_at=kwargs.get("last_contacted_at"),
            notes=normalize_text(kwargs.get("notes")) or None,
            tags=normalize_string_list(kwargs.get("tags")),
            metadata_json=safe_metadata(kwargs.get("metadata_json")),
            created_by=actor,
            updated_by=actor,
        )

        item.verification_payload_json = item.build_verification_payload(
            action="lead.created",
            actor_user_id=actor,
        )

        return item

    def update_status(
        self,
        *,
        status: LeadStatus,
        actor_user_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        actor = normalize_text(actor_user_id)
        if not actor:
            raise ValueError("actor_user_id is required.")

        old_status = self.status.value
        self.status = status
        self.updated_by = actor
        self.updated_at = utc_now()
        self.verification_status = "pending"
        self.verification_payload_json = self.build_verification_payload(
            action="lead.status_updated",
            actor_user_id=actor,
            extra={"old_status": old_status, "new_status": status.value, "reason": reason},
        )

        return self.structured_response(
            message="Lead status updated successfully.",
            action="lead.status_updated",
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "client_id": self.client_id,
            "campaign_id": self.campaign_id,
            "source": self.source,
            "title": self.title,
            "description": self.description,
            "status": self.status.value,
            "priority": self.priority.value,
            "sensitivity": self.sensitivity.value,
            "estimated_value": self.estimated_value,
            "probability": self.probability,
            "currency": self.currency,
            "assigned_agent": self.assigned_agent,
            "assigned_user_id": self.assigned_user_id,
            "expected_close_date": self.iso_datetime(self.expected_close_date),
            "last_contacted_at": self.iso_datetime(self.last_contacted_at),
            "notes": self.notes,
            "tags": self.tags or [],
            "metadata_json": safe_metadata(self.metadata_json),
            "verification_status": self.verification_status,
            "created_at": self.iso_datetime(self.created_at),
            "updated_at": self.iso_datetime(self.updated_at),
        }


class Pipeline(Base, BusinessMixin):
    """
    Sales pipeline stage model.
    """

    __tablename__ = "pipelines"

    entity_type = BusinessEntityType.PIPELINE

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    stage_order: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    probability: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    color: Mapped[str] = mapped_column(String(30), nullable=False, default="#2563eb")
    is_closed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_won_stage: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    status: Mapped[BusinessStatus] = mapped_column(
        Enum(BusinessStatus, name="pipeline_status_enum"),
        nullable=False,
        default=BusinessStatus.ACTIVE,
        index=True,
    )

    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    __table_args__ = (
        UniqueConstraint("workspace_id", "name", name="uq_pipeline_workspace_name"),
        Index("ix_pipelines_workspace_order", "workspace_id", "stage_order"),
    )

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        name: str,
        created_by: Optional[str] = None,
        **kwargs: Any,
    ) -> "Pipeline":
        safe_user_id = normalize_text(user_id)
        safe_workspace_id = normalize_text(workspace_id)
        safe_name = normalize_text(name)

        if not safe_user_id:
            raise ValueError("Pipeline requires user_id.")
        if not safe_workspace_id:
            raise ValueError("Pipeline requires workspace_id.")
        if not safe_name:
            raise ValueError("Pipeline requires name.")

        actor = normalize_text(created_by) or safe_user_id
        probability = int(kwargs.get("probability") or 0)
        probability = max(0, min(100, probability))

        return cls(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            name=safe_name,
            stage_order=int(kwargs.get("stage_order") or 1),
            probability=probability,
            color=normalize_text(kwargs.get("color")) or "#2563eb",
            is_closed=bool(kwargs.get("is_closed", False)),
            is_won_stage=bool(kwargs.get("is_won_stage", False)),
            metadata_json=safe_metadata(kwargs.get("metadata_json")),
            created_by=actor,
            updated_by=actor,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "name": self.name,
            "stage_order": self.stage_order,
            "probability": self.probability,
            "color": self.color,
            "is_closed": self.is_closed,
            "is_won_stage": self.is_won_stage,
            "status": self.status.value,
            "metadata_json": safe_metadata(self.metadata_json),
            "created_at": self.iso_datetime(self.created_at),
            "updated_at": self.iso_datetime(self.updated_at),
        }


class Deal(Base, BusinessMixin):
    """
    CRM deal/opportunity.
    """

    __tablename__ = "deals"

    entity_type = BusinessEntityType.DEAL

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    lead_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    pipeline_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    campaign_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    title: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    currency: Mapped[str] = mapped_column(String(20), nullable=False, default="USD")
    probability: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    status: Mapped[DealStatus] = mapped_column(
        Enum(DealStatus, name="deal_status_enum"),
        nullable=False,
        default=DealStatus.OPEN,
        index=True,
    )
    priority: Mapped[Priority] = mapped_column(
        Enum(Priority, name="deal_priority_enum"),
        nullable=False,
        default=Priority.MEDIUM,
        index=True,
    )
    sensitivity: Mapped[Sensitivity] = mapped_column(
        Enum(Sensitivity, name="deal_sensitivity_enum"),
        nullable=False,
        default=Sensitivity.CONFIDENTIAL,
        index=True,
    )

    expected_close_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    assigned_agent: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    assigned_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tags: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    verification_status: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, default="pending")
    verification_payload_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    __table_args__ = (
        Index("ix_deals_workspace_user_status", "workspace_id", "user_id", "status"),
        Index("ix_deals_client_status", "client_id", "status"),
        Index("ix_deals_campaign_status", "campaign_id", "status"),
    )

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        title: str,
        created_by: Optional[str] = None,
        **kwargs: Any,
    ) -> "Deal":
        safe_user_id = normalize_text(user_id)
        safe_workspace_id = normalize_text(workspace_id)
        safe_title = normalize_text(title)

        if not safe_user_id:
            raise ValueError("Deal requires user_id.")
        if not safe_workspace_id:
            raise ValueError("Deal requires workspace_id.")
        if not safe_title:
            raise ValueError("Deal requires title.")

        actor = normalize_text(created_by) or safe_user_id
        probability = int(kwargs.get("probability") or 0)
        probability = max(0, min(100, probability))

        item = cls(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            lead_id=normalize_text(kwargs.get("lead_id")) or None,
            client_id=normalize_text(kwargs.get("client_id")) or None,
            pipeline_id=normalize_text(kwargs.get("pipeline_id")) or None,
            campaign_id=normalize_text(kwargs.get("campaign_id")) or None,
            title=safe_title,
            description=normalize_text(kwargs.get("description")) or None,
            value=float(kwargs.get("value") or 0.0),
            currency=normalize_text(kwargs.get("currency")) or "USD",
            probability=probability,
            status=kwargs.get("status") or DealStatus.OPEN,
            priority=kwargs.get("priority") or Priority.MEDIUM,
            expected_close_date=kwargs.get("expected_close_date"),
            assigned_agent=normalize_text(kwargs.get("assigned_agent")) or None,
            assigned_user_id=normalize_text(kwargs.get("assigned_user_id")) or None,
            notes=normalize_text(kwargs.get("notes")) or None,
            tags=normalize_string_list(kwargs.get("tags")),
            metadata_json=safe_metadata(kwargs.get("metadata_json")),
            created_by=actor,
            updated_by=actor,
        )

        item.verification_payload_json = item.build_verification_payload(
            action="deal.created",
            actor_user_id=actor,
        )

        return item

    def close_won(self, *, actor_user_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
        actor = normalize_text(actor_user_id)
        if not actor:
            raise ValueError("actor_user_id is required.")

        self.status = DealStatus.WON
        self.probability = 100
        self.closed_at = utc_now()
        self.updated_by = actor
        self.updated_at = utc_now()
        self.verification_status = "pending"
        self.verification_payload_json = self.build_verification_payload(
            action="deal.closed_won",
            actor_user_id=actor,
            extra={"reason": reason},
        )

        return self.structured_response(
            message="Deal marked as won.",
            action="deal.closed_won",
        )

    def close_lost(self, *, actor_user_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
        actor = normalize_text(actor_user_id)
        if not actor:
            raise ValueError("actor_user_id is required.")

        self.status = DealStatus.LOST
        self.closed_at = utc_now()
        self.updated_by = actor
        self.updated_at = utc_now()
        self.verification_status = "pending"
        self.verification_payload_json = self.build_verification_payload(
            action="deal.closed_lost",
            actor_user_id=actor,
            extra={"reason": reason},
        )

        return self.structured_response(
            message="Deal marked as lost.",
            action="deal.closed_lost",
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "lead_id": self.lead_id,
            "client_id": self.client_id,
            "pipeline_id": self.pipeline_id,
            "campaign_id": self.campaign_id,
            "title": self.title,
            "description": self.description,
            "value": self.value,
            "currency": self.currency,
            "probability": self.probability,
            "status": self.status.value,
            "priority": self.priority.value,
            "sensitivity": self.sensitivity.value,
            "expected_close_date": self.iso_datetime(self.expected_close_date),
            "closed_at": self.iso_datetime(self.closed_at),
            "assigned_agent": self.assigned_agent,
            "assigned_user_id": self.assigned_user_id,
            "notes": self.notes,
            "tags": self.tags or [],
            "metadata_json": safe_metadata(self.metadata_json),
            "verification_status": self.verification_status,
            "created_at": self.iso_datetime(self.created_at),
            "updated_at": self.iso_datetime(self.updated_at),
        }


class Campaign(Base, BusinessMixin):
    """
    Marketing campaign record for SEO, PPC, SMM, email, and other business growth work.
    """

    __tablename__ = "campaigns"

    entity_type = BusinessEntityType.CAMPAIGN

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    campaign_name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    channel: Mapped[CampaignChannel] = mapped_column(
        Enum(CampaignChannel, name="campaign_channel_enum"),
        nullable=False,
        default=CampaignChannel.OTHER,
        index=True,
    )

    status: Mapped[CampaignStatus] = mapped_column(
        Enum(CampaignStatus, name="campaign_status_enum"),
        nullable=False,
        default=CampaignStatus.DRAFT,
        index=True,
    )
    sensitivity: Mapped[Sensitivity] = mapped_column(
        Enum(Sensitivity, name="campaign_sensitivity_enum"),
        nullable=False,
        default=Sensitivity.CONFIDENTIAL,
        index=True,
    )

    objective: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    budget: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    spend: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    revenue: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    currency: Mapped[str] = mapped_column(String(20), nullable=False, default="USD")

    impressions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    clicks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    leads: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    conversions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    start_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    end_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    assigned_agent: Mapped[Optional[str]] = mapped_column(String(120), nullable=True, index=True)
    assigned_user_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    tags: Mapped[List[str]] = mapped_column(JSON, nullable=False, default=list)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    verification_status: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, default="pending")
    verification_payload_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    __table_args__ = (
        Index("ix_campaigns_workspace_user_status", "workspace_id", "user_id", "status"),
        Index("ix_campaigns_client_channel", "client_id", "channel"),
    )

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        campaign_name: str,
        created_by: Optional[str] = None,
        **kwargs: Any,
    ) -> "Campaign":
        safe_user_id = normalize_text(user_id)
        safe_workspace_id = normalize_text(workspace_id)
        safe_name = normalize_text(campaign_name)

        if not safe_user_id:
            raise ValueError("Campaign requires user_id.")
        if not safe_workspace_id:
            raise ValueError("Campaign requires workspace_id.")
        if not safe_name:
            raise ValueError("Campaign requires campaign_name.")

        actor = normalize_text(created_by) or safe_user_id

        item = cls(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            client_id=normalize_text(kwargs.get("client_id")) or None,
            campaign_name=safe_name,
            channel=kwargs.get("channel") or CampaignChannel.OTHER,
            status=kwargs.get("status") or CampaignStatus.DRAFT,
            objective=normalize_text(kwargs.get("objective")) or None,
            description=normalize_text(kwargs.get("description")) or None,
            budget=float(kwargs.get("budget") or 0.0),
            spend=float(kwargs.get("spend") or 0.0),
            revenue=float(kwargs.get("revenue") or 0.0),
            currency=normalize_text(kwargs.get("currency")) or "USD",
            impressions=int(kwargs.get("impressions") or 0),
            clicks=int(kwargs.get("clicks") or 0),
            leads=int(kwargs.get("leads") or 0),
            conversions=int(kwargs.get("conversions") or 0),
            start_date=kwargs.get("start_date"),
            end_date=kwargs.get("end_date"),
            assigned_agent=normalize_text(kwargs.get("assigned_agent")) or None,
            assigned_user_id=normalize_text(kwargs.get("assigned_user_id")) or None,
            tags=normalize_string_list(kwargs.get("tags")),
            metadata_json=safe_metadata(kwargs.get("metadata_json")),
            created_by=actor,
            updated_by=actor,
        )

        item.verification_payload_json = item.build_verification_payload(
            action="campaign.created",
            actor_user_id=actor,
        )

        return item

    @property
    def ctr(self) -> float:
        if self.impressions <= 0:
            return 0.0
        return round((self.clicks / self.impressions) * 100, 4)

    @property
    def conversion_rate(self) -> float:
        if self.clicks <= 0:
            return 0.0
        return round((self.conversions / self.clicks) * 100, 4)

    @property
    def roi(self) -> float:
        if self.spend <= 0:
            return 0.0
        return round(((self.revenue - self.spend) / self.spend) * 100, 4)

    def update_metrics(
        self,
        *,
        actor_user_id: str,
        impressions: Optional[int] = None,
        clicks: Optional[int] = None,
        leads: Optional[int] = None,
        conversions: Optional[int] = None,
        spend: Optional[float] = None,
        revenue: Optional[float] = None,
    ) -> Dict[str, Any]:
        actor = normalize_text(actor_user_id)
        if not actor:
            raise ValueError("actor_user_id is required.")

        if impressions is not None:
            self.impressions = max(0, int(impressions))
        if clicks is not None:
            self.clicks = max(0, int(clicks))
        if leads is not None:
            self.leads = max(0, int(leads))
        if conversions is not None:
            self.conversions = max(0, int(conversions))
        if spend is not None:
            self.spend = max(0.0, float(spend))
        if revenue is not None:
            self.revenue = max(0.0, float(revenue))

        self.updated_by = actor
        self.updated_at = utc_now()
        self.verification_status = "pending"
        self.verification_payload_json = self.build_verification_payload(
            action="campaign.metrics_updated",
            actor_user_id=actor,
            extra={
                "impressions": self.impressions,
                "clicks": self.clicks,
                "leads": self.leads,
                "conversions": self.conversions,
                "spend": self.spend,
                "revenue": self.revenue,
                "ctr": self.ctr,
                "conversion_rate": self.conversion_rate,
                "roi": self.roi,
            },
        )

        return self.structured_response(
            message="Campaign metrics updated successfully.",
            action="campaign.metrics_updated",
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "client_id": self.client_id,
            "campaign_name": self.campaign_name,
            "channel": self.channel.value,
            "status": self.status.value,
            "sensitivity": self.sensitivity.value,
            "objective": self.objective,
            "description": self.description,
            "budget": self.budget,
            "spend": self.spend,
            "revenue": self.revenue,
            "currency": self.currency,
            "impressions": self.impressions,
            "clicks": self.clicks,
            "leads": self.leads,
            "conversions": self.conversions,
            "ctr": self.ctr,
            "conversion_rate": self.conversion_rate,
            "roi": self.roi,
            "start_date": self.iso_datetime(self.start_date),
            "end_date": self.iso_datetime(self.end_date),
            "assigned_agent": self.assigned_agent,
            "assigned_user_id": self.assigned_user_id,
            "tags": self.tags or [],
            "metadata_json": safe_metadata(self.metadata_json),
            "verification_status": self.verification_status,
            "created_at": self.iso_datetime(self.created_at),
            "updated_at": self.iso_datetime(self.updated_at),
        }


class Invoice(Base, BusinessMixin):
    """
    Customer invoice.
    """

    __tablename__ = "invoices"

    entity_type = BusinessEntityType.INVOICE

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    deal_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    invoice_number: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    title: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    subtotal: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    tax: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    discount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    total: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    currency: Mapped[str] = mapped_column(String(20), nullable=False, default="USD")

    status: Mapped[InvoiceStatus] = mapped_column(
        Enum(InvoiceStatus, name="invoice_status_enum"),
        nullable=False,
        default=InvoiceStatus.DRAFT,
        index=True,
    )
    sensitivity: Mapped[Sensitivity] = mapped_column(
        Enum(Sensitivity, name="invoice_sensitivity_enum"),
        nullable=False,
        default=Sensitivity.CONFIDENTIAL,
        index=True,
    )

    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    paid_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    line_items_json: Mapped[List[Dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    verification_status: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, default="pending")
    verification_payload_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    __table_args__ = (
        UniqueConstraint("workspace_id", "invoice_number", name="uq_invoice_workspace_number"),
        Index("ix_invoices_workspace_user_status", "workspace_id", "user_id", "status"),
        Index("ix_invoices_client_status", "client_id", "status"),
    )

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        invoice_number: str,
        created_by: Optional[str] = None,
        **kwargs: Any,
    ) -> "Invoice":
        safe_user_id = normalize_text(user_id)
        safe_workspace_id = normalize_text(workspace_id)
        safe_number = normalize_text(invoice_number)

        if not safe_user_id:
            raise ValueError("Invoice requires user_id.")
        if not safe_workspace_id:
            raise ValueError("Invoice requires workspace_id.")
        if not safe_number:
            raise ValueError("Invoice requires invoice_number.")

        actor = normalize_text(created_by) or safe_user_id

        subtotal = float(kwargs.get("subtotal") or 0.0)
        tax = float(kwargs.get("tax") or 0.0)
        discount = float(kwargs.get("discount") or 0.0)
        total = kwargs.get("total")
        calculated_total = float(total) if total is not None else max(0.0, subtotal + tax - discount)

        item = cls(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            client_id=normalize_text(kwargs.get("client_id")) or None,
            deal_id=normalize_text(kwargs.get("deal_id")) or None,
            invoice_number=safe_number,
            title=normalize_text(kwargs.get("title")) or None,
            subtotal=max(0.0, subtotal),
            tax=max(0.0, tax),
            discount=max(0.0, discount),
            total=calculated_total,
            currency=normalize_text(kwargs.get("currency")) or "USD",
            status=kwargs.get("status") or InvoiceStatus.DRAFT,
            due_date=kwargs.get("due_date"),
            notes=normalize_text(kwargs.get("notes")) or None,
            line_items_json=kwargs.get("line_items_json") or [],
            metadata_json=safe_metadata(kwargs.get("metadata_json")),
            created_by=actor,
            updated_by=actor,
        )

        item.verification_payload_json = item.build_verification_payload(
            action="invoice.created",
            actor_user_id=actor,
        )

        return item

    def mark_sent(self, *, actor_user_id: str) -> Dict[str, Any]:
        actor = normalize_text(actor_user_id)
        if not actor:
            raise ValueError("actor_user_id is required.")

        self.status = InvoiceStatus.SENT
        self.sent_at = utc_now()
        self.updated_by = actor
        self.updated_at = utc_now()
        self.verification_payload_json = self.build_verification_payload(
            action="invoice.sent",
            actor_user_id=actor,
        )

        return self.structured_response(
            message="Invoice marked as sent.",
            action="invoice.sent",
        )

    def mark_paid(self, *, actor_user_id: str) -> Dict[str, Any]:
        actor = normalize_text(actor_user_id)
        if not actor:
            raise ValueError("actor_user_id is required.")

        self.status = InvoiceStatus.PAID
        self.paid_at = utc_now()
        self.updated_by = actor
        self.updated_at = utc_now()
        self.verification_payload_json = self.build_verification_payload(
            action="invoice.paid",
            actor_user_id=actor,
        )

        return self.structured_response(
            message="Invoice marked as paid.",
            action="invoice.paid",
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "client_id": self.client_id,
            "deal_id": self.deal_id,
            "invoice_number": self.invoice_number,
            "title": self.title,
            "subtotal": self.subtotal,
            "tax": self.tax,
            "discount": self.discount,
            "total": self.total,
            "currency": self.currency,
            "status": self.status.value,
            "sensitivity": self.sensitivity.value,
            "due_date": self.iso_datetime(self.due_date),
            "sent_at": self.iso_datetime(self.sent_at),
            "paid_at": self.iso_datetime(self.paid_at),
            "notes": self.notes,
            "line_items_json": self.line_items_json or [],
            "metadata_json": safe_metadata(self.metadata_json),
            "verification_status": self.verification_status,
            "created_at": self.iso_datetime(self.created_at),
            "updated_at": self.iso_datetime(self.updated_at),
        }


class Payment(Base, BusinessMixin):
    """
    Invoice payment record.
    """

    __tablename__ = "payments"

    entity_type = BusinessEntityType.PAYMENT

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    invoice_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    amount: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    currency: Mapped[str] = mapped_column(String(20), nullable=False, default="USD")

    payment_method: Mapped[Optional[str]] = mapped_column(String(120), nullable=True)
    transaction_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)

    status: Mapped[PaymentStatus] = mapped_column(
        Enum(PaymentStatus, name="payment_status_enum"),
        nullable=False,
        default=PaymentStatus.PENDING,
        index=True,
    )
    sensitivity: Mapped[Sensitivity] = mapped_column(
        Enum(Sensitivity, name="payment_sensitivity_enum"),
        nullable=False,
        default=Sensitivity.CONFIDENTIAL,
        index=True,
    )

    paid_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    refunded_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    verification_status: Mapped[Optional[str]] = mapped_column(String(80), nullable=True, default="pending")
    verification_payload_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now)

    __table_args__ = (
        Index("ix_payments_workspace_user_status", "workspace_id", "user_id", "status"),
        Index("ix_payments_invoice_status", "invoice_id", "status"),
    )

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        invoice_id: str,
        amount: float,
        created_by: Optional[str] = None,
        **kwargs: Any,
    ) -> "Payment":
        safe_user_id = normalize_text(user_id)
        safe_workspace_id = normalize_text(workspace_id)
        safe_invoice_id = normalize_text(invoice_id)

        if not safe_user_id:
            raise ValueError("Payment requires user_id.")
        if not safe_workspace_id:
            raise ValueError("Payment requires workspace_id.")
        if not safe_invoice_id:
            raise ValueError("Payment requires invoice_id.")
        if float(amount) < 0:
            raise ValueError("Payment amount cannot be negative.")

        actor = normalize_text(created_by) or safe_user_id

        item = cls(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            invoice_id=safe_invoice_id,
            client_id=normalize_text(kwargs.get("client_id")) or None,
            amount=float(amount),
            currency=normalize_text(kwargs.get("currency")) or "USD",
            payment_method=normalize_text(kwargs.get("payment_method")) or None,
            transaction_id=normalize_text(kwargs.get("transaction_id")) or None,
            status=kwargs.get("status") or PaymentStatus.PENDING,
            paid_at=kwargs.get("paid_at"),
            notes=normalize_text(kwargs.get("notes")) or None,
            metadata_json=safe_metadata(kwargs.get("metadata_json")),
            created_by=actor,
            updated_by=actor,
        )

        item.verification_payload_json = item.build_verification_payload(
            action="payment.created",
            actor_user_id=actor,
        )

        return item

    def mark_paid(self, *, actor_user_id: str) -> Dict[str, Any]:
        actor = normalize_text(actor_user_id)
        if not actor:
            raise ValueError("actor_user_id is required.")

        self.status = PaymentStatus.PAID
        self.paid_at = utc_now()
        self.updated_by = actor
        self.updated_at = utc_now()
        self.verification_payload_json = self.build_verification_payload(
            action="payment.paid",
            actor_user_id=actor,
        )

        return self.structured_response(
            message="Payment marked as paid.",
            action="payment.paid",
        )

    def mark_refunded(self, *, actor_user_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
        actor = normalize_text(actor_user_id)
        if not actor:
            raise ValueError("actor_user_id is required.")

        self.status = PaymentStatus.REFUNDED
        self.refunded_at = utc_now()
        self.updated_by = actor
        self.updated_at = utc_now()
        self.verification_payload_json = self.build_verification_payload(
            action="payment.refunded",
            actor_user_id=actor,
            extra={"reason": reason},
        )

        return self.structured_response(
            message="Payment marked as refunded.",
            action="payment.refunded",
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "invoice_id": self.invoice_id,
            "client_id": self.client_id,
            "amount": self.amount,
            "currency": self.currency,
            "payment_method": self.payment_method,
            "transaction_id": self.transaction_id,
            "status": self.status.value,
            "sensitivity": self.sensitivity.value,
            "paid_at": self.iso_datetime(self.paid_at),
            "refunded_at": self.iso_datetime(self.refunded_at),
            "notes": self.notes,
            "metadata_json": safe_metadata(self.metadata_json),
            "verification_status": self.verification_status,
            "created_at": self.iso_datetime(self.created_at),
            "updated_at": self.iso_datetime(self.updated_at),
        }


class BusinessAnalytics(Base, BusinessMixin):
    """
    Dashboard/business analytics cache.
    """

    __tablename__ = "business_analytics"

    entity_type = BusinessEntityType.ANALYTICS

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=generate_uuid)
    user_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    workspace_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    metric_name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    metric_value: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    metric_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now, index=True)

    client_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    campaign_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    deal_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)

    status: Mapped[BusinessStatus] = mapped_column(
        Enum(BusinessStatus, name="business_analytics_status_enum"),
        nullable=False,
        default=BusinessStatus.ACTIVE,
        index=True,
    )

    extra_data: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)
    metadata_json: Mapped[Dict[str, Any]] = mapped_column(JSON, nullable=False, default=dict)

    created_by: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)

    __table_args__ = (
        Index("ix_business_analytics_workspace_metric_date", "workspace_id", "metric_name", "metric_date"),
        Index("ix_business_analytics_user_workspace", "user_id", "workspace_id"),
    )

    @classmethod
    def create(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        metric_name: str,
        metric_value: float,
        created_by: Optional[str] = None,
        **kwargs: Any,
    ) -> "BusinessAnalytics":
        safe_user_id = normalize_text(user_id)
        safe_workspace_id = normalize_text(workspace_id)
        safe_metric_name = normalize_text(metric_name)

        if not safe_user_id:
            raise ValueError("BusinessAnalytics requires user_id.")
        if not safe_workspace_id:
            raise ValueError("BusinessAnalytics requires workspace_id.")
        if not safe_metric_name:
            raise ValueError("BusinessAnalytics requires metric_name.")

        return cls(
            user_id=safe_user_id,
            workspace_id=safe_workspace_id,
            metric_name=safe_metric_name,
            metric_value=float(metric_value),
            metric_date=kwargs.get("metric_date") or utc_now(),
            client_id=normalize_text(kwargs.get("client_id")) or None,
            campaign_id=normalize_text(kwargs.get("campaign_id")) or None,
            deal_id=normalize_text(kwargs.get("deal_id")) or None,
            extra_data=safe_metadata(kwargs.get("extra_data")),
            metadata_json=safe_metadata(kwargs.get("metadata_json")),
            created_by=normalize_text(created_by) or safe_user_id,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "metric_name": self.metric_name,
            "metric_value": self.metric_value,
            "metric_date": self.iso_datetime(self.metric_date),
            "client_id": self.client_id,
            "campaign_id": self.campaign_id,
            "deal_id": self.deal_id,
            "status": self.status.value,
            "extra_data": safe_metadata(self.extra_data),
            "metadata_json": safe_metadata(self.metadata_json),
            "created_at": self.iso_datetime(self.created_at),
        }


class Business:
    """
    Compatibility wrapper for Master Agent, Business Agent, Finance Agent,
    Dashboard, Registry, API routes, and future services.

    Required class/component name:
        Business
    """

    BusinessProfile = BusinessProfile
    Client = Client
    CRMContact = CRMContact
    Lead = Lead
    Pipeline = Pipeline
    Deal = Deal
    Campaign = Campaign
    Invoice = Invoice
    Payment = Payment
    Analytics = BusinessAnalytics

    @classmethod
    def get_models(cls) -> Dict[str, Any]:
        """
        Return all registered business database models.
        """
        return {
            "business_profile": cls.BusinessProfile,
            "client": cls.Client,
            "crm_contact": cls.CRMContact,
            "lead": cls.Lead,
            "pipeline": cls.Pipeline,
            "deal": cls.Deal,
            "campaign": cls.Campaign,
            "invoice": cls.Invoice,
            "payment": cls.Payment,
            "analytics": cls.Analytics,
        }

    @classmethod
    def table_names(cls) -> List[str]:
        """
        Return all table names.
        """
        return [model.__tablename__ for model in cls.get_models().values()]

    @classmethod
    def validate_tenant_context(
        cls,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> bool:
        """
        Validate required SaaS isolation context.
        """
        return bool(normalize_text(user_id)) and bool(normalize_text(workspace_id))

    @classmethod
    def assert_tenant_context(
        cls,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
    ) -> None:
        """
        Raise safe error if tenant context is missing.
        """
        if not cls.validate_tenant_context(user_id=user_id, workspace_id=workspace_id):
            raise ValueError("Business operation requires user_id and workspace_id.")

    @classmethod
    def dashboard_filters(
        cls,
        model: Any,
        *,
        user_id: str,
        workspace_id: str,
        status: Optional[Any] = None,
    ) -> List[Any]:
        """
        Build safe filters for dashboard/API reads.
        """
        cls.assert_tenant_context(user_id=user_id, workspace_id=workspace_id)

        filters: List[Any] = [
            model.user_id == normalize_text(user_id),
            model.workspace_id == normalize_text(workspace_id),
        ]

        if status is not None and hasattr(model, "status"):
            filters.append(model.status == status)

        return filters

    @classmethod
    def check_dashboard_access(
        cls,
        *,
        role: Optional[str],
        plan: Optional[str],
        feature: str,
    ) -> Dict[str, Any]:
        """
        Lightweight role/plan/subscription check for dashboard/API functionality.
        """
        normalized_role = normalize_text(role).lower()
        normalized_plan = normalize_text(plan).lower()
        normalized_feature = normalize_text(feature).lower()

        if normalized_role not in {"owner", "admin", "manager", "sales", "finance", "viewer"}:
            return cls.error_result(
                message="Access denied.",
                action="business.access_check",
                error="Unsupported or missing role.",
            )

        paid_features = {
            "campaign_analytics",
            "deal_forecast",
            "invoice_dashboard",
            "bulk_export",
            "advanced_crm",
        }

        if normalized_feature in paid_features and normalized_plan in {"free", "starter_limited", ""}:
            return cls.error_result(
                message="Plan upgrade required.",
                action="business.access_check",
                error="This business feature requires a paid plan.",
            )

        if normalized_feature in {"invoice_dashboard", "payment_refund"}:
            if normalized_role not in {"owner", "admin", "finance"}:
                return cls.error_result(
                    message="Access denied.",
                    action="business.access_check",
                    error="Finance role required.",
                )

        return cls.safe_result(
            message="Access granted.",
            action="business.access_check",
            data={
                "role": normalized_role,
                "plan": normalized_plan,
                "feature": normalized_feature,
            },
        )

    @classmethod
    def requires_security_check(cls, *, action: str, sensitivity: Optional[Sensitivity] = None) -> bool:
        """
        Determine whether a business action should route to Security Agent.
        """
        action_key = normalize_text(action).lower()

        high_risk = {
            "delete",
            "remove",
            "archive",
            "bulk_delete",
            "bulk_export",
            "client_delete",
            "deal_delete",
            "campaign_delete",
            "invoice_delete",
            "invoice_void",
            "payment_refund",
            "business_settings_update",
        }

        if sensitivity in {
            Sensitivity.CONFIDENTIAL,
            Sensitivity.SENSITIVE,
            Sensitivity.RESTRICTED,
        }:
            return True

        return action_key in high_risk

    @classmethod
    def request_security_approval(
        cls,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        entity_type: str,
        entity_id: Optional[str] = None,
        reason: Optional[str] = None,
        sensitivity: Optional[Sensitivity] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Security Agent approval payload without importing future files.
        """
        cls.assert_tenant_context(user_id=user_id, workspace_id=workspace_id)

        requires_review = cls.requires_security_check(
            action=action,
            sensitivity=sensitivity,
        )

        return {
            "success": True,
            "approved": not requires_review,
            "requires_security_review": requires_review,
            "security_agent_payload": {
                "event": "security.review.business",
                "action": normalize_text(action),
                "user_id": normalize_text(user_id),
                "workspace_id": normalize_text(workspace_id),
                "entity_type": normalize_text(entity_type),
                "entity_id": normalize_text(entity_id) or None,
                "reason": normalize_text(reason) if reason else None,
                "sensitivity": sensitivity.value if sensitivity else None,
                "timestamp": utc_now().isoformat(),
            },
        }

    @classmethod
    def prepare_memory_payload(
        cls,
        *,
        entity: BusinessMixin,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload from any business entity.
        """
        return entity.build_memory_agent_payload()

    @classmethod
    def prepare_verification_payload(
        cls,
        *,
        entity: BusinessMixin,
        action: str,
        actor_user_id: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload from any business entity.
        """
        return entity.build_verification_payload(
            action=action,
            actor_user_id=actor_user_id,
            extra=extra,
        )

    @classmethod
    def emit_agent_event(
        cls,
        *,
        event_name: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Import-safe event hook for future AgentEvent model.
        """
        return {
            "event": normalize_text(event_name),
            "payload": safe_metadata(payload),
            "timestamp": utc_now().isoformat(),
        }

    @classmethod
    def log_audit_event(
        cls,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Import-safe audit hook for future Audit Log model.
        """
        cls.assert_tenant_context(user_id=user_id, workspace_id=workspace_id)

        return {
            "event": "business.audit",
            "action": normalize_text(action),
            "user_id": normalize_text(user_id),
            "workspace_id": normalize_text(workspace_id),
            "entity_type": normalize_text(entity_type) or None,
            "entity_id": normalize_text(entity_id) or None,
            "reason": normalize_text(reason) if reason else None,
            "timestamp": utc_now().isoformat(),
        }

    @classmethod
    def safe_result(
        cls,
        *,
        message: str,
        action: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Safe success response.
        """
        return {
            "success": True,
            "message": normalize_text(message),
            "action": normalize_text(action),
            "data": data or {},
            "error": None,
            "timestamp": utc_now().isoformat(),
        }

    @classmethod
    def error_result(
        cls,
        *,
        message: str,
        action: str,
        error: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Safe error response.
        """
        return {
            "success": False,
            "message": normalize_text(message) or "Business operation failed.",
            "action": normalize_text(action) or "business.error",
            "data": {},
            "error": {
                "type": error.__class__.__name__ if isinstance(error, Exception) else "BusinessError",
                "detail": normalize_text(str(error)) if error is not None else None,
            },
            "timestamp": utc_now().isoformat(),
        }

    @classmethod
    def default_pipeline_stages(
        cls,
        *,
        user_id: str,
        workspace_id: str,
        created_by: Optional[str] = None,
    ) -> List[Pipeline]:
        """
        Create default CRM pipeline stage objects.
        Caller should add and commit these using the active DB session.
        """
        stages = [
            ("New Lead", 1, 10, False, False),
            ("Contacted", 2, 25, False, False),
            ("Qualified", 3, 45, False, False),
            ("Proposal Sent", 4, 65, False, False),
            ("Negotiation", 5, 80, False, False),
            ("Won", 6, 100, True, True),
            ("Lost", 7, 0, True, False),
        ]

        return [
            Pipeline.create(
                user_id=user_id,
                workspace_id=workspace_id,
                name=name,
                stage_order=order,
                probability=probability,
                is_closed=is_closed,
                is_won_stage=is_won,
                created_by=created_by,
            )
            for name, order, probability, is_closed, is_won in stages
        ]


BusinessProfileModel = BusinessProfile
ClientModel = Client
CRMContactModel = CRMContact
LeadModel = Lead
PipelineModel = Pipeline
DealModel = Deal
CampaignModel = Campaign
InvoiceModel = Invoice
PaymentModel = Payment
BusinessAnalyticsModel = BusinessAnalytics
BusinessModels = Business


__all__ = [
    "Business",
    "BusinessModels",
    "BusinessMixin",
    "BusinessEntityType",
    "BusinessStatus",
    "LeadStatus",
    "DealStatus",
    "ContactType",
    "CampaignStatus",
    "CampaignChannel",
    "InvoiceStatus",
    "PaymentStatus",
    "Priority",
    "Sensitivity",
    "BusinessProfile",
    "BusinessProfileModel",
    "Client",
    "ClientModel",
    "CRMContact",
    "CRMContactModel",
    "Lead",
    "LeadModel",
    "Pipeline",
    "PipelineModel",
    "Deal",
    "DealModel",
    "Campaign",
    "CampaignModel",
    "Invoice",
    "InvoiceModel",
    "Payment",
    "PaymentModel",
    "BusinessAnalytics",
    "BusinessAnalyticsModel",
]