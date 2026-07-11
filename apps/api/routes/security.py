"""
apps/api/routes/security.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Agent/Module: API Prompt Bible
Purpose: approval requests, audit logs, risky action decisions

This module is import-safe:
- It does not require future project files to exist.
- It uses environment-driven safe defaults.
- It provides in-memory fallback repositories for early development.
- It can later connect to Master Agent, Security Agent, Memory Agent, Audit services,
  database repositories, and Verification Agent without changing route contracts.

Core responsibilities:
- Create approval requests for sensitive/risky actions.
- Approve or deny pending approval requests.
- Make risky action decisions using policy rules.
- Write and search audit logs.
- Enforce strict user/workspace isolation.
- Enforce role/plan/subscription checks.
- Prepare Verification Agent payloads after completed actions.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

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

router = APIRouter(tags=["Security"])
# No self-prefix -- apps/api/main.py's OPTIONAL_ROUTERS supplies
# "/security" as this router's default_prefix once mounted below.


# =============================================================================
# Environment safe defaults
# =============================================================================

APP_NAME = os.getenv("WILLIAM_APP_NAME", "William Jarvis")
DEFAULT_APPROVAL_EXPIRY_MINUTES = int(os.getenv("WILLIAM_SECURITY_APPROVAL_EXPIRY_MINUTES", "60"))
MAX_AUDIT_SEARCH_LIMIT = int(os.getenv("WILLIAM_SECURITY_MAX_AUDIT_SEARCH_LIMIT", "100"))
MAX_APPROVAL_SEARCH_LIMIT = int(os.getenv("WILLIAM_SECURITY_MAX_APPROVAL_SEARCH_LIMIT", "100"))
MAX_AUDIT_EXPORT_RECORDS = int(os.getenv("WILLIAM_SECURITY_MAX_AUDIT_EXPORT_RECORDS", "25000"))
AUTO_APPROVE_LOW_RISK = os.getenv("WILLIAM_SECURITY_AUTO_APPROVE_LOW_RISK", "true").lower() == "true"
AUTO_DENY_CRITICAL_WITHOUT_ADMIN = os.getenv("WILLIAM_SECURITY_AUTO_DENY_CRITICAL_WITHOUT_ADMIN", "true").lower() == "true"
ALLOW_VIEWER_AUDIT_READ = os.getenv("WILLIAM_SECURITY_ALLOW_VIEWER_AUDIT_READ", "false").lower() == "true"

SENSITIVE_PAYLOAD_KEYS = {
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "access_token",
    "refresh_token",
    "private_key",
    "client_secret",
    "cookie",
    "session",
}


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


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class DecisionOutcome(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"
    REQUIRES_APPROVAL = "requires_approval"
    NEEDS_MORE_CONTEXT = "needs_more_context"


class AuditEventStatus(str, Enum):
    SUCCESS = "success"
    DENIED = "denied"
    ERROR = "error"
    PENDING = "pending"


class SecurityActionCategory(str, Enum):
    MEMORY = "memory"
    FILES = "files"
    SYSTEM = "system"
    BROWSER = "browser"
    CODE = "code"
    BILLING = "billing"
    AGENT_ACCESS = "agent_access"
    USER_ACCESS = "user_access"
    WORKSPACE = "workspace"
    WORKFLOW = "workflow"
    DEVICE = "device"
    EXTERNAL_API = "external_api"
    GENERAL = "general"


class SecurityDecisionMode(str, Enum):
    POLICY = "policy"
    HUMAN_APPROVAL = "human_approval"
    SECURITY_AGENT = "security_agent"
    FALLBACK = "fallback"


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
class ApprovalRequestRecord:
    id: str
    user_id: str
    workspace_id: str
    action: str
    category: SecurityActionCategory
    risk_level: RiskLevel
    status: ApprovalStatus
    reason: str
    payload: Dict[str, Any]
    payload_hash: str
    requested_by: str
    decided_by: Optional[str]
    decision_reason: Optional[str]
    created_at: str
    updated_at: str
    expires_at: Optional[str]
    decided_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def visible_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditLogRecord:
    id: str
    user_id: str
    workspace_id: str
    action: str
    category: SecurityActionCategory
    status: AuditEventStatus
    actor_user_id: str
    actor_role: UserRole
    target_type: Optional[str]
    target_id: Optional[str]
    risk_level: Optional[RiskLevel]
    message: str
    details: Dict[str, Any]
    ip_address: Optional[str]
    user_agent: Optional[str]
    request_id: str
    created_at: str

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


class ApprovalCreateRequest(BaseModel):
    action: str = Field(..., min_length=2, max_length=180)
    category: SecurityActionCategory = SecurityActionCategory.GENERAL
    risk_level: RiskLevel = RiskLevel.MEDIUM
    reason: str = Field(..., min_length=3, max_length=1000)
    payload: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    expires_in_minutes: Optional[int] = Field(default=None, ge=5, le=1440)

    @field_validator("action")
    @classmethod
    def validate_action(cls, value: str) -> str:
        cleaned = value.strip()
        if not re.match(r"^[a-zA-Z0-9_.:\-/ ]+$", cleaned):
            raise ValueError("Action contains unsafe characters.")
        return cleaned

    @field_validator("payload", "metadata")
    @classmethod
    def validate_json_size(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        serialized = json.dumps(value, default=str)
        if len(serialized) > 50000:
            raise ValueError("Payload or metadata is too large.")
        return value


class ApprovalDecisionRequest(BaseModel):
    approval_id: str = Field(..., min_length=2, max_length=140)
    decision: Literal["approve", "deny"]
    decision_reason: str = Field(..., min_length=3, max_length=1000)


class RiskDecisionRequest(BaseModel):
    action: str = Field(..., min_length=2, max_length=180)
    category: SecurityActionCategory = SecurityActionCategory.GENERAL
    payload: Dict[str, Any] = Field(default_factory=dict)
    requested_risk_level: Optional[RiskLevel] = None
    reason: Optional[str] = Field(default=None, max_length=1000)
    require_human_for_high_risk: bool = True

    @field_validator("payload")
    @classmethod
    def validate_payload_size(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        serialized = json.dumps(value, default=str)
        if len(serialized) > 50000:
            raise ValueError("Payload is too large.")
        return value


class AuditLogCreateRequest(BaseModel):
    action: str = Field(..., min_length=2, max_length=180)
    category: SecurityActionCategory = SecurityActionCategory.GENERAL
    status: AuditEventStatus = AuditEventStatus.SUCCESS
    target_type: Optional[str] = Field(default=None, max_length=120)
    target_id: Optional[str] = Field(default=None, max_length=140)
    risk_level: Optional[RiskLevel] = None
    message: str = Field(default="Audit event recorded.", max_length=1000)
    details: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("details")
    @classmethod
    def validate_details_size(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        serialized = json.dumps(value, default=str)
        if len(serialized) > 50000:
            raise ValueError("Audit details are too large.")
        return value


class AuditSearchRequest(BaseModel):
    query: Optional[str] = Field(default=None, max_length=500)
    categories: List[SecurityActionCategory] = Field(default_factory=list)
    statuses: List[AuditEventStatus] = Field(default_factory=list)
    risk_levels: List[RiskLevel] = Field(default_factory=list)
    actor_user_id: Optional[str] = Field(default=None, max_length=120)
    target_type: Optional[str] = Field(default=None, max_length=120)
    target_id: Optional[str] = Field(default=None, max_length=140)
    limit: int = Field(default=25, ge=1, le=MAX_AUDIT_SEARCH_LIMIT)
    offset: int = Field(default=0, ge=0)


class ApprovalSearchRequest(BaseModel):
    query: Optional[str] = Field(default=None, max_length=500)
    statuses: List[ApprovalStatus] = Field(default_factory=list)
    categories: List[SecurityActionCategory] = Field(default_factory=list)
    risk_levels: List[RiskLevel] = Field(default_factory=list)
    requested_by: Optional[str] = Field(default=None, max_length=120)
    limit: int = Field(default=25, ge=1, le=MAX_APPROVAL_SEARCH_LIMIT)
    offset: int = Field(default=0, ge=0)


class SecurityResponse(BaseModel):
    ok: bool
    message: str
    data: Dict[str, Any] = Field(default_factory=dict)
    verification: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


class ApprovalSearchResponse(BaseModel):
    ok: bool
    message: str
    approvals: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int
    request_id: Optional[str] = None


class AuditSearchResponse(BaseModel):
    ok: bool
    message: str
    logs: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int
    request_id: Optional[str] = None


# =============================================================================
# Utility helpers
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def add_minutes_iso(minutes: int) -> str:
    from datetime import timedelta

    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def normalize_id(value: Optional[str], field_name: str) -> str:
    if value is None:
        raise_safe_error(
            status.HTTP_400_BAD_REQUEST,
            f"missing_{field_name}",
            f"{field_name} is required.",
        )

    cleaned = str(value).strip()
    if not cleaned:
        raise_safe_error(
            status.HTTP_400_BAD_REQUEST,
            f"empty_{field_name}",
            f"{field_name} cannot be empty.",
        )

    if len(cleaned) > 140:
        raise_safe_error(
            status.HTTP_400_BAD_REQUEST,
            f"invalid_{field_name}",
            f"{field_name} is too long.",
        )

    if not re.match(r"^[a-zA-Z0-9_\-:.@]+$", cleaned):
        raise_safe_error(
            status.HTTP_400_BAD_REQUEST,
            f"invalid_{field_name}",
            f"{field_name} contains unsafe characters.",
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


def safe_json(data: Any) -> Any:
    try:
        json.dumps(data, default=str)
        return data
    except Exception:
        return {"serialization_warning": "Original value could not be serialized safely."}


def redact_sensitive(value: Any) -> Any:
    """
    Recursively redact sensitive payload fields.
    This keeps audit/security visibility useful without leaking secrets.
    """

    if isinstance(value, dict):
        redacted: Dict[str, Any] = {}
        for key, nested_value in value.items():
            key_lower = str(key).lower()
            if key_lower in SENSITIVE_PAYLOAD_KEYS or any(secret_key in key_lower for secret_key in SENSITIVE_PAYLOAD_KEYS):
                redacted[key] = "***REDACTED***"
            else:
                redacted[key] = redact_sensitive(nested_value)
        return redacted

    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]

    return value


def payload_hash(payload: Dict[str, Any]) -> str:
    serialized = json.dumps(redact_sensitive(payload), sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def is_expired(iso_time: Optional[str]) -> bool:
    if not iso_time:
        return False

    try:
        expiry = datetime.fromisoformat(iso_time.replace("Z", "+00:00"))
        return datetime.now(timezone.utc) > expiry
    except Exception:
        return False


def can_create_approval(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER, UserRole.MEMBER}


def can_decide_approval(role: UserRole, risk_level: RiskLevel) -> bool:
    if risk_level == RiskLevel.CRITICAL:
        return role in {UserRole.OWNER, UserRole.ADMIN}
    if risk_level == RiskLevel.HIGH:
        return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER}
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER}


def can_read_audit(role: UserRole) -> bool:
    if ALLOW_VIEWER_AUDIT_READ and role == UserRole.VIEWER:
        return True
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER}


def can_create_audit(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER, UserRole.MEMBER}


def can_search_approvals(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER}


def plan_allows_security_dashboard(plan: SubscriptionPlan) -> bool:
    return plan in {SubscriptionPlan.PRO, SubscriptionPlan.BUSINESS, SubscriptionPlan.ENTERPRISE}


def category_base_risk(category: SecurityActionCategory) -> RiskLevel:
    high_risk = {
        SecurityActionCategory.SYSTEM,
        SecurityActionCategory.BILLING,
        SecurityActionCategory.USER_ACCESS,
        SecurityActionCategory.WORKSPACE,
        SecurityActionCategory.DEVICE,
        SecurityActionCategory.EXTERNAL_API,
    }

    medium_risk = {
        SecurityActionCategory.MEMORY,
        SecurityActionCategory.FILES,
        SecurityActionCategory.BROWSER,
        SecurityActionCategory.CODE,
        SecurityActionCategory.AGENT_ACCESS,
        SecurityActionCategory.WORKFLOW,
    }

    if category in high_risk:
        return RiskLevel.HIGH

    if category in medium_risk:
        return RiskLevel.MEDIUM

    return RiskLevel.LOW


def risk_rank(risk: RiskLevel) -> int:
    ranks = {
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }
    return ranks[risk]


def max_risk(*risks: RiskLevel) -> RiskLevel:
    return max(risks, key=risk_rank)


def infer_payload_risk(payload: Dict[str, Any]) -> RiskLevel:
    serialized = json.dumps(payload, default=str).lower()

    critical_terms = [
        "delete_workspace",
        "hard_delete",
        "drop_table",
        "remove_user",
        "billing_cancel",
        "transfer_ownership",
        "permanent_delete",
        "format_drive",
        "shutdown",
    ]

    high_terms = [
        "delete",
        "payment",
        "invoice",
        "admin",
        "secret",
        "token",
        "api_key",
        "credential",
        "file_write",
        "browser_purchase",
        "send_email",
        "external_api",
    ]

    medium_terms = [
        "export",
        "download",
        "memory",
        "client",
        "project",
        "private",
        "confidential",
        "update",
        "upload",
    ]

    if any(term in serialized for term in critical_terms):
        return RiskLevel.CRITICAL

    if any(term in serialized for term in high_terms):
        return RiskLevel.HIGH

    if any(term in serialized for term in medium_terms):
        return RiskLevel.MEDIUM

    return RiskLevel.LOW


# =============================================================================
# Fallback repositories
# =============================================================================

class InMemoryApprovalRepository:
    def __init__(self) -> None:
        self._items: Dict[str, ApprovalRequestRecord] = {}
        self._lock = RLock()

    def save(self, record: ApprovalRequestRecord) -> ApprovalRequestRecord:
        with self._lock:
            self._items[record.id] = record
            return record

    def update(self, record: ApprovalRequestRecord) -> ApprovalRequestRecord:
        with self._lock:
            self._items[record.id] = record
            return record

    def get_scoped(
        self,
        approval_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Optional[ApprovalRequestRecord]:
        with self._lock:
            record = self._items.get(approval_id)
            if record is None:
                return None
            if record.user_id != user_id or record.workspace_id != workspace_id:
                return None
            return record

    def query(
        self,
        user_id: str,
        workspace_id: str,
        query: Optional[str] = None,
        statuses: Optional[Sequence[ApprovalStatus]] = None,
        categories: Optional[Sequence[SecurityActionCategory]] = None,
        risk_levels: Optional[Sequence[RiskLevel]] = None,
        requested_by: Optional[str] = None,
    ) -> List[ApprovalRequestRecord]:
        query_normalized = query.strip().lower() if query else None
        statuses_set = {item.value if isinstance(item, ApprovalStatus) else str(item) for item in (statuses or [])}
        categories_set = {item.value if isinstance(item, SecurityActionCategory) else str(item) for item in (categories or [])}
        risk_set = {item.value if isinstance(item, RiskLevel) else str(item) for item in (risk_levels or [])}

        with self._lock:
            results: List[ApprovalRequestRecord] = []

            for record in self._items.values():
                if record.user_id != user_id or record.workspace_id != workspace_id:
                    continue

                if statuses_set and record.status.value not in statuses_set:
                    continue

                if categories_set and record.category.value not in categories_set:
                    continue

                if risk_set and record.risk_level.value not in risk_set:
                    continue

                if requested_by and record.requested_by != requested_by:
                    continue

                if query_normalized:
                    haystack = " ".join(
                        [
                            record.action,
                            record.reason,
                            record.decision_reason or "",
                            json.dumps(record.metadata, default=str),
                        ]
                    ).lower()
                    if query_normalized not in haystack:
                        continue

                if record.status == ApprovalStatus.PENDING and is_expired(record.expires_at):
                    record.status = ApprovalStatus.EXPIRED
                    record.updated_at = utc_now()
                    self._items[record.id] = record

                results.append(record)

            results.sort(key=lambda item: item.updated_at, reverse=True)
            return results


class InMemoryAuditRepository:
    def __init__(self) -> None:
        self._items: Dict[str, AuditLogRecord] = {}
        self._lock = RLock()

    def save(self, record: AuditLogRecord) -> AuditLogRecord:
        with self._lock:
            self._items[record.id] = record
            return record

    def query(
        self,
        user_id: str,
        workspace_id: str,
        query: Optional[str] = None,
        categories: Optional[Sequence[SecurityActionCategory]] = None,
        statuses: Optional[Sequence[AuditEventStatus]] = None,
        risk_levels: Optional[Sequence[RiskLevel]] = None,
        actor_user_id: Optional[str] = None,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
    ) -> List[AuditLogRecord]:
        query_normalized = query.strip().lower() if query else None
        categories_set = {item.value if isinstance(item, SecurityActionCategory) else str(item) for item in (categories or [])}
        statuses_set = {item.value if isinstance(item, AuditEventStatus) else str(item) for item in (statuses or [])}
        risk_set = {item.value if isinstance(item, RiskLevel) else str(item) for item in (risk_levels or [])}

        with self._lock:
            results: List[AuditLogRecord] = []

            for record in self._items.values():
                if record.user_id != user_id or record.workspace_id != workspace_id:
                    continue

                if categories_set and record.category.value not in categories_set:
                    continue

                if statuses_set and record.status.value not in statuses_set:
                    continue

                if risk_set and (record.risk_level is None or record.risk_level.value not in risk_set):
                    continue

                if actor_user_id and record.actor_user_id != actor_user_id:
                    continue

                if target_type and record.target_type != target_type:
                    continue

                if target_id and record.target_id != target_id:
                    continue

                if query_normalized:
                    haystack = " ".join(
                        [
                            record.action,
                            record.message,
                            record.target_type or "",
                            record.target_id or "",
                            json.dumps(record.details, default=str),
                        ]
                    ).lower()
                    if query_normalized not in haystack:
                        continue

                results.append(record)

            results.sort(key=lambda item: item.created_at, reverse=True)
            return results


_approval_repository = InMemoryApprovalRepository()
_audit_repository = InMemoryAuditRepository()


# =============================================================================
# Main Security component
# =============================================================================

class Security:
    """
    Required class/component name: Security

    Central API security component for:
    - Approval requests
    - Risk decisions
    - Audit logs
    - Agent handoff payloads
    """

    def __init__(
        self,
        approval_repository: Optional[InMemoryApprovalRepository] = None,
        audit_repository: Optional[InMemoryAuditRepository] = None,
        verification_hook: Optional[Callable[..., Any]] = None,
        memory_agent_hook: Optional[Callable[..., Any]] = None,
        master_agent_hook: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.approval_repository = approval_repository or _approval_repository
        self.audit_repository = audit_repository or _audit_repository
        self.verification_hook = verification_hook or project_prepare_verification
        self.memory_agent_hook = memory_agent_hook or project_memory_agent_index
        self.master_agent_hook = master_agent_hook or project_notify_master_agent

    def enforce_subscription(self, actor: ActorContext) -> None:
        if not actor.subscription_active:
            raise_safe_error(
                status.HTTP_402_PAYMENT_REQUIRED,
                "subscription_inactive",
                "Your subscription is inactive. Security access is currently unavailable.",
                actor.request_id,
            )

    def enforce_security_dashboard_plan(self, actor: ActorContext) -> None:
        self.enforce_subscription(actor)

        if not plan_allows_security_dashboard(actor.plan):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "plan_does_not_allow_security_dashboard",
                "Your current plan does not include advanced security dashboard access.",
                actor.request_id,
                {"plan": actor.plan.value},
            )

    def enforce_create_approval_access(self, actor: ActorContext) -> None:
        self.enforce_subscription(actor)

        if not can_create_approval(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_create_approval",
                "Your role does not allow creating approval requests.",
                actor.request_id,
                {"role": actor.role.value},
            )

    def enforce_decision_access(self, actor: ActorContext, risk_level: RiskLevel) -> None:
        self.enforce_subscription(actor)

        if not can_decide_approval(actor.role, risk_level):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_decide_approval",
                "Your role does not allow deciding this approval request.",
                actor.request_id,
                {"role": actor.role.value, "risk_level": risk_level.value},
            )

    def enforce_audit_read_access(self, actor: ActorContext) -> None:
        self.enforce_security_dashboard_plan(actor)

        if not can_read_audit(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_read_audit_logs",
                "Your role does not allow reading audit logs.",
                actor.request_id,
                {"role": actor.role.value},
            )

    def enforce_audit_create_access(self, actor: ActorContext) -> None:
        self.enforce_subscription(actor)

        if not can_create_audit(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_create_audit_log",
                "Your role does not allow creating audit logs.",
                actor.request_id,
                {"role": actor.role.value},
            )

    def enforce_approval_search_access(self, actor: ActorContext) -> None:
        self.enforce_security_dashboard_plan(actor)

        if not can_search_approvals(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_search_approvals",
                "Your role does not allow viewing approval requests.",
                actor.request_id,
                {"role": actor.role.value},
            )

    async def prepare_verification(
        self,
        actor: ActorContext,
        action: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload = {
            "agent": "Verification Agent",
            "module": "security",
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

    async def notify_master_agent(
        self,
        actor: ActorContext,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        message = {
            "agent": "Master Agent",
            "event_type": event_type,
            "module": "security",
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "request_id": actor.request_id,
            "payload": safe_json(payload),
            "created_at": utc_now(),
        }

        if callable(self.master_agent_hook):
            try:
                maybe_result = self.master_agent_hook(message)
                if hasattr(maybe_result, "__await__"):
                    await maybe_result
            except Exception:
                return

    async def index_for_memory_agent(
        self,
        actor: ActorContext,
        event_type: str,
        payload: Dict[str, Any],
    ) -> None:
        message = {
            "agent": "Memory Agent",
            "event_type": event_type,
            "module": "security",
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "request_id": actor.request_id,
            "payload": safe_json(payload),
            "created_at": utc_now(),
        }

        if callable(self.memory_agent_hook):
            try:
                maybe_result = self.memory_agent_hook(message)
                if hasattr(maybe_result, "__await__"):
                    await maybe_result
            except Exception:
                return

    async def write_audit_event(
        self,
        actor: ActorContext,
        action: str,
        category: SecurityActionCategory,
        event_status: AuditEventStatus,
        message: str,
        target_type: Optional[str] = None,
        target_id: Optional[str] = None,
        risk_level: Optional[RiskLevel] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLogRecord:
        record = AuditLogRecord(
            id=str(uuid.uuid4()),
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            action=action,
            category=category,
            status=event_status,
            actor_user_id=actor.user_id,
            actor_role=actor.role,
            target_type=target_type,
            target_id=target_id,
            risk_level=risk_level,
            message=message,
            details=redact_sensitive(details or {}),
            ip_address=actor.ip_address,
            user_agent=actor.user_agent,
            request_id=actor.request_id,
            created_at=utc_now(),
        )

        saved = self.audit_repository.save(record)

        await self.index_for_memory_agent(
            actor,
            "audit_log_created",
            {
                "audit_id": saved.id,
                "action": saved.action,
                "category": saved.category.value,
                "status": saved.status.value,
                "risk_level": saved.risk_level.value if saved.risk_level else None,
            },
        )

        return saved

    async def create_approval(
        self,
        actor: ActorContext,
        payload: ApprovalCreateRequest,
    ) -> Tuple[ApprovalRequestRecord, Dict[str, Any]]:
        self.enforce_create_approval_access(actor)

        expires_in = payload.expires_in_minutes or DEFAULT_APPROVAL_EXPIRY_MINUTES
        now = utc_now()

        record = ApprovalRequestRecord(
            id=str(uuid.uuid4()),
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            action=payload.action,
            category=payload.category,
            risk_level=payload.risk_level,
            status=ApprovalStatus.PENDING,
            reason=payload.reason,
            payload=redact_sensitive(payload.payload),
            payload_hash=payload_hash(payload.payload),
            requested_by=actor.user_id,
            decided_by=None,
            decision_reason=None,
            created_at=now,
            updated_at=now,
            expires_at=add_minutes_iso(expires_in),
            metadata=redact_sensitive(payload.metadata),
        )

        saved = self.approval_repository.save(record)

        await self.write_audit_event(
            actor=actor,
            action="security.approval.create",
            category=payload.category,
            event_status=AuditEventStatus.PENDING,
            message="Security approval request created.",
            target_type="approval_request",
            target_id=saved.id,
            risk_level=payload.risk_level,
            details={
                "approval_id": saved.id,
                "requested_action": saved.action,
                "reason": saved.reason,
            },
        )

        await self.notify_master_agent(
            actor,
            "security_approval_requested",
            {
                "approval_id": saved.id,
                "action": saved.action,
                "category": saved.category.value,
                "risk_level": saved.risk_level.value,
                "status": saved.status.value,
            },
        )

        verification = await self.prepare_verification(
            actor,
            "security.approval.create",
            {
                "approval_id": saved.id,
                "status": saved.status.value,
                "risk_level": saved.risk_level.value,
            },
        )

        return saved, verification

    async def decide_approval(
        self,
        actor: ActorContext,
        payload: ApprovalDecisionRequest,
    ) -> Tuple[ApprovalRequestRecord, Dict[str, Any]]:
        approval_id = normalize_id(payload.approval_id, "approval_id")

        record = self.approval_repository.get_scoped(
            approval_id,
            actor.user_id,
            actor.workspace_id,
        )

        if record is None:
            raise_safe_error(
                status.HTTP_404_NOT_FOUND,
                "approval_not_found",
                "Approval request was not found in this user/workspace scope.",
                actor.request_id,
            )

        self.enforce_decision_access(actor, record.risk_level)

        if record.status == ApprovalStatus.PENDING and is_expired(record.expires_at):
            record.status = ApprovalStatus.EXPIRED
            record.updated_at = utc_now()
            self.approval_repository.update(record)

            raise_safe_error(
                status.HTTP_409_CONFLICT,
                "approval_expired",
                "This approval request has expired.",
                actor.request_id,
                {"approval_id": record.id},
            )

        if record.status != ApprovalStatus.PENDING:
            raise_safe_error(
                status.HTTP_409_CONFLICT,
                "approval_not_pending",
                "Only pending approval requests can be decided.",
                actor.request_id,
                {"approval_id": record.id, "current_status": record.status.value},
            )

        record.status = ApprovalStatus.APPROVED if payload.decision == "approve" else ApprovalStatus.DENIED
        record.decided_by = actor.user_id
        record.decision_reason = payload.decision_reason
        record.decided_at = utc_now()
        record.updated_at = record.decided_at

        updated = self.approval_repository.update(record)

        audit_status = AuditEventStatus.SUCCESS if updated.status == ApprovalStatus.APPROVED else AuditEventStatus.DENIED

        await self.write_audit_event(
            actor=actor,
            action=f"security.approval.{payload.decision}",
            category=updated.category,
            event_status=audit_status,
            message=f"Security approval request {updated.status.value}.",
            target_type="approval_request",
            target_id=updated.id,
            risk_level=updated.risk_level,
            details={
                "approval_id": updated.id,
                "requested_action": updated.action,
                "decision": payload.decision,
                "decision_reason": payload.decision_reason,
            },
        )

        await self.notify_master_agent(
            actor,
            "security_approval_decided",
            {
                "approval_id": updated.id,
                "action": updated.action,
                "status": updated.status.value,
                "decided_by": actor.user_id,
            },
        )

        verification = await self.prepare_verification(
            actor,
            "security.approval.decision",
            {
                "approval_id": updated.id,
                "status": updated.status.value,
                "decided_by": updated.decided_by,
            },
        )

        return updated, verification

    async def decide_risky_action(
        self,
        actor: ActorContext,
        payload: RiskDecisionRequest,
    ) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        self.enforce_subscription(actor)

        base_risk = category_base_risk(payload.category)
        payload_risk = infer_payload_risk(payload.payload)
        requested_risk = payload.requested_risk_level or RiskLevel.LOW
        final_risk = max_risk(base_risk, payload_risk, requested_risk)

        decision_mode = SecurityDecisionMode.POLICY
        outcome = DecisionOutcome.REQUIRES_APPROVAL
        reason = "Action requires approval before execution."

        if final_risk == RiskLevel.CRITICAL and AUTO_DENY_CRITICAL_WITHOUT_ADMIN and actor.role not in {UserRole.OWNER, UserRole.ADMIN}:
            outcome = DecisionOutcome.DENIED
            reason = "Critical action denied because the actor role is not owner/admin."
            decision_mode = SecurityDecisionMode.POLICY

        elif final_risk == RiskLevel.LOW and AUTO_APPROVE_LOW_RISK:
            outcome = DecisionOutcome.APPROVED
            reason = "Low-risk action approved by policy."
            decision_mode = SecurityDecisionMode.POLICY

        elif final_risk == RiskLevel.MEDIUM and actor.role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER}:
            outcome = DecisionOutcome.APPROVED
            reason = "Medium-risk action approved by role policy."
            decision_mode = SecurityDecisionMode.POLICY

        elif final_risk == RiskLevel.HIGH and not payload.require_human_for_high_risk and actor.role in {UserRole.OWNER, UserRole.ADMIN}:
            outcome = DecisionOutcome.APPROVED
            reason = "High-risk action approved by owner/admin policy without human approval requirement."
            decision_mode = SecurityDecisionMode.POLICY

        elif final_risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            outcome = DecisionOutcome.REQUIRES_APPROVAL
            reason = "High or critical risk action requires explicit approval."
            decision_mode = SecurityDecisionMode.HUMAN_APPROVAL

        decision = {
            "outcome": outcome.value,
            "risk_level": final_risk.value,
            "decision_mode": decision_mode.value,
            "reason": reason,
            "action": payload.action,
            "category": payload.category.value,
            "payload_hash": payload_hash(payload.payload),
            "requires_approval": outcome == DecisionOutcome.REQUIRES_APPROVAL,
        }

        approval_record: Optional[ApprovalRequestRecord] = None

        if outcome == DecisionOutcome.REQUIRES_APPROVAL:
            approval_payload = ApprovalCreateRequest(
                action=payload.action,
                category=payload.category,
                risk_level=final_risk,
                reason=payload.reason or reason,
                payload=payload.payload,
                metadata={
                    "created_from": "risk_decision",
                    "decision_reason": reason,
                },
            )
            approval_record, _ = await self.create_approval(actor, approval_payload)
            decision["approval_id"] = approval_record.id

        await self.write_audit_event(
            actor=actor,
            action="security.risk_decision",
            category=payload.category,
            event_status=AuditEventStatus.SUCCESS if outcome == DecisionOutcome.APPROVED else AuditEventStatus.PENDING if outcome == DecisionOutcome.REQUIRES_APPROVAL else AuditEventStatus.DENIED,
            message="Risky action decision completed.",
            target_type="security_decision",
            target_id=decision.get("approval_id"),
            risk_level=final_risk,
            details={
                "decision": decision,
                "input_reason": payload.reason,
            },
        )

        verification = await self.prepare_verification(
            actor,
            "security.risk_decision",
            decision,
        )

        return decision, verification

    async def create_audit_log(
        self,
        actor: ActorContext,
        payload: AuditLogCreateRequest,
    ) -> Tuple[AuditLogRecord, Dict[str, Any]]:
        self.enforce_audit_create_access(actor)

        record = await self.write_audit_event(
            actor=actor,
            action=payload.action,
            category=payload.category,
            event_status=payload.status,
            message=payload.message,
            target_type=payload.target_type,
            target_id=payload.target_id,
            risk_level=payload.risk_level,
            details=payload.details,
        )

        verification = await self.prepare_verification(
            actor,
            "security.audit.create",
            {
                "audit_id": record.id,
                "action": record.action,
                "status": record.status.value,
            },
        )

        return record, verification

    async def search_audit_logs(
        self,
        actor: ActorContext,
        payload: AuditSearchRequest,
    ) -> Tuple[List[AuditLogRecord], int]:
        self.enforce_audit_read_access(actor)

        records = self.audit_repository.query(
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            query=payload.query,
            categories=payload.categories,
            statuses=payload.statuses,
            risk_levels=payload.risk_levels,
            actor_user_id=payload.actor_user_id,
            target_type=payload.target_type,
            target_id=payload.target_id,
        )

        total = len(records)
        page = records[payload.offset : payload.offset + payload.limit]

        await self.write_audit_event(
            actor=actor,
            action="security.audit.search",
            category=SecurityActionCategory.GENERAL,
            event_status=AuditEventStatus.SUCCESS,
            message="Audit logs searched.",
            target_type="audit_log",
            risk_level=RiskLevel.LOW,
            details={
                "query_present": bool(payload.query),
                "total": total,
                "limit": payload.limit,
                "offset": payload.offset,
            },
        )

        return page, total

    async def search_approvals(
        self,
        actor: ActorContext,
        payload: ApprovalSearchRequest,
    ) -> Tuple[List[ApprovalRequestRecord], int]:
        self.enforce_approval_search_access(actor)

        records = self.approval_repository.query(
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            query=payload.query,
            statuses=payload.statuses,
            categories=payload.categories,
            risk_levels=payload.risk_levels,
            requested_by=payload.requested_by,
        )

        total = len(records)
        page = records[payload.offset : payload.offset + payload.limit]

        await self.write_audit_event(
            actor=actor,
            action="security.approval.search",
            category=SecurityActionCategory.GENERAL,
            event_status=AuditEventStatus.SUCCESS,
            message="Approval requests searched.",
            target_type="approval_request",
            risk_level=RiskLevel.LOW,
            details={
                "query_present": bool(payload.query),
                "total": total,
                "limit": payload.limit,
                "offset": payload.offset,
            },
        )

        return page, total


security_service = Security()


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

    Production can replace header fallback with real dependencies:
    - apps.api.dependencies.auth.get_current_user
    - apps.api.dependencies.workspace.get_current_workspace

    Until those exist, use headers:
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
    workspace_id = normalize_id(
        str(resolved_workspace_id) if resolved_workspace_id is not None else None,
        "workspace_id",
    )

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

    subscription_active_raw = (
        getattr(current_user, "subscription_active", None)
        if current_user is not None
        else None
    )

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


def get_security_service() -> Security:
    return security_service


# =============================================================================
# Routes
# =============================================================================

@router.post("/approvals", response_model=SecurityResponse, status_code=status.HTTP_201_CREATED)
async def create_approval_request(
    payload: ApprovalCreateRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Security = Depends(get_security_service),
) -> SecurityResponse:
    """
    Create a scoped Security Agent approval request.

    User/workspace are resolved from auth/header only.
    Payload cannot override user_id/workspace_id.
    """

    approval, verification = await service.create_approval(actor, payload)

    return SecurityResponse(
        ok=True,
        message="Security approval request created successfully.",
        data={"approval": approval.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


@router.post("/approvals/decision", response_model=SecurityResponse)
async def decide_approval_request(
    payload: ApprovalDecisionRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Security = Depends(get_security_service),
) -> SecurityResponse:
    """
    Approve or deny a pending approval request.

    Only manager/admin/owner can decide approvals.
    Critical approvals require owner/admin.
    """

    approval, verification = await service.decide_approval(actor, payload)

    return SecurityResponse(
        ok=True,
        message=f"Security approval request {approval.status.value}.",
        data={"approval": approval.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


@router.post("/decide", response_model=SecurityResponse)
async def decide_risky_action(
    payload: RiskDecisionRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Security = Depends(get_security_service),
) -> SecurityResponse:
    """
    Evaluate a risky action before execution.

    Returns one of:
    - approved
    - denied
    - requires_approval
    - needs_more_context
    """

    decision, verification = await service.decide_risky_action(actor, payload)

    return SecurityResponse(
        ok=True,
        message="Risky action decision completed.",
        data={"decision": decision},
        verification=verification,
        request_id=actor.request_id,
    )


@router.get("/approvals/{approval_id}", response_model=SecurityResponse)
async def get_approval_request(
    approval_id: str,
    actor: ActorContext = Depends(get_actor_context),
    service: Security = Depends(get_security_service),
) -> SecurityResponse:
    """
    Get one approval request within user/workspace scope.
    """

    service.enforce_approval_search_access(actor)
    safe_approval_id = normalize_id(approval_id, "approval_id")

    approval = service.approval_repository.get_scoped(
        safe_approval_id,
        actor.user_id,
        actor.workspace_id,
    )

    if approval is None:
        raise_safe_error(
            status.HTTP_404_NOT_FOUND,
            "approval_not_found",
            "Approval request was not found in this user/workspace scope.",
            actor.request_id,
        )

    if approval.status == ApprovalStatus.PENDING and is_expired(approval.expires_at):
        approval.status = ApprovalStatus.EXPIRED
        approval.updated_at = utc_now()
        service.approval_repository.update(approval)

    await service.write_audit_event(
        actor=actor,
        action="security.approval.get",
        category=approval.category,
        event_status=AuditEventStatus.SUCCESS,
        message="Approval request retrieved.",
        target_type="approval_request",
        target_id=approval.id,
        risk_level=approval.risk_level,
        details={"approval_id": approval.id},
    )

    return SecurityResponse(
        ok=True,
        message="Approval request retrieved successfully.",
        data={"approval": approval.visible_dict()},
        request_id=actor.request_id,
    )


@router.post("/approvals/search", response_model=ApprovalSearchResponse)
async def search_approval_requests(
    payload: ApprovalSearchRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Security = Depends(get_security_service),
) -> ApprovalSearchResponse:
    """
    Search approval requests within user/workspace scope.
    """

    approvals, total = await service.search_approvals(actor, payload)

    return ApprovalSearchResponse(
        ok=True,
        message="Approval search completed successfully.",
        approvals=[approval.visible_dict() for approval in approvals],
        total=total,
        limit=payload.limit,
        offset=payload.offset,
        request_id=actor.request_id,
    )


@router.get("/approvals", response_model=ApprovalSearchResponse)
async def list_approval_requests(
    actor: ActorContext = Depends(get_actor_context),
    service: Security = Depends(get_security_service),
    status_filter: Optional[ApprovalStatus] = Query(default=None, alias="status"),
    category: Optional[SecurityActionCategory] = Query(default=None),
    risk_level: Optional[RiskLevel] = Query(default=None),
    query: Optional[str] = Query(default=None, max_length=500),
    limit: int = Query(default=25, ge=1, le=MAX_APPROVAL_SEARCH_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> ApprovalSearchResponse:
    """
    Lightweight approval list endpoint for dashboards.
    """

    payload = ApprovalSearchRequest(
        query=query,
        statuses=[status_filter] if status_filter else [],
        categories=[category] if category else [],
        risk_levels=[risk_level] if risk_level else [],
        limit=limit,
        offset=offset,
    )

    approvals, total = await service.search_approvals(actor, payload)

    return ApprovalSearchResponse(
        ok=True,
        message="Approval list retrieved successfully.",
        approvals=[approval.visible_dict() for approval in approvals],
        total=total,
        limit=limit,
        offset=offset,
        request_id=actor.request_id,
    )


@router.post("/audit", response_model=SecurityResponse, status_code=status.HTTP_201_CREATED)
async def create_audit_log(
    payload: AuditLogCreateRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Security = Depends(get_security_service),
) -> SecurityResponse:
    """
    Create an audit log event.

    This is useful for internal route modules that need to record state-changing
    actions before a central audit service exists.
    """

    audit_log, verification = await service.create_audit_log(actor, payload)

    return SecurityResponse(
        ok=True,
        message="Audit log created successfully.",
        data={"audit_log": audit_log.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


@router.post("/audit/search", response_model=AuditSearchResponse)
async def search_audit_logs(
    payload: AuditSearchRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Security = Depends(get_security_service),
) -> AuditSearchResponse:
    """
    Search audit logs inside the current user/workspace boundary.
    """

    logs, total = await service.search_audit_logs(actor, payload)

    return AuditSearchResponse(
        ok=True,
        message="Audit search completed successfully.",
        logs=[log.visible_dict() for log in logs],
        total=total,
        limit=payload.limit,
        offset=payload.offset,
        request_id=actor.request_id,
    )


@router.get("/audit", response_model=AuditSearchResponse)
async def list_audit_logs(
    actor: ActorContext = Depends(get_actor_context),
    service: Security = Depends(get_security_service),
    query: Optional[str] = Query(default=None, max_length=500),
    category: Optional[SecurityActionCategory] = Query(default=None),
    event_status: Optional[AuditEventStatus] = Query(default=None, alias="status"),
    risk_level: Optional[RiskLevel] = Query(default=None),
    target_type: Optional[str] = Query(default=None, max_length=120),
    target_id: Optional[str] = Query(default=None, max_length=140),
    limit: int = Query(default=25, ge=1, le=MAX_AUDIT_SEARCH_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> AuditSearchResponse:
    """
    Lightweight audit list endpoint for dashboards.
    """

    payload = AuditSearchRequest(
        query=query,
        categories=[category] if category else [],
        statuses=[event_status] if event_status else [],
        risk_levels=[risk_level] if risk_level else [],
        target_type=target_type,
        target_id=target_id,
        limit=limit,
        offset=offset,
    )

    logs, total = await service.search_audit_logs(actor, payload)

    return AuditSearchResponse(
        ok=True,
        message="Audit list retrieved successfully.",
        logs=[log.visible_dict() for log in logs],
        total=total,
        limit=limit,
        offset=offset,
        request_id=actor.request_id,
    )


@router.get("/health/status", response_model=SecurityResponse)
async def security_health(
    actor: ActorContext = Depends(get_actor_context),
    service: Security = Depends(get_security_service),
) -> SecurityResponse:
    """
    Scoped module health/status endpoint.
    """

    service.enforce_subscription(actor)

    approval_records = service.approval_repository.query(
        user_id=actor.user_id,
        workspace_id=actor.workspace_id,
    )

    audit_records = service.audit_repository.query(
        user_id=actor.user_id,
        workspace_id=actor.workspace_id,
    )

    pending_count = len([item for item in approval_records if item.status == ApprovalStatus.PENDING])
    approved_count = len([item for item in approval_records if item.status == ApprovalStatus.APPROVED])
    denied_count = len([item for item in approval_records if item.status == ApprovalStatus.DENIED])

    return SecurityResponse(
        ok=True,
        message="Security module is available.",
        data={
            "module": "security",
            "status": "healthy",
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "role": actor.role.value,
            "plan": actor.plan.value,
            "subscription_active": actor.subscription_active,
            "security_dashboard_allowed": plan_allows_security_dashboard(actor.plan),
            "approval_counts": {
                "total": len(approval_records),
                "pending": pending_count,
                "approved": approved_count,
                "denied": denied_count,
            },
            "audit_log_count": len(audit_records),
            "settings": {
                "auto_approve_low_risk": AUTO_APPROVE_LOW_RISK,
                "auto_deny_critical_without_admin": AUTO_DENY_CRITICAL_WITHOUT_ADMIN,
                "default_approval_expiry_minutes": DEFAULT_APPROVAL_EXPIRY_MINUTES,
            },
        },
        request_id=actor.request_id,
    )


# =============================================================================
# Service-compatible helper functions
# =============================================================================

async def require_security_approval(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compatibility hook for other modules.

    Other route/service files can import this function later:
        from apps.api.routes.security import require_security_approval

    Expected payload:
    {
        "action": "memory.export",
        "risk_level": "high",
        "user_id": "...",
        "workspace_id": "...",
        "role": "admin",
        "plan": "pro",
        "request_id": "...",
        "payload": {...}
    }

    Return:
    {
        "approved": bool,
        "decision": "...",
        "risk_level": "...",
        "approval_id": optional
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

    requested_risk = payload.get("risk_level") or "medium"
    risk_level = RiskLevel.MEDIUM
    for item in RiskLevel:
        if item.value == str(requested_risk).lower():
            risk_level = item

    request = RiskDecisionRequest(
        action=str(payload.get("action") or "unknown.security_action"),
        category=SecurityActionCategory.GENERAL,
        payload=payload.get("payload") if isinstance(payload.get("payload"), dict) else {},
        requested_risk_level=risk_level,
        reason="Security approval requested by internal module.",
    )

    decision, _ = await security_service.decide_risky_action(actor, request)

    return {
        "approved": decision["outcome"] == DecisionOutcome.APPROVED.value,
        "decision": decision["outcome"],
        "risk_level": decision["risk_level"],
        "approval_id": decision.get("approval_id"),
        "reason": decision["reason"],
        "mode": decision["decision_mode"],
    }


async def audit_log(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Compatibility hook for other modules.

    Other route/service files can import:
        from apps.api.routes.security import audit_log
    """

    actor = ActorContext(
        user_id=normalize_id(str(payload.get("user_id")), "user_id"),
        workspace_id=normalize_id(str(payload.get("workspace_id")), "workspace_id"),
        role=parse_role(str(payload.get("role") or "member")),
        plan=parse_plan(str(payload.get("plan") or "free")),
        subscription_active=True,
        request_id=str(payload.get("request_id") or uuid.uuid4()),
        ip_address=payload.get("ip_address"),
        user_agent=payload.get("user_agent"),
    )

    category_value = str(payload.get("category") or payload.get("target_type") or "general").lower()
    category = SecurityActionCategory.GENERAL
    for item in SecurityActionCategory:
        if item.value == category_value:
            category = item

    status_value = str(payload.get("status") or "success").lower()
    event_status = AuditEventStatus.SUCCESS
    for item in AuditEventStatus:
        if item.value == status_value:
            event_status = item

    risk_value = payload.get("risk_level")
    risk_level: Optional[RiskLevel] = None
    if risk_value:
        for item in RiskLevel:
            if item.value == str(risk_value).lower():
                risk_level = item

    record = await security_service.write_audit_event(
        actor=actor,
        action=str(payload.get("action") or "audit.event"),
        category=category,
        event_status=event_status,
        message=str(payload.get("message") or "Audit event recorded."),
        target_type=payload.get("target_type"),
        target_id=payload.get("target_id"),
        risk_level=risk_level,
        details=payload.get("details") if isinstance(payload.get("details"), dict) else {},
    )

    return {
        "ok": True,
        "audit_id": record.id,
        "request_id": actor.request_id,
    }


__all__ = [
    "router",
    "Security",
    "ActorContext",
    "RiskLevel",
    "ApprovalStatus",
    "DecisionOutcome",
    "AuditEventStatus",
    "SecurityActionCategory",
    "ApprovalCreateRequest",
    "ApprovalDecisionRequest",
    "RiskDecisionRequest",
    "AuditLogCreateRequest",
    "AuditSearchRequest",
    "ApprovalSearchRequest",
    "SecurityResponse",
    "ApprovalSearchResponse",
    "AuditSearchResponse",
    "require_security_approval",
    "audit_log",
]