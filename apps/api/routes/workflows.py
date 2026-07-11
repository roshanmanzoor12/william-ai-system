"""
apps/api/routes/workflows.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Agent/Module: API Prompt Bible
Purpose: workflow templates, run workflow, webhook management

This module is intentionally import-safe:
- It does not require future project files to exist.
- It uses in-memory fallback repositories for early development.
- It exposes clean service hooks for future Master Agent, Security Agent,
  Memory Agent, Verification Agent, audit logging, registry/plugin loading,
  and persistent database repositories.

Core responsibilities:
- Create/list/get/update/delete workflow templates.
- Run workflows with user_id and workspace_id isolation.
- Track workflow run status and history.
- Create/list/get/update/delete webhooks.
- Trigger workflow runs from webhooks.
- Route risky/sensitive actions to Security Agent.
- Prepare Verification Agent payloads after completed actions.
- Preserve useful context for Memory Agent.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
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
# Optional future integrations
# =============================================================================

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
    from apps.api.services.master_agent import run_workflow as project_master_run_workflow  # type: ignore
except Exception:
    project_master_run_workflow = None

try:
    from apps.api.services.master_agent import notify_master_agent as project_notify_master_agent  # type: ignore
except Exception:
    project_notify_master_agent = None

# Real, JWT-verified auth -- apps/api/routes/auth.py is a core module (not a
# "future" one), so this import should always succeed; the fallback exists
# only for a genuinely broken install, matching the same defensive pattern
# apps/api/routes/tasks.py already uses for the same dependency.
try:
    from apps.api.routes.auth import AuthContext as RealAuthContext, get_current_auth_context  # type: ignore
except Exception as real_auth_import_exc:
    RealAuthContext = None
    get_current_auth_context = None
    logging.getLogger(__name__).warning(
        "Real auth import fallback enabled in workflows.py: %s", real_auth_import_exc
    )


# =============================================================================
# Router
# =============================================================================

router = APIRouter(tags=["Workflows"])
# No self-prefix -- apps/api/main.py's OPTIONAL_ROUTERS supplies
# "/workflows" as this router's default_prefix once mounted below.


# =============================================================================
# Safe environment defaults
# =============================================================================

APP_NAME = os.getenv("WILLIAM_APP_NAME", "William Jarvis")
MAX_TEMPLATE_STEPS = int(os.getenv("WILLIAM_WORKFLOW_MAX_TEMPLATE_STEPS", "50"))
MAX_RUN_INPUT_BYTES = int(os.getenv("WILLIAM_WORKFLOW_MAX_RUN_INPUT_BYTES", "100000"))
MAX_WEBHOOK_PAYLOAD_BYTES = int(os.getenv("WILLIAM_WORKFLOW_MAX_WEBHOOK_PAYLOAD_BYTES", "250000"))
MAX_SEARCH_LIMIT = int(os.getenv("WILLIAM_WORKFLOW_MAX_SEARCH_LIMIT", "100"))
MAX_FREE_TEMPLATES = int(os.getenv("WILLIAM_WORKFLOW_FREE_TEMPLATE_LIMIT", "5"))
MAX_PRO_TEMPLATES = int(os.getenv("WILLIAM_WORKFLOW_PRO_TEMPLATE_LIMIT", "100"))
MAX_BUSINESS_TEMPLATES = int(os.getenv("WILLIAM_WORKFLOW_BUSINESS_TEMPLATE_LIMIT", "1000"))
MAX_ENTERPRISE_TEMPLATES = int(os.getenv("WILLIAM_WORKFLOW_ENTERPRISE_TEMPLATE_LIMIT", "10000"))
REQUIRE_SECURITY_FOR_WEBHOOKS = os.getenv("WILLIAM_REQUIRE_SECURITY_FOR_WEBHOOKS", "true").lower() == "true"
REQUIRE_SECURITY_FOR_TEMPLATE_DELETE = os.getenv("WILLIAM_REQUIRE_SECURITY_FOR_WORKFLOW_DELETE", "true").lower() == "true"
REQUIRE_SECURITY_FOR_EXTERNAL_ACTIONS = os.getenv("WILLIAM_REQUIRE_SECURITY_FOR_EXTERNAL_WORKFLOW_ACTIONS", "true").lower() == "true"
WEBHOOK_SECRET_PEPPER = os.getenv("WILLIAM_WEBHOOK_SECRET_PEPPER", "")


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


class WorkflowStatus(str, Enum):
    DRAFT = "draft"
    ACTIVE = "active"
    PAUSED = "paused"
    ARCHIVED = "archived"


class WorkflowRunStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class WorkflowStepType(str, Enum):
    MASTER_AGENT = "master_agent"
    AGENT = "agent"
    TOOL = "tool"
    HTTP_REQUEST = "http_request"
    WEBHOOK_RESPONSE = "webhook_response"
    MEMORY_SAVE = "memory_save"
    SECURITY_APPROVAL = "security_approval"
    CONDITION = "condition"
    DELAY = "delay"
    NOTIFICATION = "notification"


class WorkflowTriggerType(str, Enum):
    MANUAL = "manual"
    WEBHOOK = "webhook"
    SCHEDULE = "schedule"
    SYSTEM = "system"
    AGENT = "agent"


class WebhookStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    REVOKED = "revoked"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AuditStatus(str, Enum):
    SUCCESS = "success"
    DENIED = "denied"
    ERROR = "error"
    PENDING = "pending"


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
class WorkflowTemplateRecord:
    id: str
    user_id: str
    workspace_id: str
    name: str
    description: Optional[str]
    status: WorkflowStatus
    steps: List[Dict[str, Any]]
    trigger_types: List[WorkflowTriggerType]
    tags: List[str]
    metadata: Dict[str, Any]
    created_by: str
    updated_by: str
    created_at: str
    updated_at: str
    deleted_at: Optional[str] = None

    def visible_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowRunRecord:
    id: str
    user_id: str
    workspace_id: str
    template_id: str
    trigger_type: WorkflowTriggerType
    status: WorkflowRunStatus
    input_data: Dict[str, Any]
    output_data: Dict[str, Any]
    current_step_index: int
    step_events: List[Dict[str, Any]]
    approval_id: Optional[str]
    error: Optional[str]
    created_by: str
    started_at: Optional[str]
    completed_at: Optional[str]
    created_at: str
    updated_at: str
    metadata: Dict[str, Any]

    def visible_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WebhookRecord:
    id: str
    user_id: str
    workspace_id: str
    template_id: str
    name: str
    status: WebhookStatus
    secret_hash: str
    allowed_event_types: List[str]
    tags: List[str]
    metadata: Dict[str, Any]
    created_by: str
    updated_by: str
    created_at: str
    updated_at: str
    last_triggered_at: Optional[str] = None
    revoked_at: Optional[str] = None

    def visible_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data.pop("secret_hash", None)
        return data


# =============================================================================
# Schemas
# =============================================================================

class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class WorkflowStep(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), max_length=140)
    name: str = Field(..., min_length=2, max_length=180)
    step_type: WorkflowStepType
    agent_name: Optional[str] = Field(default=None, max_length=120)
    tool_name: Optional[str] = Field(default=None, max_length=120)
    config: Dict[str, Any] = Field(default_factory=dict)
    requires_security_approval: bool = False
    risk_level: RiskLevel = RiskLevel.LOW
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    retry_count: int = Field(default=0, ge=0, le=5)

    @field_validator("config")
    @classmethod
    def validate_config_size(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        serialized = json.dumps(value, default=str)
        if len(serialized) > 50000:
            raise ValueError("Step config is too large.")
        return value


class WorkflowTemplateCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=180)
    description: Optional[str] = Field(default=None, max_length=1500)
    status: WorkflowStatus = WorkflowStatus.DRAFT
    steps: List[WorkflowStep] = Field(..., min_length=1, max_length=MAX_TEMPLATE_STEPS)
    trigger_types: List[WorkflowTriggerType] = Field(default_factory=lambda: [WorkflowTriggerType.MANUAL])
    tags: List[str] = Field(default_factory=list, max_length=50)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def clean_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Workflow name cannot be empty.")
        return cleaned

    @field_validator("tags")
    @classmethod
    def clean_tags(cls, value: List[str]) -> List[str]:
        return normalize_tags(value)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        serialized = json.dumps(value, default=str)
        if len(serialized) > 25000:
            raise ValueError("Metadata is too large.")
        return value


class WorkflowTemplateUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=180)
    description: Optional[str] = Field(default=None, max_length=1500)
    status: Optional[WorkflowStatus] = None
    steps: Optional[List[WorkflowStep]] = Field(default=None, min_length=1, max_length=MAX_TEMPLATE_STEPS)
    trigger_types: Optional[List[WorkflowTriggerType]] = None
    tags: Optional[List[str]] = Field(default=None, max_length=50)
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("tags")
    @classmethod
    def clean_tags(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return value
        return normalize_tags(value)


class WorkflowRunRequest(BaseModel):
    template_id: str = Field(..., min_length=2, max_length=140)
    trigger_type: WorkflowTriggerType = WorkflowTriggerType.MANUAL
    input_data: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False

    @field_validator("input_data")
    @classmethod
    def validate_input_data(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        serialized = json.dumps(value, default=str)
        if len(serialized.encode("utf-8")) > MAX_RUN_INPUT_BYTES:
            raise ValueError("Workflow input is too large.")
        return value


class WorkflowSearchRequest(BaseModel):
    query: Optional[str] = Field(default=None, max_length=500)
    statuses: List[WorkflowStatus] = Field(default_factory=list)
    trigger_types: List[WorkflowTriggerType] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    include_deleted: bool = False
    limit: int = Field(default=25, ge=1, le=MAX_SEARCH_LIMIT)
    offset: int = Field(default=0, ge=0)


class WorkflowRunSearchRequest(BaseModel):
    template_id: Optional[str] = Field(default=None, max_length=140)
    statuses: List[WorkflowRunStatus] = Field(default_factory=list)
    trigger_types: List[WorkflowTriggerType] = Field(default_factory=list)
    limit: int = Field(default=25, ge=1, le=MAX_SEARCH_LIMIT)
    offset: int = Field(default=0, ge=0)


class WebhookCreateRequest(BaseModel):
    template_id: str = Field(..., min_length=2, max_length=140)
    name: str = Field(..., min_length=2, max_length=180)
    allowed_event_types: List[str] = Field(default_factory=list, max_length=50)
    tags: List[str] = Field(default_factory=list, max_length=50)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("allowed_event_types")
    @classmethod
    def clean_events(cls, value: List[str]) -> List[str]:
        cleaned: List[str] = []
        seen = set()
        for item in value:
            event = re.sub(r"[^a-zA-Z0-9_.:\-]", "", str(item).strip())
            if event and event not in seen:
                seen.add(event)
                cleaned.append(event[:120])
        return cleaned

    @field_validator("tags")
    @classmethod
    def clean_tags(cls, value: List[str]) -> List[str]:
        return normalize_tags(value)


class WebhookUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=180)
    status: Optional[WebhookStatus] = None
    allowed_event_types: Optional[List[str]] = Field(default=None, max_length=50)
    tags: Optional[List[str]] = Field(default=None, max_length=50)
    metadata: Optional[Dict[str, Any]] = None
    rotate_secret: bool = False

    @field_validator("tags")
    @classmethod
    def clean_tags(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return value
        return normalize_tags(value)


class WebhookTriggerRequest(BaseModel):
    event_type: str = Field(default="default", max_length=120)
    payload: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("payload")
    @classmethod
    def validate_payload(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        serialized = json.dumps(value, default=str)
        if len(serialized.encode("utf-8")) > MAX_WEBHOOK_PAYLOAD_BYTES:
            raise ValueError("Webhook payload is too large.")
        return value


class WorkflowResponse(BaseModel):
    ok: bool
    message: str
    data: Dict[str, Any] = Field(default_factory=dict)
    verification: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


class WorkflowTemplateSearchResponse(BaseModel):
    ok: bool
    message: str
    templates: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int
    request_id: Optional[str] = None


class WorkflowRunSearchResponse(BaseModel):
    ok: bool
    message: str
    runs: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int
    request_id: Optional[str] = None


class WebhookSearchResponse(BaseModel):
    ok: bool
    message: str
    webhooks: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int
    request_id: Optional[str] = None


# =============================================================================
# Utility helpers
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


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

    if len(cleaned) > 140:
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


def normalize_tags(value: Sequence[str]) -> List[str]:
    cleaned: List[str] = []
    seen = set()

    for tag in value:
        normalized = str(tag).strip().lower()
        normalized = re.sub(r"[^a-z0-9_\-\s]", "", normalized)
        normalized = re.sub(r"\s+", "-", normalized)
        if normalized and normalized not in seen:
            seen.add(normalized)
            cleaned.append(normalized[:60])

    return cleaned


def safe_json(data: Any) -> Any:
    try:
        json.dumps(data, default=str)
        return data
    except Exception:
        return {"serialization_warning": "Original value could not be serialized safely."}


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        for key, nested in value.items():
            key_lower = str(key).lower()
            if key_lower in SENSITIVE_PAYLOAD_KEYS or any(item in key_lower for item in SENSITIVE_PAYLOAD_KEYS):
                result[key] = "***REDACTED***"
            else:
                result[key] = redact_sensitive(nested)
        return result

    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]

    return value


def template_limit_for_plan(plan: SubscriptionPlan) -> int:
    limits = {
        SubscriptionPlan.FREE: MAX_FREE_TEMPLATES,
        SubscriptionPlan.PRO: MAX_PRO_TEMPLATES,
        SubscriptionPlan.BUSINESS: MAX_BUSINESS_TEMPLATES,
        SubscriptionPlan.ENTERPRISE: MAX_ENTERPRISE_TEMPLATES,
    }
    return limits.get(plan, MAX_FREE_TEMPLATES)


def can_create_template(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER, UserRole.MEMBER}


def can_update_template(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER, UserRole.MEMBER}


def can_delete_template(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER}


def can_run_workflow(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER, UserRole.MEMBER}


def can_manage_webhooks(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER}


def can_view_workflows(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER, UserRole.MEMBER, UserRole.VIEWER}


def plan_allows_webhooks(plan: SubscriptionPlan) -> bool:
    return plan in {SubscriptionPlan.PRO, SubscriptionPlan.BUSINESS, SubscriptionPlan.ENTERPRISE}


def hash_webhook_secret(secret: str) -> str:
    material = f"{secret}:{WEBHOOK_SECRET_PEPPER}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def generate_webhook_secret() -> str:
    return f"whsec_{uuid.uuid4().hex}_{uuid.uuid4().hex}"


def verify_webhook_secret(provided_secret: str, stored_hash: str) -> bool:
    return hmac.compare_digest(hash_webhook_secret(provided_secret), stored_hash)


def workflow_has_external_or_sensitive_steps(steps: Sequence[Dict[str, Any]]) -> bool:
    for step in steps:
        step_type = step.get("step_type") or step.get("type")
        requires_security = bool(step.get("requires_security_approval", False))
        risk_level = str(step.get("risk_level", "low")).lower()

        if requires_security:
            return True

        if risk_level in {"high", "critical"}:
            return True

        if step_type in {
            WorkflowStepType.HTTP_REQUEST.value,
            WorkflowStepType.TOOL.value,
            WorkflowStepType.WEBHOOK_RESPONSE.value,
        }:
            return True

    return False


# =============================================================================
# Fallback repositories
# =============================================================================

class InMemoryWorkflowTemplateRepository:
    def __init__(self) -> None:
        self._items: Dict[str, WorkflowTemplateRecord] = {}
        self._lock = RLock()

    def count_scoped(self, user_id: str, workspace_id: str, include_deleted: bool = False) -> int:
        with self._lock:
            count = 0
            for record in self._items.values():
                if record.user_id != user_id or record.workspace_id != workspace_id:
                    continue
                if not include_deleted and record.deleted_at is not None:
                    continue
                count += 1
            return count

    def save(self, record: WorkflowTemplateRecord) -> WorkflowTemplateRecord:
        with self._lock:
            self._items[record.id] = record
            return record

    def update(self, record: WorkflowTemplateRecord) -> WorkflowTemplateRecord:
        with self._lock:
            self._items[record.id] = record
            return record

    def get_scoped(
        self,
        template_id: str,
        user_id: str,
        workspace_id: str,
        include_deleted: bool = False,
    ) -> Optional[WorkflowTemplateRecord]:
        with self._lock:
            record = self._items.get(template_id)
            if record is None:
                return None
            if record.user_id != user_id or record.workspace_id != workspace_id:
                return None
            if not include_deleted and record.deleted_at is not None:
                return None
            return record

    def query(
        self,
        user_id: str,
        workspace_id: str,
        query: Optional[str] = None,
        statuses: Optional[Sequence[WorkflowStatus]] = None,
        trigger_types: Optional[Sequence[WorkflowTriggerType]] = None,
        tags: Optional[Sequence[str]] = None,
        include_deleted: bool = False,
    ) -> List[WorkflowTemplateRecord]:
        query_normalized = query.strip().lower() if query else None
        status_set = {item.value if isinstance(item, WorkflowStatus) else str(item) for item in (statuses or [])}
        trigger_set = {item.value if isinstance(item, WorkflowTriggerType) else str(item) for item in (trigger_types or [])}
        tag_set = set(normalize_tags(tags or []))

        with self._lock:
            results: List[WorkflowTemplateRecord] = []

            for record in self._items.values():
                if record.user_id != user_id or record.workspace_id != workspace_id:
                    continue
                if not include_deleted and record.deleted_at is not None:
                    continue
                if status_set and record.status.value not in status_set:
                    continue
                if trigger_set and not trigger_set.intersection({item.value for item in record.trigger_types}):
                    continue
                if tag_set and not tag_set.intersection(set(record.tags)):
                    continue

                if query_normalized:
                    haystack = " ".join(
                        [
                            record.name,
                            record.description or "",
                            " ".join(record.tags),
                            json.dumps(record.metadata, default=str),
                        ]
                    ).lower()
                    if query_normalized not in haystack:
                        continue

                results.append(record)

            results.sort(key=lambda item: item.updated_at, reverse=True)
            return results


class InMemoryWorkflowRunRepository:
    def __init__(self) -> None:
        self._items: Dict[str, WorkflowRunRecord] = {}
        self._lock = RLock()

    def save(self, record: WorkflowRunRecord) -> WorkflowRunRecord:
        with self._lock:
            self._items[record.id] = record
            return record

    def update(self, record: WorkflowRunRecord) -> WorkflowRunRecord:
        with self._lock:
            self._items[record.id] = record
            return record

    def get_scoped(self, run_id: str, user_id: str, workspace_id: str) -> Optional[WorkflowRunRecord]:
        with self._lock:
            record = self._items.get(run_id)
            if record is None:
                return None
            if record.user_id != user_id or record.workspace_id != workspace_id:
                return None
            return record

    def query(
        self,
        user_id: str,
        workspace_id: str,
        template_id: Optional[str] = None,
        statuses: Optional[Sequence[WorkflowRunStatus]] = None,
        trigger_types: Optional[Sequence[WorkflowTriggerType]] = None,
    ) -> List[WorkflowRunRecord]:
        status_set = {item.value if isinstance(item, WorkflowRunStatus) else str(item) for item in (statuses or [])}
        trigger_set = {item.value if isinstance(item, WorkflowTriggerType) else str(item) for item in (trigger_types or [])}

        with self._lock:
            results: List[WorkflowRunRecord] = []

            for record in self._items.values():
                if record.user_id != user_id or record.workspace_id != workspace_id:
                    continue
                if template_id and record.template_id != template_id:
                    continue
                if status_set and record.status.value not in status_set:
                    continue
                if trigger_set and record.trigger_type.value not in trigger_set:
                    continue
                results.append(record)

            results.sort(key=lambda item: item.updated_at, reverse=True)
            return results


class InMemoryWebhookRepository:
    def __init__(self) -> None:
        self._items: Dict[str, WebhookRecord] = {}
        self._lock = RLock()

    def save(self, record: WebhookRecord) -> WebhookRecord:
        with self._lock:
            self._items[record.id] = record
            return record

    def update(self, record: WebhookRecord) -> WebhookRecord:
        with self._lock:
            self._items[record.id] = record
            return record

    def get_scoped(
        self,
        webhook_id: str,
        user_id: str,
        workspace_id: str,
    ) -> Optional[WebhookRecord]:
        with self._lock:
            record = self._items.get(webhook_id)
            if record is None:
                return None
            if record.user_id != user_id or record.workspace_id != workspace_id:
                return None
            return record

    def query(
        self,
        user_id: str,
        workspace_id: str,
        template_id: Optional[str] = None,
        statuses: Optional[Sequence[WebhookStatus]] = None,
    ) -> List[WebhookRecord]:
        status_set = {item.value if isinstance(item, WebhookStatus) else str(item) for item in (statuses or [])}

        with self._lock:
            results: List[WebhookRecord] = []

            for record in self._items.values():
                if record.user_id != user_id or record.workspace_id != workspace_id:
                    continue
                if template_id and record.template_id != template_id:
                    continue
                if status_set and record.status.value not in status_set:
                    continue
                results.append(record)

            results.sort(key=lambda item: item.updated_at, reverse=True)
            return results


_template_repository = InMemoryWorkflowTemplateRepository()
_run_repository = InMemoryWorkflowRunRepository()
_webhook_repository = InMemoryWebhookRepository()


# =============================================================================
# Main component
# =============================================================================

class Workflows:
    """
    Required class/component name: Workflows

    Central workflow API component for:
    - workflow templates
    - workflow runs
    - webhook management
    - future Master Agent execution handoff
    """

    def __init__(
        self,
        template_repository: Optional[InMemoryWorkflowTemplateRepository] = None,
        run_repository: Optional[InMemoryWorkflowRunRepository] = None,
        webhook_repository: Optional[InMemoryWebhookRepository] = None,
        audit_hook: Optional[Callable[..., Any]] = None,
        security_hook: Optional[Callable[..., Any]] = None,
        verification_hook: Optional[Callable[..., Any]] = None,
        memory_agent_hook: Optional[Callable[..., Any]] = None,
        master_run_hook: Optional[Callable[..., Any]] = None,
        master_notify_hook: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.template_repository = template_repository or _template_repository
        self.run_repository = run_repository or _run_repository
        self.webhook_repository = webhook_repository or _webhook_repository
        self.audit_hook = audit_hook or project_audit_log
        self.security_hook = security_hook or project_security_approval
        self.verification_hook = verification_hook or project_prepare_verification
        self.memory_agent_hook = memory_agent_hook or project_memory_agent_index
        self.master_run_hook = master_run_hook or project_master_run_workflow
        self.master_notify_hook = master_notify_hook or project_notify_master_agent

    def enforce_subscription(self, actor: ActorContext) -> None:
        if not actor.subscription_active:
            raise_safe_error(
                status.HTTP_402_PAYMENT_REQUIRED,
                "subscription_inactive",
                "Your subscription is inactive. Workflow access is currently unavailable.",
                actor.request_id,
            )

    def enforce_view_access(self, actor: ActorContext) -> None:
        self.enforce_subscription(actor)
        if not can_view_workflows(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_view_workflows",
                "Your role does not allow viewing workflows.",
                actor.request_id,
                {"role": actor.role.value},
            )

    def enforce_create_access(self, actor: ActorContext) -> None:
        self.enforce_subscription(actor)
        if not can_create_template(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_create_workflow",
                "Your role does not allow creating workflow templates.",
                actor.request_id,
                {"role": actor.role.value},
            )

    def enforce_update_access(self, actor: ActorContext) -> None:
        self.enforce_subscription(actor)
        if not can_update_template(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_update_workflow",
                "Your role does not allow updating workflow templates.",
                actor.request_id,
                {"role": actor.role.value},
            )

    def enforce_delete_access(self, actor: ActorContext) -> None:
        self.enforce_subscription(actor)
        if not can_delete_template(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_delete_workflow",
                "Your role does not allow deleting workflow templates.",
                actor.request_id,
                {"role": actor.role.value},
            )

    def enforce_run_access(self, actor: ActorContext) -> None:
        self.enforce_subscription(actor)
        if not can_run_workflow(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_run_workflow",
                "Your role does not allow running workflows.",
                actor.request_id,
                {"role": actor.role.value},
            )

    def enforce_webhook_access(self, actor: ActorContext) -> None:
        self.enforce_subscription(actor)

        if not plan_allows_webhooks(actor.plan):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "plan_does_not_allow_webhooks",
                "Your current plan does not include webhook management.",
                actor.request_id,
                {"plan": actor.plan.value},
            )

        if not can_manage_webhooks(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_manage_webhooks",
                "Your role does not allow managing webhooks.",
                actor.request_id,
                {"role": actor.role.value},
            )

    def enforce_template_quota(self, actor: ActorContext) -> None:
        current_count = self.template_repository.count_scoped(actor.user_id, actor.workspace_id, include_deleted=False)
        allowed_count = template_limit_for_plan(actor.plan)

        if current_count >= allowed_count:
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "workflow_template_quota_exceeded",
                "Workflow template quota exceeded for this subscription plan.",
                actor.request_id,
                {
                    "current_count": current_count,
                    "allowed_count": allowed_count,
                    "plan": actor.plan.value,
                },
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
            "category": "workflow",
            "status": event_status.value,
            "target_type": "workflow",
            "target_id": target_id,
            "risk_level": risk_level.value if risk_level else None,
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "role": actor.role.value,
            "plan": actor.plan.value,
            "request_id": actor.request_id,
            "ip_address": actor.ip_address,
            "user_agent": actor.user_agent,
            "details": redact_sensitive(details or {}),
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
            "payload": redact_sensitive(payload),
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
                            "Security Agent did not approve this workflow action.",
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
                    "Security Agent could not validate this workflow action.",
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
            "module": "workflows",
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
            "module": "workflows",
            "event_type": event_type,
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "request_id": actor.request_id,
            "payload": redact_sensitive(payload),
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
            "module": "workflows",
            "event_type": event_type,
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "request_id": actor.request_id,
            "payload": redact_sensitive(payload),
            "created_at": utc_now(),
        }

        if callable(self.master_notify_hook):
            try:
                result = self.master_notify_hook(message)
                if hasattr(result, "__await__"):
                    await result
            except Exception:
                return

    async def create_template(
        self,
        actor: ActorContext,
        payload: WorkflowTemplateCreateRequest,
    ) -> Tuple[WorkflowTemplateRecord, Dict[str, Any]]:
        self.enforce_create_access(actor)
        self.enforce_template_quota(actor)

        serialized_steps = [step.model_dump() for step in payload.steps]

        if REQUIRE_SECURITY_FOR_EXTERNAL_ACTIONS and workflow_has_external_or_sensitive_steps(serialized_steps):
            await self.require_security(
                actor=actor,
                action="workflows.template.create_sensitive",
                risk_level=RiskLevel.HIGH,
                payload=payload.model_dump(),
            )

        now = utc_now()
        record = WorkflowTemplateRecord(
            id=str(uuid.uuid4()),
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            name=payload.name,
            description=payload.description,
            status=payload.status,
            steps=redact_sensitive(serialized_steps),
            trigger_types=payload.trigger_types,
            tags=payload.tags,
            metadata=redact_sensitive(payload.metadata),
            created_by=actor.user_id,
            updated_by=actor.user_id,
            created_at=now,
            updated_at=now,
        )

        saved = self.template_repository.save(record)

        await self.audit(
            actor,
            "workflows.template.create",
            AuditStatus.SUCCESS,
            target_id=saved.id,
            details={"template_id": saved.id, "name": saved.name, "status": saved.status.value},
        )

        await self.index_for_memory_agent(
            actor,
            "workflow_template_created",
            {"template_id": saved.id, "name": saved.name, "tags": saved.tags},
        )

        await self.notify_master_agent(
            actor,
            "workflow_template_created",
            {"template_id": saved.id, "status": saved.status.value},
        )

        verification = await self.prepare_verification(
            actor,
            "workflows.template.create",
            {"template_id": saved.id, "status": saved.status.value},
        )

        return saved, verification

    async def update_template(
        self,
        actor: ActorContext,
        template_id: str,
        payload: WorkflowTemplateUpdateRequest,
    ) -> Tuple[WorkflowTemplateRecord, Dict[str, Any]]:
        self.enforce_update_access(actor)

        record = self.template_repository.get_scoped(template_id, actor.user_id, actor.workspace_id)
        if record is None:
            raise_safe_error(
                status.HTTP_404_NOT_FOUND,
                "workflow_template_not_found",
                "Workflow template was not found in this user/workspace scope.",
                actor.request_id,
            )

        update_data = payload.model_dump(exclude_none=True)

        if "steps" in update_data:
            serialized_steps = [step.model_dump() if hasattr(step, "model_dump") else step for step in payload.steps or []]
            if REQUIRE_SECURITY_FOR_EXTERNAL_ACTIONS and workflow_has_external_or_sensitive_steps(serialized_steps):
                await self.require_security(
                    actor=actor,
                    action="workflows.template.update_sensitive",
                    risk_level=RiskLevel.HIGH,
                    payload={"template_id": template_id, "update": payload.model_dump(exclude_none=True)},
                )
            record.steps = redact_sensitive(serialized_steps)

        if payload.name is not None:
            record.name = payload.name.strip()
        if payload.description is not None:
            record.description = payload.description
        if payload.status is not None:
            record.status = payload.status
        if payload.trigger_types is not None:
            record.trigger_types = payload.trigger_types
        if payload.tags is not None:
            record.tags = payload.tags
        if payload.metadata is not None:
            record.metadata = redact_sensitive(payload.metadata)

        record.updated_by = actor.user_id
        record.updated_at = utc_now()

        updated = self.template_repository.update(record)

        await self.audit(
            actor,
            "workflows.template.update",
            AuditStatus.SUCCESS,
            target_id=updated.id,
            details={"template_id": updated.id, "fields": list(update_data.keys())},
        )

        await self.index_for_memory_agent(
            actor,
            "workflow_template_updated",
            {"template_id": updated.id, "fields": list(update_data.keys())},
        )

        verification = await self.prepare_verification(
            actor,
            "workflows.template.update",
            {"template_id": updated.id, "updated_at": updated.updated_at},
        )

        return updated, verification

    async def delete_template(
        self,
        actor: ActorContext,
        template_id: str,
        hard_delete: bool,
        reason: Optional[str],
    ) -> Tuple[WorkflowTemplateRecord, Dict[str, Any]]:
        self.enforce_delete_access(actor)

        record = self.template_repository.get_scoped(template_id, actor.user_id, actor.workspace_id, include_deleted=True)
        if record is None:
            raise_safe_error(
                status.HTTP_404_NOT_FOUND,
                "workflow_template_not_found",
                "Workflow template was not found in this user/workspace scope.",
                actor.request_id,
            )

        if REQUIRE_SECURITY_FOR_TEMPLATE_DELETE or hard_delete:
            await self.require_security(
                actor=actor,
                action="workflows.template.delete",
                risk_level=RiskLevel.HIGH if hard_delete else RiskLevel.MEDIUM,
                payload={"template_id": template_id, "hard_delete": hard_delete, "reason": reason},
            )

        if hard_delete:
            record.deleted_at = utc_now()
            record.status = WorkflowStatus.ARCHIVED
            record.metadata["hard_delete_requested"] = True
            record.metadata["hard_delete_note"] = "Fallback repository marks this as deleted. Database repository may physically remove it."
        else:
            record.deleted_at = utc_now()
            record.status = WorkflowStatus.ARCHIVED

        record.updated_at = utc_now()
        record.updated_by = actor.user_id
        updated = self.template_repository.update(record)

        await self.audit(
            actor,
            "workflows.template.delete",
            AuditStatus.SUCCESS,
            target_id=updated.id,
            details={"template_id": updated.id, "hard_delete": hard_delete, "reason": reason},
            risk_level=RiskLevel.HIGH if hard_delete else RiskLevel.MEDIUM,
        )

        verification = await self.prepare_verification(
            actor,
            "workflows.template.delete",
            {"template_id": updated.id, "hard_delete": hard_delete, "deleted_at": updated.deleted_at},
        )

        return updated, verification

    async def search_templates(
        self,
        actor: ActorContext,
        payload: WorkflowSearchRequest,
    ) -> Tuple[List[WorkflowTemplateRecord], int]:
        self.enforce_view_access(actor)

        include_deleted = payload.include_deleted and can_delete_template(actor.role)

        records = self.template_repository.query(
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            query=payload.query,
            statuses=payload.statuses,
            trigger_types=payload.trigger_types,
            tags=payload.tags,
            include_deleted=include_deleted,
        )

        total = len(records)
        page = records[payload.offset : payload.offset + payload.limit]

        await self.audit(
            actor,
            "workflows.template.search",
            AuditStatus.SUCCESS,
            details={"total": total, "query_present": bool(payload.query)},
        )

        return page, total

    async def get_template(self, actor: ActorContext, template_id: str) -> WorkflowTemplateRecord:
        self.enforce_view_access(actor)

        record = self.template_repository.get_scoped(template_id, actor.user_id, actor.workspace_id)
        if record is None:
            raise_safe_error(
                status.HTTP_404_NOT_FOUND,
                "workflow_template_not_found",
                "Workflow template was not found in this user/workspace scope.",
                actor.request_id,
            )

        await self.audit(
            actor,
            "workflows.template.get",
            AuditStatus.SUCCESS,
            target_id=record.id,
            details={"template_id": record.id},
        )

        return record

    async def run_workflow(
        self,
        actor: ActorContext,
        payload: WorkflowRunRequest,
    ) -> Tuple[WorkflowRunRecord, Dict[str, Any]]:
        self.enforce_run_access(actor)

        template_id = normalize_id(payload.template_id, "template_id", actor.request_id)
        template = self.template_repository.get_scoped(template_id, actor.user_id, actor.workspace_id)

        if template is None:
            raise_safe_error(
                status.HTTP_404_NOT_FOUND,
                "workflow_template_not_found",
                "Workflow template was not found in this user/workspace scope.",
                actor.request_id,
            )

        if template.status != WorkflowStatus.ACTIVE and not payload.dry_run:
            raise_safe_error(
                status.HTTP_409_CONFLICT,
                "workflow_template_not_active",
                "Only active workflow templates can be run. Use dry_run for testing drafts.",
                actor.request_id,
                {"template_status": template.status.value},
            )

        if payload.trigger_type not in template.trigger_types and payload.trigger_type != WorkflowTriggerType.SYSTEM:
            raise_safe_error(
                status.HTTP_400_BAD_REQUEST,
                "trigger_type_not_allowed",
                "This workflow template does not allow the requested trigger type.",
                actor.request_id,
                {
                    "requested_trigger": payload.trigger_type.value,
                    "allowed_triggers": [item.value for item in template.trigger_types],
                },
            )

        if workflow_has_external_or_sensitive_steps(template.steps):
            security_result = await self.require_security(
                actor=actor,
                action="workflows.run_sensitive",
                risk_level=RiskLevel.HIGH,
                payload={
                    "template_id": template.id,
                    "trigger_type": payload.trigger_type.value,
                    "input_data": payload.input_data,
                    "dry_run": payload.dry_run,
                },
            )
            approval_id = security_result.get("approval_id")
        else:
            approval_id = None

        now = utc_now()
        run = WorkflowRunRecord(
            id=str(uuid.uuid4()),
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            template_id=template.id,
            trigger_type=payload.trigger_type,
            status=WorkflowRunStatus.QUEUED,
            input_data=redact_sensitive(payload.input_data),
            output_data={},
            current_step_index=0,
            step_events=[],
            approval_id=approval_id,
            error=None,
            created_by=actor.user_id,
            started_at=None,
            completed_at=None,
            created_at=now,
            updated_at=now,
            metadata=redact_sensitive(payload.metadata),
        )

        saved_run = self.run_repository.save(run)

        execution_payload = {
            "run_id": saved_run.id,
            "template": template.visible_dict(),
            "input_data": redact_sensitive(payload.input_data),
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "request_id": actor.request_id,
            "dry_run": payload.dry_run,
        }

        if callable(self.master_run_hook):
            try:
                saved_run.status = WorkflowRunStatus.RUNNING
                saved_run.started_at = utc_now()
                saved_run.updated_at = saved_run.started_at
                self.run_repository.update(saved_run)

                result = self.master_run_hook(execution_payload)
                if hasattr(result, "__await__"):
                    result = await result

                if isinstance(result, dict):
                    saved_run.output_data = redact_sensitive(result)
                    saved_run.status = WorkflowRunStatus.COMPLETED
                else:
                    saved_run.output_data = {"result": "Master Agent returned non-dict result."}
                    saved_run.status = WorkflowRunStatus.COMPLETED

                saved_run.completed_at = utc_now()
                saved_run.updated_at = saved_run.completed_at
                saved_run.step_events.append(
                    {
                        "event": "master_agent_execution_completed",
                        "created_at": utc_now(),
                    }
                )
                self.run_repository.update(saved_run)

            except Exception as exc:
                saved_run.status = WorkflowRunStatus.FAILED
                saved_run.error = str(exc)
                saved_run.completed_at = utc_now()
                saved_run.updated_at = saved_run.completed_at
                saved_run.step_events.append(
                    {
                        "event": "master_agent_execution_failed",
                        "error": str(exc),
                        "created_at": utc_now(),
                    }
                )
                self.run_repository.update(saved_run)
        else:
            saved_run.status = WorkflowRunStatus.COMPLETED if payload.dry_run else WorkflowRunStatus.QUEUED
            saved_run.output_data = {
                "mode": "fallback",
                "message": "Workflow run accepted. Master Agent execution hook is not configured yet.",
                "dry_run": payload.dry_run,
                "step_count": len(template.steps),
            }
            saved_run.completed_at = utc_now() if payload.dry_run else None
            saved_run.updated_at = utc_now()
            saved_run.step_events.append(
                {
                    "event": "workflow_run_created_fallback",
                    "created_at": utc_now(),
                    "note": "Execution can be connected to Master Agent later.",
                }
            )
            self.run_repository.update(saved_run)

        await self.audit(
            actor,
            "workflows.run",
            AuditStatus.SUCCESS,
            target_id=saved_run.id,
            details={
                "run_id": saved_run.id,
                "template_id": template.id,
                "trigger_type": payload.trigger_type.value,
                "status": saved_run.status.value,
                "dry_run": payload.dry_run,
            },
            risk_level=RiskLevel.MEDIUM,
        )

        await self.index_for_memory_agent(
            actor,
            "workflow_run_created",
            {
                "run_id": saved_run.id,
                "template_id": template.id,
                "status": saved_run.status.value,
                "trigger_type": payload.trigger_type.value,
            },
        )

        verification = await self.prepare_verification(
            actor,
            "workflows.run",
            {
                "run_id": saved_run.id,
                "template_id": template.id,
                "status": saved_run.status.value,
            },
        )

        return saved_run, verification

    async def get_run(self, actor: ActorContext, run_id: str) -> WorkflowRunRecord:
        self.enforce_view_access(actor)

        record = self.run_repository.get_scoped(run_id, actor.user_id, actor.workspace_id)
        if record is None:
            raise_safe_error(
                status.HTTP_404_NOT_FOUND,
                "workflow_run_not_found",
                "Workflow run was not found in this user/workspace scope.",
                actor.request_id,
            )

        return record

    async def search_runs(
        self,
        actor: ActorContext,
        payload: WorkflowRunSearchRequest,
    ) -> Tuple[List[WorkflowRunRecord], int]:
        self.enforce_view_access(actor)

        records = self.run_repository.query(
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            template_id=payload.template_id,
            statuses=payload.statuses,
            trigger_types=payload.trigger_types,
        )

        total = len(records)
        page = records[payload.offset : payload.offset + payload.limit]

        return page, total

    async def create_webhook(
        self,
        actor: ActorContext,
        payload: WebhookCreateRequest,
    ) -> Tuple[WebhookRecord, str, Dict[str, Any]]:
        self.enforce_webhook_access(actor)

        template_id = normalize_id(payload.template_id, "template_id", actor.request_id)
        template = self.template_repository.get_scoped(template_id, actor.user_id, actor.workspace_id)

        if template is None:
            raise_safe_error(
                status.HTTP_404_NOT_FOUND,
                "workflow_template_not_found",
                "Workflow template was not found in this user/workspace scope.",
                actor.request_id,
            )

        if WorkflowTriggerType.WEBHOOK not in template.trigger_types:
            raise_safe_error(
                status.HTTP_400_BAD_REQUEST,
                "template_does_not_allow_webhook",
                "This workflow template does not allow webhook triggers.",
                actor.request_id,
            )

        if REQUIRE_SECURITY_FOR_WEBHOOKS:
            await self.require_security(
                actor=actor,
                action="workflows.webhook.create",
                risk_level=RiskLevel.HIGH,
                payload=payload.model_dump(),
            )

        secret = generate_webhook_secret()
        now = utc_now()

        record = WebhookRecord(
            id=str(uuid.uuid4()),
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            template_id=template.id,
            name=payload.name.strip(),
            status=WebhookStatus.ACTIVE,
            secret_hash=hash_webhook_secret(secret),
            allowed_event_types=payload.allowed_event_types,
            tags=payload.tags,
            metadata=redact_sensitive(payload.metadata),
            created_by=actor.user_id,
            updated_by=actor.user_id,
            created_at=now,
            updated_at=now,
        )

        saved = self.webhook_repository.save(record)

        await self.audit(
            actor,
            "workflows.webhook.create",
            AuditStatus.SUCCESS,
            target_id=saved.id,
            details={"webhook_id": saved.id, "template_id": saved.template_id},
            risk_level=RiskLevel.HIGH,
        )

        verification = await self.prepare_verification(
            actor,
            "workflows.webhook.create",
            {"webhook_id": saved.id, "template_id": saved.template_id},
        )

        return saved, secret, verification

    async def update_webhook(
        self,
        actor: ActorContext,
        webhook_id: str,
        payload: WebhookUpdateRequest,
    ) -> Tuple[WebhookRecord, Optional[str], Dict[str, Any]]:
        self.enforce_webhook_access(actor)

        record = self.webhook_repository.get_scoped(webhook_id, actor.user_id, actor.workspace_id)
        if record is None:
            raise_safe_error(
                status.HTTP_404_NOT_FOUND,
                "webhook_not_found",
                "Webhook was not found in this user/workspace scope.",
                actor.request_id,
            )

        if REQUIRE_SECURITY_FOR_WEBHOOKS:
            await self.require_security(
                actor=actor,
                action="workflows.webhook.update",
                risk_level=RiskLevel.HIGH,
                payload={"webhook_id": webhook_id, "update": payload.model_dump(exclude_none=True)},
            )

        new_secret: Optional[str] = None

        if payload.name is not None:
            record.name = payload.name.strip()
        if payload.status is not None:
            record.status = payload.status
            if payload.status == WebhookStatus.REVOKED:
                record.revoked_at = utc_now()
        if payload.allowed_event_types is not None:
            record.allowed_event_types = payload.allowed_event_types
        if payload.tags is not None:
            record.tags = payload.tags
        if payload.metadata is not None:
            record.metadata = redact_sensitive(payload.metadata)
        if payload.rotate_secret:
            new_secret = generate_webhook_secret()
            record.secret_hash = hash_webhook_secret(new_secret)

        record.updated_by = actor.user_id
        record.updated_at = utc_now()

        updated = self.webhook_repository.update(record)

        await self.audit(
            actor,
            "workflows.webhook.update",
            AuditStatus.SUCCESS,
            target_id=updated.id,
            details={"webhook_id": updated.id, "rotate_secret": payload.rotate_secret},
            risk_level=RiskLevel.HIGH,
        )

        verification = await self.prepare_verification(
            actor,
            "workflows.webhook.update",
            {"webhook_id": updated.id, "rotated_secret": bool(new_secret)},
        )

        return updated, new_secret, verification

    async def list_webhooks(
        self,
        actor: ActorContext,
        template_id: Optional[str],
        status_filter: Optional[WebhookStatus],
        limit: int,
        offset: int,
    ) -> Tuple[List[WebhookRecord], int]:
        self.enforce_webhook_access(actor)

        records = self.webhook_repository.query(
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            template_id=template_id,
            statuses=[status_filter] if status_filter else [],
        )

        total = len(records)
        page = records[offset : offset + limit]

        return page, total

    async def get_webhook(self, actor: ActorContext, webhook_id: str) -> WebhookRecord:
        self.enforce_webhook_access(actor)

        record = self.webhook_repository.get_scoped(webhook_id, actor.user_id, actor.workspace_id)
        if record is None:
            raise_safe_error(
                status.HTTP_404_NOT_FOUND,
                "webhook_not_found",
                "Webhook was not found in this user/workspace scope.",
                actor.request_id,
            )

        return record

    async def delete_webhook(
        self,
        actor: ActorContext,
        webhook_id: str,
        reason: Optional[str],
    ) -> Tuple[WebhookRecord, Dict[str, Any]]:
        self.enforce_webhook_access(actor)

        record = self.webhook_repository.get_scoped(webhook_id, actor.user_id, actor.workspace_id)
        if record is None:
            raise_safe_error(
                status.HTTP_404_NOT_FOUND,
                "webhook_not_found",
                "Webhook was not found in this user/workspace scope.",
                actor.request_id,
            )

        if REQUIRE_SECURITY_FOR_WEBHOOKS:
            await self.require_security(
                actor=actor,
                action="workflows.webhook.revoke",
                risk_level=RiskLevel.HIGH,
                payload={"webhook_id": webhook_id, "reason": reason},
            )

        record.status = WebhookStatus.REVOKED
        record.revoked_at = utc_now()
        record.updated_at = utc_now()
        record.updated_by = actor.user_id

        updated = self.webhook_repository.update(record)

        await self.audit(
            actor,
            "workflows.webhook.revoke",
            AuditStatus.SUCCESS,
            target_id=updated.id,
            details={"webhook_id": updated.id, "reason": reason},
            risk_level=RiskLevel.HIGH,
        )

        verification = await self.prepare_verification(
            actor,
            "workflows.webhook.revoke",
            {"webhook_id": updated.id, "status": updated.status.value},
        )

        return updated, verification

    async def trigger_webhook(
        self,
        actor: ActorContext,
        webhook_id: str,
        secret: str,
        payload: WebhookTriggerRequest,
    ) -> Tuple[WorkflowRunRecord, Dict[str, Any]]:
        record = self.webhook_repository.get_scoped(webhook_id, actor.user_id, actor.workspace_id)

        if record is None:
            raise_safe_error(
                status.HTTP_404_NOT_FOUND,
                "webhook_not_found",
                "Webhook was not found in this user/workspace scope.",
                actor.request_id,
            )

        if record.status != WebhookStatus.ACTIVE:
            raise_safe_error(
                status.HTTP_409_CONFLICT,
                "webhook_not_active",
                "Webhook is not active.",
                actor.request_id,
                {"webhook_status": record.status.value},
            )

        if not verify_webhook_secret(secret, record.secret_hash):
            await self.audit(
                actor,
                "workflows.webhook.trigger_denied",
                AuditStatus.DENIED,
                target_id=record.id,
                details={"webhook_id": record.id, "reason": "Invalid webhook secret."},
                risk_level=RiskLevel.HIGH,
            )
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "invalid_webhook_secret",
                "Webhook secret is invalid.",
                actor.request_id,
            )

        if record.allowed_event_types and payload.event_type not in record.allowed_event_types:
            raise_safe_error(
                status.HTTP_400_BAD_REQUEST,
                "webhook_event_not_allowed",
                "This webhook does not allow the provided event type.",
                actor.request_id,
                {
                    "event_type": payload.event_type,
                    "allowed_event_types": record.allowed_event_types,
                },
            )

        record.last_triggered_at = utc_now()
        record.updated_at = record.last_triggered_at
        self.webhook_repository.update(record)

        run_payload = WorkflowRunRequest(
            template_id=record.template_id,
            trigger_type=WorkflowTriggerType.WEBHOOK,
            input_data={
                "event_type": payload.event_type,
                "payload": payload.payload,
                "webhook_id": record.id,
            },
            metadata={"source": "webhook"},
            dry_run=False,
        )

        run, verification = await self.run_workflow(actor, run_payload)

        await self.audit(
            actor,
            "workflows.webhook.trigger",
            AuditStatus.SUCCESS,
            target_id=record.id,
            details={"webhook_id": record.id, "run_id": run.id, "event_type": payload.event_type},
            risk_level=RiskLevel.MEDIUM,
        )

        return run, verification


workflows_service = Workflows()


# =============================================================================
# Dependencies
# =============================================================================

if get_current_auth_context is not None:

    async def get_actor_context(
        request: Request,
        context: "RealAuthContext" = Depends(get_current_auth_context),
    ) -> ActorContext:
        """
        Real, JWT-verified auth/workspace context, matching every other
        router's get_current_auth_context dependency (apps/api/routes/
        auth.py). Previously this read X-User-Id/X-Workspace-Id/X-User-Role
        headers directly with no signature verification at all -- any
        caller could claim to be any user or workspace. role/plan are
        passed through parse_role()/parse_plan() below, which already
        default safely (MEMBER/FREE) for any of the real backend's role/
        plan values this router's narrower local enums don't recognize
        (e.g. "developer", "starter").
        """
        return ActorContext(
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            role=parse_role(context.role),
            plan=parse_plan(context.plan),
            subscription_active=True,
            request_id=context.request_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("User-Agent"),
        )

else:
    # Only reachable if apps.api.routes.auth itself failed to import (a
    # broken install) -- fail closed instead of falling back to trusting
    # caller-supplied identity headers.
    async def get_actor_context(request: Request) -> ActorContext:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "AUTH_MODULE_UNAVAILABLE",
                "message": "Authentication is not available.",
            },
        )


def get_workflows_service() -> Workflows:
    return workflows_service


# =============================================================================
# Template routes
# =============================================================================

@router.post("/templates", response_model=WorkflowResponse, status_code=status.HTTP_201_CREATED)
async def create_workflow_template(
    payload: WorkflowTemplateCreateRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
) -> WorkflowResponse:
    template, verification = await service.create_template(actor, payload)

    return WorkflowResponse(
        ok=True,
        message="Workflow template created successfully.",
        data={"template": template.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


@router.get("/templates", response_model=WorkflowTemplateSearchResponse)
async def list_workflow_templates(
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
    query: Optional[str] = Query(default=None, max_length=500),
    status_filter: Optional[WorkflowStatus] = Query(default=None, alias="status"),
    trigger_type: Optional[WorkflowTriggerType] = Query(default=None),
    tag: Optional[str] = Query(default=None, max_length=60),
    include_deleted: bool = Query(default=False),
    limit: int = Query(default=25, ge=1, le=MAX_SEARCH_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> WorkflowTemplateSearchResponse:
    payload = WorkflowSearchRequest(
        query=query,
        statuses=[status_filter] if status_filter else [],
        trigger_types=[trigger_type] if trigger_type else [],
        tags=[tag] if tag else [],
        include_deleted=include_deleted,
        limit=limit,
        offset=offset,
    )

    templates, total = await service.search_templates(actor, payload)

    return WorkflowTemplateSearchResponse(
        ok=True,
        message="Workflow templates retrieved successfully.",
        templates=[template.visible_dict() for template in templates],
        total=total,
        limit=limit,
        offset=offset,
        request_id=actor.request_id,
    )


@router.post("/templates/search", response_model=WorkflowTemplateSearchResponse)
async def search_workflow_templates(
    payload: WorkflowSearchRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
) -> WorkflowTemplateSearchResponse:
    templates, total = await service.search_templates(actor, payload)

    return WorkflowTemplateSearchResponse(
        ok=True,
        message="Workflow template search completed successfully.",
        templates=[template.visible_dict() for template in templates],
        total=total,
        limit=payload.limit,
        offset=payload.offset,
        request_id=actor.request_id,
    )


@router.get("/templates/{template_id}", response_model=WorkflowResponse)
async def get_workflow_template(
    template_id: str,
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
) -> WorkflowResponse:
    safe_template_id = normalize_id(template_id, "template_id", actor.request_id)
    template = await service.get_template(actor, safe_template_id)

    return WorkflowResponse(
        ok=True,
        message="Workflow template retrieved successfully.",
        data={"template": template.visible_dict()},
        request_id=actor.request_id,
    )


@router.patch("/templates/{template_id}", response_model=WorkflowResponse)
async def update_workflow_template(
    template_id: str,
    payload: WorkflowTemplateUpdateRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
) -> WorkflowResponse:
    safe_template_id = normalize_id(template_id, "template_id", actor.request_id)
    template, verification = await service.update_template(actor, safe_template_id, payload)

    return WorkflowResponse(
        ok=True,
        message="Workflow template updated successfully.",
        data={"template": template.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


@router.delete("/templates/{template_id}", response_model=WorkflowResponse)
async def delete_workflow_template(
    template_id: str,
    hard_delete: bool = Query(default=False),
    reason: Optional[str] = Query(default=None, max_length=500),
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
) -> WorkflowResponse:
    safe_template_id = normalize_id(template_id, "template_id", actor.request_id)
    template, verification = await service.delete_template(actor, safe_template_id, hard_delete, reason)

    return WorkflowResponse(
        ok=True,
        message="Workflow template deleted successfully.",
        data={"template": template.visible_dict(), "hard_delete": hard_delete},
        verification=verification,
        request_id=actor.request_id,
    )


# =============================================================================
# Run routes
# =============================================================================

@router.post("/run", response_model=WorkflowResponse, status_code=status.HTTP_202_ACCEPTED)
async def run_workflow(
    payload: WorkflowRunRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
) -> WorkflowResponse:
    run, verification = await service.run_workflow(actor, payload)

    return WorkflowResponse(
        ok=True,
        message="Workflow run accepted successfully.",
        data={"run": run.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


@router.get("/runs", response_model=WorkflowRunSearchResponse)
async def list_workflow_runs(
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
    template_id: Optional[str] = Query(default=None, max_length=140),
    status_filter: Optional[WorkflowRunStatus] = Query(default=None, alias="status"),
    trigger_type: Optional[WorkflowTriggerType] = Query(default=None),
    limit: int = Query(default=25, ge=1, le=MAX_SEARCH_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> WorkflowRunSearchResponse:
    payload = WorkflowRunSearchRequest(
        template_id=template_id,
        statuses=[status_filter] if status_filter else [],
        trigger_types=[trigger_type] if trigger_type else [],
        limit=limit,
        offset=offset,
    )

    runs, total = await service.search_runs(actor, payload)

    return WorkflowRunSearchResponse(
        ok=True,
        message="Workflow runs retrieved successfully.",
        runs=[run.visible_dict() for run in runs],
        total=total,
        limit=limit,
        offset=offset,
        request_id=actor.request_id,
    )


@router.post("/runs/search", response_model=WorkflowRunSearchResponse)
async def search_workflow_runs(
    payload: WorkflowRunSearchRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
) -> WorkflowRunSearchResponse:
    runs, total = await service.search_runs(actor, payload)

    return WorkflowRunSearchResponse(
        ok=True,
        message="Workflow run search completed successfully.",
        runs=[run.visible_dict() for run in runs],
        total=total,
        limit=payload.limit,
        offset=payload.offset,
        request_id=actor.request_id,
    )


@router.get("/runs/{run_id}", response_model=WorkflowResponse)
async def get_workflow_run(
    run_id: str,
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
) -> WorkflowResponse:
    safe_run_id = normalize_id(run_id, "run_id", actor.request_id)
    run = await service.get_run(actor, safe_run_id)

    return WorkflowResponse(
        ok=True,
        message="Workflow run retrieved successfully.",
        data={"run": run.visible_dict()},
        request_id=actor.request_id,
    )


# =============================================================================
# Webhook routes
# =============================================================================

@router.post("/webhooks", response_model=WorkflowResponse, status_code=status.HTTP_201_CREATED)
async def create_webhook(
    payload: WebhookCreateRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
) -> WorkflowResponse:
    webhook, secret, verification = await service.create_webhook(actor, payload)

    return WorkflowResponse(
        ok=True,
        message="Webhook created successfully. Store the secret now; it will not be shown again.",
        data={
            "webhook": webhook.visible_dict(),
            "secret": secret,
            "trigger_header": "X-Webhook-Secret",
        },
        verification=verification,
        request_id=actor.request_id,
    )


@router.get("/webhooks", response_model=WebhookSearchResponse)
async def list_webhooks(
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
    template_id: Optional[str] = Query(default=None, max_length=140),
    status_filter: Optional[WebhookStatus] = Query(default=None, alias="status"),
    limit: int = Query(default=25, ge=1, le=MAX_SEARCH_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> WebhookSearchResponse:
    webhooks, total = await service.list_webhooks(actor, template_id, status_filter, limit, offset)

    return WebhookSearchResponse(
        ok=True,
        message="Webhooks retrieved successfully.",
        webhooks=[webhook.visible_dict() for webhook in webhooks],
        total=total,
        limit=limit,
        offset=offset,
        request_id=actor.request_id,
    )


@router.get("/webhooks/{webhook_id}", response_model=WorkflowResponse)
async def get_webhook(
    webhook_id: str,
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
) -> WorkflowResponse:
    safe_webhook_id = normalize_id(webhook_id, "webhook_id", actor.request_id)
    webhook = await service.get_webhook(actor, safe_webhook_id)

    return WorkflowResponse(
        ok=True,
        message="Webhook retrieved successfully.",
        data={"webhook": webhook.visible_dict()},
        request_id=actor.request_id,
    )


@router.patch("/webhooks/{webhook_id}", response_model=WorkflowResponse)
async def update_webhook(
    webhook_id: str,
    payload: WebhookUpdateRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
) -> WorkflowResponse:
    safe_webhook_id = normalize_id(webhook_id, "webhook_id", actor.request_id)
    webhook, new_secret, verification = await service.update_webhook(actor, safe_webhook_id, payload)

    data: Dict[str, Any] = {"webhook": webhook.visible_dict()}
    if new_secret:
        data["secret"] = new_secret
        data["secret_notice"] = "Store the rotated secret now; it will not be shown again."

    return WorkflowResponse(
        ok=True,
        message="Webhook updated successfully.",
        data=data,
        verification=verification,
        request_id=actor.request_id,
    )


@router.delete("/webhooks/{webhook_id}", response_model=WorkflowResponse)
async def delete_webhook(
    webhook_id: str,
    reason: Optional[str] = Query(default=None, max_length=500),
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
) -> WorkflowResponse:
    safe_webhook_id = normalize_id(webhook_id, "webhook_id", actor.request_id)
    webhook, verification = await service.delete_webhook(actor, safe_webhook_id, reason)

    return WorkflowResponse(
        ok=True,
        message="Webhook revoked successfully.",
        data={"webhook": webhook.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


@router.post("/webhooks/{webhook_id}/trigger", response_model=WorkflowResponse, status_code=status.HTTP_202_ACCEPTED)
async def trigger_webhook(
    webhook_id: str,
    payload: WebhookTriggerRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
    x_webhook_secret: Optional[str] = Header(default=None, alias="X-Webhook-Secret"),
) -> WorkflowResponse:
    safe_webhook_id = normalize_id(webhook_id, "webhook_id", actor.request_id)

    if not x_webhook_secret:
        raise_safe_error(
            status.HTTP_401_UNAUTHORIZED,
            "missing_webhook_secret",
            "X-Webhook-Secret header is required.",
            actor.request_id,
        )

    run, verification = await service.trigger_webhook(actor, safe_webhook_id, x_webhook_secret, payload)

    return WorkflowResponse(
        ok=True,
        message="Webhook triggered workflow successfully.",
        data={"run": run.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


# =============================================================================
# Health route
# =============================================================================

@router.get("/health/status", response_model=WorkflowResponse)
async def workflows_health(
    actor: ActorContext = Depends(get_actor_context),
    service: Workflows = Depends(get_workflows_service),
) -> WorkflowResponse:
    service.enforce_subscription(actor)

    template_count = service.template_repository.count_scoped(actor.user_id, actor.workspace_id, include_deleted=False)
    runs = service.run_repository.query(actor.user_id, actor.workspace_id)
    webhooks = service.webhook_repository.query(actor.user_id, actor.workspace_id)

    return WorkflowResponse(
        ok=True,
        message="Workflows module is available.",
        data={
            "module": "workflows",
            "status": "healthy",
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "role": actor.role.value,
            "plan": actor.plan.value,
            "subscription_active": actor.subscription_active,
            "template_count": template_count,
            "template_limit": template_limit_for_plan(actor.plan),
            "run_count": len(runs),
            "webhook_count": len(webhooks),
            "webhooks_allowed": plan_allows_webhooks(actor.plan),
            "settings": {
                "max_template_steps": MAX_TEMPLATE_STEPS,
                "max_search_limit": MAX_SEARCH_LIMIT,
                "require_security_for_webhooks": REQUIRE_SECURITY_FOR_WEBHOOKS,
                "require_security_for_external_actions": REQUIRE_SECURITY_FOR_EXTERNAL_ACTIONS,
            },
        },
        request_id=actor.request_id,
    )


__all__ = [
    "router",
    "Workflows",
    "ActorContext",
    "WorkflowStatus",
    "WorkflowRunStatus",
    "WorkflowStepType",
    "WorkflowTriggerType",
    "WebhookStatus",
    "WorkflowStep",
    "WorkflowTemplateCreateRequest",
    "WorkflowTemplateUpdateRequest",
    "WorkflowRunRequest",
    "WorkflowSearchRequest",
    "WorkflowRunSearchRequest",
    "WebhookCreateRequest",
    "WebhookUpdateRequest",
    "WebhookTriggerRequest",
    "WorkflowResponse",
    "WorkflowTemplateSearchResponse",
    "WorkflowRunSearchResponse",
    "WebhookSearchResponse",
]