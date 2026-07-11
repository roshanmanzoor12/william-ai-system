"""
apps/api/routes/memory.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Agent/Module: API Prompt Bible
Purpose: short/long/project/client memory save/search/delete/export

This module is intentionally import-safe:
- It does not require future project files to exist.
- It uses optional dependency discovery where possible.
- It provides safe fallback behavior for development and early integration.
- It enforces user_id and workspace_id isolation on every memory operation.

Core Responsibilities:
- Save short-term, long-term, project, and client memory.
- Search memory safely within a user/workspace boundary.
- Delete one memory record or bulk-delete scoped records.
- Export memory in JSON or JSONL format.
- Prepare future-compatible payloads for Master Agent, Security Agent, Memory Agent, and Verification Agent.
- Add audit hooks for state-changing and sensitive actions.
- Add role, plan, and subscription checks for dashboard/API access.
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
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Sequence, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator


# =============================================================================
# Optional project integration hooks
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
    from apps.api.services.audit import audit_log as project_audit_log  # type: ignore
except Exception:
    project_audit_log = None

try:
    from apps.api.services.security import require_security_approval as project_security_approval  # type: ignore
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


# =============================================================================
# Router
# =============================================================================

router = APIRouter(tags=["Memory"])
# No self-prefix here -- apps/api/main.py's OPTIONAL_ROUTERS already
# applies "/memory" as this router's default_prefix. Baking it in here
# too produced double-prefixed live paths like /api/v1/memory/memory/save.


# =============================================================================
# Constants and environment-driven safe defaults
# =============================================================================

APP_NAME = os.getenv("WILLIAM_APP_NAME", "William Jarvis")
DEFAULT_FREE_MEMORY_LIMIT = int(os.getenv("WILLIAM_FREE_MEMORY_LIMIT", "250"))
DEFAULT_PRO_MEMORY_LIMIT = int(os.getenv("WILLIAM_PRO_MEMORY_LIMIT", "5000"))
DEFAULT_BUSINESS_MEMORY_LIMIT = int(os.getenv("WILLIAM_BUSINESS_MEMORY_LIMIT", "25000"))
DEFAULT_ENTERPRISE_MEMORY_LIMIT = int(os.getenv("WILLIAM_ENTERPRISE_MEMORY_LIMIT", "100000"))
MAX_EXPORT_RECORDS = int(os.getenv("WILLIAM_MEMORY_MAX_EXPORT_RECORDS", "25000"))
MAX_SEARCH_LIMIT = int(os.getenv("WILLIAM_MEMORY_MAX_SEARCH_LIMIT", "100"))
MAX_CONTENT_LENGTH = int(os.getenv("WILLIAM_MEMORY_MAX_CONTENT_LENGTH", "50000"))
REQUIRE_SECURITY_FOR_EXPORT = os.getenv("WILLIAM_REQUIRE_SECURITY_FOR_MEMORY_EXPORT", "true").lower() == "true"
REQUIRE_SECURITY_FOR_BULK_DELETE = os.getenv("WILLIAM_REQUIRE_SECURITY_FOR_MEMORY_BULK_DELETE", "true").lower() == "true"


# =============================================================================
# Enums
# =============================================================================

class MemoryType(str, Enum):
    SHORT = "short"
    LONG = "long"
    PROJECT = "project"
    CLIENT = "client"


class MemorySensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class MemorySource(str, Enum):
    USER = "user"
    MASTER_AGENT = "master_agent"
    MEMORY_AGENT = "memory_agent"
    SYSTEM = "system"
    API = "api"


class ExportFormat(str, Enum):
    JSON = "json"
    JSONL = "jsonl"


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


class ActionStatus(str, Enum):
    SUCCESS = "success"
    DENIED = "denied"
    ERROR = "error"


# =============================================================================
# Data models
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
class MemoryRecord:
    id: str
    user_id: str
    workspace_id: str
    memory_type: MemoryType
    content: str
    title: Optional[str]
    tags: List[str]
    source: MemorySource
    sensitivity: MemorySensitivity
    project_id: Optional[str]
    client_id: Optional[str]
    metadata: Dict[str, Any]
    created_at: str
    updated_at: str
    deleted_at: Optional[str] = None
    created_by: Optional[str] = None
    updated_by: Optional[str] = None

    def visible_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        return data


# =============================================================================
# Request / response schemas
# =============================================================================

class ErrorDetail(BaseModel):
    code: str
    message: str
    request_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class MemoryCreateRequest(BaseModel):
    memory_type: MemoryType = Field(..., description="short, long, project, or client")
    content: str = Field(..., min_length=1, max_length=MAX_CONTENT_LENGTH)
    title: Optional[str] = Field(default=None, max_length=250)
    tags: List[str] = Field(default_factory=list, max_length=50)
    source: MemorySource = MemorySource.USER
    sensitivity: MemorySensitivity = MemorySensitivity.INTERNAL
    project_id: Optional[str] = Field(default=None, max_length=120)
    client_id: Optional[str] = Field(default=None, max_length=120)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("content")
    @classmethod
    def clean_content(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Memory content cannot be empty.")
        return cleaned

    @field_validator("tags")
    @classmethod
    def clean_tags(cls, value: List[str]) -> List[str]:
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

    @field_validator("metadata")
    @classmethod
    def clean_metadata(cls, value: Dict[str, Any]) -> Dict[str, Any]:
        serialized = json.dumps(value, default=str)
        if len(serialized) > 20000:
            raise ValueError("Metadata is too large.")
        return value


class MemoryUpdateRequest(BaseModel):
    content: Optional[str] = Field(default=None, min_length=1, max_length=MAX_CONTENT_LENGTH)
    title: Optional[str] = Field(default=None, max_length=250)
    tags: Optional[List[str]] = Field(default=None, max_length=50)
    sensitivity: Optional[MemorySensitivity] = None
    metadata: Optional[Dict[str, Any]] = None

    @field_validator("content")
    @classmethod
    def clean_content(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Memory content cannot be empty.")
        return cleaned

    @field_validator("tags")
    @classmethod
    def clean_tags(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return value
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


class MemorySearchRequest(BaseModel):
    query: Optional[str] = Field(default=None, max_length=500)
    memory_types: List[MemoryType] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    project_id: Optional[str] = Field(default=None, max_length=120)
    client_id: Optional[str] = Field(default=None, max_length=120)
    sensitivity: Optional[MemorySensitivity] = None
    include_deleted: bool = False
    limit: int = Field(default=20, ge=1, le=MAX_SEARCH_LIMIT)
    offset: int = Field(default=0, ge=0)


class MemoryExportRequest(BaseModel):
    memory_types: List[MemoryType] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    project_id: Optional[str] = Field(default=None, max_length=120)
    client_id: Optional[str] = Field(default=None, max_length=120)
    include_deleted: bool = False
    export_format: ExportFormat = ExportFormat.JSON


class MemoryDeleteRequest(BaseModel):
    memory_ids: List[str] = Field(default_factory=list, max_length=500)
    memory_types: List[MemoryType] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    project_id: Optional[str] = Field(default=None, max_length=120)
    client_id: Optional[str] = Field(default=None, max_length=120)
    hard_delete: bool = False
    reason: Optional[str] = Field(default=None, max_length=500)


class MemoryResponse(BaseModel):
    ok: bool
    message: str
    data: Dict[str, Any] = Field(default_factory=dict)
    verification: Dict[str, Any] = Field(default_factory=dict)
    request_id: Optional[str] = None


class MemorySearchResponse(BaseModel):
    ok: bool
    message: str
    records: List[Dict[str, Any]]
    total: int
    limit: int
    offset: int
    request_id: Optional[str] = None


# =============================================================================
# Utility helpers
# =============================================================================

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def normalize_id(value: Optional[str], field_name: str) -> str:
    if value is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": f"missing_{field_name}", "message": f"{field_name} is required."},
        )

    cleaned = value.strip()
    if not cleaned:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": f"empty_{field_name}", "message": f"{field_name} cannot be empty."},
        )

    if len(cleaned) > 120:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": f"invalid_{field_name}", "message": f"{field_name} is too long."},
        )

    if not re.match(r"^[a-zA-Z0-9_\-:.@]+$", cleaned):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": f"invalid_{field_name}", "message": f"{field_name} contains unsafe characters."},
        )

    return cleaned


def safe_json(data: Any) -> Any:
    try:
        json.dumps(data, default=str)
        return data
    except Exception:
        return {"serialization_warning": "Original value could not be serialized safely."}


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


def memory_limit_for_plan(plan: SubscriptionPlan) -> int:
    limits = {
        SubscriptionPlan.FREE: DEFAULT_FREE_MEMORY_LIMIT,
        SubscriptionPlan.PRO: DEFAULT_PRO_MEMORY_LIMIT,
        SubscriptionPlan.BUSINESS: DEFAULT_BUSINESS_MEMORY_LIMIT,
        SubscriptionPlan.ENTERPRISE: DEFAULT_ENTERPRISE_MEMORY_LIMIT,
    }
    return limits.get(plan, DEFAULT_FREE_MEMORY_LIMIT)


def can_write_memory(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER, UserRole.MEMBER}


def can_delete_memory(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER}


def can_export_memory(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN, UserRole.MANAGER}


def can_view_restricted(role: UserRole) -> bool:
    return role in {UserRole.OWNER, UserRole.ADMIN}


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


# =============================================================================
# Fallback in-memory repository
# =============================================================================

class InMemoryMemoryRepository:
    """
    Safe development fallback repository.

    In production, replace this behind the same interface with a database-backed
    repository using PostgreSQL, Redis, vector DB, or project storage services.
    """

    def __init__(self) -> None:
        self._records: Dict[str, MemoryRecord] = {}
        self._lock = RLock()

    def count_workspace_records(self, user_id: str, workspace_id: str, include_deleted: bool = False) -> int:
        with self._lock:
            count = 0
            for record in self._records.values():
                if record.user_id != user_id or record.workspace_id != workspace_id:
                    continue
                if not include_deleted and record.deleted_at is not None:
                    continue
                count += 1
            return count

    def save(self, record: MemoryRecord) -> MemoryRecord:
        with self._lock:
            self._records[record.id] = record
            return record

    def get_scoped(
        self,
        memory_id: str,
        user_id: str,
        workspace_id: str,
        include_deleted: bool = False,
    ) -> Optional[MemoryRecord]:
        with self._lock:
            record = self._records.get(memory_id)
            if record is None:
                return None
            if record.user_id != user_id or record.workspace_id != workspace_id:
                return None
            if not include_deleted and record.deleted_at is not None:
                return None
            return record

    def update(self, record: MemoryRecord) -> MemoryRecord:
        with self._lock:
            self._records[record.id] = record
            return record

    def hard_delete(self, memory_id: str, user_id: str, workspace_id: str) -> bool:
        with self._lock:
            record = self._records.get(memory_id)
            if record is None:
                return False
            if record.user_id != user_id or record.workspace_id != workspace_id:
                return False
            del self._records[memory_id]
            return True

    def query(
        self,
        user_id: str,
        workspace_id: str,
        query: Optional[str] = None,
        memory_types: Optional[Sequence[MemoryType]] = None,
        tags: Optional[Sequence[str]] = None,
        project_id: Optional[str] = None,
        client_id: Optional[str] = None,
        sensitivity: Optional[MemorySensitivity] = None,
        include_deleted: bool = False,
    ) -> List[MemoryRecord]:
        memory_types_set = {item.value if isinstance(item, MemoryType) else str(item) for item in (memory_types or [])}
        tags_set = {str(tag).strip().lower() for tag in (tags or []) if str(tag).strip()}
        query_normalized = query.strip().lower() if query else None

        with self._lock:
            results: List[MemoryRecord] = []

            for record in self._records.values():
                if record.user_id != user_id or record.workspace_id != workspace_id:
                    continue

                if not include_deleted and record.deleted_at is not None:
                    continue

                if memory_types_set and record.memory_type.value not in memory_types_set:
                    continue

                if tags_set and not tags_set.intersection(set(record.tags)):
                    continue

                if project_id and record.project_id != project_id:
                    continue

                if client_id and record.client_id != client_id:
                    continue

                if sensitivity and record.sensitivity != sensitivity:
                    continue

                if query_normalized:
                    haystack = " ".join(
                        [
                            record.title or "",
                            record.content,
                            " ".join(record.tags),
                            json.dumps(record.metadata, default=str),
                        ]
                    ).lower()
                    if query_normalized not in haystack:
                        continue

                results.append(record)

            results.sort(key=lambda item: item.updated_at, reverse=True)
            return results


_repository = InMemoryMemoryRepository()


# =============================================================================
# Agent and service hooks
# =============================================================================

class Memory:
    """
    Required class/component name: Memory

    This class centralizes memory API behavior while keeping route functions thin.
    It is designed so future services can replace fallback hooks without changing
    route contracts.
    """

    def __init__(
        self,
        repository: Optional[InMemoryMemoryRepository] = None,
        audit_hook: Optional[Callable[..., Any]] = None,
        security_hook: Optional[Callable[..., Any]] = None,
        verification_hook: Optional[Callable[..., Any]] = None,
        memory_agent_hook: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.repository = repository or _repository
        self.audit_hook = audit_hook or project_audit_log
        self.security_hook = security_hook or project_security_approval
        self.verification_hook = verification_hook or project_prepare_verification
        self.memory_agent_hook = memory_agent_hook or project_memory_agent_index

    async def audit(
        self,
        actor: ActorContext,
        action: str,
        status_value: ActionStatus,
        target_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        payload = {
            "app": APP_NAME,
            "action": action,
            "status": status_value.value,
            "target_type": "memory",
            "target_id": target_id,
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
                maybe_result = self.audit_hook(payload)
                if hasattr(maybe_result, "__await__"):
                    await maybe_result
                return
            except Exception:
                return

    async def require_security(
        self,
        actor: ActorContext,
        action: str,
        risk_level: Literal["low", "medium", "high", "critical"],
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        request_payload = {
            "action": action,
            "risk_level": risk_level,
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
                    approved = bool(result.get("approved", False))
                    if not approved:
                        raise_safe_error(
                            status.HTTP_403_FORBIDDEN,
                            "security_agent_denied",
                            "Security Agent did not approve this memory action.",
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
                    "Security Agent could not validate this sensitive memory action.",
                    actor.request_id,
                )

        return {
            "approved": True,
            "mode": "fallback",
            "reason": "No external Security Agent hook configured.",
            "risk_level": risk_level,
        }

    async def prepare_verification(
        self,
        actor: ActorContext,
        action: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        payload = {
            "agent": "Verification Agent",
            "module": "memory",
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

    async def index_for_memory_agent(self, actor: ActorContext, record: MemoryRecord) -> None:
        payload = {
            "agent": "Memory Agent",
            "action": "index_memory",
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "memory": record.visible_dict(),
            "request_id": actor.request_id,
        }

        if callable(self.memory_agent_hook):
            try:
                maybe_result = self.memory_agent_hook(payload)
                if hasattr(maybe_result, "__await__"):
                    await maybe_result
            except Exception:
                return

    def enforce_subscription(self, actor: ActorContext) -> None:
        if not actor.subscription_active:
            raise_safe_error(
                status.HTTP_402_PAYMENT_REQUIRED,
                "subscription_inactive",
                "Your subscription is inactive. Memory access is currently unavailable.",
                actor.request_id,
            )

    def enforce_memory_quota(self, actor: ActorContext) -> None:
        current_count = self.repository.count_workspace_records(
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            include_deleted=False,
        )
        allowed_count = memory_limit_for_plan(actor.plan)

        if current_count >= allowed_count:
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "memory_quota_exceeded",
                "Memory quota exceeded for this subscription plan.",
                actor.request_id,
                {
                    "current_count": current_count,
                    "allowed_count": allowed_count,
                    "plan": actor.plan.value,
                },
            )

    def enforce_read_access(self, actor: ActorContext) -> None:
        self.enforce_subscription(actor)

    def enforce_write_access(self, actor: ActorContext) -> None:
        self.enforce_subscription(actor)
        if not can_write_memory(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_write_memory",
                "Your role does not allow saving or updating memory.",
                actor.request_id,
                {"role": actor.role.value},
            )

    def enforce_delete_access(self, actor: ActorContext) -> None:
        self.enforce_subscription(actor)
        if not can_delete_memory(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_delete_memory",
                "Your role does not allow deleting memory.",
                actor.request_id,
                {"role": actor.role.value},
            )

    def enforce_export_access(self, actor: ActorContext) -> None:
        self.enforce_subscription(actor)
        if not can_export_memory(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "role_cannot_export_memory",
                "Your role does not allow exporting memory.",
                actor.request_id,
                {"role": actor.role.value},
            )

    def filter_by_role_sensitivity(self, actor: ActorContext, records: Iterable[MemoryRecord]) -> List[MemoryRecord]:
        if can_view_restricted(actor.role):
            return list(records)

        return [
            record
            for record in records
            if record.sensitivity != MemorySensitivity.RESTRICTED
        ]

    async def save_memory(self, actor: ActorContext, payload: MemoryCreateRequest) -> Tuple[MemoryRecord, Dict[str, Any]]:
        self.enforce_write_access(actor)
        self.enforce_memory_quota(actor)

        if payload.sensitivity in {MemorySensitivity.CONFIDENTIAL, MemorySensitivity.RESTRICTED}:
            await self.require_security(
                actor=actor,
                action="memory.save_sensitive",
                risk_level="medium",
                payload=payload.model_dump(),
            )

        now = utc_now()
        record = MemoryRecord(
            id=str(uuid.uuid4()),
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            memory_type=payload.memory_type,
            content=payload.content,
            title=payload.title,
            tags=payload.tags,
            source=payload.source,
            sensitivity=payload.sensitivity,
            project_id=payload.project_id,
            client_id=payload.client_id,
            metadata=payload.metadata,
            created_at=now,
            updated_at=now,
            created_by=actor.user_id,
            updated_by=actor.user_id,
        )

        saved = self.repository.save(record)
        await self.index_for_memory_agent(actor, saved)

        verification = await self.prepare_verification(
            actor=actor,
            action="memory.save",
            result={"memory_id": saved.id, "memory_type": saved.memory_type.value},
        )

        await self.audit(
            actor=actor,
            action="memory.save",
            status_value=ActionStatus.SUCCESS,
            target_id=saved.id,
            details={
                "memory_type": saved.memory_type.value,
                "sensitivity": saved.sensitivity.value,
                "project_id": saved.project_id,
                "client_id": saved.client_id,
            },
        )

        return saved, verification

    async def update_memory(
        self,
        actor: ActorContext,
        memory_id: str,
        payload: MemoryUpdateRequest,
    ) -> Tuple[MemoryRecord, Dict[str, Any]]:
        self.enforce_write_access(actor)

        record = self.repository.get_scoped(memory_id, actor.user_id, actor.workspace_id)
        if record is None:
            raise_safe_error(
                status.HTTP_404_NOT_FOUND,
                "memory_not_found",
                "Memory record was not found in this user/workspace scope.",
                actor.request_id,
            )

        if record.sensitivity == MemorySensitivity.RESTRICTED and not can_view_restricted(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "restricted_memory_access_denied",
                "Your role does not allow updating restricted memory.",
                actor.request_id,
            )

        if payload.sensitivity in {MemorySensitivity.CONFIDENTIAL, MemorySensitivity.RESTRICTED}:
            await self.require_security(
                actor=actor,
                action="memory.update_sensitive",
                risk_level="medium",
                payload={"memory_id": memory_id, "update": payload.model_dump(exclude_none=True)},
            )

        if payload.content is not None:
            record.content = payload.content
        if payload.title is not None:
            record.title = payload.title
        if payload.tags is not None:
            record.tags = payload.tags
        if payload.sensitivity is not None:
            record.sensitivity = payload.sensitivity
        if payload.metadata is not None:
            record.metadata = payload.metadata

        record.updated_at = utc_now()
        record.updated_by = actor.user_id

        updated = self.repository.update(record)
        await self.index_for_memory_agent(actor, updated)

        verification = await self.prepare_verification(
            actor=actor,
            action="memory.update",
            result={"memory_id": updated.id, "updated_at": updated.updated_at},
        )

        await self.audit(
            actor=actor,
            action="memory.update",
            status_value=ActionStatus.SUCCESS,
            target_id=updated.id,
            details={"fields": list(payload.model_dump(exclude_none=True).keys())},
        )

        return updated, verification

    async def search_memory(self, actor: ActorContext, payload: MemorySearchRequest) -> Tuple[List[MemoryRecord], int]:
        self.enforce_read_access(actor)

        records = self.repository.query(
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            query=payload.query,
            memory_types=payload.memory_types,
            tags=payload.tags,
            project_id=payload.project_id,
            client_id=payload.client_id,
            sensitivity=payload.sensitivity,
            include_deleted=payload.include_deleted and can_delete_memory(actor.role),
        )

        records = self.filter_by_role_sensitivity(actor, records)
        total = len(records)
        page = records[payload.offset : payload.offset + payload.limit]

        await self.audit(
            actor=actor,
            action="memory.search",
            status_value=ActionStatus.SUCCESS,
            details={
                "query_present": bool(payload.query),
                "memory_types": [item.value for item in payload.memory_types],
                "tags": payload.tags,
                "project_id": payload.project_id,
                "client_id": payload.client_id,
                "total": total,
            },
        )

        return page, total

    async def get_memory(self, actor: ActorContext, memory_id: str) -> MemoryRecord:
        self.enforce_read_access(actor)

        record = self.repository.get_scoped(memory_id, actor.user_id, actor.workspace_id)

        if record is None:
            raise_safe_error(
                status.HTTP_404_NOT_FOUND,
                "memory_not_found",
                "Memory record was not found in this user/workspace scope.",
                actor.request_id,
            )

        if record.sensitivity == MemorySensitivity.RESTRICTED and not can_view_restricted(actor.role):
            raise_safe_error(
                status.HTTP_403_FORBIDDEN,
                "restricted_memory_access_denied",
                "Your role does not allow viewing restricted memory.",
                actor.request_id,
            )

        await self.audit(
            actor=actor,
            action="memory.get",
            status_value=ActionStatus.SUCCESS,
            target_id=record.id,
            details={"memory_type": record.memory_type.value},
        )

        return record

    async def delete_memory(
        self,
        actor: ActorContext,
        payload: MemoryDeleteRequest,
    ) -> Tuple[List[str], Dict[str, Any]]:
        self.enforce_delete_access(actor)

        if not payload.memory_ids and not any(
            [payload.memory_types, payload.tags, payload.project_id, payload.client_id]
        ):
            raise_safe_error(
                status.HTTP_400_BAD_REQUEST,
                "delete_filter_required",
                "Provide memory_ids or at least one scoped filter before deleting memory.",
                actor.request_id,
            )

        is_bulk_delete = len(payload.memory_ids) != 1 or any(
            [payload.memory_types, payload.tags, payload.project_id, payload.client_id]
        )

        if payload.hard_delete or (is_bulk_delete and REQUIRE_SECURITY_FOR_BULK_DELETE):
            await self.require_security(
                actor=actor,
                action="memory.delete",
                risk_level="high" if payload.hard_delete else "medium",
                payload=payload.model_dump(),
            )

        records_to_delete: List[MemoryRecord] = []

        if payload.memory_ids:
            for memory_id in payload.memory_ids:
                record = self.repository.get_scoped(memory_id, actor.user_id, actor.workspace_id, include_deleted=True)
                if record is not None:
                    records_to_delete.append(record)
        else:
            records_to_delete = self.repository.query(
                user_id=actor.user_id,
                workspace_id=actor.workspace_id,
                memory_types=payload.memory_types,
                tags=payload.tags,
                project_id=payload.project_id,
                client_id=payload.client_id,
                include_deleted=False,
            )

        records_to_delete = self.filter_by_role_sensitivity(actor, records_to_delete)
        deleted_ids: List[str] = []

        for record in records_to_delete:
            if payload.hard_delete:
                removed = self.repository.hard_delete(record.id, actor.user_id, actor.workspace_id)
                if removed:
                    deleted_ids.append(record.id)
            else:
                record.deleted_at = utc_now()
                record.updated_at = utc_now()
                record.updated_by = actor.user_id
                self.repository.update(record)
                deleted_ids.append(record.id)

        verification = await self.prepare_verification(
            actor=actor,
            action="memory.delete",
            result={
                "deleted_ids": deleted_ids,
                "count": len(deleted_ids),
                "hard_delete": payload.hard_delete,
            },
        )

        await self.audit(
            actor=actor,
            action="memory.delete",
            status_value=ActionStatus.SUCCESS,
            details={
                "deleted_count": len(deleted_ids),
                "hard_delete": payload.hard_delete,
                "reason": payload.reason,
                "filters": {
                    "memory_ids": payload.memory_ids,
                    "memory_types": [item.value for item in payload.memory_types],
                    "tags": payload.tags,
                    "project_id": payload.project_id,
                    "client_id": payload.client_id,
                },
            },
        )

        return deleted_ids, verification

    async def export_memory(self, actor: ActorContext, payload: MemoryExportRequest) -> Tuple[List[MemoryRecord], Dict[str, Any]]:
        self.enforce_export_access(actor)

        if REQUIRE_SECURITY_FOR_EXPORT:
            await self.require_security(
                actor=actor,
                action="memory.export",
                risk_level="high",
                payload=payload.model_dump(),
            )

        records = self.repository.query(
            user_id=actor.user_id,
            workspace_id=actor.workspace_id,
            memory_types=payload.memory_types,
            tags=payload.tags,
            project_id=payload.project_id,
            client_id=payload.client_id,
            include_deleted=payload.include_deleted,
        )

        records = self.filter_by_role_sensitivity(actor, records)
        records = records[:MAX_EXPORT_RECORDS]

        verification = await self.prepare_verification(
            actor=actor,
            action="memory.export",
            result={
                "count": len(records),
                "format": payload.export_format.value,
                "max_export_records": MAX_EXPORT_RECORDS,
            },
        )

        await self.audit(
            actor=actor,
            action="memory.export",
            status_value=ActionStatus.SUCCESS,
            details={
                "count": len(records),
                "format": payload.export_format.value,
                "filters": payload.model_dump(),
            },
        )

        return records, verification


memory_service = Memory()


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
    Import-safe authentication adapter.

    Production should wire this to real auth/session dependencies.
    During early integration, it accepts explicit headers:
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


def get_memory_service() -> Memory:
    return memory_service


# =============================================================================
# Exception helpers
# =============================================================================

def http_error_response(exc: HTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict):
        return JSONResponse(status_code=exc.status_code, content={"ok": False, "error": exc.detail})
    return JSONResponse(
        status_code=exc.status_code,
        content={"ok": False, "error": {"code": "http_error", "message": str(exc.detail)}},
    )


# =============================================================================
# Routes
# =============================================================================

@router.post("/save", response_model=MemoryResponse, status_code=status.HTTP_201_CREATED)
async def save_memory(
    payload: MemoryCreateRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Memory = Depends(get_memory_service),
) -> MemoryResponse:
    """
    Save short/long/project/client memory.

    Required isolation:
    - user_id is resolved from auth/header.
    - workspace_id is resolved from auth/header.
    - payload never controls user_id or workspace_id.
    """

    record, verification = await service.save_memory(actor, payload)

    return MemoryResponse(
        ok=True,
        message="Memory saved successfully.",
        data={"memory": record.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


@router.patch("/{memory_id}", response_model=MemoryResponse)
async def update_memory(
    memory_id: str,
    payload: MemoryUpdateRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Memory = Depends(get_memory_service),
) -> MemoryResponse:
    """
    Update a scoped memory record.
    """

    safe_memory_id = normalize_id(memory_id, "memory_id")
    record, verification = await service.update_memory(actor, safe_memory_id, payload)

    return MemoryResponse(
        ok=True,
        message="Memory updated successfully.",
        data={"memory": record.visible_dict()},
        verification=verification,
        request_id=actor.request_id,
    )


@router.get("/{memory_id}", response_model=MemoryResponse)
async def get_memory(
    memory_id: str,
    actor: ActorContext = Depends(get_actor_context),
    service: Memory = Depends(get_memory_service),
) -> MemoryResponse:
    """
    Get one memory record by ID within user/workspace isolation.
    """

    safe_memory_id = normalize_id(memory_id, "memory_id")
    record = await service.get_memory(actor, safe_memory_id)

    return MemoryResponse(
        ok=True,
        message="Memory record retrieved successfully.",
        data={"memory": record.visible_dict()},
        request_id=actor.request_id,
    )


@router.post("/search", response_model=MemorySearchResponse)
async def search_memory(
    payload: MemorySearchRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Memory = Depends(get_memory_service),
) -> MemorySearchResponse:
    """
    Search memory within user/workspace scope.

    Supports:
    - Full-text style substring search.
    - Memory type filtering.
    - Tag filtering.
    - Project/client memory filtering.
    - Sensitivity filtering.
    """

    records, total = await service.search_memory(actor, payload)

    return MemorySearchResponse(
        ok=True,
        message="Memory search completed successfully.",
        records=[record.visible_dict() for record in records],
        total=total,
        limit=payload.limit,
        offset=payload.offset,
        request_id=actor.request_id,
    )


@router.get("", response_model=MemorySearchResponse)
async def list_memory(
    actor: ActorContext = Depends(get_actor_context),
    service: Memory = Depends(get_memory_service),
    query: Optional[str] = Query(default=None, max_length=500),
    memory_type: Optional[MemoryType] = Query(default=None),
    tag: Optional[str] = Query(default=None, max_length=60),
    project_id: Optional[str] = Query(default=None, max_length=120),
    client_id: Optional[str] = Query(default=None, max_length=120),
    limit: int = Query(default=20, ge=1, le=MAX_SEARCH_LIMIT),
    offset: int = Query(default=0, ge=0),
) -> MemorySearchResponse:
    """
    Lightweight GET endpoint for dashboard list views.
    """

    payload = MemorySearchRequest(
        query=query,
        memory_types=[memory_type] if memory_type else [],
        tags=[tag] if tag else [],
        project_id=project_id,
        client_id=client_id,
        include_deleted=False,
        limit=limit,
        offset=offset,
    )

    records, total = await service.search_memory(actor, payload)

    return MemorySearchResponse(
        ok=True,
        message="Memory list retrieved successfully.",
        records=[record.visible_dict() for record in records],
        total=total,
        limit=limit,
        offset=offset,
        request_id=actor.request_id,
    )


@router.delete("", response_model=MemoryResponse)
async def delete_memory(
    payload: MemoryDeleteRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Memory = Depends(get_memory_service),
) -> MemoryResponse:
    """
    Delete scoped memory records.

    Soft delete is default.
    Hard delete requires elevated role and Security Agent approval where configured.
    """

    deleted_ids, verification = await service.delete_memory(actor, payload)

    return MemoryResponse(
        ok=True,
        message="Memory deleted successfully.",
        data={
            "deleted_ids": deleted_ids,
            "deleted_count": len(deleted_ids),
            "hard_delete": payload.hard_delete,
        },
        verification=verification,
        request_id=actor.request_id,
    )


@router.delete("/{memory_id}", response_model=MemoryResponse)
async def delete_one_memory(
    memory_id: str,
    hard_delete: bool = Query(default=False),
    reason: Optional[str] = Query(default=None, max_length=500),
    actor: ActorContext = Depends(get_actor_context),
    service: Memory = Depends(get_memory_service),
) -> MemoryResponse:
    """
    Delete one scoped memory record by ID.
    """

    safe_memory_id = normalize_id(memory_id, "memory_id")
    payload = MemoryDeleteRequest(
        memory_ids=[safe_memory_id],
        hard_delete=hard_delete,
        reason=reason,
    )

    deleted_ids, verification = await service.delete_memory(actor, payload)

    return MemoryResponse(
        ok=True,
        message="Memory deleted successfully.",
        data={
            "deleted_ids": deleted_ids,
            "deleted_count": len(deleted_ids),
            "hard_delete": hard_delete,
        },
        verification=verification,
        request_id=actor.request_id,
    )


@router.post("/export")
async def export_memory(
    payload: MemoryExportRequest,
    actor: ActorContext = Depends(get_actor_context),
    service: Memory = Depends(get_memory_service),
) -> Response:
    """
    Export scoped memory records.

    Supported formats:
    - JSON
    - JSONL

    Export is treated as sensitive because memory may contain client/project data.
    """

    records, verification = await service.export_memory(actor, payload)
    export_data = [record.visible_dict() for record in records]

    filename = f"william-memory-{actor.workspace_id}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

    if payload.export_format == ExportFormat.JSONL:
        def jsonl_stream() -> Iterable[str]:
            for record in export_data:
                yield json.dumps(record, default=str) + "\n"

        headers = {
            "Content-Disposition": f'attachment; filename="{filename}.jsonl"',
            "X-Request-Id": actor.request_id,
            "X-Verification-Prepared": "true" if verification else "false",
        }

        return StreamingResponse(
            jsonl_stream(),
            media_type="application/x-ndjson",
            headers=headers,
        )

    body = {
        "ok": True,
        "message": "Memory export completed successfully.",
        "request_id": actor.request_id,
        "count": len(export_data),
        "records": export_data,
        "verification": verification,
    }

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=body,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}.json"',
            "X-Request-Id": actor.request_id,
            "X-Verification-Prepared": "true" if verification else "false",
        },
    )


@router.get("/health/status", response_model=MemoryResponse)
async def memory_health(
    actor: ActorContext = Depends(get_actor_context),
    service: Memory = Depends(get_memory_service),
) -> MemoryResponse:
    """
    Health endpoint for dashboard/API integration.

    Returns scoped memory count only for the authenticated user/workspace.
    """

    service.enforce_read_access(actor)

    active_count = service.repository.count_workspace_records(
        user_id=actor.user_id,
        workspace_id=actor.workspace_id,
        include_deleted=False,
    )

    total_count = service.repository.count_workspace_records(
        user_id=actor.user_id,
        workspace_id=actor.workspace_id,
        include_deleted=True,
    )

    return MemoryResponse(
        ok=True,
        message="Memory module is available.",
        data={
            "module": "memory",
            "status": "healthy",
            "user_id": actor.user_id,
            "workspace_id": actor.workspace_id,
            "role": actor.role.value,
            "plan": actor.plan.value,
            "subscription_active": actor.subscription_active,
            "active_memory_count": active_count,
            "total_scoped_memory_count": total_count,
            "memory_limit": memory_limit_for_plan(actor.plan),
            "security_export_required": REQUIRE_SECURITY_FOR_EXPORT,
            "security_bulk_delete_required": REQUIRE_SECURITY_FOR_BULK_DELETE,
        },
        request_id=actor.request_id,
    )


# =============================================================================
# Optional direct ASGI app export compatibility
# =============================================================================

__all__ = [
    "router",
    "Memory",
    "MemoryRecord",
    "MemoryType",
    "MemorySensitivity",
    "MemorySource",
    "MemoryCreateRequest",
    "MemoryUpdateRequest",
    "MemorySearchRequest",
    "MemoryDeleteRequest",
    "MemoryExportRequest",
    "MemoryResponse",
    "MemorySearchResponse",
    "ActorContext",
]