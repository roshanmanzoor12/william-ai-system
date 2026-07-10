"""
tests/integration_tests/test_saas_isolation.py

Integration tests for SaaS user/workspace isolation in the William / Jarvis
Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
- Verify strict user_id and workspace_id isolation across tasks, memory, files,
  logs, analytics, billing, agent access, Security Agent approvals, and
  Verification Agent payloads.
- Keep this file import-safe even if the final production app modules are not
  implemented yet.
- Provide realistic fixtures and contract tests that can later connect to the
  real Master Agent, Security Agent, Memory Agent, Verification Agent, API layer,
  database, registry, billing, and audit services.

These tests intentionally include local in-memory doubles. They are not fake
production logic; they are executable contracts for how the real SaaS platform
must behave.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence
from uuid import uuid4

import pytest


# ---------------------------------------------------------------------------
# Import candidates for future real implementation
# ---------------------------------------------------------------------------

MASTER_AGENT_IMPORT_CANDIDATES = (
    "agents.master_agent",
    "app.agents.master_agent",
    "apps.agents.master_agent",
    "backend.agents.master_agent",
    "src.agents.master_agent",
    "william.agents.master_agent",
    "jarvis.agents.master_agent",
    "core.agents.master_agent",
)

MEMORY_AGENT_IMPORT_CANDIDATES = (
    "agents.memory_agent",
    "app.agents.memory_agent",
    "apps.agents.memory_agent",
    "backend.agents.memory_agent",
    "src.agents.memory_agent",
    "william.agents.memory_agent",
    "jarvis.agents.memory_agent",
    "core.agents.memory_agent",
)

SECURITY_AGENT_IMPORT_CANDIDATES = (
    "agents.security_agent",
    "app.agents.security_agent",
    "apps.agents.security_agent",
    "backend.agents.security_agent",
    "src.agents.security_agent",
    "william.agents.security_agent",
    "jarvis.agents.security_agent",
    "core.agents.security_agent",
)

VERIFICATION_AGENT_IMPORT_CANDIDATES = (
    "agents.verification_agent",
    "app.agents.verification_agent",
    "apps.agents.verification_agent",
    "backend.agents.verification_agent",
    "src.agents.verification_agent",
    "william.agents.verification_agent",
    "jarvis.agents.verification_agent",
    "core.agents.verification_agent",
)


# ---------------------------------------------------------------------------
# Test constants
# ---------------------------------------------------------------------------

ALPHA_USER_ID = "user_alpha"
ALPHA_WORKSPACE_ID = "workspace_alpha"
BETA_USER_ID = "user_beta"
BETA_WORKSPACE_ID = "workspace_beta"
SHARED_WORKSPACE_ID = "workspace_shared_team"

PRO_PLAN = "pro"
ENTERPRISE_PLAN = "enterprise"
FREE_PLAN = "free"

OWNER_ROLE = "owner"
ADMIN_ROLE = "admin"
OPERATOR_ROLE = "operator"
VIEWER_ROLE = "viewer"

SENSITIVE_ACTIONS = {
    "execute_command",
    "modify_permission",
    "delete_memory",
    "delete_file",
    "export_workspace",
    "send_email",
    "sync_google_ads",
    "push_ip_block",
    "change_subscription",
}

STATE_CHANGING_ACTIONS = {
    "create_task",
    "update_task",
    "delete_task",
    "save_memory",
    "write_file",
    "delete_file",
    "modify_permission",
    "change_subscription",
    "run_workflow",
    "send_email",
    "push_ip_block",
}


# ---------------------------------------------------------------------------
# Local contracts
# ---------------------------------------------------------------------------

class TaskStatus(str, Enum):
    RECEIVED = "received"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMPLETED = "completed"
    FAILED = "failed"


class AuditEventType(str, Enum):
    TASK_RECEIVED = "task.received"
    TASK_COMPLETED = "task.completed"
    TASK_REJECTED = "task.rejected"
    SECURITY_REVIEWED = "security.reviewed"
    MEMORY_WRITTEN = "memory.written"
    FILE_WRITTEN = "file.written"
    BILLING_CHECKED = "billing.checked"
    AGENT_ACCESS_CHECKED = "agent_access.checked"


@dataclass(frozen=True)
class TenantIdentity:
    user_id: str
    workspace_id: str
    role: str = OWNER_ROLE
    plan: str = PRO_PLAN


@dataclass(frozen=True)
class AgentTask:
    task_id: str
    user_id: str
    workspace_id: str
    action: str
    agent_name: str
    payload: Dict[str, Any] = field(default_factory=dict)
    sensitive: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResponse:
    success: bool
    task_id: str
    user_id: str
    workspace_id: str
    status: str
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    security_payload: Optional[Dict[str, Any]] = None
    memory_payload: Optional[Dict[str, Any]] = None
    verification_payload: Optional[Dict[str, Any]] = None
    audit_ids: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class MemoryRecord:
    memory_id: str
    user_id: str
    workspace_id: str
    task_id: str
    agent_name: str
    content: Dict[str, Any]
    created_at: str


@dataclass(frozen=True)
class FileRecord:
    file_id: str
    user_id: str
    workspace_id: str
    filename: str
    content: str
    created_at: str


@dataclass(frozen=True)
class AuditRecord:
    audit_id: str
    event_type: str
    user_id: str
    workspace_id: str
    task_id: Optional[str]
    actor_role: str
    details: Dict[str, Any]
    created_at: str


@dataclass(frozen=True)
class AnalyticsRecord:
    analytics_id: str
    user_id: str
    workspace_id: str
    metric_name: str
    metric_value: int
    created_at: str


@dataclass(frozen=True)
class BillingRecord:
    billing_id: str
    user_id: str
    workspace_id: str
    plan: str
    usage_units: int
    created_at: str


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_error(message: str) -> str:
    """Return safe error messages without leaking secrets or internal config."""

    unsafe_values = [
        os.environ.get("DATABASE_URL", ""),
        os.environ.get("OPENAI_API_KEY", ""),
        os.environ.get("SECRET_KEY", ""),
        os.environ.get("JWT_SECRET", ""),
    ]

    safe = str(message)
    for value in unsafe_values:
        if value:
            safe = safe.replace(value, "[redacted]")

    dangerous_terms = ("traceback", "stacktrace", "password=", "secret=", "token=")
    lowered = safe.lower()
    if any(term in lowered for term in dangerous_terms):
        return "A safe application error occurred."

    return safe


def make_task(
    *,
    user_id: str,
    workspace_id: str,
    action: str = "create_task",
    agent_name: str = "master_agent",
    payload: Optional[Dict[str, Any]] = None,
    sensitive: Optional[bool] = None,
    task_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> AgentTask:
    resolved_sensitive = action in SENSITIVE_ACTIONS if sensitive is None else sensitive
    return AgentTask(
        task_id=task_id or f"task_{uuid4().hex}",
        user_id=user_id,
        workspace_id=workspace_id,
        action=action,
        agent_name=agent_name,
        payload=payload or {},
        sensitive=resolved_sensitive,
        metadata=metadata or {"source": "pytest", "request_id": f"request_{uuid4().hex}"},
    )


def response_to_dict(response: AgentResponse) -> Dict[str, Any]:
    return {
        "success": response.success,
        "task_id": response.task_id,
        "user_id": response.user_id,
        "workspace_id": response.workspace_id,
        "status": response.status,
        "data": response.data,
        "error": response.error,
        "security_payload": response.security_payload,
        "memory_payload": response.memory_payload,
        "verification_payload": response.verification_payload,
        "audit_ids": response.audit_ids,
    }


def normalize_response(response: Any) -> Dict[str, Any]:
    if isinstance(response, Mapping):
        return dict(response)

    if hasattr(response, "model_dump") and callable(response.model_dump):
        return dict(response.model_dump())

    if hasattr(response, "dict") and callable(response.dict):
        return dict(response.dict())

    if hasattr(response, "__dataclass_fields__"):
        return {
            key: getattr(response, key)
            for key in response.__dataclass_fields__.keys()
        }

    keys = (
        "success",
        "task_id",
        "user_id",
        "workspace_id",
        "status",
        "data",
        "error",
        "security_payload",
        "memory_payload",
        "verification_payload",
        "audit_ids",
    )
    return {key: getattr(response, key, None) for key in keys if hasattr(response, key)}


def import_class_from_candidates(candidates: Sequence[str], class_name: str) -> Optional[type]:
    for module_path in candidates:
        try:
            module = importlib.import_module(module_path)
        except Exception:
            continue

        candidate = getattr(module, class_name, None)
        if inspect.isclass(candidate):
            return candidate

    return None


# ---------------------------------------------------------------------------
# In-memory SaaS storage double
# ---------------------------------------------------------------------------

class InMemorySaasStore:
    """
    In-memory tenant-aware storage used by integration contract tests.

    Every read method requires both user_id and workspace_id. This mirrors the
    expected production rule: no memory, files, logs, tasks, analytics, billing,
    or agent access can be queried by only one boundary.
    """

    def __init__(self) -> None:
        self.tasks: List[AgentTask] = []
        self.memory_records: List[MemoryRecord] = []
        self.file_records: List[FileRecord] = []
        self.audit_records: List[AuditRecord] = []
        self.analytics_records: List[AnalyticsRecord] = []
        self.billing_records: List[BillingRecord] = []
        self.agent_permissions: Dict[str, Dict[str, List[str]]] = {}
        self.workspace_plans: Dict[str, str] = {}

    def set_workspace_plan(self, workspace_id: str, plan: str) -> None:
        self.workspace_plans[workspace_id] = plan

    def get_workspace_plan(self, workspace_id: str) -> str:
        return self.workspace_plans.get(workspace_id, FREE_PLAN)

    def grant_agent_access(self, workspace_id: str, role: str, agent_names: Iterable[str]) -> None:
        self.agent_permissions.setdefault(workspace_id, {})
        self.agent_permissions[workspace_id][role] = list(agent_names)

    def can_access_agent(self, *, workspace_id: str, role: str, agent_name: str) -> bool:
        allowed = self.agent_permissions.get(workspace_id, {}).get(role, [])
        return "*" in allowed or agent_name in allowed

    def save_task(self, task: AgentTask) -> None:
        self.tasks.append(task)

    def list_tasks(self, *, user_id: str, workspace_id: str) -> List[AgentTask]:
        return [
            task
            for task in self.tasks
            if task.user_id == user_id and task.workspace_id == workspace_id
        ]

    def save_memory(self, record: MemoryRecord) -> None:
        self.memory_records.append(record)

    def list_memory(self, *, user_id: str, workspace_id: str) -> List[MemoryRecord]:
        return [
            record
            for record in self.memory_records
            if record.user_id == user_id and record.workspace_id == workspace_id
        ]

    def write_file(self, record: FileRecord) -> None:
        self.file_records.append(record)

    def list_files(self, *, user_id: str, workspace_id: str) -> List[FileRecord]:
        return [
            record
            for record in self.file_records
            if record.user_id == user_id and record.workspace_id == workspace_id
        ]

    def save_audit(self, record: AuditRecord) -> None:
        self.audit_records.append(record)

    def list_audit(self, *, user_id: str, workspace_id: str) -> List[AuditRecord]:
        return [
            record
            for record in self.audit_records
            if record.user_id == user_id and record.workspace_id == workspace_id
        ]

    def save_analytics(self, record: AnalyticsRecord) -> None:
        self.analytics_records.append(record)

    def list_analytics(self, *, user_id: str, workspace_id: str) -> List[AnalyticsRecord]:
        return [
            record
            for record in self.analytics_records
            if record.user_id == user_id and record.workspace_id == workspace_id
        ]

    def save_billing(self, record: BillingRecord) -> None:
        self.billing_records.append(record)

    def list_billing(self, *, user_id: str, workspace_id: str) -> List[BillingRecord]:
        return [
            record
            for record in self.billing_records
            if record.user_id == user_id and record.workspace_id == workspace_id
        ]


# ---------------------------------------------------------------------------
# Service doubles
# ---------------------------------------------------------------------------

class AuditServiceDouble:
    def __init__(self, store: InMemorySaasStore) -> None:
        self.store = store

    async def log(
        self,
        *,
        event_type: str,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str],
        actor_role: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        record = AuditRecord(
            audit_id=f"audit_{uuid4().hex}",
            event_type=event_type,
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=task_id,
            actor_role=actor_role,
            details=details or {},
            created_at=utc_now_iso(),
        )
        self.store.save_audit(record)
        return record


class SecurityAgentDouble:
    def __init__(self, audit_service: AuditServiceDouble, approve: bool = True) -> None:
        self.audit_service = audit_service
        self.approve = approve
        self.reviews: List[Dict[str, Any]] = []

    async def review_sensitive_action(self, task: AgentTask, identity: TenantIdentity) -> Dict[str, Any]:
        review = {
            "approved": self.approve,
            "task_id": task.task_id,
            "user_id": task.user_id,
            "workspace_id": task.workspace_id,
            "action": task.action,
            "risk_level": "high" if task.sensitive else "low",
            "reason": "approved by security policy" if self.approve else "rejected by security policy",
            "reviewed_at": utc_now_iso(),
        }
        self.reviews.append(review)

        await self.audit_service.log(
            event_type=AuditEventType.SECURITY_REVIEWED.value,
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            task_id=task.task_id,
            actor_role=identity.role,
            details={
                "approved": review["approved"],
                "risk_level": review["risk_level"],
                "action": task.action,
            },
        )

        return review


class MemoryAgentDouble:
    def __init__(self, store: InMemorySaasStore, audit_service: AuditServiceDouble) -> None:
        self.store = store
        self.audit_service = audit_service

    async def save_context(self, task: AgentTask, result: Mapping[str, Any], identity: TenantIdentity) -> MemoryRecord:
        record = MemoryRecord(
            memory_id=f"memory_{uuid4().hex}",
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            task_id=task.task_id,
            agent_name=task.agent_name,
            content={
                "action": task.action,
                "input": task.payload,
                "result_summary": {
                    "success": bool(result.get("success", True)),
                    "status": result.get("status", TaskStatus.COMPLETED.value),
                },
            },
            created_at=utc_now_iso(),
        )
        self.store.save_memory(record)

        await self.audit_service.log(
            event_type=AuditEventType.MEMORY_WRITTEN.value,
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            task_id=task.task_id,
            actor_role=identity.role,
            details={"memory_id": record.memory_id, "agent_name": task.agent_name},
        )

        return record

    async def recall(self, *, user_id: str, workspace_id: str) -> List[MemoryRecord]:
        return self.store.list_memory(user_id=user_id, workspace_id=workspace_id)


class VerificationAgentDouble:
    def __init__(self) -> None:
        self.payloads: List[Dict[str, Any]] = []

    async def prepare_verification_payload(self, task: AgentTask, result: Mapping[str, Any]) -> Dict[str, Any]:
        payload = {
            "verification_id": f"verify_{uuid4().hex}",
            "task_id": task.task_id,
            "user_id": task.user_id,
            "workspace_id": task.workspace_id,
            "agent_name": task.agent_name,
            "status": result.get("status", TaskStatus.COMPLETED.value),
            "result": dict(result),
            "requires_user_confirmation": False,
            "prepared_at": utc_now_iso(),
        }
        self.payloads.append(payload)
        return payload


class BillingServiceDouble:
    PLAN_ORDER = {
        FREE_PLAN: 0,
        PRO_PLAN: 1,
        ENTERPRISE_PLAN: 2,
    }

    AGENT_PLAN_REQUIREMENTS = {
        "master_agent": FREE_PLAN,
        "memory_agent": PRO_PLAN,
        "security_agent": PRO_PLAN,
        "verification_agent": PRO_PLAN,
        "browser_agent": PRO_PLAN,
        "code_agent": PRO_PLAN,
        "finance_agent": ENTERPRISE_PLAN,
        "workflow_agent": PRO_PLAN,
        "call_agent": ENTERPRISE_PLAN,
    }

    def __init__(self, store: InMemorySaasStore, audit_service: AuditServiceDouble) -> None:
        self.store = store
        self.audit_service = audit_service

    async def check_plan_access(self, task: AgentTask, identity: TenantIdentity) -> Dict[str, Any]:
        workspace_plan = self.store.get_workspace_plan(task.workspace_id)
        required_plan = self.AGENT_PLAN_REQUIREMENTS.get(task.agent_name, FREE_PLAN)

        allowed = self.PLAN_ORDER.get(workspace_plan, 0) >= self.PLAN_ORDER.get(required_plan, 0)

        await self.audit_service.log(
            event_type=AuditEventType.BILLING_CHECKED.value,
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            task_id=task.task_id,
            actor_role=identity.role,
            details={
                "workspace_plan": workspace_plan,
                "required_plan": required_plan,
                "allowed": allowed,
            },
        )

        return {
            "allowed": allowed,
            "workspace_plan": workspace_plan,
            "required_plan": required_plan,
        }

    async def record_usage(self, task: AgentTask) -> BillingRecord:
        record = BillingRecord(
            billing_id=f"billing_{uuid4().hex}",
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            plan=self.store.get_workspace_plan(task.workspace_id),
            usage_units=1,
            created_at=utc_now_iso(),
        )
        self.store.save_billing(record)
        return record


class AgentRegistryDouble:
    def __init__(self, store: InMemorySaasStore, audit_service: AuditServiceDouble) -> None:
        self.store = store
        self.audit_service = audit_service

    async def check_agent_access(self, task: AgentTask, identity: TenantIdentity) -> Dict[str, Any]:
        allowed = self.store.can_access_agent(
            workspace_id=task.workspace_id,
            role=identity.role,
            agent_name=task.agent_name,
        )

        await self.audit_service.log(
            event_type=AuditEventType.AGENT_ACCESS_CHECKED.value,
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            task_id=task.task_id,
            actor_role=identity.role,
            details={
                "agent_name": task.agent_name,
                "role": identity.role,
                "allowed": allowed,
            },
        )

        return {
            "allowed": allowed,
            "agent_name": task.agent_name,
            "role": identity.role,
        }


class FileServiceDouble:
    def __init__(self, store: InMemorySaasStore, audit_service: AuditServiceDouble) -> None:
        self.store = store
        self.audit_service = audit_service

    async def write_file(self, task: AgentTask, identity: TenantIdentity) -> FileRecord:
        filename = str(task.payload.get("filename", f"{task.task_id}.txt"))
        content = str(task.payload.get("content", ""))

        record = FileRecord(
            file_id=f"file_{uuid4().hex}",
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            filename=filename,
            content=content,
            created_at=utc_now_iso(),
        )
        self.store.write_file(record)

        await self.audit_service.log(
            event_type=AuditEventType.FILE_WRITTEN.value,
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            task_id=task.task_id,
            actor_role=identity.role,
            details={"file_id": record.file_id, "filename": filename},
        )

        return record

    async def list_files(self, *, user_id: str, workspace_id: str) -> List[FileRecord]:
        return self.store.list_files(user_id=user_id, workspace_id=workspace_id)


class AnalyticsServiceDouble:
    def __init__(self, store: InMemorySaasStore) -> None:
        self.store = store

    async def record_task_completion(self, task: AgentTask) -> AnalyticsRecord:
        record = AnalyticsRecord(
            analytics_id=f"analytics_{uuid4().hex}",
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            metric_name="task_completed",
            metric_value=1,
            created_at=utc_now_iso(),
        )
        self.store.save_analytics(record)
        return record

    async def dashboard_metrics(self, *, user_id: str, workspace_id: str) -> Dict[str, int]:
        records = self.store.list_analytics(user_id=user_id, workspace_id=workspace_id)
        return {
            "task_completed": sum(
                record.metric_value
                for record in records
                if record.metric_name == "task_completed"
            )
        }


class MasterAgentDouble:
    """
    Tenant-aware Master Agent double.

    This object simulates the orchestration contract:
    - validate tenant identity
    - check agent permission
    - check subscription/plan
    - route sensitive actions to Security Agent
    - execute state-changing behavior under tenant boundaries
    - save Memory Agent context
    - prepare Verification Agent payload
    - emit audit logs
    - record billing/analytics usage
    """

    def __init__(
        self,
        *,
        store: InMemorySaasStore,
        security_agent: SecurityAgentDouble,
        memory_agent: MemoryAgentDouble,
        verification_agent: VerificationAgentDouble,
        billing_service: BillingServiceDouble,
        agent_registry: AgentRegistryDouble,
        file_service: FileServiceDouble,
        analytics_service: AnalyticsServiceDouble,
        audit_service: AuditServiceDouble,
    ) -> None:
        self.store = store
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.billing_service = billing_service
        self.agent_registry = agent_registry
        self.file_service = file_service
        self.analytics_service = analytics_service
        self.audit_service = audit_service

    async def execute_task(self, task: AgentTask, identity: TenantIdentity) -> Dict[str, Any]:
        audit_ids: List[str] = []

        validation_error = self._validate_task_identity(task, identity)
        if validation_error:
            return response_to_dict(
                AgentResponse(
                    success=False,
                    task_id=getattr(task, "task_id", "unknown"),
                    user_id=getattr(task, "user_id", "unknown"),
                    workspace_id=getattr(task, "workspace_id", "unknown"),
                    status=TaskStatus.FAILED.value,
                    error=validation_error,
                )
            )

        received_audit = await self.audit_service.log(
            event_type=AuditEventType.TASK_RECEIVED.value,
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            task_id=task.task_id,
            actor_role=identity.role,
            details={"action": task.action, "agent_name": task.agent_name},
        )
        audit_ids.append(received_audit.audit_id)

        access = await self.agent_registry.check_agent_access(task, identity)
        if not access["allowed"]:
            rejected_audit = await self.audit_service.log(
                event_type=AuditEventType.TASK_REJECTED.value,
                user_id=task.user_id,
                workspace_id=task.workspace_id,
                task_id=task.task_id,
                actor_role=identity.role,
                details={"reason": "agent_access_denied", "agent_name": task.agent_name},
            )
            audit_ids.append(rejected_audit.audit_id)

            return response_to_dict(
                AgentResponse(
                    success=False,
                    task_id=task.task_id,
                    user_id=task.user_id,
                    workspace_id=task.workspace_id,
                    status=TaskStatus.REJECTED.value,
                    error=safe_error("Agent access denied for this workspace or role."),
                    audit_ids=audit_ids,
                )
            )

        plan_access = await self.billing_service.check_plan_access(task, identity)
        if not plan_access["allowed"]:
            rejected_audit = await self.audit_service.log(
                event_type=AuditEventType.TASK_REJECTED.value,
                user_id=task.user_id,
                workspace_id=task.workspace_id,
                task_id=task.task_id,
                actor_role=identity.role,
                details={"reason": "subscription_plan_denied", **plan_access},
            )
            audit_ids.append(rejected_audit.audit_id)

            return response_to_dict(
                AgentResponse(
                    success=False,
                    task_id=task.task_id,
                    user_id=task.user_id,
                    workspace_id=task.workspace_id,
                    status=TaskStatus.REJECTED.value,
                    error=safe_error("Subscription plan does not allow this agent action."),
                    audit_ids=audit_ids,
                )
            )

        security_payload = None
        if task.sensitive or task.action in SENSITIVE_ACTIONS:
            security_payload = await self.security_agent.review_sensitive_action(task, identity)
            if not security_payload["approved"]:
                rejected_audit = await self.audit_service.log(
                    event_type=AuditEventType.TASK_REJECTED.value,
                    user_id=task.user_id,
                    workspace_id=task.workspace_id,
                    task_id=task.task_id,
                    actor_role=identity.role,
                    details={"reason": "security_rejected"},
                )
                audit_ids.append(rejected_audit.audit_id)

                return response_to_dict(
                    AgentResponse(
                        success=False,
                        task_id=task.task_id,
                        user_id=task.user_id,
                        workspace_id=task.workspace_id,
                        status=TaskStatus.REJECTED.value,
                        error=safe_error("Security Agent rejected this sensitive action."),
                        security_payload=security_payload,
                        audit_ids=audit_ids,
                    )
                )

        self.store.save_task(task)

        result_data = {
            "action": task.action,
            "agent_name": task.agent_name,
            "payload_echo": task.payload,
        }

        if task.action == "write_file":
            file_record = await self.file_service.write_file(task, identity)
            result_data["file_id"] = file_record.file_id
            result_data["filename"] = file_record.filename

        memory_record = await self.memory_agent.save_context(
            task,
            {"success": True, "status": TaskStatus.COMPLETED.value},
            identity,
        )

        verification_payload = await self.verification_agent.prepare_verification_payload(
            task,
            {
                "success": True,
                "status": TaskStatus.COMPLETED.value,
                "data": result_data,
            },
        )

        await self.billing_service.record_usage(task)
        await self.analytics_service.record_task_completion(task)

        completed_audit = await self.audit_service.log(
            event_type=AuditEventType.TASK_COMPLETED.value,
            user_id=task.user_id,
            workspace_id=task.workspace_id,
            task_id=task.task_id,
            actor_role=identity.role,
            details={"agent_name": task.agent_name, "action": task.action},
        )
        audit_ids.append(completed_audit.audit_id)

        return response_to_dict(
            AgentResponse(
                success=True,
                task_id=task.task_id,
                user_id=task.user_id,
                workspace_id=task.workspace_id,
                status=TaskStatus.COMPLETED.value,
                data=result_data,
                security_payload=security_payload,
                memory_payload={
                    "memory_id": memory_record.memory_id,
                    "user_id": memory_record.user_id,
                    "workspace_id": memory_record.workspace_id,
                    "task_id": memory_record.task_id,
                },
                verification_payload=verification_payload,
                audit_ids=audit_ids,
            )
        )

    @staticmethod
    def _validate_task_identity(task: AgentTask, identity: TenantIdentity) -> Optional[str]:
        if not getattr(task, "task_id", None):
            return safe_error("Task is missing task_id.")

        if not getattr(task, "user_id", None):
            return safe_error("Task is missing user_id.")

        if not getattr(task, "workspace_id", None):
            return safe_error("Task is missing workspace_id.")

        if task.user_id != identity.user_id:
            return safe_error("Task user_id does not match authenticated user.")

        if task.workspace_id != identity.workspace_id:
            return safe_error("Task workspace_id does not match authenticated workspace.")

        return None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def alpha_identity() -> TenantIdentity:
    return TenantIdentity(
        user_id=ALPHA_USER_ID,
        workspace_id=ALPHA_WORKSPACE_ID,
        role=OWNER_ROLE,
        plan=PRO_PLAN,
    )


@pytest.fixture()
def beta_identity() -> TenantIdentity:
    return TenantIdentity(
        user_id=BETA_USER_ID,
        workspace_id=BETA_WORKSPACE_ID,
        role=OWNER_ROLE,
        plan=PRO_PLAN,
    )


@pytest.fixture()
def alpha_viewer_identity() -> TenantIdentity:
    return TenantIdentity(
        user_id=ALPHA_USER_ID,
        workspace_id=ALPHA_WORKSPACE_ID,
        role=VIEWER_ROLE,
        plan=FREE_PLAN,
    )


@pytest.fixture()
def shared_owner_identity() -> TenantIdentity:
    return TenantIdentity(
        user_id=ALPHA_USER_ID,
        workspace_id=SHARED_WORKSPACE_ID,
        role=OWNER_ROLE,
        plan=ENTERPRISE_PLAN,
    )


@pytest.fixture()
def shared_operator_identity() -> TenantIdentity:
    return TenantIdentity(
        user_id=BETA_USER_ID,
        workspace_id=SHARED_WORKSPACE_ID,
        role=OPERATOR_ROLE,
        plan=ENTERPRISE_PLAN,
    )


@pytest.fixture()
def saas_store() -> InMemorySaasStore:
    store = InMemorySaasStore()

    store.set_workspace_plan(ALPHA_WORKSPACE_ID, PRO_PLAN)
    store.set_workspace_plan(BETA_WORKSPACE_ID, PRO_PLAN)
    store.set_workspace_plan(SHARED_WORKSPACE_ID, ENTERPRISE_PLAN)

    store.grant_agent_access(ALPHA_WORKSPACE_ID, OWNER_ROLE, ["*"])
    store.grant_agent_access(ALPHA_WORKSPACE_ID, ADMIN_ROLE, ["master_agent", "memory_agent", "security_agent"])
    store.grant_agent_access(ALPHA_WORKSPACE_ID, OPERATOR_ROLE, ["master_agent", "memory_agent"])
    store.grant_agent_access(ALPHA_WORKSPACE_ID, VIEWER_ROLE, [])

    store.grant_agent_access(BETA_WORKSPACE_ID, OWNER_ROLE, ["*"])
    store.grant_agent_access(BETA_WORKSPACE_ID, ADMIN_ROLE, ["master_agent", "memory_agent", "security_agent"])
    store.grant_agent_access(BETA_WORKSPACE_ID, OPERATOR_ROLE, ["master_agent", "memory_agent"])
    store.grant_agent_access(BETA_WORKSPACE_ID, VIEWER_ROLE, [])

    store.grant_agent_access(SHARED_WORKSPACE_ID, OWNER_ROLE, ["*"])
    store.grant_agent_access(SHARED_WORKSPACE_ID, ADMIN_ROLE, ["*"])
    store.grant_agent_access(SHARED_WORKSPACE_ID, OPERATOR_ROLE, ["master_agent", "memory_agent", "workflow_agent"])
    store.grant_agent_access(SHARED_WORKSPACE_ID, VIEWER_ROLE, [])

    return store


@pytest.fixture()
def saas_services(saas_store: InMemorySaasStore) -> Dict[str, Any]:
    audit_service = AuditServiceDouble(saas_store)
    security_agent = SecurityAgentDouble(audit_service, approve=True)
    memory_agent = MemoryAgentDouble(saas_store, audit_service)
    verification_agent = VerificationAgentDouble()
    billing_service = BillingServiceDouble(saas_store, audit_service)
    agent_registry = AgentRegistryDouble(saas_store, audit_service)
    file_service = FileServiceDouble(saas_store, audit_service)
    analytics_service = AnalyticsServiceDouble(saas_store)

    return {
        "store": saas_store,
        "audit_service": audit_service,
        "security_agent": security_agent,
        "memory_agent": memory_agent,
        "verification_agent": verification_agent,
        "billing_service": billing_service,
        "agent_registry": agent_registry,
        "file_service": file_service,
        "analytics_service": analytics_service,
    }


@pytest.fixture()
def master_agent(saas_services: Dict[str, Any]) -> MasterAgentDouble:
    return MasterAgentDouble(
        store=saas_services["store"],
        security_agent=saas_services["security_agent"],
        memory_agent=saas_services["memory_agent"],
        verification_agent=saas_services["verification_agent"],
        billing_service=saas_services["billing_service"],
        agent_registry=saas_services["agent_registry"],
        file_service=saas_services["file_service"],
        analytics_service=saas_services["analytics_service"],
        audit_service=saas_services["audit_service"],
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSaasIsolation:
    """Integration contract tests for SaaS tenant isolation."""

    def test_future_real_agent_imports_are_safe(self) -> None:
        """
        Real production modules may not exist yet.

        This test confirms the import probing itself is safe and does not break
        test collection during incremental architecture builds.
        """

        master_agent_class = import_class_from_candidates(
            MASTER_AGENT_IMPORT_CANDIDATES,
            "MasterAgent",
        )
        memory_agent_class = import_class_from_candidates(
            MEMORY_AGENT_IMPORT_CANDIDATES,
            "MemoryAgent",
        )
        security_agent_class = import_class_from_candidates(
            SECURITY_AGENT_IMPORT_CANDIDATES,
            "SecurityAgent",
        )
        verification_agent_class = import_class_from_candidates(
            VERIFICATION_AGENT_IMPORT_CANDIDATES,
            "VerificationAgent",
        )

        for candidate in (
            master_agent_class,
            memory_agent_class,
            security_agent_class,
            verification_agent_class,
        ):
            assert candidate is None or inspect.isclass(candidate)

    @pytest.mark.asyncio()
    async def test_task_identity_requires_user_id_and_workspace_id(
        self,
        master_agent: MasterAgentDouble,
        alpha_identity: TenantIdentity,
    ) -> None:
        missing_user_task = make_task(
            user_id="",
            workspace_id=ALPHA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
        )
        missing_workspace_task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id="",
            action="create_task",
            agent_name="master_agent",
        )

        response_missing_user = await master_agent.execute_task(missing_user_task, alpha_identity)
        response_missing_workspace = await master_agent.execute_task(missing_workspace_task, alpha_identity)

        assert response_missing_user["success"] is False
        assert response_missing_workspace["success"] is False
        assert "user_id" in response_missing_user["error"]
        assert "workspace_id" in response_missing_workspace["error"]

    @pytest.mark.asyncio()
    async def test_task_user_must_match_authenticated_identity(
        self,
        master_agent: MasterAgentDouble,
        alpha_identity: TenantIdentity,
    ) -> None:
        beta_task_under_alpha_auth = make_task(
            user_id=BETA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
        )

        response = await master_agent.execute_task(beta_task_under_alpha_auth, alpha_identity)

        assert response["success"] is False
        assert response["status"] == TaskStatus.FAILED.value
        assert "user_id" in response["error"]
        assert "traceback" not in response["error"].lower()

    @pytest.mark.asyncio()
    async def test_task_workspace_must_match_authenticated_identity(
        self,
        master_agent: MasterAgentDouble,
        alpha_identity: TenantIdentity,
    ) -> None:
        cross_workspace_task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=BETA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
        )

        response = await master_agent.execute_task(cross_workspace_task, alpha_identity)

        assert response["success"] is False
        assert response["status"] == TaskStatus.FAILED.value
        assert "workspace_id" in response["error"]
        assert "traceback" not in response["error"].lower()

    @pytest.mark.asyncio()
    async def test_tasks_do_not_mix_between_users_or_workspaces(
        self,
        master_agent: MasterAgentDouble,
        saas_store: InMemorySaasStore,
        alpha_identity: TenantIdentity,
        beta_identity: TenantIdentity,
    ) -> None:
        alpha_task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
            payload={"private_note": "alpha only"},
        )
        beta_task = make_task(
            user_id=BETA_USER_ID,
            workspace_id=BETA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
            payload={"private_note": "beta only"},
        )

        response_alpha, response_beta = await asyncio.gather(
            master_agent.execute_task(alpha_task, alpha_identity),
            master_agent.execute_task(beta_task, beta_identity),
        )

        assert response_alpha["success"] is True
        assert response_beta["success"] is True

        alpha_tasks = saas_store.list_tasks(user_id=ALPHA_USER_ID, workspace_id=ALPHA_WORKSPACE_ID)
        beta_tasks = saas_store.list_tasks(user_id=BETA_USER_ID, workspace_id=BETA_WORKSPACE_ID)

        assert len(alpha_tasks) == 1
        assert len(beta_tasks) == 1
        assert alpha_tasks[0].payload["private_note"] == "alpha only"
        assert beta_tasks[0].payload["private_note"] == "beta only"

        assert "beta only" not in str(alpha_tasks)
        assert "alpha only" not in str(beta_tasks)

    @pytest.mark.asyncio()
    async def test_memory_records_are_isolated_by_user_and_workspace(
        self,
        master_agent: MasterAgentDouble,
        saas_services: Dict[str, Any],
        alpha_identity: TenantIdentity,
        beta_identity: TenantIdentity,
    ) -> None:
        memory_agent: MemoryAgentDouble = saas_services["memory_agent"]

        alpha_task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="save_memory",
            agent_name="memory_agent",
            payload={"knowledge": "alpha workspace memory"},
        )
        beta_task = make_task(
            user_id=BETA_USER_ID,
            workspace_id=BETA_WORKSPACE_ID,
            action="save_memory",
            agent_name="memory_agent",
            payload={"knowledge": "beta workspace memory"},
        )

        await master_agent.execute_task(alpha_task, alpha_identity)
        await master_agent.execute_task(beta_task, beta_identity)

        alpha_memory = await memory_agent.recall(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
        )
        beta_memory = await memory_agent.recall(
            user_id=BETA_USER_ID,
            workspace_id=BETA_WORKSPACE_ID,
        )

        assert len(alpha_memory) == 1
        assert len(beta_memory) == 1

        assert alpha_memory[0].user_id == ALPHA_USER_ID
        assert alpha_memory[0].workspace_id == ALPHA_WORKSPACE_ID
        assert beta_memory[0].user_id == BETA_USER_ID
        assert beta_memory[0].workspace_id == BETA_WORKSPACE_ID

        assert "beta workspace memory" not in str(alpha_memory)
        assert "alpha workspace memory" not in str(beta_memory)

    @pytest.mark.asyncio()
    async def test_file_records_are_isolated_by_user_and_workspace(
        self,
        master_agent: MasterAgentDouble,
        saas_services: Dict[str, Any],
        alpha_identity: TenantIdentity,
        beta_identity: TenantIdentity,
    ) -> None:
        file_service: FileServiceDouble = saas_services["file_service"]

        alpha_file_task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="write_file",
            agent_name="master_agent",
            payload={
                "filename": "alpha-report.txt",
                "content": "confidential alpha report",
            },
        )
        beta_file_task = make_task(
            user_id=BETA_USER_ID,
            workspace_id=BETA_WORKSPACE_ID,
            action="write_file",
            agent_name="master_agent",
            payload={
                "filename": "beta-report.txt",
                "content": "confidential beta report",
            },
        )

        await master_agent.execute_task(alpha_file_task, alpha_identity)
        await master_agent.execute_task(beta_file_task, beta_identity)

        alpha_files = await file_service.list_files(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
        )
        beta_files = await file_service.list_files(
            user_id=BETA_USER_ID,
            workspace_id=BETA_WORKSPACE_ID,
        )

        assert len(alpha_files) == 1
        assert len(beta_files) == 1
        assert alpha_files[0].filename == "alpha-report.txt"
        assert beta_files[0].filename == "beta-report.txt"
        assert "confidential beta report" not in str(alpha_files)
        assert "confidential alpha report" not in str(beta_files)

    @pytest.mark.asyncio()
    async def test_audit_logs_are_isolated_by_user_and_workspace(
        self,
        master_agent: MasterAgentDouble,
        saas_store: InMemorySaasStore,
        alpha_identity: TenantIdentity,
        beta_identity: TenantIdentity,
    ) -> None:
        alpha_task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="write_file",
            agent_name="master_agent",
            payload={"filename": "alpha.txt", "content": "alpha audit data"},
        )
        beta_task = make_task(
            user_id=BETA_USER_ID,
            workspace_id=BETA_WORKSPACE_ID,
            action="write_file",
            agent_name="master_agent",
            payload={"filename": "beta.txt", "content": "beta audit data"},
        )

        await master_agent.execute_task(alpha_task, alpha_identity)
        await master_agent.execute_task(beta_task, beta_identity)

        alpha_audit = saas_store.list_audit(user_id=ALPHA_USER_ID, workspace_id=ALPHA_WORKSPACE_ID)
        beta_audit = saas_store.list_audit(user_id=BETA_USER_ID, workspace_id=BETA_WORKSPACE_ID)

        assert alpha_audit
        assert beta_audit

        assert all(record.user_id == ALPHA_USER_ID for record in alpha_audit)
        assert all(record.workspace_id == ALPHA_WORKSPACE_ID for record in alpha_audit)
        assert all(record.user_id == BETA_USER_ID for record in beta_audit)
        assert all(record.workspace_id == BETA_WORKSPACE_ID for record in beta_audit)

        assert "beta.txt" not in str(alpha_audit)
        assert "alpha.txt" not in str(beta_audit)

    @pytest.mark.asyncio()
    async def test_dashboard_analytics_are_tenant_scoped(
        self,
        master_agent: MasterAgentDouble,
        saas_services: Dict[str, Any],
        alpha_identity: TenantIdentity,
        beta_identity: TenantIdentity,
    ) -> None:
        analytics_service: AnalyticsServiceDouble = saas_services["analytics_service"]

        alpha_task_one = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
        )
        alpha_task_two = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
        )
        beta_task = make_task(
            user_id=BETA_USER_ID,
            workspace_id=BETA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
        )

        await master_agent.execute_task(alpha_task_one, alpha_identity)
        await master_agent.execute_task(alpha_task_two, alpha_identity)
        await master_agent.execute_task(beta_task, beta_identity)

        alpha_metrics = await analytics_service.dashboard_metrics(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
        )
        beta_metrics = await analytics_service.dashboard_metrics(
            user_id=BETA_USER_ID,
            workspace_id=BETA_WORKSPACE_ID,
        )

        assert alpha_metrics["task_completed"] == 2
        assert beta_metrics["task_completed"] == 1

    @pytest.mark.asyncio()
    async def test_billing_usage_is_tenant_scoped(
        self,
        master_agent: MasterAgentDouble,
        saas_store: InMemorySaasStore,
        alpha_identity: TenantIdentity,
        beta_identity: TenantIdentity,
    ) -> None:
        alpha_task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
        )
        beta_task = make_task(
            user_id=BETA_USER_ID,
            workspace_id=BETA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
        )

        await master_agent.execute_task(alpha_task, alpha_identity)
        await master_agent.execute_task(beta_task, beta_identity)

        alpha_billing = saas_store.list_billing(user_id=ALPHA_USER_ID, workspace_id=ALPHA_WORKSPACE_ID)
        beta_billing = saas_store.list_billing(user_id=BETA_USER_ID, workspace_id=BETA_WORKSPACE_ID)

        assert len(alpha_billing) == 1
        assert len(beta_billing) == 1
        assert alpha_billing[0].plan == PRO_PLAN
        assert beta_billing[0].plan == PRO_PLAN
        assert alpha_billing[0].workspace_id != beta_billing[0].workspace_id

    @pytest.mark.asyncio()
    async def test_agent_access_is_role_and_workspace_scoped(
        self,
        master_agent: MasterAgentDouble,
        alpha_viewer_identity: TenantIdentity,
    ) -> None:
        task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
        )

        response = await master_agent.execute_task(task, alpha_viewer_identity)

        assert response["success"] is False
        assert response["status"] == TaskStatus.REJECTED.value
        assert "access denied" in response["error"].lower()
        assert response["user_id"] == ALPHA_USER_ID
        assert response["workspace_id"] == ALPHA_WORKSPACE_ID

    @pytest.mark.asyncio()
    async def test_subscription_plan_blocks_enterprise_only_agent(
        self,
        master_agent: MasterAgentDouble,
        alpha_identity: TenantIdentity,
    ) -> None:
        task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="create_task",
            agent_name="finance_agent",
            payload={"report": "enterprise finance forecast"},
        )

        response = await master_agent.execute_task(task, alpha_identity)

        assert response["success"] is False
        assert response["status"] == TaskStatus.REJECTED.value
        assert "subscription" in response["error"].lower()
        assert response["user_id"] == ALPHA_USER_ID
        assert response["workspace_id"] == ALPHA_WORKSPACE_ID

    @pytest.mark.asyncio()
    async def test_subscription_plan_allows_enterprise_workspace_agent(
        self,
        master_agent: MasterAgentDouble,
        shared_owner_identity: TenantIdentity,
    ) -> None:
        task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=SHARED_WORKSPACE_ID,
            action="create_task",
            agent_name="finance_agent",
            payload={"report": "enterprise finance forecast"},
        )

        response = await master_agent.execute_task(task, shared_owner_identity)

        assert response["success"] is True
        assert response["status"] == TaskStatus.COMPLETED.value
        assert response["user_id"] == ALPHA_USER_ID
        assert response["workspace_id"] == SHARED_WORKSPACE_ID

    @pytest.mark.asyncio()
    async def test_sensitive_action_routes_to_security_agent(
        self,
        master_agent: MasterAgentDouble,
        saas_services: Dict[str, Any],
        alpha_identity: TenantIdentity,
    ) -> None:
        security_agent: SecurityAgentDouble = saas_services["security_agent"]

        task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="push_ip_block",
            agent_name="security_agent",
            payload={"ip": "203.0.113.44", "reason": "invalid click pattern"},
            sensitive=True,
        )

        response = await master_agent.execute_task(task, alpha_identity)

        assert response["success"] is True
        assert response["security_payload"] is not None
        assert len(security_agent.reviews) == 1
        assert security_agent.reviews[0]["task_id"] == task.task_id
        assert security_agent.reviews[0]["user_id"] == ALPHA_USER_ID
        assert security_agent.reviews[0]["workspace_id"] == ALPHA_WORKSPACE_ID

    @pytest.mark.asyncio()
    async def test_security_rejection_stops_sensitive_action(
        self,
        saas_store: InMemorySaasStore,
        alpha_identity: TenantIdentity,
    ) -> None:
        audit_service = AuditServiceDouble(saas_store)
        security_agent = SecurityAgentDouble(audit_service, approve=False)
        memory_agent = MemoryAgentDouble(saas_store, audit_service)
        verification_agent = VerificationAgentDouble()
        billing_service = BillingServiceDouble(saas_store, audit_service)
        agent_registry = AgentRegistryDouble(saas_store, audit_service)
        file_service = FileServiceDouble(saas_store, audit_service)
        analytics_service = AnalyticsServiceDouble(saas_store)

        master_agent = MasterAgentDouble(
            store=saas_store,
            security_agent=security_agent,
            memory_agent=memory_agent,
            verification_agent=verification_agent,
            billing_service=billing_service,
            agent_registry=agent_registry,
            file_service=file_service,
            analytics_service=analytics_service,
            audit_service=audit_service,
        )

        task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="modify_permission",
            agent_name="security_agent",
            payload={"target_user_id": BETA_USER_ID, "new_role": ADMIN_ROLE},
            sensitive=True,
        )

        response = await master_agent.execute_task(task, alpha_identity)

        assert response["success"] is False
        assert response["status"] == TaskStatus.REJECTED.value
        assert response["security_payload"]["approved"] is False
        assert not saas_store.list_tasks(user_id=ALPHA_USER_ID, workspace_id=ALPHA_WORKSPACE_ID)
        assert not saas_store.list_memory(user_id=ALPHA_USER_ID, workspace_id=ALPHA_WORKSPACE_ID)

    @pytest.mark.asyncio()
    async def test_completed_action_prepares_verification_payload_with_tenant_scope(
        self,
        master_agent: MasterAgentDouble,
        saas_services: Dict[str, Any],
        alpha_identity: TenantIdentity,
    ) -> None:
        verification_agent: VerificationAgentDouble = saas_services["verification_agent"]

        task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
            payload={"goal": "verify tenant-safe completion"},
        )

        response = await master_agent.execute_task(task, alpha_identity)

        assert response["success"] is True
        assert response["verification_payload"] is not None
        assert response["verification_payload"]["task_id"] == task.task_id
        assert response["verification_payload"]["user_id"] == ALPHA_USER_ID
        assert response["verification_payload"]["workspace_id"] == ALPHA_WORKSPACE_ID

        assert len(verification_agent.payloads) == 1
        assert verification_agent.payloads[0]["task_id"] == task.task_id
        assert verification_agent.payloads[0]["workspace_id"] == ALPHA_WORKSPACE_ID

    @pytest.mark.asyncio()
    async def test_useful_context_is_memory_agent_compatible_and_tenant_scoped(
        self,
        master_agent: MasterAgentDouble,
        saas_store: InMemorySaasStore,
        alpha_identity: TenantIdentity,
    ) -> None:
        task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
            payload={
                "useful_context": True,
                "summary": "Alpha workspace onboarding preference",
            },
        )

        response = await master_agent.execute_task(task, alpha_identity)

        assert response["success"] is True
        assert response["memory_payload"] is not None
        assert response["memory_payload"]["user_id"] == ALPHA_USER_ID
        assert response["memory_payload"]["workspace_id"] == ALPHA_WORKSPACE_ID

        memory_records = saas_store.list_memory(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
        )
        assert len(memory_records) == 1
        assert memory_records[0].content["input"]["summary"] == "Alpha workspace onboarding preference"

    @pytest.mark.asyncio()
    async def test_same_user_multiple_workspaces_remain_isolated(
        self,
        master_agent: MasterAgentDouble,
        saas_store: InMemorySaasStore,
    ) -> None:
        saas_store.set_workspace_plan("workspace_user_alpha_one", PRO_PLAN)
        saas_store.set_workspace_plan("workspace_user_alpha_two", PRO_PLAN)
        saas_store.grant_agent_access("workspace_user_alpha_one", OWNER_ROLE, ["*"])
        saas_store.grant_agent_access("workspace_user_alpha_two", OWNER_ROLE, ["*"])

        identity_one = TenantIdentity(
            user_id=ALPHA_USER_ID,
            workspace_id="workspace_user_alpha_one",
            role=OWNER_ROLE,
            plan=PRO_PLAN,
        )
        identity_two = TenantIdentity(
            user_id=ALPHA_USER_ID,
            workspace_id="workspace_user_alpha_two",
            role=OWNER_ROLE,
            plan=PRO_PLAN,
        )

        task_one = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id="workspace_user_alpha_one",
            action="create_task",
            agent_name="master_agent",
            payload={"workspace_value": "workspace one private value"},
        )
        task_two = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id="workspace_user_alpha_two",
            action="create_task",
            agent_name="master_agent",
            payload={"workspace_value": "workspace two private value"},
        )

        await master_agent.execute_task(task_one, identity_one)
        await master_agent.execute_task(task_two, identity_two)

        workspace_one_memory = saas_store.list_memory(
            user_id=ALPHA_USER_ID,
            workspace_id="workspace_user_alpha_one",
        )
        workspace_two_memory = saas_store.list_memory(
            user_id=ALPHA_USER_ID,
            workspace_id="workspace_user_alpha_two",
        )

        assert len(workspace_one_memory) == 1
        assert len(workspace_two_memory) == 1
        assert "workspace two private value" not in str(workspace_one_memory)
        assert "workspace one private value" not in str(workspace_two_memory)

    @pytest.mark.asyncio()
    async def test_multiple_users_same_workspace_keep_user_identity_intact(
        self,
        master_agent: MasterAgentDouble,
        saas_store: InMemorySaasStore,
        shared_owner_identity: TenantIdentity,
        shared_operator_identity: TenantIdentity,
    ) -> None:
        owner_task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=SHARED_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
            payload={"actor": "owner private action"},
        )
        operator_task = make_task(
            user_id=BETA_USER_ID,
            workspace_id=SHARED_WORKSPACE_ID,
            action="create_task",
            agent_name="workflow_agent",
            payload={"actor": "operator private action"},
        )

        response_owner, response_operator = await asyncio.gather(
            master_agent.execute_task(owner_task, shared_owner_identity),
            master_agent.execute_task(operator_task, shared_operator_identity),
        )

        assert response_owner["success"] is True
        assert response_operator["success"] is True

        owner_memory = saas_store.list_memory(
            user_id=ALPHA_USER_ID,
            workspace_id=SHARED_WORKSPACE_ID,
        )
        operator_memory = saas_store.list_memory(
            user_id=BETA_USER_ID,
            workspace_id=SHARED_WORKSPACE_ID,
        )

        assert len(owner_memory) == 1
        assert len(operator_memory) == 1
        assert "operator private action" not in str(owner_memory)
        assert "owner private action" not in str(operator_memory)

    @pytest.mark.asyncio()
    async def test_cross_tenant_read_attempt_returns_empty_not_foreign_records(
        self,
        master_agent: MasterAgentDouble,
        saas_store: InMemorySaasStore,
        alpha_identity: TenantIdentity,
    ) -> None:
        task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
            payload={"private": "alpha private data"},
        )

        await master_agent.execute_task(task, alpha_identity)

        wrong_workspace_memory = saas_store.list_memory(
            user_id=ALPHA_USER_ID,
            workspace_id=BETA_WORKSPACE_ID,
        )
        wrong_user_memory = saas_store.list_memory(
            user_id=BETA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
        )

        assert wrong_workspace_memory == []
        assert wrong_user_memory == []

    @pytest.mark.asyncio()
    async def test_safe_errors_do_not_leak_secrets(
        self,
        master_agent: MasterAgentDouble,
        alpha_identity: TenantIdentity,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("DATABASE_URL", "postgresql://user:password@example.test:5432/app")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real-secret")

        invalid_task = make_task(
            user_id=BETA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
            payload={
                "database_url": os.environ["DATABASE_URL"],
                "api_key": os.environ["OPENAI_API_KEY"],
            },
        )

        response = await master_agent.execute_task(invalid_task, alpha_identity)
        response_text = str(response)

        assert response["success"] is False
        assert "postgresql://user:password@example.test:5432/app" not in response_text
        assert "sk-test-not-real-secret" not in response_text
        assert "traceback" not in response_text.lower()

    @pytest.mark.asyncio()
    async def test_structured_response_contract_for_success_and_failure(
        self,
        master_agent: MasterAgentDouble,
        alpha_identity: TenantIdentity,
        alpha_viewer_identity: TenantIdentity,
    ) -> None:
        success_task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
        )
        failure_task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="create_task",
            agent_name="master_agent",
        )

        success_response = await master_agent.execute_task(success_task, alpha_identity)
        failure_response = await master_agent.execute_task(failure_task, alpha_viewer_identity)

        required_keys = {
            "success",
            "task_id",
            "user_id",
            "workspace_id",
            "status",
            "data",
            "error",
            "verification_payload",
            "audit_ids",
        }

        assert required_keys.issubset(success_response.keys())
        assert required_keys.issubset(failure_response.keys())

        assert success_response["success"] is True
        assert failure_response["success"] is False

        assert success_response["user_id"] == ALPHA_USER_ID
        assert success_response["workspace_id"] == ALPHA_WORKSPACE_ID
        assert failure_response["user_id"] == ALPHA_USER_ID
        assert failure_response["workspace_id"] == ALPHA_WORKSPACE_ID

    @pytest.mark.asyncio()
    async def test_concurrent_sensitive_tasks_keep_security_reviews_tenant_scoped(
        self,
        master_agent: MasterAgentDouble,
        saas_services: Dict[str, Any],
        alpha_identity: TenantIdentity,
        beta_identity: TenantIdentity,
    ) -> None:
        security_agent: SecurityAgentDouble = saas_services["security_agent"]

        alpha_task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="push_ip_block",
            agent_name="security_agent",
            payload={"ip": "203.0.113.10", "source": "alpha"},
            sensitive=True,
        )
        beta_task = make_task(
            user_id=BETA_USER_ID,
            workspace_id=BETA_WORKSPACE_ID,
            action="push_ip_block",
            agent_name="security_agent",
            payload={"ip": "203.0.113.20", "source": "beta"},
            sensitive=True,
        )

        alpha_response, beta_response = await asyncio.gather(
            master_agent.execute_task(alpha_task, alpha_identity),
            master_agent.execute_task(beta_task, beta_identity),
        )

        assert alpha_response["success"] is True
        assert beta_response["success"] is True
        assert len(security_agent.reviews) == 2

        alpha_reviews = [
            review
            for review in security_agent.reviews
            if review["user_id"] == ALPHA_USER_ID and review["workspace_id"] == ALPHA_WORKSPACE_ID
        ]
        beta_reviews = [
            review
            for review in security_agent.reviews
            if review["user_id"] == BETA_USER_ID and review["workspace_id"] == BETA_WORKSPACE_ID
        ]

        assert len(alpha_reviews) == 1
        assert len(beta_reviews) == 1
        assert "beta" not in str(alpha_reviews)
        assert "alpha" not in str(beta_reviews)

    @pytest.mark.asyncio()
    async def test_audit_log_exists_for_state_changing_action(
        self,
        master_agent: MasterAgentDouble,
        saas_store: InMemorySaasStore,
        alpha_identity: TenantIdentity,
    ) -> None:
        task = make_task(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            action="write_file",
            agent_name="master_agent",
            payload={"filename": "state-change.txt", "content": "state changed safely"},
        )

        response = await master_agent.execute_task(task, alpha_identity)

        assert response["success"] is True
        assert response["audit_ids"]

        audit_records = saas_store.list_audit(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
        )
        event_types = {record.event_type for record in audit_records}

        assert AuditEventType.TASK_RECEIVED.value in event_types
        assert AuditEventType.FILE_WRITTEN.value in event_types
        assert AuditEventType.MEMORY_WRITTEN.value in event_types
        assert AuditEventType.TASK_COMPLETED.value in event_types

    def test_store_never_returns_records_without_both_user_and_workspace_filters(
        self,
        saas_store: InMemorySaasStore,
    ) -> None:
        alpha_memory = MemoryRecord(
            memory_id=f"memory_{uuid4().hex}",
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
            task_id=f"task_{uuid4().hex}",
            agent_name="memory_agent",
            content={"value": "alpha"},
            created_at=utc_now_iso(),
        )
        beta_memory = MemoryRecord(
            memory_id=f"memory_{uuid4().hex}",
            user_id=BETA_USER_ID,
            workspace_id=BETA_WORKSPACE_ID,
            task_id=f"task_{uuid4().hex}",
            agent_name="memory_agent",
            content={"value": "beta"},
            created_at=utc_now_iso(),
        )

        saas_store.save_memory(alpha_memory)
        saas_store.save_memory(beta_memory)

        alpha_results = saas_store.list_memory(
            user_id=ALPHA_USER_ID,
            workspace_id=ALPHA_WORKSPACE_ID,
        )
        beta_results = saas_store.list_memory(
            user_id=BETA_USER_ID,
            workspace_id=BETA_WORKSPACE_ID,
        )

        assert alpha_results == [alpha_memory]
        assert beta_results == [beta_memory]
        assert alpha_results != beta_results