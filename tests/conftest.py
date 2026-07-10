"""
tests/conftest.py

Test fixtures for William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
- Provide safe, deterministic pytest fixtures for app, database, users, workspaces,
  roles, plans, subscriptions, security checks, audit logging, memory hooks,
  verification hooks, and agent bridge stubs.
- Enforce user_id and workspace_id isolation in tests.
- Import safely even when future application modules are not created yet.

Design goals:
- No hardcoded real secrets.
- No network calls.
- No production database usage.
- Works as a standalone test foundation.
- Allows future FastAPI / SQLAlchemy app integration without breaking current tests.
"""

from __future__ import annotations

import asyncio
import os
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, MutableMapping, Optional

import pytest


# ---------------------------------------------------------------------------
# Test Environment Safety
# ---------------------------------------------------------------------------

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("WILLIAM_ENV", "test")
os.environ.setdefault("TESTING", "1")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("JWT_SECRET", "test-only-jwt-secret-not-for-production")
os.environ.setdefault("ENCRYPTION_KEY", "test-only-encryption-key-not-for-production")
os.environ.setdefault("MASTER_AGENT_ENABLED", "false")
os.environ.setdefault("EXTERNAL_ACTIONS_ENABLED", "false")
os.environ.setdefault("BILLING_PROVIDER_ENABLED", "false")


# ---------------------------------------------------------------------------
# Optional Imports
# ---------------------------------------------------------------------------

try:
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
except Exception:  # pragma: no cover
    FastAPI = None  # type: ignore[assignment]
    TestClient = None  # type: ignore[assignment]

try:
    from httpx import AsyncClient
except Exception:  # pragma: no cover
    AsyncClient = None  # type: ignore[assignment]

try:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
except Exception:  # pragma: no cover
    AsyncSession = None  # type: ignore[assignment]
    async_sessionmaker = None  # type: ignore[assignment]
    create_async_engine = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Structured Response Helpers
# ---------------------------------------------------------------------------

def utc_now() -> datetime:
    """Return timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    """Create deterministic-looking but unique test IDs."""
    return f"{prefix}_{uuid.uuid4().hex}"


def success_response(data: Any = None) -> Dict[str, Any]:
    """Consistent success response shape used across tests."""
    return {
        "success": True,
        "data": data if data is not None else {},
        "error": None,
    }


def error_response(
    code: str,
    message: str,
    status_code: int = 400,
    details: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Consistent safe error response shape used across tests."""
    return {
        "success": False,
        "data": None,
        "error": {
            "code": code,
            "message": message,
            "status_code": status_code,
            "details": dict(details or {}),
        },
    }


# ---------------------------------------------------------------------------
# Domain Test Models
# ---------------------------------------------------------------------------

class Role(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


class Plan(str, Enum):
    FREE = "free"
    STARTER = "starter"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class AgentName(str, Enum):
    MASTER = "master_agent"
    SECURITY = "security_agent"
    MEMORY = "memory_agent"
    VERIFICATION = "verification_agent"
    VOICE = "voice_agent"
    SYSTEM = "system_agent"
    BROWSER = "browser_agent"
    CODE = "code_agent"
    VISUAL = "visual_agent"
    WORKFLOW = "workflow_agent"
    CALL = "call_agent"
    BUSINESS = "business_agent"
    FINANCE = "finance_agent"
    CREATOR = "creator_agent"


@dataclass(frozen=True)
class TestUser:
    user_id: str
    email: str
    role: Role
    is_active: bool = True
    created_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class TestWorkspace:
    workspace_id: str
    owner_user_id: str
    name: str
    created_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class TestSubscription:
    subscription_id: str
    workspace_id: str
    plan: Plan
    status: str = "active"
    max_agents: int = 14
    max_tasks_per_month: int = 1000
    sensitive_actions_enabled: bool = True
    created_at: datetime = field(default_factory=utc_now)


@dataclass(frozen=True)
class TestAuthContext:
    user_id: str
    workspace_id: str
    role: Role
    plan: Plan
    permissions: frozenset[str]
    request_id: str = field(default_factory=lambda: new_id("req"))


@dataclass
class AuditEvent:
    event_id: str
    event_type: str
    user_id: str
    workspace_id: str
    action: str
    risk_level: str
    metadata: Dict[str, Any]
    created_at: datetime = field(default_factory=utc_now)


@dataclass
class VerificationPayload:
    verification_id: str
    user_id: str
    workspace_id: str
    action: str
    status: str
    evidence: Dict[str, Any]
    created_at: datetime = field(default_factory=utc_now)


@dataclass
class MemoryRecord:
    memory_id: str
    user_id: str
    workspace_id: str
    key: str
    value: Dict[str, Any]
    created_at: datetime = field(default_factory=utc_now)


# ---------------------------------------------------------------------------
# In-Memory Test Store
# ---------------------------------------------------------------------------

class TestStore:
    """
    Safe in-memory store for tests.

    This intentionally does not mimic production persistence perfectly.
    Its job is to make isolation failures obvious and fast.
    """

    def __init__(self) -> None:
        self.users: Dict[str, TestUser] = {}
        self.workspaces: Dict[str, TestWorkspace] = {}
        self.subscriptions: Dict[str, TestSubscription] = {}
        self.memberships: Dict[str, Dict[str, Role]] = {}
        self.audit_events: List[AuditEvent] = []
        self.verifications: List[VerificationPayload] = []
        self.memories: List[MemoryRecord] = []
        self.agent_access: Dict[str, set[str]] = {}

    def add_user(self, user: TestUser) -> TestUser:
        self.users[user.user_id] = user
        return user

    def add_workspace(self, workspace: TestWorkspace) -> TestWorkspace:
        self.workspaces[workspace.workspace_id] = workspace
        self.memberships.setdefault(workspace.workspace_id, {})
        self.memberships[workspace.workspace_id][workspace.owner_user_id] = Role.OWNER
        return workspace

    def add_member(self, workspace_id: str, user_id: str, role: Role) -> None:
        self.require_workspace(workspace_id)
        self.require_user(user_id)
        self.memberships.setdefault(workspace_id, {})
        self.memberships[workspace_id][user_id] = role

    def add_subscription(self, subscription: TestSubscription) -> TestSubscription:
        self.require_workspace(subscription.workspace_id)
        self.subscriptions[subscription.workspace_id] = subscription
        return subscription

    def grant_agent_access(self, workspace_id: str, agent_name: AgentName | str) -> None:
        self.require_workspace(workspace_id)
        self.agent_access.setdefault(workspace_id, set()).add(str(agent_name))

    def has_agent_access(self, workspace_id: str, agent_name: AgentName | str) -> bool:
        return str(agent_name) in self.agent_access.get(workspace_id, set())

    def require_user(self, user_id: str) -> TestUser:
        user = self.users.get(user_id)
        if user is None:
            raise PermissionError(f"Unknown test user_id: {user_id}")
        if not user.is_active:
            raise PermissionError(f"Inactive test user_id: {user_id}")
        return user

    def require_workspace(self, workspace_id: str) -> TestWorkspace:
        workspace = self.workspaces.get(workspace_id)
        if workspace is None:
            raise PermissionError(f"Unknown test workspace_id: {workspace_id}")
        return workspace

    def require_membership(self, user_id: str, workspace_id: str) -> Role:
        self.require_user(user_id)
        self.require_workspace(workspace_id)

        workspace_members = self.memberships.get(workspace_id, {})
        role = workspace_members.get(user_id)

        if role is None:
            raise PermissionError(
                f"Isolation violation: user_id={user_id} does not belong to workspace_id={workspace_id}"
            )

        return role

    def require_subscription(self, workspace_id: str) -> TestSubscription:
        subscription = self.subscriptions.get(workspace_id)
        if subscription is None:
            raise PermissionError(f"Missing subscription for workspace_id={workspace_id}")
        if subscription.status != "active":
            raise PermissionError(f"Inactive subscription for workspace_id={workspace_id}")
        return subscription

    def assert_isolated(self, user_id: str, workspace_id: str) -> None:
        self.require_membership(user_id=user_id, workspace_id=workspace_id)

    def add_audit_event(
        self,
        *,
        event_type: str,
        user_id: str,
        workspace_id: str,
        action: str,
        risk_level: str,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> AuditEvent:
        self.assert_isolated(user_id=user_id, workspace_id=workspace_id)
        event = AuditEvent(
            event_id=new_id("audit"),
            event_type=event_type,
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            risk_level=risk_level,
            metadata=dict(metadata or {}),
        )
        self.audit_events.append(event)
        return event

    def add_verification(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action: str,
        status: str,
        evidence: Optional[Mapping[str, Any]] = None,
    ) -> VerificationPayload:
        self.assert_isolated(user_id=user_id, workspace_id=workspace_id)
        payload = VerificationPayload(
            verification_id=new_id("verify"),
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            status=status,
            evidence=dict(evidence or {}),
        )
        self.verifications.append(payload)
        return payload

    def add_memory(
        self,
        *,
        user_id: str,
        workspace_id: str,
        key: str,
        value: Optional[Mapping[str, Any]] = None,
    ) -> MemoryRecord:
        self.assert_isolated(user_id=user_id, workspace_id=workspace_id)
        record = MemoryRecord(
            memory_id=new_id("memory"),
            user_id=user_id,
            workspace_id=workspace_id,
            key=key,
            value=dict(value or {}),
        )
        self.memories.append(record)
        return record

    def memories_for(self, *, user_id: str, workspace_id: str) -> List[MemoryRecord]:
        self.assert_isolated(user_id=user_id, workspace_id=workspace_id)
        return [
            record
            for record in self.memories
            if record.user_id == user_id and record.workspace_id == workspace_id
        ]


# ---------------------------------------------------------------------------
# Role / Plan / Permission Rules
# ---------------------------------------------------------------------------

ROLE_PERMISSIONS: Dict[Role, frozenset[str]] = {
    Role.OWNER: frozenset(
        {
            "workspace:read",
            "workspace:write",
            "users:read",
            "users:invite",
            "billing:read",
            "billing:write",
            "agents:read",
            "agents:run",
            "agents:configure",
            "memory:read",
            "memory:write",
            "security:approve",
            "audit:read",
            "tasks:read",
            "tasks:write",
            "tasks:cancel",
        }
    ),
    Role.ADMIN: frozenset(
        {
            "workspace:read",
            "workspace:write",
            "users:read",
            "agents:read",
            "agents:run",
            "agents:configure",
            "memory:read",
            "memory:write",
            "audit:read",
            "tasks:read",
            "tasks:write",
            "tasks:cancel",
        }
    ),
    Role.MEMBER: frozenset(
        {
            "workspace:read",
            "agents:read",
            "agents:run",
            "memory:read",
            "memory:write",
            "tasks:read",
            "tasks:write",
        }
    ),
    Role.VIEWER: frozenset(
        {
            "workspace:read",
            "agents:read",
            "memory:read",
            "tasks:read",
        }
    ),
}

PLAN_LIMITS: Dict[Plan, Dict[str, Any]] = {
    Plan.FREE: {
        "max_agents": 2,
        "max_tasks_per_month": 50,
        "sensitive_actions_enabled": False,
    },
    Plan.STARTER: {
        "max_agents": 5,
        "max_tasks_per_month": 250,
        "sensitive_actions_enabled": False,
    },
    Plan.PRO: {
        "max_agents": 14,
        "max_tasks_per_month": 2500,
        "sensitive_actions_enabled": True,
    },
    Plan.ENTERPRISE: {
        "max_agents": 14,
        "max_tasks_per_month": 100000,
        "sensitive_actions_enabled": True,
    },
}


def permissions_for_role(role: Role) -> frozenset[str]:
    return ROLE_PERMISSIONS.get(role, frozenset())


def assert_permission(context: TestAuthContext, permission: str) -> None:
    if permission not in context.permissions:
        raise PermissionError(
            f"Permission denied: user_id={context.user_id} role={context.role.value} lacks {permission}"
        )


def assert_plan_allows(subscription: TestSubscription, capability: str) -> None:
    if capability == "sensitive_actions" and not subscription.sensitive_actions_enabled:
        raise PermissionError(
            f"Plan denied: workspace_id={subscription.workspace_id} plan={subscription.plan.value} "
            "does not allow sensitive actions"
        )


# ---------------------------------------------------------------------------
# Agent Test Bridges
# ---------------------------------------------------------------------------

class FakeSecurityAgent:
    """Security Agent stub for safe approval checks in tests."""

    sensitive_actions = {
        "system.open_app",
        "system.close_app",
        "browser.submit_form",
        "billing.change_plan",
        "users.invite",
        "memory.export",
        "files.delete",
        "tasks.run_device_action",
    }

    def __init__(self, store: TestStore) -> None:
        self.store = store

    async def evaluate(
        self,
        *,
        context: TestAuthContext,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        self.store.assert_isolated(context.user_id, context.workspace_id)

        is_sensitive = action in self.sensitive_actions
        risk_level = "high" if is_sensitive else "low"

        self.store.add_audit_event(
            event_type="security_evaluation",
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            action=action,
            risk_level=risk_level,
            metadata={
                "payload_keys": sorted(list((payload or {}).keys())),
                "is_sensitive": is_sensitive,
            },
        )

        if is_sensitive and "security:approve" not in context.permissions:
            return error_response(
                code="SECURITY_APPROVAL_REQUIRED",
                message="This action requires Security Agent approval.",
                status_code=403,
                details={
                    "action": action,
                    "risk_level": risk_level,
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                },
            )

        return success_response(
            {
                "approved": True,
                "action": action,
                "risk_level": risk_level,
                "approved_by": AgentName.SECURITY.value,
            }
        )


class FakeMemoryAgent:
    """Memory Agent stub with strict user/workspace isolation."""

    def __init__(self, store: TestStore) -> None:
        self.store = store

    async def remember(
        self,
        *,
        context: TestAuthContext,
        key: str,
        value: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        assert_permission(context, "memory:write")
        record = self.store.add_memory(
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            key=key,
            value=value or {},
        )
        return success_response(
            {
                "memory_id": record.memory_id,
                "key": record.key,
                "user_id": record.user_id,
                "workspace_id": record.workspace_id,
            }
        )

    async def recall(self, *, context: TestAuthContext) -> Dict[str, Any]:
        assert_permission(context, "memory:read")
        records = self.store.memories_for(
            user_id=context.user_id,
            workspace_id=context.workspace_id,
        )
        return success_response(
            [
                {
                    "memory_id": record.memory_id,
                    "key": record.key,
                    "value": record.value,
                    "user_id": record.user_id,
                    "workspace_id": record.workspace_id,
                }
                for record in records
            ]
        )


class FakeVerificationAgent:
    """Verification Agent stub that records completion payloads."""

    def __init__(self, store: TestStore) -> None:
        self.store = store

    async def prepare_payload(
        self,
        *,
        context: TestAuthContext,
        action: str,
        status: str,
        evidence: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        verification = self.store.add_verification(
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            action=action,
            status=status,
            evidence=evidence or {},
        )
        return success_response(
            {
                "verification_id": verification.verification_id,
                "action": verification.action,
                "status": verification.status,
                "user_id": verification.user_id,
                "workspace_id": verification.workspace_id,
            }
        )


class FakeMasterAgent:
    """
    Master Agent stub.

    Every task must include user_id and workspace_id and must pass:
    - workspace isolation
    - role permission checks
    - subscription checks
    - Security Agent evaluation
    - audit logging
    - Verification Agent payload creation
    """

    def __init__(
        self,
        *,
        store: TestStore,
        security_agent: FakeSecurityAgent,
        memory_agent: FakeMemoryAgent,
        verification_agent: FakeVerificationAgent,
    ) -> None:
        self.store = store
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent

    async def run_task(
        self,
        *,
        context: TestAuthContext,
        agent_name: AgentName | str,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        self.store.assert_isolated(context.user_id, context.workspace_id)
        assert_permission(context, "tasks:write")
        assert_permission(context, "agents:run")

        subscription = self.store.require_subscription(context.workspace_id)
        assert_plan_allows(
            subscription,
            "sensitive_actions" if action in FakeSecurityAgent.sensitive_actions else "normal_actions",
        )

        if not self.store.has_agent_access(context.workspace_id, agent_name):
            return error_response(
                code="AGENT_ACCESS_DENIED",
                message="Workspace does not have access to the requested agent.",
                status_code=403,
                details={
                    "agent_name": str(agent_name),
                    "workspace_id": context.workspace_id,
                },
            )

        security_result = await self.security_agent.evaluate(
            context=context,
            action=action,
            payload=payload,
        )

        if not security_result["success"]:
            return security_result

        task_id = new_id("task")

        self.store.add_audit_event(
            event_type="task_execution",
            user_id=context.user_id,
            workspace_id=context.workspace_id,
            action=action,
            risk_level=security_result["data"]["risk_level"],
            metadata={
                "task_id": task_id,
                "agent_name": str(agent_name),
                "payload": dict(payload or {}),
            },
        )

        verification_result = await self.verification_agent.prepare_payload(
            context=context,
            action=action,
            status="completed",
            evidence={
                "task_id": task_id,
                "agent_name": str(agent_name),
                "security": security_result["data"],
            },
        )

        return success_response(
            {
                "task_id": task_id,
                "agent_name": str(agent_name),
                "action": action,
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "security": security_result["data"],
                "verification": verification_result["data"],
            }
        )


# ---------------------------------------------------------------------------
# Async Test Helpers
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def event_loop() -> Iterable[asyncio.AbstractEventLoop]:
    """
    Session-scoped event loop for async tests.

    This supports older pytest-asyncio setups while remaining harmless for newer ones.
    """
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def run_async() -> Callable[[Awaitable[Any]], Any]:
    """Run an async coroutine from sync tests."""

    def _runner(awaitable: Awaitable[Any]) -> Any:
        return asyncio.get_event_loop().run_until_complete(awaitable)

    return _runner


# ---------------------------------------------------------------------------
# Core Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def test_store() -> TestStore:
    """Fresh isolated in-memory test store for each test."""
    return TestStore()


@pytest.fixture
def owner_user(test_store: TestStore) -> TestUser:
    user = TestUser(
        user_id=new_id("user"),
        email="owner@example.test",
        role=Role.OWNER,
    )
    return test_store.add_user(user)


@pytest.fixture
def admin_user(test_store: TestStore) -> TestUser:
    user = TestUser(
        user_id=new_id("user"),
        email="admin@example.test",
        role=Role.ADMIN,
    )
    return test_store.add_user(user)


@pytest.fixture
def member_user(test_store: TestStore) -> TestUser:
    user = TestUser(
        user_id=new_id("user"),
        email="member@example.test",
        role=Role.MEMBER,
    )
    return test_store.add_user(user)


@pytest.fixture
def viewer_user(test_store: TestStore) -> TestUser:
    user = TestUser(
        user_id=new_id("user"),
        email="viewer@example.test",
        role=Role.VIEWER,
    )
    return test_store.add_user(user)


@pytest.fixture
def outsider_user(test_store: TestStore) -> TestUser:
    user = TestUser(
        user_id=new_id("user"),
        email="outsider@example.test",
        role=Role.MEMBER,
    )
    return test_store.add_user(user)


@pytest.fixture
def workspace(test_store: TestStore, owner_user: TestUser) -> TestWorkspace:
    item = TestWorkspace(
        workspace_id=new_id("workspace"),
        owner_user_id=owner_user.user_id,
        name="Primary Test Workspace",
    )
    return test_store.add_workspace(item)


@pytest.fixture
def second_workspace(test_store: TestStore, outsider_user: TestUser) -> TestWorkspace:
    item = TestWorkspace(
        workspace_id=new_id("workspace"),
        owner_user_id=outsider_user.user_id,
        name="Second Isolated Workspace",
    )
    return test_store.add_workspace(item)


@pytest.fixture
def workspace_members(
    test_store: TestStore,
    workspace: TestWorkspace,
    admin_user: TestUser,
    member_user: TestUser,
    viewer_user: TestUser,
) -> Dict[str, TestUser]:
    test_store.add_member(workspace.workspace_id, admin_user.user_id, Role.ADMIN)
    test_store.add_member(workspace.workspace_id, member_user.user_id, Role.MEMBER)
    test_store.add_member(workspace.workspace_id, viewer_user.user_id, Role.VIEWER)

    return {
        "admin": admin_user,
        "member": member_user,
        "viewer": viewer_user,
    }


@pytest.fixture
def subscription(test_store: TestStore, workspace: TestWorkspace) -> TestSubscription:
    limits = PLAN_LIMITS[Plan.PRO]
    item = TestSubscription(
        subscription_id=new_id("sub"),
        workspace_id=workspace.workspace_id,
        plan=Plan.PRO,
        max_agents=limits["max_agents"],
        max_tasks_per_month=limits["max_tasks_per_month"],
        sensitive_actions_enabled=limits["sensitive_actions_enabled"],
    )
    return test_store.add_subscription(item)


@pytest.fixture
def free_subscription(test_store: TestStore, second_workspace: TestWorkspace) -> TestSubscription:
    limits = PLAN_LIMITS[Plan.FREE]
    item = TestSubscription(
        subscription_id=new_id("sub"),
        workspace_id=second_workspace.workspace_id,
        plan=Plan.FREE,
        max_agents=limits["max_agents"],
        max_tasks_per_month=limits["max_tasks_per_month"],
        sensitive_actions_enabled=limits["sensitive_actions_enabled"],
    )
    return test_store.add_subscription(item)


@pytest.fixture
def agent_registry(test_store: TestStore, workspace: TestWorkspace) -> Dict[str, str]:
    for agent in AgentName:
        test_store.grant_agent_access(workspace.workspace_id, agent)

    return {
        agent.value: agent.value
        for agent in AgentName
    }


@pytest.fixture
def limited_agent_registry(test_store: TestStore, second_workspace: TestWorkspace) -> Dict[str, str]:
    allowed = [AgentName.MASTER, AgentName.SECURITY, AgentName.MEMORY]
    for agent in allowed:
        test_store.grant_agent_access(second_workspace.workspace_id, agent)

    return {
        agent.value: agent.value
        for agent in allowed
    }


# ---------------------------------------------------------------------------
# Auth Context Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def owner_context(
    owner_user: TestUser,
    workspace: TestWorkspace,
    subscription: TestSubscription,
) -> TestAuthContext:
    return TestAuthContext(
        user_id=owner_user.user_id,
        workspace_id=workspace.workspace_id,
        role=Role.OWNER,
        plan=subscription.plan,
        permissions=permissions_for_role(Role.OWNER),
    )


@pytest.fixture
def admin_context(
    admin_user: TestUser,
    workspace: TestWorkspace,
    workspace_members: Dict[str, TestUser],
    subscription: TestSubscription,
) -> TestAuthContext:
    return TestAuthContext(
        user_id=admin_user.user_id,
        workspace_id=workspace.workspace_id,
        role=Role.ADMIN,
        plan=subscription.plan,
        permissions=permissions_for_role(Role.ADMIN),
    )


@pytest.fixture
def member_context(
    member_user: TestUser,
    workspace: TestWorkspace,
    workspace_members: Dict[str, TestUser],
    subscription: TestSubscription,
) -> TestAuthContext:
    return TestAuthContext(
        user_id=member_user.user_id,
        workspace_id=workspace.workspace_id,
        role=Role.MEMBER,
        plan=subscription.plan,
        permissions=permissions_for_role(Role.MEMBER),
    )


@pytest.fixture
def viewer_context(
    viewer_user: TestUser,
    workspace: TestWorkspace,
    workspace_members: Dict[str, TestUser],
    subscription: TestSubscription,
) -> TestAuthContext:
    return TestAuthContext(
        user_id=viewer_user.user_id,
        workspace_id=workspace.workspace_id,
        role=Role.VIEWER,
        plan=subscription.plan,
        permissions=permissions_for_role(Role.VIEWER),
    )


@pytest.fixture
def outsider_context(
    outsider_user: TestUser,
    workspace: TestWorkspace,
) -> TestAuthContext:
    """
    Context intentionally points outsider_user at the wrong workspace.

    Use this fixture to assert workspace isolation failures.
    """
    return TestAuthContext(
        user_id=outsider_user.user_id,
        workspace_id=workspace.workspace_id,
        role=Role.MEMBER,
        plan=Plan.FREE,
        permissions=permissions_for_role(Role.MEMBER),
    )


@pytest.fixture
def second_workspace_context(
    outsider_user: TestUser,
    second_workspace: TestWorkspace,
    free_subscription: TestSubscription,
) -> TestAuthContext:
    return TestAuthContext(
        user_id=outsider_user.user_id,
        workspace_id=second_workspace.workspace_id,
        role=Role.OWNER,
        plan=free_subscription.plan,
        permissions=permissions_for_role(Role.OWNER),
    )


# ---------------------------------------------------------------------------
# Agent Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def security_agent(test_store: TestStore) -> FakeSecurityAgent:
    return FakeSecurityAgent(test_store)


@pytest.fixture
def memory_agent(test_store: TestStore) -> FakeMemoryAgent:
    return FakeMemoryAgent(test_store)


@pytest.fixture
def verification_agent(test_store: TestStore) -> FakeVerificationAgent:
    return FakeVerificationAgent(test_store)


@pytest.fixture
def master_agent(
    test_store: TestStore,
    security_agent: FakeSecurityAgent,
    memory_agent: FakeMemoryAgent,
    verification_agent: FakeVerificationAgent,
    subscription: TestSubscription,
    agent_registry: Dict[str, str],
) -> FakeMasterAgent:
    return FakeMasterAgent(
        store=test_store,
        security_agent=security_agent,
        memory_agent=memory_agent,
        verification_agent=verification_agent,
    )


# ---------------------------------------------------------------------------
# Request / Payload Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def request_headers(owner_context: TestAuthContext) -> Dict[str, str]:
    return {
        "X-Request-ID": owner_context.request_id,
        "X-User-ID": owner_context.user_id,
        "X-Workspace-ID": owner_context.workspace_id,
        "Authorization": "Bearer test-only-token",
    }


@pytest.fixture
def task_payload(owner_context: TestAuthContext) -> Dict[str, Any]:
    return {
        "task_id": new_id("task"),
        "user_id": owner_context.user_id,
        "workspace_id": owner_context.workspace_id,
        "agent_name": AgentName.CODE.value,
        "action": "code.generate_file",
        "input": {
            "file_path": "example.py",
            "requirements": ["safe imports", "structured response"],
        },
        "metadata": {
            "source": "pytest",
            "requires_verification": True,
        },
    }


@pytest.fixture
def sensitive_task_payload(owner_context: TestAuthContext) -> Dict[str, Any]:
    return {
        "task_id": new_id("task"),
        "user_id": owner_context.user_id,
        "workspace_id": owner_context.workspace_id,
        "agent_name": AgentName.SYSTEM.value,
        "action": "system.open_app",
        "input": {
            "app_name": "notepad",
            "dry_run": True,
        },
        "metadata": {
            "source": "pytest",
            "requires_security_approval": True,
            "requires_verification": True,
        },
    }


@pytest.fixture
def invalid_cross_workspace_payload(
    member_user: TestUser,
    second_workspace: TestWorkspace,
) -> Dict[str, Any]:
    """
    Payload intentionally mixes user_id from one workspace with another workspace_id.

    Use this to assert isolation protections.
    """
    return {
        "task_id": new_id("task"),
        "user_id": member_user.user_id,
        "workspace_id": second_workspace.workspace_id,
        "agent_name": AgentName.MEMORY.value,
        "action": "memory.write",
        "input": {"key": "bad-cross-workspace-test"},
    }


# ---------------------------------------------------------------------------
# Assertion Helper Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def assert_success() -> Callable[[Mapping[str, Any]], None]:
    def _assert(response: Mapping[str, Any]) -> None:
        assert response.get("success") is True
        assert response.get("error") is None
        assert "data" in response

    return _assert


@pytest.fixture
def assert_error() -> Callable[[Mapping[str, Any], str], None]:
    def _assert(response: Mapping[str, Any], code: str) -> None:
        assert response.get("success") is False
        assert response.get("data") is None
        assert response.get("error", {}).get("code") == code

    return _assert


@pytest.fixture
def assert_workspace_isolation(test_store: TestStore) -> Callable[[str, str], None]:
    def _assert(user_id: str, workspace_id: str) -> None:
        test_store.assert_isolated(user_id=user_id, workspace_id=workspace_id)

    return _assert


@pytest.fixture
def assert_audit_logged(test_store: TestStore) -> Callable[[str, str, str], None]:
    def _assert(user_id: str, workspace_id: str, action: str) -> None:
        matches = [
            event
            for event in test_store.audit_events
            if event.user_id == user_id
            and event.workspace_id == workspace_id
            and event.action == action
        ]
        assert matches, f"Expected audit log for action={action}"

    return _assert


@pytest.fixture
def assert_verification_created(test_store: TestStore) -> Callable[[str, str, str], None]:
    def _assert(user_id: str, workspace_id: str, action: str) -> None:
        matches = [
            verification
            for verification in test_store.verifications
            if verification.user_id == user_id
            and verification.workspace_id == workspace_id
            and verification.action == action
        ]
        assert matches, f"Expected verification payload for action={action}"

    return _assert


# ---------------------------------------------------------------------------
# Database Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def async_engine() -> Any:
    """
    Optional async SQLAlchemy engine.

    If SQLAlchemy is not installed, tests that request this fixture are skipped.
    """
    if create_async_engine is None:
        pytest.skip("SQLAlchemy async dependencies are not installed.")

    database_url = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

    if "production" in database_url.lower() or "prod" in database_url.lower():
        raise RuntimeError("Refusing to run tests against a production-looking database URL.")

    engine = create_async_engine(database_url, echo=False, future=True)

    try:
        yield engine
    finally:
        await engine.dispose()


@pytest.fixture
async def db_session(async_engine: Any) -> Any:
    """
    Optional async database session.

    This is intentionally metadata-free so the fixture remains safe before
    application models/migrations exist.
    """
    if async_sessionmaker is None or AsyncSession is None:
        pytest.skip("SQLAlchemy async session dependencies are not installed.")

    session_factory = async_sessionmaker(
        bind=async_engine,
        expire_on_commit=False,
        class_=AsyncSession,
    )

    async with session_factory() as session:
        yield session
        await session.rollback()


# ---------------------------------------------------------------------------
# FastAPI App / Client Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def app(
    test_store: TestStore,
    security_agent: FakeSecurityAgent,
    memory_agent: FakeMemoryAgent,
    verification_agent: FakeVerificationAgent,
) -> Any:
    """
    Optional FastAPI test app.

    The fixture first tries to import the real application factory.
    If the real app does not exist yet, it creates a minimal safe app
    so API tests can still run against structured responses.
    """
    if FastAPI is None:
        pytest.skip("FastAPI is not installed.")

    application = None

    try:
        from apps.api.main import create_app  # type: ignore

        application = create_app(testing=True)
    except Exception:
        application = FastAPI(title="William/Jarvis Test App")

        @application.get("/health")
        async def health() -> Dict[str, Any]:
            return success_response(
                {
                    "status": "ok",
                    "environment": "test",
                    "service": "william-jarvis",
                }
            )

        @application.post("/test/security/evaluate")
        async def evaluate_security(payload: Dict[str, Any]) -> Dict[str, Any]:
            context = TestAuthContext(
                user_id=payload["user_id"],
                workspace_id=payload["workspace_id"],
                role=Role(payload.get("role", Role.MEMBER.value)),
                plan=Plan(payload.get("plan", Plan.PRO.value)),
                permissions=permissions_for_role(Role(payload.get("role", Role.MEMBER.value))),
            )
            return await security_agent.evaluate(
                context=context,
                action=payload["action"],
                payload=payload.get("payload", {}),
            )

    application.state.test_store = test_store
    application.state.security_agent = security_agent
    application.state.memory_agent = memory_agent
    application.state.verification_agent = verification_agent

    return application


@pytest.fixture
def client(app: Any) -> Any:
    """Synchronous FastAPI test client."""
    if TestClient is None:
        pytest.skip("FastAPI TestClient is not installed.")
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
async def async_client(app: Any) -> Any:
    """
    Async HTTP client for FastAPI tests.

    Supports newer httpx versions through ASGITransport when available.
    """
    if AsyncClient is None:
        pytest.skip("httpx is not installed.")

    try:
        from httpx import ASGITransport

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as test_client:
            yield test_client
    except Exception:
        async with AsyncClient(app=app, base_url="http://testserver") as test_client:  # type: ignore[call-arg]
            yield test_client


# ---------------------------------------------------------------------------
# Isolation Assertion Tests Available To Import
# ---------------------------------------------------------------------------

def assert_payload_has_isolation(payload: Mapping[str, Any]) -> None:
    """Reusable assertion: every task-like payload must carry user_id and workspace_id."""
    assert payload.get("user_id"), "Payload missing user_id"
    assert payload.get("workspace_id"), "Payload missing workspace_id"


def assert_no_cross_workspace_records(
    records: Iterable[Mapping[str, Any]],
    *,
    expected_user_id: str,
    expected_workspace_id: str,
) -> None:
    """Reusable assertion: no returned record leaks data from another user/workspace."""
    for record in records:
        assert record.get("user_id") == expected_user_id
        assert record.get("workspace_id") == expected_workspace_id


def build_test_token(context: TestAuthContext) -> str:
    """
    Create a non-production opaque token for tests.

    This is not a JWT and must never be used as production auth logic.
    """
    random_part = secrets.token_urlsafe(16)
    return (
        f"test-token."
        f"user-{context.user_id}."
        f"workspace-{context.workspace_id}."
        f"role-{context.role.value}."
        f"{random_part}"
    )


@pytest.fixture
def auth_token(owner_context: TestAuthContext) -> str:
    return build_test_token(owner_context)


# ---------------------------------------------------------------------------
# Pytest Configuration Hooks
# ---------------------------------------------------------------------------

def pytest_configure(config: Any) -> None:
    config.addinivalue_line("markers", "unit: fast isolated unit tests")
    config.addinivalue_line("markers", "integration: integration tests using app/db fixtures")
    config.addinivalue_line("markers", "security: security and approval tests")
    config.addinivalue_line("markers", "isolation: user_id/workspace_id isolation tests")
    config.addinivalue_line("markers", "agents: multi-agent orchestration tests")
    config.addinivalue_line("markers", "billing: subscription and plan tests")
    config.addinivalue_line("markers", "memory: Memory Agent tests")
    config.addinivalue_line("markers", "verification: Verification Agent tests")


def pytest_collection_modifyitems(config: Any, items: List[Any]) -> None:
    """
    Add default 'unit' marker to unmarked tests.

    This keeps reporting clean without forcing every early test file to include markers.
    """
    known_markers = {
        "unit",
        "integration",
        "security",
        "isolation",
        "agents",
        "billing",
        "memory",
        "verification",
    }

    for item in items:
        marker_names = {marker.name for marker in item.iter_markers()}
        if not marker_names.intersection(known_markers):
            item.add_marker(pytest.mark.unit)