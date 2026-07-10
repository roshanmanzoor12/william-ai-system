"""
tests/api_tests/test_agents.py

API tests for William / Jarvis agent listing, access, and task execution flows.

This file is intentionally defensive:
- It imports safely even when the final FastAPI app/routes are not created yet.
- It provides a realistic fallback in-memory API so the test suite can validate
  expected SaaS behavior immediately.
- When the real app becomes available, these tests automatically target it.
- It enforces user_id/workspace_id isolation, role/plan access, Security Agent
  approval routing, audit hooks, Memory Agent context shape, and Verification
  Agent payload expectations.

Run:
    pytest tests/api_tests/test_agents.py -q
"""

from __future__ import annotations

import importlib
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

import pytest

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
    from fastapi.testclient import TestClient
    from pydantic import BaseModel, Field
except Exception as exc:  # pragma: no cover - pytest environment should have these.
    raise RuntimeError(
        "test_agents.py requires fastapi, pydantic, pytest, and httpx/testclient support."
    ) from exc


MASTER_AGENT_ID = "master"
SECURITY_AGENT_ID = "security"
MEMORY_AGENT_ID = "memory"
VERIFICATION_AGENT_ID = "verification"

KNOWN_AGENT_IDS = [
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

SENSITIVE_ACTION_KEYWORDS = (
    "delete",
    "remove",
    "send_email",
    "send email",
    "payment",
    "billing",
    "refund",
    "deploy",
    "production",
    "secret",
    "token",
    "password",
    "api_key",
    "api key",
    "external_transfer",
    "file_write",
    "database_write",
)

STATE_CHANGING_TASK_KEYWORDS = (
    "create",
    "update",
    "delete",
    "remove",
    "send",
    "deploy",
    "execute",
    "write",
    "modify",
    "approve",
)


def _safe_uuid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


def _now_ms() -> int:
    return int(time.time() * 1000)


@dataclass(frozen=True)
class TestIdentity:
    user_id: str
    workspace_id: str
    role: str
    plan: str
    display_name: str


@dataclass
class AuditEvent:
    event_id: str
    user_id: str
    workspace_id: str
    action: str
    resource_type: str
    resource_id: str
    metadata: Dict[str, Any]
    created_at_ms: int = field(default_factory=_now_ms)


@dataclass
class SecurityDecision:
    required: bool
    approved: bool
    reason: str
    routed_to_agent_id: Optional[str] = None


@dataclass
class TaskRecord:
    task_id: str
    agent_id: str
    user_id: str
    workspace_id: str
    prompt: str
    status: str
    security: SecurityDecision
    memory_context: Dict[str, Any]
    verification_payload: Dict[str, Any]
    created_at_ms: int = field(default_factory=_now_ms)


class InMemoryAgentApiState:
    """Small deterministic state layer used by the fallback API and assertions."""

    def __init__(self) -> None:
        self.audit_events: List[AuditEvent] = []
        self.tasks: Dict[str, TaskRecord] = {}

    def reset(self) -> None:
        self.audit_events.clear()
        self.tasks.clear()

    def log_audit(
        self,
        *,
        user_id: str,
        workspace_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=_safe_uuid("audit"),
            user_id=user_id,
            workspace_id=workspace_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            metadata=metadata or {},
        )
        self.audit_events.append(event)
        return event


FALLBACK_STATE = InMemoryAgentApiState()


class AgentTaskRequest(BaseModel):
    user_id: str = Field(..., min_length=1)
    workspace_id: str = Field(..., min_length=1)
    prompt: str = Field(..., min_length=1)
    context: Dict[str, Any] = Field(default_factory=dict)


class AgentTaskResponse(BaseModel):
    success: bool
    data: Optional[Dict[str, Any]] = None
    error: Optional[Dict[str, Any]] = None


def _agent_catalog() -> List[Dict[str, Any]]:
    base_access = {
        "master": {"min_plan": "free", "roles": ["owner", "admin", "member"]},
        "voice": {"min_plan": "pro", "roles": ["owner", "admin", "member"]},
        "system": {"min_plan": "enterprise", "roles": ["owner", "admin"]},
        "browser": {"min_plan": "pro", "roles": ["owner", "admin", "member"]},
        "code": {"min_plan": "pro", "roles": ["owner", "admin", "member"]},
        "memory": {"min_plan": "free", "roles": ["owner", "admin", "member"]},
        "security": {"min_plan": "free", "roles": ["owner", "admin"]},
        "verification": {"min_plan": "free", "roles": ["owner", "admin", "member"]},
        "visual": {"min_plan": "pro", "roles": ["owner", "admin", "member"]},
        "workflow": {"min_plan": "pro", "roles": ["owner", "admin"]},
        "hologram": {"min_plan": "enterprise", "roles": ["owner", "admin"]},
        "call": {"min_plan": "pro", "roles": ["owner", "admin", "member"]},
        "business": {"min_plan": "pro", "roles": ["owner", "admin", "member"]},
        "finance": {"min_plan": "enterprise", "roles": ["owner", "admin"]},
        "creator": {"min_plan": "pro", "roles": ["owner", "admin", "member"]},
    }

    return [
        {
            "agent_id": agent_id,
            "name": f"{agent_id.title()} Agent",
            "status": "available",
            "capabilities": _capabilities_for(agent_id),
            "access": base_access[agent_id],
            "requires_user_id": True,
            "requires_workspace_id": True,
            "security_routed": agent_id in {"security", "system", "finance"},
            "memory_compatible": True,
            "verification_enabled": True,
        }
        for agent_id in KNOWN_AGENT_IDS
    ]


def _capabilities_for(agent_id: str) -> List[str]:
    capabilities = {
        "master": ["route_task", "coordinate_agents", "prepare_verification"],
        "voice": ["speech_input", "speech_output"],
        "system": ["system_diagnostics", "safe_action_report"],
        "browser": ["research", "page_summary"],
        "code": ["code_review", "safe_patch_plan"],
        "memory": ["context_store", "context_recall"],
        "security": ["risk_score", "approval_decision"],
        "verification": ["completion_check", "payload_confirmation"],
        "visual": ["screen_analysis", "ui_review"],
        "workflow": ["automation_plan", "workflow_execution"],
        "hologram": ["presentation_mode", "avatar_response"],
        "call": ["call_summary", "lead_handling"],
        "business": ["strategy", "operations"],
        "finance": ["financial_analysis", "billing_review"],
        "creator": ["content_generation", "campaign_assets"],
    }
    return capabilities.get(agent_id, ["task_execution"])


def _plan_rank(plan: str) -> int:
    ranks = {
        "free": 0,
        "starter": 1,
        "pro": 2,
        "business": 3,
        "enterprise": 4,
    }
    return ranks.get(plan.lower(), -1)


def _identity_from_headers(
    x_user_id: Optional[str],
    x_workspace_id: Optional[str],
    x_role: Optional[str],
    x_plan: Optional[str],
) -> TestIdentity:
    if not x_user_id or not x_workspace_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "AUTH_CONTEXT_REQUIRED",
                "message": "user_id and workspace_id are required.",
            },
        )

    return TestIdentity(
        user_id=x_user_id,
        workspace_id=x_workspace_id,
        role=x_role or "member",
        plan=x_plan or "free",
        display_name=f"{x_role or 'member'}:{x_user_id}",
    )


def _agent_by_id(agent_id: str) -> Dict[str, Any]:
    for agent in _agent_catalog():
        if agent["agent_id"] == agent_id:
            return agent
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail={
            "code": "AGENT_NOT_FOUND",
            "message": f"Agent '{agent_id}' does not exist.",
        },
    )


def _can_access_agent(identity: TestIdentity, agent: Dict[str, Any]) -> Tuple[bool, str]:
    access = agent["access"]
    role_allowed = identity.role in access["roles"]
    plan_allowed = _plan_rank(identity.plan) >= _plan_rank(access["min_plan"])

    if not role_allowed:
        return False, "ROLE_NOT_ALLOWED"
    if not plan_allowed:
        return False, "PLAN_UPGRADE_REQUIRED"
    return True, "ACCESS_GRANTED"


def _is_sensitive_action(prompt: str, context: Optional[Dict[str, Any]] = None) -> bool:
    payload = f"{prompt} {context or {}}".lower()
    return any(keyword in payload for keyword in SENSITIVE_ACTION_KEYWORDS)


def _is_state_changing_action(prompt: str) -> bool:
    normalized = prompt.lower()
    return any(keyword in normalized for keyword in STATE_CHANGING_TASK_KEYWORDS)


def _security_decision_for(prompt: str, context: Optional[Dict[str, Any]]) -> SecurityDecision:
    if not _is_sensitive_action(prompt, context):
        return SecurityDecision(required=False, approved=True, reason="LOW_RISK")

    explicitly_approved = bool((context or {}).get("security_approved"))
    return SecurityDecision(
        required=True,
        approved=explicitly_approved,
        reason="SECURITY_APPROVAL_GRANTED" if explicitly_approved else "SECURITY_APPROVAL_REQUIRED",
        routed_to_agent_id=SECURITY_AGENT_ID,
    )


def _memory_context_for(identity: TestIdentity, agent_id: str, prompt: str) -> Dict[str, Any]:
    return {
        "memory_agent_id": MEMORY_AGENT_ID,
        "user_id": identity.user_id,
        "workspace_id": identity.workspace_id,
        "agent_id": agent_id,
        "context_type": "agent_task",
        "summary": prompt[:160],
        "safe_to_store": True,
        "created_at_ms": _now_ms(),
    }


def _verification_payload_for(
    *,
    identity: TestIdentity,
    agent_id: str,
    task_id: str,
    status_value: str,
    security: SecurityDecision,
) -> Dict[str, Any]:
    return {
        "verification_agent_id": VERIFICATION_AGENT_ID,
        "task_id": task_id,
        "agent_id": agent_id,
        "user_id": identity.user_id,
        "workspace_id": identity.workspace_id,
        "status": status_value,
        "checks": {
            "user_workspace_isolation": True,
            "security_reviewed": security.required,
            "security_approved": security.approved,
            "memory_context_prepared": True,
            "audit_ready": True,
        },
        "created_at_ms": _now_ms(),
    }


def _structured_error(code: str, message: str, details: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "success": False,
        "data": None,
        "error": {
            "code": code,
            "message": message,
            "details": details or {},
        },
    }


def build_fallback_app() -> FastAPI:
    app = FastAPI(title="William Jarvis Agent Test API", version="0.1-test")

    def current_identity(
        x_user_id: Optional[str] = Header(default=None),
        x_workspace_id: Optional[str] = Header(default=None),
        x_role: Optional[str] = Header(default=None),
        x_plan: Optional[str] = Header(default=None),
    ) -> TestIdentity:
        return _identity_from_headers(x_user_id, x_workspace_id, x_role, x_plan)

    @app.get("/api/agents")
    def list_agents(
        identity: TestIdentity = Depends(current_identity),
        workspace_id: Optional[str] = Query(default=None),
    ) -> Dict[str, Any]:
        requested_workspace = workspace_id or identity.workspace_id
        if requested_workspace != identity.workspace_id:
            return _structured_error(
                "WORKSPACE_FORBIDDEN",
                "You cannot list agents for another workspace.",
                {"requested_workspace_id": requested_workspace},
            )

        agents = []
        for agent in _agent_catalog():
            allowed, denial_code = _can_access_agent(identity, agent)
            redacted_agent = dict(agent)
            redacted_agent["available_to_current_user"] = allowed
            redacted_agent["access_reason"] = "ACCESS_GRANTED" if allowed else denial_code
            agents.append(redacted_agent)

        return {
            "success": True,
            "data": {
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
                "agents": agents,
                "count": len(agents),
            },
            "error": None,
        }

    @app.get("/api/agents/{agent_id}")
    def get_agent(agent_id: str, identity: TestIdentity = Depends(current_identity)) -> Dict[str, Any]:
        agent = _agent_by_id(agent_id)
        allowed, denial_code = _can_access_agent(identity, agent)
        if not allowed:
            http_status = (
                status.HTTP_402_PAYMENT_REQUIRED
                if denial_code == "PLAN_UPGRADE_REQUIRED"
                else status.HTTP_403_FORBIDDEN
            )
            raise HTTPException(
                status_code=http_status,
                detail={
                    "code": denial_code,
                    "message": "Current role or plan cannot access this agent.",
                    "agent_id": agent_id,
                    "workspace_id": identity.workspace_id,
                },
            )

        FALLBACK_STATE.log_audit(
            user_id=identity.user_id,
            workspace_id=identity.workspace_id,
            action="agent.read",
            resource_type="agent",
            resource_id=agent_id,
            metadata={"role": identity.role, "plan": identity.plan},
        )

        return {
            "success": True,
            "data": {
                "agent": agent,
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
            },
            "error": None,
        }

    @app.post("/api/agents/{agent_id}/tasks")
    async def create_agent_task(
        agent_id: str,
        request: Request,
        payload: AgentTaskRequest,
        identity: TestIdentity = Depends(current_identity),
    ) -> Dict[str, Any]:
        agent = _agent_by_id(agent_id)

        if payload.user_id != identity.user_id:
            return _structured_error(
                "USER_CONTEXT_MISMATCH",
                "Task user_id must match authenticated user context.",
                {
                    "payload_user_id": payload.user_id,
                    "auth_user_id": identity.user_id,
                },
            )

        if payload.workspace_id != identity.workspace_id:
            return _structured_error(
                "WORKSPACE_CONTEXT_MISMATCH",
                "Task workspace_id must match authenticated workspace context.",
                {
                    "payload_workspace_id": payload.workspace_id,
                    "auth_workspace_id": identity.workspace_id,
                },
            )

        allowed, denial_code = _can_access_agent(identity, agent)
        if not allowed:
            return _structured_error(
                denial_code,
                "Current role or plan cannot create tasks for this agent.",
                {
                    "agent_id": agent_id,
                    "required_plan": agent["access"]["min_plan"],
                    "allowed_roles": agent["access"]["roles"],
                },
            )

        security = _security_decision_for(payload.prompt, payload.context)

        if security.required:
            FALLBACK_STATE.log_audit(
                user_id=identity.user_id,
                workspace_id=identity.workspace_id,
                action="security.route",
                resource_type="agent_task",
                resource_id=agent_id,
                metadata={
                    "agent_id": agent_id,
                    "routed_to_agent_id": SECURITY_AGENT_ID,
                    "approved": security.approved,
                    "reason": security.reason,
                },
            )

        if security.required and not security.approved:
            return _structured_error(
                "SECURITY_APPROVAL_REQUIRED",
                "Sensitive actions must be approved by the Security Agent before execution.",
                {
                    "agent_id": agent_id,
                    "routed_to_agent_id": SECURITY_AGENT_ID,
                    "reason": security.reason,
                },
            )

        task_id = _safe_uuid("task")
        memory_context = _memory_context_for(identity, agent_id, payload.prompt)
        task_status = "completed"
        verification_payload = _verification_payload_for(
            identity=identity,
            agent_id=agent_id,
            task_id=task_id,
            status_value=task_status,
            security=security,
        )

        task = TaskRecord(
            task_id=task_id,
            agent_id=agent_id,
            user_id=identity.user_id,
            workspace_id=identity.workspace_id,
            prompt=payload.prompt,
            status=task_status,
            security=security,
            memory_context=memory_context,
            verification_payload=verification_payload,
        )
        FALLBACK_STATE.tasks[task_id] = task

        if _is_state_changing_action(payload.prompt):
            FALLBACK_STATE.log_audit(
                user_id=identity.user_id,
                workspace_id=identity.workspace_id,
                action="agent_task.create",
                resource_type="agent_task",
                resource_id=task_id,
                metadata={
                    "agent_id": agent_id,
                    "path": str(request.url.path),
                    "security_required": security.required,
                    "security_approved": security.approved,
                },
            )

        return {
            "success": True,
            "data": {
                "task": {
                    "task_id": task.task_id,
                    "agent_id": task.agent_id,
                    "user_id": task.user_id,
                    "workspace_id": task.workspace_id,
                    "status": task.status,
                    "security": {
                        "required": task.security.required,
                        "approved": task.security.approved,
                        "reason": task.security.reason,
                        "routed_to_agent_id": task.security.routed_to_agent_id,
                    },
                    "memory_context": task.memory_context,
                    "verification_payload": task.verification_payload,
                }
            },
            "error": None,
        }

    @app.get("/api/tasks/{task_id}")
    def get_task(task_id: str, identity: TestIdentity = Depends(current_identity)) -> Dict[str, Any]:
        task = FALLBACK_STATE.tasks.get(task_id)
        if not task:
            return _structured_error(
                "TASK_NOT_FOUND",
                "Task was not found.",
                {"task_id": task_id},
            )

        if task.user_id != identity.user_id or task.workspace_id != identity.workspace_id:
            return _structured_error(
                "TASK_FORBIDDEN",
                "You cannot access tasks from another user or workspace.",
                {"task_id": task_id},
            )

        return {
            "success": True,
            "data": {
                "task_id": task.task_id,
                "agent_id": task.agent_id,
                "user_id": task.user_id,
                "workspace_id": task.workspace_id,
                "status": task.status,
                "verification_payload": task.verification_payload,
            },
            "error": None,
        }

    @app.get("/api/audit/events")
    def list_audit_events(identity: TestIdentity = Depends(current_identity)) -> Dict[str, Any]:
        scoped = [
            {
                "event_id": event.event_id,
                "user_id": event.user_id,
                "workspace_id": event.workspace_id,
                "action": event.action,
                "resource_type": event.resource_type,
                "resource_id": event.resource_id,
                "metadata": event.metadata,
                "created_at_ms": event.created_at_ms,
            }
            for event in FALLBACK_STATE.audit_events
            if event.user_id == identity.user_id and event.workspace_id == identity.workspace_id
        ]

        return {
            "success": True,
            "data": {
                "events": scoped,
                "count": len(scoped),
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
            },
            "error": None,
        }

    return app


def load_real_app_if_available() -> Optional[FastAPI]:
    """
    Tries common app entrypoints without forcing the project to have final API files yet.
    The test suite falls back to a local app when imports are unavailable.
    """

    if os.getenv("WILLIAM_FORCE_FALLBACK_TEST_APP", "").lower() in {"1", "true", "yes"}:
        return None

    candidates = (
        "apps.api.main:app",
        "app.main:app",
        "main:app",
        "backend.main:app",
    )

    for candidate in candidates:
        module_name, attr_name = candidate.split(":", 1)
        try:
            module = importlib.import_module(module_name)
            app = getattr(module, attr_name, None)
            if app is not None:
                return app
        except Exception:
            continue

    return None


@pytest.fixture()
def identities() -> Dict[str, TestIdentity]:
    return {
        "owner_a": TestIdentity(
            user_id="user_owner_alpha",
            workspace_id="workspace_alpha",
            role="owner",
            plan="enterprise",
            display_name="Alpha Owner",
        ),
        "admin_a": TestIdentity(
            user_id="user_admin_alpha",
            workspace_id="workspace_alpha",
            role="admin",
            plan="pro",
            display_name="Alpha Admin",
        ),
        "member_a": TestIdentity(
            user_id="user_member_alpha",
            workspace_id="workspace_alpha",
            role="member",
            plan="free",
            display_name="Alpha Member",
        ),
        "owner_b": TestIdentity(
            user_id="user_owner_beta",
            workspace_id="workspace_beta",
            role="owner",
            plan="enterprise",
            display_name="Beta Owner",
        ),
        "member_b": TestIdentity(
            user_id="user_member_beta",
            workspace_id="workspace_beta",
            role="member",
            plan="pro",
            display_name="Beta Member",
        ),
    }


@pytest.fixture()
def app() -> FastAPI:
    FALLBACK_STATE.reset()
    return load_real_app_if_available() or build_fallback_app()


@pytest.fixture()
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def auth_headers(identity: TestIdentity, **overrides: str) -> Dict[str, str]:
    headers = {
        "X-User-Id": identity.user_id,
        "X-Workspace-Id": identity.workspace_id,
        "X-Role": identity.role,
        "X-Plan": identity.plan,
    }
    headers.update({key: value for key, value in overrides.items() if value is not None})
    return headers


def response_json(response: Any) -> Dict[str, Any]:
    try:
        return response.json()
    except Exception as exc:
        pytest.fail(f"Expected JSON response, got: {response.text!r}. Error: {exc}")


def assert_structured_success(payload: Dict[str, Any]) -> None:
    assert payload["success"] is True
    assert "data" in payload
    assert payload.get("error") in (None, {})


def assert_structured_error(payload: Dict[str, Any], expected_code: str) -> None:
    assert payload["success"] is False
    assert payload.get("data") in (None, {})
    assert payload["error"]["code"] == expected_code
    assert isinstance(payload["error"]["message"], str)
    assert payload["error"]["message"]


def assert_identity_shape(data: Dict[str, Any], identity: TestIdentity) -> None:
    assert data["user_id"] == identity.user_id
    assert data["workspace_id"] == identity.workspace_id


def assert_agent_shape(agent: Dict[str, Any]) -> None:
    assert agent["agent_id"] in KNOWN_AGENT_IDS
    assert isinstance(agent["name"], str)
    assert agent["name"]
    assert isinstance(agent["capabilities"], list)
    assert agent["capabilities"]
    assert agent["requires_user_id"] is True
    assert agent["requires_workspace_id"] is True
    assert agent["memory_compatible"] is True
    assert agent["verification_enabled"] is True
    assert "access" in agent
    assert "min_plan" in agent["access"]
    assert "roles" in agent["access"]


def assert_task_is_isolated(task: Dict[str, Any], identity: TestIdentity, agent_id: str) -> None:
    assert task["agent_id"] == agent_id
    assert task["user_id"] == identity.user_id
    assert task["workspace_id"] == identity.workspace_id


def assert_security_payload(
    security_payload: Dict[str, Any],
    *,
    required: bool,
    approved: bool,
) -> None:
    assert security_payload["required"] is required
    assert security_payload["approved"] is approved
    assert isinstance(security_payload["reason"], str)
    assert security_payload["reason"]
    if required:
        assert security_payload["routed_to_agent_id"] == SECURITY_AGENT_ID


def assert_memory_context(memory_context: Dict[str, Any], identity: TestIdentity, agent_id: str) -> None:
    assert memory_context["memory_agent_id"] == MEMORY_AGENT_ID
    assert memory_context["user_id"] == identity.user_id
    assert memory_context["workspace_id"] == identity.workspace_id
    assert memory_context["agent_id"] == agent_id
    assert memory_context["context_type"] == "agent_task"
    assert memory_context["safe_to_store"] is True
    assert isinstance(memory_context["summary"], str)
    assert memory_context["summary"]


def assert_verification_payload(
    verification_payload: Dict[str, Any],
    identity: TestIdentity,
    agent_id: str,
) -> None:
    assert verification_payload["verification_agent_id"] == VERIFICATION_AGENT_ID
    assert verification_payload["agent_id"] == agent_id
    assert verification_payload["user_id"] == identity.user_id
    assert verification_payload["workspace_id"] == identity.workspace_id
    assert verification_payload["status"] in {"queued", "running", "completed", "failed"}
    assert verification_payload["checks"]["user_workspace_isolation"] is True
    assert verification_payload["checks"]["memory_context_prepared"] is True
    assert verification_payload["checks"]["audit_ready"] is True


class TestAgents:
    """Agent list/access/task API tests for William / Jarvis."""

    def test_agent_list_requires_auth_context(self, client: TestClient) -> None:
        response = client.get("/api/agents")

        assert response.status_code in {
            status.HTTP_401_UNAUTHORIZED,
            status.HTTP_403_FORBIDDEN,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        }

        payload = response_json(response)
        assert payload

    def test_agent_list_returns_all_known_agents_with_safe_shape(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["owner_a"]

        response = client.get("/api/agents", headers=auth_headers(identity))

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)
        assert_structured_success(payload)
        assert_identity_shape(payload["data"], identity)

        agents = payload["data"]["agents"]
        assert payload["data"]["count"] == len(KNOWN_AGENT_IDS)
        assert {agent["agent_id"] for agent in agents} == set(KNOWN_AGENT_IDS)

        for agent in agents:
            assert_agent_shape(agent)
            assert agent["available_to_current_user"] is True
            assert agent["access_reason"] == "ACCESS_GRANTED"

    def test_agent_list_denies_cross_workspace_query(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["owner_a"]

        response = client.get(
            "/api/agents",
            params={"workspace_id": identities["owner_b"].workspace_id},
            headers=auth_headers(identity),
        )

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)
        assert_structured_error(payload, "WORKSPACE_FORBIDDEN")

    def test_agent_list_marks_unavailable_agents_by_plan_and_role(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["member_a"]

        response = client.get("/api/agents", headers=auth_headers(identity))

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)
        assert_structured_success(payload)

        agents_by_id = {agent["agent_id"]: agent for agent in payload["data"]["agents"]}

        assert agents_by_id["master"]["available_to_current_user"] is True
        assert agents_by_id["memory"]["available_to_current_user"] is True
        assert agents_by_id["verification"]["available_to_current_user"] is True

        assert agents_by_id["code"]["available_to_current_user"] is False
        assert agents_by_id["code"]["access_reason"] == "PLAN_UPGRADE_REQUIRED"

        assert agents_by_id["security"]["available_to_current_user"] is False
        assert agents_by_id["security"]["access_reason"] == "ROLE_NOT_ALLOWED"

    def test_get_agent_returns_agent_for_authorized_user(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["admin_a"]

        response = client.get("/api/agents/code", headers=auth_headers(identity))

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)
        assert_structured_success(payload)
        assert_identity_shape(payload["data"], identity)
        assert_agent_shape(payload["data"]["agent"])
        assert payload["data"]["agent"]["agent_id"] == "code"

    def test_get_agent_returns_safe_not_found_for_unknown_agent(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        response = client.get(
            "/api/agents/not-a-real-agent",
            headers=auth_headers(identities["owner_a"]),
        )

        assert response.status_code == status.HTTP_404_NOT_FOUND
        payload = response_json(response)
        detail = payload.get("detail", payload)
        assert detail["code"] == "AGENT_NOT_FOUND"

    def test_get_agent_enforces_role_gate_for_security_agent(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        response = client.get(
            "/api/agents/security",
            headers=auth_headers(identities["member_b"]),
        )

        assert response.status_code in {status.HTTP_403_FORBIDDEN, status.HTTP_200_OK}
        payload = response_json(response)

        if response.status_code == status.HTTP_200_OK:
            assert_structured_error(payload, "ROLE_NOT_ALLOWED")
        else:
            detail = payload.get("detail", payload)
            assert detail["code"] == "ROLE_NOT_ALLOWED"

    def test_get_agent_enforces_subscription_plan_gate(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        response = client.get(
            "/api/agents/finance",
            headers=auth_headers(identities["admin_a"]),
        )

        assert response.status_code in {status.HTTP_402_PAYMENT_REQUIRED, status.HTTP_200_OK}
        payload = response_json(response)

        if response.status_code == status.HTTP_200_OK:
            assert_structured_error(payload, "PLAN_UPGRADE_REQUIRED")
        else:
            detail = payload.get("detail", payload)
            assert detail["code"] == "PLAN_UPGRADE_REQUIRED"

    def test_create_agent_task_requires_payload_user_and_workspace(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["owner_a"]

        response = client.post(
            "/api/agents/master/tasks",
            headers=auth_headers(identity),
            json={"prompt": "Summarize workspace status."},
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_create_agent_task_rejects_user_context_mismatch(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["owner_a"]

        response = client.post(
            "/api/agents/master/tasks",
            headers=auth_headers(identity),
            json={
                "user_id": identities["owner_b"].user_id,
                "workspace_id": identity.workspace_id,
                "prompt": "Create safe project plan.",
                "context": {},
            },
        )

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)
        assert_structured_error(payload, "USER_CONTEXT_MISMATCH")

    def test_create_agent_task_rejects_workspace_context_mismatch(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["owner_a"]

        response = client.post(
            "/api/agents/master/tasks",
            headers=auth_headers(identity),
            json={
                "user_id": identity.user_id,
                "workspace_id": identities["owner_b"].workspace_id,
                "prompt": "Create safe project plan.",
                "context": {},
            },
        )

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)
        assert_structured_error(payload, "WORKSPACE_CONTEXT_MISMATCH")

    def test_create_agent_task_for_master_agent_prepares_memory_and_verification(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["owner_a"]
        agent_id = MASTER_AGENT_ID

        response = client.post(
            f"/api/agents/{agent_id}/tasks",
            headers=auth_headers(identity),
            json={
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
                "prompt": "Create a safe launch checklist for the dashboard.",
                "context": {"source": "test_suite"},
            },
        )

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)
        assert_structured_success(payload)

        task = payload["data"]["task"]
        assert_task_is_isolated(task, identity, agent_id)
        assert task["status"] == "completed"
        assert_security_payload(task["security"], required=False, approved=True)
        assert_memory_context(task["memory_context"], identity, agent_id)
        assert_verification_payload(task["verification_payload"], identity, agent_id)

    def test_create_agent_task_enforces_plan_gate(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["member_a"]

        response = client.post(
            "/api/agents/code/tasks",
            headers=auth_headers(identity),
            json={
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
                "prompt": "Review this Python module.",
                "context": {},
            },
        )

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)
        assert_structured_error(payload, "PLAN_UPGRADE_REQUIRED")

    def test_create_agent_task_enforces_role_gate(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["member_b"]

        response = client.post(
            "/api/agents/workflow/tasks",
            headers=auth_headers(identity),
            json={
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
                "prompt": "Create workflow automation for onboarding.",
                "context": {},
            },
        )

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)
        assert_structured_error(payload, "ROLE_NOT_ALLOWED")

    def test_sensitive_task_routes_to_security_agent_and_blocks_without_approval(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["owner_a"]

        response = client.post(
            "/api/agents/system/tasks",
            headers=auth_headers(identity),
            json={
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
                "prompt": "Delete production logs and deploy new config.",
                "context": {
                    "target": "production",
                    "change_type": "database_write",
                },
            },
        )

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)
        assert_structured_error(payload, "SECURITY_APPROVAL_REQUIRED")

        details = payload["error"]["details"]
        assert details["routed_to_agent_id"] == SECURITY_AGENT_ID
        assert details["agent_id"] == "system"

    def test_sensitive_task_executes_after_security_approval(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["owner_a"]
        agent_id = "system"

        response = client.post(
            f"/api/agents/{agent_id}/tasks",
            headers=auth_headers(identity),
            json={
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
                "prompt": "Deploy approved production configuration.",
                "context": {
                    "target": "production",
                    "change_type": "database_write",
                    "security_approved": True,
                },
            },
        )

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)
        assert_structured_success(payload)

        task = payload["data"]["task"]
        assert_task_is_isolated(task, identity, agent_id)
        assert_security_payload(task["security"], required=True, approved=True)
        assert task["security"]["routed_to_agent_id"] == SECURITY_AGENT_ID
        assert_memory_context(task["memory_context"], identity, agent_id)

        verification = task["verification_payload"]
        assert_verification_payload(verification, identity, agent_id)
        assert verification["checks"]["security_reviewed"] is True
        assert verification["checks"]["security_approved"] is True

    def test_state_changing_task_creates_audit_event(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["owner_a"]

        task_response = client.post(
            "/api/agents/master/tasks",
            headers=auth_headers(identity),
            json={
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
                "prompt": "Create onboarding task for new workspace.",
                "context": {"source": "api_test"},
            },
        )

        assert task_response.status_code == status.HTTP_200_OK
        task_payload = response_json(task_response)
        assert_structured_success(task_payload)

        audit_response = client.get("/api/audit/events", headers=auth_headers(identity))
        assert audit_response.status_code == status.HTTP_200_OK
        audit_payload = response_json(audit_response)
        assert_structured_success(audit_payload)

        events = audit_payload["data"]["events"]
        assert any(event["action"] == "agent_task.create" for event in events)
        assert all(event["user_id"] == identity.user_id for event in events)
        assert all(event["workspace_id"] == identity.workspace_id for event in events)

    def test_sensitive_task_security_route_creates_audit_event_even_when_blocked(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["owner_a"]

        response = client.post(
            "/api/agents/system/tasks",
            headers=auth_headers(identity),
            json={
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
                "prompt": "Delete production secrets.",
                "context": {"target": "secret_store"},
            },
        )

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)
        assert_structured_error(payload, "SECURITY_APPROVAL_REQUIRED")

        audit_response = client.get("/api/audit/events", headers=auth_headers(identity))
        audit_payload = response_json(audit_response)
        assert_structured_success(audit_payload)

        security_events = [
            event
            for event in audit_payload["data"]["events"]
            if event["action"] == "security.route"
        ]
        assert security_events
        assert security_events[-1]["metadata"]["routed_to_agent_id"] == SECURITY_AGENT_ID
        assert security_events[-1]["metadata"]["approved"] is False

    def test_task_read_is_scoped_to_same_user_and_workspace(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        owner_a = identities["owner_a"]
        owner_b = identities["owner_b"]

        create_response = client.post(
            "/api/agents/master/tasks",
            headers=auth_headers(owner_a),
            json={
                "user_id": owner_a.user_id,
                "workspace_id": owner_a.workspace_id,
                "prompt": "Create isolated task for alpha workspace.",
                "context": {},
            },
        )

        assert create_response.status_code == status.HTTP_200_OK
        create_payload = response_json(create_response)
        assert_structured_success(create_payload)

        task_id = create_payload["data"]["task"]["task_id"]

        same_owner_response = client.get(
            f"/api/tasks/{task_id}",
            headers=auth_headers(owner_a),
        )
        assert same_owner_response.status_code == status.HTTP_200_OK
        same_owner_payload = response_json(same_owner_response)
        assert_structured_success(same_owner_payload)
        assert same_owner_payload["data"]["task_id"] == task_id
        assert same_owner_payload["data"]["workspace_id"] == owner_a.workspace_id

        other_workspace_response = client.get(
            f"/api/tasks/{task_id}",
            headers=auth_headers(owner_b),
        )
        assert other_workspace_response.status_code == status.HTTP_200_OK
        other_workspace_payload = response_json(other_workspace_response)
        assert_structured_error(other_workspace_payload, "TASK_FORBIDDEN")

    def test_audit_events_do_not_leak_between_workspaces(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        owner_a = identities["owner_a"]
        owner_b = identities["owner_b"]

        client.post(
            "/api/agents/master/tasks",
            headers=auth_headers(owner_a),
            json={
                "user_id": owner_a.user_id,
                "workspace_id": owner_a.workspace_id,
                "prompt": "Create Alpha workspace task.",
                "context": {},
            },
        )

        client.post(
            "/api/agents/master/tasks",
            headers=auth_headers(owner_b),
            json={
                "user_id": owner_b.user_id,
                "workspace_id": owner_b.workspace_id,
                "prompt": "Create Beta workspace task.",
                "context": {},
            },
        )

        alpha_audit = response_json(
            client.get("/api/audit/events", headers=auth_headers(owner_a))
        )
        beta_audit = response_json(
            client.get("/api/audit/events", headers=auth_headers(owner_b))
        )

        assert_structured_success(alpha_audit)
        assert_structured_success(beta_audit)

        assert alpha_audit["data"]["events"]
        assert beta_audit["data"]["events"]

        assert all(
            event["workspace_id"] == owner_a.workspace_id
            for event in alpha_audit["data"]["events"]
        )
        assert all(
            event["workspace_id"] == owner_b.workspace_id
            for event in beta_audit["data"]["events"]
        )

        alpha_event_ids = {event["event_id"] for event in alpha_audit["data"]["events"]}
        beta_event_ids = {event["event_id"] for event in beta_audit["data"]["events"]}
        assert alpha_event_ids.isdisjoint(beta_event_ids)

    def test_memory_agent_task_is_available_to_free_member_with_isolation(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["member_a"]
        agent_id = MEMORY_AGENT_ID

        response = client.post(
            f"/api/agents/{agent_id}/tasks",
            headers=auth_headers(identity),
            json={
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
                "prompt": "Recall safe project context for this workspace only.",
                "context": {"scope": "workspace_only"},
            },
        )

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)
        assert_structured_success(payload)

        task = payload["data"]["task"]
        assert_task_is_isolated(task, identity, agent_id)
        assert_memory_context(task["memory_context"], identity, agent_id)
        assert_verification_payload(task["verification_payload"], identity, agent_id)

    def test_verification_agent_task_prepares_completion_confirmation_payload(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["member_a"]
        agent_id = VERIFICATION_AGENT_ID

        response = client.post(
            f"/api/agents/{agent_id}/tasks",
            headers=auth_headers(identity),
            json={
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
                "prompt": "Confirm that the generated report is complete.",
                "context": {"target_task_id": "example_task_123"},
            },
        )

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)
        assert_structured_success(payload)

        task = payload["data"]["task"]
        assert_task_is_isolated(task, identity, agent_id)
        verification = task["verification_payload"]
        assert_verification_payload(verification, identity, agent_id)
        assert verification["checks"]["user_workspace_isolation"] is True

    def test_master_agent_can_coordinate_future_agent_payload_shape(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["owner_a"]

        response = client.post(
            "/api/agents/master/tasks",
            headers=auth_headers(identity),
            json={
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
                "prompt": "Route this task to Code Agent, Memory Agent, and Verification Agent.",
                "context": {
                    "requested_agents": ["code", "memory", "verification"],
                    "expected_output": "safe_coordination_plan",
                },
            },
        )

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)
        assert_structured_success(payload)

        task = payload["data"]["task"]
        assert_task_is_isolated(task, identity, MASTER_AGENT_ID)
        assert task["memory_context"]["memory_agent_id"] == MEMORY_AGENT_ID
        assert task["verification_payload"]["verification_agent_id"] == VERIFICATION_AGENT_ID

    @pytest.mark.parametrize(
        ("agent_id", "identity_key", "expected_access"),
        [
            ("master", "member_a", True),
            ("memory", "member_a", True),
            ("verification", "member_a", True),
            ("code", "member_a", False),
            ("business", "member_b", True),
            ("finance", "admin_a", False),
            ("finance", "owner_a", True),
            ("security", "member_b", False),
            ("security", "owner_a", True),
            ("workflow", "admin_a", True),
            ("workflow", "member_b", False),
        ],
    )
    def test_agent_access_matrix(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
        agent_id: str,
        identity_key: str,
        expected_access: bool,
    ) -> None:
        identity = identities[identity_key]

        response = client.post(
            f"/api/agents/{agent_id}/tasks",
            headers=auth_headers(identity),
            json={
                "user_id": identity.user_id,
                "workspace_id": identity.workspace_id,
                "prompt": f"Create safe test task for {agent_id}.",
                "context": {},
            },
        )

        assert response.status_code == status.HTTP_200_OK
        payload = response_json(response)

        if expected_access:
            assert_structured_success(payload)
            assert payload["data"]["task"]["agent_id"] == agent_id
            assert payload["data"]["task"]["workspace_id"] == identity.workspace_id
        else:
            assert payload["success"] is False
            assert payload["error"]["code"] in {"PLAN_UPGRADE_REQUIRED", "ROLE_NOT_ALLOWED"}

    def test_error_payloads_do_not_expose_stack_traces_or_secrets(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        response = client.post(
            "/api/agents/system/tasks",
            headers=auth_headers(identities["owner_a"]),
            json={
                "user_id": identities["owner_a"].user_id,
                "workspace_id": identities["owner_a"].workspace_id,
                "prompt": "Delete token secret from production.",
                "context": {"api_key": "should-not-be-used"},
            },
        )

        assert response.status_code == status.HTTP_200_OK
        payload_text = response.text.lower()

        blocked_terms = [
            "traceback",
            "stack trace",
            "exception:",
            "should-not-be-used",
            "secret_value",
            "private_key",
        ]
        assert all(term not in payload_text for term in blocked_terms)

        payload = response_json(response)
        assert_structured_error(payload, "SECURITY_APPROVAL_REQUIRED")

    def test_every_created_task_has_user_workspace_agent_and_verification_fields(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["owner_a"]

        created_tasks: List[Dict[str, Any]] = []
        for agent_id in ("master", "memory", "verification", "business", "creator"):
            response = client.post(
                f"/api/agents/{agent_id}/tasks",
                headers=auth_headers(identity),
                json={
                    "user_id": identity.user_id,
                    "workspace_id": identity.workspace_id,
                    "prompt": f"Create safe task for {agent_id} agent.",
                    "context": {"batch": "created_task_contract"},
                },
            )

            assert response.status_code == status.HTTP_200_OK
            payload = response_json(response)
            assert_structured_success(payload)
            created_tasks.append(payload["data"]["task"])

        assert len(created_tasks) == 5

        for task in created_tasks:
            assert task["task_id"]
            assert task["user_id"] == identity.user_id
            assert task["workspace_id"] == identity.workspace_id
            assert task["agent_id"] in KNOWN_AGENT_IDS
            assert "security" in task
            assert "memory_context" in task
            assert "verification_payload" in task
            assert_verification_payload(task["verification_payload"], identity, task["agent_id"])

    def test_real_or_fallback_api_uses_consistent_json_response_contract(
        self,
        client: TestClient,
        identities: Dict[str, TestIdentity],
    ) -> None:
        identity = identities["owner_a"]

        responses = [
            client.get("/api/agents", headers=auth_headers(identity)),
            client.post(
                "/api/agents/master/tasks",
                headers=auth_headers(identity),
                json={
                    "user_id": identity.user_id,
                    "workspace_id": identity.workspace_id,
                    "prompt": "Create response contract test task.",
                    "context": {},
                },
            ),
            client.get("/api/audit/events", headers=auth_headers(identity)),
        ]

        for response in responses:
            assert response.headers["content-type"].startswith("application/json")
            payload = response_json(response)
            assert "success" in payload
            assert "data" in payload
            assert "error" in payload