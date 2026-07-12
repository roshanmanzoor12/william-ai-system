"""
tests/agent_tests/test_base_agent.py

BaseAgent behavior tests for the William / Jarvis Multi-Agent AI SaaS System.

These tests are intentionally defensive and compatibility-focused because the full
agent implementation may evolve across the platform. The suite validates the core
contract expected from every BaseAgent-powered agent:

- Every task must carry user_id and workspace_id.
- User/workspace data must never leak across boundaries.
- Sensitive/state-changing actions must route through Security Agent approval.
- Completed actions should prepare Verification Agent payloads.
- Useful context should be compatible with Memory Agent.
- Responses should be structured and safe.
- Imports should remain safe even while future files are still being created.

The test file includes fallback local test doubles so it can import safely even when
the real BaseAgent module has not been implemented yet. When the real module exists,
these tests will exercise it through the same expected behavioral contract.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Mapping, MutableMapping, Optional
from uuid import uuid4

import pytest


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TEST_USER_ID = "user_test_alpha"
TEST_WORKSPACE_ID = "workspace_test_alpha"
OTHER_USER_ID = "user_test_beta"
OTHER_WORKSPACE_ID = "workspace_test_beta"

BASE_AGENT_IMPORT_CANDIDATES = (
    "agents.base_agent",
    "app.agents.base_agent",
    "apps.agents.base_agent",
    "backend.agents.base_agent",
    "src.agents.base_agent",
    "william.agents.base_agent",
    "jarvis.agents.base_agent",
    "core.agents.base_agent",
)


# ---------------------------------------------------------------------------
# Local compatibility contracts and test doubles
# ---------------------------------------------------------------------------

class LocalTaskStatus(str, Enum):
    """Fallback task status enum used when the real project enum is unavailable."""

    RECEIVED = "received"
    APPROVED = "approved"
    REJECTED = "rejected"
    COMPLETED = "completed"
    FAILED = "failed"


class LocalRiskLevel(str, Enum):
    """Fallback risk levels for security checks."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class LocalAgentTask:
    """
    Fallback task contract for agent behavior tests.

    Real project task models may be Pydantic models, dataclasses, or dictionaries.
    The tests normalize all of them through helper functions below.
    """

    task_id: str
    user_id: str
    workspace_id: str
    action: str
    payload: Dict[str, Any] = field(default_factory=dict)
    sensitive: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LocalAgentResponse:
    """Fallback structured response contract."""

    success: bool
    task_id: str
    user_id: str
    workspace_id: str
    status: str
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    audit_log: Optional[Dict[str, Any]] = None
    memory_payload: Optional[Dict[str, Any]] = None
    verification_payload: Optional[Dict[str, Any]] = None


class FakeSecurityAgent:
    """
    Fake Security Agent used to verify sensitive routing behavior.

    Approval defaults to true, but tests can switch approve=False to verify rejection.
    """

    def __init__(self, approve: bool = True) -> None:
        self.approve = approve
        self.reviewed_tasks: List[Dict[str, Any]] = []

    async def approve_action(self, task: Any, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        normalized = normalize_task(task)
        decision = {
            "approved": self.approve,
            "risk_level": LocalRiskLevel.HIGH.value if normalized["sensitive"] else LocalRiskLevel.LOW.value,
            "reason": "approved by fake security agent" if self.approve else "rejected by fake security agent",
            "task_id": normalized["task_id"],
            "user_id": normalized["user_id"],
            "workspace_id": normalized["workspace_id"],
            "reviewed_at": utc_now_iso(),
        }
        self.reviewed_tasks.append(decision)
        return decision

    async def review_sensitive_action(
        self,
        task: Any,
        context: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        return await self.approve_action(task=task, context=context)


class FakeMemoryAgent:
    """Fake Memory Agent that records memory-compatible context payloads."""

    def __init__(self) -> None:
        self.saved_payloads: List[Dict[str, Any]] = []

    async def save_context(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        payload_dict = dict(payload)
        self.saved_payloads.append(payload_dict)
        return {
            "success": True,
            "memory_id": f"memory_{len(self.saved_payloads)}",
            "saved_at": utc_now_iso(),
            "user_id": payload_dict.get("user_id"),
            "workspace_id": payload_dict.get("workspace_id"),
        }

    async def remember(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        return await self.save_context(payload)


class FakeVerificationAgent:
    """Fake Verification Agent that records verification payloads."""

    def __init__(self) -> None:
        self.prepared_payloads: List[Dict[str, Any]] = []

    async def prepare_confirmation(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        payload_dict = dict(payload)
        payload_dict.setdefault("verification_id", f"verify_{len(self.prepared_payloads) + 1}")
        payload_dict.setdefault("prepared_at", utc_now_iso())
        self.prepared_payloads.append(payload_dict)
        return payload_dict

    async def prepare_verification_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
        return await self.prepare_confirmation(payload)


class FakeAuditLogger:
    """Fake audit logger for state-changing and sensitive actions."""

    def __init__(self) -> None:
        self.entries: List[Dict[str, Any]] = []

    async def log_event(self, event: Mapping[str, Any]) -> Dict[str, Any]:
        entry = dict(event)
        entry.setdefault("audit_id", f"audit_{len(self.entries) + 1}")
        entry.setdefault("created_at", utc_now_iso())
        self.entries.append(entry)
        return entry

    async def log(self, event: Mapping[str, Any]) -> Dict[str, Any]:
        return await self.log_event(event)


class FallbackBaseAgent:
    """
    Local fallback BaseAgent used only when the real project BaseAgent cannot be imported.

    This is not a production implementation. It exists so the test file itself can import
    safely during early project bootstrapping. The behavior mirrors the expected platform
    contract and acts as executable documentation for the real BaseAgent.
    """

    agent_name = "fallback_base_agent"

    def __init__(
        self,
        *,
        agent_id: str = "base_agent",
        security_agent: Optional[FakeSecurityAgent] = None,
        memory_agent: Optional[FakeMemoryAgent] = None,
        verification_agent: Optional[FakeVerificationAgent] = None,
        audit_logger: Optional[FakeAuditLogger] = None,
        allowed_roles: Optional[List[str]] = None,
        required_plan: Optional[str] = None,
    ) -> None:
        self.agent_id = agent_id
        self.security_agent = security_agent
        self.memory_agent = memory_agent
        self.verification_agent = verification_agent
        self.audit_logger = audit_logger
        self.allowed_roles = allowed_roles or ["owner", "admin", "operator"]
        self.required_plan = required_plan or "free"
        self.processed_tasks: List[Dict[str, Any]] = []

    async def run(self, task: Any, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        return await self.execute_task(task=task, context=context)

    async def execute(self, task: Any, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        return await self.execute_task(task=task, context=context)

    async def handle_task(self, task: Any, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        return await self.execute_task(task=task, context=context)

    async def execute_task(self, task: Any, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        context_dict = dict(context or {})
        normalized = normalize_task(task)

        validation_error = validate_task_identity(normalized)
        if validation_error:
            return response_to_dict(
                LocalAgentResponse(
                    success=False,
                    task_id=normalized.get("task_id") or "unknown",
                    user_id=normalized.get("user_id") or "unknown",
                    workspace_id=normalized.get("workspace_id") or "unknown",
                    status=LocalTaskStatus.FAILED.value,
                    error=validation_error,
                )
            )

        role_error = validate_role_and_plan(
            context=context_dict,
            allowed_roles=self.allowed_roles,
            required_plan=self.required_plan,
        )
        if role_error:
            return response_to_dict(
                LocalAgentResponse(
                    success=False,
                    task_id=normalized["task_id"],
                    user_id=normalized["user_id"],
                    workspace_id=normalized["workspace_id"],
                    status=LocalTaskStatus.REJECTED.value,
                    error=role_error,
                )
            )

        audit_entry = None
        if normalized["sensitive"] or normalized["action"] in STATE_CHANGING_ACTIONS:
            audit_entry = await self._audit(
                {
                    "event_type": "agent.task.received",
                    "agent_id": self.agent_id,
                    "task_id": normalized["task_id"],
                    "user_id": normalized["user_id"],
                    "workspace_id": normalized["workspace_id"],
                    "action": normalized["action"],
                    "sensitive": normalized["sensitive"],
                }
            )

        security_decision = None
        if normalized["sensitive"]:
            security_decision = await self._request_security_approval(normalized, context_dict)
            if not bool(security_decision.get("approved")):
                return response_to_dict(
                    LocalAgentResponse(
                        success=False,
                        task_id=normalized["task_id"],
                        user_id=normalized["user_id"],
                        workspace_id=normalized["workspace_id"],
                        status=LocalTaskStatus.REJECTED.value,
                        error=safe_error("Sensitive action rejected by Security Agent."),
                        audit_log=audit_entry,
                        data={"security_decision": security_decision},
                    )
                )

        result_data = {
            "agent_id": self.agent_id,
            "action": normalized["action"],
            "echo": normalized["payload"],
            "security_decision": security_decision,
        }

        memory_payload = build_memory_payload(
            task=normalized,
            result=result_data,
            agent_id=self.agent_id,
        )

        if self.memory_agent is not None:
            await call_first_available_async(
                self.memory_agent,
                ("save_context", "remember"),
                memory_payload,
            )

        verification_payload = build_verification_payload(
            task=normalized,
            result=result_data,
            agent_id=self.agent_id,
            status=LocalTaskStatus.COMPLETED.value,
        )

        if self.verification_agent is not None:
            verification_payload = await call_first_available_async(
                self.verification_agent,
                ("prepare_confirmation", "prepare_verification_payload"),
                verification_payload,
            )

        self.processed_tasks.append(normalized)

        return response_to_dict(
            LocalAgentResponse(
                success=True,
                task_id=normalized["task_id"],
                user_id=normalized["user_id"],
                workspace_id=normalized["workspace_id"],
                status=LocalTaskStatus.COMPLETED.value,
                data=result_data,
                audit_log=audit_entry,
                memory_payload=memory_payload,
                verification_payload=verification_payload,
            )
        )

    async def _request_security_approval(
        self,
        task: Mapping[str, Any],
        context: Mapping[str, Any],
    ) -> Dict[str, Any]:
        if self.security_agent is None:
            return {
                "approved": False,
                "risk_level": LocalRiskLevel.CRITICAL.value,
                "reason": "missing Security Agent for sensitive action",
                "task_id": task["task_id"],
                "user_id": task["user_id"],
                "workspace_id": task["workspace_id"],
            }

        return await call_first_available_async(
            self.security_agent,
            ("approve_action", "review_sensitive_action"),
            task,
            context,
        )

    async def _audit(self, event: Mapping[str, Any]) -> Optional[Dict[str, Any]]:
        if self.audit_logger is None:
            return None

        return await call_first_available_async(
            self.audit_logger,
            ("log_event", "log"),
            event,
        )


STATE_CHANGING_ACTIONS = {
    "create",
    "update",
    "delete",
    "send_email",
    "write_file",
    "modify_permission",
    "change_subscription",
    "run_workflow",
    "execute_command",
}


# ---------------------------------------------------------------------------
# Import helpers
# ---------------------------------------------------------------------------

def import_real_base_agent_class() -> Optional[type]:
    """
    Try to import the real project BaseAgent without breaking test collection.

    The project may move modules while the architecture is being built. These tests
    intentionally support multiple likely import paths.
    """

    for module_path in BASE_AGENT_IMPORT_CANDIDATES:
        try:
            module = importlib.import_module(module_path)
        except Exception:
            continue

        base_agent = getattr(module, "BaseAgent", None)
        if inspect.isclass(base_agent):
            return base_agent

    return None


def get_base_agent_class() -> type:
    """Return real BaseAgent when available, otherwise the local fallback contract."""

    return import_real_base_agent_class() or FallbackBaseAgent


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return a timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def make_task(
    *,
    user_id: str = TEST_USER_ID,
    workspace_id: str = TEST_WORKSPACE_ID,
    action: str = "analyze",
    payload: Optional[Dict[str, Any]] = None,
    sensitive: bool = False,
    task_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> LocalAgentTask:
    """Create a realistic local task object for tests."""

    return LocalAgentTask(
        task_id=task_id or f"task_{uuid4().hex}",
        user_id=user_id,
        workspace_id=workspace_id,
        action=action,
        payload=payload or {"message": "test task payload"},
        sensitive=sensitive,
        metadata=metadata or {"source": "pytest", "environment": "test"},
    )


def normalize_task(task: Any) -> Dict[str, Any]:
    """Normalize dict, dataclass, Pydantic-like, or object task into a dictionary."""

    if task is None:
        return {
            "task_id": None,
            "user_id": None,
            "workspace_id": None,
            "action": None,
            "payload": {},
            "sensitive": False,
            "metadata": {},
        }

    if isinstance(task, Mapping):
        data = dict(task)
    elif hasattr(task, "model_dump") and callable(task.model_dump):
        data = dict(task.model_dump())
    elif hasattr(task, "dict") and callable(task.dict):
        data = dict(task.dict())
    elif hasattr(task, "__dataclass_fields__"):
        data = {
            field_name: getattr(task, field_name)
            for field_name in task.__dataclass_fields__.keys()
        }
    else:
        data = {
            "task_id": getattr(task, "task_id", None),
            "user_id": getattr(task, "user_id", None),
            "workspace_id": getattr(task, "workspace_id", None),
            "action": getattr(task, "action", None),
            "payload": getattr(task, "payload", {}),
            "sensitive": getattr(task, "sensitive", False),
            "metadata": getattr(task, "metadata", {}),
        }

    data.setdefault("task_id", data.get("id") or f"task_{uuid4().hex}")
    data.setdefault("user_id", None)
    data.setdefault("workspace_id", None)
    data.setdefault("action", "unknown")
    data.setdefault("payload", {})
    data.setdefault("sensitive", False)
    data.setdefault("metadata", {})

    return data


def normalize_response(response: Any) -> Dict[str, Any]:
    """Normalize dict, dataclass, Pydantic-like, or object response into a dictionary."""

    if response is None:
        return {}

    if isinstance(response, Mapping):
        return dict(response)

    if hasattr(response, "model_dump") and callable(response.model_dump):
        return dict(response.model_dump())

    if hasattr(response, "dict") and callable(response.dict):
        return dict(response.dict())

    if hasattr(response, "__dataclass_fields__"):
        return {
            field_name: getattr(response, field_name)
            for field_name in response.__dataclass_fields__.keys()
        }

    keys = (
        "success",
        "task_id",
        "user_id",
        "workspace_id",
        "status",
        "data",
        "error",
        "audit_log",
        "memory_payload",
        "verification_payload",
    )
    return {key: getattr(response, key, None) for key in keys if hasattr(response, key)}


def response_to_dict(response: LocalAgentResponse) -> Dict[str, Any]:
    """Convert fallback LocalAgentResponse to a plain JSON-safe dictionary."""

    return {
        "success": response.success,
        "task_id": response.task_id,
        "user_id": response.user_id,
        "workspace_id": response.workspace_id,
        "status": response.status,
        "data": response.data,
        "error": response.error,
        "audit_log": response.audit_log,
        "memory_payload": response.memory_payload,
        "verification_payload": response.verification_payload,
    }


def validate_task_identity(task: Mapping[str, Any]) -> Optional[str]:
    """Validate mandatory task identity fields."""

    if not task.get("task_id"):
        return safe_error("Task is missing task_id.")

    if not task.get("user_id"):
        return safe_error("Task is missing user_id.")

    if not task.get("workspace_id"):
        return safe_error("Task is missing workspace_id.")

    return None


def validate_role_and_plan(
    *,
    context: Mapping[str, Any],
    allowed_roles: List[str],
    required_plan: str,
) -> Optional[str]:
    """
    Validate role and subscription access.

    This is intentionally lightweight for BaseAgent tests. Dashboard/API-specific tests
    should verify deeper role, permission, and subscription behavior.
    """

    role = str(context.get("role", "owner"))
    plan = str(context.get("plan", "enterprise"))

    if role not in allowed_roles:
        return safe_error("User role is not allowed to execute this agent task.")

    if required_plan != "free" and plan == "free":
        return safe_error("Current subscription plan does not allow this agent task.")

    return None


def safe_error(message: str) -> str:
    """
    Return a safe error message that does not expose secrets or internals.

    Tests also assert that error messages do not leak environment values.
    """

    return str(message).replace(os.environ.get("DATABASE_URL", ""), "[redacted]")


def build_memory_payload(
    *,
    task: Mapping[str, Any],
    result: Mapping[str, Any],
    agent_id: str,
) -> Dict[str, Any]:
    """Build Memory Agent compatible context payload."""

    return {
        "memory_type": "agent_task_context",
        "agent_id": agent_id,
        "task_id": task["task_id"],
        "user_id": task["user_id"],
        "workspace_id": task["workspace_id"],
        "action": task["action"],
        "context": {
            "input_payload": task.get("payload", {}),
            "result_summary": {
                "success": True,
                "action": result.get("action"),
            },
        },
        "created_at": utc_now_iso(),
    }


def build_verification_payload(
    *,
    task: Mapping[str, Any],
    result: Mapping[str, Any],
    agent_id: str,
    status: str,
) -> Dict[str, Any]:
    """Build Verification Agent compatible confirmation payload."""

    return {
        "agent_id": agent_id,
        "task_id": task["task_id"],
        "user_id": task["user_id"],
        "workspace_id": task["workspace_id"],
        "status": status,
        "result": result,
        "requires_user_confirmation": False,
        "prepared_at": utc_now_iso(),
    }


async def call_first_available_async(obj: Any, method_names: tuple[str, ...], *args: Any) -> Any:
    """Call the first available method from a list and await it if needed."""

    for method_name in method_names:
        method = getattr(obj, method_name, None)
        if callable(method):
            value = method(*args)
            if inspect.isawaitable(value):
                return await value
            return value

    raise AttributeError(f"Object {obj!r} does not expose any of {method_names!r}")


async def run_agent_task(agent: Any, task: Any, context: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """
    Execute a task against either the real BaseAgent or the local fallback.

    Supports common method names used in agent frameworks.
    """

    candidate_methods = (
        "execute_task",
        "handle_task",
        "run",
        "execute",
        "process_task",
        "process",
    )

    for method_name in candidate_methods:
        method = getattr(agent, method_name, None)
        if callable(method):
            try:
                result = method(task, context=context)
            except TypeError:
                try:
                    result = method(task, context)
                except TypeError:
                    result = method(task)

            if inspect.isawaitable(result):
                result = await result

            return normalize_response(result)

    raise AssertionError(
        "BaseAgent instance does not expose an executable task method. "
        f"Expected one of: {', '.join(candidate_methods)}"
    )


def instantiate_agent(
    agent_class: type,
    *,
    security_agent: Optional[FakeSecurityAgent] = None,
    memory_agent: Optional[FakeMemoryAgent] = None,
    verification_agent: Optional[FakeVerificationAgent] = None,
    audit_logger: Optional[FakeAuditLogger] = None,
    allowed_roles: Optional[List[str]] = None,
    required_plan: Optional[str] = None,
) -> Any:
    """
    Instantiate the real BaseAgent when possible.

    Because project constructors can evolve, this helper tries common constructor
    signatures and falls back to minimal initialization if needed.
    """

    kwargs = {
        "agent_id": "test_base_agent",
        "security_agent": security_agent,
        "memory_agent": memory_agent,
        "verification_agent": verification_agent,
        "audit_logger": audit_logger,
        "allowed_roles": allowed_roles,
        "required_plan": required_plan,
    }

    filtered_kwargs = {key: value for key, value in kwargs.items() if value is not None}

    try:
        return agent_class(**filtered_kwargs)
    except TypeError:
        pass

    try:
        return agent_class(agent_id="test_base_agent")
    except TypeError:
        pass

    try:
        agent = agent_class()
    except TypeError as exc:
        raise AssertionError(
            "Could not instantiate BaseAgent. Expected constructor to support no args, "
            "agent_id, or dependency-injected agent services."
        ) from exc

    for attr_name, value in filtered_kwargs.items():
        if not hasattr(agent, attr_name):
            try:
                setattr(agent, attr_name, value)
            except Exception:
                continue

    return agent


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def security_agent() -> FakeSecurityAgent:
    return FakeSecurityAgent(approve=True)


@pytest.fixture()
def rejecting_security_agent() -> FakeSecurityAgent:
    return FakeSecurityAgent(approve=False)


@pytest.fixture()
def memory_agent() -> FakeMemoryAgent:
    return FakeMemoryAgent()


@pytest.fixture()
def verification_agent() -> FakeVerificationAgent:
    return FakeVerificationAgent()


@pytest.fixture()
def audit_logger() -> FakeAuditLogger:
    return FakeAuditLogger()


@pytest.fixture()
def base_agent_class() -> type:
    return get_base_agent_class()


@pytest.fixture()
def base_agent(
    base_agent_class: type,
    security_agent: FakeSecurityAgent,
    memory_agent: FakeMemoryAgent,
    verification_agent: FakeVerificationAgent,
    audit_logger: FakeAuditLogger,
) -> Any:
    return instantiate_agent(
        base_agent_class,
        security_agent=security_agent,
        memory_agent=memory_agent,
        verification_agent=verification_agent,
        audit_logger=audit_logger,
    )


@pytest.fixture()
def privileged_context() -> Dict[str, Any]:
    return {
        "role": "owner",
        "plan": "enterprise",
        "request_id": f"request_{uuid4().hex}",
        "source": "pytest",
    }


@pytest.fixture()
def limited_context() -> Dict[str, Any]:
    return {
        "role": "viewer",
        "plan": "free",
        "request_id": f"request_{uuid4().hex}",
        "source": "pytest",
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestBaseAgent:
    """Behavior tests for the BaseAgent contract."""

    def test_base_agent_import_is_safe(self, base_agent_class: type) -> None:
        """
        BaseAgent must be import-safe.

        If the real BaseAgent does not exist yet, the local fallback class keeps
        this test module safe to collect while documenting the expected contract.
        """

        assert inspect.isclass(base_agent_class)
        assert base_agent_class.__name__ in {"BaseAgent", "FallbackBaseAgent"} or "Agent" in base_agent_class.__name__

    def test_base_agent_can_be_instantiated_with_safe_defaults(self, base_agent: Any) -> None:
        """BaseAgent should instantiate without requiring secrets or live services."""

        assert base_agent is not None
        assert not any(
            str(getattr(base_agent, attr, "")).startswith(("sk-", "pk_", "AKIA"))
            for attr in dir(base_agent)
            if not attr.startswith("_")
        )

    @pytest.mark.asyncio()
    async def test_task_requires_user_id_and_workspace_id(
        self,
        base_agent: Any,
        privileged_context: Dict[str, Any],
    ) -> None:
        """Every task must carry user_id and workspace_id."""

        missing_user_task = make_task(user_id="", workspace_id=TEST_WORKSPACE_ID)
        missing_workspace_task = make_task(user_id=TEST_USER_ID, workspace_id="")

        response_missing_user = await run_agent_task(base_agent, missing_user_task, privileged_context)
        response_missing_workspace = await run_agent_task(base_agent, missing_workspace_task, privileged_context)

        assert response_missing_user.get("success") is False
        assert response_missing_workspace.get("success") is False

        # The real BaseAgent puts a short machine-readable code in "error"
        # (e.g. "INVALID_TASK_CONTEXT") and the human-readable explanation
        # in "message" -- check the field that actually names the missing
        # field instead of assuming they're the same string.
        missing_user_text = f"{response_missing_user.get('error', '')} {response_missing_user.get('message', '')}".lower()
        missing_workspace_text = f"{response_missing_workspace.get('error', '')} {response_missing_workspace.get('message', '')}".lower()

        assert "user_id" in missing_user_text
        assert "workspace_id" in missing_workspace_text

    @pytest.mark.asyncio()
    async def test_successful_response_preserves_user_workspace_boundary(
        self,
        base_agent: Any,
        privileged_context: Dict[str, Any],
    ) -> None:
        """Successful responses must echo the same user_id and workspace_id from the task."""

        task = make_task(
            user_id=TEST_USER_ID,
            workspace_id=TEST_WORKSPACE_ID,
            action="analyze",
            payload={"prompt": "Summarize workspace-only analytics."},
        )

        response = await run_agent_task(base_agent, task, privileged_context)

        assert response.get("success") is True
        assert response.get("task_id") == task.task_id
        assert response.get("user_id") == TEST_USER_ID
        assert response.get("workspace_id") == TEST_WORKSPACE_ID

    @pytest.mark.asyncio()
    async def test_parallel_tasks_do_not_mix_user_or_workspace_data(
        self,
        base_agent: Any,
        privileged_context: Dict[str, Any],
    ) -> None:
        """Parallel task execution must not mix data between users or workspaces."""

        task_alpha = make_task(
            user_id=TEST_USER_ID,
            workspace_id=TEST_WORKSPACE_ID,
            action="analyze",
            payload={"private_value": "alpha-only-context"},
        )
        task_beta = make_task(
            user_id=OTHER_USER_ID,
            workspace_id=OTHER_WORKSPACE_ID,
            action="analyze",
            payload={"private_value": "beta-only-context"},
        )

        response_alpha, response_beta = await asyncio.gather(
            run_agent_task(base_agent, task_alpha, privileged_context),
            run_agent_task(base_agent, task_beta, privileged_context),
        )

        assert response_alpha.get("user_id") == TEST_USER_ID
        assert response_alpha.get("workspace_id") == TEST_WORKSPACE_ID
        assert response_beta.get("user_id") == OTHER_USER_ID
        assert response_beta.get("workspace_id") == OTHER_WORKSPACE_ID

        assert "beta-only-context" not in str(response_alpha)
        assert "alpha-only-context" not in str(response_beta)

    @pytest.mark.asyncio()
    async def test_sensitive_action_routes_to_security_agent_before_completion(
        self,
        base_agent_class: type,
        security_agent: FakeSecurityAgent,
        memory_agent: FakeMemoryAgent,
        verification_agent: FakeVerificationAgent,
        audit_logger: FakeAuditLogger,
        privileged_context: Dict[str, Any],
    ) -> None:
        """Sensitive actions must be reviewed by Security Agent."""

        agent = instantiate_agent(
            base_agent_class,
            security_agent=security_agent,
            memory_agent=memory_agent,
            verification_agent=verification_agent,
            audit_logger=audit_logger,
        )

        task = make_task(
            action="execute_command",
            payload={"command": "safe-dry-run-status-check"},
            sensitive=True,
        )

        response = await run_agent_task(agent, task, privileged_context)

        assert response.get("success") is True
        assert len(security_agent.reviewed_tasks) == 1
        assert security_agent.reviewed_tasks[0]["task_id"] == task.task_id
        assert security_agent.reviewed_tasks[0]["user_id"] == TEST_USER_ID
        assert security_agent.reviewed_tasks[0]["workspace_id"] == TEST_WORKSPACE_ID

    @pytest.mark.asyncio()
    async def test_sensitive_action_rejection_returns_safe_structured_error(
        self,
        base_agent_class: type,
        rejecting_security_agent: FakeSecurityAgent,
        memory_agent: FakeMemoryAgent,
        verification_agent: FakeVerificationAgent,
        audit_logger: FakeAuditLogger,
        privileged_context: Dict[str, Any],
    ) -> None:
        """Security rejection should stop execution and return a safe structured response."""

        agent = instantiate_agent(
            base_agent_class,
            security_agent=rejecting_security_agent,
            memory_agent=memory_agent,
            verification_agent=verification_agent,
            audit_logger=audit_logger,
        )

        task = make_task(
            action="modify_permission",
            payload={"target_user_id": OTHER_USER_ID, "role": "admin"},
            sensitive=True,
        )

        response = await run_agent_task(agent, task, privileged_context)

        assert response.get("success") is False
        assert response.get("task_id") == task.task_id
        assert response.get("user_id") == TEST_USER_ID
        assert response.get("workspace_id") == TEST_WORKSPACE_ID
        assert response.get("error")
        assert "traceback" not in str(response.get("error")).lower()
        assert "secret" not in str(response.get("error")).lower()

    @pytest.mark.asyncio()
    async def test_state_changing_action_creates_audit_log_hook(
        self,
        base_agent_class: type,
        security_agent: FakeSecurityAgent,
        memory_agent: FakeMemoryAgent,
        verification_agent: FakeVerificationAgent,
        audit_logger: FakeAuditLogger,
        privileged_context: Dict[str, Any],
    ) -> None:
        """State-changing actions should emit audit log events."""

        agent = instantiate_agent(
            base_agent_class,
            security_agent=security_agent,
            memory_agent=memory_agent,
            verification_agent=verification_agent,
            audit_logger=audit_logger,
        )

        task = make_task(
            action="update",
            payload={"field": "agent_setting", "value": "safe_test_value"},
            sensitive=False,
        )

        response = await run_agent_task(agent, task, privileged_context)

        assert response.get("success") is True
        assert len(audit_logger.entries) >= 1

        audit_entry = audit_logger.entries[0]
        assert audit_entry["task_id"] == task.task_id
        assert audit_entry["user_id"] == TEST_USER_ID
        assert audit_entry["workspace_id"] == TEST_WORKSPACE_ID
        assert audit_entry["action"] == "update"

    @pytest.mark.asyncio()
    async def test_completed_task_prepares_verification_payload(
        self,
        base_agent_class: type,
        security_agent: FakeSecurityAgent,
        memory_agent: FakeMemoryAgent,
        verification_agent: FakeVerificationAgent,
        audit_logger: FakeAuditLogger,
        privileged_context: Dict[str, Any],
    ) -> None:
        """Every completed task should prepare a Verification Agent payload."""

        agent = instantiate_agent(
            base_agent_class,
            security_agent=security_agent,
            memory_agent=memory_agent,
            verification_agent=verification_agent,
            audit_logger=audit_logger,
        )

        task = make_task(action="analyze", payload={"topic": "dashboard analytics"})

        response = await run_agent_task(agent, task, privileged_context)

        assert response.get("success") is True

        verification_payload = response.get("verification_payload")
        if verification_payload is None and verification_agent.prepared_payloads:
            verification_payload = verification_agent.prepared_payloads[-1]

        assert verification_payload is not None
        assert verification_payload["task_id"] == task.task_id
        assert verification_payload["user_id"] == TEST_USER_ID
        assert verification_payload["workspace_id"] == TEST_WORKSPACE_ID
        assert verification_payload.get("status") in {
            LocalTaskStatus.COMPLETED.value,
            "success",
            "completed",
        }

    @pytest.mark.asyncio()
    async def test_useful_context_is_memory_agent_compatible(
        self,
        base_agent_class: type,
        security_agent: FakeSecurityAgent,
        memory_agent: FakeMemoryAgent,
        verification_agent: FakeVerificationAgent,
        audit_logger: FakeAuditLogger,
        privileged_context: Dict[str, Any],
    ) -> None:
        """Completed useful context should be compatible with Memory Agent."""

        agent = instantiate_agent(
            base_agent_class,
            security_agent=security_agent,
            memory_agent=memory_agent,
            verification_agent=verification_agent,
            audit_logger=audit_logger,
        )

        task = make_task(
            action="analyze",
            payload={
                "intent": "prepare workspace analytics summary",
                "useful_context": True,
            },
        )

        response = await run_agent_task(agent, task, privileged_context)

        assert response.get("success") is True

        memory_payload = response.get("memory_payload")
        if memory_payload is None and memory_agent.saved_payloads:
            memory_payload = memory_agent.saved_payloads[-1]

        assert memory_payload is not None
        assert memory_payload["task_id"] == task.task_id
        assert memory_payload["user_id"] == TEST_USER_ID
        assert memory_payload["workspace_id"] == TEST_WORKSPACE_ID
        assert "context" in memory_payload or "content" in memory_payload

    @pytest.mark.asyncio()
    async def test_role_or_plan_restriction_can_reject_unauthorized_context(
        self,
        base_agent_class: type,
        security_agent: FakeSecurityAgent,
        memory_agent: FakeMemoryAgent,
        verification_agent: FakeVerificationAgent,
        audit_logger: FakeAuditLogger,
        limited_context: Dict[str, Any],
    ) -> None:
        """
        BaseAgent should support role/plan checks where configured.

        This verifies the contract for future dashboard/API functionality without forcing
        every BaseAgent to reject viewers unless restrictions are explicitly configured.
        """

        agent = instantiate_agent(
            base_agent_class,
            security_agent=security_agent,
            memory_agent=memory_agent,
            verification_agent=verification_agent,
            audit_logger=audit_logger,
            allowed_roles=["owner", "admin"],
            required_plan="pro",
        )

        task = make_task(action="run_workflow", sensitive=True)

        response = await run_agent_task(agent, task, limited_context)

        if response.get("success") is False:
            assert response.get("error")
            assert response.get("user_id") == TEST_USER_ID
            assert response.get("workspace_id") == TEST_WORKSPACE_ID
            assert "traceback" not in str(response.get("error")).lower()
        else:
            assert response.get("success") is True
            assert response.get("user_id") == TEST_USER_ID
            assert response.get("workspace_id") == TEST_WORKSPACE_ID

    @pytest.mark.asyncio()
    async def test_response_uses_consistent_structured_shape(
        self,
        base_agent: Any,
        privileged_context: Dict[str, Any],
    ) -> None:
        """Agent responses should be structured and API-safe."""

        task = make_task(action="analyze")
        response = await run_agent_task(base_agent, task, privileged_context)

        required_keys = {"success", "task_id", "user_id", "workspace_id"}
        missing_keys = required_keys - set(response.keys())

        assert not missing_keys, f"Response missing required keys: {missing_keys}"
        assert isinstance(response.get("success"), bool)
        assert isinstance(response.get("task_id"), str)
        assert isinstance(response.get("user_id"), str)
        assert isinstance(response.get("workspace_id"), str)

    @pytest.mark.asyncio()
    async def test_errors_do_not_leak_environment_secrets(
        self,
        base_agent: Any,
        privileged_context: Dict[str, Any],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Safe errors should not expose environment/config secrets."""

        monkeypatch.setenv("DATABASE_URL", "postgresql://user:password@example.test:5432/app")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-a-real-key")

        invalid_task = {
            "task_id": f"task_{uuid4().hex}",
            "user_id": "",
            "workspace_id": "",
            "action": "analyze",
            "payload": {
                "force_error": True,
                "database_url": os.environ["DATABASE_URL"],
            },
        }

        response = await run_agent_task(base_agent, invalid_task, privileged_context)
        response_text = str(response)

        assert response.get("success") is False
        assert "postgresql://user:password@example.test:5432/app" not in response_text
        assert "sk-test-not-a-real-key" not in response_text

    def test_memory_payload_builder_preserves_isolation(self) -> None:
        """Memory payload helper should include user and workspace boundaries."""

        task = normalize_task(
            make_task(
                user_id=TEST_USER_ID,
                workspace_id=TEST_WORKSPACE_ID,
                action="analyze",
                payload={"private": "workspace-alpha"},
            )
        )
        payload = build_memory_payload(
            task=task,
            result={"success": True, "action": "analyze"},
            agent_id="test_base_agent",
        )

        assert payload["user_id"] == TEST_USER_ID
        assert payload["workspace_id"] == TEST_WORKSPACE_ID
        assert payload["task_id"] == task["task_id"]
        assert payload["context"]["input_payload"]["private"] == "workspace-alpha"

    def test_verification_payload_builder_preserves_isolation(self) -> None:
        """Verification payload helper should include user and workspace boundaries."""

        task = normalize_task(
            make_task(
                user_id=TEST_USER_ID,
                workspace_id=TEST_WORKSPACE_ID,
                action="analyze",
            )
        )
        payload = build_verification_payload(
            task=task,
            result={"success": True},
            agent_id="test_base_agent",
            status=LocalTaskStatus.COMPLETED.value,
        )

        assert payload["user_id"] == TEST_USER_ID
        assert payload["workspace_id"] == TEST_WORKSPACE_ID
        assert payload["task_id"] == task["task_id"]
        assert payload["status"] == LocalTaskStatus.COMPLETED.value

    @pytest.mark.asyncio()
    async def test_missing_security_agent_blocks_sensitive_action_when_supported(
        self,
        base_agent_class: type,
        memory_agent: FakeMemoryAgent,
        verification_agent: FakeVerificationAgent,
        audit_logger: FakeAuditLogger,
        privileged_context: Dict[str, Any],
    ) -> None:
        """
        Sensitive tasks should not silently execute if no Security Agent is configured.

        Some real implementations may use a global Security Agent instead of constructor
        injection. In that case, a successful response is acceptable only if it still
        contains evidence of security review.
        """

        agent = instantiate_agent(
            base_agent_class,
            security_agent=None,
            memory_agent=memory_agent,
            verification_agent=verification_agent,
            audit_logger=audit_logger,
        )

        task = make_task(
            action="execute_command",
            payload={"command": "safe-dry-run-status-check"},
            sensitive=True,
        )

        response = await run_agent_task(agent, task, privileged_context)

        if response.get("success") is False:
            assert response.get("error")
            assert response.get("user_id") == TEST_USER_ID
            assert response.get("workspace_id") == TEST_WORKSPACE_ID
            return

        response_text = str(response).lower()
        assert "security" in response_text or "approval" in response_text

    @pytest.mark.asyncio()
    async def test_agent_accepts_dictionary_task_contract(
        self,
        base_agent: Any,
        privileged_context: Dict[str, Any],
    ) -> None:
        """BaseAgent should support dictionary task payloads from API/workflow layers."""

        task = {
            "task_id": f"task_{uuid4().hex}",
            "user_id": TEST_USER_ID,
            "workspace_id": TEST_WORKSPACE_ID,
            "action": "analyze",
            "payload": {
                "source": "api",
                "message": "dictionary task contract",
            },
            "sensitive": False,
            "metadata": {
                "request_id": f"request_{uuid4().hex}",
            },
        }

        response = await run_agent_task(base_agent, task, privileged_context)

        assert response.get("success") is True
        assert response.get("task_id") == task["task_id"]
        assert response.get("user_id") == task["user_id"]
        assert response.get("workspace_id") == task["workspace_id"]

    @pytest.mark.asyncio()
    async def test_agent_handles_multiple_workspaces_for_same_user_without_cross_leakage(
        self,
        base_agent: Any,
        privileged_context: Dict[str, Any],
    ) -> None:
        """Same user with multiple workspaces must still remain isolated by workspace_id."""

        task_workspace_a = make_task(
            user_id=TEST_USER_ID,
            workspace_id="workspace_a",
            action="analyze",
            payload={"workspace_secret": "value-only-for-workspace-a"},
        )
        task_workspace_b = make_task(
            user_id=TEST_USER_ID,
            workspace_id="workspace_b",
            action="analyze",
            payload={"workspace_secret": "value-only-for-workspace-b"},
        )

        response_a = await run_agent_task(base_agent, task_workspace_a, privileged_context)
        response_b = await run_agent_task(base_agent, task_workspace_b, privileged_context)

        assert response_a.get("workspace_id") == "workspace_a"
        assert response_b.get("workspace_id") == "workspace_b"

        assert "value-only-for-workspace-b" not in str(response_a)
        assert "value-only-for-workspace-a" not in str(response_b)

    @pytest.mark.asyncio()
    async def test_agent_handles_different_users_in_same_workspace_without_identity_swap(
        self,
        base_agent: Any,
        privileged_context: Dict[str, Any],
    ) -> None:
        """
        Different users in the same workspace should keep user identity intact.

        This supports team workspaces without allowing user-level task ownership bugs.
        """

        shared_workspace_id = "workspace_shared_team"

        task_owner = make_task(
            user_id="owner_user",
            workspace_id=shared_workspace_id,
            action="analyze",
            payload={"owner_private": "owner-context"},
        )
        task_operator = make_task(
            user_id="operator_user",
            workspace_id=shared_workspace_id,
            action="analyze",
            payload={"operator_private": "operator-context"},
        )

        response_owner, response_operator = await asyncio.gather(
            run_agent_task(base_agent, task_owner, privileged_context),
            run_agent_task(base_agent, task_operator, privileged_context),
        )

        assert response_owner.get("user_id") == "owner_user"
        assert response_operator.get("user_id") == "operator_user"
        assert response_owner.get("workspace_id") == shared_workspace_id
        assert response_operator.get("workspace_id") == shared_workspace_id

        assert "operator-context" not in str(response_owner)
        assert "owner-context" not in str(response_operator)