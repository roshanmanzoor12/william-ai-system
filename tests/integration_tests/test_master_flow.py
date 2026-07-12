"""
tests/integration_tests/test_master_flow.py

Integration tests for William / Jarvis Multi-Agent AI SaaS System by Digital Promotix.

Purpose:
- Validate request -> planner -> security -> agent -> verification flow.
- Assert every task carries user_id and workspace_id.
- Assert workspace/user isolation.
- Assert role, plan, subscription, and agent access behavior.
- Assert sensitive actions route through Security Agent.
- Assert completed actions create Verification Agent payloads.
- Assert useful execution context is compatible with Memory Agent.
- Import safely even when future production modules are not created yet.

These tests primarily use fixtures from tests/conftest.py.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Mapping, Optional

import pytest


try:
    from tests.conftest import (
        AgentName,
        FakeMasterAgent,
        FakeMemoryAgent,
        FakeSecurityAgent,
        FakeVerificationAgent,
        Plan,
        Role,
        TestAuthContext,
        TestStore,
        assert_no_cross_workspace_records,
        assert_payload_has_isolation,
        error_response,
        new_id,
        permissions_for_role,
        success_response,
    )
except Exception:  # pragma: no cover
    # Fallback copies keep this file import-safe if conftest is not loaded directly
    # by an external test collector. The real pytest run should use conftest.py.
    def new_id(prefix: str) -> str:
        import uuid

        return f"{prefix}_{uuid.uuid4().hex}"

    def success_response(data: Any = None) -> Dict[str, Any]:
        return {"success": True, "data": data if data is not None else {}, "error": None}

    def error_response(
        code: str,
        message: str,
        status_code: int = 400,
        details: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
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
    class TestAuthContext:
        user_id: str
        workspace_id: str
        role: Role
        plan: Plan
        permissions: frozenset[str]
        request_id: str = field(default_factory=lambda: new_id("req"))

    def permissions_for_role(role: Role) -> frozenset[str]:
        if role == Role.OWNER:
            return frozenset(
                {
                    "tasks:read",
                    "tasks:write",
                    "agents:read",
                    "agents:run",
                    "agents:configure",
                    "memory:read",
                    "memory:write",
                    "security:approve",
                    "audit:read",
                    "billing:read",
                    "billing:write",
                }
            )
        if role == Role.ADMIN:
            return frozenset(
                {
                    "tasks:read",
                    "tasks:write",
                    "agents:read",
                    "agents:run",
                    "agents:configure",
                    "memory:read",
                    "memory:write",
                    "audit:read",
                }
            )
        if role == Role.MEMBER:
            return frozenset(
                {
                    "tasks:read",
                    "tasks:write",
                    "agents:read",
                    "agents:run",
                    "memory:read",
                    "memory:write",
                }
            )
        return frozenset({"tasks:read", "agents:read", "memory:read"})

    class TestStore:  # type: ignore[no-redef]
        pass

    class FakeSecurityAgent:  # type: ignore[no-redef]
        pass

    class FakeMemoryAgent:  # type: ignore[no-redef]
        pass

    class FakeVerificationAgent:  # type: ignore[no-redef]
        pass

    class FakeMasterAgent:  # type: ignore[no-redef]
        pass

    def assert_payload_has_isolation(payload: Mapping[str, Any]) -> None:
        assert payload.get("user_id")
        assert payload.get("workspace_id")

    def assert_no_cross_workspace_records(
        records: Any,
        *,
        expected_user_id: str,
        expected_workspace_id: str,
    ) -> None:
        for record in records:
            assert record.get("user_id") == expected_user_id
            assert record.get("workspace_id") == expected_workspace_id


pytestmark = [
    pytest.mark.integration,
    pytest.mark.agents,
    pytest.mark.security,
    pytest.mark.verification,
    pytest.mark.isolation,
]


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


@dataclass(frozen=True)
class PlannerStep:
    """A single planner step in the Master Agent flow."""

    step_id: str
    agent_name: str
    action: str
    requires_security: bool
    requires_memory: bool
    requires_verification: bool
    payload: Dict[str, Any]


class DeterministicPlanner:
    """
    Minimal deterministic planner for integration tests.

    This planner is intentionally small and predictable:
    - every plan preserves user_id and workspace_id
    - sensitive actions are marked for security routing
    - useful context is marked for Memory Agent compatibility
    - completed action is marked for Verification Agent payload
    """

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

    def create_plan(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        assert_payload_has_isolation(request)

        action = str(request.get("action") or "")
        agent_name = str(request.get("agent_name") or AgentName.MASTER.value)

        if not action:
            return error_response(
                code="INVALID_REQUEST",
                message="Task request must include an action.",
                status_code=422,
            )

        if not agent_name:
            return error_response(
                code="INVALID_REQUEST",
                message="Task request must include an agent_name.",
                status_code=422,
            )

        step = PlannerStep(
            step_id=new_id("plan_step"),
            agent_name=agent_name,
            action=action,
            requires_security=action in self.sensitive_actions,
            requires_memory=bool(request.get("remember_context", True)),
            requires_verification=True,
            payload={
                "task_id": request.get("task_id") or new_id("task"),
                "user_id": request["user_id"],
                "workspace_id": request["workspace_id"],
                "input": dict(request.get("input") or {}),
                "metadata": {
                    **dict(request.get("metadata") or {}),
                    "planned_at": _utc_now_iso(),
                    "planner": "deterministic_test_planner",
                },
            },
        )

        return success_response(
            {
                "plan_id": new_id("plan"),
                "user_id": request["user_id"],
                "workspace_id": request["workspace_id"],
                "steps": [
                    {
                        "step_id": step.step_id,
                        "agent_name": step.agent_name,
                        "action": step.action,
                        "requires_security": step.requires_security,
                        "requires_memory": step.requires_memory,
                        "requires_verification": step.requires_verification,
                        "payload": step.payload,
                    }
                ],
            }
        )


class FlowHarness:
    """
    Test harness for request -> planner -> security -> agent -> verification.

    The harness delegates actual agent execution to the FakeMasterAgent from conftest.py
    when available. It keeps the test focused on the full integration flow rather than
    on implementation-specific production classes.
    """

    def __init__(
        self,
        *,
        planner: DeterministicPlanner,
        master_agent: Any,
        memory_agent: Any,
        store: Any,
    ) -> None:
        self.planner = planner
        self.master_agent = master_agent
        self.memory_agent = memory_agent
        self.store = store

    async def execute(self, *, context: TestAuthContext, request: Mapping[str, Any]) -> Dict[str, Any]:
        if request.get("user_id") != context.user_id:
            return error_response(
                code="USER_CONTEXT_MISMATCH",
                message="Request user_id does not match authenticated context.",
                status_code=403,
                details={
                    "request_user_id": request.get("user_id"),
                    "context_user_id": context.user_id,
                },
            )

        if request.get("workspace_id") != context.workspace_id:
            return error_response(
                code="WORKSPACE_CONTEXT_MISMATCH",
                message="Request workspace_id does not match authenticated context.",
                status_code=403,
                details={
                    "request_workspace_id": request.get("workspace_id"),
                    "context_workspace_id": context.workspace_id,
                },
            )

        plan_result = self.planner.create_plan(request)
        if not plan_result["success"]:
            return plan_result

        plan = plan_result["data"]
        steps = plan["steps"]

        if not steps:
            return error_response(
                code="EMPTY_PLAN",
                message="Planner returned no executable steps.",
                status_code=422,
            )

        step = steps[0]
        step_payload = step["payload"]

        assert_payload_has_isolation(step_payload)

        if hasattr(self.store, "assert_isolated"):
            self.store.assert_isolated(
                user_id=step_payload["user_id"],
                workspace_id=step_payload["workspace_id"],
            )

        # Authorize and execute the actual requested task before doing any
        # supporting work like preparing memory context -- checking
        # memory:write first meant a caller who lacked both tasks:write and
        # memory:write always failed on the unrelated memory permission
        # instead of the permission for the action they actually asked for.
        execution_result = await _maybe_await(
            self.master_agent.run_task(
                context=context,
                agent_name=step["agent_name"],
                action=step["action"],
                payload=step_payload,
            )
        )

        if not execution_result["success"]:
            return execution_result

        memory_result: Optional[Dict[str, Any]] = None
        if step.get("requires_memory") and self.memory_agent is not None:
            memory_result = await _maybe_await(
                self.memory_agent.remember(
                    context=context,
                    key=f"task_context:{step_payload['task_id']}",
                    value={
                        "plan_id": plan["plan_id"],
                        "step_id": step["step_id"],
                        "agent_name": step["agent_name"],
                        "action": step["action"],
                        "input_keys": sorted(list(step_payload.get("input", {}).keys())),
                    },
                )
            )

            if not memory_result["success"]:
                return memory_result

        response_data = {
            "request_id": context.request_id,
            "plan": plan,
            "memory": memory_result["data"] if memory_result else None,
            "execution": execution_result["data"],
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
        }

        assert_payload_has_isolation(response_data)

        return success_response(response_data)


@pytest.fixture
def deterministic_planner() -> DeterministicPlanner:
    return DeterministicPlanner()


@pytest.fixture
def flow_harness(
    deterministic_planner: DeterministicPlanner,
    master_agent: FakeMasterAgent,
    memory_agent: FakeMemoryAgent,
    test_store: TestStore,
) -> FlowHarness:
    return FlowHarness(
        planner=deterministic_planner,
        master_agent=master_agent,
        memory_agent=memory_agent,
        store=test_store,
    )


class TestMasterFlow:
    """Integration tests for the William/Jarvis Master Agent execution flow."""

    @pytest.mark.asyncio
    async def test_request_planner_security_agent_verification_success_flow(
        self,
        flow_harness: FlowHarness,
        owner_context: TestAuthContext,
        task_payload: Dict[str, Any],
        assert_success: Any,
        assert_audit_logged: Any,
        assert_verification_created: Any,
    ) -> None:
        task_payload["agent_name"] = AgentName.CODE.value
        task_payload["action"] = "code.generate_file"
        task_payload["remember_context"] = True

        result = await flow_harness.execute(
            context=owner_context,
            request=task_payload,
        )

        assert_success(result)

        data = result["data"]
        assert data["user_id"] == owner_context.user_id
        assert data["workspace_id"] == owner_context.workspace_id

        plan = data["plan"]
        assert plan["user_id"] == owner_context.user_id
        assert plan["workspace_id"] == owner_context.workspace_id
        assert len(plan["steps"]) == 1

        step = plan["steps"][0]
        assert step["agent_name"] == AgentName.CODE.value
        assert step["action"] == "code.generate_file"
        assert step["requires_security"] is False
        assert step["requires_memory"] is True
        assert step["requires_verification"] is True
        assert step["payload"]["user_id"] == owner_context.user_id
        assert step["payload"]["workspace_id"] == owner_context.workspace_id

        execution = data["execution"]
        assert execution["agent_name"] == AgentName.CODE.value
        assert execution["action"] == "code.generate_file"
        assert execution["user_id"] == owner_context.user_id
        assert execution["workspace_id"] == owner_context.workspace_id
        assert execution["security"]["approved"] is True
        assert execution["verification"]["status"] == "completed"

        memory = data["memory"]
        assert memory is not None
        assert memory["user_id"] == owner_context.user_id
        assert memory["workspace_id"] == owner_context.workspace_id
        assert memory["key"].startswith("task_context:")

        assert_audit_logged(owner_context.user_id, owner_context.workspace_id, "code.generate_file")
        assert_verification_created(owner_context.user_id, owner_context.workspace_id, "code.generate_file")

    @pytest.mark.asyncio
    async def test_sensitive_action_routes_through_security_agent_and_is_approved_for_owner(
        self,
        flow_harness: FlowHarness,
        owner_context: TestAuthContext,
        sensitive_task_payload: Dict[str, Any],
        assert_success: Any,
        assert_audit_logged: Any,
        assert_verification_created: Any,
    ) -> None:
        sensitive_task_payload["agent_name"] = AgentName.SYSTEM.value
        sensitive_task_payload["action"] = "system.open_app"
        sensitive_task_payload["remember_context"] = True

        result = await flow_harness.execute(
            context=owner_context,
            request=sensitive_task_payload,
        )

        assert_success(result)

        data = result["data"]
        step = data["plan"]["steps"][0]
        execution = data["execution"]

        assert step["requires_security"] is True
        assert execution["security"]["approved"] is True
        assert execution["security"]["risk_level"] == "high"
        assert execution["verification"]["status"] == "completed"

        assert_audit_logged(owner_context.user_id, owner_context.workspace_id, "system.open_app")
        assert_verification_created(owner_context.user_id, owner_context.workspace_id, "system.open_app")

    @pytest.mark.asyncio
    async def test_sensitive_action_is_denied_for_member_without_security_approval(
        self,
        flow_harness: FlowHarness,
        member_context: TestAuthContext,
    ) -> None:
        request = {
            "task_id": new_id("task"),
            "user_id": member_context.user_id,
            "workspace_id": member_context.workspace_id,
            "agent_name": AgentName.SYSTEM.value,
            "action": "system.open_app",
            "input": {
                "app_name": "calculator",
                "dry_run": True,
            },
            "remember_context": True,
        }

        result = await flow_harness.execute(
            context=member_context,
            request=request,
        )

        assert result["success"] is False
        assert result["error"]["code"] == "SECURITY_APPROVAL_REQUIRED"
        assert result["error"]["status_code"] == 403
        assert result["error"]["details"]["action"] == "system.open_app"
        assert result["error"]["details"]["workspace_id"] == member_context.workspace_id

    @pytest.mark.asyncio
    async def test_viewer_cannot_execute_agent_task(
        self,
        flow_harness: FlowHarness,
        viewer_context: TestAuthContext,
    ) -> None:
        request = {
            "task_id": new_id("task"),
            "user_id": viewer_context.user_id,
            "workspace_id": viewer_context.workspace_id,
            "agent_name": AgentName.CODE.value,
            "action": "code.review_file",
            "input": {
                "file_path": "apps/api/main.py",
                "review_type": "security",
            },
            "remember_context": True,
        }

        with pytest.raises(PermissionError, match="tasks:write"):
            await flow_harness.execute(
                context=viewer_context,
                request=request,
            )

    @pytest.mark.asyncio
    async def test_request_user_id_must_match_authenticated_context(
        self,
        flow_harness: FlowHarness,
        owner_context: TestAuthContext,
        member_user: Any,
    ) -> None:
        request = {
            "task_id": new_id("task"),
            "user_id": member_user.user_id,
            "workspace_id": owner_context.workspace_id,
            "agent_name": AgentName.CODE.value,
            "action": "code.generate_file",
            "input": {"file_path": "unsafe_mix.py"},
            "remember_context": True,
        }

        result = await flow_harness.execute(
            context=owner_context,
            request=request,
        )

        assert result["success"] is False
        assert result["error"]["code"] == "USER_CONTEXT_MISMATCH"
        assert result["error"]["status_code"] == 403

    @pytest.mark.asyncio
    async def test_request_workspace_id_must_match_authenticated_context(
        self,
        flow_harness: FlowHarness,
        owner_context: TestAuthContext,
        second_workspace: Any,
    ) -> None:
        request = {
            "task_id": new_id("task"),
            "user_id": owner_context.user_id,
            "workspace_id": second_workspace.workspace_id,
            "agent_name": AgentName.CODE.value,
            "action": "code.generate_file",
            "input": {"file_path": "unsafe_workspace_mix.py"},
            "remember_context": True,
        }

        result = await flow_harness.execute(
            context=owner_context,
            request=request,
        )

        assert result["success"] is False
        assert result["error"]["code"] == "WORKSPACE_CONTEXT_MISMATCH"
        assert result["error"]["status_code"] == 403

    @pytest.mark.asyncio
    async def test_cross_workspace_payload_is_rejected_before_agent_execution(
        self,
        flow_harness: FlowHarness,
        member_context: TestAuthContext,
        invalid_cross_workspace_payload: Dict[str, Any],
    ) -> None:
        invalid_cross_workspace_payload["user_id"] = member_context.user_id

        result = await flow_harness.execute(
            context=member_context,
            request=invalid_cross_workspace_payload,
        )

        assert result["success"] is False
        assert result["error"]["code"] == "WORKSPACE_CONTEXT_MISMATCH"
        assert result["error"]["status_code"] == 403

    @pytest.mark.asyncio
    async def test_memory_recall_returns_only_current_user_workspace_context(
        self,
        flow_harness: FlowHarness,
        memory_agent: FakeMemoryAgent,
        owner_context: TestAuthContext,
        second_workspace_context: TestAuthContext,
        test_store: TestStore,
        limited_agent_registry: Dict[str, str],
    ) -> None:
        owner_request = {
            "task_id": new_id("task"),
            "user_id": owner_context.user_id,
            "workspace_id": owner_context.workspace_id,
            "agent_name": AgentName.MEMORY.value,
            "action": "memory.write",
            "input": {"key": "owner-context", "value": "private-owner-data"},
            "remember_context": True,
        }

        owner_result = await flow_harness.execute(
            context=owner_context,
            request=owner_request,
        )

        assert owner_result["success"] is True

        test_store.add_memory(
            user_id=second_workspace_context.user_id,
            workspace_id=second_workspace_context.workspace_id,
            key="other-workspace-context",
            value={"value": "private-other-workspace-data"},
        )

        recall = await memory_agent.recall(context=owner_context)

        assert recall["success"] is True
        assert recall["data"]

        assert_no_cross_workspace_records(
            recall["data"],
            expected_user_id=owner_context.user_id,
            expected_workspace_id=owner_context.workspace_id,
        )

        leaked_values = [
            item
            for item in recall["data"]
            if item.get("value", {}).get("value") == "private-other-workspace-data"
        ]
        assert leaked_values == []

    @pytest.mark.asyncio
    async def test_unavailable_agent_access_is_denied_by_workspace_registry(
        self,
        master_agent: FakeMasterAgent,
        second_workspace_context: TestAuthContext,
        limited_agent_registry: Dict[str, str],
    ) -> None:
        result = await master_agent.run_task(
            context=second_workspace_context,
            agent_name=AgentName.CODE.value,
            action="code.generate_file",
            payload={
                "task_id": new_id("task"),
                "user_id": second_workspace_context.user_id,
                "workspace_id": second_workspace_context.workspace_id,
                "input": {"file_path": "blocked.py"},
            },
        )

        assert result["success"] is False
        assert result["error"]["code"] == "AGENT_ACCESS_DENIED"
        assert result["error"]["status_code"] == 403
        assert result["error"]["details"]["agent_name"] == AgentName.CODE.value
        assert result["error"]["details"]["workspace_id"] == second_workspace_context.workspace_id

    @pytest.mark.asyncio
    async def test_free_plan_denies_sensitive_action_even_for_workspace_owner(
        self,
        master_agent: FakeMasterAgent,
        second_workspace_context: TestAuthContext,
        limited_agent_registry: Dict[str, str],
    ) -> None:
        result = await master_agent.run_task(
            context=second_workspace_context,
            agent_name=AgentName.SYSTEM.value,
            action="system.open_app",
            payload={
                "task_id": new_id("task"),
                "user_id": second_workspace_context.user_id,
                "workspace_id": second_workspace_context.workspace_id,
                "input": {"app_name": "notepad", "dry_run": True},
            },
        )

        assert result["success"] is False or isinstance(result, dict)

        if result["success"] is False:
            assert result["error"]["code"] in {
                "AGENT_ACCESS_DENIED",
                "SECURITY_APPROVAL_REQUIRED",
                "PLAN_DENIED",
            }
        else:
            pytest.fail("Free plan sensitive action should not complete successfully.")

    @pytest.mark.asyncio
    async def test_planner_rejects_task_without_action(
        self,
        flow_harness: FlowHarness,
        owner_context: TestAuthContext,
    ) -> None:
        request = {
            "task_id": new_id("task"),
            "user_id": owner_context.user_id,
            "workspace_id": owner_context.workspace_id,
            "agent_name": AgentName.CODE.value,
            "input": {"file_path": "missing_action.py"},
            "remember_context": True,
        }

        result = await flow_harness.execute(
            context=owner_context,
            request=request,
        )

        assert result["success"] is False
        assert result["error"]["code"] == "INVALID_REQUEST"
        assert result["error"]["status_code"] == 422

    @pytest.mark.asyncio
    async def test_every_completed_flow_has_audit_security_and_verification_records(
        self,
        flow_harness: FlowHarness,
        owner_context: TestAuthContext,
        test_store: TestStore,
    ) -> None:
        request = {
            "task_id": new_id("task"),
            "user_id": owner_context.user_id,
            "workspace_id": owner_context.workspace_id,
            "agent_name": AgentName.BUSINESS.value,
            "action": "business.generate_strategy",
            "input": {
                "company": "Digital Promotix",
                "goal": "Build SaaS-ready multi-agent platform",
            },
            "remember_context": True,
            "metadata": {
                "source": "integration_test",
                "requires_verification": True,
            },
        }

        result = await flow_harness.execute(
            context=owner_context,
            request=request,
        )

        assert result["success"] is True

        security_events = [
            event
            for event in test_store.audit_events
            if event.event_type == "security_evaluation"
            and event.user_id == owner_context.user_id
            and event.workspace_id == owner_context.workspace_id
            and event.action == "business.generate_strategy"
        ]

        execution_events = [
            event
            for event in test_store.audit_events
            if event.event_type == "task_execution"
            and event.user_id == owner_context.user_id
            and event.workspace_id == owner_context.workspace_id
            and event.action == "business.generate_strategy"
        ]

        verification_events = [
            verification
            for verification in test_store.verifications
            if verification.user_id == owner_context.user_id
            and verification.workspace_id == owner_context.workspace_id
            and verification.action == "business.generate_strategy"
            and verification.status == "completed"
        ]

        assert security_events, "Expected Security Agent audit event."
        assert execution_events, "Expected task execution audit event."
        assert verification_events, "Expected Verification Agent payload."

        latest_verification = verification_events[-1]
        assert latest_verification.evidence["agent_name"] == AgentName.BUSINESS.value
        assert latest_verification.evidence["security"]["approved"] is True

    @pytest.mark.asyncio
    async def test_parallel_workspace_flows_do_not_mix_results(
        self,
        flow_harness: FlowHarness,
        master_agent: FakeMasterAgent,
        memory_agent: FakeMemoryAgent,
        deterministic_planner: DeterministicPlanner,
        owner_context: TestAuthContext,
        second_workspace_context: TestAuthContext,
        test_store: TestStore,
        limited_agent_registry: Dict[str, str],
    ) -> None:
        second_harness = FlowHarness(
            planner=deterministic_planner,
            master_agent=master_agent,
            memory_agent=memory_agent,
            store=test_store,
        )

        owner_request = {
            "task_id": new_id("task"),
            "user_id": owner_context.user_id,
            "workspace_id": owner_context.workspace_id,
            "agent_name": AgentName.MEMORY.value,
            "action": "memory.write",
            "input": {"key": "owner-parallel"},
            "remember_context": True,
        }

        second_request = {
            "task_id": new_id("task"),
            "user_id": second_workspace_context.user_id,
            "workspace_id": second_workspace_context.workspace_id,
            "agent_name": AgentName.MEMORY.value,
            "action": "memory.write",
            "input": {"key": "second-parallel"},
            "remember_context": True,
        }

        owner_result, second_result = await asyncio.gather(
            flow_harness.execute(context=owner_context, request=owner_request),
            second_harness.execute(context=second_workspace_context, request=second_request),
        )

        assert owner_result["success"] is True
        assert second_result["success"] is True

        owner_recall = await memory_agent.recall(context=owner_context)
        second_recall = await memory_agent.recall(context=second_workspace_context)

        assert owner_recall["success"] is True
        assert second_recall["success"] is True

        assert_no_cross_workspace_records(
            owner_recall["data"],
            expected_user_id=owner_context.user_id,
            expected_workspace_id=owner_context.workspace_id,
        )

        assert_no_cross_workspace_records(
            second_recall["data"],
            expected_user_id=second_workspace_context.user_id,
            expected_workspace_id=second_workspace_context.workspace_id,
        )

        owner_memory_ids = {item["memory_id"] for item in owner_recall["data"]}
        second_memory_ids = {item["memory_id"] for item in second_recall["data"]}

        assert owner_memory_ids.isdisjoint(second_memory_ids)

    @pytest.mark.asyncio
    async def test_structured_error_shape_for_context_mismatch(
        self,
        flow_harness: FlowHarness,
        owner_context: TestAuthContext,
        outsider_user: Any,
    ) -> None:
        request = {
            "task_id": new_id("task"),
            "user_id": outsider_user.user_id,
            "workspace_id": owner_context.workspace_id,
            "agent_name": AgentName.CODE.value,
            "action": "code.generate_file",
            "input": {"file_path": "blocked.py"},
        }

        result = await flow_harness.execute(context=owner_context, request=request)

        assert result["success"] is False
        assert result["data"] is None
        assert isinstance(result["error"], dict)
        assert result["error"]["code"] == "USER_CONTEXT_MISMATCH"
        assert result["error"]["message"]
        assert result["error"]["status_code"] == 403
        assert "details" in result["error"]

    @pytest.mark.asyncio
    async def test_flow_output_is_ready_for_dashboard_analytics(
        self,
        flow_harness: FlowHarness,
        owner_context: TestAuthContext,
    ) -> None:
        request = {
            "task_id": new_id("task"),
            "user_id": owner_context.user_id,
            "workspace_id": owner_context.workspace_id,
            "agent_name": AgentName.FINANCE.value,
            "action": "finance.prepare_report",
            "input": {
                "period": "month_to_date",
                "include_usage": True,
            },
            "remember_context": True,
            "metadata": {
                "dashboard_widget": "finance_summary",
                "analytics_enabled": True,
            },
        }

        result = await flow_harness.execute(context=owner_context, request=request)

        assert result["success"] is True

        data = result["data"]
        execution = data["execution"]

        assert data["request_id"] == owner_context.request_id
        assert data["user_id"] == owner_context.user_id
        assert data["workspace_id"] == owner_context.workspace_id
        assert execution["task_id"]
        assert execution["agent_name"] == AgentName.FINANCE.value
        assert execution["verification"]["verification_id"]
        assert execution["verification"]["user_id"] == owner_context.user_id
        assert execution["verification"]["workspace_id"] == owner_context.workspace_id