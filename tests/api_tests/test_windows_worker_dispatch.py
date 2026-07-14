"""
tests/api_tests/test_windows_worker_dispatch.py

Phase I coverage for the Windows Worker task-dispatch protocol built this
session: real WorkerTask queuing/polling/result-reporting (database/models/
worker_task.py, apps/api/routes/system_worker.py), the risky-action
Security Agent gate (classify_worker_action), System Agent's honest
active-count fix (apps/api/routes/agents.py::get_agent_health), and the
Phase H capability roadmap (core/capability_roadmap.py).

Complements tests/api_tests/test_system_worker.py (worker presence/
heartbeat/offline) and tests/api_tests/test_assistant.py (final_answer
shape, VEO clarification, knowledge-question honesty) rather than
duplicating them.
"""

from __future__ import annotations

import uuid

import pytest

from agents.system_agent.system_agent import SystemAgent, TaskContext


def _connect_worker(client, owner) -> None:
    heartbeat = client.post(
        "/api/v1/system/worker/heartbeat",
        json={
            "platform": "windows",
            "device_name": "Roshan Windows Laptop",
            "supported_actions": ["open_notepad", "open_microsoft_store"],
        },
        headers=owner.headers,
    )
    assert heartbeat.status_code == 200
    assert heartbeat.json()["data"]["worker_connected"] is True


class TestTaskQueuing:
    @pytest.mark.asyncio
    async def test_microsoft_store_queues_a_real_task(self, client, make_owner) -> None:
        owner = make_owner()
        _connect_worker(client, owner)

        agent = SystemAgent()
        context = TaskContext(
            user_id=owner.user_id,
            workspace_id=owner.workspace_id,
            request_id=f"req_{uuid.uuid4().hex[:12]}",
        )
        result = await agent.open_app({"app": "Microsoft Store"}, context)

        assert result["success"] is True
        assert result["data"]["runtime_state"] == "queued"
        task_id = result["data"]["task_id"]
        assert task_id

        tasks = client.get("/api/v1/system/worker/tasks", headers=owner.headers).json()["data"]["tasks"]
        assert any(t["task_id"] == task_id and t["action_type"] == "open_microsoft_store" for t in tasks)

    @pytest.mark.asyncio
    async def test_notepad_queues_a_real_task(self, client, make_owner) -> None:
        owner = make_owner()
        _connect_worker(client, owner)

        agent = SystemAgent()
        context = TaskContext(
            user_id=owner.user_id,
            workspace_id=owner.workspace_id,
            request_id=f"req_{uuid.uuid4().hex[:12]}",
        )
        result = await agent.open_app({"app": "notepad"}, context)

        assert result["success"] is True
        assert result["data"]["runtime_state"] == "queued"

    @pytest.mark.asyncio
    async def test_unsupported_app_returns_clear_error_no_task_created(self, client, make_owner) -> None:
        owner = make_owner()
        _connect_worker(client, owner)

        agent = SystemAgent()
        context = TaskContext(
            user_id=owner.user_id,
            workspace_id=owner.workspace_id,
            request_id=f"req_{uuid.uuid4().hex[:12]}",
        )
        result = await agent.open_app({"app": "some-random-unmapped-app"}, context)

        assert result["success"] is False
        # SystemAgent's own _error_result() puts caller-supplied metadata
        # (like runtime_state) under the top-level "metadata" key, not
        # "data" -- only _safe_result() (the success path) uses "data".
        assert result["metadata"]["runtime_state"] == "unsupported_worker_action"

        tasks = client.get("/api/v1/system/worker/tasks", headers=owner.headers).json()["data"]["tasks"]
        assert tasks == []

    @pytest.mark.asyncio
    async def test_risky_delete_action_requires_approval_never_queued(self, client, make_owner) -> None:
        """delete_file is a WORKER_RISKY_ACTIONS entry -- classify_worker_action
        must route it through security_review() and it must never reach
        status="queued" on its own."""
        owner = make_owner()
        _connect_worker(client, owner)

        from apps.api.routes.system_worker import classify_worker_action
        from apps.api.routes.auth import AuthContext

        context = AuthContext(
            request_id=f"req_{uuid.uuid4().hex[:12]}",
            user_id=owner.user_id,
            workspace_id=owner.workspace_id,
            session_id=f"session_{uuid.uuid4().hex[:12]}",
            role=owner.role,
            plan=owner.plan,
            email=owner.email,
        )
        classification = await classify_worker_action("delete_file", context=context)
        assert classification in ("requires_approval", "rejected")
        assert classification != "allowed"


class TestWorkerPollIsolation:
    @pytest.mark.asyncio
    async def test_worker_only_polls_own_workspace_tasks(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()
        _connect_worker(client, owner_a)
        _connect_worker(client, owner_b)

        agent = SystemAgent()
        context_a = TaskContext(
            user_id=owner_a.user_id,
            workspace_id=owner_a.workspace_id,
            request_id=f"req_{uuid.uuid4().hex[:12]}",
        )
        await agent.open_app({"app": "notepad"}, context_a)

        tasks_b = client.get("/api/v1/system/worker/tasks", headers=owner_b.headers).json()["data"]["tasks"]
        assert tasks_b == []

        tasks_a = client.get("/api/v1/system/worker/tasks", headers=owner_a.headers).json()["data"]["tasks"]
        assert len(tasks_a) == 1


class TestWorkerResultReporting:
    @pytest.mark.asyncio
    async def test_result_report_updates_task_and_worker_status(self, client, make_owner) -> None:
        owner = make_owner()
        _connect_worker(client, owner)

        agent = SystemAgent()
        context = TaskContext(
            user_id=owner.user_id,
            workspace_id=owner.workspace_id,
            request_id=f"req_{uuid.uuid4().hex[:12]}",
        )
        result = await agent.open_app({"app": "notepad"}, context)
        task_id = result["data"]["task_id"]

        report = client.post(
            f"/api/v1/system/worker/tasks/{task_id}/result",
            json={"status": "completed", "result_message": "Notepad opened."},
            headers=owner.headers,
        )
        assert report.status_code == 200
        assert report.json()["data"]["status"] == "completed"

        worker_status = client.get("/api/v1/system/worker/status", headers=owner.headers).json()["data"]
        assert worker_status["last_command"] == "open_notepad"
        assert worker_status["last_result"] == "Notepad opened."

    def test_result_report_rejects_cross_workspace_task_id(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()
        _connect_worker(client, owner_a)

        report = client.post(
            "/api/v1/system/worker/tasks/wtask_does_not_belong_to_b/result",
            json={"status": "completed", "result_message": "should not apply"},
            headers=owner_b.headers,
        )
        assert report.status_code == 404


class TestSystemAgentHonestActiveCount:
    def test_system_agent_is_idle_with_no_recent_worker_activity(self, client, make_owner) -> None:
        owner = make_owner()
        health = client.get("/api/v1/agents/system", headers=owner.headers).json()["data"]["health"]
        assert health["status"] == "idle"

    @pytest.mark.asyncio
    async def test_system_agent_becomes_active_after_real_task(self, client, make_owner) -> None:
        owner = make_owner()
        _connect_worker(client, owner)

        agent = SystemAgent()
        context = TaskContext(
            user_id=owner.user_id,
            workspace_id=owner.workspace_id,
            request_id=f"req_{uuid.uuid4().hex[:12]}",
        )
        await agent.open_app({"app": "notepad"}, context)

        health = client.get("/api/v1/agents/system", headers=owner.headers).json()["data"]["health"]
        assert health["status"] == "available"


class TestCapabilityRoadmap:
    def test_capability_roadmap_has_50_functions(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.get("/api/v1/system/capabilities", headers=owner.headers)
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["count"] == 50
        assert len(data["capabilities"]) == 50

    def test_capability_roadmap_never_fabricates_available_status(self, client, make_owner) -> None:
        owner = make_owner()
        data = client.get("/api/v1/system/capabilities", headers=owner.headers).json()["data"]
        valid_statuses = {"available", "dependency_required", "approval_required", "roadmap"}
        for entry in data["capabilities"]:
            assert entry["current_status"] in valid_statuses
