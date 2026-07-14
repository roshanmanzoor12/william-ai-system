"""
tests/api_tests/test_system_worker.py

Real HTTP tests for apps/api/routes/system_worker.py (GET /system/worker/status,
POST /system/worker/heartbeat), plus the integration point where
agents/system_agent/system_agent.py's open_app reads that same real,
DB-backed status to decide between device_worker_offline and
external_dependency_required -- never a fake success either way.
"""

from __future__ import annotations

import uuid

import pytest

from agents.system_agent.system_agent import SystemAgent, TaskContext


class TestSystemWorkerStatus:
    def test_status_requires_auth(self, client) -> None:
        response = client.get("/api/v1/system/worker/status")
        assert response.status_code in (401, 403)

    def test_default_status_is_not_connected(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.get("/api/v1/system/worker/status", headers=owner.headers)
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["worker_connected"] is False

    def test_heartbeat_requires_auth(self, client) -> None:
        response = client.post("/api/v1/system/worker/heartbeat")
        assert response.status_code in (401, 403)

    def test_heartbeat_marks_worker_connected(self, client, make_owner) -> None:
        owner = make_owner()

        heartbeat = client.post(
            "/api/v1/system/worker/heartbeat",
            json={"platform": "windows"},
            headers=owner.headers,
        )
        assert heartbeat.status_code == 200
        assert heartbeat.json()["data"]["worker_connected"] is True

        status = client.get("/api/v1/system/worker/status", headers=owner.headers)
        assert status.json()["data"]["worker_connected"] is True

    def test_worker_status_is_workspace_isolated(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()

        client.post("/api/v1/system/worker/heartbeat", json={"platform": "windows"}, headers=owner_a.headers)

        status_b = client.get("/api/v1/system/worker/status", headers=owner_b.headers)
        assert status_b.json()["data"]["worker_connected"] is False


class TestSystemAgentReflectsRealWorkerStatus:
    @pytest.mark.asyncio
    async def test_open_app_after_worker_heartbeat_queues_a_real_task(
        self, client, make_owner
    ) -> None:
        """Once a Windows worker has heartbeat-registered for this exact
        workspace, SystemAgent.open_app's honest state changes from "no
        worker at all" (device_worker_offline) to a REAL queued task now
        that the dispatch protocol exists (database/models/worker_task.py,
        apps/api/routes/system_worker.py's GET /worker/tasks + POST
        /worker/tasks/{id}/result). It still never claims the app actually
        opened -- only "queued", never "completed", since only the
        worker's own result report can say that."""
        owner = make_owner()

        heartbeat = client.post(
            "/api/v1/system/worker/heartbeat",
            json={"platform": "windows"},
            headers=owner.headers,
        )
        assert heartbeat.status_code == 200
        assert heartbeat.json()["data"]["worker_connected"] is True

        agent = SystemAgent()
        context = TaskContext(
            user_id=owner.user_id,
            workspace_id=owner.workspace_id,
            request_id=f"req_{uuid.uuid4().hex[:12]}",
        )

        result = await agent.open_app({"app": "Microsoft Store"}, context)

        assert result["success"] is True
        assert result["data"]["runtime_state"] == "queued"
        assert result["data"]["task_id"]
