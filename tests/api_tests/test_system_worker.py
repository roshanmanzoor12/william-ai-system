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
from datetime import datetime, timedelta, timezone

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

    def test_expired_heartbeat_reports_worker_offline(self, client, make_owner) -> None:
        """A worker that heartbeated once but has gone quiet past
        WORKER_STALE_AFTER_SECONDS must honestly read as disconnected --
        this is the "worker terminal said connected but /status said
        offline" symptom, except the correct, intended version of it: a
        real worker that has actually stopped heartbeating SHOULD flip
        back to offline on its own, rather than staying "connected"
        forever from one stale timestamp."""
        owner = make_owner()

        client.post(
            "/api/v1/system/worker/heartbeat",
            json={"platform": "windows"},
            headers=owner.headers,
        )

        from database.db import db_manager
        from database.models.system_worker import SystemWorkerStatus

        stale_time = datetime.now(timezone.utc) - timedelta(seconds=999)
        with db_manager.session_scope() as db:
            row = (
                db.query(SystemWorkerStatus)
                .filter(SystemWorkerStatus.workspace_id == owner.workspace_id)
                .first()
            )
            assert row is not None
            row.worker_last_seen_at = stale_time.replace(tzinfo=None)

        status = client.get("/api/v1/system/worker/status", headers=owner.headers)
        assert status.json()["data"]["worker_connected"] is False


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


def _create_setup_token(client, owner) -> dict:
    response = client.post(
        "/api/v1/system/device/setup-token",
        json={"device_name": "Events Test Laptop"},
        headers=owner.headers,
    )
    assert response.status_code == 200
    return response.json()["data"]


def _register_device(client, setup_token: str) -> dict:
    response = client.post(
        "/api/v1/system/device/register",
        json={"setup_token": setup_token, "device_name": "Events Test Laptop", "supported_actions": ["open_notepad"]},
    )
    assert response.status_code == 200
    return response.json()["data"]


class TestWorkerEvents:
    """Phase coverage: POST /system/worker/events was missing entirely
    (404 on every real Windows Worker heartbeat/task-lifecycle event) --
    apps/worker_nodes/windows/windows_worker.py::record_event() has always
    posted here, unmodified, so these tests exercise the exact real wire
    shape that method sends (event_id/worker_id/session_id/event_type/
    status/payload/created_at), not just the richer explicit shape."""

    def _real_wire_payload(self, **overrides: object) -> dict:
        payload = {
            "event_id": "wevt_test_wire",
            "worker_id": "device_test_wire",
            "session_id": "sess_test_wire",
            "event_type": "heartbeat_sent",
            "status": "idle",
            "payload": {"response_ok": True},
            "created_at": "2026-07-15T00:00:00+00:00",
        }
        payload.update(overrides)
        return payload

    def test_no_404_events_route_exists(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post(
            "/api/v1/system/worker/events",
            json=self._real_wire_payload(),
            headers=owner.headers,
        )
        assert response.status_code != 404

    def test_jwt_dev_mode_can_post_event(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post(
            "/api/v1/system/worker/events",
            json=self._real_wire_payload(event_type="task_polled"),
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["event_type"] == "task_polled"
        assert data["user_id"] == owner.user_id
        assert data["workspace_id"] == owner.workspace_id
        assert data["device_id"] == "device_test_wire"

    def test_device_token_can_post_event(self, client, make_owner) -> None:
        owner = make_owner()
        setup_data = _create_setup_token(client, owner)
        register_data = _register_device(client, setup_data["setup_token"])
        device_headers = {"Authorization": f"Bearer {register_data['device_token']}"}

        response = client.post(
            "/api/v1/system/worker/events",
            json=self._real_wire_payload(worker_id=register_data["device_id"]),
            headers=device_headers,
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["workspace_id"] == owner.workspace_id
        assert data["user_id"] == owner.user_id
        assert data["device_id"] == register_data["device_id"]

    def test_invalid_token_rejected(self, client) -> None:
        response = client.post(
            "/api/v1/system/worker/events",
            json=self._real_wire_payload(),
            headers={"Authorization": "Bearer totally-invalid-garbage-token"},
        )
        assert response.status_code == 401

    def test_no_auth_header_rejected(self, client) -> None:
        response = client.post("/api/v1/system/worker/events", json=self._real_wire_payload())
        assert response.status_code in (401, 403)

    def test_richer_explicit_shape_also_accepted(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post(
            "/api/v1/system/worker/events",
            json={
                "event_type": "task_failed",
                "message": "Notepad failed to open",
                "level": "error",
                "device_id": "device_explicit",
                "worker_task_id": "wtask_explicit123",
                "action_type": "open_notepad",
                "metadata": {"error_code": "APP_LAUNCH_FAILED"},
            },
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["message"] == "Notepad failed to open"
        assert data["level"] == "error"
        assert data["worker_task_id"] == "wtask_explicit123"
        assert data["action_type"] == "open_notepad"
        assert data["metadata"]["error_code"] == "APP_LAUNCH_FAILED"

    def test_level_inferred_when_not_provided(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post(
            "/api/v1/system/worker/events",
            json=self._real_wire_payload(event_type="permission_denied"),
            headers=owner.headers,
        )
        assert response.status_code == 200
        assert response.json()["data"]["level"] == "warning"

    def test_events_are_workspace_isolated(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()

        client.post(
            "/api/v1/system/worker/events",
            json=self._real_wire_payload(event_type="heartbeat_sent"),
            headers=owner_a.headers,
        )

        from database.db import db_manager
        from database.models.system_worker_event import SystemWorkerEventService

        with db_manager.session_scope() as db:
            events_a = SystemWorkerEventService.list_recent_for_workspace(db, workspace_id=owner_a.workspace_id)
            events_b = SystemWorkerEventService.list_recent_for_workspace(db, workspace_id=owner_b.workspace_id)

        assert len(events_a) >= 1
        assert all(e.workspace_id == owner_a.workspace_id for e in events_a)
        assert len(events_b) == 0

    def test_event_persisted_and_queryable(self, client, make_owner) -> None:
        owner = make_owner()
        client.post(
            "/api/v1/system/worker/events",
            json=self._real_wire_payload(event_type="worker_stopped"),
            headers=owner.headers,
        )

        from database.db import db_manager
        from database.models.system_worker_event import SystemWorkerEventService

        with db_manager.session_scope() as db:
            events = SystemWorkerEventService.list_recent_for_workspace(db, workspace_id=owner.workspace_id)

        assert any(e.event_type == "worker_stopped" for e in events)
