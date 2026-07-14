"""
tests/api_tests/test_device_setup.py

Phase 8 coverage for the Windows Worker Auto-Enable + Device Setup flow
(apps/api/routes/device_setup.py, database/models/device_setup_token.py,
database/models/system_worker.py's device-token columns): setup-token
creation/scoping/expiry, device registration + device-token issuance,
device-token dual-mode auth on the worker routes (never reaching
admin-only routes), revocation, dashboard connection_state transitions,
and assistant wording for not_enabled/offline/disabled.

Complements tests/api_tests/test_system_worker.py (presence/heartbeat) and
tests/api_tests/test_windows_worker_dispatch.py (task queue/dispatch/
risky-action gate) rather than duplicating them.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from agents.system_agent.system_agent import SystemAgent, TaskContext


def _create_setup_token(client, owner) -> dict:
    response = client.post(
        "/api/v1/system/device/setup-token",
        json={"device_name": "Test Laptop"},
        headers=owner.headers,
    )
    assert response.status_code == 200
    return response.json()["data"]


def _register_device(client, setup_token: str, *, device_name: str = "Test Laptop") -> dict:
    response = client.post(
        "/api/v1/system/device/register",
        json={"setup_token": setup_token, "device_name": device_name, "supported_actions": ["open_notepad"]},
    )
    assert response.status_code == 200
    return response.json()["data"]


class TestSetupTokenCreation:
    def test_setup_token_requires_auth(self, client) -> None:
        response = client.post("/api/v1/system/device/setup-token", json={})
        assert response.status_code in (401, 403)

    def test_setup_token_is_scoped_and_expires(self, client, make_owner) -> None:
        owner = make_owner()
        data = _create_setup_token(client, owner)

        assert data["setup_token"]
        assert data["expires_in_seconds"] > 0
        assert data["setup_command"]
        assert data["setup_token"] in data["setup_command"]

        expires_at = datetime.fromisoformat(data["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        assert expires_at > datetime.now(timezone.utc)


class TestDeviceRegistration:
    def test_invalid_setup_token_rejected(self, client) -> None:
        response = client.post(
            "/api/v1/system/device/register",
            json={"setup_token": "not-a-real-token", "device_name": "X", "supported_actions": []},
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "SETUP_TOKEN_INVALID"

    def test_expired_setup_token_rejected(self, client, make_owner) -> None:
        owner = make_owner()
        data = _create_setup_token(client, owner)

        from database.db import db_manager
        from database.models.device_setup_token import DeviceSetupToken

        with db_manager.session_scope() as db:
            row = db.query(DeviceSetupToken).filter(
                DeviceSetupToken.workspace_id == owner.workspace_id
            ).first()
            assert row is not None
            row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)

        response = client.post(
            "/api/v1/system/device/register",
            json={"setup_token": data["setup_token"], "device_name": "X", "supported_actions": []},
        )
        assert response.status_code == 401

    def test_register_with_setup_token_creates_system_worker_row(self, client, make_owner) -> None:
        owner = make_owner()
        data = _create_setup_token(client, owner)
        register_data = _register_device(client, data["setup_token"])

        assert register_data["device_id"]
        assert register_data["device_token"]
        assert register_data["workspace_id"] == owner.workspace_id
        assert register_data["user_id"] == owner.user_id

        status_response = client.get("/api/v1/system/worker/status", headers=owner.headers)
        status_data = status_response.json()["data"]
        assert status_data["device_id"] == register_data["device_id"]
        assert status_data["device_token_status"] == "active"
        assert status_data["connection_state"] == "connected"

    def test_setup_token_is_single_use(self, client, make_owner) -> None:
        owner = make_owner()
        data = _create_setup_token(client, owner)
        _register_device(client, data["setup_token"])

        response = client.post(
            "/api/v1/system/device/register",
            json={"setup_token": data["setup_token"], "device_name": "X", "supported_actions": []},
        )
        assert response.status_code == 401


class TestDeviceTokenAuth:
    def test_device_token_can_heartbeat(self, client, make_owner) -> None:
        owner = make_owner()
        setup_data = _create_setup_token(client, owner)
        register_data = _register_device(client, setup_data["setup_token"])
        device_headers = {"Authorization": f"Bearer {register_data['device_token']}"}

        response = client.post(
            "/api/v1/system/worker/heartbeat", json={"platform": "windows"}, headers=device_headers
        )
        assert response.status_code == 200
        assert response.json()["data"]["worker_connected"] is True

    def test_device_token_cannot_access_admin_route(self, client, make_owner) -> None:
        owner = make_owner()
        setup_data = _create_setup_token(client, owner)
        register_data = _register_device(client, setup_data["setup_token"])
        device_headers = {"Authorization": f"Bearer {register_data['device_token']}"}

        response = client.get("/api/v1/agents", headers=device_headers)
        assert response.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_device_token_polls_only_own_workspace(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()
        setup_a = _create_setup_token(client, owner_a)
        register_a = _register_device(client, setup_a["setup_token"])
        device_headers_a = {"Authorization": f"Bearer {register_a['device_token']}"}

        setup_b = _create_setup_token(client, owner_b)
        _register_device(client, setup_b["setup_token"], device_name="Owner B Laptop")

        agent = SystemAgent()
        context_b = TaskContext(
            user_id=owner_b.user_id,
            workspace_id=owner_b.workspace_id,
            request_id=f"req_{uuid.uuid4().hex[:12]}",
        )
        # A real task queued for owner_b's own connected worker must never
        # be visible to owner_a's device token.
        await agent.open_app({"app": "notepad"}, context_b)

        tasks_response = client.get("/api/v1/system/worker/tasks", headers=device_headers_a)
        assert tasks_response.json()["data"]["tasks"] == []


class TestDisableAndRevocation:
    def test_disable_revokes_device_token(self, client, make_owner) -> None:
        owner = make_owner()
        setup_data = _create_setup_token(client, owner)
        register_data = _register_device(client, setup_data["setup_token"])

        response = client.post("/api/v1/system/device/disable", headers=owner.headers)
        assert response.status_code == 200

        status_response = client.get("/api/v1/system/worker/status", headers=owner.headers)
        assert status_response.json()["data"]["connection_state"] == "disabled"

    def test_revoked_device_token_cannot_poll_tasks(self, client, make_owner) -> None:
        owner = make_owner()
        setup_data = _create_setup_token(client, owner)
        register_data = _register_device(client, setup_data["setup_token"])
        device_headers = {"Authorization": f"Bearer {register_data['device_token']}"}

        client.post("/api/v1/system/device/disable", headers=owner.headers)

        response = client.get("/api/v1/system/worker/tasks", headers=device_headers)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "DEVICE_TOKEN_REVOKED"


class TestDashboardConnectionStateTransitions:
    def test_needs_setup_when_no_worker_exists(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.get("/api/v1/system/worker/status", headers=owner.headers)
        assert response.json()["data"]["connection_state"] == "needs_setup"

    def test_offline_when_worker_exists_but_stale(self, client, make_owner) -> None:
        owner = make_owner()
        setup_data = _create_setup_token(client, owner)
        _register_device(client, setup_data["setup_token"])

        from database.db import db_manager
        from database.models.system_worker import SystemWorkerStatus

        with db_manager.session_scope() as db:
            row = db.query(SystemWorkerStatus).filter(
                SystemWorkerStatus.workspace_id == owner.workspace_id
            ).first()
            assert row is not None
            row.worker_last_seen_at = datetime.now(timezone.utc) - timedelta(seconds=999)

        response = client.get("/api/v1/system/worker/status", headers=owner.headers)
        assert response.json()["data"]["connection_state"] == "offline"

    def test_connected_when_heartbeat_recent(self, client, make_owner) -> None:
        owner = make_owner()
        setup_data = _create_setup_token(client, owner)
        _register_device(client, setup_data["setup_token"])

        response = client.get("/api/v1/system/worker/status", headers=owner.headers)
        assert response.json()["data"]["connection_state"] == "connected"


class TestAssistantDeviceSetupWording:
    def test_assistant_says_enable_when_no_setup_exists(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post(
            "/api/v1/assistant/message",
            json={"message": "William open Notepad"},
            headers=owner.headers,
        )
        final_answer = response.json()["data"]["final_answer"]
        assert "not enabled yet" in final_answer
        assert "Enable Windows Worker" in final_answer

    def test_assistant_says_offline_when_enabled_but_worker_not_running(self, client, make_owner) -> None:
        owner = make_owner()
        setup_data = _create_setup_token(client, owner)
        _register_device(client, setup_data["setup_token"])

        from database.db import db_manager
        from database.models.system_worker import SystemWorkerStatus

        with db_manager.session_scope() as db:
            row = db.query(SystemWorkerStatus).filter(
                SystemWorkerStatus.workspace_id == owner.workspace_id
            ).first()
            assert row is not None
            row.worker_last_seen_at = datetime.now(timezone.utc) - timedelta(seconds=999)

        response = client.post(
            "/api/v1/assistant/message",
            json={"message": "William open Notepad"},
            headers=owner.headers,
        )
        final_answer = response.json()["data"]["final_answer"]
        assert "enabled but offline" in final_answer

    def test_assistant_says_disabled_when_worker_disabled(self, client, make_owner) -> None:
        owner = make_owner()
        setup_data = _create_setup_token(client, owner)
        _register_device(client, setup_data["setup_token"])
        client.post("/api/v1/system/device/disable", headers=owner.headers)

        response = client.post(
            "/api/v1/assistant/message",
            json={"message": "William open Notepad"},
            headers=owner.headers,
        )
        final_answer = response.json()["data"]["final_answer"]
        assert "disabled" in final_answer.lower()

    def test_assistant_queues_notepad_when_worker_connected(self, client, make_owner) -> None:
        owner = make_owner()
        setup_data = _create_setup_token(client, owner)
        _register_device(client, setup_data["setup_token"])

        response = client.post(
            "/api/v1/assistant/message",
            json={"message": "William open Notepad"},
            headers=owner.headers,
        )
        final_answer = response.json()["data"]["final_answer"]
        assert "notepad" in final_answer.lower()
        assert "Done boss" in final_answer
        assert response.json()["data"]["status"] != "failed"


class TestRiskyActionsStillGated:
    @pytest.mark.asyncio
    async def test_risky_action_requires_approval_with_device_token_context(self, client, make_owner) -> None:
        owner = make_owner()
        setup_data = _create_setup_token(client, owner)
        _register_device(client, setup_data["setup_token"])

        from apps.api.routes.system_worker import classify_worker_action
        from apps.api.routes.auth import AuthContext

        device_context = AuthContext(
            request_id=f"req_{uuid.uuid4().hex[:12]}",
            user_id=owner.user_id,
            workspace_id=owner.workspace_id,
            session_id="device_test",
            role="device",
            plan="free",
            email="device@worker.local",
        )
        classification = await classify_worker_action("delete_file", context=device_context)
        assert classification == "requires_approval"
