"""
tests/api_tests/test_agent_permissions.py

Real HTTP tests for apps/api/routes/agent_permissions.py -- the route the
dashboard's Agent Permissions page (agent-permissions/page.tsx) calls.
Before this route existed, every GET/PUT hit FastAPI's default 404 body
(`{"detail": "Not Found"}`), which the frontend correctly rejected as
"The API returned an invalid response shape."
"""

from __future__ import annotations


class TestAgentPermissions:
    def test_requires_auth(self, client) -> None:
        response = client.get("/api/v1/agent-permissions")
        assert response.status_code in (401, 403)

    def test_owner_can_load_permissions_shape(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.get("/api/v1/agent-permissions", headers=owner.headers)
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        data = body["data"]
        assert "users" in data and "agents" in data and "role_matrix" in data
        assert any(user["user_id"] == owner.user_id for user in data["users"])
        assert len(data["agents"]) > 0
        for agent in data["agents"]:
            assert "key" in agent and "allowed_roles" in agent and "minimum_plan" in agent
        for role in ("owner", "admin", "manager", "member", "viewer"):
            assert role in data["role_matrix"]

    def test_users_are_workspace_isolated(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()

        response = client.get("/api/v1/agent-permissions", headers=owner_a.headers)
        user_ids = [user["user_id"] for user in response.json()["data"]["users"]]
        assert owner_b.user_id not in user_ids

    def test_member_cannot_write_permissions(self, client, make_owner, make_member) -> None:
        owner = make_owner()
        member = make_member(owner, role="member")

        response = client.put(
            f"/api/v1/agent-permissions/{member.user_id}",
            json={"target_user_id": member.user_id, "assigned_agents": ["creator"]},
            headers=member.headers,
        )
        assert response.status_code == 403

    def test_owner_can_assign_and_revoke_agent_access(self, client, make_owner) -> None:
        owner = make_owner()

        grant = client.put(
            f"/api/v1/agent-permissions/{owner.user_id}",
            json={"target_user_id": owner.user_id, "assigned_agents": ["creator", "browser"]},
            headers=owner.headers,
        )
        assert grant.status_code == 200
        assert sorted(grant.json()["data"]["assigned_agents"]) == ["browser", "creator"]

        revoke = client.put(
            f"/api/v1/agent-permissions/{owner.user_id}",
            json={"target_user_id": owner.user_id, "assigned_agents": []},
            headers=owner.headers,
        )
        assert revoke.status_code == 200
        assert revoke.json()["data"]["assigned_agents"] == []

    def test_cannot_edit_permissions_for_user_outside_workspace(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()

        response = client.put(
            f"/api/v1/agent-permissions/{owner_b.user_id}",
            json={"target_user_id": owner_b.user_id, "assigned_agents": ["creator"]},
            headers=owner_a.headers,
        )
        assert response.status_code == 404
