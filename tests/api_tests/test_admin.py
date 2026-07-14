"""
tests/api_tests/test_admin.py

Real HTTP tests for apps/api/routes/admin.py -- the platform Admin Control
Center. Uses the same real JWT auth fixtures as tests/api_tests/test_voice.py/
test_agent_permissions.py, plus a local helper that flips
database.models.user.User.is_platform_admin directly (the one flag every
/api/v1/admin/* route gates on).
"""

from __future__ import annotations

from database.db import db_manager
from database.models.user import User


def make_platform_admin(user_id: str) -> None:
    """Flip is_platform_admin=True for an already-registered real user.
    get_current_auth_context() re-fetches the User row fresh on every
    request (never caches it in the JWT payload), so an already-issued
    access token picks this up immediately -- no re-login required."""

    with db_manager.session_scope() as db:
        user = db.query(User).filter(User.id == user_id).first()
        assert user is not None
        user.is_platform_admin = True


class TestAdminAccessControl:
    def test_platform_admin_can_list_users(self, client, make_owner) -> None:
        admin = make_owner()
        make_platform_admin(admin.user_id)

        response = client.get("/api/v1/admin/users", headers=admin.headers)
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["count"] >= 1
        assert any(u["id"] == admin.user_id for u in data["users"])
        # never leak password fields
        for user in data["users"]:
            assert "password" not in user
            assert "password_hash" not in user

    def test_non_admin_cannot_list_users(self, client, make_owner) -> None:
        owner = make_owner()  # real owner of their own workspace, but not a platform admin
        response = client.get("/api/v1/admin/users", headers=owner.headers)
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "PLATFORM_ADMIN_REQUIRED"

    def test_admin_routes_require_auth(self, client) -> None:
        response = client.get("/api/v1/admin/overview")
        assert response.status_code in (401, 403)

    def test_platform_admin_can_load_overview(self, client, make_owner) -> None:
        admin = make_owner()
        make_platform_admin(admin.user_id)

        response = client.get("/api/v1/admin/overview", headers=admin.headers)
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["users_count"] >= 1
        assert data["workspaces_count"] >= 1
        assert "active_plans" in data
        assert "agent_usage_summary" in data

    def test_non_admin_cannot_load_overview(self, client, make_owner) -> None:
        owner = make_owner()  # real owner, not a platform admin

        response = client.get("/api/v1/admin/overview", headers=owner.headers)
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "PLATFORM_ADMIN_REQUIRED"

    def test_platform_admin_grant_is_reflected_in_a_fresh_login(
        self, client, make_owner
    ) -> None:
        """Regression test for the reported bug: scripts/grant_platform_admin.py
        writes User.is_platform_admin directly to the database; a fresh
        POST /auth/login for that same user must see it immediately, with
        no re-registration or caching involved. (The real-world cause of
        this appearing to fail was a relative SQLite dev-database path
        resolving differently for two separately-launched processes --
        see database/db.py's _anchor_relative_sqlite_url and
        tests/database_tests/test_db_path_resolution.py. Within a single
        test process sharing one in-memory database, this test instead
        guards the auth-layer half of the fix: login must never cache or
        skip a fresh read of is_platform_admin.)"""
        owner = make_owner(email="freshlogin@example.test", password="Sup3rSecure!Pass1")
        make_platform_admin(owner.user_id)

        login = client.post(
            "/api/v1/auth/login",
            json={"email": "freshlogin@example.test", "password": "Sup3rSecure!Pass1"},
        )
        assert login.status_code == 200
        login_data = login.json()["data"]
        assert login_data["user"]["is_platform_admin"] is True


class TestAdminWorkspacePlan:
    def test_platform_admin_can_change_workspace_plan(self, client, make_owner) -> None:
        admin = make_owner()
        make_platform_admin(admin.user_id)
        target = make_owner()

        response = client.patch(
            f"/api/v1/admin/workspaces/{target.workspace_id}/plan",
            json={"plan": "business"},
            headers=admin.headers,
        )
        assert response.status_code == 200
        assert response.json()["data"]["workspace"]["plan"] == "business"

    def test_non_admin_cannot_change_plan(self, client, make_owner) -> None:
        owner = make_owner()
        other = make_owner()

        response = client.patch(
            f"/api/v1/admin/workspaces/{other.workspace_id}/plan",
            json={"plan": "enterprise"},
            headers=owner.headers,
        )
        assert response.status_code == 403

    def test_starter_plan_is_a_valid_assignable_plan(self, client, make_owner) -> None:
        """Regression test: WorkspacePlan previously had no STARTER member
        even though "starter" is a real, canonical plan tier used
        everywhere else (seeders, agent required_plan gates) -- assigning
        it would have failed at the DB enum layer."""
        admin = make_owner()
        make_platform_admin(admin.user_id)
        target = make_owner()

        response = client.patch(
            f"/api/v1/admin/workspaces/{target.workspace_id}/plan",
            json={"plan": "starter"},
            headers=admin.headers,
        )
        assert response.status_code == 200
        assert response.json()["data"]["workspace"]["plan"] == "starter"


class TestAdminInvites:
    def test_invite_creation_works(self, client, make_owner) -> None:
        admin = make_owner()
        make_platform_admin(admin.user_id)
        workspace = make_owner()

        response = client.post(
            "/api/v1/admin/invites",
            json={"email": "invitee@example.test", "workspace_id": workspace.workspace_id, "role": "member"},
            headers=admin.headers,
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["invite"]["invited_email"] == "invitee@example.test"
        assert data["invite"]["status"] == "pending"
        assert "token=" in data["invite_link"]
        # No SMTP provider configured in tests -> honest external_dependency_required, never a fake "sent".
        assert data["email_status"] == "external_dependency_required"

    def test_invite_accept_works(self, client, make_owner) -> None:
        admin = make_owner()
        make_platform_admin(admin.user_id)
        workspace = make_owner()

        invitee_email = "accepting_invitee@example.test"
        create = client.post(
            "/api/v1/admin/invites",
            json={"email": invitee_email, "workspace_id": workspace.workspace_id, "role": "manager"},
            headers=admin.headers,
        )
        invite_link = create.json()["data"]["invite_link"]
        token = invite_link.split("token=", 1)[1]

        invitee = make_owner(email=invitee_email)  # registers a real account with the invited email

        response = client.post(f"/api/v1/admin/invites/{token}/accept", headers=invitee.headers)
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["invite"]["status"] == "accepted"
        assert data["membership"]["role"] == "manager"
        assert data["membership"]["workspace_id"] == workspace.workspace_id

    def test_invite_accept_rejects_wrong_email(self, client, make_owner) -> None:
        admin = make_owner()
        make_platform_admin(admin.user_id)
        workspace = make_owner()

        create = client.post(
            "/api/v1/admin/invites",
            json={"email": "someone_specific@example.test", "workspace_id": workspace.workspace_id, "role": "member"},
            headers=admin.headers,
        )
        token = create.json()["data"]["invite_link"].split("token=", 1)[1]

        wrong_user = make_owner()  # a different, real, already-registered account
        response = client.post(f"/api/v1/admin/invites/{token}/accept", headers=wrong_user.headers)
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "INVITE_EMAIL_MISMATCH"


class TestAdminAuditLog:
    def test_admin_action_creates_audit_log(self, client, make_owner) -> None:
        admin = make_owner()
        make_platform_admin(admin.user_id)
        target = make_owner()

        client.patch(
            f"/api/v1/admin/workspaces/{target.workspace_id}/plan",
            json={"plan": "pro"},
            headers=admin.headers,
        )

        response = client.get("/api/v1/admin/audit", headers=admin.headers)
        assert response.status_code == 200
        entries = response.json()["data"]["entries"]
        assert any(e["action"] == "admin.workspace.plan_changed" and e["resource_id"] == target.workspace_id for e in entries)


class TestAdminAgentPermissionUpdate:
    def test_admin_can_update_agent_permissions_for_any_workspace(self, client, make_owner) -> None:
        admin = make_owner()
        make_platform_admin(admin.user_id)
        target = make_owner()

        response = client.put(
            f"/api/v1/agent-permissions/{target.user_id}?workspace_id={target.workspace_id}",
            json={"target_user_id": target.user_id, "assigned_agents": ["creator", "browser"]},
            headers=admin.headers,
        )
        assert response.status_code == 200
        assert sorted(response.json()["data"]["assigned_agents"]) == ["browser", "creator"]

    def test_non_admin_non_owner_cannot_update_other_workspace_permissions(self, client, make_owner) -> None:
        outsider = make_owner()
        target = make_owner()

        response = client.put(
            f"/api/v1/agent-permissions/{target.user_id}?workspace_id={target.workspace_id}",
            json={"target_user_id": target.user_id, "assigned_agents": ["creator"]},
            headers=outsider.headers,
        )
        # outsider is an owner of THEIR OWN workspace (role rank passes
        # require_workspace_admin_or_platform_admin), but the target
        # membership lookup is scoped to the admin-requested workspace_id,
        # so they still can't reach a user who isn't a member of it.
        assert response.status_code == 404


class TestAdminWorkspaceIsolation:
    def test_admin_users_list_spans_all_workspaces_but_never_leaks_cross_workspace_writes(self, client, make_owner) -> None:
        admin = make_owner()
        make_platform_admin(admin.user_id)
        workspace_a = make_owner()
        workspace_b = make_owner()

        response = client.get("/api/v1/admin/users", headers=admin.headers)
        user_ids = {u["id"] for u in response.json()["data"]["users"]}
        assert workspace_a.user_id in user_ids
        assert workspace_b.user_id in user_ids

        # A non-platform-admin still cannot see the platform-wide view at all.
        response_b = client.get("/api/v1/admin/users", headers=workspace_b.headers)
        assert response_b.status_code == 403
