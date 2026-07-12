"""
tests/api_tests/test_billing.py

Real HTTP tests for apps/api/routes/billing.py's platform-admin dev-only
"effective plan" bypass (apps.api.routes.auth.platform_admin_gets_unlimited_plan),
and the plan-sync-on-read fix that made GET /billing/subscription actually
reflect a real Workspace.plan change instead of a permanently-stale cached
in-memory record.
"""

from __future__ import annotations

from database.db import db_manager
from database.models.user import User


def make_platform_admin(user_id: str) -> None:
    """Flip is_platform_admin=True for an already-registered real user.
    get_current_auth_context() re-fetches the User row fresh on every
    request, so an already-issued access token picks this up immediately."""

    with db_manager.session_scope() as db:
        user = db.query(User).filter(User.id == user_id).first()
        assert user is not None
        user.is_platform_admin = True


class TestBillingEffectivePlan:
    def test_normal_free_workspace_stays_free(self, client, make_owner) -> None:
        owner = make_owner()

        response = client.get("/api/v1/billing/subscription", headers=owner.headers)
        assert response.status_code == 200
        body = response.json()
        assert body["ok"] is True
        assert body["data"]["subscription"]["plan"] == "free"

    def test_platform_admin_sees_enterprise_in_dev_without_real_upgrade(
        self, client, make_owner
    ) -> None:
        owner = make_owner()
        make_platform_admin(owner.user_id)

        response = client.get("/api/v1/billing/subscription", headers=owner.headers)
        assert response.status_code == 200
        body = response.json()
        assert body["data"]["subscription"]["plan"] == "enterprise"

    def test_non_admin_cannot_bypass_plan_via_billing(
        self, client, make_owner, make_member
    ) -> None:
        owner = make_owner()
        # "member" cannot view billing at all (can_view_billing() requires
        # manager/admin/owner) -- "manager" is the lowest role that can
        # actually reach this endpoint, which is what this test needs to
        # confirm still shows "free" without is_platform_admin.
        manager = make_member(owner, role="manager")

        response = client.get("/api/v1/billing/subscription", headers=manager.headers)
        assert response.status_code == 200
        assert response.json()["data"]["subscription"]["plan"] == "free"

    def test_real_workspace_plan_upgrade_is_reflected_on_next_read(
        self, client, make_owner, set_plan
    ) -> None:
        """Regression test for the bug this session fixed: billing.py's
        in-memory SubscriptionRecord cache previously never synced with a
        real Workspace.plan change, so billing looked permanently stuck on
        the plan seen at the very first read."""
        owner = make_owner()

        first = client.get("/api/v1/billing/subscription", headers=owner.headers)
        assert first.json()["data"]["subscription"]["plan"] == "free"

        set_plan(owner.workspace_id, "enterprise")

        second = client.get("/api/v1/billing/subscription", headers=owner.headers)
        assert second.json()["data"]["subscription"]["plan"] == "enterprise"
