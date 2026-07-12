"""
tests/api_tests/conftest.py

Shared real-auth test helpers for tests/api_tests/*.py.

Building an authenticated actor for these tests previously meant either
faking auth entirely (spoofable X-User-Id/X-Role headers -- which
apps/api/routes/{agents,memory}.py correctly reject now, since both use the
real, JWT-verified get_current_auth_context) or a static fake bearer token.
This module uses the real token-issuing/session/membership machinery from
apps.api.routes.auth (TOKEN_SERVICE, AUTH_STORE) plus the real
WorkspaceMembership ORM model directly to build a genuinely valid Bearer
token + workspace membership for any role. The authentication/authorization
code path under test (JWT signature verification, session lookup, live
membership lookup) is entirely untouched -- only account/session setup
skips the multi-step HTTP register -> invite -> accept UI flow in favor of
direct model construction, which is standard test-fixture practice (e.g.
Django's User.objects.create() instead of posting to a signup form for
every fixture).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional
from uuid import uuid4

import pytest

from apps.api.routes.auth import AUTH_SETTINGS, AUTH_STORE, TOKEN_SERVICE
from database.db import db_manager
from database.models.workspace import WorkspaceMembership as _DbMembership, WorkspaceMemberRole

DEFAULT_TEST_PASSWORD = "Sup3rSecure!Pass1"


@dataclass
class RealActor:
    """A real, JWT-authenticated user/workspace/role for API tests."""

    user_id: str
    workspace_id: str
    email: str
    role: str
    plan: str
    access_token: str
    headers: Dict[str, str]


def register_owner(
    client,
    *,
    email: Optional[str] = None,
    password: str = DEFAULT_TEST_PASSWORD,
    workspace_name: str = "Test Workspace",
    full_name: str = "Test Owner",
) -> RealActor:
    """Register a brand-new real owner + workspace through the real HTTP endpoint."""

    email = email or f"owner_{uuid4().hex[:12]}@example.test"

    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": password,
            "full_name": full_name,
            "workspace_name": workspace_name,
        },
    )
    assert response.status_code in (200, 201), response.text

    data = response.json()["data"]
    access_token = data["tokens"]["access_token"]

    return RealActor(
        user_id=data["user"]["user_id"],
        workspace_id=data["workspace"]["workspace_id"],
        email=email,
        role=data["membership"]["role"],
        plan=data["membership"]["plan"],
        access_token=access_token,
        headers={"Authorization": f"Bearer {access_token}"},
    )


def add_member_with_role(
    client,
    owner: RealActor,
    *,
    role: str,
    email: Optional[str] = None,
    password: str = DEFAULT_TEST_PASSWORD,
) -> RealActor:
    """
    Create a second real user and give them `role` in `owner`'s workspace.

    Uses the real WorkspaceMembership model directly (skipping the invite/
    accept HTTP dance) plus a real session + signed access token via
    AUTH_STORE/TOKEN_SERVICE -- the exact machinery get_current_auth_context
    verifies against on every request. `role` must be one of the DB-level
    WorkspaceMemberRole values: owner, admin, manager, member, viewer.
    """

    email = email or f"{role}_{uuid4().hex[:12]}@example.test"

    # Register as a standalone user first (creates their own throwaway
    # workspace too, which this helper ignores) purely to get a real
    # UserRecord with a real password hash through the real endpoint.
    solo = register_owner(
        client,
        email=email,
        password=password,
        workspace_name=f"{role} scratch workspace",
        full_name=f"Test {role.title()}",
    )

    user = AUTH_STORE.get_user_by_id(solo.user_id)
    member_role = WorkspaceMemberRole(role)

    with db_manager.session_scope() as session:
        membership = _DbMembership.create_member(
            workspace_id=owner.workspace_id,
            user_id=user.user_id,
            role=member_role,
        )
        session.add(membership)
        session.flush()

    membership_record = AUTH_STORE.get_membership(user.user_id, owner.workspace_id)
    assert membership_record is not None

    _, refresh_jti, refresh_expires_at = TOKEN_SERVICE.create_token(
        token_type="refresh",
        user_id=user.user_id,
        workspace_id=owner.workspace_id,
        session_id="pending",
        role=membership_record.role,
        plan=membership_record.plan,
        email=user.email,
        ttl_seconds=AUTH_SETTINGS.refresh_token_ttl_seconds,
    )

    session_record = AUTH_STORE.create_session(
        user=user,
        membership=membership_record,
        refresh_jti=refresh_jti,
        refresh_expires_at=refresh_expires_at,
        ip_address=None,
        user_agent="pytest",
    )

    access_token, _, _ = TOKEN_SERVICE.create_token(
        token_type="access",
        user_id=user.user_id,
        workspace_id=owner.workspace_id,
        session_id=session_record.session_id,
        role=membership_record.role,
        plan=membership_record.plan,
        email=user.email,
        ttl_seconds=AUTH_SETTINGS.access_token_ttl_seconds,
    )

    return RealActor(
        user_id=user.user_id,
        workspace_id=owner.workspace_id,
        email=user.email,
        role=membership_record.role,
        plan=membership_record.plan,
        access_token=access_token,
        headers={"Authorization": f"Bearer {access_token}"},
    )


def set_workspace_plan(workspace_id: str, plan: str) -> None:
    """Directly set a workspace's plan for plan-gating tests (e.g. 'free')."""

    from database.models.workspace import Workspace as _DbWorkspace, WorkspacePlan as _DbWorkspacePlan

    with db_manager.session_scope() as session:
        workspace = session.get(_DbWorkspace, workspace_id)
        assert workspace is not None
        workspace.plan = _DbWorkspacePlan(plan)
        session.add(workspace)
        session.flush()


# ---------------------------------------------------------------------------
# Fixtures (this project has no tests/__init__.py package markers, so plain
# `from tests.api_tests.conftest import ...` doesn't resolve -- expose the
# helpers above as fixtures instead, which pytest auto-injects with no
# import statement needed, matching this file tree's existing convention).
# ---------------------------------------------------------------------------

@pytest.fixture
def make_owner(client):
    """Factory fixture: make_owner(**kwargs) -> RealActor (owner + new workspace)."""

    def _make(**kwargs) -> RealActor:
        return register_owner(client, **kwargs)

    return _make


@pytest.fixture
def make_member(client):
    """Factory fixture: make_member(owner, role=...) -> RealActor in owner's workspace."""

    def _make(owner: RealActor, *, role: str, **kwargs) -> RealActor:
        return add_member_with_role(client, owner, role=role, **kwargs)

    return _make


@pytest.fixture
def set_plan():
    """Factory fixture: set_plan(workspace_id, plan)."""

    return set_workspace_plan
