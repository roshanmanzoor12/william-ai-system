"""
scripts/grant_platform_admin.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Local dev helper that makes a user a fully-unlimited platform admin:
  1. Sets database.models.user.User.is_platform_admin = True.
  2. Ensures they have an ACTIVE membership in a real workspace, with role
     OWNER (creates the membership if they somehow have none, using their
     first/default workspace).
  3. Sets that workspace's REAL stored plan
     (database.models.workspace.Workspace.plan) to ENTERPRISE -- a genuine,
     persisted upgrade, not just the separate is_platform_admin dev-only
     effective_plan override (apps.api.routes.auth.
     platform_admin_gets_unlimited_plan) that apps/api/routes/{agents,
     agent_permissions,billing}.py also apply for platform admins in
     non-production environments. Both exist: this script makes the
     REAL plan true so it's correct even outside the dev bypass; the
     bypass is a safety net for a platform admin who hasn't been
     migrated to a real workspace yet.
  4. Prints the final user role, workspace, plan, and plan/role-eligible
     agent count (how many of the 15 real agents OWNER+ENTERPRISE unlocks
     by required_role/required_plan -- NOT the same as "assigned" or
     "enabled", which is what scripts/dev_activate_all_agents.py sets).

Never runs automatically; only takes effect when a human runs it directly.
The user must already have registered a real account (this script does not
create one) -- register first via the dashboard or
POST /api/v1/auth/register, then run this script.
get_current_auth_context() (apps/api/routes/auth.py) re-reads the User row
from the database on every request rather than trusting anything baked
into the JWT, so this takes effect immediately for an already-issued
token too -- no re-login required (only a page refresh, so the dashboard
sidebar's Admin link, itself read once at page load, picks it up).

Usage:
    python scripts/grant_platform_admin.py roshanmanzoor230@gmail.com
    python scripts/grant_platform_admin.py roshanmanzoor230@gmail.com --revoke
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Running this file directly (`python scripts/grant_platform_admin.py`) puts
# scripts/ on sys.path, not the repo root, so `from database.db import ...`
# below would fail with "No module named 'database'" -- add the repo root
# explicitly rather than requiring `python -m scripts.grant_platform_admin`
# (which would also need a scripts/__init__.py that doesn't otherwise need
# to exist).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

DEFAULT_ADMIN_EMAIL = "roshanmanzoor230@gmail.com"


def _count_role_plan_eligible_agents(role: str, plan: str) -> int:
    try:
        from apps.api.routes.agents import AGENT_CATALOG, has_min_role, has_min_plan

        return sum(
            1
            for definition in AGENT_CATALOG.values()
            if has_min_role(role, definition.required_role) and has_min_plan(plan, definition.required_plan)
        )
    except Exception:
        return -1


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="Grant or revoke full local/dev platform-admin access for a user by email.")
    parser.add_argument("email", nargs="?", default=DEFAULT_ADMIN_EMAIL, help=f"User email (default: {DEFAULT_ADMIN_EMAIL})")
    parser.add_argument("--revoke", action="store_true", help="Revoke platform-admin access instead of granting it.")
    args = parser.parse_args(argv)

    from database.db import db_manager
    from database.models.user import User
    from database.models.workspace import (
        Workspace,
        WorkspaceMembership,
        WorkspaceMemberRole,
        WorkspaceMembershipStatus,
        WorkspacePlan,
        enum_value,
        plan_member_limit,
        plan_agent_limit,
    )

    target_flag = not args.revoke
    email = args.email.strip().lower()

    summary: dict = {}

    with db_manager.session_scope() as db:
        user = db.query(User).filter(User.email == email).first()

        if user is None:
            print(f"No user found with email {email!r}. Register the account first, then re-run this script.")
            return 1

        user.is_platform_admin = target_flag

        if not target_flag:
            db.flush()
            print(f"{email} (user_id={user.id}) is_platform_admin revoked.")
            return 0

        memberships = (
            db.query(WorkspaceMembership)
            .filter(WorkspaceMembership.user_id == user.id, WorkspaceMembership.status == WorkspaceMembershipStatus.ACTIVE)
            .all()
        )

        membership = None
        if user.default_workspace_id:
            membership = next((m for m in memberships if m.workspace_id == user.default_workspace_id), None)
        if membership is None:
            membership = next((m for m in memberships if m.role == WorkspaceMemberRole.OWNER), None)
        if membership is None and memberships:
            membership = memberships[0]

        if membership is None:
            db.flush()  # still persist is_platform_admin even though there's no workspace to upgrade yet
            print(
                f"{email} (user_id={user.id}) is now is_platform_admin=True, but has NO workspace membership yet.\n"
                "Register a workspace via the dashboard (or POST /api/v1/auth/register), then re-run this script "
                "to upgrade that workspace to enterprise."
            )
            return 1

        membership.role = WorkspaceMemberRole.OWNER
        membership.status = WorkspaceMembershipStatus.ACTIVE

        workspace = db.query(Workspace).filter(Workspace.id == membership.workspace_id).first()
        if workspace is None:
            print(f"Membership pointed at workspace_id={membership.workspace_id!r}, but that workspace no longer exists.")
            return 1

        workspace.plan = WorkspacePlan.ENTERPRISE
        workspace.max_members = plan_member_limit(WorkspacePlan.ENTERPRISE)
        workspace.max_agents = plan_agent_limit(WorkspacePlan.ENTERPRISE)

        db.flush()

        summary = {
            "email": email,
            "user_id": user.id,
            "role": enum_value(membership.role),
            "workspace_id": workspace.id,
            "workspace_name": workspace.name,
            "plan": enum_value(workspace.plan),
        }

    eligible_count = _count_role_plan_eligible_agents(summary["role"], summary["plan"])

    print("Platform admin granted.")
    print(f"  email          : {summary['email']}")
    print(f"  user_id        : {summary['user_id']}")
    print(f"  role           : {summary['role']}")
    print(f"  workspace      : {summary['workspace_name']} ({summary['workspace_id']})")
    print(f"  plan           : {summary['plan']}")
    if eligible_count >= 0:
        print(f"  role/plan-eligible agents : {eligible_count}/15")
    print(
        "\nThis takes effect immediately -- no re-login required (every API request re-checks the "
        "database directly). Refresh the dashboard to see the Admin sidebar link and updated plan."
    )
    print(
        "\nEligible does not mean assigned/enabled yet -- run "
        f"'python scripts/dev_activate_all_agents.py --email {summary['email']}' to actually enable and assign all "
        "agents to this admin."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
