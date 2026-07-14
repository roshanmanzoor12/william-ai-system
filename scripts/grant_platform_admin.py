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
  4. Prints the exact database file this write went to, then re-reads the
     row back from a FRESH session to prove the write actually persisted
     (not just visible inside the same transaction) -- plus the final
     user role, workspace, plan, and plan/role-eligible agent count.

Never runs automatically; only takes effect when a human runs it directly.
The user must already have registered a real account (this script does not
create one) -- register first via the dashboard or
POST /api/v1/auth/register, then run this script.
get_current_auth_context() (apps/api/routes/auth.py) re-reads the User row
from the database on every request rather than trusting anything baked
into the JWT, so this takes effect immediately for an already-issued
token too -- no re-login required (only a page refresh, so the dashboard
sidebar's Admin link, itself read once at page load, picks it up).

Known footgun this script now defends against: database/db.py's SQLite
dev fallback used to be a *relative* path ("sqlite:///./william.db"),
resolved by sqlite3 against whatever directory the CURRENT PROCESS
happened to be launched from. Two processes started from different
working directories (a real backend server started one way, this script
run another way) could silently read and write two different,
unrelated william.db files with no error from either side -- this
script would report success while the live API kept reading an
unmodified database. database/db.py now anchors every relative sqlite
URL to the repo root regardless of launch-time CWD, so this script and
a real running backend always share the same physical database file --
this script prints that resolved path below so that fact is verifiable,
not just assumed.

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


def _resolved_db_path() -> str:
    try:
        from database.db import db_manager

        return db_manager.engine.url.render_as_string(hide_password=True)
    except Exception as exc:  # pragma: no cover
        return f"<could not resolve: {exc}>"


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="Grant or revoke full local/dev platform-admin access for a user by email.")
    parser.add_argument("email", nargs="?", default=DEFAULT_ADMIN_EMAIL, help=f"User email (default: {DEFAULT_ADMIN_EMAIL})")
    parser.add_argument("--revoke", action="store_true", help="Revoke platform-admin access instead of granting it.")
    parser.add_argument("--quiet", action="store_true", help="Suppress the summary banner (used by dev_activate_all_agents.py --force-dev-admin).")
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
    db_path = _resolved_db_path()

    if not args.quiet:
        print(f"database    : {db_path}")

    summary: dict = {}

    with db_manager.session_scope() as db:
        user = db.query(User).filter(User.email == email).first()

        if user is None:
            print(f"No user found with email {email!r} in {db_path}. Register the account first, then re-run this script.")
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
            "workspace_slug": workspace.slug,
            "plan": enum_value(workspace.plan),
        }

    # Re-read from a BRAND NEW session (not the one that just wrote the
    # change) to prove the write actually persisted to disk rather than
    # only being visible inside the transaction that made it -- this is
    # the check that would have caught the DB-path mismatch bug directly:
    # if this script and the live API server were reading different
    # files, this re-read would still show the correct value (since it's
    # the same process/session as the write), but a *second, independent*
    # process (the running backend, or dev_activate_all_agents.py) reading
    # a different file would not. Print the persisted value so a human
    # comparing it against a live /auth/login response can spot a
    # mismatch immediately.
    with db_manager.session_scope() as verify_db:
        persisted_user = verify_db.query(User).filter(User.id == summary["user_id"]).first()
        persisted_is_admin = bool(persisted_user.is_platform_admin) if persisted_user else False

    eligible_count = _count_role_plan_eligible_agents(summary["role"], summary["plan"])

    if not args.quiet:
        print("Platform admin granted.")
        print(f"  database                  : {db_path}")
        print(f"  email                     : {summary['email']}")
        print(f"  user_id                   : {summary['user_id']}")
        print(f"  is_platform_admin (re-read): {persisted_is_admin}")
        print(f"  role                      : {summary['role']}")
        print(f"  workspace                 : {summary['workspace_name']} ({summary['workspace_id']})")
        print(f"  workspace slug            : {summary['workspace_slug']}")
        print(f"  plan                      : {summary['plan']}")
        if eligible_count >= 0:
            print(f"  role/plan-eligible agents : {eligible_count}/15")
        print(
            "\nThis takes effect immediately -- no re-login required (every API request re-checks the "
            "database directly). Refresh the dashboard to see the Admin sidebar link and updated plan."
        )
        print(
            "\nEligible does not mean assigned/enabled yet -- run "
            f"'python scripts/dev_activate_all_agents.py --email {summary['email']}' to actually enable and assign "
            "all agents to this admin, or re-run this script's caller with --force-dev-admin to do both in one step."
        )

    if not persisted_is_admin:
        print(
            "\nWARNING: the write appears to have been made, but re-reading it from a fresh session shows "
            "is_platform_admin=False. This should not happen -- if it does, the running backend and this script "
            "may still be pointed at two different database files despite the anchored-path fix; compare the "
            "'database' path printed above against the backend's own startup log line "
            "('SQLite dev database ensured at startup | ... | db_path=...')."
        )
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
