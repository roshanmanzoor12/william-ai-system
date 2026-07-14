"""
scripts/dev_activate_all_agents.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Local dev helper: enables and assigns all 15 real agents to one admin
user/workspace, via the REAL running backend's HTTP API -- not by
importing/mutating apps.api.routes.agents.AGENT_STORE directly.

AGENT_STORE (workspace-level agent enable/disable + per-user allow/deny
lists) is an in-memory dict that lives inside the running FastAPI server
process. A standalone script that imports apps.api.main and pokes
AGENT_STORE directly would mutate its OWN private copy of that store, with
zero effect on the actual server your dashboard/browser is talking to --
the same class of "looks like it worked, did nothing" bug this whole
codebase's real-vs-fake plumbing work has been about avoiding. So this
script is an HTTP client (same shape as apps/worker_nodes/voice/
voice_worker.py), not an in-process mutator.

For each of the 15 real agents (agents.py::AGENT_CATALOG):
  1. POST /agents/{name}/enable  -- workspace-level activation (goes
     through the real SecurityAgent/audit/memory/verification hooks
     apps/api/routes/agents.py::enable_agent already has; this script adds
     no bypass of its own).
  2. Assigns the target user to that agent via
     PUT /agent-permissions/{user_id}?workspace_id=... (one call at the
     end with all successfully-enabled agent keys) -- the same endpoint
     apps/dashboard/src/app/(dashboard)/admin/agent-access/page.tsx uses.

Never fakes "active" runtime state -- "enabled" (workspace activation +
user assignment) and "active" (a real task/worker actually ran recently)
are different things; this script only ever touches the former. Security-
routed agents stay security-routed: enabling them here goes through the
same real security_review() call as always, it just doesn't require a
human to click through the dashboard for each of the 15.

Previously-live bug this script helped surface (fixed in database/db.py
and apps/api/routes/agents.py, not here): a relative SQLite dev-database
path resolved against the CURRENT PROCESS's working directory meant a
script run from one directory and a backend server started from another
could silently read/write two different william.db files -- so
scripts/grant_platform_admin.py could report success while a fresh
/auth/login against the real running server still showed
is_platform_admin=False, and every /agents/{name}/enable call then hit a
second, independent bug: the Security Agent hook crashed with a bare
TypeError (caught and turned into a blanket 403) for every single agent,
regardless of role, because it was being called with an incompatible
argument shape. Both are now fixed at the root (database/db.py anchors
relative sqlite:/// paths to the repo root regardless of launch-time CWD;
apps/api/routes/agents.py's OptionalAgentHook now calls check_permission
with the arguments it actually requires). This script's diagnostics below
are designed to make either bug immediately visible again if it recurs.

Usage:
    python scripts/dev_activate_all_agents.py --email roshanmanzoor230@gmail.com
    python scripts/dev_activate_all_agents.py --email roshanmanzoor230@gmail.com --password AdminPass123 --workspace-slug digital-promotix-hq
    python scripts/dev_activate_all_agents.py --token <JWT> --api-base-url http://localhost:8000/api/v1

    # Grants platform-admin (scripts/grant_platform_admin.py) for --email
    # first, in-process against the same database, then logs in and
    # enables/assigns all 15 agents in one step:
    python scripts/dev_activate_all_agents.py --email roshanmanzoor230@gmail.com --password AdminPass123 --force-dev-admin
"""

from __future__ import annotations

import argparse
import os
import sys

try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore

DEFAULT_API_BASE_URL = "http://localhost:8000/api/v1"

# Mirrors apps/api/routes/agents.py::AGENT_CATALOG exactly (all 15 real
# agent_name keys) -- kept as an explicit list rather than importing the
# FastAPI app (this script must run as a separate process/machine from the
# backend it's calling, same reasoning as apps/worker_nodes/voice/
# voice_worker.py).
ALL_AGENT_NAMES = [
    "master",
    "security",
    "verification",
    "memory",
    "code",
    "browser",
    "voice",
    "system",
    "visual",
    "workflow",
    "hologram",
    "call",
    "business",
    "finance",
    "creator",
]


def _fail(message: str) -> int:
    print(f"ERROR: {message}", file=sys.stderr)
    return 1


def _run_force_dev_admin(email: str) -> bool:
    """
    Runs scripts/grant_platform_admin.py's real logic in-process, against
    the same database this process would otherwise only read via HTTP.
    This is safe (unlike touching AGENT_STORE) because User.is_platform_admin
    and Workspace.plan are real, persisted DB rows -- not an in-memory
    per-process cache -- so writing them here is visible to the live
    backend server on its very next request, same as running
    grant_platform_admin.py as its own separate process would be.

    grant_platform_admin.py lives in this same scripts/ directory, so a
    bare `import grant_platform_admin` resolves it directly (Python adds a
    directly-run script's own directory to sys.path[0]) without needing a
    scripts/__init__.py package marker.
    """
    try:
        import grant_platform_admin as gpa
    except Exception as exc:
        print(f"WARNING: --force-dev-admin could not import grant_platform_admin.py: {exc}")
        return False

    print(f"\n--force-dev-admin: granting platform admin for {email} before logging in...")
    exit_code = gpa.main([email, "--quiet"])
    if exit_code != 0:
        print("WARNING: --force-dev-admin's grant step did not report success; continuing to login anyway.")
        return False

    print(f"--force-dev-admin: platform admin granted for {email}.\n")
    return True


def _db_check_is_platform_admin(email: str) -> "bool | None":
    """
    Best-effort, READ-ONLY cross-check against the same database
    grant_platform_admin.py writes to -- unlike AGENT_STORE, User rows are
    real and shared, so reading (never writing) them here from a second
    process is safe and is exactly the kind of independent-process check
    that would have caught the relative-sqlite-path bug immediately: if
    this prints a different value than the login response below, the two
    processes are still reading different database files.
    Returns None if the database package isn't importable from here
    (e.g. running against a remote deployment with no local DB access).
    """
    try:
        from database.db import db_manager
        from database.models.user import User

        with db_manager.session_scope() as db:
            user = db.query(User).filter(User.email == email.strip().lower()).first()
            if user is None:
                return None
            return bool(user.is_platform_admin)
    except Exception:
        return None


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enable and assign all 15 real agents to one admin user/workspace via the real running backend.")
    parser.add_argument("--email", default=None, help="Login email (mutually exclusive with --token).")
    parser.add_argument("--password", default=None, help="Login password. Falls back to WILLIAM_DEV_PASSWORD env var.")
    parser.add_argument("--token", default=None, help="A real JWT access token, instead of --email/--password.")
    parser.add_argument("--workspace-slug", default=None, help="Sanity-check the logged-in workspace's slug matches this (does not target a different workspace).")
    parser.add_argument("--api-base-url", default=os.getenv("WILLIAM_API_BASE_URL", DEFAULT_API_BASE_URL))
    parser.add_argument(
        "--force-dev-admin",
        action="store_true",
        help="Development only: run scripts/grant_platform_admin.py's grant logic for --email first (same database, in-process), then log in and enable/assign all agents in one step.",
    )
    args = parser.parse_args(argv)

    if requests is None:
        return _fail("The 'requests' package is required for this script (pip install requests).")

    base_url = args.api_base_url.rstrip("/")
    print(f"API base URL: {base_url}")

    if args.force_dev_admin:
        if not args.email:
            return _fail("--force-dev-admin requires --email.")
        _run_force_dev_admin(args.email)

    token = args.token
    user_id = None
    workspace_id = None
    workspace_slug = None

    if not token:
        if not args.email:
            return _fail("Provide either --token, or --email (+ --password / WILLIAM_DEV_PASSWORD).")

        password = args.password or os.getenv("WILLIAM_DEV_PASSWORD")
        if not password:
            return _fail("No password given -- pass --password or set WILLIAM_DEV_PASSWORD.")

        db_is_admin = _db_check_is_platform_admin(args.email)

        login = requests.post(f"{base_url}/auth/login", json={"email": args.email, "password": password}, timeout=15)
        if login.status_code != 200 or not login.json().get("success"):
            return _fail(f"Login failed ({login.status_code}): {login.text[:300]}")

        login_data = login.json()["data"]
        token = login_data["tokens"]["access_token"]
        user_id = login_data["user"]["user_id"]
        workspace_id = login_data["workspace"]["workspace_id"]
        workspace_slug = login_data["workspace"].get("slug")
        is_admin = bool(login_data["user"].get("is_platform_admin"))

        print(f"Logged in as {args.email} | user_id={user_id} | workspace_id={workspace_id} | workspace_slug={workspace_slug or '(none)'}")
        print(f"  login response is_platform_admin : {is_admin}")
        print(f"  DB row is_platform_admin (cross-check) : {db_is_admin if db_is_admin is not None else 'unavailable (no local DB access from this process)'}")

        if db_is_admin is not None and db_is_admin != is_admin:
            print(
                "WARNING: the database row and the live login response DISAGREE on is_platform_admin. "
                "This is exactly the symptom of the backend server and this script reading two different "
                "database files -- compare this process's resolved DB path against the backend server's own "
                "startup log line ('SQLite dev database ensured at startup | ... | db_path=...')."
            )

        if not is_admin:
            print(
                "WARNING: this user is not a platform admin according to the live backend -- agent enable/assign "
                "will still be attempted using their real workspace role, but plan-gating will NOT be bypassed. "
                "Run 'python scripts/grant_platform_admin.py' first, or re-run this command with "
                "--force-dev-admin, if you want the full dev-unlimited behavior."
            )
        if args.workspace_slug and workspace_slug and args.workspace_slug != workspace_slug:
            print(
                f"WARNING: --workspace-slug={args.workspace_slug!r} does not match this login's actual workspace "
                f"({workspace_slug!r}). Proceeding with the real logged-in workspace ({workspace_slug!r}) -- this "
                "script only ever acts on the admin's own current workspace, never an arbitrary one."
            )

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    if user_id is None:
        me = requests.get(f"{base_url}/agents", headers=headers, timeout=15)
        if me.status_code != 200:
            return _fail(f"Could not resolve identity from token ({me.status_code}): {me.text[:300]}")
        isolation = me.json().get("data", {}).get("isolation") or {}
        user_id = isolation.get("user_id")
        workspace_id = isolation.get("workspace_id")
        if not user_id or not workspace_id:
            return _fail("Could not resolve user_id/workspace_id for the given --token.")

    enabled: list[str] = []
    failed: list[str] = []

    for agent_name in ALL_AGENT_NAMES:
        response = requests.post(f"{base_url}/agents/{agent_name}/enable", json={"reason": "dev_activate_all_agents"}, headers=headers, timeout=15)
        body = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        if response.status_code == 200 and body.get("success"):
            enabled.append(agent_name)
        else:
            failed.append(agent_name)
            error = body.get("error")
            reason = None
            if isinstance(error, dict):
                reason = error.get("code")
                details = error.get("details")
                if isinstance(details, dict):
                    # security_review()'s raw result is embedded here when
                    # SECURITY_AGENT_DENIED -- surface the actual denial
                    # message/error instead of just the generic wrapper.
                    inner_message = details.get("message")
                    inner_error = details.get("error")
                    if inner_message or inner_error:
                        reason = f"{reason}: {inner_message or ''} {inner_error or ''}".strip()
            print(f"  could not enable '{agent_name}': {response.status_code} {body.get('message') or response.text[:200]} | reason={reason or 'unknown'}")

    if enabled:
        assign = requests.put(
            f"{base_url}/agent-permissions/{user_id}?workspace_id={workspace_id}",
            json={"target_user_id": user_id, "assigned_agents": enabled},
            headers=headers,
            timeout=15,
        )
        if assign.status_code != 200:
            print(f"WARNING: agent-permissions assignment failed ({assign.status_code}): {assign.text[:300]}")

    agents_list = requests.get(f"{base_url}/agents", headers=headers, timeout=15)
    enabled_count = 0
    total_count = 0
    if agents_list.status_code == 200:
        entries = agents_list.json().get("data", {}).get("agents", [])
        total_count = len(entries)
        enabled_count = sum(1 for entry in entries if (entry.get("workspace_config") or {}).get("enabled"))

    permissions = requests.get(f"{base_url}/agent-permissions?workspace_id={workspace_id}", headers=headers, timeout=15)
    assigned_count = 0
    if permissions.status_code == 200:
        users = permissions.json().get("data", {}).get("users", [])
        me_entry = next((u for u in users if u.get("user_id") == user_id), None)
        if me_entry:
            assigned_count = len(me_entry.get("assigned_agents", []))

    print(f"\nEnabled via /agents/*/enable    : {len(enabled)}/{len(ALL_AGENT_NAMES)} ({', '.join(enabled) or 'none'})")
    if failed:
        print(f"Failed to enable                : {', '.join(failed)}")
    print(f"/agents now reports Enabled      : {enabled_count}/{total_count}")
    print(f"/agent-permissions reports Assigned : {assigned_count} agent(s) for user_id={user_id}")
    print(
        "\nNote: 'enabled'/'assigned' is not the same as 'active' -- active means a real task or worker has actually "
        "run recently, which this script never fakes. Voice/System agents may show runtime_state=dependency_required "
        "or device_worker_offline even while enabled, honestly, until real providers/workers are connected."
    )

    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
