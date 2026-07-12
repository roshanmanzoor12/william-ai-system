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

Usage:
    python scripts/dev_activate_all_agents.py --email roshanmanzoor230@gmail.com
    python scripts/dev_activate_all_agents.py --email roshanmanzoor230@gmail.com --password AdminPass123 --workspace-slug digital-promotix-hq
    python scripts/dev_activate_all_agents.py --token <JWT> --api-base-url http://localhost:8000/api/v1
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


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enable and assign all 15 real agents to one admin user/workspace via the real running backend.")
    parser.add_argument("--email", default=None, help="Login email (mutually exclusive with --token).")
    parser.add_argument("--password", default=None, help="Login password. Falls back to WILLIAM_DEV_PASSWORD env var.")
    parser.add_argument("--token", default=None, help="A real JWT access token, instead of --email/--password.")
    parser.add_argument("--workspace-slug", default=None, help="Sanity-check the logged-in workspace's slug matches this (does not target a different workspace).")
    parser.add_argument("--api-base-url", default=os.getenv("WILLIAM_API_BASE_URL", DEFAULT_API_BASE_URL))
    args = parser.parse_args(argv)

    if requests is None:
        return _fail("The 'requests' package is required for this script (pip install requests).")

    base_url = args.api_base_url.rstrip("/")

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

        login = requests.post(f"{base_url}/auth/login", json={"email": args.email, "password": password}, timeout=15)
        if login.status_code != 200 or not login.json().get("success"):
            return _fail(f"Login failed ({login.status_code}): {login.text[:300]}")

        login_data = login.json()["data"]
        token = login_data["tokens"]["access_token"]
        user_id = login_data["user"]["user_id"]
        workspace_id = login_data["workspace"]["workspace_id"]
        workspace_slug = login_data["workspace"].get("slug")
        is_admin = bool(login_data["user"].get("is_platform_admin"))

        print(f"Logged in as {args.email} | user_id={user_id} | workspace={workspace_slug or workspace_id} | is_platform_admin={is_admin}")
        if not is_admin:
            print(
                "WARNING: this user is not a platform admin -- agent enable/assign will still be attempted using their "
                "real workspace role, but plan-gating will NOT be bypassed. Run scripts/grant_platform_admin.py first "
                "if you want the full dev-unlimited behavior."
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
            print(f"  could not enable '{agent_name}': {response.status_code} {body.get('message') or response.text[:200]}")

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

    print(f"\nEnabled via /agents/*/enable : {len(enabled)}/{len(ALL_AGENT_NAMES)} ({', '.join(enabled) or 'none'})")
    if failed:
        print(f"Failed to enable            : {', '.join(failed)}")
    print(f"Assigned via /agent-permissions : {len(enabled)} agent(s) to user_id={user_id}")
    print(f"/agents now reports enabled  : {enabled_count}/{total_count}")
    print(
        "\nNote: 'enabled'/'assigned' is not the same as 'active' -- active means a real task or worker has actually "
        "run recently, which this script never fakes. Voice/System agents may show runtime_state=dependency_required "
        "or device_worker_offline even while enabled, honestly, until real providers/workers are connected."
    )

    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
