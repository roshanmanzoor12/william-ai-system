"""
tests/api_tests/test_agents.py

API tests for William / Jarvis agent listing, access, and task execution flows.

These tests run against the REAL FastAPI app (apps.api.main.create_app) with
real, JWT-verified authentication (see tests/api_tests/conftest.py's
make_owner/make_member/set_plan fixtures -- no spoofable X-User-Id-style
headers are used anywhere in this file).

Real endpoint map exercised here (all under /api/v1):
- apps/api/routes/agents.py  -> GET /agents, /agents/catalog, /agents/health,
  /agents/{name}, /agents/{name}/capabilities, /agents/{name}/health,
  /agents/{name}/access, POST /agents/access/check, GET /agents/audit.
- apps/api/routes/tasks.py   -> POST /tasks, POST /tasks/run,
  GET /tasks, GET /tasks/{id}, POST /tasks/{id}/run, GET /tasks/audit.
- apps/api/routes/audit.py   -> GET /audit.

There is no agent-scoped task-execution endpoint (no
POST /agents/{agent}/tasks) in the real system -- "run task on agent X"
is expressed as POST /tasks (or /tasks/run) with `preferred_agent` set,
per apps/api/routes/tasks.py's TaskCreateRequest.

Two real, root-cause application bugs were found and fixed while writing
these tests (see apps/api/routes/agents.py and apps/api/routes/tasks.py's
ROLE_RANK dicts): the real DB-level WorkspaceMemberRole value "member"
(the most common non-owner real role, see database/models/workspace.py)
was never mapped in either file's local ROLE_RANK table, so
ROLE_RANK.get("member", 0) silently fell through to rank 0 -- lower than
even "viewer" -- denying ordinary workspace members every agent/task
action that only requires the baseline Role.USER tier. Fixed by mapping
"member" to the same rank as "user" (20) in both files.

Known, out-of-scope gap intentionally NOT touched by this test file: the
real MasterAgent/SecurityAgent/MemoryAgent bridges invoked from
apps/api/routes/tasks.py (via OptionalHook.call) currently have method
signatures that don't match what tasks.py calls them with (e.g.
`SecurityAgent.check_permission() missing 1 required positional argument:
'action'`, `MasterAgent.handle_request() missing 2 required positional
arguments`), so task *execution* past the security-approval gate always
ends in status "failed" today. That is a deeper, separate integration gap
between apps/api/routes/tasks.py and the real agent implementations, well
beyond what this test file's own URL/auth/contract mismatches call for --
tests below verify routing, isolation, and security-approval gating (all
of which happen before those broken bridge calls) without asserting a
task ever reaches status "completed".
"""

from __future__ import annotations

from typing import Any, Dict

import pytest

from database.db import db_manager
from database.models.user import User


def make_platform_admin(user_id: str) -> None:
    """Flip is_platform_admin=True for an already-registered real user."""

    with db_manager.session_scope() as db:
        user = db.query(User).filter(User.id == user_id).first()
        assert user is not None
        user.is_platform_admin = True


MASTER_AGENT_ID = "master"
SECURITY_AGENT_ID = "security"
MEMORY_AGENT_ID = "memory"
VERIFICATION_AGENT_ID = "verification"

# Authoritative list, mirrors AGENT_CATALOG in apps/api/routes/agents.py.
KNOWN_AGENT_IDS = [
    "master",
    "voice",
    "system",
    "browser",
    "code",
    "memory",
    "security",
    "verification",
    "visual",
    "workflow",
    "hologram",
    "call",
    "business",
    "finance",
    "creator",
]

# Agents whose AgentDefinition.default_enabled is True, or which are in
# AgentRouteSettings.default_enabled_agents -- these are the only agents
# enabled for a brand-new workspace before any admin explicitly enables
# more via POST /agents/{name}/enable.
DEFAULT_ENABLED_AGENT_IDS = {"master", "memory", "security", "verification", "business", "creator"}

# Of the default-enabled agents, these require only the baseline "user"
# role and the "free" plan -- reachable by any owner on a brand-new
# workspace with no plan upgrade.
CORE_FREE_AGENT_IDS = {"master", "memory", "security", "verification"}


def response_json(response: Any) -> Dict[str, Any]:
    try:
        return response.json()
    except Exception as exc:  # pragma: no cover - defensive
        pytest.fail(f"Expected JSON response, got: {response.text!r}. Error: {exc}")


def assert_envelope_success(payload: Dict[str, Any]) -> None:
    assert payload["success"] is True
    assert "data" in payload
    assert payload.get("error") is None
    assert "metadata" in payload


def assert_envelope_error(payload: Dict[str, Any], expected_code: str) -> None:
    assert payload["success"] is False
    assert payload["error"]["code"] == expected_code


class TestAgentListing:
    """GET /api/v1/agents and related read-only agent metadata endpoints."""

    def test_agent_list_requires_auth(self, client) -> None:
        response = client.get("/api/v1/agents")
        assert response.status_code in (401, 403)

    def test_agent_list_returns_all_known_agents_with_safe_shape(self, client, make_owner) -> None:
        owner = make_owner()

        response = client.get("/api/v1/agents", headers=owner.headers)

        assert response.status_code == 200
        payload = response_json(response)
        assert_envelope_success(payload)

        data = payload["data"]
        assert data["isolation"]["user_id"] == owner.user_id
        assert data["isolation"]["workspace_id"] == owner.workspace_id

        agents = data["agents"]
        assert data["count"] == len(KNOWN_AGENT_IDS)
        assert {item["agent"]["agent_name"] for item in agents} == set(KNOWN_AGENT_IDS)

        for item in agents:
            agent = item["agent"]
            assert isinstance(agent["display_name"], str) and agent["display_name"]
            assert isinstance(agent["capabilities"], list) and agent["capabilities"]
            assert "access" in item and "allowed" in item["access"] and "reason" in item["access"]
            assert "workspace_config" in item and "enabled" in item["workspace_config"]

    def test_agent_list_include_disabled_false_hides_disabled_agents(self, client, make_owner) -> None:
        owner = make_owner()

        all_response = response_json(client.get("/api/v1/agents", headers=owner.headers))
        enabled_only_response = response_json(
            client.get("/api/v1/agents", params={"include_disabled": False}, headers=owner.headers)
        )

        assert all_response["data"]["count"] == len(KNOWN_AGENT_IDS)
        enabled_ids = {item["agent"]["agent_name"] for item in enabled_only_response["data"]["agents"]}
        # A brand-new workspace only has DEFAULT_ENABLED_AGENT_IDS turned on.
        assert enabled_ids == DEFAULT_ENABLED_AGENT_IDS

    def test_agent_list_marks_core_free_agents_available_to_owner(self, client, make_owner) -> None:
        owner = make_owner()

        payload = response_json(client.get("/api/v1/agents", headers=owner.headers))
        agents_by_id = {item["agent"]["agent_name"]: item for item in payload["data"]["agents"]}

        for agent_id in CORE_FREE_AGENT_IDS:
            assert agents_by_id[agent_id]["access"]["allowed"] is True, agent_id
            assert agents_by_id[agent_id]["access"]["reason"] == "Access granted."

        # Not enabled for a fresh workspace regardless of the owner's role/plan.
        assert agents_by_id["code"]["access"]["allowed"] is False
        assert "disabled" in agents_by_id["code"]["access"]["reason"].lower()

    def test_agent_list_marks_agents_unavailable_by_role_for_member(
        self, client, make_owner, make_member
    ) -> None:
        owner = make_owner()
        member = make_member(owner, role="viewer")

        payload = response_json(client.get("/api/v1/agents", headers=member.headers))
        agents_by_id = {item["agent"]["agent_name"]: item for item in payload["data"]["agents"]}

        # Viewer rank (10) is below the "user" tier (20) required by the
        # core free agents, so they're denied for role reasons even though
        # those agents are enabled for the workspace.
        for agent_id in CORE_FREE_AGENT_IDS:
            item = agents_by_id[agent_id]
            assert item["access"]["allowed"] is False
            assert "role" in item["access"]["reason"].lower()

    def test_agent_list_member_role_can_reach_core_free_agents(
        self, client, make_owner, make_member
    ) -> None:
        # Regression test for the real ROLE_RANK bug fixed in
        # apps/api/routes/agents.py: the DB-level "member" role must map
        # to at least the "user" tier, not fall through to rank 0.
        owner = make_owner()
        member = make_member(owner, role="member")

        payload = response_json(client.get("/api/v1/agents", headers=member.headers))
        agents_by_id = {item["agent"]["agent_name"]: item for item in payload["data"]["agents"]}

        for agent_id in CORE_FREE_AGENT_IDS:
            item = agents_by_id[agent_id]
            assert item["access"]["allowed"] is True, (agent_id, item["access"])
            assert item["access"]["reason"] == "Access granted."

    def test_agent_list_denies_cross_workspace_query_isolation(
        self, client, make_owner
    ) -> None:
        owner_a = make_owner()
        owner_b = make_owner()

        # There is no workspace_id query override on the real endpoint --
        # the workspace is always taken from the authenticated context, so
        # a caller can never list another workspace's agents by asking for
        # a different workspace_id. Confirm that isolation holds even when
        # a workspace_id belonging to another tenant is supplied.
        response = client.get(
            "/api/v1/agents",
            params={"workspace_id": owner_b.workspace_id},
            headers=owner_a.headers,
        )

        assert response.status_code == 200
        payload = response_json(response)
        assert payload["data"]["isolation"]["workspace_id"] == owner_a.workspace_id
        assert payload["data"]["isolation"]["workspace_id"] != owner_b.workspace_id


class TestAgentCapabilityManifestEndpoint:
    """
    GET /api/v1/agents must return the full 50-capability futuristic
    manifest per agent (agents/capability_manifest.py), not just the older
    short `capabilities` list -- see apps/api/routes/agents.py's
    public_agent_definition(), which adds `capability_manifest` and
    `capability_manifest_meta` alongside the existing `capabilities` field
    without changing its shape (real permission-gate logic elsewhere in that
    file keys off the short list, so it must stay untouched).
    """

    def test_requires_auth(self, client) -> None:
        response = client.get("/api/v1/agents")
        assert response.status_code in (401, 403)

    def test_every_specialized_agent_exposes_fifty_capabilities(self, client, make_owner) -> None:
        from agents.capability_manifest import AGENT_CAPABILITY_KEYS

        owner = make_owner()
        payload = response_json(client.get("/api/v1/agents", headers=owner.headers))
        agents_by_id = {item["agent"]["agent_name"]: item["agent"] for item in payload["data"]["agents"]}

        assert set(AGENT_CAPABILITY_KEYS).issubset(agents_by_id.keys())

        for agent_key in AGENT_CAPABILITY_KEYS:
            agent = agents_by_id[agent_key]
            manifest = agent["capability_manifest"]
            meta = agent["capability_manifest_meta"]

            assert len(manifest) == 50, f"{agent_key} returned {len(manifest)} capabilities, expected 50"
            assert meta["count"] == 50
            assert meta["complete"] is True

            for capability in manifest:
                for field_name in (
                    "id",
                    "name",
                    "description",
                    "risk_level",
                    "permission_level",
                    "status",
                    "required_integrations",
                    "safe_mvp_behavior",
                    "verification_method",
                    "memory_policy",
                    "audit_required",
                ):
                    assert field_name in capability, f"{agent_key} capability missing {field_name}"

    def test_master_agent_has_no_futuristic_capability_manifest(self, client, make_owner) -> None:
        """master is the orchestrator, not one of the 14 capability-bearing
        agents per the mission spec -- its capability_manifest is honestly
        empty rather than padded with fake entries."""
        owner = make_owner()
        payload = response_json(client.get("/api/v1/agents", headers=owner.headers))
        agents_by_id = {item["agent"]["agent_name"]: item["agent"] for item in payload["data"]["agents"]}

        master = agents_by_id["master"]
        assert master["capability_manifest"] == []
        assert master["capability_manifest_meta"]["count"] == 0

    def test_some_capabilities_report_external_dependency_required_honestly(self, client, make_owner) -> None:
        """Missing integrations must surface as external_dependency_required,
        never as a fake success -- confirm at least one real example exists
        in the live API response (voice's STT/TTS-dependent capabilities)."""
        owner = make_owner()
        payload = response_json(client.get("/api/v1/agents", headers=owner.headers))
        agents_by_id = {item["agent"]["agent_name"]: item["agent"] for item in payload["data"]["agents"]}

        voice_manifest = agents_by_id["voice"]["capability_manifest"]
        external_dep_entries = [c for c in voice_manifest if c["status"] == "external_dependency_required"]
        assert external_dep_entries, "expected at least one external_dependency_required capability for voice"
        for entry in external_dep_entries:
            assert entry["required_integrations"], f"{entry['id']} is external_dependency_required with no required_integrations listed"

    def test_get_agent_catalog(self, client, make_owner) -> None:
        owner = make_owner()

        response = client.get("/api/v1/agents/catalog", headers=owner.headers)

        assert response.status_code == 200
        payload = response_json(response)
        assert_envelope_success(payload)
        data = payload["data"]
        assert data["count"] == len(KNOWN_AGENT_IDS)
        assert data["total_named_agents"] == 15
        assert set(data["core_agents"]) == CORE_FREE_AGENT_IDS
        assert {item["agent_name"] for item in data["catalog"]} == set(KNOWN_AGENT_IDS)

    def test_get_agent_returns_agent_for_authorized_user(self, client, make_owner) -> None:
        owner = make_owner()

        response = client.get("/api/v1/agents/memory", headers=owner.headers)

        assert response.status_code == 200
        payload = response_json(response)
        assert_envelope_success(payload)
        assert payload["data"]["agent"]["agent_name"] == "memory"
        assert payload["data"]["isolation"]["user_id"] == owner.user_id
        assert payload["data"]["isolation"]["workspace_id"] == owner.workspace_id

    def test_get_agent_returns_safe_not_found_for_unknown_agent(self, client, make_owner) -> None:
        owner = make_owner()

        response = client.get("/api/v1/agents/not-a-real-agent", headers=owner.headers)

        assert response.status_code == 404
        payload = response_json(response)
        assert_envelope_error(payload, "AGENT_NOT_FOUND")

    def test_get_agent_is_always_readable_regardless_of_access_decision(
        self, client, make_owner, make_member
    ) -> None:
        # GET /agents/{name} never 402/403s on access -- it always returns
        # 200 with the access decision embedded in the payload. This
        # matches the real evaluate_agent_access()/get_agent() contract
        # (apps/api/routes/agents.py), unlike the old imagined contract
        # which expected 402/403 status codes here.
        owner = make_owner()
        viewer = make_member(owner, role="viewer")

        response = client.get("/api/v1/agents/finance", headers=viewer.headers)

        assert response.status_code == 200
        payload = response_json(response)
        assert_envelope_success(payload)
        assert payload["data"]["access"]["allowed"] is False

    def test_get_agent_capabilities(self, client, make_owner) -> None:
        owner = make_owner()

        response = client.get("/api/v1/agents/code/capabilities", headers=owner.headers)

        assert response.status_code == 200
        payload = response_json(response)
        assert_envelope_success(payload)
        assert payload["data"]["agent_name"] == "code"
        assert isinstance(payload["data"]["capabilities"], list) and payload["data"]["capabilities"]

    def test_check_access_endpoint(self, client, make_owner) -> None:
        owner = make_owner()

        response = client.post(
            "/api/v1/agents/access/check",
            headers=owner.headers,
            json={"agent_name": "security"},
        )

        assert response.status_code == 200
        payload = response_json(response)
        assert_envelope_success(payload)
        assert payload["data"]["access"]["agent_name"] == "security"
        assert payload["data"]["access"]["allowed"] is True

    def test_health_all_agents_requires_analyst_role_or_higher(
        self, client, make_owner, make_member
    ) -> None:
        owner = make_owner()
        viewer = make_member(owner, role="viewer")

        denied = client.get("/api/v1/agents/health", headers=viewer.headers)
        assert denied.status_code == 403
        assert_envelope_error(response_json(denied), "INSUFFICIENT_ROLE")

        allowed = client.get("/api/v1/agents/health", headers=owner.headers)
        assert allowed.status_code == 200
        payload = response_json(allowed)
        assert_envelope_success(payload)
        assert payload["data"]["summary"]["total"] == len(KNOWN_AGENT_IDS)

    def test_agents_audit_requires_admin_role(self, client, make_owner, make_member) -> None:
        owner = make_owner()
        manager = make_member(owner, role="manager")

        # ADMIN required -- a manager (below admin rank) must be denied.
        denied = client.get("/api/v1/agents/audit", headers=manager.headers)
        assert denied.status_code == 403

        allowed = client.get("/api/v1/agents/audit", headers=owner.headers)
        assert allowed.status_code == 200
        payload = response_json(allowed)
        assert_envelope_success(payload)
        assert payload["data"]["isolation"]["workspace_id"] == owner.workspace_id


class TestAgentAccessMatrix:
    """Role/plan gating for agents that are enabled by default (core + business/creator)."""

    @pytest.mark.parametrize(
        ("agent_id", "role", "expect_allowed"),
        [
            ("master", "owner", True),
            ("memory", "member", True),
            ("verification", "member", True),
            ("security", "viewer", False),
            ("master", "viewer", False),
        ],
    )
    def test_role_gate_for_core_agents(
        self, client, make_owner, make_member, agent_id, role, expect_allowed
    ) -> None:
        owner = make_owner()
        actor = owner if role == "owner" else make_member(owner, role=role)

        payload = response_json(client.get(f"/api/v1/agents/{agent_id}", headers=actor.headers))
        assert payload["data"]["access"]["allowed"] is expect_allowed

    def test_plan_gate_for_business_and_creator_agents(self, client, make_owner, set_plan) -> None:
        owner = make_owner()

        # Fresh workspace defaults to the "free" plan; business/creator
        # require at least "starter" plan rank, so they start out denied
        # purely on plan even though the owner's role and the agents'
        # default_enabled flag are both satisfied.
        before = response_json(client.get("/api/v1/agents/business", headers=owner.headers))
        assert before["data"]["access"]["allowed"] is False
        assert "plan" in before["data"]["access"]["reason"].lower()

        set_plan(owner.workspace_id, "pro")

        after = response_json(client.get("/api/v1/agents/business", headers=owner.headers))
        assert after["data"]["access"]["allowed"] is True
        assert after["data"]["access"]["reason"] == "Access granted."


class TestAdminEnablesAllAgents:
    """Regression coverage for scripts/dev_activate_all_agents.py's core
    claim: a platform admin can enable every one of the 15 real agents for
    their workspace, and GET /agents's enabled count reflects it -- this is
    workspace-level enablement (POST /agents/{name}/enable), independent of
    per-user assignment (see test_agent_permissions.py)."""

    def test_enabled_count_becomes_fifteen_after_enabling_every_agent(
        self, client, make_owner
    ) -> None:
        owner = make_owner()
        # Enabling every one of the 15 agents includes paid-tier ones
        # (business/creator/voice/... require at least "starter"); a
        # platform admin's dev-only effective_plan bypass is what makes
        # this reachable without a real plan upgrade, matching
        # scripts/dev_activate_all_agents.py's real-world precondition.
        make_platform_admin(owner.user_id)

        before = response_json(client.get("/api/v1/agents", headers=owner.headers))
        before_enabled = sum(
            1 for entry in before["data"]["agents"] if (entry.get("workspace_config") or {}).get("enabled")
        )
        assert before_enabled < len(KNOWN_AGENT_IDS)

        for agent_id in KNOWN_AGENT_IDS:
            response = client.post(
                f"/api/v1/agents/{agent_id}/enable",
                json={"reason": "test_enable_all"},
                headers=owner.headers,
            )
            assert response.status_code == 200, response.text

        after = response_json(client.get("/api/v1/agents", headers=owner.headers))
        after_enabled = sum(
            1 for entry in after["data"]["agents"] if (entry.get("workspace_config") or {}).get("enabled")
        )
        assert after_enabled == len(KNOWN_AGENT_IDS) == 15

    def test_non_admin_role_cannot_enable_agents(self, client, make_owner, make_member) -> None:
        """POST /agents/{name}/enable requires Role.ADMIN or higher
        (require_auth_role) -- a "member" must be rejected before the
        request ever reaches the Security Agent hook."""
        owner = make_owner()
        member = make_member(owner, role="member")

        response = client.post(
            "/api/v1/agents/creator/enable",
            json={"reason": "should be denied"},
            headers=member.headers,
        )
        assert response.status_code == 403

    def test_free_plan_owner_cannot_enable_a_starter_plan_agent(
        self, client, make_owner
    ) -> None:
        """A real (non-admin) owner on the free plan must still be
        plan-gated when calling POST /agents/{name}/enable directly --
        the Security Agent hook fix must not have created a bypass."""
        owner = make_owner()

        response = client.post(
            "/api/v1/agents/business/enable",
            json={"reason": "should be plan-blocked"},
            headers=owner.headers,
        )
        assert response.status_code == 402
        assert response.json()["error"]["code"] == "PLAN_REQUIRED"

    def test_security_review_no_longer_crashes_but_still_requires_real_role_gate(
        self, client, make_owner
    ) -> None:
        """Regression test for the Security Agent hook fix itself: a plan-
        and role-eligible owner enabling a single core agent must succeed
        cleanly (no 500, no SECURITY_AGENT_DENIED from the previous
        check_permission() TypeError), while the enable-endpoint's real
        role/plan gates (proven by the two tests above) remain intact."""
        owner = make_owner()

        response = client.post(
            "/api/v1/agents/memory/enable",
            json={"reason": "core agent, free plan, owner role"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["data"]["workspace_config"]["enabled"] is True


class TestTaskCreationAndIsolation:
    """POST /api/v1/tasks -- the real way to 'run agent X', per tasks.py's TaskCreateRequest."""

    def test_create_task_requires_auth(self, client) -> None:
        response = client.post("/api/v1/tasks", json={"message": "hello", "preferred_agent": "master"})
        assert response.status_code in (401, 403)

    def test_create_task_uses_authenticated_identity_not_payload_supplied_ids(
        self, client, make_owner
    ) -> None:
        # TaskCreateRequest has no user_id/workspace_id fields at all --
        # confirm that even trying to smuggle a foreign identity in the
        # body has no effect; the task is always scoped to the real,
        # JWT-verified caller. This is the real-world equivalent of the
        # old imagined USER_CONTEXT_MISMATCH/WORKSPACE_CONTEXT_MISMATCH
        # checks, whose premise (the server trusting a client-supplied
        # user_id/workspace_id at all) no longer exists post auth-fix.
        owner = make_owner()
        other = make_owner()

        response = client.post(
            "/api/v1/tasks",
            headers=owner.headers,
            json={
                "message": "Create a safe launch checklist.",
                "preferred_agent": "master",
                "input_data": {},
                "user_id": other.user_id,
                "workspace_id": other.workspace_id,
            },
        )

        assert response.status_code == 200
        payload = response_json(response)
        assert_envelope_success(payload)
        task = payload["data"]["task"]
        assert task["user_id"] == owner.user_id
        assert task["workspace_id"] == owner.workspace_id
        assert task["user_id"] != other.user_id
        assert task["workspace_id"] != other.workspace_id

    def test_create_task_for_master_agent_returns_isolated_task_record(
        self, client, make_owner
    ) -> None:
        owner = make_owner()

        response = client.post(
            "/api/v1/tasks",
            headers=owner.headers,
            json={
                "message": "Create a safe launch checklist for the dashboard.",
                "preferred_agent": MASTER_AGENT_ID,
                "input_data": {"source": "test_suite"},
            },
        )

        assert response.status_code == 200
        payload = response_json(response)
        assert_envelope_success(payload)

        task = payload["data"]["task"]
        assert task["preferred_agent"] == MASTER_AGENT_ID
        assert task["user_id"] == owner.user_id
        assert task["workspace_id"] == owner.workspace_id
        assert task["status"] == "created"
        assert task["task_id"]

    def test_create_task_role_gate_denies_viewer(self, client, make_owner, make_member) -> None:
        owner = make_owner()
        viewer = make_member(owner, role="viewer")

        response = client.post(
            "/api/v1/tasks",
            headers=viewer.headers,
            json={"message": "Try to create a task.", "preferred_agent": "master", "input_data": {}},
        )

        assert response.status_code == 403
        assert_envelope_error(response_json(response), "TASK_CREATE_ROLE_REQUIRED")

    def test_create_task_role_gate_allows_member(self, client, make_owner, make_member) -> None:
        # Regression coverage for the real ROLE_RANK bug fixed in
        # apps/api/routes/tasks.py: "member" must be able to create tasks.
        owner = make_owner()
        member = make_member(owner, role="member")

        response = client.post(
            "/api/v1/tasks",
            headers=member.headers,
            json={"message": "Create a task as a member.", "preferred_agent": "master", "input_data": {}},
        )

        assert response.status_code == 200
        payload = response_json(response)
        assert_envelope_success(payload)
        assert payload["data"]["task"]["user_id"] == member.user_id

    def test_every_created_task_has_isolation_and_agent_fields(self, client, make_owner) -> None:
        owner = make_owner()

        created_tasks = []
        for agent_id in ("master", "memory", "verification", "security"):
            response = client.post(
                "/api/v1/tasks",
                headers=owner.headers,
                json={
                    "message": f"Create safe task for {agent_id} agent.",
                    "preferred_agent": agent_id,
                    "input_data": {"batch": "created_task_contract"},
                },
            )
            assert response.status_code == 200
            payload = response_json(response)
            assert_envelope_success(payload)
            created_tasks.append(payload["data"]["task"])

        assert len(created_tasks) == 4
        for task in created_tasks:
            assert task["task_id"]
            assert task["user_id"] == owner.user_id
            assert task["workspace_id"] == owner.workspace_id
            assert task["preferred_agent"] in KNOWN_AGENT_IDS

    def test_task_read_is_scoped_to_same_workspace(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()

        create_response = client.post(
            "/api/v1/tasks",
            headers=owner_a.headers,
            json={"message": "Create isolated task.", "preferred_agent": "master", "input_data": {}},
        )
        task_id = response_json(create_response)["data"]["task"]["task_id"]

        same_owner = client.get(f"/api/v1/tasks/{task_id}", headers=owner_a.headers)
        assert same_owner.status_code == 200
        assert response_json(same_owner)["data"]["task"]["task_id"] == task_id

        other_workspace = client.get(f"/api/v1/tasks/{task_id}", headers=owner_b.headers)
        assert other_workspace.status_code == 403
        assert_envelope_error(response_json(other_workspace), "TASK_SCOPE_DENIED")

    def test_task_read_not_found_is_structured(self, client, make_owner) -> None:
        owner = make_owner()

        response = client.get("/api/v1/tasks/task_does_not_exist", headers=owner.headers)

        assert response.status_code == 404
        assert_envelope_error(response_json(response), "TASK_NOT_FOUND")

    def test_task_list_is_scoped_to_caller(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()

        client.post(
            "/api/v1/tasks",
            headers=owner_a.headers,
            json={"message": "Alpha task.", "preferred_agent": "master", "input_data": {}},
        )
        client.post(
            "/api/v1/tasks",
            headers=owner_b.headers,
            json={"message": "Beta task.", "preferred_agent": "master", "input_data": {}},
        )

        alpha_tasks = response_json(client.get("/api/v1/tasks", headers=owner_a.headers))["data"]["tasks"]
        beta_tasks = response_json(client.get("/api/v1/tasks", headers=owner_b.headers))["data"]["tasks"]

        assert alpha_tasks and all(task["workspace_id"] == owner_a.workspace_id for task in alpha_tasks)
        assert beta_tasks and all(task["workspace_id"] == owner_b.workspace_id for task in beta_tasks)

        alpha_ids = {task["task_id"] for task in alpha_tasks}
        beta_ids = {task["task_id"] for task in beta_tasks}
        assert alpha_ids.isdisjoint(beta_ids)


class TestSensitiveTaskSecurityRouting:
    """
    POST /api/v1/tasks/{id}/run -- sensitive-task Security Agent gating.

    apps/api/routes/tasks.py's looks_sensitive_task() flags a task as
    sensitive by keyword (e.g. "delete", "secret", "credential" --
    see SENSITIVE_ACTION_KEYWORDS). A sensitive task cannot run without
    security approval; supplying approved_by_security on the *run*
    request (TaskRunRequest) is a real, first-class caller-approval path
    (see _run_existing_task's "caller supplied" branch) that does not
    depend on the real SecurityAgent bridge integration.
    """

    def _create_sensitive_task(self, client, actor) -> str:
        response = client.post(
            "/api/v1/tasks",
            headers=actor.headers,
            json={
                "message": "Delete production secrets and credentials.",
                "preferred_agent": "security",
                "input_data": {"target": "production"},
            },
        )
        assert response.status_code == 200
        return response_json(response)["data"]["task"]["task_id"]

    def test_sensitive_task_blocks_without_approval(self, client, make_owner) -> None:
        owner = make_owner()
        task_id = self._create_sensitive_task(client, owner)

        response = client.post(f"/api/v1/tasks/{task_id}/run", headers=owner.headers, json={})

        assert response.status_code == 403
        payload = response_json(response)
        assert_envelope_error(payload, "SECURITY_APPROVAL_REQUIRED")

        # The task itself is left in a safe, inspectable "waiting" state,
        # not silently discarded.
        task_after = response_json(client.get(f"/api/v1/tasks/{task_id}", headers=owner.headers))["data"]["task"]
        assert task_after["status"] == "waiting_security"
        assert task_after["approved_by_security"] is False

    def test_sensitive_task_proceeds_once_caller_supplies_security_approval(
        self, client, make_owner
    ) -> None:
        owner = make_owner()
        task_id = self._create_sensitive_task(client, owner)

        response = client.post(
            f"/api/v1/tasks/{task_id}/run",
            headers=owner.headers,
            json={"approved_by_security": True},
        )

        # No longer blocked at the security gate -- the request is
        # accepted and the task moves past "waiting_security". (Execution
        # itself may still fail downstream due to the unrelated, known
        # MasterAgent bridge signature gap documented at the top of this
        # file -- that is not what this test asserts.)
        assert response.status_code == 200
        payload = response_json(response)
        assert_envelope_success(payload)

        task = payload["data"]["task"]
        assert task["approved_by_security"] is True
        assert task["status"] != "waiting_security"
        assert task["security_result"]["data"]["approved"] is True
        assert task["security_result"]["data"]["caller_supplied"] is True

    def test_non_sensitive_task_run_does_not_require_security_approval(
        self, client, make_owner
    ) -> None:
        owner = make_owner()

        create_response = client.post(
            "/api/v1/tasks",
            headers=owner.headers,
            json={
                "message": "Summarize the current workspace status.",
                "preferred_agent": "master",
                "input_data": {},
            },
        )
        task_id = response_json(create_response)["data"]["task"]["task_id"]

        run_response = client.post(f"/api/v1/tasks/{task_id}/run", headers=owner.headers, json={})

        assert run_response.status_code == 200
        task = response_json(run_response)["data"]["task"]
        assert task["status"] != "waiting_security"
        assert task["security_result"] is None

    def test_sensitive_task_run_denial_does_not_leak_stack_traces_or_secrets(
        self, client, make_owner
    ) -> None:
        owner = make_owner()

        create_response = client.post(
            "/api/v1/tasks",
            headers=owner.headers,
            json={
                "message": "Delete token secret from production.",
                "preferred_agent": "security",
                "input_data": {"api_key": "should-not-be-echoed-back"},
            },
        )
        task_id = response_json(create_response)["data"]["task"]["task_id"]

        response = client.post(f"/api/v1/tasks/{task_id}/run", headers=owner.headers, json={})

        assert response.status_code == 403
        body_text = response.text.lower()
        for blocked_term in ("traceback", "should-not-be-echoed-back", "private_key"):
            assert blocked_term not in body_text


class TestAuditIsolation:
    """GET /api/v1/audit and GET /api/v1/tasks/audit -- MANAGER+ role gate, workspace scoping."""

    def test_workspace_audit_requires_manager_role_or_higher(
        self, client, make_owner, make_member
    ) -> None:
        owner = make_owner()
        viewer = make_member(owner, role="viewer")

        denied = client.get("/api/v1/audit", headers=viewer.headers)
        assert denied.status_code == 403

        allowed = client.get("/api/v1/audit", headers=owner.headers)
        assert allowed.status_code == 200
        payload = response_json(allowed)
        assert_envelope_success(payload)
        assert "events" in payload["data"]

    def test_workspace_audit_does_not_leak_between_workspaces(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()

        alpha_payload = response_json(client.get("/api/v1/audit", headers=owner_a.headers))
        beta_payload = response_json(client.get("/api/v1/audit", headers=owner_b.headers))

        assert_envelope_success(alpha_payload)
        assert_envelope_success(beta_payload)

        for event in alpha_payload["data"]["events"]:
            assert event["workspace_id"] == owner_a.workspace_id
        for event in beta_payload["data"]["events"]:
            assert event["workspace_id"] == owner_b.workspace_id

    def test_task_audit_requires_manager_role_and_records_task_creation(
        self, client, make_owner, make_member
    ) -> None:
        owner = make_owner()
        viewer = make_member(owner, role="viewer")

        denied = client.get("/api/v1/tasks/audit", headers=viewer.headers)
        assert denied.status_code == 403

        client.post(
            "/api/v1/tasks",
            headers=owner.headers,
            json={"message": "Audited task.", "preferred_agent": "master", "input_data": {}},
        )

        audit_response = client.get("/api/v1/tasks/audit", headers=owner.headers)
        assert audit_response.status_code == 200
        audit_payload = response_json(audit_response)
        assert_envelope_success(audit_payload)

        logs = audit_payload["data"]["logs"]
        assert any(log["action"] == "create_task" for log in logs)
        assert all(log["workspace_id"] == owner.workspace_id for log in logs)


class TestResponseContract:
    """Every real endpoint in this module returns the same {success,message,data,error,metadata} envelope."""

    def test_consistent_json_response_contract(self, client, make_owner) -> None:
        owner = make_owner()

        responses = [
            client.get("/api/v1/agents", headers=owner.headers),
            client.post(
                "/api/v1/tasks",
                headers=owner.headers,
                json={"message": "Contract check task.", "preferred_agent": "master", "input_data": {}},
            ),
            client.get("/api/v1/audit", headers=owner.headers),
        ]

        for response in responses:
            assert response.headers["content-type"].startswith("application/json")
            payload = response_json(response)
            assert "success" in payload
            assert "data" in payload
            assert "error" in payload
            assert "metadata" in payload
