"""
tests/agent_tests/test_capability_manifest.py

Regression tests for agents/capability_manifest.py and its 14 per-agent
agents/capability_data/*.py modules -- the "50 futuristic capabilities per
agent" catalog. Also covers agent_execution_adapter's crash-safety guarantee
(a live smoke test that discovered and fixed every specialized agent's
generic-dispatch bug) and the MasterAgentBridge registry-unification fix.
"""

from __future__ import annotations

import pytest

from agents.capability_manifest import (
    AGENT_CAPABILITY_KEYS,
    REQUIRED_CAPABILITY_COUNT,
    AgentCapabilityEntry,
    get_capabilities,
    validate_manifest,
)


@pytest.fixture(scope="module")
def shared_master_agent_bridge():
    """
    Module-scoped: constructing MasterAgentBridge builds a real
    agents.registry.AgentRegistry and instantiates all 14 real specialized
    agent classes underneath it. Sharing one instance across every test in
    this file (instead of each test building its own) keeps this file's
    total real-agent-instantiation footprint low relative to the rest of
    the suite, which otherwise made the full `pytest` run flaky (some
    unrelated tests elsewhere in the suite failed only when run after many
    fresh agent instantiations had accumulated in the same process).
    """
    from apps.api.services.master_agent_bridge import MasterAgentBridge

    return MasterAgentBridge()


def test_exactly_fourteen_capability_bearing_agents():
    assert len(AGENT_CAPABILITY_KEYS) == 14
    assert "master" not in AGENT_CAPABILITY_KEYS


@pytest.mark.parametrize("agent_key", list(AGENT_CAPABILITY_KEYS))
def test_each_agent_has_exactly_fifty_capabilities(agent_key):
    capabilities = get_capabilities(agent_key)
    assert len(capabilities) == REQUIRED_CAPABILITY_COUNT == 50, (
        f"{agent_key} has {len(capabilities)} capabilities, expected 50"
    )


@pytest.mark.parametrize("agent_key", list(AGENT_CAPABILITY_KEYS))
def test_every_capability_has_required_metadata(agent_key):
    required_fields = (
        "id",
        "name",
        "description",
        "risk_level",
        "permission_level",
        "status",
        "safe_mvp_behavior",
        "verification_method",
        "memory_policy",
    )

    for entry in get_capabilities(agent_key):
        assert isinstance(entry, AgentCapabilityEntry)
        for field_name in required_fields:
            value = getattr(entry, field_name)
            assert value, f"{agent_key}::{entry.id} missing {field_name}"
        assert isinstance(entry.audit_required, bool)
        assert isinstance(entry.required_integrations, list)


def test_capability_ids_are_unique_within_each_agent():
    for agent_key in AGENT_CAPABILITY_KEYS:
        ids = [entry.id for entry in get_capabilities(agent_key)]
        assert len(ids) == len(set(ids)), f"{agent_key} has duplicate capability ids"


def test_capability_ids_are_globally_unique_across_agents():
    all_ids = []
    for agent_key in AGENT_CAPABILITY_KEYS:
        all_ids.extend(entry.id for entry in get_capabilities(agent_key))
    assert len(all_ids) == len(set(all_ids)), "capability ids collide across agents"
    assert len(all_ids) == 700


def test_validate_manifest_reports_complete():
    report = validate_manifest()
    assert report["complete"] is True
    for agent_key in AGENT_CAPABILITY_KEYS:
        agent_report = report["agents"][agent_key]
        assert agent_report["ok"] is True
        assert agent_report["count"] == 50
        assert agent_report["missing_field_entries"] == []


def test_status_vocabulary_matches_mission_spec():
    allowed_statuses = {
        "available",
        "configured",
        "approval_required",
        "external_dependency_required",
        "planned",
        "capability_unavailable",
    }
    for agent_key in AGENT_CAPABILITY_KEYS:
        for entry in get_capabilities(agent_key):
            status_value = entry.status.value if hasattr(entry.status, "value") else entry.status
            assert status_value in allowed_statuses, f"{agent_key}::{entry.id} has invalid status {status_value}"


def test_permission_vocabulary_matches_mission_spec():
    allowed = {"allowed", "approval_required", "blocked_by_default"}
    for agent_key in AGENT_CAPABILITY_KEYS:
        for entry in get_capabilities(agent_key):
            value = entry.permission_level.value if hasattr(entry.permission_level, "value") else entry.permission_level
            assert value in allowed, f"{agent_key}::{entry.id} has invalid permission_level {value}"


def test_risk_vocabulary_matches_mission_spec():
    allowed = {"low", "medium", "high", "critical"}
    for agent_key in AGENT_CAPABILITY_KEYS:
        for entry in get_capabilities(agent_key):
            value = entry.risk_level.value if hasattr(entry.risk_level, "value") else entry.risk_level
            assert value in allowed, f"{agent_key}::{entry.id} has invalid risk_level {value}"


def test_at_least_some_capabilities_require_approval_per_agent():
    """
    Sensitive-action agents (security/finance/system especially) should have
    real approval-gated capabilities, not just "allowed" ones -- otherwise
    the capability catalog would misrepresent real risk.
    """
    for agent_key in ("security", "finance", "system"):
        approval_flagged = [
            entry
            for entry in get_capabilities(agent_key)
            if (entry.permission_level.value if hasattr(entry.permission_level, "value") else entry.permission_level)
            in {"approval_required", "blocked_by_default"}
        ]
        assert approval_flagged, f"{agent_key} has no approval_required/blocked_by_default capabilities"


def test_finance_agent_hard_blocks_auto_transfer_and_credential_storage():
    """
    CLAUDE.md / mission hard rule: Finance Agent must never execute real
    transactions or store bank/card credentials. The capability manifest
    entries describing these refusals must be BLOCKED_BY_DEFAULT, not merely
    "approval_required" (a human approving away a fundamental safety rule is
    not the same guarantee as a hard-coded refusal).
    """
    finance_capabilities = {entry.name: entry for entry in get_capabilities("finance")}
    hard_block_names = [
        name for name in finance_capabilities if "auto-transfer" in name.lower() or "credentials" in name.lower()
    ]
    assert hard_block_names, "expected at least one auto-transfer/credential-storage capability in finance manifest"

    for name in hard_block_names:
        entry = finance_capabilities[name]
        value = entry.permission_level.value if hasattr(entry.permission_level, "value") else entry.permission_level
        assert value == "blocked_by_default", f"finance::{name} must be blocked_by_default, got {value}"


class TestAgentExecutionAdapterCrashSafety:
    """
    A live smoke test (run manually during development) discovered every one
    of the 14 specialized agents crashed with a TypeError/AttributeError when
    invoked through BaseAgent's inherited execute_task() pipeline, due to
    each agent's own incompatible overrides of BaseAgent's internal hooks.
    agents/agent_execution_adapter.py fixes this by calling each agent's own
    real entrypoint (run_task/handle_task/arun/run/execute) directly instead.
    This test locks in that no specialized agent instance can crash the
    adapter for a generic/unsupported task -- it must always return a
    structured, non-exception result.
    """

    @pytest.mark.asyncio
    async def test_no_specialized_agent_raises_on_generic_task(self, shared_master_agent_bridge):
        from apps.api.services.master_agent_bridge import CANONICAL_AGENT_KEYS
        from agents.agent_execution_adapter import call_agent

        registry = shared_master_agent_bridge.agent_registry
        assert registry, "expected at least one real agent instance to be built"

        results = {}
        for agent_key in CANONICAL_AGENT_KEYS:
            agent = registry.get(agent_key)
            task = {
                "message": "generic smoke-test task",
                "action": "general_request",
                "user_id": "test_user_1",
                "workspace_id": "test_workspace_1",
                "input_data": {},
                "permissions": [],
                "metadata": {},
            }
            # call_agent() must never raise -- any agent-side exception is
            # caught internally and returned as a structured error.
            result = await call_agent(agent, task, agent_name=agent_key)
            results[agent_key] = result

        for agent_key, result in results.items():
            assert isinstance(result, dict), f"{agent_key} adapter result was not a dict"
            assert "success" in result, f"{agent_key} adapter result missing 'success'"
            assert "error" in result, f"{agent_key} adapter result missing 'error'"


class TestMasterAgentRegistryUnification:
    """
    core.master_agent.MasterAgent.__init__ defaults self.agent_registry to an
    empty dict when nothing populates it -- the confirmed root cause of "No
    suitable registered agent found" for every real task. MasterAgentBridge
    (apps/api/services/master_agent_bridge.py) fixes this by injecting a
    real, populated registry built from agents/registry.py::AgentRegistry.
    """

    def test_master_agent_bridge_populates_all_fourteen_agents(self, shared_master_agent_bridge):
        from apps.api.services.master_agent_bridge import CANONICAL_AGENT_KEYS

        bridge = shared_master_agent_bridge
        assert bridge._master_agent is not None, "MasterAgentBridge failed to construct a real MasterAgent"

        registered = {key for key in bridge.agent_registry if not key.endswith("_agent")}
        for agent_key in CANONICAL_AGENT_KEYS:
            assert agent_key in registered, f"{agent_key} missing from MasterAgent's real agent_registry"

    @pytest.mark.asyncio
    async def test_master_agent_never_reports_no_suitable_agent_for_real_task(self, shared_master_agent_bridge):
        bridge = shared_master_agent_bridge

        result = await bridge.execute(
            {
                "message": "Summarize our current CRM pipeline status",
                "user_id": "test_user_1",
                "workspace_id": "test_workspace_1",
                "action": "general_request",
                "preferred_agent": "business",
                "input_data": {},
                "permissions": {},
                "metadata": {"role": "owner", "plan": "free"},
            }
        )
        assert isinstance(result, dict)
        # The specific business-action vocabulary may still be rejected
        # (a separate, smaller Planner<->BusinessAgent action-naming gap),
        # but it must never be the empty-registry failure mode.
        serialized = str(result)
        assert "No suitable registered agent found" not in serialized


class TestVerificationAgentAdapter:
    """
    agents.verification_agent.verification_agent.VerificationAgent.verify_task
    takes `context` and `task_payload` as separate required arguments, not a
    single combined dict. core/verification_bridge.py's
    _send_to_verification_agent() and apps/api/services/
    verification_agent_bridge.py's VerificationAgentBridge both split a
    single payload into that real shape -- this locks in that the real,
    live VerificationAgent instance reachable through MasterAgentBridge
    actually verifies a completed task without raising.
    """

    def test_verification_bridge_verifies_a_completed_task(self, shared_master_agent_bridge):
        verification_bridge = shared_master_agent_bridge._master_agent.verification_bridge
        assert verification_bridge is not None

        result = verification_bridge.verify_completed_task(
            task_payload={
                "user_id": "test_user_1",
                "workspace_id": "test_workspace_1",
                "task_id": "test_task_1",
                "action_type": "business_assist",
                "task": {"action": "business_assist"},
            },
            completed_result={"success": True, "data": {}},
        )

        assert isinstance(result, dict)
        assert result.get("success") is True
        assert result.get("error") is None

    @pytest.mark.asyncio
    async def test_verification_agent_bridge_execute_task_splits_payload_correctly(self):
        from apps.api.services.verification_agent_bridge import VerificationAgentBridge

        bridge = VerificationAgentBridge()

        result = await bridge.execute_task(
            {
                "type": "auth_register_confirmation",
                "user_id": "test_user_1",
                "workspace_id": "test_workspace_1",
                "request_id": "req_1",
                "result": "success",
            }
        )
        assert isinstance(result, dict)
        assert result.get("success") is True
        assert result.get("error") is None
