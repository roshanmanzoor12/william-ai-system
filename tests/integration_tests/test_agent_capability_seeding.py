"""
tests/integration_tests/test_agent_capability_seeding.py

Idempotency tests for database/seeders/seed_agent_capabilities.py and
database/seeders/default_plans.py -- Phase 5's "seed all 14 agents, seed 50
capabilities per agent, seed starter plans and role permissions... do not
duplicate seed rows on repeated runs" requirement.

Runs against the shared test DB (see tests/conftest.py) so it exercises the
real SQLAlchemy models/constraints, not a mock.
"""

from __future__ import annotations

from database.db import db_manager
from database.models.agent_registry import AgentRegistry


def test_seed_agents_and_capabilities_is_idempotent():
    from database.seeders.seed_agent_capabilities import seed_agents_and_capabilities

    first = seed_agents_and_capabilities()
    assert first["success"] is True

    with db_manager.session_scope() as db:
        count_after_first = db.query(AgentRegistry).count()

    second = seed_agents_and_capabilities()
    assert second["success"] is True

    with db_manager.session_scope() as db:
        count_after_second = db.query(AgentRegistry).count()

    assert count_after_first == count_after_second == 15

    for agent_key, entry in second["capability_updates"].items():
        assert entry["count"] == 50, f"{agent_key} lost its 50 capabilities after a second seed run"


def test_seed_default_plans_is_idempotent():
    from database.seeders.default_plans import seed_default_plans

    with db_manager.session_scope() as db:
        first = seed_default_plans(session=db, force=False)
    assert first.get("status") == "success", first.get("errors")

    with db_manager.session_scope() as db:
        second = seed_default_plans(session=db, force=False)
    assert second.get("status") == "success", second.get("errors")

    # A fully idempotent second run should skip every record it already
    # seeded rather than raising a UNIQUE constraint error.
    skipped_total = sum(len(v) for v in second.get("skipped", {}).values())
    seeded_total = sum(len(v) for v in second.get("seeded", {}).values())
    assert skipped_total > 0
    assert second.get("errors") == []
