"""
database/seeders/seed_agent_capabilities.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Idempotent entrypoint that seeds the real DB agent_registry table with all 15
agents (master + the 14 capability-bearing specialized agents) and stamps
each of the 14 specialized agents' capabilities_json with the full 50
capability IDs from agents/capability_manifest.py.

Safe to run multiple times: agent rows are upserted (not duplicated) by
agents.registry_service.AgentRegistryService.seed_core_agents(), and the
capability-ID update step always overwrites capabilities_json with the
current manifest rather than depending on some other operation not having
touched it in between -- so this script is the reliable, idempotent source
of truth for capability seeding regardless of what else has run before it.

Usage:
    python -m database.seeders.seed_agent_capabilities
"""

from __future__ import annotations

import logging
from typing import Any, Dict

logger = logging.getLogger("william.database.seeders.seed_agent_capabilities")


def seed_agents_and_capabilities(actor_user_id: str = "system", actor_workspace_id: str = "system") -> Dict[str, Any]:
    from database.db import db_manager
    from database.models.agent_registry import agent_registry_service
    from agents.capability_manifest import AGENT_CAPABILITY_KEYS, get_capabilities

    report: Dict[str, Any] = {
        "success": True,
        "agent_registry_seed": None,
        "capability_updates": {},
        "errors": [],
    }

    with db_manager.session_scope() as db:
        seed_result = agent_registry_service.seed_core_agents(
            db=db,
            actor_user_id=actor_user_id,
            actor_workspace_id=actor_workspace_id,
        )
        report["agent_registry_seed"] = {
            "success": seed_result.get("success"),
            "message": seed_result.get("message"),
        }
        if not seed_result.get("success"):
            report["success"] = False
            report["errors"].append({"step": "seed_core_agents", "detail": seed_result.get("error")})

        for agent_key in AGENT_CAPABILITY_KEYS:
            capability_ids = [c.id for c in get_capabilities(agent_key)]
            if len(capability_ids) != 50:
                logger.warning(
                    "seed_agent_capabilities: %s has %d capabilities, expected 50 -- seeding anyway with what's available",
                    agent_key,
                    len(capability_ids),
                )

            update_result = agent_registry_service.update_agent_capabilities(
                db=db,
                agent_key=agent_key,
                capabilities=capability_ids,
                user_id=actor_user_id,
                workspace_id=actor_workspace_id,
            )
            report["capability_updates"][agent_key] = {
                "success": update_result.get("success"),
                "count": len(capability_ids),
            }
            if not update_result.get("success"):
                report["success"] = False
                report["errors"].append({"step": f"update_agent_capabilities:{agent_key}", "detail": update_result.get("error")})

    return report


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    result = seed_agents_and_capabilities()

    complete = all(
        entry.get("count") == 50 and entry.get("success")
        for entry in result["capability_updates"].values()
    )

    print(f"agent_registry_seed: {result['agent_registry_seed']}")
    for agent_key, entry in result["capability_updates"].items():
        print(f"  {agent_key:14s} success={entry['success']} count={entry['count']}")

    if result["errors"]:
        print("errors:", result["errors"])

    print("overall success:", result["success"] and complete)
    return 0 if (result["success"] and complete) else 1


if __name__ == "__main__":
    raise SystemExit(main())
