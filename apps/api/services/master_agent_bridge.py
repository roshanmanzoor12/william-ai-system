"""
apps/api/services/master_agent_bridge.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Wires the real, shared `agents.registry.AgentRegistry` into `core.master_agent.
MasterAgent` so task routing can actually find the 14 specialized agents.

Root cause this fixes: `MasterAgent.__init__(self, config=None,
agent_registry=None, ...)` defaults `self.agent_registry` to an empty dict
when nothing populates it, so every routed step fails with "No suitable
registered agent found" regardless of how correct the Planner/Router logic
is. `apps/api/routes/tasks.py`'s `MASTER_AGENT` hook already tries importing
`apps.api.services.master_agent_bridge.MasterAgentBridge` as its first, most
preferred candidate -- this module is that missing piece.

This module never crashes the app: any agent that fails to import or
instantiate is skipped (not fatal), and the resulting task for that agent
surfaces a structured error instead of taking down the whole pipeline.
"""

from __future__ import annotations

import inspect
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("william.api.services.master_agent_bridge")


# Canonical agent keys, matching agents/registry.py::DEFAULT_AGENT_SPECS and
# agents/capability_manifest.py::AGENT_CAPABILITY_KEYS exactly. This is the
# vocabulary core/planner.py actually emits as `agent_name` on plan steps.
CANONICAL_AGENT_KEYS = [
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


def _build_populated_agent_registry() -> Dict[str, Any]:
    """Import and instantiate every real specialized agent, returning a flat
    {agent_key: instance} dict (plus "<key>_agent" aliases) suitable for
    `MasterAgent(agent_registry=...)`.

    Import-safe: a single broken agent module logs a warning and is skipped
    rather than raising, so registry construction can never crash app boot.
    """
    try:
        from agents.registry import AgentRegistry
    except Exception as exc:  # noqa: BLE001 - import-safe by design
        logger.warning("master_agent_bridge: agents.registry unavailable: %s", exc)
        return {}

    try:
        registry = AgentRegistry(auto_register_defaults=True, auto_import=False, auto_instantiate=False)
        registry.register_default_agents()
    except Exception as exc:  # noqa: BLE001
        logger.warning("master_agent_bridge: failed to build AgentRegistry: %s", exc)
        return {}

    populated: Dict[str, Any] = {}
    for agent_key in CANONICAL_AGENT_KEYS:
        try:
            result = registry.get_or_create_agent_instance(agent_key)
        except Exception as exc:  # noqa: BLE001
            logger.warning("master_agent_bridge: exception building '%s': %s", agent_key, exc)
            continue

        if not isinstance(result, dict) or not result.get("success"):
            error = result.get("error") if isinstance(result, dict) else result
            logger.warning("master_agent_bridge: could not build '%s': %s", agent_key, error)
            continue

        instance = (result.get("data") or {}).get("instance")
        if instance is None:
            logger.warning("master_agent_bridge: '%s' reported success with no instance", agent_key)
            continue

        populated[agent_key] = instance
        populated[f"{agent_key}_agent"] = instance

    logger.info(
        "master_agent_bridge: populated agent_registry with %d/%d canonical agents",
        len({k for k in populated if not k.endswith("_agent")}),
        len(CANONICAL_AGENT_KEYS),
    )
    return populated


class MasterAgentBridge:
    """Drop-in MasterAgent replacement consumed by apps/api/routes/tasks.py's
    (and, where reused, apps/api/routes/auth.py's) OptionalHook/OptionalAgentHook.

    Constructs the real `core.master_agent.MasterAgent` with a real, populated
    agent registry (instead of the empty-dict default) and forwards calls to
    it via `execute()`, the documented BaseAgent-compatible entrypoint.
    """

    def __init__(self, settings: Optional[Any] = None) -> None:
        self.settings = settings
        self.agent_registry: Dict[str, Any] = _build_populated_agent_registry()

        try:
            from core.master_agent import MasterAgent
        except Exception as exc:  # noqa: BLE001
            logger.error("master_agent_bridge: core.master_agent.MasterAgent unavailable: %s", exc)
            self._master_agent = None
            self._init_error = str(exc)
            return

        self._init_error = None
        self._master_agent = MasterAgent(agent_registry=self.agent_registry)

    async def execute(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self._master_agent is None:
            return {
                "success": False,
                "message": "Master Agent could not be constructed.",
                "data": {"registered_agents": list(self.agent_registry.keys())},
                "error": {"code": "MASTER_AGENT_UNAVAILABLE", "detail": self._init_error},
                "metadata": {},
            }

        payload = payload or {}
        result = self._master_agent.execute(payload)
        if inspect.isawaitable(result):
            result = await result
        return result

    def list_agents(self) -> Dict[str, Any]:
        if self._master_agent is None:
            return {
                "success": False,
                "message": "Master Agent could not be constructed.",
                "data": {},
                "error": {"code": "MASTER_AGENT_UNAVAILABLE", "detail": self._init_error},
                "metadata": {},
            }
        return self._master_agent.list_agents()
