"""
agents/capability_manifest.py

Centralized capability manifest system for William/Jarvis.

This module is the single source of truth for the "50 futuristic capabilities per
agent" catalog. It intentionally does NOT replace `agents/registry.py` (agent
class registration/instantiation) or `agents/agent_manifest.py` (agent lifecycle
metadata used by the Master Agent / dashboard health views) — those remain
responsible for what they already own. This module owns *capability-level*
metadata only: what each agent can do, how risky it is, what permission tier it
needs, whether it is actually usable right now, and how it should be verified,
remembered, and audited.

Per-agent capability data lives in `agents/capability_data/<agent_key>.py`, each
exporting a module-level `CAPABILITIES: List[AgentCapabilityEntry]` of exactly 50
entries. This module aggregates those into `AGENT_CAPABILITY_MANIFEST` and never
crashes on a missing/broken per-agent module — a broken capability file degrades
to an empty list for that agent rather than taking down the whole app, consistent
with this codebase's import-safe pattern (see CLAUDE.md).
"""

from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("william.agents.capability_manifest")


class CapabilityRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CapabilityPermissionLevel(str, Enum):
    ALLOWED = "allowed"
    APPROVAL_REQUIRED = "approval_required"
    BLOCKED_BY_DEFAULT = "blocked_by_default"


class CapabilityStatus(str, Enum):
    AVAILABLE = "available"
    CONFIGURED = "configured"
    APPROVAL_REQUIRED = "approval_required"
    EXTERNAL_DEPENDENCY_REQUIRED = "external_dependency_required"
    PLANNED = "planned"
    CAPABILITY_UNAVAILABLE = "capability_unavailable"


@dataclass
class AgentCapabilityEntry:
    """One declared capability belonging to one agent."""

    id: str
    name: str
    description: str
    risk_level: CapabilityRiskLevel
    permission_level: CapabilityPermissionLevel
    status: CapabilityStatus
    required_integrations: List[str] = field(default_factory=list)
    safe_mvp_behavior: str = ""
    verification_method: str = ""
    memory_policy: str = ""
    audit_required: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "risk_level": self.risk_level.value if isinstance(self.risk_level, CapabilityRiskLevel) else self.risk_level,
            "permission_level": self.permission_level.value if isinstance(self.permission_level, CapabilityPermissionLevel) else self.permission_level,
            "status": self.status.value if isinstance(self.status, CapabilityStatus) else self.status,
            "required_integrations": list(self.required_integrations or []),
            "safe_mvp_behavior": self.safe_mvp_behavior,
            "verification_method": self.verification_method,
            "memory_policy": self.memory_policy,
            "audit_required": bool(self.audit_required),
        }


# Canonical capability-bearing agent keys. Deliberately excludes "master" — the
# Master Agent orchestrates the other 14, it does not itself carry a 50-item
# futuristic capability list per the mission spec (AGENT 1-14 below).
AGENT_CAPABILITY_KEYS: List[str] = [
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

REQUIRED_CAPABILITY_COUNT = 50


def _load_agent_capabilities(agent_key: str) -> List[AgentCapabilityEntry]:
    """Import agents.capability_data.<agent_key> and return its CAPABILITIES list.

    Import-safe: any failure (missing module, broken syntax, wrong export) logs
    a warning and yields an empty list rather than raising, so one bad capability
    file can never crash agent registration, the API, or the dashboard.
    """
    module_name = f"agents.capability_data.{agent_key}"
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # noqa: BLE001 - import-safe by design
        logger.warning("capability_manifest: failed to import %s: %s", module_name, exc)
        return []

    capabilities = getattr(module, "CAPABILITIES", None)
    if not isinstance(capabilities, list):
        logger.warning("capability_manifest: %s has no CAPABILITIES list", module_name)
        return []

    valid: List[AgentCapabilityEntry] = []
    for entry in capabilities:
        if isinstance(entry, AgentCapabilityEntry):
            valid.append(entry)
        else:
            logger.warning(
                "capability_manifest: %s contains a non-AgentCapabilityEntry item, skipping", module_name
            )

    if len(valid) != REQUIRED_CAPABILITY_COUNT:
        logger.warning(
            "capability_manifest: %s declares %d capabilities, expected %d",
            module_name,
            len(valid),
            REQUIRED_CAPABILITY_COUNT,
        )

    return valid


def _build_manifest() -> Dict[str, List[AgentCapabilityEntry]]:
    manifest: Dict[str, List[AgentCapabilityEntry]] = {}
    for agent_key in AGENT_CAPABILITY_KEYS:
        manifest[agent_key] = _load_agent_capabilities(agent_key)
    return manifest


# Built once at import time. Re-import agents.capability_manifest after editing a
# capability_data module during development, or call reload_manifest().
AGENT_CAPABILITY_MANIFEST: Dict[str, List[AgentCapabilityEntry]] = _build_manifest()


def reload_manifest() -> Dict[str, List[AgentCapabilityEntry]]:
    """Reload all per-agent capability_data modules and rebuild the manifest."""
    global AGENT_CAPABILITY_MANIFEST
    for agent_key in AGENT_CAPABILITY_KEYS:
        module_name = f"agents.capability_data.{agent_key}"
        try:
            module = importlib.import_module(module_name)
            importlib.reload(module)
        except Exception as exc:  # noqa: BLE001
            logger.warning("capability_manifest: reload failed for %s: %s", module_name, exc)
    AGENT_CAPABILITY_MANIFEST = _build_manifest()
    return AGENT_CAPABILITY_MANIFEST


def get_capabilities(agent_key: str) -> List[AgentCapabilityEntry]:
    return list(AGENT_CAPABILITY_MANIFEST.get(agent_key, []))


def get_capabilities_as_dicts(agent_key: str) -> List[Dict[str, Any]]:
    return [entry.to_dict() for entry in get_capabilities(agent_key)]


def get_capability(agent_key: str, capability_id: str) -> Optional[AgentCapabilityEntry]:
    for entry in AGENT_CAPABILITY_MANIFEST.get(agent_key, []):
        if entry.id == capability_id:
            return entry
    return None


def get_capability_status(agent_key: str, capability_id: str) -> Optional[str]:
    entry = get_capability(agent_key, capability_id)
    if entry is None:
        return None
    return entry.status.value if isinstance(entry.status, CapabilityStatus) else entry.status


def validate_manifest() -> Dict[str, Any]:
    """Return a structured validation report: which agents are missing / short."""
    report: Dict[str, Any] = {"complete": True, "agents": {}}
    for agent_key in AGENT_CAPABILITY_KEYS:
        capabilities = AGENT_CAPABILITY_MANIFEST.get(agent_key, [])
        count = len(capabilities)
        ok = count == REQUIRED_CAPABILITY_COUNT
        if not ok:
            report["complete"] = False
        missing_fields: List[str] = []
        for entry in capabilities:
            for field_name in (
                "id",
                "name",
                "description",
                "risk_level",
                "permission_level",
                "status",
                "safe_mvp_behavior",
                "verification_method",
                "memory_policy",
            ):
                if not getattr(entry, field_name, None):
                    missing_fields.append(f"{entry.id or '?'}::{field_name}")
        report["agents"][agent_key] = {
            "count": count,
            "expected": REQUIRED_CAPABILITY_COUNT,
            "ok": ok,
            "missing_field_entries": missing_fields,
        }
    return report


__all__ = [
    "AgentCapabilityEntry",
    "CapabilityRiskLevel",
    "CapabilityPermissionLevel",
    "CapabilityStatus",
    "AGENT_CAPABILITY_KEYS",
    "AGENT_CAPABILITY_MANIFEST",
    "REQUIRED_CAPABILITY_COUNT",
    "reload_manifest",
    "get_capabilities",
    "get_capabilities_as_dicts",
    "get_capability",
    "get_capability_status",
    "validate_manifest",
]
