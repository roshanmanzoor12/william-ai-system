"""Per-agent capability data modules for agents.capability_manifest.

Each sibling module (voice.py, system.py, browser.py, ...) exports a
module-level CAPABILITIES list of exactly 50 AgentCapabilityEntry objects.
Kept as plain data modules (no logic) so they can be authored/reviewed
independently per agent.
"""
