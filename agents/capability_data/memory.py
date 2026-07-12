"""Capability data for the Memory Agent (agent_key="memory").

Purpose (from mission spec): Short/long/project/client/team memory with
privacy, recall, and workspace isolation.

Live MVP behavior:
- Save/search/forget scoped memory.
- Use DB fallback if vector engine not configured.
- Never store sensitive data without approval.
"""

from __future__ import annotations

import re
from typing import List, Optional

from agents.capability_manifest import (
    AgentCapabilityEntry,
    CapabilityPermissionLevel as Perm,
    CapabilityRiskLevel as Risk,
    CapabilityStatus as Status,
)

AGENT_KEY = "memory"


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _cap(
    index: int,
    name: str,
    description: str,
    risk: Risk,
    permission: Perm,
    status: Status,
    safe_mvp_behavior: str,
    verification_method: str,
    memory_policy: str,
    audit_required: bool = True,
    required_integrations: Optional[List[str]] = None,
) -> AgentCapabilityEntry:
    return AgentCapabilityEntry(
        id=f"{AGENT_KEY}.{index:03d}_{_slug(name)}",
        name=name,
        description=description,
        risk_level=risk,
        permission_level=permission,
        status=status,
        required_integrations=required_integrations or [],
        safe_mvp_behavior=safe_mvp_behavior,
        verification_method=verification_method,
        memory_policy=memory_policy,
        audit_required=audit_required,
    )


DB_SCOPED = "Stored in the DB-backed memory table, keyed by user_id + workspace_id; never mixed across tenants."
EPHEMERAL = "Held only for the lifetime of the active session; not persisted to durable storage."
APPROVAL_GATED = "Persisted only after explicit user/Security Agent approval; sensitive payloads redacted until approved."
NOT_PERSISTED = "Not persisted; operates on already-stored memory rather than creating new records."

SCHEMA_CHECK = "VerificationAgent confirms response matches the normalized result schema."
DB_CHECK = "VerificationAgent confirms the expected row exists/changed in the memory table for the scoped user_id/workspace_id."
AUDIT_CHECK = "VerificationAgent confirms a matching audit log row was written for this action."
UNAVAILABLE_CHECK = "N/A while capability_status is external_dependency_required or planned; verification is skipped and surfaced as such."

CAPABILITIES: List[AgentCapabilityEntry] = [
    _cap(1, "Short-term session memory", "Cache conversation/task context for the duration of the active session.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Store in an in-process/session-scoped cache keyed by session_id.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(2, "Long-term preference memory", "Persist durable user preferences (tone, formatting, defaults) across sessions.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Store/read via the real DB-backed memory table.", DB_CHECK, DB_SCOPED),
    _cap(3, "Project memory", "Persist notes and facts tied to a specific project.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Store/read via the DB-backed memory table with a project tag.", DB_CHECK, DB_SCOPED),
    _cap(4, "Client memory", "Persist notes and facts tied to a specific client/contact.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Store/read via the DB-backed memory table with a client tag.", DB_CHECK, DB_SCOPED),
    _cap(5, "Team memory", "Persist notes shared across a team within a workspace.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Store/read via the DB-backed memory table with a team-visibility flag.", DB_CHECK, DB_SCOPED),
    _cap(6, "Workspace memory isolation", "Guarantee memory records never cross workspace boundaries.",
         Risk.HIGH, Perm.ALLOWED, Status.AVAILABLE,
         "Every query is filtered by workspace_id at the DB layer; cross-workspace reads are rejected.", DB_CHECK, DB_SCOPED),
    _cap(7, "User memory isolation", "Guarantee memory records never cross user boundaries within a workspace.",
         Risk.HIGH, Perm.ALLOWED, Status.AVAILABLE,
         "Every query is filtered by user_id at the DB layer; cross-user reads are rejected.", DB_CHECK, DB_SCOPED),
    _cap(8, "Role-based memory access", "Restrict which roles can read/write which memory categories.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Check the caller's role against a category ACL before returning results.", DB_CHECK, DB_SCOPED),
    _cap(9, "Keyword recall", "Search stored memory by literal keyword match.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Run a scoped LIKE/full-text query against the memory table.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(10, "Semantic recall adapter", "Search stored memory by meaning rather than literal keywords.",
         Risk.LOW, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Falls back to keyword recall until an embeddings provider is configured.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["embeddings_provider_api_key"]),
    _cap(11, "Vector embeddings adapter", "Generate and store vector embeddings for memory records.",
         Risk.LOW, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns capability_unavailable-style response until a vector store/provider is configured.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["vector_db_url", "embeddings_provider_api_key"]),
    _cap(12, "Memory summarization", "Condense a large set of memory records into a short summary.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Summarize scoped records already in the DB using local text summarization.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(13, "Memory deduplication", "Detect and merge near-duplicate memory records.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Flag likely duplicates by similarity heuristic; merge only after confirmation.", DB_CHECK, DB_SCOPED),
    _cap(14, "Memory cleanup", "Remove stale or expired memory records per retention rules.",
         Risk.MEDIUM, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Proposes a cleanup plan; deletion requires explicit approval.", AUDIT_CHECK, DB_SCOPED),
    _cap(15, "Conflict detection", "Detect contradictory memory records for the same subject.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Compare scoped records and flag contradictions for review.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(16, "Knowledge graph nodes", "Represent memory subjects (people, projects, clients) as graph nodes.",
         Risk.LOW, Perm.ALLOWED, Status.PLANNED,
         "No graph store exists yet; returns a planned/capability_unavailable response.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["graph_db_url"]),
    _cap(17, "Knowledge graph edges", "Represent relationships between memory subjects as graph edges.",
         Risk.LOW, Perm.ALLOWED, Status.PLANNED,
         "No graph store exists yet; returns a planned/capability_unavailable response.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["graph_db_url"]),
    _cap(18, "Project timeline tracking", "Track a chronological history of project-related memory events.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Derive a timeline from timestamped project-tagged memory records.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(19, "Decision history", "Track a chronological history of decisions recorded in memory.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Derive a decision log from tagged memory records.", DB_CHECK, DB_SCOPED),
    _cap(20, "Agent-specific memory", "Store memory scoped to a single specialist agent's own use.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Store/read via the DB-backed memory table with an agent tag.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(21, "Prompt preference recall", "Recall a user's preferred prompt style/format.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Read from long-term preference memory.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(22, "Style rule recall", "Recall a user/workspace's writing or brand style rules.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Read from long-term preference memory.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(23, "Codebase rule recall", "Recall project-specific coding conventions for the Code Agent.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Read from project memory tagged for code conventions.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(24, "Client follow-up memory", "Track outstanding follow-ups owed to a client.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Store/read via client memory with a follow-up-due flag.", DB_CHECK, DB_SCOPED),
    _cap(25, "CRM memory linking", "Link memory records to CRM contact/deal records.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Store a foreign-key reference to the CRM record alongside the memory row.", DB_CHECK, DB_SCOPED),
    _cap(26, "Voice note memory with consent", "Store transcribed voice notes as memory, only with explicit consent.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Requires an explicit consent flag on the request; refuses to store without it.", AUDIT_CHECK, APPROVAL_GATED),
    _cap(27, "Document memory with consent", "Store extracted document content as memory, only with explicit consent.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Requires an explicit consent flag on the request; refuses to store without it.", AUDIT_CHECK, APPROVAL_GATED),
    _cap(28, "Chat memory with consent", "Store chat transcript excerpts as memory, only with explicit consent.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Requires an explicit consent flag on the request; refuses to store without it.", AUDIT_CHECK, APPROVAL_GATED),
    _cap(29, "Privacy classification", "Classify a memory record's sensitivity level before storing.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Apply a rule-based sensitivity classifier before persistence.", SCHEMA_CHECK, NOT_PERSISTED),
    _cap(30, "Sensitive memory blocker", "Block storage of records classified as sensitive unless approved.",
         Risk.HIGH, Perm.BLOCKED_BY_DEFAULT, Status.AVAILABLE,
         "Rejects the write and returns approval_required instead of silently storing.", AUDIT_CHECK, NOT_PERSISTED),
    _cap(31, "Approval flow for sensitive memory", "Route sensitive memory writes through Security Agent approval.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Creates a Security Agent approval request; write proceeds only on approval.", AUDIT_CHECK, APPROVAL_GATED),
    _cap(32, "Forget memory", "Permanently delete a specific memory record on request.",
         Risk.MEDIUM, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Deletes the scoped row after explicit confirmation; logs the deletion.", AUDIT_CHECK, DB_SCOPED),
    _cap(33, "Update memory", "Update the content of an existing memory record.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Update the scoped row in the memory table.", DB_CHECK, DB_SCOPED),
    _cap(34, "Export memory", "Export a user/workspace's memory records to a portable format.",
         Risk.MEDIUM, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Generates an export file only after explicit approval; sensitive fields redacted by default.", AUDIT_CHECK, DB_SCOPED),
    _cap(35, "Backup memory", "Create a backup snapshot of a workspace's memory records.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Writes a scoped snapshot to internal storage.", AUDIT_CHECK, DB_SCOPED),
    _cap(36, "Restore memory", "Restore memory records from a prior backup snapshot.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Restores from a scoped snapshot only after explicit approval.", AUDIT_CHECK, DB_SCOPED),
    _cap(37, "Memory import", "Import memory records from an external file/source.",
         Risk.MEDIUM, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Validates and imports scoped records only after explicit approval.", AUDIT_CHECK, DB_SCOPED),
    _cap(38, "Multi-device memory sync", "Synchronize memory state across a user's multiple devices.",
         Risk.LOW, Perm.ALLOWED, Status.PLANNED,
         "No device-sync transport exists yet; returns a planned response.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["device_sync_service"]),
    _cap(39, "Conflict resolution", "Resolve a detected memory conflict by choosing/merging a value.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Applies the caller's chosen resolution to the scoped records.", DB_CHECK, DB_SCOPED),
    _cap(40, "Memory health scoring", "Score overall memory-store health (staleness, duplication, coverage).",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Compute a score from scoped record metadata.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(41, "Memory retention rules", "Define/enforce how long different memory categories are retained.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Reads/applies a per-workspace retention policy record.", DB_CHECK, DB_SCOPED),
    _cap(42, "Memory access audit", "Report which users/agents accessed which memory records and when.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Reads from the audit log table filtered to memory-category events.", AUDIT_CHECK, DB_SCOPED),
    _cap(43, "Memory search by project", "Search memory records filtered by project tag.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Scoped DB query filtered by project tag.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(44, "Memory search by client", "Search memory records filtered by client tag.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Scoped DB query filtered by client tag.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(45, "Memory search by date", "Search memory records filtered by a date range.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Scoped DB query filtered by created_at/updated_at range.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(46, "Memory search by agent", "Search memory records filtered by which agent wrote them.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Scoped DB query filtered by agent tag.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(47, "Memory safe result formatting", "Format memory results with sensitive fields redacted by default.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Applies the redaction formatter to every outbound result.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(48, "Memory-to-MasterAgent context injection", "Supply recalled memory as context for MasterAgent planning.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Returns a scoped context bundle consumed by MasterAgent before planning.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(49, "Memory Agent health/dependency check", "Report Memory Agent health and configured dependencies.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reports DB connectivity and whether optional vector/graph adapters are configured.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(50, "Memory dashboard metrics", "Provide aggregate memory metrics for the dashboard.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Computes counts/aggregates from scoped memory records.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
]

assert len(CAPABILITIES) == 50, f"memory capability_data must declare exactly 50 entries, got {len(CAPABILITIES)}"
