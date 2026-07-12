"""Capability data for the Business Agent (agent_key="business").

Purpose (from mission spec): CRM, leads, clients, pipeline, reports, campaign
analytics, business intelligence.

Live MVP behavior:
- CRUD/summarize real DB-backed leads/clients/deals if the underlying models
  exist in this repo.
- Otherwise return an honest empty state.
- Hard rule: no fake revenue or fake leads — every reporting/summary
  capability must return real data or an explicit empty/zero state, never a
  fabricated figure.
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

AGENT_KEY = "business"


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


DB_SCOPED = "Stored in the DB-backed CRM/business tables, keyed by user_id + workspace_id; never mixed across tenants."
NOT_PERSISTED = "Not persisted; operates on already-stored business data rather than creating new records."
APPROVAL_GATED = "Persisted/exported only after explicit user/Security Agent approval; sensitive payloads redacted until approved."

SCHEMA_CHECK = "VerificationAgent confirms the response matches the normalized business-result schema."
DB_CHECK = "VerificationAgent confirms the expected row exists/changed in the scoped DB table for the user_id/workspace_id."
AUDIT_CHECK = "VerificationAgent confirms a matching audit log row was written for this action."
UNAVAILABLE_CHECK = "N/A while capability_status is external_dependency_required or planned; verification is skipped and surfaced as such."

CAPABILITIES: List[AgentCapabilityEntry] = [
    _cap(1, "CRM contact management", "Create/read/update CRM contact records.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Operates on real DB-backed contact records if the model exists, otherwise returns an honest empty state — never fabricates contacts.", DB_CHECK, DB_SCOPED),
    _cap(2, "CRM deal management", "Create/read/update CRM deal records.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Operates on real DB-backed deal records if the model exists, otherwise returns an honest empty state — never fabricates deals.", DB_CHECK, DB_SCOPED),
    _cap(3, "Lead tracking across channels", "Track leads originating from multiple channels (call, web, ads) in one place.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Aggregates real lead records tagged by source channel from the DB, or returns an honest empty state.", DB_CHECK, DB_SCOPED),
    _cap(4, "Lead scoring", "Score leads by likelihood to convert.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Computes a rule-based score from real lead record fields; never invents a score for a non-existent lead.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(5, "Hot/cold lead tagging", "Tag leads as hot/warm/cold based on scoring.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes a hot/cold tag derived from the real lead score to the scoped lead record.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(6, "Client records", "Maintain records for converted clients.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Operates on real DB-backed client records if the model exists, otherwise returns an honest empty state.", DB_CHECK, DB_SCOPED),
    _cap(7, "Sales pipeline stages", "Track deals through configured pipeline stages.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Reads/updates the stage field on real deal records; never fabricates pipeline movement.", DB_CHECK, DB_SCOPED),
    _cap(8, "Follow-up reminders", "Generate reminders for outstanding follow-ups.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Computes due follow-ups from real scoped records carrying a follow-up-due flag.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(9, "Campaign performance tracking", "Track marketing campaign performance metrics.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Aggregates real campaign metric records if present, otherwise returns an honest empty state — never fabricates performance numbers.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(10, "Google Ads lead analysis", "Analyze leads attributed to Google Ads campaigns.",
         Risk.MEDIUM, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns an honest capability_unavailable response until Google Ads API credentials are configured.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["google_ads_api_credentials"]),
    _cap(11, "SEO/client report tracking", "Track SEO performance reports per client.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reads/stores real SEO report records supplied by the Browser Agent's SEO analyzer, or returns an honest empty state.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(12, "Revenue summary", "Summarize revenue across clients/deals.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Sums real invoice/deal revenue fields from the DB; returns an explicit zero/empty state rather than any fabricated revenue figure — no fake revenue.", DB_CHECK, DB_SCOPED),
    _cap(13, "Invoice status overview", "Summarize outstanding/paid invoice status.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Reads real invoice records if the model exists, otherwise returns an honest empty state.", DB_CHECK, DB_SCOPED),
    _cap(14, "Team task assignment", "Assign business tasks to team members.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes a real assignment record linking a task to a team member.", DB_CHECK, DB_SCOPED),
    _cap(15, "Project status reporting", "Report status of active projects.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reads real project status records, or returns an honest empty state if none exist.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(16, "Client health score", "Score client relationship health (engagement, satisfaction signals).",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Computes a rule-based score from real client activity records; never invents a score without underlying data.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(17, "Proposal tracking", "Track sent proposals and their status.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reads/writes real proposal records, or returns an honest empty state.", DB_CHECK, DB_SCOPED),
    _cap(18, "Won/lost deal analysis", "Analyze patterns in won vs lost deals.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Aggregates real closed-deal records by outcome; returns an honest empty state if none exist.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(19, "Pipeline forecast", "Forecast expected revenue from the current pipeline.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Computes a forecast strictly from real open-deal values and stage probabilities; never fabricates pipeline revenue when no deals exist — no fake revenue.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(20, "Weekly business report", "Generate a weekly summary report of business activity.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Compiles a report from real scoped records for the past week; returns an honest empty-state report rather than fabricated figures if no data exists.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(21, "Dashboard KPI cards", "Generate KPI summary cards for the dashboard.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Computes KPI card values from real scoped data, defaulting to an explicit zero/empty state — never fake revenue or fake leads.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(22, "Agent usage analytics", "Report usage analytics across William's agents.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Aggregates real agent-task/event records from the DB for the scoped workspace.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(23, "Workspace analytics", "Report analytics for the whole workspace.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Aggregates real scoped workspace records; returns an honest empty state if none exist.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(24, "SaaS user activity reports", "Report user activity within the SaaS product.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Aggregates real scoped user-activity/audit records.", DB_CHECK, DB_SCOPED),
    _cap(25, "Churn risk detection", "Flag clients at risk of churning.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Applies a rule-based heuristic to real client activity/engagement records to flag risk; never flags without underlying data.", SCHEMA_CHECK, DB_SCOPED),
    _cap(26, "Growth opportunity suggestions", "Suggest growth opportunities based on business data.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Generates suggestions from patterns in real scoped business records; returns an honest 'insufficient data' response if none exist.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(27, "Client onboarding checklist", "Generate/track an onboarding checklist for a new client.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Generates a checklist and tracks completion against a real client record.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(28, "Lead source attribution", "Attribute leads to their originating source/channel.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reads the source field on real lead records to build an attribution breakdown.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(29, "Conversion rate report", "Report lead-to-client conversion rate.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Computes conversion rate strictly from real counted lead/client records; returns 0/empty rather than a fabricated rate when no data exists.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(30, "Sales activity timeline", "Show a chronological timeline of sales activity.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Derives a timeline from real timestamped deal/activity records.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(31, "Client notes memory", "Persist notes about a client for future recall.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Stores/reads client notes via the DB-backed memory/CRM table.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(32, "CRM duplicate detection", "Detect duplicate contact/lead records.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Flags likely duplicate real CRM records by similarity heuristic; merge requires confirmation.", DB_CHECK, DB_SCOPED),
    _cap(33, "Contact import", "Import contacts from an external file/source.",
         Risk.MEDIUM, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Validates and imports contact records into the DB only after explicit approval.", AUDIT_CHECK, DB_SCOPED),
    _cap(34, "Contact export with approval", "Export contact records, only with explicit approval.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Generates a contact export file only after explicit user/Security Agent approval; sensitive fields redacted by default.", AUDIT_CHECK, APPROVAL_GATED),
    _cap(35, "Task due-date alerts", "Alert when a business task is nearing/past its due date.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Computes due-date alerts from real scoped task records.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(36, "Team workload view", "Show current workload distribution across team members.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Aggregates real assigned-task counts per team member.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(37, "Campaign ROI summary", "Summarize return on investment for marketing campaigns.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Computes ROI strictly from real campaign spend/revenue records; returns an honest empty state instead of a fabricated ROI figure when data is missing — no fake revenue.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(38, "Monthly business review", "Generate a monthly business performance review.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Compiles a review from real scoped records for the month; returns an honest empty-state review rather than fabricated performance if no data exists.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(39, "Service package recommendation", "Recommend a service package based on client needs.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Matches real client profile/needs data against the stored service catalog to suggest a package.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(40, "Client follow-up email draft", "Draft a follow-up email for a client.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Generates an email draft from real client/context data; sending requires separate approval via the messaging capability.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(41, "Proposal outline builder", "Build a structured proposal outline for a prospective client.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Generates a proposal outline from real client/service data provided in the request.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(42, "Business dashboard widgets", "Provide widget-ready data for the business dashboard.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Computes widget values from real scoped business data, defaulting to an explicit empty state — never fake revenue or fake leads.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(43, "Business report export", "Export a business report to a portable file format.",
         Risk.MEDIUM, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Generates the export file from real scoped report data only after explicit approval.", AUDIT_CHECK, APPROVAL_GATED),
    _cap(44, "Business-to-Memory handoff", "Hand off business context to the Memory Agent for persistence/recall.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Forwards a structured payload to the Memory Agent and returns its response.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(45, "Business-to-Workflow handoff", "Hand off a business process to the Workflow Agent for execution.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Forwards a structured workflow-trigger payload to the Workflow Agent and returns its response.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(46, "Business-to-Call handoff", "Hand off a business follow-up task to the Call Agent.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Forwards a structured payload to the Call Agent and returns its response.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(47, "Business-to-Finance handoff", "Hand off a business financial task to the Finance Agent.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Forwards a structured payload to the Finance Agent and returns its response.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(48, "Business Agent health/dependency check", "Report Business Agent health and configured dependencies.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reports DB connectivity and whether optional CRM/ads integrations are configured.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(49, "Business audit log", "Report an audit trail of Business Agent actions.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reads from the audit log table filtered to business-category events.", AUDIT_CHECK, DB_SCOPED, audit_required=False),
    _cap(50, "Business safe empty-state behavior", "Guarantee reporting capabilities return honest empty states rather than fabricated data.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Every reporting/summary code path checks for real underlying records first and returns an explicit empty-state response instead of inventing leads or revenue when none exist.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
]

assert len(CAPABILITIES) == 50, f"business capability_data must declare exactly 50 entries, got {len(CAPABILITIES)}"
