"""Capability data for the Finance Agent (agent_key="finance").

Purpose (from mission spec): Safe finance preparation: invoices, budgets,
receipts, transaction drafts only, never auto-transfer.

Live MVP behavior:
- Create invoice drafts and summaries. Never submit transfer/payment.
- Sensitive finance tasks require SecurityAgent.

This is the strictest agent in the system. Per CLAUDE.md: "Finance Agent must
never execute real transactions unless explicitly approved (`real transaction
permission` defaults to `false`)." Auto-transfer, bank-credential storage, and
card-credential storage are hard-coded refusals, not configurable options.
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

AGENT_KEY = "finance"


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


DB_SCOPED = "Stored in the DB-backed finance table, keyed by user_id + workspace_id; never mixed across tenants."
EPHEMERAL = "Held only for the lifetime of the active request; not persisted to durable storage."
APPROVAL_GATED = "Persisted only after explicit user/Security Agent approval; sensitive payloads redacted until approved."
NOT_PERSISTED = "Not persisted; operates on already-stored records rather than creating new ones."
NEVER_STORED = "Never persisted anywhere, under any configuration; the refusal itself is written only to the audit log."

SCHEMA_CHECK = "VerificationAgent confirms response matches the normalized result schema."
DB_CHECK = "VerificationAgent confirms the expected row exists/changed in the finance table for the scoped user_id/workspace_id."
AUDIT_CHECK = "VerificationAgent confirms a matching audit log row was written for this action."
UNAVAILABLE_CHECK = "N/A while capability_status is external_dependency_required or planned; verification is skipped and surfaced as such."
REFUSAL_CHECK = "VerificationAgent confirms the request was rejected and no transfer/credential-store call was ever attempted."

CAPABILITIES: List[AgentCapabilityEntry] = [
    _cap(1, "Invoice draft creation", "Generate a local invoice draft for a client or project.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Generates a local invoice draft record; never submitted, sent, or charged to a payment processor.",
         DB_CHECK, DB_SCOPED),
    _cap(2, "Invoice status tracking", "Track and update the status (draft/sent/paid/overdue) of existing invoices.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Reads and updates the status field of existing invoice draft records in the DB.",
         DB_CHECK, DB_SCOPED),
    _cap(3, "Payment reminder draft", "Generate a reminder message draft tied to an overdue invoice.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Generates a reminder message draft for review; never auto-sent to the client.",
         DB_CHECK, DB_SCOPED),
    _cap(4, "Receipt OCR adapter", "Extract structured data from a scanned/photographed receipt.",
         Risk.MEDIUM, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns a structured capability_unavailable response until a receipt OCR provider is configured.",
         UNAVAILABLE_CHECK, NOT_PERSISTED, audit_required=False, required_integrations=["receipt_ocr_provider"]),
    _cap(5, "Expense categorization", "Categorize stored expense records by type.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Applies a rule-based categorizer to expense records already stored in the DB.",
         DB_CHECK, DB_SCOPED),
    _cap(6, "Budget tracking", "Track budget vs. actual spend for a project or workspace.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Computes budget-vs-actual figures from scoped DB records and stores the tracked budget definition.",
         DB_CHECK, DB_SCOPED),
    _cap(7, "Subscription tracking", "Track recurring subscription costs owed by the user/workspace.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Tracks recurring subscription cost records from scoped DB data.",
         DB_CHECK, DB_SCOPED),
    _cap(8, "Profit/loss summary", "Summarize profit and loss from stored income/expense records.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Computes a read-only profit/loss summary from scoped DB records; no transaction is executed.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(9, "Tax category preparation", "Tag income/expense records with tax categories for later export.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Applies tax-category tags to existing records for later export; never files taxes.",
         DB_CHECK, DB_SCOPED),
    _cap(10, "Duplicate invoice detection", "Detect likely duplicate invoices for review.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Flags likely duplicate invoices by similarity heuristic; read-only, no record is changed.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(11, "Payment draft preparation", "Prepare a local payment draft for review before any approval.",
         Risk.HIGH, Perm.ALLOWED, Status.AVAILABLE,
         "Generates a local payment draft record for review; never submits or transfers funds.",
         DB_CHECK, APPROVAL_GATED),
    _cap(12, "Recipient verification", "Cross-check a payment recipient against known vendor/client records.",
         Risk.HIGH, Perm.ALLOWED, Status.AVAILABLE,
         "Cross-checks recipient details against stored vendor/client records and flags mismatches; sends nothing.",
         SCHEMA_CHECK, NOT_PERSISTED),
    _cap(13, "Amount verification", "Cross-check a requested payment amount against invoice/budget records.",
         Risk.HIGH, Perm.ALLOWED, Status.AVAILABLE,
         "Cross-checks the requested amount against invoice/budget records and flags anomalies.",
         SCHEMA_CHECK, NOT_PERSISTED),
    _cap(14, "Never auto-transfer", "Guarantee this agent never initiates a real funds transfer on its own.",
         Risk.CRITICAL, Perm.BLOCKED_BY_DEFAULT, Status.AVAILABLE,
         "Hard-coded refusal: no code path in this agent ever initiates a real fund transfer; every transfer "
         "request returns blocked_by_default regardless of configuration or plan tier.",
         REFUSAL_CHECK, NEVER_STORED),
    _cap(15, "Never store bank credentials", "Guarantee bank account/routing details are never persisted.",
         Risk.CRITICAL, Perm.BLOCKED_BY_DEFAULT, Status.AVAILABLE,
         "Hard-coded refusal: bank account/routing numbers are rejected before reaching any storage layer, "
         "regardless of configuration.",
         REFUSAL_CHECK, NEVER_STORED),
    _cap(16, "Never store card credentials", "Guarantee card numbers/CVV/expiry are never persisted.",
         Risk.CRITICAL, Perm.BLOCKED_BY_DEFAULT, Status.AVAILABLE,
         "Hard-coded refusal: card number/CVV/expiry fields are rejected before reaching any storage layer, "
         "regardless of configuration.",
         REFUSAL_CHECK, NEVER_STORED),
    _cap(17, "SecurityAgent mandatory for financial actions", "Route every financial action through Security Agent approval first.",
         Risk.CRITICAL, Perm.ALLOWED, Status.AVAILABLE,
         "Every capability in this agent classified as a financial action is routed through Security Agent for "
         "approval before any execution step; there is no bypass flag.",
         AUDIT_CHECK, "Persisted only as an audit-log/approval reference; no raw financial payload is stored outside the approval record."),
    _cap(18, "Approval flow for payment draft", "Route a prepared payment draft through explicit approval.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Creates a Security Agent approval request for a prepared payment draft; the draft is never sent unless approval is granted.",
         AUDIT_CHECK, APPROVAL_GATED),
    _cap(19, "Refund draft only", "Generate a local refund draft for review.",
         Risk.HIGH, Perm.ALLOWED, Status.AVAILABLE,
         "Generates a local refund draft for review; never submits or executes an actual refund.",
         DB_CHECK, DB_SCOPED),
    _cap(20, "Cashflow report", "Summarize projected/actual cashflow from stored records.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Computes a read-only cashflow report from scoped DB records.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(21, "Monthly expense alerts", "Alert when monthly expenses cross a configured threshold.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Generates an informational alert when monthly expenses cross a configured threshold; nothing is charged.",
         SCHEMA_CHECK, EPHEMERAL),
    _cap(22, "Budget overspend alert", "Alert when actual spend exceeds a defined budget.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Generates an informational alert when tracked spend exceeds the defined budget; nothing is charged.",
         SCHEMA_CHECK, EPHEMERAL),
    _cap(23, "Finance dashboard", "Provide aggregate finance metrics for the dashboard.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Computes read-only counts/aggregates from scoped finance records.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(24, "Invoice aging report", "Report how long unpaid invoices have been outstanding.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Computes a read-only aging report from scoped invoice records.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(25, "Export reports with approval", "Export finance reports to a portable file, gated by approval.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Generates an export file of scoped financial reports only after explicit approval; sensitive fields redacted by default.",
         AUDIT_CHECK, APPROVAL_GATED),
    _cap(26, "Vendor list", "Maintain a scoped list of known vendors.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Maintains a scoped list of vendor records in the DB.",
         DB_CHECK, DB_SCOPED),
    _cap(27, "Client billing summary", "Summarize what a given client has been billed.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Computes a read-only billing summary for a client from scoped invoice records.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(28, "Recurring invoice draft", "Generate a recurring invoice schedule draft.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Generates a recurring invoice draft/schedule for review; drafts are never auto-sent or auto-charged.",
         DB_CHECK, DB_SCOPED),
    _cap(29, "Late payment reminder", "Generate a late-payment reminder draft for an overdue invoice.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Generates a late-payment reminder draft for review; never auto-sent.",
         DB_CHECK, DB_SCOPED),
    _cap(30, "Expense duplicate detection", "Detect likely duplicate expense entries for review.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Flags likely duplicate expenses by similarity heuristic; read-only, no record is changed.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(31, "Merchant categorization", "Categorize expenses by merchant.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Applies a rule-based merchant categorizer to expense records already stored in the DB.",
         DB_CHECK, DB_SCOPED),
    _cap(32, "Tax preparation summary", "Summarize tax-relevant totals for a period.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Computes a read-only tax-relevant totals summary from scoped, tagged records.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(33, "Safe finance memory", "Persist finance records with sensitive fields redacted.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Persists finance records through the DB-backed memory layer with sensitive fields "
         "(credentials, full account numbers) redacted before storage.",
         DB_CHECK, DB_SCOPED),
    _cap(34, "Approved recurring rules", "Store and enforce recurring-action rules that were explicitly approved.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Stores recurring-action rules only after explicit Security Agent approval; enforces the approved scope "
         "on every subsequent recurring draft.",
         AUDIT_CHECK, APPROVAL_GATED),
    _cap(35, "Payment risk scoring", "Score a prepared payment/invoice draft for risk signals.",
         Risk.HIGH, Perm.ALLOWED, Status.AVAILABLE,
         "Scores a prepared payment/invoice draft for risk signals (mismatched recipient, unusual amount) "
         "before it reaches approval.",
         SCHEMA_CHECK, NOT_PERSISTED),
    _cap(36, "Fake invoice detection handoff", "Flag a suspected fraudulent invoice and hand off to Security Agent.",
         Risk.HIGH, Perm.ALLOWED, Status.AVAILABLE,
         "Flags a suspected fraudulent invoice by heuristic and hands the flagged case off to the Security Agent for review.",
         AUDIT_CHECK, DB_SCOPED),
    _cap(37, "Finance audit log", "Report which users/agents took which finance actions and when.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Reads from the audit log table filtered to finance-category events; read-only.",
         AUDIT_CHECK, DB_SCOPED, audit_required=False),
    _cap(38, "Finance report PDF/export adapter", "Render finance reports to a PDF/export file.",
         Risk.MEDIUM, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns a structured capability_unavailable response until a PDF export engine is configured.",
         UNAVAILABLE_CHECK, NOT_PERSISTED, audit_required=False, required_integrations=["pdf_export_engine"]),
    _cap(39, "Subscription renewal alert", "Alert ahead of an upcoming subscription renewal charge.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Generates an informational alert ahead of a tracked subscription's renewal date; nothing is charged.",
         SCHEMA_CHECK, EPHEMERAL),
    _cap(40, "Cancellation reminder", "Remind the user to cancel a subscription before renewal if desired.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Generates an informational cancellation reminder ahead of a tracked renewal date; nothing is cancelled automatically.",
         SCHEMA_CHECK, EPHEMERAL),
    _cap(41, "Finance-to-Business handoff", "Hand off scoped finance summaries to the Business Agent.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Hands off scoped finance summary data to the Business Agent for cross-agent reporting.",
         SCHEMA_CHECK, NOT_PERSISTED),
    _cap(42, "Finance-to-Security handoff", "Hand off a financial action requiring approval to the Security Agent.",
         Risk.HIGH, Perm.ALLOWED, Status.AVAILABLE,
         "Hands off a financial action payload to the Security Agent for approval before any execution step.",
         AUDIT_CHECK, APPROVAL_GATED),
    _cap(43, "Finance-to-Memory handoff", "Hand off finance records to the Memory Agent for durable, scoped storage.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Hands off redacted finance records to the Memory Agent for durable, scoped storage.",
         DB_CHECK, DB_SCOPED),
    _cap(44, "Financial action proof handoff", "Attach a verifiable proof record to every completed financial action.",
         Risk.HIGH, Perm.ALLOWED, Status.AVAILABLE,
         "Attaches a verifiable proof record (audit log reference) to every completed financial action before "
         "handoff to the Verification Agent.",
         AUDIT_CHECK, DB_SCOPED),
    _cap(45, "Finance role/plan access control", "Restrict finance capabilities by caller role and subscription plan.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Checks the caller's role and subscription plan against finance capability ACLs before executing.",
         SCHEMA_CHECK, NOT_PERSISTED),
    _cap(46, "Finance data isolation", "Guarantee finance records never cross user/workspace boundaries.",
         Risk.HIGH, Perm.ALLOWED, Status.AVAILABLE,
         "Every finance query is filtered by user_id + workspace_id at the DB layer; cross-tenant reads are rejected.",
         DB_CHECK, DB_SCOPED),
    _cap(47, "Finance empty-state behavior", "Return a structured empty result when no finance records exist.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Returns a structured empty-state result (not an error) when no finance records exist for the scope.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(48, "Finance Agent health/dependency check", "Report Finance Agent health and configured dependencies.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reports DB connectivity and whether optional OCR/PDF-export adapters are configured.",
         SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(49, "Finance structured unavailable for payment APIs", "Return a structured unavailable response for any real payment-processor request.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Returns a structured capability_unavailable response (never a silent failure or fake success) whenever "
         "a real payment-processor API call is requested.",
         UNAVAILABLE_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(50, "Finance no-autopay enforcement test", "Self-test confirming auto-transfer and credential-storage refusals hold.",
         Risk.CRITICAL, Perm.ALLOWED, Status.AVAILABLE,
         "Runs an automated self-test confirming that auto-transfer, bank-credential storage, and card-credential "
         "storage are all refused as expected; fails loudly if any refusal is bypassed.",
         "VerificationAgent confirms the self-test result recorded all three refusal checks as passed.",
         "Persisted as a self-test result record in the finance table for the audit trail."),
]

assert len(CAPABILITIES) == 50, f"finance capability_data must declare exactly 50 entries, got {len(CAPABILITIES)}"
