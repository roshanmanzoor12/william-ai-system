"""Capability data for the Call Agent (agent_key="call").

Purpose (from mission spec): AI receptionist, call consent, lead qualification,
summaries, CRM handoff, appointment booking.

Live MVP behavior:
- Generate receptionist scripts (real, local).
- Qualify a lead from provided text/transcript (real, local).
- Summarize a provided transcript (real, local).
- No real call answering/recording/telephony unless a provider is configured
  and, where personal data or real communication is involved, explicit
  consent/approval has been granted.
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

AGENT_KEY = "call"


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


DB_SCOPED = "Stored in the DB-backed memory/CRM table, keyed by user_id + workspace_id; never mixed across tenants."
EPHEMERAL = "Held only for the lifetime of the active call/session; not persisted to durable storage."
NOT_PERSISTED = "Not persisted; operates on already-available call/transcript data rather than creating new stored records."
APPROVAL_GATED = "Persisted/sent only after explicit user/Security Agent approval or caller consent; refused otherwise."

SCHEMA_CHECK = "VerificationAgent confirms the response matches the normalized call/result schema."
DB_CHECK = "VerificationAgent confirms the expected row exists/changed in the scoped DB table for the user_id/workspace_id."
AUDIT_CHECK = "VerificationAgent confirms a matching audit log row was written for this action."
UNAVAILABLE_CHECK = "N/A while capability_status is external_dependency_required or planned; verification is skipped and surfaced as such."

CAPABILITIES: List[AgentCapabilityEntry] = [
    _cap(1, "Incoming call detection adapter", "Detect an incoming call via a connected telephony provider.",
         Risk.MEDIUM, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns an honest capability_unavailable response until a telephony provider (e.g. Twilio) is configured.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["telephony_provider_api_key"]),
    _cap(2, "Outgoing call detection adapter", "Detect and track an outgoing call placed via a connected telephony provider.",
         Risk.MEDIUM, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns an honest capability_unavailable response until a telephony provider is configured.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["telephony_provider_api_key"]),
    _cap(3, "Business auto-answer only when enabled", "Automatically answer incoming business calls, but only when explicitly enabled by the user.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Auto-answer stays disabled until the user explicitly enables it and a telephony provider is configured; never answers silently.", AUDIT_CHECK, APPROVAL_GATED,
         required_integrations=["telephony_provider_api_key"]),
    _cap(4, "Caller ID lookup adapter", "Look up caller identity/name via a telephony/caller-ID provider.",
         Risk.MEDIUM, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns an honest capability_unavailable response until a telephony/caller-ID lookup provider is configured.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["telephony_provider_api_key", "caller_id_lookup_api"]),
    _cap(5, "Business hours routing", "Route calls differently based on the configured business-hours schedule.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Evaluates the current time against a stored business-hours schedule and returns a routing decision.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(6, "Known contact recognition", "Recognize a caller as an existing known contact from CRM records.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Matches caller info against real CRM contact records if present, otherwise returns an honest unknown-caller result.", DB_CHECK, DB_SCOPED),
    _cap(7, "VIP caller recognition", "Recognize a caller as a VIP based on a configured VIP list.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Matches caller info against a stored VIP tag list.", DB_CHECK, DB_SCOPED),
    _cap(8, "Receptionist greeting by business profile", "Generate a greeting script based on the configured business profile.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Generates greeting text from the stored business profile record.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(9, "Caller intent detection", "Classify the caller's intent from spoken/transcribed input.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Runs a local rule/NLP classifier over the provided transcript text to label intent.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(10, "Service matching", "Match the caller's stated need to a configured service offering.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Matches transcript keywords against the stored service catalog.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(11, "Transfer/escalation rules", "Apply configured rules for when to transfer/escalate a call to a human.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Evaluates stored escalation rules against call context and returns a transfer decision.", SCHEMA_CHECK, DB_SCOPED),
    _cap(12, "Lead qualification", "Qualify a caller as a sales lead from conversation content.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Runs a rule-based qualification scorer over the provided transcript/answers.", SCHEMA_CHECK, DB_SCOPED),
    _cap(13, "Budget question flow", "Ask/record the caller's budget as part of lead qualification.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Generates the budget question and records the caller's stated answer to the lead record.", DB_CHECK, DB_SCOPED),
    _cap(14, "Service question flow", "Ask/record which service the caller needs.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Generates the service question and records the caller's stated answer to the lead record.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(15, "Location question flow", "Ask/record the caller's location.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Generates the location question and records the caller's stated answer to the lead record.", DB_CHECK, DB_SCOPED),
    _cap(16, "Urgency question flow", "Ask/record how urgent the caller's need is.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Generates the urgency question and records the caller's stated answer to the lead record.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(17, "Appointment intent detection", "Detect that the caller wants to book an appointment.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Classifies the provided transcript text for appointment-booking intent.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(18, "Calendar availability check", "Check calendar availability for a requested appointment slot.",
         Risk.MEDIUM, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns an honest capability_unavailable response until a calendar provider is configured.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["calendar_provider_api_key"]),
    _cap(19, "Appointment booking with confirmation", "Book an appointment and send the caller a confirmation.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Booking proceeds only after explicit user/business confirmation and a configured calendar provider; never fabricates a booked slot.", AUDIT_CHECK, APPROVAL_GATED,
         required_integrations=["calendar_provider_api_key"]),
    _cap(20, "Voicemail capture with consent", "Capture voicemail audio, only with recording consent.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Requires an explicit consent flag on the request before capturing voicemail; refuses to record without it.", AUDIT_CHECK, APPROVAL_GATED,
         required_integrations=["telephony_provider_api_key"]),
    _cap(21, "Missed-call recovery", "Generate a follow-up plan/message for a missed call.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Generates a follow-up message draft for a missed-call record; sending requires separate approval.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(22, "Call transcription with legal/user consent", "Transcribe call audio to text, only with legal/user consent.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Requires an explicit consent flag and a configured transcription provider before transcribing; refuses otherwise.", AUDIT_CHECK, APPROVAL_GATED,
         required_integrations=["speech_to_text_provider"]),
    _cap(23, "Live call summary", "Summarize an in-progress call from live transcript text.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Summarizes the provided live transcript text using local summarization.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(24, "Post-call action items", "Extract action items from a completed call transcript.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Extracts action items from the provided transcript text via local rule/NLP parsing.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(25, "CRM lead creation", "Create a CRM lead record from qualified call data.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Creates a real lead record in the DB-backed CRM table if the model exists, otherwise returns an honest not-configured result — never fabricates a lead.", DB_CHECK, DB_SCOPED),
    _cap(26, "CRM call log", "Log the call as an activity record against a CRM contact.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Writes a real call-log row to the DB-backed CRM activity table if present, otherwise returns an honest empty state.", DB_CHECK, DB_SCOPED),
    _cap(27, "Call tagging", "Tag a call record with descriptive labels.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Writes tag values onto the scoped call-log record.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(28, "Lead/support/client/vendor classification", "Classify the caller's relationship type.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Runs a rule-based classifier over caller/transcript data to assign a relationship-type tag.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(29, "Human escalation", "Escalate the call to a human team member.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Flags the call record for human handoff and returns the assigned escalation target; does not itself place a call.", DB_CHECK, DB_SCOPED),
    _cap(30, "Spam/robocall detection", "Detect that an incoming call is likely spam/robocall.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Applies a rule-based heuristic to whatever caller-pattern data is available to flag likely spam.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(31, "Language auto-detection", "Detect the caller's spoken/written language.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Runs local language detection over the provided transcript/text.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(32, "Bilingual receptionist mode", "Serve the caller in their detected language using a bilingual script set.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Selects the matching pre-authored script language based on detected language.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(33, "Call script selection", "Select the appropriate receptionist script for the call context.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Selects a script from the stored script library based on call context/intent.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(34, "Objection handling script", "Generate an objection-handling response script.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Selects/generates an objection-handling script from the stored script library.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(35, "Follow-up WhatsApp with approval", "Send a follow-up WhatsApp message to the caller, only with approval.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Drafts the WhatsApp message and sends only after explicit user/Security Agent approval and a configured WhatsApp provider.", AUDIT_CHECK, APPROVAL_GATED,
         required_integrations=["whatsapp_business_api"]),
    _cap(36, "Follow-up email with approval", "Send a follow-up email to the caller, only with approval.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Drafts the follow-up email and sends only after explicit approval and a configured email provider.", AUDIT_CHECK, APPROVAL_GATED,
         required_integrations=["email_provider_api_key"]),
    _cap(37, "Call recording consent announcement", "Announce to the caller that the call may be recorded, before recording starts.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Plays/states the recording-consent announcement before any recording capability is permitted to run; recording is refused if the announcement was not delivered.", AUDIT_CHECK, NOT_PERSISTED),
    _cap(38, "Do-not-call handling", "Honor a caller/number's do-not-call preference.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Checks the scoped do-not-call list before allowing outbound follow-up actions and blocks matches.", DB_CHECK, DB_SCOPED),
    _cap(39, "Opt-out handling", "Process a caller's opt-out request from future communications.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Writes an opt-out flag to the scoped contact record and suppresses future outbound actions to it.", DB_CHECK, DB_SCOPED),
    _cap(40, "Emergency call exclusion", "Exclude emergency-service numbers from all automated call handling.",
         Risk.HIGH, Perm.ALLOWED, Status.AVAILABLE,
         "Matches dialed/incoming numbers against an emergency-number list and routes them outside all automation.", AUDIT_CHECK, NOT_PERSISTED),
    _cap(41, "After-hours voicemail flow", "Route after-hours calls to a voicemail flow.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Evaluates the business-hours schedule and routes after-hours calls to the voicemail flow definition.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(42, "Caller sentiment detection", "Detect the caller's sentiment from transcript text.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Runs local sentiment analysis over the provided transcript text.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(43, "Sales score after call", "Score the sales potential of a completed call.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Computes a rule-based sales score from real call/lead record data; never fabricates a score without underlying data.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(44, "Repeat caller memory", "Recall prior call history for a returning caller.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Reads prior call-log records for the matching caller from the DB-backed CRM table.", DB_CHECK, DB_SCOPED),
    _cap(45, "Call analytics dashboard", "Provide aggregate call metrics for the dashboard.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Computes counts/aggregates from real scoped call-log records, or an honest empty state if none exist.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(46, "Team assignment by lead type", "Assign a qualified lead to the appropriate team member.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Matches the lead's classification to a stored team-assignment rule and writes the assignment.", DB_CHECK, DB_SCOPED),
    _cap(47, "Call privacy guard", "Prevent call data from leaking across users/workspaces.",
         Risk.HIGH, Perm.ALLOWED, Status.AVAILABLE,
         "Every call-data query is filtered by user_id/workspace_id at the DB layer; cross-tenant reads are rejected.", DB_CHECK, DB_SCOPED),
    _cap(48, "Call Agent health/dependency check", "Report Call Agent health and configured telephony dependencies.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reports process health and whether telephony/calendar/messaging providers are configured.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(49, "Call audit log", "Report an audit trail of Call Agent actions.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reads from the audit log table filtered to call-category events.", AUDIT_CHECK, DB_SCOPED, audit_required=False),
    _cap(50, "Call-to-Business handoff", "Hand off qualified call/lead data to the Business Agent.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Forwards the structured lead/call payload to the Business Agent and returns its response.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
]

assert len(CAPABILITIES) == 50, f"call capability_data must declare exactly 50 entries, got {len(CAPABILITIES)}"
