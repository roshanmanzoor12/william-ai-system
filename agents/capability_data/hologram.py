"""Capability data for the Hologram Agent (agent_key="hologram").

Purpose (from mission spec): AR/glasses/spatial overlay brain with safe
structured output when hardware is unavailable.

Live MVP behavior:
- Generate AR overlay JSON/cards (pure data/JSON generation, no hardware needed).
- Return external_dependency_required for real AR device control (object
  detection, spatial mapping, gesture control, glass wake, device bridges) since
  no AR hardware SDK exists in this repo.
- Never simulate hardware presence; always return an honest response.
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

AGENT_KEY = "hologram"


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
EPHEMERAL = "Held only for the lifetime of the active AR session/display; not persisted to durable storage."
NOT_PERSISTED = "Not persisted; operates on already-available data rather than creating new stored records."
APPROVAL_GATED = "Persisted only after explicit user/Security Agent approval; sensitive payloads redacted until approved."

SCHEMA_CHECK = "VerificationAgent confirms the response matches the normalized overlay/card result schema."
DB_CHECK = "VerificationAgent confirms the expected row exists/changed in the scoped DB table for the user_id/workspace_id."
AUDIT_CHECK = "VerificationAgent confirms a matching audit log row was written for this action."
UNAVAILABLE_CHECK = "N/A while capability_status is external_dependency_required or planned; verification is skipped and surfaced as such."

CAPABILITIES: List[AgentCapabilityEntry] = [
    _cap(1, "AR overlay card generation", "Generate a structured AR overlay card (title, body, position) as JSON for the current context.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Generates and returns overlay card JSON locally; no AR device is required to produce it.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(2, "Floating task cards", "Generate a floating task-list overlay card summarizing the user's active tasks.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a floating task-card JSON payload from the user's active task list.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(3, "Real-world object detection adapter", "Identify real-world objects in the wearer's field of view via a camera/vision pipeline.",
         Risk.MEDIUM, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns an honest capability_unavailable response until AR camera hardware and a detection model are configured.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["ar_camera_hardware", "object_detection_model"]),
    _cap(4, "Spatial mapping adapter", "Build a 3D spatial map of the wearer's surroundings for overlay anchoring.",
         Risk.MEDIUM, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns an honest capability_unavailable response until an AR hardware SDK and spatial mapping SDK are configured.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["ar_hardware_sdk", "spatial_mapping_sdk"]),
    _cap(5, "Gesture control adapter", "Interpret hand/gesture input to control AR overlays.",
         Risk.LOW, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns an honest capability_unavailable response until an AR hardware SDK and gesture recognition SDK are configured.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["ar_hardware_sdk", "gesture_recognition_sdk"]),
    _cap(6, "Glass tap wake command", "Wake the AR assistant via a physical tap gesture on smart glasses hardware.",
         Risk.LOW, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns an honest capability_unavailable response until an AR hardware SDK is configured.", UNAVAILABLE_CHECK, EPHEMERAL,
         audit_required=False, required_integrations=["ar_hardware_sdk"]),
    _cap(7, "Real-world navigation arrows", "Generate directional arrow overlay data to guide the wearer to a destination.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Computes a navigation-arrow overlay plan (bearing/distance) as JSON from provided coordinates.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(8, "Meeting overlays", "Generate an in-meeting overlay card with agenda/participant info.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a meeting overlay card JSON from provided meeting context.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(9, "Notification overlays", "Generate an overlay card surfacing a pending notification.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a notification overlay card JSON from the pending notification payload.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(10, "Translation captions in AR", "Generate live translation caption overlay text for spoken/written input.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Formats already-translated caption text into an overlay card JSON; does not itself perform translation.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(11, "Device status overlay", "Generate an overlay card showing connected device status/battery.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a device-status card JSON from device status data already reported to the system.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(12, "Repair/setup guidance", "Generate step-by-step repair/setup instruction overlay cards.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Generates a structured step-by-step guidance card sequence from a known procedure definition.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(13, "Live instruction cards", "Generate real-time instruction overlay cards for a task in progress.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Builds live instruction-card JSON reflecting the current task step.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(14, "Privacy redaction for bystanders", "Redact identifying details of bystanders captured in AR view before display/storage.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Applies a rule-based redaction pass to any bystander-identifying fields before an overlay is generated or logged.", SCHEMA_CHECK, NOT_PERSISTED),
    _cap(15, "No hidden monitoring", "Guarantee the AR system never records/transmits without a visible on-device indication.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Enforces and reports an always-visible recording-state indicator policy; refuses silent capture modes.", AUDIT_CHECK, NOT_PERSISTED),
    _cap(16, "Workstation overlay", "Generate an overlay of relevant apps/files for the wearer's current desk workstation.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a workstation overlay card JSON from the user's current active-app context.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(17, "CRM/client cards in AR", "Generate an AR overlay card showing CRM/client details for a recognized contact.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a client info card JSON from real CRM records if present, otherwise an honest empty-state card.", DB_CHECK, DB_SCOPED),
    _cap(18, "Call info overlay", "Generate an overlay card showing live call caller/context info.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a call-info overlay card JSON from data supplied by the Call Agent for the active call.", SCHEMA_CHECK, EPHEMERAL),
    _cap(19, "Content shot framing guide", "Generate a framing/composition guide overlay for capturing photo/video content.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a framing-guide overlay card JSON (grid/subject markers) for the current shot.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(20, "Memory recall cards in AR", "Generate an overlay card surfacing recalled memory relevant to the current context.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a memory-recall card JSON from records returned by the Memory Agent for the scoped user/workspace.", DB_CHECK, DB_SCOPED),
    _cap(21, "Smart glasses device bridge", "Bridge overlay output to a physical smart glasses device.",
         Risk.MEDIUM, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns an honest capability_unavailable response until a smart glasses vendor SDK is configured.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["ar_hardware_sdk", "smart_glasses_vendor_api"]),
    _cap(22, "Watch/phone/laptop stream bridge", "Stream AR overlay output to a paired watch/phone/laptop screen.",
         Risk.MEDIUM, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Returns an honest capability_unavailable response until a device streaming SDK is configured.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["device_streaming_sdk"]),
    _cap(23, "AR safe zone settings", "Configure zones/areas where AR overlays are suppressed for safety.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reads/writes a per-user safe-zone settings record via the DB-backed memory table.", DB_CHECK, DB_SCOPED),
    _cap(24, "Public/private AR mode", "Toggle whether AR overlays render bystander-visible content in public settings.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reads/writes a per-user public/private AR mode setting.", DB_CHECK, DB_SCOPED),
    _cap(25, "AR notification filtering", "Filter which notifications are allowed to surface as AR overlays.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Applies a per-user notification-filter rule set before generating overlay cards.", SCHEMA_CHECK, DB_SCOPED, audit_required=False),
    _cap(26, "AR task progress timeline", "Generate a timeline overlay of progress through a multi-step task.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a progress-timeline card JSON from tracked task-step state.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(27, "AR proof display", "Generate an overlay card displaying proof/evidence of a completed action.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a proof-of-completion card JSON from the verification result already produced by VerificationAgent.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(28, "AR command confirmation", "Generate a confirmation overlay card before executing a voice/gesture AR command.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a confirmation-card JSON requiring explicit acknowledgment before the underlying command proceeds.", SCHEMA_CHECK, EPHEMERAL),
    _cap(29, "AR gesture approval", "Generate an approval overlay card gating a gesture-triggered sensitive action.",
         Risk.MEDIUM, Perm.APPROVAL_REQUIRED, Status.APPROVAL_REQUIRED,
         "Blocks the gesture-triggered action and displays an approval card until the user/Security Agent confirms.", AUDIT_CHECK, EPHEMERAL),
    _cap(30, "AR object label confidence", "Display a confidence score alongside object-detection labels in AR.",
         Risk.LOW, Perm.ALLOWED, Status.EXTERNAL_DEPENDENCY_REQUIRED,
         "Formats a confidence score onto detection output when the object detection adapter is available; otherwise returns capability_unavailable.", UNAVAILABLE_CHECK, NOT_PERSISTED,
         audit_required=False, required_integrations=["ar_camera_hardware", "object_detection_model"]),
    _cap(31, "AR navigation instruction plan", "Generate a structured multi-step navigation instruction plan for AR display.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Computes a step-by-step navigation plan as JSON from provided route data.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(32, "AR overlay export JSON", "Export the current AR overlay layout as a portable JSON document.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Serializes the current overlay state to a JSON document for export.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(33, "AR layout memory", "Persist a user's preferred AR overlay layout across sessions.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Stores/reads the layout preference via the DB-backed memory table.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(34, "AR recurring overlay preferences", "Persist recurring overlay preferences (e.g. always show meeting cards) per user.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Stores/reads recurring overlay preference records via the DB-backed memory table.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(35, "AR device dependency check", "Report which AR hardware/software dependencies are currently configured.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Inspects configuration/environment for AR hardware SDK presence and reports an honest configured/not-configured status.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(36, "AR privacy audit", "Audit recent AR overlay activity for privacy-policy compliance.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Reads from the audit log table filtered to AR/hologram-category events and reports compliance.", AUDIT_CHECK, DB_SCOPED),
    _cap(37, "AR bystander protection", "Enforce that bystanders near the wearer are never identified/recorded without consent.",
         Risk.HIGH, Perm.ALLOWED, Status.AVAILABLE,
         "Applies the bystander-redaction rule set to all overlay/detection output and blocks identification without consent.", AUDIT_CHECK, NOT_PERSISTED),
    _cap(38, "AR language caption settings", "Configure preferred caption language/format for AR translation captions.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reads/writes a per-user caption language preference record.", DB_CHECK, DB_SCOPED, audit_required=False),
    _cap(39, "AR meeting summary cards", "Generate a post-meeting summary overlay card.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a meeting summary card JSON from provided meeting notes/transcript text.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(40, "AR workflow guidance", "Generate overlay cards guiding the wearer through a multi-step workflow.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Builds workflow-step overlay cards JSON from the Workflow Agent's step definitions.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(41, "AR browser research cards", "Generate an overlay card summarizing browser research results.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a research-summary card JSON from results supplied by the Browser Agent.", SCHEMA_CHECK, EPHEMERAL, audit_required=False),
    _cap(42, "AR system status card", "Generate an overlay card showing system health/status.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a system-status card JSON from data supplied by the System Agent.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(43, "AR finance warning card", "Generate an overlay warning card for a finance-related risk/alert.",
         Risk.MEDIUM, Perm.ALLOWED, Status.AVAILABLE,
         "Builds a finance-warning card JSON from an alert supplied by the Finance Agent; never displays fabricated figures.", SCHEMA_CHECK, NOT_PERSISTED),
    _cap(44, "AR security approval card", "Generate an overlay card requesting Security Agent approval for a sensitive action.",
         Risk.HIGH, Perm.APPROVAL_REQUIRED, Status.AVAILABLE,
         "Builds a security-approval card JSON reflecting a pending Security Agent approval request; the underlying action does not proceed until approved.", AUDIT_CHECK, NOT_PERSISTED),
    _cap(45, "AR handoff to Visual Agent", "Hand off AR visual-analysis tasks to the Visual Agent.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Forwards a structured task payload to the Visual Agent and returns its response.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(46, "AR handoff to Voice Agent", "Hand off AR voice-interaction tasks to the Voice Agent.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Forwards a structured task payload to the Voice Agent and returns its response.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(47, "AR unavailable hardware response", "Return a safe, honest structured response when AR hardware is not connected.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Detects missing AR hardware and returns a capability_unavailable response instead of simulating success.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(48, "Hologram Agent health/dependency check", "Report Hologram Agent health and configured AR dependencies.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reports process health and whether optional AR hardware SDKs are configured.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
    _cap(49, "Hologram audit log", "Report an audit trail of Hologram Agent actions.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Reads from the audit log table filtered to hologram-category events.", AUDIT_CHECK, DB_SCOPED, audit_required=False),
    _cap(50, "Hologram dashboard preview", "Provide a dashboard-ready preview of current AR overlay state.",
         Risk.LOW, Perm.ALLOWED, Status.AVAILABLE,
         "Computes a lightweight preview summary of active overlay cards for the dashboard.", SCHEMA_CHECK, NOT_PERSISTED, audit_required=False),
]

assert len(CAPABILITIES) == 50, f"hologram capability_data must declare exactly 50 entries, got {len(CAPABILITIES)}"
