"""
core/capability_roadmap.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Phase H -- a plain, inspectable manifest of the 50 advanced functions the
user asked for, each honestly marked by what is REALLY implemented today
versus what still needs a provider/worker/agent build-out. This is a
roadmap record, not a claim of completeness -- current_status is never
set to "available" unless the described MVP behavior genuinely works
end-to-end in this codebase right now.

current_status meanings:
- available: works today, for the MVP behavior described.
- approval_required: the feature IS implemented, but by design it always
  routes through Security Agent approval before it can run (e.g. deleting
  files) -- not a "not built yet" state.
- dependency_required: the code path exists but needs an external
  provider/worker (LLM, weather, Twilio, TTS, a connected Windows Worker,
  a file-generation pipeline) that isn't configured/built yet.
- roadmap: not implemented yet in any form.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass(frozen=True)
class CapabilityEntry:
    number: int
    function_name: str
    description: str
    required_agents: List[str]
    required_provider_or_worker: str
    security_level: str  # low | medium | high | critical
    current_status: str  # available | dependency_required | approval_required | roadmap
    mvp_behavior: str
    future_behavior: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "number": self.number,
            "function_name": self.function_name,
            "description": self.description,
            "required_agents": list(self.required_agents),
            "required_provider_or_worker": self.required_provider_or_worker,
            "security_level": self.security_level,
            "current_status": self.current_status,
            "mvp_behavior": self.mvp_behavior,
            "future_behavior": self.future_behavior,
        }


CAPABILITY_ROADMAP: List[CapabilityEntry] = [
    CapabilityEntry(
        1, "Open Windows apps by voice/text",
        "Open a mapped Windows app (Store, Chrome, VS Code, Notepad, Explorer) by name.",
        ["system", "voice"], "windows_worker", "low", "dependency_required",
        "Text command (\"William open Notepad\") queues a real WorkerTask for the 10 MVP actions via a connected Windows Worker.",
        "The same dispatch triggered by a live wake-word/voice command once Voice Agent's STT is connected.",
    ),
    CapabilityEntry(
        2, "Open project folder in VS Code",
        "Open the William/Jarvis project root in VS Code on the user's device.",
        ["system"], "windows_worker", "low", "available",
        "`open_vscode` action runs `code .` on the connected worker.",
        "Open a specific named project folder path, not just the worker's cwd.",
    ),
    CapabilityEntry(
        3, "Read project folder structure",
        "Return a directory tree summary of a workspace-owned project.",
        ["code"], "none", "low", "roadmap",
        "Not yet implemented.",
        "Code Agent walks a workspace-owned project directory and returns a structured tree.",
    ),
    CapabilityEntry(
        4, "Deep scan project for errors",
        "Static-analyze a project folder and report likely bugs.",
        ["code"], "none", "medium", "roadmap",
        "Not yet implemented.",
        "Code Agent's self-debugger runs linters/compilers and summarizes findings in plain language.",
    ),
    CapabilityEntry(
        5, "Explain each file's role",
        "Summarize what each file in a project does.",
        ["code"], "llm_provider", "low", "dependency_required",
        "Requires an LLM provider to generate real explanations; without one, honestly reports the provider is not configured.",
        "Per-file summaries generated from real static analysis plus LLM narration.",
    ),
    CapabilityEntry(
        6, "Fix frontend route issues",
        "Diagnose and patch broken Next.js routes.",
        ["code"], "llm_provider", "medium", "roadmap",
        "Not yet implemented.",
        "Code Agent detects routing errors and proposes/applies a fix, gated by Security Agent for file writes.",
    ),
    CapabilityEntry(
        7, "Fix backend API errors",
        "Diagnose and patch broken FastAPI routes.",
        ["code"], "llm_provider", "medium", "roadmap",
        "Not yet implemented.",
        "Code Agent reproduces the error, proposes a fix, and applies it only after approval.",
    ),
    CapabilityEntry(
        8, "Generate full project folder structure",
        "Scaffold a new project's folders/files from a description.",
        ["code"], "llm_provider", "medium", "roadmap",
        "Not yet implemented.",
        "Given collected requirements, Code Agent generates a real, connected folder/file structure.",
    ),
    CapabilityEntry(
        9, "Create connected frontend/backend files",
        "Generate working, wired frontend+backend code for a feature.",
        ["code"], "llm_provider", "high", "roadmap",
        "Not yet implemented.",
        "Generates real API routes, frontend pages, and the glue between them, tested before being reported done.",
    ),
    CapabilityEntry(
        10, "Generate test suite for project",
        "Write automated tests for a generated or existing project.",
        ["code"], "llm_provider", "medium", "roadmap",
        "Not yet implemented.",
        "Code Agent writes and runs a real test suite against the generated code.",
    ),
    CapabilityEntry(
        11, "Run safe tests and summarize errors",
        "Execute a project's test suite and report failures in plain language.",
        ["code"], "none", "medium", "roadmap",
        "Not yet implemented.",
        "Runs pytest/npm test in a sandboxed context and summarizes failures without fabricating a pass.",
    ),
    CapabilityEntry(
        12, "Create PDF document from prompt",
        "Generate a PDF from a natural-language request.",
        ["creator"], "file_generation_provider", "low", "dependency_required",
        "No real PDF-generation pipeline is wired yet -- honestly reports files/download links can't be faked.",
        "Real PDF generation with a genuine, workspace-scoped download link.",
    ),
    CapabilityEntry(
        13, "Create DOCX proposal/agreement",
        "Generate a DOCX business document from a prompt.",
        ["creator", "business"], "file_generation_provider", "low", "roadmap",
        "Not yet implemented.",
        "Template-driven DOCX generation with real download links.",
    ),
    CapabilityEntry(
        14, "Convert DOCX to PDF when dependency exists",
        "Convert a generated DOCX into PDF.",
        ["creator"], "docx_to_pdf_dependency", "low", "dependency_required",
        "No conversion dependency (e.g. LibreOffice/docx2pdf) is installed/configured yet.",
        "Automatic conversion once the dependency is present, or an honest \"conversion tool not installed\" message.",
    ),
    CapabilityEntry(
        15, "Download generated files to Windows Downloads",
        "Push a generated file to the user's Downloads folder via the worker.",
        ["system"], "windows_worker", "low", "dependency_required",
        "`download_generated_file_to_downloads` worker action exists and honestly fails (\"No generated file is available to download yet.\") since no real file-generation pipeline produces a download_url yet.",
        "Real generated files (PDF/DOCX/exports) pushed straight to the user's Downloads folder.",
    ),
    CapabilityEntry(
        16, "Open generated files locally",
        "Open a previously generated file on the user's device.",
        ["system"], "windows_worker", "low", "dependency_required",
        "`open_file` worker action is real and path-validated, but nothing generates real files to point it at yet.",
        "Opens a real generated file (PDF/DOCX/export) the moment file generation exists.",
    ),
    CapabilityEntry(
        17, "Ask clarifying questions before building",
        "Ask for missing details instead of guessing.",
        ["master"], "none", "low", "available",
        "ConversationSession required_inputs/collected_inputs flow asks for missing fields (e.g. VEO prompt style/duration) before proceeding.",
        "Richer multi-turn clarification for larger build tasks (full project scaffolding, not just templates).",
    ),
    CapabilityEntry(
        18, "Continue pending task from user answer",
        "Resume a task waiting on the user instead of starting a new one.",
        ["master"], "none", "low", "available",
        "A reply to a `waiting_for_user` thread merges into collected_inputs and continues the same conversation_thread_id.",
        "Same continuation model extended to long-running multi-step build tasks.",
    ),
    CapabilityEntry(
        19, "Manage multiple project tasks at once",
        "Track several active tasks per user without mixing them up.",
        ["master"], "none", "low", "available",
        "Each conversation_thread_id is an isolated, user/workspace-scoped ConversationSession; a new message can start an unrelated thread without disturbing others.",
        "A visible task/thread switcher in the dashboard so the user can jump between concurrent projects.",
    ),
    CapabilityEntry(
        20, "Save important project memory",
        "Persist key facts about a project/task for later recall.",
        ["memory"], "none", "low", "available",
        "Memory Agent already records and recalls per-user/workspace memory entries.",
        "Structured, project-scoped memory summaries surfaced back into future planning.",
    ),
    CapabilityEntry(
        21, "Search workspace knowledge base",
        "Search uploaded/ingested workspace documents for answers.",
        ["memory"], "vector_store_provider", "low", "roadmap",
        "Not yet implemented.",
        "RAG-style search over workspace-uploaded documents, cited in the final answer.",
    ),
    CapabilityEntry(
        22, "Use LLM provider for knowledge answers",
        "Answer general knowledge questions like a normal assistant.",
        ["master"], "llm_provider", "low", "dependency_required",
        "No LLM provider is configured yet -- honestly reports \"AI knowledge provider is not configured yet.\"",
        "Real LLM-backed answers once an OpenAI-compatible or local provider is configured.",
    ),
    CapabilityEntry(
        23, "Use live weather provider for current weather",
        "Answer live weather questions (e.g. current Lahore weather).",
        ["master"], "weather_provider", "low", "dependency_required",
        "No weather provider is configured -- honestly reports \"live weather provider is not connected yet.\"",
        "Real current weather once a weather API is configured.",
    ),
    CapabilityEntry(
        24, "Use browser worker for web research",
        "Research a topic live on the web.",
        ["browser"], "browser_worker", "medium", "roadmap",
        "Not yet implemented as a real browsing worker.",
        "Browser Agent drives a real headless/worker browser session and cites sources.",
    ),
    CapabilityEntry(
        25, "Compare reference designs",
        "Compare screenshots/URLs of reference UI designs.",
        ["visual"], "llm_provider_vision", "low", "roadmap",
        "Not yet implemented.",
        "Vision-capable LLM comparison of reference designs with a written summary.",
    ),
    CapabilityEntry(
        26, "Suggest UI redesign concepts",
        "Propose redesign directions for an existing page.",
        ["visual"], "llm_provider", "low", "roadmap",
        "Not yet implemented.",
        "Concrete redesign proposals grounded in the current page's real markup/styles.",
    ),
    CapabilityEntry(
        27, "Apply selected UI design to one page",
        "Apply a chosen redesign to a single page.",
        ["visual", "code"], "llm_provider", "medium", "roadmap",
        "Not yet implemented.",
        "Applies an approved design to one page's real code, verified before reporting done.",
    ),
    CapabilityEntry(
        28, "Apply selected UI design to whole app",
        "Roll a chosen redesign out across the whole app.",
        ["visual", "code"], "llm_provider", "high", "roadmap",
        "Not yet implemented.",
        "App-wide redesign rollout, page by page, with regression checks between pages.",
    ),
    CapabilityEntry(
        29, "Keep backend/API behavior while redesigning UI",
        "Guarantee a UI redesign never changes backend/API behavior.",
        ["code"], "none", "medium", "roadmap",
        "Not yet implemented as an explicit guarantee/check.",
        "Automated diff/check step confirming only presentation layers changed.",
    ),
    CapabilityEntry(
        30, "Audit SecurityAgent risky actions",
        "Log every risky action classification for later audit.",
        ["security"], "none", "medium", "available",
        "`classify_worker_action` and the audit log already record every allowed/requires_approval/rejected decision.",
        "A dedicated security audit dashboard view over this log.",
    ),
    CapabilityEntry(
        31, "Require approval before deleting files",
        "Never delete a file without Security Agent approval.",
        ["system", "security"], "windows_worker", "critical", "approval_required",
        "`delete_file` is a WORKER_RISKY_ACTIONS entry -- always routed through `security_review()` before it can ever queue.",
        "Same gate, plus a human-readable approval record shown in the dashboard.",
    ),
    CapabilityEntry(
        32, "Require approval before shutdown/restart",
        "Never shut down or restart a device without approval.",
        ["system", "security"], "windows_worker", "critical", "approval_required",
        "`shutdown`/`restart` are WORKER_RISKY_ACTIONS entries -- always routed through Security Agent review first.",
        "Same gate, plus scheduled/maintenance-window awareness.",
    ),
    CapabilityEntry(
        33, "Require approval before sending emails/calls",
        "Never send a message or place a call without approval.",
        ["call", "security"], "security_review", "critical", "approval_required",
        "`send_message`/`place_call` are WORKER_RISKY_ACTIONS entries -- the gate is real even though no call/email provider is connected yet.",
        "Same gate, wired to a real Twilio/SIP/email provider once connected.",
    ),
    CapabilityEntry(
        34, "Connect Twilio/SIP call provider",
        "Place real phone calls through a telephony provider.",
        ["call"], "twilio_or_sip_provider", "critical", "dependency_required",
        "No telephony provider is configured -- Call Agent never places a real call yet.",
        "Real outbound/inbound calls once Twilio/SIP credentials are configured, always Security-Agent gated.",
    ),
    CapabilityEntry(
        35, "Log calls with consent and audit",
        "Record and audit call activity with explicit consent.",
        ["call", "security"], "call_provider", "high", "roadmap",
        "Not yet implemented (no call provider connected).",
        "Consent-gated call logging tied into the existing audit trail.",
    ),
    CapabilityEntry(
        36, "Create customer support summary",
        "Summarize a support interaction/call into a report.",
        ["call", "memory"], "llm_provider", "low", "roadmap",
        "Not yet implemented.",
        "Real call/chat transcripts summarized via LLM and saved to memory.",
    ),
    CapabilityEntry(
        37, "Generate business proposal",
        "Draft a client-facing business proposal.",
        ["business"], "llm_provider", "low", "roadmap",
        "Not yet implemented.",
        "LLM-drafted proposal using workspace/business context, exported as a real document.",
    ),
    CapabilityEntry(
        38, "Generate SEO content plan",
        "Produce an SEO content plan for a site/brand.",
        ["browser", "creator"], "llm_provider", "low", "roadmap",
        "Not yet implemented.",
        "Combines real keyword/competitor research with LLM-drafted content plans.",
    ),
    CapabilityEntry(
        39, "Generate Google Ads campaign plan",
        "Draft a Google Ads campaign structure and copy.",
        ["business", "creator"], "llm_provider", "low", "roadmap",
        "Not yet implemented.",
        "LLM-drafted campaign plan, optionally cross-checked against real ad account data.",
    ),
    CapabilityEntry(
        40, "Generate VEO/video prompts",
        "Draft a structured video-generation prompt (style, duration, CTA).",
        ["creator"], "none", "low", "available",
        "Assistant's VEO template flow asks for style/duration/visual/CTA before generating the prompt.",
        "Direct handoff of the generated prompt into a real video-generation provider.",
    ),
    CapabilityEntry(
        41, "Generate social media content calendar",
        "Plan a multi-week social content calendar.",
        ["creator"], "llm_provider", "low", "roadmap",
        "Not yet implemented.",
        "LLM-drafted content calendar tied to a brand's real posting cadence.",
    ),
    CapabilityEntry(
        42, "Generate voice response from final_answer via TTS",
        "Speak the assistant's final_answer out loud.",
        ["voice"], "tts_provider", "low", "dependency_required",
        "TTS engine scaffolding exists (pyttsx3) but is not wired into the assistant chat response path yet.",
        "final_answer is spoken aloud automatically when voice mode is active.",
    ),
    CapabilityEntry(
        43, "Always-live wake word mode with voice worker",
        "Listen continuously for the \"William\" wake word.",
        ["voice"], "voice_worker", "medium", "dependency_required",
        "Wake-word scaffolding (wake_word.py) exists but no live always-on voice worker is connected yet.",
        "Continuous local listening, only sending audio after the wake word fires.",
    ),
    CapabilityEntry(
        44, "Push-to-talk text fallback",
        "A manual push-to-talk/text fallback when voice isn't available.",
        ["voice"], "none", "low", "roadmap",
        "Assistant chat already accepts text input as a de facto fallback; no dedicated push-to-talk UI yet.",
        "A dedicated push-to-talk control in the dashboard that falls back to text seamlessly.",
    ),
    CapabilityEntry(
        45, "Speaker recognition for admin-only commands",
        "Restrict sensitive voice commands to a recognized admin voice.",
        ["voice", "security"], "voice_biometrics_provider", "critical", "roadmap",
        "Not yet implemented.",
        "Voice-print verification gating sensitive commands, audited like any other Security Agent approval.",
    ),
    CapabilityEntry(
        46, "Device worker heartbeat monitoring",
        "Track whether the Windows Worker is alive and recently seen.",
        ["system"], "windows_worker", "low", "available",
        "`/system/worker/heartbeat` + staleness-aware `worker_connected` computation are live.",
        "Historical heartbeat/uptime charts in the dashboard.",
    ),
    CapabilityEntry(
        47, "Worker offline troubleshooting",
        "Give a clear, honest message when the worker isn't reachable.",
        ["system"], "windows_worker", "low", "available",
        "Assistant/System Agent return the exact \"your Windows device worker is offline. Start it first.\" message, never a fake success.",
        "Guided troubleshooting steps (e.g. \"run this exact command\") inline in the same message.",
    ),
    CapabilityEntry(
        48, "Workspace-isolated generated files",
        "Keep every generated file strictly scoped to its owning workspace.",
        ["system", "memory"], "file_storage_provider", "medium", "roadmap",
        "No generated-file storage pipeline exists yet to isolate -- tracked as a hard requirement for when file generation lands.",
        "Every generated file is stored and served strictly scoped to its owning user_id/workspace_id.",
    ),
    CapabilityEntry(
        49, "Admin support view of user worker status",
        "Let a platform admin see a user's worker connection status for support.",
        ["system"], "none", "medium", "roadmap",
        "Not yet implemented in the dashboard.",
        "An admin-only view of any workspace's worker connection/heartbeat/last-command state, isolation-safe.",
    ),
    CapabilityEntry(
        50, "Provider setup checklist and test buttons",
        "Show which providers/workers are configured and let the user test them.",
        ["master"], "none", "low", "roadmap",
        "Not yet implemented as a dedicated UI; provider-missing states are only surfaced reactively per request.",
        "A settings page listing every provider/worker with live status and a one-click test button.",
    ),
]

assert len(CAPABILITY_ROADMAP) == 50, f"Expected 50 capability entries, got {len(CAPABILITY_ROADMAP)}"


def capability_roadmap_as_dicts() -> List[Dict[str, Any]]:
    return [entry.to_dict() for entry in CAPABILITY_ROADMAP]


__all__ = ["CapabilityEntry", "CAPABILITY_ROADMAP", "capability_roadmap_as_dicts"]
