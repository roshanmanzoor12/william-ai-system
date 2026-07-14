"""
core/intent_classifier.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Phase 1 (Conversational Assistant Brain) — classifies a user message into one
of 12 human-facing intent categories, and (for a small, growing registry of
templated tasks) a declarative list of fields William must collect before
anything can execute.

This wraps core/planner.py's Planner.detect_intent() rather than
reimplementing agent/risk scoring from scratch — that classifier is already
deterministic (keyword/regex based, no LLM call anywhere in this repo) and
already knows which agent a message routes to and how risky it is. This
module only adds the coarser, user-facing category label plus the
clarifying-question machinery apps/api/routes/assistant.py needs.

No LLM call anywhere in this file -- Phase 2 owns real knowledge/LLM
integration. Everything here is deterministic string matching.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from core.planner import Planner

# =============================================================================
# The 12 user-facing intent categories
# =============================================================================

INTENT_KNOWLEDGE_QUESTION = "knowledge_question"
INTENT_CREATION_TASK = "creation_task"
INTENT_PROJECT_BUILD_TASK = "project_build_task"
INTENT_FILE_GENERATION_TASK = "file_generation_task"
INTENT_WINDOWS_DEVICE_ACTION = "windows_device_action"
INTENT_VOICE_CONTROL_ACTION = "voice_control_action"
INTENT_RISKY_SECURITY_ACTION = "risky_security_action"
INTENT_CALL_ACTION_PROVIDER_TASK = "call_action_provider_task"
INTENT_BROWSER_RESEARCH_TASK = "browser_research_task"
INTENT_DESIGN_TASK = "design_task"
INTENT_CODE_DEBUG_TASK = "code_debug_task"
INTENT_MULTI_STEP_WORKFLOW = "multi_step_workflow"

INTENT_CATEGORIES = (
    INTENT_KNOWLEDGE_QUESTION,
    INTENT_CREATION_TASK,
    INTENT_PROJECT_BUILD_TASK,
    INTENT_FILE_GENERATION_TASK,
    INTENT_WINDOWS_DEVICE_ACTION,
    INTENT_VOICE_CONTROL_ACTION,
    INTENT_RISKY_SECURITY_ACTION,
    INTENT_CALL_ACTION_PROVIDER_TASK,
    INTENT_BROWSER_RESEARCH_TASK,
    INTENT_DESIGN_TASK,
    INTENT_CODE_DEBUG_TASK,
    INTENT_MULTI_STEP_WORKFLOW,
)


# =============================================================================
# Declarative required-field specs (per templated task)
# =============================================================================

@dataclass
class RequiredField:
    name: str
    prompt: str
    options: Optional[List[str]] = None
    required: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "prompt": self.prompt,
            "options": self.options,
            "required": self.required,
        }


@dataclass
class TaskTemplate:
    key: str
    category: str
    required_fields: List[RequiredField]
    match: Callable[[str], bool]


@dataclass
class IntentClassification:
    category: str
    template_key: Optional[str]
    required_fields: List[RequiredField]
    primary_agent: str
    secondary_agents: List[str]
    risk_level: str
    requires_security: bool
    confidence: float


# =============================================================================
# Fallback keyword rules (used only when no TASK_TEMPLATES entry matches)
# =============================================================================

_CATEGORY_RULES: Dict[str, List[str]] = {
    INTENT_WINDOWS_DEVICE_ACTION: [
        "open app", "open microsoft", "close app", "shutdown", "restart pc",
        "restart my", "launch app", "open notepad", "open chrome", "open explorer",
    ],
    INTENT_VOICE_CONTROL_ACTION: [
        "wake word", "push to talk", "voice mode", "enable voice", "disable voice",
        "standby mode", "listen for", "voice control",
    ],
    INTENT_CALL_ACTION_PROVIDER_TASK: [
        "call this customer", "place a call", "call the client", "send whatsapp",
        "send sms", "make a call",
    ],
    INTENT_BROWSER_RESEARCH_TASK: [
        "research", "look up", "search the web", "find information about",
        "browse", "scrape", "competitor analysis",
    ],
    INTENT_DESIGN_TASK: [
        "redesign", "ui design", "design a", "mockup", "wireframe", "logo design",
        "color palette", "brand style",
    ],
    INTENT_CODE_DEBUG_TASK: [
        "fix this bug", "debug", "fix the error", "why is this failing",
        "stack trace", "exception", "code review",
    ],
    INTENT_PROJECT_BUILD_TASK: [
        "build a website", "build an app", "build this project", "saas banao",
        "website builder", "app builder", "scaffold a project", "create a project",
    ],
    INTENT_FILE_GENERATION_TASK: [
        "make a pdf", "create a pdf", "generate a pdf", "docx", "nda", "proposal pdf",
        "agreement pdf", "export as pdf", "download link",
    ],
    INTENT_MULTI_STEP_WORKFLOW: [
        "automation", "workflow", "every monday", "recurring", "schedule this",
    ],
    INTENT_CREATION_TASK: [
        "create a", "generate a", "write a", "draft a", "make a", "veo prompt",
        "video prompt", "ad copy", "social media post",
    ],
}


def _matches_any(text: str, keywords: List[str]) -> bool:
    return any(keyword in text for keyword in keywords)


# =============================================================================
# VEO prompt template — the Phase 1 worked example
# =============================================================================

def _match_veo_prompt(message: str) -> bool:
    lowered = message.lower()
    has_veo_signal = bool(re.search(r"\bveo\b|video prompt|video ad prompt", lowered))
    has_creation_verb = bool(re.search(r"\bcreate\b|\bgenerate\b|\bbuild\b|\bwrite\b|\bmake\b", lowered))
    return has_veo_signal and has_creation_verb


VEO_PROMPT_TEMPLATE = TaskTemplate(
    key="veo_prompt",
    category=INTENT_CREATION_TASK,
    match=_match_veo_prompt,
    required_fields=[
        RequiredField(
            name="style",
            prompt="What style — cinematic cybersecurity, SaaS dashboard, neural globe, or product ad?",
            options=["cinematic cybersecurity", "saas dashboard", "neural globe", "product ad"],
        ),
        RequiredField(
            name="duration",
            prompt="How long — 8s, 15s, or 30s?",
            options=["8s", "15s", "30s"],
        ),
        RequiredField(
            name="main_visual",
            prompt="What's the main visual — shield, globe, dashboard, or particles?",
            options=["shield", "globe", "dashboard", "particles"],
        ),
        RequiredField(
            name="cta",
            prompt="What CTA text should appear at the end?",
            options=None,
        ),
    ],
)

# Registry of templated tasks. Adding a new template later (e.g. a Phase 3+
# NDA/PDF template) means registering one more TaskTemplate here, not adding
# new branching logic to the classifier or the assistant route.
TASK_TEMPLATES: Dict[str, TaskTemplate] = {
    VEO_PROMPT_TEMPLATE.key: VEO_PROMPT_TEMPLATE,
}


_BRAND_NAME_PATTERN = re.compile(r"\bfor ([A-Z][\w]*)\b")


def extract_brand_name(message: str, *, default: str = "your brand") -> str:
    """Deterministic string extraction, not an LLM call."""
    match = _BRAND_NAME_PATTERN.search(message)
    return match.group(1) if match else default


# Known app names this deterministically extracts -- kept in sync with
# agents/system_agent/system_agent.py::SystemAgent._APP_TO_WORKER_ACTION's
# key set (both are small, human-app-name-facing tables; this one only
# needs to recognize a name well enough to hand it to SystemAgent, which
# owns the actual open_app -> worker action_type mapping).
_KNOWN_APP_NAMES = [
    "microsoft store", "store", "chrome", "google chrome", "vscode",
    "vs code", "visual studio code", "notepad", "explorer", "file explorer",
    "downloads folder", "downloads",
]

_OPEN_CLOSE_PATTERN = re.compile(r"\b(?:open|close|launch)\s+(?:the\s+)?(.+)$", re.IGNORECASE)


def extract_app_name(message: str) -> Optional[str]:
    """Deterministic string extraction, not an LLM call. Tries known app
    names first (substring match, longest first so "microsoft store"
    matches before a bare "store" would), then falls back to whatever
    follows an open/close/launch verb -- SystemAgent's own
    _map_app_to_worker_action() is the real authority on whether the
    result maps to anything; this just needs to hand it a plausible app
    name string."""
    lowered = message.lower()

    for name in sorted(_KNOWN_APP_NAMES, key=len, reverse=True):
        if name in lowered:
            return name

    match = _OPEN_CLOSE_PATTERN.search(message)
    if match:
        return match.group(1).strip().rstrip(".!?")

    return None


# =============================================================================
# Classifier entrypoint
# =============================================================================

def classify(
    message: str,
    action: str = "general_request",
    preferred_agent: Optional[str] = None,
    input_data: Optional[Dict[str, Any]] = None,
) -> IntentClassification:
    """Deterministic, no-LLM classification of a user message."""

    planner_result = Planner().detect_intent(
        message=message,
        action=action,
        preferred_agent=preferred_agent,
        input_data=input_data,
    )
    planner_data = planner_result.get("data") or {} if planner_result.get("success") else {}

    primary_agent = planner_data.get("primary_agent", "business")
    secondary_agents = planner_data.get("secondary_agents", [])
    risk_level = planner_data.get("risk_level", "low")
    requires_security = bool(planner_data.get("requires_security", False))
    confidence = float(planner_data.get("confidence", 0.0))

    lowered = message.lower()

    template_key: Optional[str] = None
    required_fields: List[RequiredField] = []
    category: Optional[str] = None

    for template in TASK_TEMPLATES.values():
        if template.match(message):
            template_key = template.key
            required_fields = template.required_fields
            category = template.category
            break

    if category is None:
        for candidate_category, keywords in _CATEGORY_RULES.items():
            if _matches_any(lowered, keywords):
                category = candidate_category
                break

    if category is None:
        category = INTENT_KNOWLEDGE_QUESTION

    # Safety wins ties: an elevated risk level always relabels the category,
    # even if a template also matched (the template's required_fields are
    # left untouched, since the clarification flow is still meaningful for a
    # risky-but-templated task -- only the human-facing category changes).
    if risk_level not in ("low", None, ""):
        category = INTENT_RISKY_SECURITY_ACTION

    return IntentClassification(
        category=category,
        template_key=template_key,
        required_fields=required_fields,
        primary_agent=primary_agent,
        secondary_agents=secondary_agents,
        risk_level=risk_level,
        requires_security=requires_security,
        confidence=confidence,
    )


def missing_fields(
    required_fields: List[RequiredField],
    collected_inputs: Dict[str, Any],
) -> List[RequiredField]:
    """Generic across any template -- not hardcoded to VEO."""
    missing: List[RequiredField] = []
    for field_spec in required_fields:
        if not field_spec.required:
            continue
        value = collected_inputs.get(field_spec.name)
        if value is None or (isinstance(value, str) and not value.strip()):
            missing.append(field_spec)
    return missing


def merge_free_text_answer(
    required_fields: List[RequiredField],
    collected_inputs: Dict[str, Any],
    message: str,
) -> Dict[str, Any]:
    """
    Best-effort, deterministic slot-filling from one free-text message --
    no LLM call. Matches each still-missing field's fixed `options` list
    against the message (case-insensitive substring match); the one
    remaining free-form field (no `options`, e.g. CTA text) takes a
    quoted substring if present, or text following a "cta"/"call to
    action" keyword, or -- if nothing else is missing and no other clue
    is found -- the trimmed message itself.
    """
    merged = dict(collected_inputs)
    lowered_message = message.lower()

    still_missing = missing_fields(required_fields, merged)
    free_form_fields = [f for f in still_missing if not f.options]
    option_fields = [f for f in still_missing if f.options]

    for field_spec in option_fields:
        for option in field_spec.options or []:
            if option.lower() in lowered_message:
                merged[field_spec.name] = option
                break

    for field_spec in free_form_fields:
        quoted = re.search(r'"([^"]+)"|\'([^\']+)\'', message)
        if quoted:
            merged[field_spec.name] = quoted.group(1) or quoted.group(2)
            continue

        keyword_match = re.search(
            r"(?:cta|call to action)[:\s]+(.+)$", message, re.IGNORECASE
        )
        if keyword_match:
            merged[field_spec.name] = keyword_match.group(1).strip().rstrip(".")
            continue

        # Absolute fallback: only use the raw message if this is the ONLY
        # field still missing, so a multi-field free-text answer doesn't
        # get incorrectly dumped into every remaining free-form field.
        if len(still_missing) == 1 and message.strip():
            merged[field_spec.name] = message.strip()

    return merged


__all__ = [
    "INTENT_CATEGORIES",
    "INTENT_KNOWLEDGE_QUESTION",
    "INTENT_CREATION_TASK",
    "INTENT_PROJECT_BUILD_TASK",
    "INTENT_FILE_GENERATION_TASK",
    "INTENT_WINDOWS_DEVICE_ACTION",
    "INTENT_VOICE_CONTROL_ACTION",
    "INTENT_RISKY_SECURITY_ACTION",
    "INTENT_CALL_ACTION_PROVIDER_TASK",
    "INTENT_BROWSER_RESEARCH_TASK",
    "INTENT_DESIGN_TASK",
    "INTENT_CODE_DEBUG_TASK",
    "INTENT_MULTI_STEP_WORKFLOW",
    "RequiredField",
    "TaskTemplate",
    "IntentClassification",
    "TASK_TEMPLATES",
    "VEO_PROMPT_TEMPLATE",
    "classify",
    "missing_fields",
    "merge_free_text_answer",
    "extract_brand_name",
    "extract_app_name",
]
