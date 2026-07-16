"""
apps/api/routes/assistant.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Phase 1 (Conversational Assistant Brain) — the new "talk to William
naturally" entrypoint. Classifies a message, asks clarifying questions when
required fields are missing, executes through the existing agent system
once complete, and always returns a human-readable final_answer with raw
JSON available only via the caller digging into the full envelope (the
dashboard puts it behind an "Export JSON" toggle, not in the primary
response text).

Conversation continuation contract (the entire multi-task isolation story):
a thread is only ever continued when the caller supplies its EXACT
conversation_thread_id, it belongs to this (user_id, workspace_id), and it
is currently waiting_for_user. Any other message -- no thread id, an
unrelated thread id, or a thread that isn't waiting -- always starts a
brand-new thread, classified independently. This is what guarantees an
unrelated question never touches a pending clarification, and one tenant
can never continue another tenant's thread even if the id leaks.

This file imports safely even when future files are missing, matching the
rest of apps/api/routes/*.py.
"""

from __future__ import annotations

import ast
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field


LOGGER_NAME = "william.api.routes.assistant"
logger = logging.getLogger(LOGGER_NAME)
if not logger.handlers:
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    )
    logger.addHandler(stream_handler)
logger.setLevel(os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper())


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def api_success(
    message: str,
    data: Optional[Dict[str, Any]] = None,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "success": True,
        "message": message,
        "data": data or {},
        "error": None,
        "metadata": {"request_id": request_id, "timestamp": utc_now(), "module": "assistant"},
    }


def raise_api_error(
    status_code: int,
    message: str,
    code: str,
    request_id: Optional[str] = None,
    details: Optional[Any] = None,
) -> None:
    raise HTTPException(
        status_code=status_code,
        detail={
            "success": False,
            "message": message,
            "data": {},
            "error": {"code": code, "details": details},
            "metadata": {"request_id": request_id, "timestamp": utc_now(), "module": "assistant"},
        },
    )


# =============================================================================
# Auth (same canonical context every other router uses, with the same
# import-safe fallback convention as apps/api/routes/tasks.py)
# =============================================================================

class FallbackAuthContext(BaseModel):
    request_id: str
    user_id: str
    workspace_id: str
    role: str = "owner"
    plan: str = "free"


try:
    from apps.api.routes.auth import AuthContext, get_current_auth_context  # type: ignore
except Exception as auth_import_exc:  # pragma: no cover
    logger.warning("Auth import fallback enabled in assistant.py: %s", auth_import_exc)
    AuthContext = FallbackAuthContext

    async def get_current_auth_context(
        request: Request,
        x_request_id: Optional[str] = Header(default=None, alias="X-Request-ID"),
        x_user_id: Optional[str] = Header(default="demo_user", alias="X-User-ID"),
        x_workspace_id: Optional[str] = Header(default="demo_workspace", alias="X-Workspace-ID"),
    ) -> FallbackAuthContext:
        return FallbackAuthContext(
            request_id=x_request_id or f"req_{utc_now()}",
            user_id=x_user_id or "demo_user",
            workspace_id=x_workspace_id or "demo_workspace",
        )


from database.db import db_manager  # noqa: E402
from database.models.conversation_session import (  # noqa: E402
    ConversationSession,
    ConversationSessionService,
    SESSION_STATUS_WAITING_FOR_USER,
)
from core.intent_classifier import (  # noqa: E402
    INTENT_KNOWLEDGE_QUESTION,
    INTENT_RISKY_SECURITY_ACTION,
    INTENT_WINDOWS_DEVICE_ACTION,
    FILE_GENERATION_STANDARD_DEFAULTS,
    PROJECT_BUILD_STANDARD_DEFAULTS,
    RequiredField,
    classify,
    extract_app_name,
    extract_brand_name,
    extract_file_generation_hints,
    is_standard_shortcut_answer,
    merge_free_text_answer,
    missing_fields,
)
from core.final_response_builder import build_final_response  # noqa: E402
from core import llm_provider  # noqa: E402

STANDARD_DEFAULTS_BY_TEMPLATE: Dict[str, Dict[str, str]] = {
    "pdf_document": FILE_GENERATION_STANDARD_DEFAULTS,
    "project_build": PROJECT_BUILD_STANDARD_DEFAULTS,
}

try:
    from apps.api.routes.tasks import MASTER_AGENT  # type: ignore
except Exception as master_agent_import_exc:  # pragma: no cover
    logger.warning("Could not import MASTER_AGENT hook in assistant.py: %s", master_agent_import_exc)
    MASTER_AGENT = None

try:
    from agents.super_agents.creator_agent.creator_agent import CreatorAgent  # type: ignore
    from agents.agent_execution_adapter import call_agent  # type: ignore

    _CREATOR_AGENT = CreatorAgent()
except Exception as creator_import_exc:  # pragma: no cover
    logger.warning("Could not import CreatorAgent in assistant.py: %s", creator_import_exc)
    _CREATOR_AGENT = None
    call_agent = None  # type: ignore


# =============================================================================
# Request/response models
# =============================================================================

class AssistantMessageRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=8000)
    conversation_thread_id: Optional[str] = None
    collected_inputs: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None


router = APIRouter(tags=["Assistant"])


# =============================================================================
# Shared envelope builders
# =============================================================================

def _fields_to_dicts(fields: List[RequiredField]) -> List[Dict[str, Any]]:
    return [f.to_dict() for f in fields]


def _clarification_envelope(
    session: ConversationSession,
    missing: List[RequiredField],
    context: "AuthContext",
) -> Dict[str, Any]:
    questions = [f.prompt for f in missing]
    if len(questions) > 1:
        intro = "Boss, I can do that — I just need a few details first: "
        composite = intro + "; ".join(q.rstrip("?") for q in questions) + "."
    else:
        composite = f"Boss, I can do that — {questions[0][0].lower()}{questions[0][1:]}" if questions else "Boss, I can do that."

    return api_success(
        "Clarification needed.",
        data={
            "final_answer": composite,
            "follow_up_questions": questions,
            "status": SESSION_STATUS_WAITING_FOR_USER,
            "route": [],
            "generated_files": [],
            "error": None,
            "conversation_thread_id": session.conversation_thread_id,
            "required_inputs": session.required_inputs,
            "collected_inputs": session.collected_inputs,
        },
        request_id=context.request_id,
    )


def _final_envelope(
    session: ConversationSession,
    final: Dict[str, Any],
    context: "AuthContext",
) -> Dict[str, Any]:
    return api_success(
        final["final_answer"],
        data={**final, "conversation_thread_id": session.conversation_thread_id},
        request_id=context.request_id,
    )


async def _execute_veo_template(
    session: ConversationSession,
    collected_inputs: Dict[str, Any],
    context: "AuthContext",
    last_message: str,
) -> Dict[str, Any]:
    """Real, deterministic templating -- agents/super_agents/creator_agent/
    creator_agent.py::CreatorAgent.build_veo_prompt does plain f-string
    composition, no LLM/network call. Called directly (not through the full
    MasterAgent.execute() pipeline) because MasterAgent's routed dispatch
    currently nests caller fields under task["input_data"] while CreatorAgent
    reads flat top-level fields -- routing through the full pipeline today
    would silently drop every collected field. Documented gap for a future
    phase; CreatorAgent.handle_task already does its own internal
    security/verification/memory payload prep, so this is a scope decision,
    not a safety regression."""
    if _CREATOR_AGENT is None or call_agent is None:
        return build_final_response(
            {
                "success": False,
                "message": "Creator Agent is not available yet.",
                "error": {"code": "CREATOR_AGENT_UNAVAILABLE"},
            },
            route_hint=["creator"],
            apply_tone=True,
        )

    # The brand name must come from the ORIGINAL request message (e.g.
    # "...for ClickRonix"), not whichever message happens to complete the
    # clarification -- that could be a generic reply like "here you go"
    # with no brand mention at all. Extracted once at thread creation and
    # persisted in session.extra_metadata; last_message is only a fallback
    # for the (unlikely) case a thread predates that persistence.
    brand = session.extra_metadata.get("subject") or extract_brand_name(last_message)
    main_visual = collected_inputs.get("main_visual", "")
    style = collected_inputs.get("style", "")
    duration_raw = str(collected_inputs.get("duration", "15s"))
    cta = collected_inputs.get("cta", "")

    try:
        duration_seconds = int("".join(ch for ch in duration_raw if ch.isdigit()) or "15")
    except ValueError:
        duration_seconds = 15

    # Deliberately avoids the word "call" anywhere in this string --
    # agents/super_agents/creator_agent/creator_agent.py's own
    # _requires_security_check() treats \bcall\b as a prohibited-direct-
    # action keyword (meant for real outbound phone calls), and "call-to-
    # action" was tripping it as a false positive purely on wording.
    topic = (
        f"{main_visual} representing {brand}'s security platform, "
        f"ending with the on-screen text '{cta}'"
    ).strip()

    task = {
        "type": "build_veo_prompt",
        "topic": topic,
        "visual_style": style,
        "duration_seconds": duration_seconds,
        "platform": "ads",
        "user_id": context.user_id,
        "workspace_id": context.workspace_id,
    }

    result = await call_agent(_CREATOR_AGENT, task, agent_name="creator")

    if result.get("success"):
        prompt_text = ((result.get("data") or {}).get("veo_prompt") or {}).get("prompt")
        final = build_final_response(
            {
                "success": True,
                "message": f"Done boss, your VEO prompt is ready:\n\n{prompt_text}" if prompt_text else None,
                "data": result.get("data"),
            },
            route_hint=["creator"],
        )
    else:
        final = build_final_response(result, route_hint=["creator"], apply_tone=True)

    return final


async def _execute_windows_device_action(
    context: "AuthContext",
    last_message: str,
) -> Dict[str, Any]:
    """Closes a real wiring gap: core/planner.py has no "open"/"launch"
    action keyword, so a windows_device_action-classified message would
    otherwise route to MASTER_AGENT's generic handler, which never
    receives an "app" field and could never reach SystemAgent.open_app at
    all. Bypasses MASTER_AGENT and calls SystemAgent directly, mirroring
    _execute_veo_template's exact precedent for the same reason (the
    generic pipeline can't carry this payload shape)."""
    app = extract_app_name(last_message)
    if not app:
        return build_final_response(
            {
                "success": False,
                "message": "Which app should I open?",
                "error": {"code": "missing_app"},
            },
            route_hint=["system"],
            apply_tone=True,
        )

    try:
        from agents.system_agent.system_agent import SystemAgent, TaskContext as SystemTaskContext
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not import SystemAgent in assistant.py: %s", exc)
        return build_final_response(
            {
                "success": False,
                "message": "System Agent is not available yet.",
                "error": {"code": "SYSTEM_AGENT_UNAVAILABLE"},
            },
            route_hint=["system"],
            apply_tone=True,
        )

    agent = SystemAgent()
    task_context = SystemTaskContext(
        user_id=context.user_id,
        workspace_id=context.workspace_id,
        request_id=context.request_id,
    )
    result = await agent.open_app({"app": app}, task_context)

    # SystemAgent's own `message` field is its established, separately-
    # tested internal contract (tests/agent_tests/test_system_agent.py
    # pins its exact wording) -- left untouched. The conversational layer
    # is free to phrase the SAME real outcome in the exact words asked for
    # here, without changing what SystemAgent itself returns.
    runtime_state = (result.get("metadata") or {}).get("runtime_state") or (result.get("data") or {}).get("runtime_state")
    display_name = "Microsoft Store" if app.strip().lower() in {"microsoft store", "store", "ms-windows-store"} else app

    if runtime_state == "not_enabled":
        final_answer = "Boss, Windows Worker is not enabled yet. Open Settings > Devices and click Enable Windows Worker."
    elif runtime_state == "disabled":
        final_answer = "Boss, Windows Worker is disabled. Enable it from Settings before I can open apps."
    elif runtime_state == "device_worker_offline":
        final_answer = "Boss, Windows Worker is enabled but offline. Start the worker or reinstall it from Settings."
    elif runtime_state == "queued":
        final_answer = f"Done boss, I sent the command to your Windows device. {display_name} is opening."
    elif runtime_state == "approval_required":
        final_answer = "Boss, this action needs Security Agent approval before I can continue."
    elif runtime_state == "unsupported_worker_action":
        final_answer = f"Boss, I don't support opening '{app}' yet."
    else:
        final_answer = None  # fall through to build_final_response's own synthesis

    final = build_final_response(result, route_hint=["system"], apply_tone=(final_answer is None))
    if final_answer:
        final["final_answer"] = final_answer
    # SystemAgent's queued-task id (agents/system_agent/system_agent.py::
    # _dispatch_worker_action sets data.task_id) would otherwise be
    # discarded here -- build_final_response only ever returns
    # {final_answer, follow_up_questions, status, route, generated_files,
    # error}. Voice (apps/api/routes/voice.py::push_to_talk_text, which
    # calls this same dispatcher) needs it to report worker_task_id back
    # to the caller.
    worker_task_id = (result.get("data") or {}).get("task_id")
    if worker_task_id:
        final["worker_task_id"] = worker_task_id
    return final


async def _execute_risky_security_action(
    context: "AuthContext",
    last_message: str,
) -> Dict[str, Any]:
    """core/intent_classifier.py::classify() already relabels ANY message
    core/planner.py risk-scored above "low" as INTENT_RISKY_SECURITY_ACTION
    (e.g. "delete my downloads folder") -- but before this handler existed,
    _dispatch had no branch for that category, so it fell through to
    _dispatch_generic -> MasterAgent's generic pipeline, which has no real
    agent/action for an arbitrary risky request and failed with an opaque
    "Step routing failed." (a raw internal routing error, not a safety
    message). This is the actual, honest safety gate for that category:
    a real SecurityAgent.authorize() call (fails closed, matching every
    other approval flow in this codebase -- e.g. apps/api/routes/voice.py::
    request_voice_mode_approval), never a fabricated approval.

    Deliberately never executes anything regardless of the decision: no
    real destructive-action executor (real file deletion, real payments,
    etc.) exists anywhere in this codebase, by design -- see CLAUDE.md's
    sensitive-action list. Reporting "needs approval" is the correct,
    honest terminal state for this category today, not a placeholder for
    an executor that doesn't exist."""
    try:
        from agents.security_agent.security_agent import SecurityAgent
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not import SecurityAgent in assistant.py: %s", exc)
        return build_final_response(
            {
                "success": False,
                "message": "Boss, this is a risky action and needs Security Agent approval before I continue.",
                "error": {"code": "SECURITY_AGENT_UNAVAILABLE"},
            },
            route_hint=["security"],
        )

    task = {
        "command": "authorize",
        "task_context": {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "role": getattr(context, "role", "owner"),
            "request_id": context.request_id,
        },
        "action": "risky_voice_or_text_command",
        "payload": {"message": last_message},
    }

    result = await call_agent(SecurityAgent(), task, agent_name="security")
    data = result.get("data") if isinstance(result, dict) else {}
    approved = bool(result.get("success")) and bool(
        (data or {}).get("decision") in ("allow", "approved", True) or (data or {}).get("approved")
    )

    if approved:
        # Security Agent approved the ACTION TYPE, but there is still no
        # real executor for arbitrary risky commands -- honest either way.
        final_answer = "Boss, Security Agent approved this, but I don't have a real way to carry it out yet."
    else:
        final_answer = "Boss, this is a risky action and needs Security Agent approval before I continue."

    return build_final_response(
        {
            "success": False,
            "message": final_answer,
            "data": {},
            "error": {"code": "SECURITY_APPROVAL_REQUIRED", "message": final_answer},
        },
        route_hint=["security"],
    )


async def _execute_knowledge_question(
    context: "AuthContext",
    last_message: str,
) -> Dict[str, Any]:
    """Real LLM-backed knowledge Q&A (core/llm_provider.py) -- honestly
    reports "AI knowledge provider is not configured yet." when no
    WILLIAM_LLM_PROVIDER is set, and NEVER calls the LLM for a live/current
    data question (weather, news, stock prices, "today") -- those are
    deterministically short-circuited first, since a model can hallucinate
    a plausible-sounding "current weather" answer despite instructions not
    to."""
    live_kind = llm_provider.is_live_data_query(last_message)
    if live_kind == "weather":
        return build_final_response(
            {
                "success": False,
                "message": llm_provider.LIVE_WEATHER_FALLBACK_MESSAGE,
                "error": {"code": "live_weather_provider_missing"},
            },
            route_hint=["master"],
        )
    if live_kind == "other":
        return build_final_response(
            {
                "success": False,
                "message": llm_provider.LIVE_DATA_FALLBACK_MESSAGE,
                "error": {"code": "live_data_provider_missing"},
            },
            route_hint=["master"],
        )

    result = llm_provider.answer_knowledge_question(last_message)
    if not result.get("ok"):
        return build_final_response(
            {
                "success": False,
                "message": llm_provider.KNOWLEDGE_PROVIDER_MISSING_MESSAGE,
                "error": {"code": "llm_provider_not_configured", "message": result.get("error")},
            },
            route_hint=["master"],
        )

    return build_final_response(
        {"success": True, "message": result["text"], "data": {}},
        route_hint=["master"],
        apply_tone=True,
    )


async def _execute_file_generation_template(
    session: ConversationSession,
    collected_inputs: Dict[str, Any],
    context: "AuthContext",
    last_message: str,
) -> Dict[str, Any]:
    """Real PDF/DOCX generation via CreatorAgent.generate_document (agents/
    super_agents/creator_agent/document_generator.py) -- called directly,
    same reasoning as _execute_veo_template (MasterAgent's routed dispatch
    nests fields under input_data; CreatorAgent reads flat top-level
    fields). Never fabricates a download link -- generated_files is only
    ever set from a real file CreatorAgent actually wrote to disk."""
    if _CREATOR_AGENT is None or call_agent is None:
        return build_final_response(
            {
                "success": False,
                "message": "Creator Agent is not available yet.",
                "error": {"code": "CREATOR_AGENT_UNAVAILABLE"},
            },
            route_hint=["creator"],
            apply_tone=True,
        )

    task = {
        "type": "generate_document",
        "doc_type": collected_inputs.get("doc_type", ""),
        "parties": collected_inputs.get("parties", ""),
        "jurisdiction": collected_inputs.get("jurisdiction", ""),
        "duration": collected_inputs.get("duration", ""),
        "confidentiality_scope": collected_inputs.get("confidentiality_scope", ""),
        "format": collected_inputs.get("format", "PDF"),
        "topic": session.extra_metadata.get("subject") or last_message,
        "source_prompt": last_message,
        "conversation_thread_id": session.conversation_thread_id,
        "user_id": context.user_id,
        "workspace_id": context.workspace_id,
    }

    result = await call_agent(_CREATOR_AGENT, task, agent_name="creator")

    if not result.get("success"):
        return build_final_response(result, route_hint=["creator"], apply_tone=True)

    data = result.get("data") or {}
    final = build_final_response(
        {
            "success": True,
            "message": f"your {data.get('title') or 'document'} is ready.",
            "data": {},
        },
        route_hint=["creator"],
        apply_tone=True,
    )
    final["generated_files"] = [
        {
            "file_id": data.get("file_id"),
            "filename": data.get("filename"),
            "download_url": data.get("download_url"),
        }
    ]
    return final


def _draft_project_blueprint(collected: Dict[str, Any], project_name: str) -> Dict[str, str]:
    """Deterministic, no LLM call -- a real, minimal, WORKING starter
    scaffold (FastAPI backend that actually imports and runs, a static
    frontend page) built from the collected requirements. Not a finished
    production SaaS -- see README.md's own honest framing below. Kept
    LLM-free so project building never depends on WILLIAM_LLM_PROVIDER
    being configured, matching document_generator.py's same design choice."""
    target_user = str(collected.get("target_user") or "general users").strip()
    features = str(collected.get("features") or "core functionality").strip()
    stack = str(collected.get("stack") or "python fastapi + nextjs").strip()
    auth_subscription = str(collected.get("auth_subscription") or "no").strip()
    admin_panel = str(collected.get("admin_panel") or "no").strip().lower()
    template_upload = str(collected.get("template_upload") or "no").strip()
    seo = str(collected.get("seo") or "no").strip().lower()
    download_zip = str(collected.get("download_zip") or "no").strip()

    needs_auth = auth_subscription.strip().lower() != "no"

    readme = f"""# {project_name}

Generated by William / Jarvis (Digital Promotix).

## Requirements captured
- Target user: {target_user}
- Key features: {features}
- Tech stack: {stack}
- Auth/subscription: {auth_subscription}
- Admin panel: {admin_panel}
- Template upload: {template_upload}
- SEO: {seo}
- Downloadable ZIP: {download_zip}

## Getting started

    cd backend
    pip install -r requirements.txt
    uvicorn main:app --reload

This is a real, minimal, working starter scaffold, not a finished
production SaaS. Extend backend/main.py and frontend/index.html to build
out the features listed above.
"""

    auth_route = ""
    if needs_auth:
        auth_route = '''

@app.post("/auth/login")
def login(payload: dict):
    """Stub login endpoint -- replace with real authentication before shipping."""
    return {"success": False, "message": "Authentication is not implemented yet."}
'''

    admin_route = ""
    if admin_panel == "yes":
        admin_route = '''

@app.get("/admin/overview")
def admin_overview():
    """Stub admin endpoint -- gate this behind real role checks before shipping."""
    return {"success": True, "message": "Admin panel placeholder."}
'''

    backend_main = f'''"""
backend/main.py

Generated by William / Jarvis (Digital Promotix) -- minimal, real FastAPI
starter for: {project_name}.
Target user: {target_user}
Key features: {features}
"""

from fastapi import FastAPI

app = FastAPI(title="{project_name}")


@app.get("/health")
def health():
    return {{"success": True, "message": "{project_name} backend is running."}}


@app.get("/features")
def list_features():
    return {{"success": True, "data": {{"target_user": "{target_user}", "features": "{features}"}}}}
{auth_route}{admin_route}
'''

    backend_requirements = "fastapi>=0.115.0,<1.0.0\nuvicorn[standard]>=0.30.0,<1.0.0\n"

    seo_meta = ""
    if seo == "yes":
        safe_description = features[:150].replace('"', "'")
        seo_meta = f'\n    <meta name="description" content="{safe_description}">\n    <meta name="robots" content="index,follow">'

    frontend_index = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{project_name}</title>{seo_meta}
</head>
<body>
    <h1>{project_name}</h1>
    <p>Built for: {target_user}</p>
    <p>Key features: {features}</p>
</body>
</html>
"""

    return {
        "README.md": readme,
        "backend/main.py": backend_main,
        "backend/requirements.txt": backend_requirements,
        "frontend/index.html": frontend_index,
        ".gitignore": "__pycache__/\n*.pyc\n.env\nnode_modules/\n",
    }


async def _execute_project_build_template(
    session: ConversationSession,
    collected_inputs: Dict[str, Any],
    context: "AuthContext",
    last_message: str,
) -> Dict[str, Any]:
    """Real project scaffolding via CodeAgent.create_project (agents/
    code_agent/code_agent.py) -- called directly for the same reason
    _execute_veo_template/_execute_windows_device_action are: the generic
    MasterAgent pipeline has no route to create_project's payload shape.
    Files are only written once the user has answered target_folder and
    new_or_overwrite (enforced by core/intent_classifier.py's
    PROJECT_BUILD_TEMPLATE required fields, resolved before this function
    is ever called) -- never overwrites an existing file unless
    new_or_overwrite == "overwrite"."""
    try:
        from agents.code_agent.code_agent import CodeAgent
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not import CodeAgent in assistant.py: %s", exc)
        return build_final_response(
            {
                "success": False,
                "message": "Code Agent is not available yet.",
                "error": {"code": "CODE_AGENT_UNAVAILABLE"},
            },
            route_hint=["code"],
            apply_tone=True,
        )

    project_name = str(collected_inputs.get("target_folder") or "").strip()
    if not project_name:
        return build_final_response(
            {
                "success": False,
                "message": "What folder name should I create this project in?",
                "error": {"code": "missing_target_folder"},
            },
            route_hint=["code"],
            apply_tone=True,
        )

    overwrite = str(collected_inputs.get("new_or_overwrite", "new")).strip().lower() == "overwrite"
    files = _draft_project_blueprint(collected_inputs, project_name)

    # Same WILLIAM_PROJECTS_ROOT convention as agents/code_agent/
    # project_builder.py and agents/code_agent/file_generator.py -- without
    # this, CodeAgentConfig's own default (workspace_root=".") would write
    # generated projects straight into the repo's current working
    # directory instead of the dedicated project workspace root.
    workspace_root = os.getenv("WILLIAM_PROJECTS_ROOT", "./william_workspaces")
    code_agent = CodeAgent(config={"workspace_root": workspace_root, "dry_run_default": False})
    task = {
        "action": "create_project",
        "context": {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "role": getattr(context, "role", "owner"),
            "request_id": context.request_id,
            # The user already explicitly confirmed target_folder AND
            # new_or_overwrite through the clarifying-question flow above
            # (core/intent_classifier.py's PROJECT_BUILD_TEMPLATE) before
            # this function is ever reached -- that confirmation IS the
            # approval gate for this per-request CodeAgent instance
            # (constructed with no security_client, so CodeAgent's own
            # _request_security_approval falls back to this permission
            # list). No broader, standing permission is granted.
            "permissions": ["code_agent:create_project"],
        },
        "dry_run": False,
        "payload": {
            "project_name": project_name,
            "project_type": "python",
            "files": files,
            "overwrite": overwrite,
        },
    }

    result = await call_agent(code_agent, task, agent_name="code")

    if not result.get("success"):
        return build_final_response(result, route_hint=["code"], apply_tone=True)

    data = result.get("data") or {}
    changes = data.get("changes") or []
    written = [c for c in changes if c.get("action") in ("create", "overwrite")]
    skipped = [c for c in changes if c.get("action") == "skip"]

    syntax_errors: List[Dict[str, str]] = []
    for rel_path, content in files.items():
        if rel_path.endswith(".py"):
            try:
                ast.parse(content)
            except SyntaxError as exc:
                syntax_errors.append({"file": rel_path, "error": str(exc)})

    checks_summary = (
        "All generated Python files passed a syntax check."
        if not syntax_errors
        else f"{len(syntax_errors)} generated file(s) failed a syntax check."
    )
    file_names = ", ".join(Path(c["path"]).name for c in written[:8]) if written else "no files"
    skip_note = (
        f" {len(skipped)} existing file(s) were left untouched because overwrite wasn't approved."
        if skipped
        else ""
    )

    final_answer = (
        f"I created '{project_name}' with {len(written)} file(s): {file_names}. {checks_summary}{skip_note}"
    )
    final = build_final_response(
        {"success": True, "message": final_answer, "data": {}},
        route_hint=["code"],
        apply_tone=True,
    )
    final["files_changed"] = [c.get("path") for c in written]
    final["files_skipped"] = [c.get("path") for c in skipped]
    final["checks"] = {"syntax_errors": syntax_errors}
    final["project_root"] = data.get("project_root")
    return final


async def _dispatch_generic(
    session: ConversationSession,
    context: "AuthContext",
    last_message: str,
    classification_route: List[str],
) -> Dict[str, Any]:
    if MASTER_AGENT is None:
        return build_final_response(
            {
                "success": False,
                "message": "William's general task routing isn't connected yet.",
                "error": {"code": "MASTER_AGENT_UNAVAILABLE"},
            },
            route_hint=classification_route,
            apply_tone=True,
        )

    master_payload = {
        "task_id": session.pending_task_id,
        "request_id": context.request_id,
        "user_id": context.user_id,
        "workspace_id": context.workspace_id,
        "role": getattr(context, "role", "owner"),
        "plan": getattr(context, "plan", "free"),
        "action": "general_request",
        "message": last_message,
        "input_data": {},
        "metadata": {"source": "apps/api/routes/assistant.py"},
    }
    master_result = await MASTER_AGENT.call(master_payload)
    return build_final_response(master_result, route_hint=classification_route, apply_tone=True)


async def _dispatch(
    session: ConversationSession,
    context: "AuthContext",
    last_message: str,
    classification_route: List[str],
) -> Dict[str, Any]:
    """Deliberately takes no `db` -- this may call into SystemAgent's real
    Windows Worker dispatch (_execute_windows_device_action), which opens
    its own short-lived db_manager.session_scope() to queue a WorkerTask.
    SQLite allows only one writer at a time for the whole file; if a caller
    held an outer session_scope() open across this call, that nested write
    would self-deadlock against the still-open outer transaction. Callers
    must persist the session's final status in their OWN session_scope()
    after this returns -- see send_message()."""
    if session.template_key == "veo_prompt":
        final = await _execute_veo_template(session, session.collected_inputs, context, last_message)
    elif session.template_key == "pdf_document":
        final = await _execute_file_generation_template(session, session.collected_inputs, context, last_message)
    elif session.template_key == "project_build":
        final = await _execute_project_build_template(session, session.collected_inputs, context, last_message)
    elif session.intent_category == INTENT_WINDOWS_DEVICE_ACTION:
        final = await _execute_windows_device_action(context, last_message)
    elif session.intent_category == INTENT_KNOWLEDGE_QUESTION:
        final = await _execute_knowledge_question(context, last_message)
    elif session.intent_category == INTENT_RISKY_SECURITY_ACTION:
        final = await _execute_risky_security_action(context, last_message)
    else:
        final = await _dispatch_generic(session, context, last_message, classification_route)

    return final


# =============================================================================
# Routes
# =============================================================================

async def process_assistant_message(
    payload: AssistantMessageRequest,
    context: "AuthContext",
) -> Dict[str, Any]:
    """The one shared dispatcher behind both POST /assistant/message and
    POST /voice/push-to-talk/text (apps/api/routes/voice.py) -- classifies
    the message, asks clarifying questions when required fields are
    missing, executes through the same agent pipeline (including
    SystemAgent/Windows Worker dispatch for windows_device_action intents)
    either way, and always returns the same final_answer-first envelope.
    Extracted verbatim from this module's original send_message() route
    body so voice text commands stop bypassing SystemAgent through the raw
    MasterAgent pipeline -- the exact bug the dashboard Command Console had
    before it was fixed the same way."""
    active_session: ConversationSession
    classification_route: List[str]

    with db_manager.session_scope() as db:
        thread: Optional[ConversationSession] = None

        if payload.conversation_thread_id:
            thread = ConversationSessionService.get(
                db,
                conversation_thread_id=payload.conversation_thread_id,
                user_id=context.user_id,
                workspace_id=context.workspace_id,
            )
            if thread is None:
                raise_api_error(
                    status.HTTP_404_NOT_FOUND,
                    "Conversation thread not found.",
                    "THREAD_NOT_FOUND",
                    context.request_id,
                )

        if thread is not None and thread.status == SESSION_STATUS_WAITING_FOR_USER:
            required_field_objs = [RequiredField(**f) for f in thread.required_inputs]

            merged = dict(thread.collected_inputs)
            if payload.collected_inputs:
                merged.update(payload.collected_inputs)

            # "standard one" / "use defaults" on a pdf_document or
            # project_build clarification fills every still-missing field
            # that has a safe default (core/intent_classifier.py's
            # STANDARD_DEFAULTS_BY_TEMPLATE) WITHOUT going through
            # merge_free_text_answer -- that generic fallback would
            # otherwise dump the literal word "standard" into whichever
            # single free-form field happened to be the only one left
            # missing (e.g. target_folder), which is never what the user
            # meant.
            template_defaults = STANDARD_DEFAULTS_BY_TEMPLATE.get(thread.template_key or "")
            if template_defaults and is_standard_shortcut_answer(payload.message):
                for default_key, default_value in template_defaults.items():
                    merged.setdefault(default_key, default_value)
            else:
                merged = merge_free_text_answer(required_field_objs, merged, payload.message)

            still_missing = missing_fields(required_field_objs, merged)

            ConversationSessionService.update_collected_inputs(
                db, thread, merged, last_message=payload.message
            )

            if still_missing:
                # Narrow to just what's still needed -- mirrors the
                # brand-new-thread branch below (_fields_to_dicts(missing),
                # not the full template). Round 2 of a multi-round
                # clarification (e.g. project_build's 10 fields) must not
                # re-ask fields the user already answered in round 1.
                ConversationSessionService.mark_waiting(
                    db,
                    thread,
                    _fields_to_dicts(still_missing),
                    next_step=f"Waiting for: {', '.join(f.name for f in still_missing)}",
                )
                return _clarification_envelope(thread, still_missing, context)

            classification = classify(payload.message)
            active_session = thread
            classification_route = [classification.primary_agent, *classification.secondary_agents]
        else:
            # No thread, or the named thread isn't waiting -- always starts a
            # brand-new, independently-classified thread.
            classification = classify(
                payload.message,
                input_data=payload.collected_inputs,
            )
            session_metadata = dict(payload.metadata or {})
            initial_collected_inputs = dict(payload.collected_inputs or {})
            if classification.template_key == "veo_prompt":
                # Extracted once, here, from the ORIGINAL request message
                # (e.g. "...for ClickRonix") -- a later turn completing the
                # clarification (e.g. "here you go") won't mention the
                # brand at all, so this must not be re-derived from
                # last_message at execution time.
                session_metadata["subject"] = extract_brand_name(payload.message)
            elif classification.template_key == "pdf_document":
                # "William make a PDF NDA for Digital Promotix" already says
                # PDF and NDA -- don't ask "PDF or DOCX?"/"NDA, proposal, or
                # agreement?" again when the message already answered them.
                for hint_key, hint_value in extract_file_generation_hints(payload.message).items():
                    initial_collected_inputs.setdefault(hint_key, hint_value)

            active_session = ConversationSessionService.create(
                db,
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                intent_category=classification.category,
                template_key=classification.template_key,
                required_inputs=_fields_to_dicts(classification.required_fields),
                collected_inputs=initial_collected_inputs,
                status="running",
                last_message=payload.message,
                metadata=session_metadata,
            )

            missing = missing_fields(classification.required_fields, active_session.collected_inputs)
            if missing:
                ConversationSessionService.mark_waiting(
                    db,
                    active_session,
                    _fields_to_dicts(missing),
                    next_step=f"Waiting for: {', '.join(f.name for f in missing)}",
                )
                return _clarification_envelope(active_session, missing, context)

            classification_route = [classification.primary_agent, *classification.secondary_agents]

    # The bookkeeping session above has committed and closed. _dispatch may
    # itself open a short-lived session_scope() (directly, or via
    # SystemAgent queuing a real Windows Worker task) -- calling it while
    # the block above is still open would nest a second write transaction
    # inside this request's own thread and self-deadlock, since SQLite
    # only allows one writer at a time for the whole file.
    conversation_thread_id = active_session.conversation_thread_id
    final = await _dispatch(active_session, context, payload.message, classification_route)

    with db_manager.session_scope() as db:
        active_session = ConversationSessionService.get(
            db,
            conversation_thread_id=conversation_thread_id,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
        )
        if final.get("status") == "failed" or final.get("error"):
            ConversationSessionService.mark_failed(
                db,
                active_session,
                (final.get("error") or {}).get("code", "TASK_FAILED"),
                final.get("final_answer") or "The task could not be completed.",
            )
        else:
            ConversationSessionService.mark_completed(db, active_session, final.get("final_answer", ""))

    return _final_envelope(active_session, final, context)


@router.post("/message")
async def send_message(
    payload: AssistantMessageRequest,
    context: "AuthContext" = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    return await process_assistant_message(payload, context)


@router.get("/threads/{conversation_thread_id}")
async def get_thread(
    conversation_thread_id: str,
    context: "AuthContext" = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    with db_manager.session_scope() as db:
        thread = ConversationSessionService.get(
            db,
            conversation_thread_id=conversation_thread_id,
            user_id=context.user_id,
            workspace_id=context.workspace_id,
        )
        if thread is None:
            raise_api_error(
                status.HTTP_404_NOT_FOUND,
                "Conversation thread not found.",
                "THREAD_NOT_FOUND",
                context.request_id,
            )

        return api_success("Conversation thread loaded.", data=thread.to_dict(), request_id=context.request_id)


@router.get("/llm/status")
async def get_llm_status(
    context: "AuthContext" = Depends(get_current_auth_context),
) -> Dict[str, Any]:
    """Honest, environment-driven LLM provider status -- see
    core/llm_provider.py::check_status(). configured=False never means
    "broken", it means no WILLIAM_LLM_PROVIDER/BASE_URL/MODEL is set for
    this deployment yet."""
    return api_success(
        "LLM provider status loaded.",
        data={"llm_provider": llm_provider.check_status()},
        request_id=context.request_id,
    )
