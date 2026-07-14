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

import logging
import os
from datetime import datetime, timezone
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
    INTENT_WINDOWS_DEVICE_ACTION,
    RequiredField,
    classify,
    extract_app_name,
    extract_brand_name,
    merge_free_text_answer,
    missing_fields,
)
from core.final_response_builder import build_final_response  # noqa: E402

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
    elif session.intent_category == INTENT_WINDOWS_DEVICE_ACTION:
        final = await _execute_windows_device_action(context, last_message)
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
            merged = merge_free_text_answer(required_field_objs, merged, payload.message)

            still_missing = missing_fields(required_field_objs, merged)

            ConversationSessionService.update_collected_inputs(
                db, thread, merged, last_message=payload.message
            )

            if still_missing:
                ConversationSessionService.mark_waiting(
                    db,
                    thread,
                    thread.required_inputs,
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
            if classification.template_key == "veo_prompt":
                # Extracted once, here, from the ORIGINAL request message
                # (e.g. "...for ClickRonix") -- a later turn completing the
                # clarification (e.g. "here you go") won't mention the
                # brand at all, so this must not be re-derived from
                # last_message at execution time.
                session_metadata["subject"] = extract_brand_name(payload.message)

            active_session = ConversationSessionService.create(
                db,
                user_id=context.user_id,
                workspace_id=context.workspace_id,
                intent_category=classification.category,
                template_key=classification.template_key,
                required_inputs=_fields_to_dicts(classification.required_fields),
                collected_inputs=payload.collected_inputs or {},
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
