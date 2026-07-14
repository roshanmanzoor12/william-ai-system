"""
core/final_response_builder.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Phase 1 (Conversational Assistant Brain) — the single shared place that
turns a MasterAgent/agent result dict into a human-readable answer, instead
of every caller re-deriving one on its own.

This generalizes the naive 3-tier fallback that used to live only in
apps/api/services/voice_service.py::_extract_response_text (message ->
data.summary/data.message -> generic canned string) into a 4-tier synthesis
that actually reads state.execution_results for a multi-step plan, while
staying a strict superset of the old logic for every shape the existing
voice tests exercise (voice_service.py now delegates to this module instead
of duplicating it).

No LLM call anywhere in this file. `route` and `generated_files` are only
ever populated from data that is actually present in the result -- never
fabricated. An empty `generated_files: []` is the honest, correct answer
until a later phase wires up real file generation.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# Known generic wrapper messages that don't actually describe what happened
# -- worth synthesizing something better from execution_results/errors
# instead of surfacing verbatim. Kept in sync with core/master_agent.py's
# FallbackResponseBuilder and the pre-existing voice_service.py fallback.
_GENERIC_WRAPPER_MESSAGES = {
    "Master Agent completed request.",
    "Master Agent completed request with errors.",
    "Task processed.",
    "",
    None,
}

_DEFAULT_SUCCESS_FALLBACK = "Task processed."
_DEFAULT_FAILURE_FALLBACK = "The task could not be completed."


def _normalize_error(master_result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """master_result.get('error') is inconsistently either a string or a
    dict depending on the caller/agent -- normalize both shapes once, here,
    instead of every caller re-deriving it."""
    raw_error = master_result.get("error")
    if raw_error is None:
        return None
    if isinstance(raw_error, dict):
        return {
            "code": raw_error.get("code", "UNKNOWN_ERROR"),
            "message": raw_error.get("message") or master_result.get("message") or "An error occurred.",
            "details": raw_error.get("details"),
        }
    return {
        "code": "UNKNOWN_ERROR",
        "message": str(raw_error),
        "details": None,
    }


def _synthesize_from_results(data: Dict[str, Any]) -> Optional[str]:
    """Turn a multi-step plan's execution_results into one or two natural
    sentences, instead of just picking whatever top-level string is
    available. Returns None if there's nothing usable to synthesize from
    (caller falls through to the generic fallback)."""
    results = data.get("results") or data.get("execution_results")
    if not isinstance(results, list) or not results:
        return None

    successful_messages = [
        str(item.get("message")).strip()
        for item in results
        if isinstance(item, dict) and item.get("success") is True and item.get("message")
    ]
    if successful_messages:
        # Dedupe while preserving order -- multiple steps often share the
        # same underlying agent message.
        seen = set()
        unique_messages = []
        for message in successful_messages:
            if message not in seen:
                seen.add(message)
                unique_messages.append(message)
        return " ".join(unique_messages[:3])

    errors = data.get("errors")
    if isinstance(errors, list) and errors:
        error_descriptions = []
        for item in errors:
            if isinstance(item, dict):
                payload = item.get("payload")
                description = None
                if isinstance(payload, dict):
                    description = payload.get("message") or payload.get("error")
                error_descriptions.append(str(description or item.get("error_type") or "an error"))
        if error_descriptions:
            return "This could not be completed: " + "; ".join(error_descriptions[:2]) + "."

    return None


def _derive_route(data: Dict[str, Any], route_hint: Optional[List[str]]) -> List[str]:
    """Never fabricated -- only ever derived from real data actually
    present, or an explicit hint the caller already computed (e.g. from
    core/intent_classifier.py's own classification, which already knows
    the primary/secondary agent) for cases where the raw result doesn't
    echo the agent name back."""
    if route_hint:
        return list(dict.fromkeys(route_hint))

    agents_used: List[str] = []
    results = data.get("results") or data.get("execution_results")
    if isinstance(results, list):
        for item in results:
            if not isinstance(item, dict):
                continue
            agent_name = (
                item.get("agent_name")
                or (item.get("data") or {}).get("agent_name")
                or (item.get("metadata") or {}).get("agent")
            )
            if agent_name and agent_name not in agents_used:
                agents_used.append(str(agent_name))

    return agents_used


def _derive_generated_files(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Stays [] until a real file-generation phase populates it -- never a
    placeholder/fake entry."""
    generated_files: List[Dict[str, Any]] = []
    results = data.get("results") or data.get("execution_results")
    if not isinstance(results, list):
        return generated_files

    for item in results:
        if not isinstance(item, dict):
            continue
        item_data = item.get("data") or {}
        candidate = item_data.get("generated_files")
        if isinstance(candidate, list):
            generated_files.extend(candidate)
        file_id = item_data.get("file_id")
        if file_id:
            generated_files.append(
                {
                    "file_id": file_id,
                    "filename": item_data.get("filename"),
                    "download_url": item_data.get("download_url"),
                }
            )

    return generated_files


def _tone_wrap(text: str, status: str, *, apply_tone: bool) -> str:
    """Light, rule-based phrasing -- no LLM. Only applied when the caller
    opts in (apply_tone=True), so terse dashboard/analytics-style responses
    elsewhere in the app don't suddenly all say "Boss" out of nowhere."""
    if not apply_tone or not text:
        return text

    lowered = text.lower()
    if status == "waiting_for_user":
        if not lowered.startswith(("boss", "i need", "i can")):
            return f"Boss, I can do that — {text[0].lower()}{text[1:]}" if text else text
        return text
    if status == "completed":
        if not lowered.startswith(("done boss", "boss")):
            return f"Done boss, {text[0].lower()}{text[1:]}" if text else text
        return text
    if status == "failed":
        if not lowered.startswith(("boss", "i need", "i can", "i'm not", "i cannot", "i can't")):
            return f"Boss, {text[0].lower()}{text[1:]}" if text else text
        return text
    return text


def build_final_response(
    master_result: Optional[Dict[str, Any]],
    *,
    override_status: Optional[str] = None,
    override_follow_up_questions: Optional[List[str]] = None,
    route_hint: Optional[List[str]] = None,
    apply_tone: bool = False,
) -> Dict[str, Any]:
    """
    Returns exactly:
        {final_answer, follow_up_questions, status, route, generated_files, error}

    `override_status`/`override_follow_up_questions` let a caller like
    apps/api/routes/assistant.py express states MasterAgent itself has no
    concept of (e.g. "waiting_for_user" for a clarifying question) without
    this module needing to know anything about conversation sessions.
    """
    if not master_result:
        return {
            "final_answer": "",
            "follow_up_questions": override_follow_up_questions or [],
            "status": override_status or "failed",
            "route": route_hint or [],
            "generated_files": [],
            "error": None,
        }

    data = master_result.get("data") or {}
    if not isinstance(data, dict):
        data = {}

    success = bool(master_result.get("success"))
    status = override_status or ("completed" if success else "failed")

    top_level_message = master_result.get("message")
    final_answer: Optional[str] = None

    # Tier 1: an explicit final_answer already set upstream (forward-compat
    # with core/master_agent.py's MasterExecutionState.final_response, an
    # already-declared-but-currently-unused field).
    if isinstance(data.get("final_answer"), str) and data["final_answer"].strip():
        final_answer = data["final_answer"]

    # Tier 2: the top-level message, unless it's one of the known-generic
    # wrapper strings -- in which case try to synthesize something real
    # instead of surfacing the wrapper verbatim.
    if final_answer is None and top_level_message not in _GENERIC_WRAPPER_MESSAGES:
        final_answer = str(top_level_message)

    # Tier 3: synthesize from execution_results/errors.
    if final_answer is None:
        final_answer = _synthesize_from_results(data)

    # Tier 4: absolute fallback -- unchanged from the pre-existing behavior.
    if final_answer is None:
        final_answer = _DEFAULT_SUCCESS_FALLBACK if success else _DEFAULT_FAILURE_FALLBACK

    final_answer = _tone_wrap(final_answer, status, apply_tone=apply_tone)

    return {
        "final_answer": final_answer,
        "follow_up_questions": override_follow_up_questions or [],
        "status": status,
        "route": _derive_route(data, route_hint),
        "generated_files": _derive_generated_files(data),
        "error": _normalize_error(master_result) if not success else None,
    }


__all__ = ["build_final_response"]
