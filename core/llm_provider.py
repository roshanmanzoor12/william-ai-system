"""
core/llm_provider.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Real "brain" layer -- an OpenAI-compatible chat-completions client. This
single HTTP code path works against real OpenAI, a local Ollama server
(which serves an OpenAI-compatible /v1/chat/completions endpoint), or a
local LM Studio server (same compatibility) -- the only thing that differs
between them is which WILLIAM_LLM_BASE_URL/WILLIAM_LLM_API_KEY/
WILLIAM_LLM_MODEL the operator points at. No provider-specific SDK
branching, no hardcoded secrets, nothing installed automatically.

Mirrors apps/worker_nodes/voice/providers/stt.py's check_status()/honest-
dependency-required convention exactly: configured requires the operator
to have actually set WILLIAM_LLM_PROVIDER + WILLIAM_LLM_BASE_URL +
WILLIAM_LLM_MODEL (WILLIAM_LLM_API_KEY may stay blank for a local
Ollama/LM Studio server that doesn't require one -- only WILLIAM_LLM_
PROVIDER=openai requires a real key). Never fabricates a reply: an
unconfigured or failed call returns ok=False and the caller must surface
an honest "provider not configured" message, never a guessed answer.

Live/current data (weather, news, stock prices, sports scores, "today")
is explicitly out of scope for this module -- see is_live_data_query()
below, which apps/api/routes/assistant.py checks BEFORE ever calling the
LLM, since a model can hallucinate a plausible-sounding "current weather"
answer despite being told not to. That deterministic guard is the actual
enforcement; the system prompt below is defense in depth, not the primary
mechanism.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional

logger = logging.getLogger("william.core.llm_provider")

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - import-safe fallback
    requests = None  # type: ignore


DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_TEMPERATURE = 0.3
DEFAULT_MAX_TOKENS = 900

KNOWLEDGE_SYSTEM_PROMPT = (
    "You are William, a helpful AI assistant built by Digital Promotix. Answer "
    "the user's question directly and naturally, like a knowledgeable "
    "general-purpose assistant. You do not have access to live or current "
    "data (no real-time weather, news, stock prices, sports scores, or "
    "today's actual date/time beyond what the user tells you) -- if a "
    "question genuinely depends on live/current information you do not "
    "have, say so honestly instead of guessing or inventing an answer."
)


def _provider_name() -> str:
    return os.getenv("WILLIAM_LLM_PROVIDER", "").strip().lower()


def _base_url() -> str:
    return os.getenv("WILLIAM_LLM_BASE_URL", "").strip().rstrip("/")


def _api_key() -> str:
    return os.getenv("WILLIAM_LLM_API_KEY", "").strip()


def _model() -> str:
    return os.getenv("WILLIAM_LLM_MODEL", "").strip()


def check_status() -> Dict[str, Any]:
    """Honest, environment-driven status check -- see module docstring for
    exactly what "configured" requires. Returns
    {"configured": bool, "reason": str | None, "install_guidance": str | None}."""
    provider = _provider_name()
    base_url = _base_url()
    model = _model()

    if not provider:
        return {
            "configured": False,
            "reason": "WILLIAM_LLM_PROVIDER is not set",
            "install_guidance": (
                "Set WILLIAM_LLM_PROVIDER=openai with WILLIAM_LLM_BASE_URL/"
                "WILLIAM_LLM_API_KEY for real OpenAI, or WILLIAM_LLM_PROVIDER="
                "ollama / lmstudio for a local, free OpenAI-compatible server."
            ),
        }
    if not base_url:
        return {
            "configured": False,
            "reason": f"WILLIAM_LLM_PROVIDER={provider!r} requires WILLIAM_LLM_BASE_URL",
            "install_guidance": (
                "Set WILLIAM_LLM_BASE_URL, e.g. https://api.openai.com/v1 (OpenAI), "
                "http://localhost:11434/v1 (Ollama), or http://localhost:1234/v1 (LM Studio)."
            ),
        }
    if not model:
        return {
            "configured": False,
            "reason": f"WILLIAM_LLM_PROVIDER={provider!r} requires WILLIAM_LLM_MODEL",
            "install_guidance": (
                "Set WILLIAM_LLM_MODEL to the model name your provider serves, "
                "e.g. gpt-4o-mini (OpenAI) or llama3.1 (Ollama/LM Studio)."
            ),
        }
    if provider == "openai" and not _api_key():
        return {
            "configured": False,
            "reason": "WILLIAM_LLM_PROVIDER=openai requires WILLIAM_LLM_API_KEY",
            "install_guidance": (
                "Set WILLIAM_LLM_API_KEY to a real OpenAI API key, or switch to a "
                "local provider (WILLIAM_LLM_PROVIDER=ollama or lmstudio) that "
                "doesn't need one."
            ),
        }
    if requests is None:
        return {
            "configured": False,
            "reason": "the 'requests' package is not installed",
            "install_guidance": "Not installed. Run: pip install requests",
        }
    return {"configured": True, "reason": None, "install_guidance": None}


def chat_completion(
    messages: List[Dict[str, str]],
    *,
    temperature: float = DEFAULT_TEMPERATURE,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> Dict[str, Any]:
    """Real OpenAI-compatible POST {base_url}/chat/completions call.
    Returns {"ok", "text", "error"} -- ok=False with text=None if no
    provider is configured or the call fails; never returns a placeholder
    reply."""
    status = check_status()
    if not status["configured"]:
        return {"ok": False, "text": None, "error": f"dependency_required: {status['reason']}"}

    base_url = _base_url()
    api_key = _api_key()
    model = _model()

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        response = requests.post(  # type: ignore[union-attr]
            f"{base_url}/chat/completions",
            headers=headers,
            json={
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
            timeout=DEFAULT_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        body = response.json()
        choices = body.get("choices") or []
        if not choices:
            return {"ok": False, "text": None, "error": "LLM provider returned no choices"}
        message = (choices[0] or {}).get("message") or {}
        text = str(message.get("content") or "").strip()
        if not text:
            return {"ok": False, "text": None, "error": "LLM provider returned an empty response"}
        return {"ok": True, "text": text, "error": None}
    except Exception as exc:  # pragma: no cover - real network/provider failure
        logger.exception("LLM chat completion failed.")
        return {"ok": False, "text": None, "error": f"LLM request failed: {exc}"}


def answer_knowledge_question(question: str) -> Dict[str, Any]:
    """Real knowledge Q&A through the configured LLM. Callers must run
    is_live_data_query() first and short-circuit honestly for live/current
    data questions -- this function does not filter those itself."""
    return chat_completion(
        [
            {"role": "system", "content": KNOWLEDGE_SYSTEM_PROMPT},
            {"role": "user", "content": question},
        ]
    )


def draft_text(system_prompt: str, user_prompt: str, *, max_tokens: int = DEFAULT_MAX_TOKENS) -> Dict[str, Any]:
    """General-purpose single-shot drafting call (used by the PDF/DOCX
    document generator and the project-builder blueprint drafter) -- same
    honest ok/text/error contract as answer_knowledge_question."""
    return chat_completion(
        [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        max_tokens=max_tokens,
    )


# =============================================================================
# Live/current-data detection -- deterministic, no LLM call. See module
# docstring: this is the real enforcement for "never fake live data."
# =============================================================================

_WEATHER_PATTERN = re.compile(r"\bweather\b|\btemperature\s+(in|at|today)\b|\bforecast\b", re.IGNORECASE)
_OTHER_LIVE_DATA_PATTERN = re.compile(
    r"\bcurrent\s+(news|stock\s+price|score|exchange\s+rate)\b"
    r"|\btoday'?s\s+(news|date|score)\b"
    r"|\blive\s+(score|news|price)\b"
    r"|\bstock\s+price\s+of\b",
    re.IGNORECASE,
)


def is_live_data_query(message: str) -> Optional[str]:
    """Returns "weather" | "other" | None. Deterministic keyword match,
    checked before any LLM call -- see module docstring."""
    if _WEATHER_PATTERN.search(message or ""):
        return "weather"
    if _OTHER_LIVE_DATA_PATTERN.search(message or ""):
        return "other"
    return None


LIVE_WEATHER_FALLBACK_MESSAGE = "Boss, live weather provider is not connected yet."
LIVE_DATA_FALLBACK_MESSAGE = "Boss, I don't have a connected live/current data provider for that yet."
KNOWLEDGE_PROVIDER_MISSING_MESSAGE = "Boss, AI knowledge provider is not configured yet."


__all__ = [
    "check_status",
    "chat_completion",
    "answer_knowledge_question",
    "draft_text",
    "is_live_data_query",
    "KNOWLEDGE_SYSTEM_PROMPT",
    "LIVE_WEATHER_FALLBACK_MESSAGE",
    "LIVE_DATA_FALLBACK_MESSAGE",
    "KNOWLEDGE_PROVIDER_MISSING_MESSAGE",
]
