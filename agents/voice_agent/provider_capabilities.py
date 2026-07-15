"""
agents/voice_agent/provider_capabilities.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Honest local-package detection for the voice provider layer. This module
never claims a provider is "ready" just because a package happens to be
importable -- see compute_dependency_status()'s docstring in apps/api/
routes/voice.py: a workspace only reports a dependency as "configured"
once the matching WILLIAM_*_PROVIDER env var is actually set. What this
module adds on top of that existing configured/external_dependency_required
vocabulary is install_guidance -- a concrete "pip install X" string when
nothing usable is on disk yet, or None when a local package IS importable
(so the guidance can say "already installed, set WILLIAM_STT_PROVIDER=..."
instead of naming a package to install).

Never installs anything itself (importlib.util.find_spec only inspects
what is already on disk) -- packages are installed by the user, explicitly,
never automatically by this codebase.
"""

from __future__ import annotations

import importlib.util
from typing import Any, Dict, List, Optional, Tuple


def detect_local_package(candidates: List[Tuple[str, str]]) -> Dict[str, Any]:
    """candidates is a list of (importable_module_name, pip_install_name)
    pairs, checked in order. Returns the first one genuinely importable
    (find_spec only, never actually imports the module -- avoids paying
    import cost / side effects just to check availability), or an honest
    "nothing found" result naming every pip package that would satisfy it."""
    for module_name, pip_name in candidates:
        try:
            spec = importlib.util.find_spec(module_name)
        except (ImportError, ValueError, ModuleNotFoundError):
            spec = None
        if spec is not None:
            return {"found": True, "module_name": module_name, "pip_name": pip_name}

    pip_names = [pip_name for _, pip_name in candidates]
    return {"found": False, "module_name": None, "pip_name": None, "candidates": pip_names}


def _install_guidance(
    *,
    detection: Dict[str, Any],
    env_var: str,
    provider_value_hint: str,
) -> Optional[str]:
    """None means "a local package is already importable" -- the caller
    still needs to set env_var for it to count as configured (a package on
    disk is not the same as a chosen, active provider), so the guidance in
    that case names the env var to set rather than a package to install."""
    if detection["found"]:
        return f"{detection['pip_name']} is installed. Set {env_var}={provider_value_hint} to use it."
    joined = " or ".join(detection["candidates"])
    return f"Not installed. Run: pip install {joined}"


def stt_install_guidance() -> Dict[str, Any]:
    detection = detect_local_package(
        [
            ("faster_whisper", "faster-whisper"),
            ("whisper", "openai-whisper"),
        ]
    )
    return {
        "detection": detection,
        "install_guidance": _install_guidance(
            detection=detection, env_var="WILLIAM_STT_PROVIDER", provider_value_hint="faster_whisper_local"
        ),
    }


def tts_install_guidance() -> Dict[str, Any]:
    detection = detect_local_package(
        [
            ("pyttsx3", "pyttsx3"),
        ]
    )
    return {
        "detection": detection,
        "install_guidance": _install_guidance(
            detection=detection, env_var="WILLIAM_TTS_PROVIDER", provider_value_hint="pyttsx3_local"
        ),
    }


def wake_word_install_guidance() -> Dict[str, Any]:
    detection = detect_local_package(
        [
            ("openwakeword", "openwakeword"),
        ]
    )
    return {
        "detection": detection,
        "install_guidance": _install_guidance(
            detection=detection, env_var="WILLIAM_WAKE_WORD_PROVIDER", provider_value_hint="openwakeword_local"
        ),
    }


# Backend-safe mirror of apps/worker_nodes/voice/providers/wake_word.py's own
# BUNDLED_MODEL_NAMES/FALLBACK_BUNDLED_MODEL constants -- duplicated here
# (rather than importing the worker-side module into a backend API route)
# because this is pure data (no openwakeword import required), and the
# backend process may not have openwakeword installed at all in a real
# distributed deployment. Keep both lists in sync if openwakeword ever adds
# a new bundled model.
BUNDLED_WAKE_WORD_MODELS = {"alexa", "hey_mycroft", "hey_jarvis", "hey_rhasspy", "timer", "weather"}
FALLBACK_BUNDLED_WAKE_WORD_MODEL = "hey_jarvis"


def resolve_bundled_wake_word_model(phrase: str) -> Dict[str, Any]:
    """Maps a per-workspace wake_word phrase to the real openwakeword
    bundled model that will actually be loaded -- never claims a custom
    phrase (e.g. "William") has a pretrained model when it doesn't.
    Returns {"active_model", "matched_phrase", "notice"}; `notice` is the
    exact honest message to surface to the user when matched_phrase is
    False, e.g. "This wake word requires a custom model. Current active
    local model is hey_jarvis." -- None when the phrase already has a real
    bundled model."""
    normalized = (phrase or "").strip().lower().replace(" ", "_").replace("-", "_")
    if normalized in BUNDLED_WAKE_WORD_MODELS:
        return {"active_model": normalized, "matched_phrase": True, "notice": None}
    return {
        "active_model": FALLBACK_BUNDLED_WAKE_WORD_MODEL,
        "matched_phrase": False,
        "notice": (
            "This wake word requires a custom model. Current active local "
            f"model is {FALLBACK_BUNDLED_WAKE_WORD_MODEL}."
        ),
    }


__all__ = [
    "detect_local_package",
    "stt_install_guidance",
    "tts_install_guidance",
    "wake_word_install_guidance",
    "resolve_bundled_wake_word_model",
    "BUNDLED_WAKE_WORD_MODELS",
    "FALLBACK_BUNDLED_WAKE_WORD_MODEL",
]
