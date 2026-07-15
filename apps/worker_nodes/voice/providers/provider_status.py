"""
apps/worker_nodes/voice/providers/provider_status.py

Single source of truth for "what real voice capability is actually
available right now" -- aggregates audio_input.py/stt.py/tts.py/
wake_word.py's individual honest checks into the shape both the backend
(apps/api/routes/voice.py::GET /voice/status, /voice/worker/status) and
the worker (voice_worker.py's --test-* flags, dependency-required gating)
need. Never upgrades a status because a package merely exists on disk --
each per-provider status/install_guidance is exactly what
audio_input.check_status()/stt.check_status()/tts.check_status()/
wake_word.check_status() already computed.

Speaker recognition is intentionally NOT wired to a new local module here
-- agents/voice_agent/speaker_recognition.py already owns that (out of
this phase's scope per the mission spec: "keep optional for now"). This
module reads its status the same way apps/api/routes/voice.py already
does (WILLIAM_SPEAKER_RECOGNITION_PROVIDER env var), for a single unified
response shape only.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from apps.worker_nodes.voice.providers import audio_input, stt, tts, wake_word


def _dependency_entry(configured: bool, reason: Any, install_guidance: Any) -> Dict[str, Any]:
    return {
        "status": "configured" if configured else "external_dependency_required",
        "install_guidance": install_guidance,
    }


def get_full_status() -> Dict[str, Any]:
    """Returns the exact fields Phase 6 requires: per-provider status,
    the 3 aggregate availability booleans, missing_dependencies, and
    setup_commands -- computed fresh every call (cheap: these are all
    find_spec/env-var checks, no model loading happens here)."""
    audio_status = audio_input.check_status()
    stt_status = stt.check_status()
    tts_status = tts.check_status()
    wake_word_status = wake_word.check_status()

    speaker_provider = os.getenv("WILLIAM_SPEAKER_RECOGNITION_PROVIDER", "").strip()
    speaker_configured = bool(speaker_provider) and speaker_provider.lower() != "none"

    audio_entry = _dependency_entry(
        audio_status["available"], audio_status["reason"], audio_status["install_guidance"]
    )
    stt_entry = _dependency_entry(stt_status["configured"], stt_status["reason"], stt_status["install_guidance"])
    tts_entry = _dependency_entry(tts_status["configured"], tts_status["reason"], tts_status["install_guidance"])
    wake_word_entry = _dependency_entry(
        wake_word_status["configured"], wake_word_status["reason"], wake_word_status["install_guidance"]
    )
    speaker_entry = _dependency_entry(
        speaker_configured,
        None if speaker_configured else "WILLIAM_SPEAKER_RECOGNITION_PROVIDER is not set",
        None if speaker_configured else "Optional -- sensitive commands fall back to typed confirmation/PIN without it.",
    )

    real_microphone_available = audio_entry["status"] == "configured"
    speech_output_available = tts_entry["status"] == "configured"
    always_listening_available = (
        real_microphone_available and stt_entry["status"] == "configured" and wake_word_entry["status"] == "configured"
    )

    missing_dependencies: List[str] = [
        key
        for key, entry in (
            ("audio_input_worker", audio_entry),
            ("stt_provider", stt_entry),
            ("tts_provider", tts_entry),
            ("wake_word_provider", wake_word_entry),
            ("speaker_recognition_provider", speaker_entry),
        )
        if entry["status"] != "configured"
    ]

    return {
        "audio_input_status": audio_entry,
        "stt_status": stt_entry,
        "tts_status": tts_entry,
        "wake_word_status": wake_word_entry,
        "speaker_recognition_status": speaker_entry,
        "real_microphone_available": real_microphone_available,
        "speech_output_available": speech_output_available,
        "always_listening_available": always_listening_available,
        # Typed/simulated text commands (push-to-talk, --simulate-text)
        # never require any of the above -- always true, stated outright.
        "text_command_available": True,
        "missing_dependencies": missing_dependencies,
        "setup_commands": {
            "install_dependencies": r"powershell -ExecutionPolicy Bypass -File .\scripts\windows\install_voice_dependencies.ps1",
            "check_dependencies": r"powershell -ExecutionPolicy Bypass -File .\scripts\windows\check_voice_dependencies.ps1",
        },
    }


__all__ = ["get_full_status"]
