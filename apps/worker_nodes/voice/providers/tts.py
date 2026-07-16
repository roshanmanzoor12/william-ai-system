"""
apps/worker_nodes/voice/providers/tts.py

Real text-to-speech: pyttsx3 (Windows SAPI voices, 100% local, no API key)
when WILLIAM_TTS_PROVIDER=pyttsx3 is set and the pyttsx3 package is
installed, or a remote provider (WILLIAM_TTS_BASE_URL + WILLIAM_TTS_API_KEY)
otherwise. Never fabricates spoken output -- a missing provider returns
tts_missing and the caller must print text only, exactly as if TTS were
never attempted.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict

logger = logging.getLogger("william.worker_nodes.voice.providers.tts")

try:
    import pyttsx3  # type: ignore
except Exception:  # pragma: no cover - import-safe fallback
    pyttsx3 = None  # type: ignore

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - import-safe fallback
    requests = None  # type: ignore


def local_package_available() -> bool:
    return pyttsx3 is not None


# "pyttsx3_local" is accepted as an honest alias for "pyttsx3" -- same
# local engine, matching the "_local" naming convention
# WILLIAM_AUDIO_INPUT_PROVIDER already uses ("local_microphone"). Without
# this alias, an operator who reasonably follows that same convention for
# WILLIAM_TTS_PROVIDER gets silently rejected here.
_LOCAL_PYTTSX3_PROVIDER_NAMES = {"pyttsx3", "pyttsx3_local"}


def _provider_name() -> str:
    raw = os.getenv("WILLIAM_TTS_PROVIDER", "").strip().lower()
    if raw == "none":
        return ""
    return "pyttsx3" if raw in _LOCAL_PYTTSX3_PROVIDER_NAMES else raw


def check_status() -> Dict[str, Any]:
    provider = _provider_name()
    if not provider:
        return {
            "configured": False,
            "reason": "WILLIAM_TTS_PROVIDER is not set",
            "install_guidance": (
                "pyttsx3 is installed. Set WILLIAM_TTS_PROVIDER=pyttsx3 to use it."
                if local_package_available()
                else "Not installed. Run: pip install pyttsx3 comtypes pywin32"
            ),
        }
    if provider == "pyttsx3":
        if not local_package_available():
            return {
                "configured": False,
                "reason": "pyttsx3 is not installed",
                "install_guidance": "Not installed. Run: pip install pyttsx3 comtypes pywin32",
            }
        return {"configured": True, "reason": None, "install_guidance": None}
    if os.getenv("WILLIAM_TTS_BASE_URL") and os.getenv("WILLIAM_TTS_API_KEY"):
        if requests is None:
            return {
                "configured": False,
                "reason": "the 'requests' package is not installed",
                "install_guidance": "Not installed. Run: pip install requests",
            }
        return {"configured": True, "reason": None, "install_guidance": None}
    return {
        "configured": False,
        "reason": f"WILLIAM_TTS_PROVIDER={provider!r} requires WILLIAM_TTS_BASE_URL and WILLIAM_TTS_API_KEY",
        "install_guidance": "Set WILLIAM_TTS_BASE_URL and WILLIAM_TTS_API_KEY, or use WILLIAM_TTS_PROVIDER=pyttsx3 for a local, free option.",
    }


def list_voices() -> list:
    """Real installed-voice enumeration (Windows SAPI voices via pyttsx3) --
    empty list if pyttsx3 isn't installed."""
    if not local_package_available():
        return []
    engine = pyttsx3.init()  # type: ignore[union-attr]
    try:
        voices = engine.getProperty("voices") or []
        return [{"id": v.id, "name": v.name} for v in voices]
    finally:
        engine.stop()


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name, "")
    try:
        return float(raw) if raw else default
    except ValueError:
        return default


def speak(text: str) -> Dict[str, Any]:
    """Speaks real text through a real TTS engine. Returns
    {"ok", "spoken", "error"} -- spoken=False (never fabricated True) if no
    provider is configured; the caller must print the text either way."""
    if not text or not text.strip():
        return {"ok": False, "spoken": False, "error": "empty text"}

    status = check_status()
    if not status["configured"]:
        return {"ok": False, "spoken": False, "error": f"tts_missing: {status['reason']}"}

    provider = _provider_name()
    try:
        if provider == "pyttsx3":
            engine = pyttsx3.init()  # type: ignore[union-attr]
            try:
                rate = _env_float("WILLIAM_TTS_RATE", 175.0)
                volume = _env_float("WILLIAM_TTS_VOLUME", 1.0)
                engine.setProperty("rate", rate)
                engine.setProperty("volume", max(0.0, min(1.0, volume)))

                voice_selector = os.getenv("WILLIAM_TTS_VOICE", "").strip()
                if voice_selector:
                    for voice in engine.getProperty("voices") or []:
                        if voice_selector.lower() in (voice.id or "").lower() or voice_selector.lower() in (voice.name or "").lower():
                            engine.setProperty("voice", voice.id)
                            break

                engine.say(text)
                engine.runAndWait()
            finally:
                engine.stop()
            return {"ok": True, "spoken": True, "error": None}

        base_url = os.getenv("WILLIAM_TTS_BASE_URL", "").rstrip("/")
        api_key = os.getenv("WILLIAM_TTS_API_KEY", "")
        model_name = os.getenv("WILLIAM_TTS_MODEL", "tts-1")
        voice_name = os.getenv("WILLIAM_TTS_VOICE", "alloy")
        response = requests.post(  # type: ignore[union-attr]
            f"{base_url}/audio/speech",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"model": model_name, "voice": voice_name, "input": text},
            timeout=30,
        )
        response.raise_for_status()
        # Remote synthesis returned audio bytes but this worker has no
        # local audio-output playback wired up for a remote provider yet
        # (out of this MVP's honest scope) -- report the real limitation
        # rather than silently discarding the audio and claiming success.
        return {"ok": False, "spoken": False, "error": "remote TTS audio playback is not implemented yet"}
    except Exception as exc:  # pragma: no cover - real engine/network failure
        logger.exception("TTS speech failed.")
        return {"ok": False, "spoken": False, "error": f"speech failed: {exc}"}


__all__ = ["local_package_available", "check_status", "list_voices", "speak"]
