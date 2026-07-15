"""
apps/worker_nodes/voice/providers/stt.py

Real speech-to-text: faster-whisper running 100% locally (CPU by default,
via WILLIAM_STT_DEVICE/WILLIAM_STT_COMPUTE_TYPE) when
WILLIAM_STT_PROVIDER=faster_whisper is set and the faster-whisper package
is installed, or an OpenAI-compatible remote endpoint
(WILLIAM_STT_BASE_URL + WILLIAM_STT_API_KEY) otherwise. Never fabricates a
transcript -- a missing provider returns dependency_required and the
caller (voice_worker.py) must not proceed as if a transcription happened.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

logger = logging.getLogger("william.worker_nodes.voice.providers.stt")

try:
    from faster_whisper import WhisperModel  # type: ignore
except Exception:  # pragma: no cover - import-safe fallback
    WhisperModel = None  # type: ignore

try:
    import requests  # type: ignore
except Exception:  # pragma: no cover - import-safe fallback
    requests = None  # type: ignore


def local_package_available() -> bool:
    return WhisperModel is not None


# "local_whisper" is accepted as an honest alias for "faster_whisper" --
# same local engine, matching the exact provider value names the product
# spec documents (WILLIAM_STT_PROVIDER=openai/local_whisper/faster_whisper/
# none) without adding a second code path.
_LOCAL_WHISPER_PROVIDER_NAMES = {"faster_whisper", "local_whisper"}


def _provider_name() -> str:
    raw = os.getenv("WILLIAM_STT_PROVIDER", "").strip().lower()
    if raw == "none":
        return ""
    return "faster_whisper" if raw in _LOCAL_WHISPER_PROVIDER_NAMES else raw


def check_status() -> Dict[str, Any]:
    provider = _provider_name()
    if not provider:
        return {
            "configured": False,
            "reason": "WILLIAM_STT_PROVIDER is not set",
            "install_guidance": (
                "faster-whisper is installed. Set WILLIAM_STT_PROVIDER=faster_whisper to use it."
                if local_package_available()
                else "Not installed. Run: pip install faster-whisper"
            ),
        }
    if provider == "faster_whisper":
        if not local_package_available():
            return {
                "configured": False,
                "reason": "faster-whisper is not installed",
                "install_guidance": "Not installed. Run: pip install faster-whisper",
            }
        return {"configured": True, "reason": None, "install_guidance": None}
    # Any other provider name is treated as the OpenAI-compatible remote path.
    if os.getenv("WILLIAM_STT_BASE_URL") and os.getenv("WILLIAM_STT_API_KEY"):
        if requests is None:
            return {
                "configured": False,
                "reason": "the 'requests' package is not installed",
                "install_guidance": "Not installed. Run: pip install requests",
            }
        return {"configured": True, "reason": None, "install_guidance": None}
    return {
        "configured": False,
        "reason": f"WILLIAM_STT_PROVIDER={provider!r} requires WILLIAM_STT_BASE_URL and WILLIAM_STT_API_KEY",
        "install_guidance": "Set WILLIAM_STT_BASE_URL and WILLIAM_STT_API_KEY, or use WILLIAM_STT_PROVIDER=faster_whisper for a local, free option.",
    }


_model_cache: Dict[str, Any] = {}


def _get_local_model() -> Any:
    """Loading a Whisper model is expensive (seconds, real disk/CPU work)
    -- cached per (model_size, device, compute_type) so repeated
    transcriptions in one worker process don't reload it every time."""
    model_size = os.getenv("WILLIAM_STT_MODEL", "base").strip() or "base"
    device = os.getenv("WILLIAM_STT_DEVICE", "cpu").strip() or "cpu"
    compute_type = os.getenv("WILLIAM_STT_COMPUTE_TYPE", "int8").strip() or "int8"
    cache_key = f"{model_size}:{device}:{compute_type}"
    if cache_key not in _model_cache:
        logger.info("Loading local faster-whisper model %r (device=%s, compute_type=%s)...", model_size, device, compute_type)
        _model_cache[cache_key] = WhisperModel(model_size, device=device, compute_type=compute_type)  # type: ignore[misc]
    return _model_cache[cache_key]


def transcribe(audio_path: str) -> Dict[str, Any]:
    """Transcribes a real WAV file (see audio_input.py::record_to_tempfile).
    Returns {"ok", "text", "confidence", "error"} -- ok=False with text=None
    if no provider is configured; this function never returns a placeholder
    transcript."""
    status = check_status()
    if not status["configured"]:
        return {"ok": False, "text": None, "confidence": None, "error": f"dependency_required: {status['reason']}"}

    provider = _provider_name()
    try:
        if provider == "faster_whisper":
            model = _get_local_model()
            segments, info = model.transcribe(audio_path)
            text_parts = [segment.text.strip() for segment in segments]
            text = " ".join(part for part in text_parts if part).strip()
            confidence = float(getattr(info, "language_probability", 0.0) or 0.0)
            if not text:
                return {"ok": False, "text": None, "confidence": confidence, "error": "no speech detected"}
            return {"ok": True, "text": text, "confidence": confidence, "error": None}

        # OpenAI-compatible remote endpoint.
        base_url = os.getenv("WILLIAM_STT_BASE_URL", "").rstrip("/")
        api_key = os.getenv("WILLIAM_STT_API_KEY", "")
        model_name = os.getenv("WILLIAM_STT_MODEL", "whisper-1")
        with open(audio_path, "rb") as audio_file:
            response = requests.post(  # type: ignore[union-attr]
                f"{base_url}/audio/transcriptions",
                headers={"Authorization": f"Bearer {api_key}"},
                files={"file": (os.path.basename(audio_path), audio_file, "audio/wav")},
                data={"model": model_name},
                timeout=30,
            )
        response.raise_for_status()
        body = response.json()
        text = str(body.get("text", "")).strip()
        if not text:
            return {"ok": False, "text": None, "confidence": None, "error": "no speech detected"}
        return {"ok": True, "text": text, "confidence": None, "error": None}
    except Exception as exc:  # pragma: no cover - real model/network failure
        logger.exception("STT transcription failed.")
        return {"ok": False, "text": None, "confidence": None, "error": f"transcription failed: {exc}"}


__all__ = ["local_package_available", "check_status", "transcribe"]
