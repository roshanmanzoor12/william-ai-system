"""
apps/worker_nodes/voice/providers/wake_word.py

Real *audio* wake-word detection via openwakeword, for always-listening
microphone mode (wake_word_admin). Distinct from the always-available
TEXT-based wake-word detection in agents/voice_agent/wake_word.py (pure
regex/confidence scoring on typed/simulated text, needs no provider) --
that one keeps working unconditionally for --simulate-text and
push_to_talk. This module is the real-audio counterpart: if
openwakeword isn't installed or WILLIAM_WAKE_WORD_PROVIDER isn't set,
always-listening mode honestly reports dependency_required and the worker
must not pretend to listen.
"""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Callable, Dict, Optional

logger = logging.getLogger("william.worker_nodes.voice.providers.wake_word")

try:
    import openwakeword  # type: ignore
    from openwakeword.model import Model as OpenWakeWordModel  # type: ignore
except Exception:  # pragma: no cover - import-safe fallback
    openwakeword = None  # type: ignore
    OpenWakeWordModel = None  # type: ignore

try:
    import sounddevice as sd  # type: ignore
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover - import-safe fallback
    sd = None  # type: ignore
    np = None  # type: ignore

FRAME_SAMPLES = 1280  # openwakeword's expected chunk size at 16kHz
SAMPLE_RATE = 16000

# openwakeword ships exactly these 6 pretrained models -- there is no
# "william" among them (confirmed via openwakeword.MODELS.keys() against
# the installed release). hey_jarvis is the closest real match to this
# product's own branding (William/Jarvis) and is what a bare
# WILLIAM_WAKE_WORD_PHRASE default of "william" honestly falls back to,
# with a logged explanation -- never silently loaded as if "william" itself
# had a real model, and never silently loading ALL 6 default models
# together (which is what happens if none is specified, and is why an
# untargeted first real test triggered a false-positive "alexa" detection
# on unrelated audio; found via a real --test-wake-word run).
BUNDLED_MODEL_NAMES = {"alexa", "hey_mycroft", "hey_jarvis", "hey_rhasspy", "timer", "weather"}
FALLBACK_BUNDLED_MODEL = "hey_jarvis"
DEFAULT_WAKE_WORD_PHRASE = "william"


def local_package_available() -> bool:
    return OpenWakeWordModel is not None


def resolve_bundled_model_name() -> Dict[str, Any]:
    """Maps WILLIAM_WAKE_WORD_PHRASE to a real openwakeword bundled model
    name, honestly, without ever claiming "william" itself has a
    pretrained model. Returns {"model_name", "matched_configured_phrase",
    "configured_phrase"}."""
    configured_phrase = os.getenv("WILLIAM_WAKE_WORD_PHRASE", DEFAULT_WAKE_WORD_PHRASE).strip().lower()
    normalized = configured_phrase.replace(" ", "_").replace("-", "_")
    if normalized in BUNDLED_MODEL_NAMES:
        return {"model_name": normalized, "matched_configured_phrase": True, "configured_phrase": configured_phrase}
    return {
        "model_name": FALLBACK_BUNDLED_MODEL,
        "matched_configured_phrase": False,
        "configured_phrase": configured_phrase,
    }


def _provider_name() -> str:
    return os.getenv("WILLIAM_WAKE_WORD_PROVIDER", "").strip().lower()


def check_status() -> Dict[str, Any]:
    provider = _provider_name()
    if not provider:
        return {
            "configured": False,
            "reason": "WILLIAM_WAKE_WORD_PROVIDER is not set",
            "install_guidance": (
                "openwakeword is installed. Set WILLIAM_WAKE_WORD_PROVIDER=openwakeword to use it."
                if local_package_available()
                else "Not installed. Run: pip install openwakeword"
            ),
        }
    if provider != "openwakeword":
        return {
            "configured": False,
            "reason": f"unknown WILLIAM_WAKE_WORD_PROVIDER={provider!r} (only 'openwakeword' is supported)",
            "install_guidance": "Set WILLIAM_WAKE_WORD_PROVIDER=openwakeword.",
        }
    if not local_package_available():
        return {
            "configured": False,
            "reason": "openwakeword is not installed",
            "install_guidance": "Not installed. Run: pip install openwakeword",
        }
    if sd is None or np is None:
        return {
            "configured": False,
            "reason": "sounddevice/numpy not installed (needed to feed openwakeword real audio)",
            "install_guidance": "Not installed. Run: pip install sounddevice numpy",
        }
    return {"configured": True, "reason": None, "install_guidance": None}


_default_models_checked = False


def _ensure_default_models_downloaded() -> None:
    """openwakeword's PyPI package ships code only -- the actual pretrained
    model weight FILES (.onnx/.tflite) are not bundled in the wheel and
    must be fetched once via openwakeword.utils.download_models() (a real,
    one-time network download of openwakeword's own official release
    assets, a few MB total). Without this, constructing Model() raises
    onnxruntime.NoSuchFile the first time, honestly surfacing as a crash
    rather than a fabricated "it's working" state -- found via a real
    --test-wake-word run, not a hypothetical. Runs at most once per
    process (openwakeword's own download_models() already no-ops for
    files that already exist on disk, but the process-local flag avoids
    even that redundant disk check on every WakeWordListener() call)."""
    global _default_models_checked
    if _default_models_checked:
        return
    try:
        import openwakeword.utils as oww_utils  # type: ignore

        oww_utils.download_models()
    except Exception as exc:  # pragma: no cover - real network/disk failure
        logger.warning("Could not download openwakeword's default models: %s", exc)
    _default_models_checked = True


class WakeWordListener:
    """Real-time audio wake-word listener. Feeds live microphone frames
    into openwakeword's model and calls on_detected(score) the moment the
    configured phrase's confidence crosses the threshold. No audio is ever
    buffered beyond openwakeword's own small internal ring buffer -- this
    class holds no persistent recording, matching the "no raw audio stored"
    privacy rule."""

    def __init__(self, *, threshold: float = 0.5) -> None:
        status = check_status()
        if not status["configured"]:
            raise RuntimeError(f"dependency_required: {status['reason']}")

        model_path = os.getenv("WILLIAM_WAKE_WORD_MODEL", "").strip() or None
        # inference_framework defaults to "tflite", which requires the
        # tflite_runtime package (a separate, Linux/ARM-oriented wheel that
        # is NOT part of `pip install openwakeword` and does not have a
        # standard Windows CPython 3.12 wheel) -- openwakeword's own
        # fallback-to-onnx logic only fires for certain code paths, not
        # this one, so it must be requested explicitly. onnxruntime (a
        # normal, widely-available wheel) IS part of what
        # install_voice_dependencies.ps1's `pip install openwakeword`
        # pulls in as a real dependency, so "onnx" is the framework this
        # worker actually has available on a stock Windows install.
        # Found via a real --test-wake-word run, not a hypothetical.
        if model_path:
            self._model = OpenWakeWordModel(wakeword_models=[model_path], inference_framework="onnx")  # type: ignore[misc]
            self.active_model_name = model_path
        else:
            # Load exactly ONE targeted bundled model, not openwakeword's
            # full default set of 6 -- loading all of them (the behavior
            # of omitting wakeword_models entirely) means ANY of
            # alexa/hey_mycroft/hey_jarvis/hey_rhasspy/timer/weather can
            # trigger "detection", which is not what a workspace
            # configured for one specific wake phrase should do, and
            # measurably increases false-positive risk. Found via a real
            # --test-wake-word run: an untargeted load produced a false
            # "alexa" detection with no one having said "alexa".
            _ensure_default_models_downloaded()
            resolved = resolve_bundled_model_name()
            if not resolved["matched_configured_phrase"]:
                logger.warning(
                    "openwakeword has no pretrained model for WILLIAM_WAKE_WORD_PHRASE=%r -- "
                    "openwakeword only ships %s. Using %r (this product's own Jarvis branding) "
                    "as the closest real match. Set WILLIAM_WAKE_WORD_PHRASE to one of the exact "
                    "supported names to pick a different one, or WILLIAM_WAKE_WORD_MODEL to a "
                    "custom-trained model path.",
                    resolved["configured_phrase"], sorted(BUNDLED_MODEL_NAMES), resolved["model_name"],
                )
            self._model = OpenWakeWordModel(wakeword_models=[resolved["model_name"]], inference_framework="onnx")  # type: ignore[misc]
            self.active_model_name = resolved["model_name"]
        self._threshold = threshold
        self._stop_requested = False

    def listen_until_detected(
        self,
        *,
        max_seconds: Optional[float] = None,
        on_poll: Optional[Callable[[], None]] = None,
    ) -> Dict[str, Any]:
        """Blocks, feeding live mic audio into the model, until the wake
        phrase is detected or max_seconds elapses (None = listen
        indefinitely, until stop() is called from another thread).
        Returns {"detected": bool, "score": float, "trigger": str|None}."""
        started_at = time.monotonic()
        self._stop_requested = False

        with sd.InputStream(  # type: ignore[union-attr]
            samplerate=SAMPLE_RATE, channels=1, dtype="int16", blocksize=FRAME_SAMPLES,
        ) as stream:
            while not self._stop_requested:
                if max_seconds is not None and (time.monotonic() - started_at) >= max_seconds:
                    return {"detected": False, "score": 0.0, "trigger": None}

                chunk, _overflowed = stream.read(FRAME_SAMPLES)
                frame = chunk.reshape(-1).astype(np.int16)  # type: ignore[union-attr]
                predictions = self._model.predict(frame)

                for phrase_key, score in predictions.items():
                    if score >= self._threshold:
                        return {"detected": True, "score": float(score), "trigger": phrase_key}

                if on_poll is not None:
                    on_poll()

        return {"detected": False, "score": 0.0, "trigger": None}

    def stop(self) -> None:
        self._stop_requested = True


__all__ = ["local_package_available", "check_status", "WakeWordListener"]
