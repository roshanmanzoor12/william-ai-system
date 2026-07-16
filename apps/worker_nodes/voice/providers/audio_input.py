"""
apps/worker_nodes/voice/providers/audio_input.py

Real local microphone capture via sounddevice -- no simulation, no
fabricated audio. If sounddevice isn't installed or no input device is
available, every function here returns an honest dependency_required
result; callers (voice_worker.py) must never fabricate a transcript or
proceed as if a recording happened.

Recording writes a real WAV file to a temp path using only the stdlib
`wave` module (avoids requiring scipy just to write a WAV header) and
records via sounddevice.InputStream with a simple RMS-energy silence
cutoff: recording keeps going until real speech is first detected, then
stops after `silence_timeout_seconds` of continued silence, capped at
`max_duration_seconds` either way. The caller owns the returned path and
is responsible for deleting it after STT consumes it (see voice_worker.py
-- "no raw audio stored by default" is enforced by the caller's cleanup,
not by this module silently deleting a file the caller might still need
for a debug-mode replay).
"""

from __future__ import annotations

import logging
import os
import tempfile
import time
import uuid
import wave
from typing import Any, Dict, List, Optional

logger = logging.getLogger("william.worker_nodes.voice.providers.audio_input")

try:
    import sounddevice as sd  # type: ignore
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover - import-safe fallback
    sd = None  # type: ignore
    np = None  # type: ignore

SAMPLE_RATE = 16000
CHANNELS = 1
DTYPE = "int16"
FRAME_MS = 100  # size of each polled chunk, in milliseconds
SILENCE_RMS_THRESHOLD = 350  # int16 RMS below this counts as "silence"


def is_available() -> bool:
    return sd is not None and np is not None


def check_status() -> Dict[str, Any]:
    """Honest status: WILLIAM_AUDIO_INPUT_PROVIDER must be set (matching
    every other provider's "chosen, not merely present" rule -- see
    apps/api/routes/voice.py::compute_dependency_status), AND the package
    must be importable, AND at least one real input device must exist, for
    "configured". --list-audio-devices still works regardless (it's a
    diagnostic, not a claim that always-listening is live), which is why
    `devices` is always populated when the package is importable even if
    this returns available=False."""
    if not is_available():
        return {
            "available": False,
            "reason": "sounddevice (and numpy) not installed",
            "install_guidance": "Not installed. Run: pip install sounddevice numpy",
            "devices": [],
        }
    try:
        devices = list_devices()
    except Exception as exc:  # pragma: no cover - real device-query failure
        return {
            "available": False,
            "reason": f"could not query audio devices: {exc}",
            "install_guidance": "Check that your microphone driver is installed and not disabled.",
            "devices": [],
        }
    if not devices:
        return {
            "available": False,
            "reason": "no input-capable audio device found",
            "install_guidance": "Connect a microphone, then re-run --list-audio-devices.",
            "devices": [],
        }
    if os.getenv("WILLIAM_AUDIO_INPUT_PROVIDER", "").strip().lower() in ("", "none"):
        return {
            "available": False,
            "reason": "WILLIAM_AUDIO_INPUT_PROVIDER is not set",
            "install_guidance": "sounddevice and a microphone are both available. Set WILLIAM_AUDIO_INPUT_PROVIDER=local_microphone to use it.",
            "devices": devices,
        }
    return {"available": True, "reason": None, "install_guidance": None, "devices": devices}


def list_devices() -> List[Dict[str, Any]]:
    """Real device enumeration via sounddevice.query_devices() -- returns
    only devices with at least one input channel. Empty list (not an
    exception) if sounddevice is unavailable."""
    if not is_available():
        return []
    raw_devices = sd.query_devices()  # type: ignore[union-attr]
    try:
        default_input_index = sd.default.device[0]  # type: ignore[union-attr]
    except Exception:
        default_input_index = None

    devices: List[Dict[str, Any]] = []
    for index, device in enumerate(raw_devices):
        if device.get("max_input_channels", 0) <= 0:
            continue
        devices.append(
            {
                "index": index,
                "name": device.get("name"),
                "max_input_channels": device.get("max_input_channels"),
                "default_samplerate": device.get("default_samplerate"),
                "is_default": index == default_input_index,
            }
        )
    return devices


def _resolve_device() -> Optional[Any]:
    """WILLIAM_VOICE_MIC_DEVICE (preferred) or WILLIAM_AUDIO_DEVICE
    (original name, still honored) may be a device index (int) or a
    substring of a device name; blank means "use the system default input
    device" (pass None to sounddevice, its own default-device
    resolution)."""
    raw = os.getenv("WILLIAM_VOICE_MIC_DEVICE", "").strip() or os.getenv("WILLIAM_AUDIO_DEVICE", "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        pass
    for device in list_devices():
        if raw.lower() in str(device.get("name", "")).lower():
            return device["index"]
    logger.warning("WILLIAM_VOICE_MIC_DEVICE/WILLIAM_AUDIO_DEVICE=%r did not match any input device; falling back to system default.", raw)
    return None


def selected_device_label() -> str:
    """Human-readable label for whichever input device _resolve_device()
    would pick right now -- used only for debug output (WILLIAM_VOICE_
    DEBUG=1), never for the actual recording decision."""
    resolved = _resolve_device()
    if resolved is None:
        return "system default"
    for device in list_devices():
        if device["index"] == resolved:
            return f"[{device['index']}] {device['name']}"
    return str(resolved)


def record_to_tempfile(
    *,
    max_duration_seconds: float = 8.0,
    silence_timeout_seconds: float = 1.5,
    min_speech_seconds: float = 0.3,
) -> Dict[str, Any]:
    """Records real microphone audio to a temp WAV file. Stops on real
    silence (RMS energy below SILENCE_RMS_THRESHOLD for
    silence_timeout_seconds, after at least min_speech_seconds of
    non-silent audio was captured) or at max_duration_seconds, whichever
    comes first. Returns {"ok", "audio_path", "duration_seconds", "error"}
    -- ok=False (with audio_path=None) if no microphone is available;
    never fabricates a recording."""
    if not is_available():
        return {
            "ok": False,
            "audio_path": None,
            "duration_seconds": 0.0,
            "error": "dependency_required: sounddevice/numpy not installed",
        }

    device = _resolve_device()
    frame_samples = int(SAMPLE_RATE * (FRAME_MS / 1000.0))
    frames: List[Any] = []
    speech_started_at: Optional[float] = None
    silence_started_at: Optional[float] = None
    started_at = time.monotonic()
    peak_rms = 0.0

    try:
        with sd.InputStream(  # type: ignore[union-attr]
            samplerate=SAMPLE_RATE, channels=CHANNELS, dtype=DTYPE, device=device, blocksize=frame_samples,
        ) as stream:
            while True:
                elapsed = time.monotonic() - started_at
                if elapsed >= max_duration_seconds:
                    break

                chunk, _overflowed = stream.read(frame_samples)
                frames.append(chunk.copy())

                rms = float(np.sqrt(np.mean(np.square(chunk.astype(np.float64)))))  # type: ignore[union-attr]
                peak_rms = max(peak_rms, rms)
                now = time.monotonic()
                if rms >= SILENCE_RMS_THRESHOLD:
                    if speech_started_at is None:
                        speech_started_at = now
                    silence_started_at = None
                else:
                    if speech_started_at is not None and (now - speech_started_at) >= min_speech_seconds:
                        if silence_started_at is None:
                            silence_started_at = now
                        elif (now - silence_started_at) >= silence_timeout_seconds:
                            break
    except Exception as exc:  # pragma: no cover - real hardware/driver failure
        return {"ok": False, "audio_path": None, "duration_seconds": 0.0, "error": f"recording failed: {exc}", "peak_rms": 0.0}

    if not frames:
        return {"ok": False, "audio_path": None, "duration_seconds": 0.0, "error": "no audio captured", "peak_rms": 0.0}

    audio = np.concatenate(frames, axis=0)  # type: ignore[union-attr]
    duration_seconds = len(audio) / float(SAMPLE_RATE)

    temp_dir = tempfile.gettempdir()
    audio_path = os.path.join(temp_dir, f"william_voice_{uuid.uuid4().hex}.wav")
    with wave.open(audio_path, "wb") as wav_file:
        wav_file.setnchannels(CHANNELS)
        wav_file.setsampwidth(2)  # int16 = 2 bytes
        wav_file.setframerate(SAMPLE_RATE)
        wav_file.writeframes(audio.tobytes())

    # peak_rms is debug-only telemetry (WILLIAM_VOICE_DEBUG=1 printing) --
    # real int16 RMS energy of the loudest captured frame, never estimated.
    return {
        "ok": True, "audio_path": audio_path, "duration_seconds": duration_seconds, "error": None,
        "peak_rms": round(peak_rms, 1),
    }


__all__ = ["is_available", "check_status", "list_devices", "record_to_tempfile", "SAMPLE_RATE"]
