"""
apps/worker_nodes/voice/providers/speaker_embedding.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Real, local, honest speaker-embedding computation for Trusted Voice
Profiles -- WILLIAM_SPEAKER_RECOGNITION_PROVIDER=local_speaker_embedding.
No deep-learning model ships with this repo (no torch/tensorflow
dependency); this is a real, if simple, signal-processing fingerprint
(log-magnitude spectral energy averaged over the utterance, in a small
number of frequency bins, L2-normalized) computed with numpy only (already
a hard dependency of audio_input.py) -- never a fabricated/random vector.
Real speakers with genuinely different voices produce measurably different
fingerprints; this is not state-of-the-art speaker recognition, but it is
real math over the real captured audio, matching this codebase's "real
but simple, never fake" convention for every other local provider
(stt.py/tts.py/wake_word.py).

Never touches raw audio beyond reading the WAV file the caller (voice_
worker.py) already captured and will delete afterward per the "no raw
audio stored by default" rule -- this module has no persistence of its
own. The resulting embedding is a plain list of floats; encrypting and
storing it is the BACKEND's job (apps/api/services/voice_embedding_crypto.py),
never this module's.
"""

from __future__ import annotations

import logging
import os
import wave
from typing import Any, Dict, List, Optional

logger = logging.getLogger("william.worker_nodes.voice.providers.speaker_embedding")

try:
    import numpy as np  # type: ignore
except Exception:  # pragma: no cover - import-safe fallback
    np = None  # type: ignore

LOCAL_PROVIDER_NAME = "local_speaker_embedding"
EMBEDDING_BINS = 24
FRAME_MS = 25
HOP_MS = 10


def local_package_available() -> bool:
    return np is not None


def _provider_name() -> str:
    raw = os.getenv("WILLIAM_SPEAKER_RECOGNITION_PROVIDER", "").strip().lower()
    return "" if raw in ("", "none") else raw


def check_status() -> Dict[str, Any]:
    """Mirrors stt.py/tts.py/wake_word.py's check_status() shape exactly --
    {"configured", "reason", "install_guidance"}. numpy is already a hard
    dependency of this whole voice-provider package (audio_input.py
    requires it too), so the only real gate here is the env var itself."""
    provider = _provider_name()
    if not provider:
        return {
            "configured": False,
            "reason": "WILLIAM_SPEAKER_RECOGNITION_PROVIDER is not set",
            "install_guidance": f"Set WILLIAM_SPEAKER_RECOGNITION_PROVIDER={LOCAL_PROVIDER_NAME} to use it.",
        }
    if provider != LOCAL_PROVIDER_NAME:
        return {
            "configured": False,
            "reason": f"unknown WILLIAM_SPEAKER_RECOGNITION_PROVIDER={provider!r} (only {LOCAL_PROVIDER_NAME!r} is supported locally)",
            "install_guidance": f"Set WILLIAM_SPEAKER_RECOGNITION_PROVIDER={LOCAL_PROVIDER_NAME}.",
        }
    if not local_package_available():
        return {
            "configured": False,
            "reason": "numpy is not installed",
            "install_guidance": "Not installed. Run: pip install numpy",
        }
    return {"configured": True, "reason": None, "install_guidance": None}


def _read_wav_samples(audio_path: str) -> Optional["np.ndarray"]:
    with wave.open(audio_path, "rb") as wav_file:
        sample_width = wav_file.getsampwidth()
        n_frames = wav_file.getnframes()
        raw = wav_file.readframes(n_frames)
    if sample_width != 2:  # int16 only -- matches audio_input.py's own WAV format
        return None
    samples = np.frombuffer(raw, dtype=np.int16).astype(np.float64)  # type: ignore[union-attr]
    if samples.size == 0:
        return None
    return samples


def compute_embedding(audio_path: str) -> Dict[str, Any]:
    """Computes a real spectral-fingerprint embedding from a captured WAV
    file. Returns {"ok", "embedding": List[float] | None, "error"} -- never
    fabricates an embedding when the audio is empty/unreadable."""
    if np is None:
        return {"ok": False, "embedding": None, "error": "dependency_required: numpy is not installed"}

    try:
        samples = _read_wav_samples(audio_path)
    except (OSError, wave.Error) as exc:
        return {"ok": False, "embedding": None, "error": f"could not read captured audio: {exc}"}

    if samples is None or samples.size < 256:
        return {"ok": False, "embedding": None, "error": "captured audio is too short/empty to fingerprint"}

    # 16kHz assumption matches audio_input.py::SAMPLE_RATE (this module is
    # only ever fed WAVs that module wrote).
    sample_rate = 16000
    frame_len = max(int(sample_rate * FRAME_MS / 1000), 1)
    hop_len = max(int(sample_rate * HOP_MS / 1000), 1)

    window = np.hanning(frame_len)  # type: ignore[union-attr]
    bin_energy_sum = np.zeros(EMBEDDING_BINS, dtype=np.float64)  # type: ignore[union-attr]
    frame_count = 0

    start = 0
    while start + frame_len <= samples.size:
        frame = samples[start:start + frame_len] * window
        spectrum = np.abs(np.fft.rfft(frame))  # type: ignore[union-attr]
        # Log-spaced bin edges across the usable spectrum -- a cheap stand-
        # in for a mel filterbank, real math over the real FFT output.
        edges = np.unique(  # type: ignore[union-attr]
            np.logspace(0, np.log10(max(spectrum.size - 1, 2)), EMBEDDING_BINS + 1).astype(int)  # type: ignore[union-attr]
        )
        for i in range(min(EMBEDDING_BINS, len(edges) - 1)):
            lo, hi = edges[i], max(edges[i + 1], edges[i] + 1)
            bin_energy_sum[i] += float(np.log1p(np.mean(spectrum[lo:hi])))  # type: ignore[union-attr]
        frame_count += 1
        start += hop_len

    if frame_count == 0:
        return {"ok": False, "embedding": None, "error": "captured audio is too short to fingerprint"}

    embedding = bin_energy_sum / frame_count
    norm = float(np.linalg.norm(embedding))  # type: ignore[union-attr]
    if norm > 0:
        embedding = embedding / norm

    return {"ok": True, "embedding": [float(v) for v in embedding], "error": None}


__all__ = ["local_package_available", "check_status", "compute_embedding", "LOCAL_PROVIDER_NAME"]
