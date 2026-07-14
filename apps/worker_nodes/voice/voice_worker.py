"""
apps/worker_nodes/voice/voice_worker.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

Phase 9 -- Voice Worker.

Purpose:
    Runnable worker process that talks to the real, live voice API
    (apps/api/routes/voice.py, mounted at /api/v1/voice/*) using the same
    real JWT `Authorization: Bearer <token>` auth the dashboard uses --
    there is no separate device-token auth system for voice yet.

    This worker does NOT implement real microphone capture, real STT, or
    real TTS. Those provider integrations (pyaudio/whisper/vosk/etc.) are
    not installed in this environment and this file never imports them.
    What it does provide is real, working plumbing:

      - Startup + periodic dependency-status reporting (GET /voice/status),
        staying alive in a safe idle loop even when no audio/STT/TTS/
        wake-word provider is configured ("dependency-check mode").
      - Real TEXT-based wake-word detection via
        agents.voice_agent.wake_word.WakeWordDetector.detect_from_text()
        (pure regex/confidence scoring -- genuinely works with zero
        external providers).
      - A --simulate-text control path that runs a piece of text straight
        through the real pipeline: local wake-word detection -> (if the
        currently configured voice mode locally requires wake-word gating,
        and the wake word was detected) POST /voice/wake-event -> POST
        /voice/push-to-talk/text (the same shared dispatcher POST
        /assistant/message uses -- real SystemAgent/Windows Worker
        dispatch for "William open Notepad"-style commands) -> print the
        full response.
      - An interactive stdin fallback loop (typed text stands in for
        speech) when no --simulate-text is given and stdin is a TTY, and a
        safe non-interactive idle loop (periodic status re-check) when it
        is not.

    Composition, not reinvention:
        This worker composes apps.worker_nodes.common.worker_client.
        WorkerClient for HTTP transport, JWT bearer auth headers, timeouts,
        and redaction rather than hand-rolling another urllib/requests
        layer. WorkerClient's public register/heartbeat/poll_tasks/report
        methods target a different protocol (the generic `/api/worker/*`
        device task-polling contract) that voice does not use, so this
        worker calls WorkerClient's internal `_request()` transport helper
        directly against the real `/voice/*` paths -- the exact plumbing
        (auth headers, retries-friendly structured WorkerResponse, safe
        error/redaction handling) this task was told to reuse rather than
        rebuild.

    Hard privacy/safety rule (mirrors the rest of this codebase): this
    worker never captures, buffers, or persists raw audio -- there is no
    microphone integration in this file. The method a future real
    microphone integration would extend to hold a short rolling audio
    buffer before wake-word/STT hand-off is documented at
    VoiceWorker.on_audio_frame() below: it intentionally discards whatever
    it receives and stores nothing.

Run:
    python -m apps.worker_nodes.voice.voice_worker
    python -m apps.worker_nodes.voice.voice_worker --simulate-text "William create a VEO prompt for ClickRonix"

Config (CLI flag, then env var, then default):
    --token / WILLIAM_VOICE_WORKER_TOKEN            real JWT access token (dev/manual mode)
    --device-token / WILLIAM_VOICE_WORKER_DEVICE_TOKEN   installed-worker device token from
                                                          POST /voice/device/register (preferred
                                                          over --token when both are set)
    --config <path>                                  JSON config file written by
                                                          scripts/windows/install_voice_worker.ps1
                                                          (api_base_url/device_token) -- CLI
                                                          flags/env vars always override it
    --api-base-url / WILLIAM_API_BASE_URL            default http://localhost:8000/api/v1
    --poll-interval / WILLIAM_VOICE_WORKER_POLL_INTERVAL   idle-loop status re-check seconds (default 20)
    --wake-word / WILLIAM_VOICE_WORKER_WAKE_WORD      local wake-word override (default: server-configured, else "william")
    --max-backoff / WILLIAM_VOICE_WORKER_MAX_BACKOFF   reconnect backoff cap in seconds (default 30)
    --simulate-text "<text>"                          one-shot text-simulation mode (no live loop)
    --ignore-mode-for-dev                             bypass the local "voice mode disabled" gate for
                                                          --simulate-text dev/test runs only -- never use
                                                          this for production listening

If no token/device-token is configured, the worker still starts (it will
not crash) -- the status call will honestly fail with an auth error and
the worker falls back to dependency-check / idle mode. If a real 401 comes
back (expired JWT or revoked device token), the worker prints a clear,
credential-specific message and stops cleanly rather than retrying forever
or crashing with a traceback.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Optional


# ---------------------------------------------------------------------
# Import-safe dependencies (see CLAUDE.md "Import-safe pattern" -- this
# worker must still start, in a degraded/dependency-check way, even if
# these forward-looking modules are missing or broken).
# ---------------------------------------------------------------------

try:
    from apps.worker_nodes.common.worker_client import (  # type: ignore
        WorkerClient,
        WorkerClientConfig,
    )
except Exception:  # pragma: no cover - import-safe fallback
    WorkerClient = None  # type: ignore
    WorkerClientConfig = None  # type: ignore

try:
    from agents.voice_agent.wake_word import (  # type: ignore
        WakeWordDetector,
        WakeWordConfig,
    )
except Exception:  # pragma: no cover - import-safe fallback
    WakeWordDetector = None  # type: ignore
    WakeWordConfig = None  # type: ignore


LOGGER_NAME = "william.worker_nodes.voice"
logger = logging.getLogger(LOGGER_NAME)

if not logger.handlers:
    _handler = logging.StreamHandler(stream=sys.stdout)
    _handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
    logger.addHandler(_handler)

logger.setLevel(os.getenv("WILLIAM_LOG_LEVEL", "INFO").upper())


DEFAULT_API_BASE_URL = "http://localhost:8000/api/v1"
DEFAULT_WAKE_WORD = "william"
DEFAULT_HEARTBEAT_INTERVAL_SECONDS = 30

# Modes (from database/models/voice.py::VALID_VOICE_MODES) that require a
# detected wake word before the worker will bother sending a command at
# all. push_to_talk and continuous_conversation do not gate on wake word
# server-side, but the worker still respects wake-word semantics locally
# for the gated modes per the mission's client-side-responsibility rule.
# standby is included -- the server refuses any /voice/command in standby
# mode that doesn't carry a detected wake word (see apps/api/routes/
# voice.py::submit_voice_command), so the worker must gate identically.
VOICE_MODE_DISABLED = "disabled"
VOICE_MODE_PUSH_TO_TALK = "push_to_talk"
VOICE_MODE_STANDBY = "standby"
WAKE_WORD_GATED_MODES = {"wake_word_admin", "wake_word_trusted_users", "standby"}


class VoiceWorkerState(str, Enum):
    """
    Console lifecycle states, exact names from the Phase 9 spec.
    """

    IDLE = "idle"
    LISTENING = "listening"
    WAKE_DETECTED = "wake_detected"
    VERIFYING_SPEAKER = "verifying_speaker"
    TRANSCRIBING = "transcribing"
    LANGUAGE_DETECTED = "language_detected"
    SENDING_TO_MASTER = "sending_to_master"
    SPEAKING = "speaking"
    ERROR = "error"


@dataclass
class VoiceWorkerConfig:
    api_base_url: str = DEFAULT_API_BASE_URL
    token: str = ""
    # An installed worker (scripts/windows/install_voice_worker.ps1 style
    # setup) authenticates with this instead of `token` (a full user JWT).
    # Both end up in the same Authorization: Bearer header --
    # apps/api/routes/voice_device_setup.py::get_voice_worker_auth_context
    # tells them apart server-side by hash lookup, not the worker. Preferred
    # over `token` when both are set (see _build_worker_client), matching
    # "installed worker mode" being the intended steady state once setup is
    # done -- the same precedence windows_worker.py's device_token/
    # worker_token pair already uses.
    device_token: str = ""
    # Set via --config; present only so _auth_failure_message-adjacent
    # tooling/tests can inspect where a loaded config file came from. The
    # actual file values are merged into a VoiceWorkerConfig by
    # build_config()/main(), with explicit CLI flags always winning.
    config_path: Optional[str] = None
    poll_interval_seconds: int = 20
    wake_word: Optional[str] = None
    max_backoff_seconds: int = 30
    request_timeout_seconds: int = 20
    simulate_text: Optional[str] = None
    # Bypasses ONLY this worker's own local "mode == disabled -> don't send"
    # gate inside _handle_input_text, for --simulate-text dev/test runs
    # against a workspace that hasn't been switched out of the disabled
    # default yet. Never applied to the interactive/idle loop. Do not use
    # this for production listening -- it does not change the workspace's
    # real voice mode setting, and does not bypass any server-side check.
    ignore_mode_for_dev: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class VoiceWorker:
    """
    Voice worker control loop. Owns:
      - a composed WorkerClient for real HTTP/auth transport to the API,
      - a real WakeWordDetector for local text-based wake-word gating,
      - the console state machine + reconnect-with-backoff logic.
    """

    def __init__(self, config: VoiceWorkerConfig) -> None:
        self.config = config
        self.state = VoiceWorkerState.IDLE
        self.session_id = str(uuid.uuid4())
        self._client = self._build_worker_client()
        self._wake_detector = self._build_wake_detector()
        self._known_wake_word = (config.wake_word or DEFAULT_WAKE_WORD).strip().lower()

    # -----------------------------------------------------------------
    # Construction helpers
    # -----------------------------------------------------------------

    def _build_worker_client(self) -> Optional["WorkerClient"]:
        if WorkerClient is None or WorkerClientConfig is None:
            logger.warning(
                "apps.worker_nodes.common.worker_client is unavailable; "
                "voice worker will run in offline dependency-check mode only."
            )
            return None

        client_config = WorkerClientConfig(
            backend_url=self.config.api_base_url,
            api_token=self.config.device_token or self.config.token,
            worker_type="voice_worker",
            worker_version="1.0.0",
            request_timeout_seconds=self.config.request_timeout_seconds,
        )
        return WorkerClient(config=client_config)

    def _auth_failure_message(self) -> str:
        """Distinguishes a dev-mode JWT simply expiring (config.token set,
        config.device_token not) from a real installed device token being
        revoked (config.device_token set) -- both surface as an
        http_401 WorkerResponse, but the honest, actionable message for the
        operator differs: a JWT can be refreshed by logging in again; a
        device token is durable and only ever stops working because it was
        actually revoked from the dashboard. If both are set, device_token
        wins (matches _build_worker_client's own precedence -- the 401 came
        from whichever credential was actually sent on the wire)."""
        if self.config.device_token:
            return "Device token revoked. Re-enable worker from dashboard."
        return "JWT expired. Use installed device-token worker or login again."

    @staticmethod
    def _is_auth_failure(result: Dict[str, Any]) -> bool:
        return str(result.get("transport_status")) == "http_401"

    def _build_wake_detector(self) -> Optional["WakeWordDetector"]:
        if WakeWordDetector is None or WakeWordConfig is None:
            logger.warning(
                "agents.voice_agent.wake_word is unavailable; local wake-word "
                "gating will be skipped (all input treated as not-detected)."
            )
            return None

        wake_words = [self._effective_wake_word_seed(), "jarvis"]
        detector_config = WakeWordConfig(
            default_wake_words=list(dict.fromkeys(wake_words)),
            # This worker does no SaaS-scoped audit/memory writes of its
            # own for local text pre-checks -- it is a client-side gate,
            # not a source-of-truth agent action -- so user/workspace
            # context is not required for the local detection call itself.
            require_user_context=False,
            require_workspace_context=False,
        )
        return WakeWordDetector(config=detector_config)

    def _effective_wake_word_seed(self) -> str:
        return (self.config.wake_word or DEFAULT_WAKE_WORD).strip().lower() or DEFAULT_WAKE_WORD

    def _sync_wake_word(self, server_wake_word: Optional[str]) -> None:
        """Keeps the local detector's primary wake word aligned with the
        workspace's server-configured wake word (unless the operator
        explicitly overrode it with --wake-word)."""
        if self._wake_detector is None:
            return
        if self.config.wake_word:
            return  # explicit local override always wins
        candidate = (server_wake_word or DEFAULT_WAKE_WORD).strip().lower()
        if not candidate or candidate == self._known_wake_word:
            return
        self._known_wake_word = candidate
        self._wake_detector.update_config({"default_wake_words": [candidate, "jarvis"]})

    # -----------------------------------------------------------------
    # Console state machine
    # -----------------------------------------------------------------

    def _set_state(self, new_state: VoiceWorkerState, detail: str = "") -> None:
        previous = self.state
        self.state = new_state
        suffix = f" | {detail}" if detail else ""
        logger.info("[state] %s -> %s%s", previous.value, new_state.value, suffix)

    def _log(self, message: str) -> None:
        logger.info(message)

    # -----------------------------------------------------------------
    # Audio buffer discard hook (documented per project safety rules --
    # see module docstring). No real microphone is attached in this
    # environment; this method exists so a future real audio-input
    # integration has one obvious, already-safety-reviewed place to plug
    # into, and so the "never persist raw audio" rule is enforced in code,
    # not just in a comment.
    # -----------------------------------------------------------------

    def on_audio_frame(self, frame: Any) -> None:
        """
        Would receive a raw audio frame/chunk from a real microphone
        worker if one were attached. Intentionally discards it immediately
        and stores nothing -- no buffer, no file, no memory payload. Only
        metadata (e.g. frame length) may ever be logged, never audio
        content.
        """
        try:
            frame_len = len(frame)  # type: ignore[arg-type]
        except Exception:
            frame_len = None
        logger.debug("Discarded raw audio frame (length=%s); no audio is ever persisted.", frame_len)
        del frame  # never retained

    # -----------------------------------------------------------------
    # HTTP transport (thin reuse wrapper around WorkerClient._request)
    # -----------------------------------------------------------------

    def _transport_call(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if self._client is None:
            return {
                "ok": False,
                "status": "client_unavailable",
                "message": "Worker HTTP client is unavailable (worker_client import failed).",
                "data": {},
                "errors": [{"error": "worker_client_unavailable"}],
            }
        # WorkerClient._request is the shared, already-built HTTP/auth/
        # redaction transport this task was told to reuse. It has no
        # public method for calling an arbitrary backend path (its public
        # methods are all specific to the /api/worker/* task-polling
        # protocol, which voice does not use), so the internal transport
        # helper is called directly here rather than duplicating urllib/
        # requests + auth-header + JSON handling.
        response = self._client._request(method=method, path=path, payload=payload or {})  # noqa: SLF001
        return response.to_dict()

    @staticmethod
    def _extract_envelope(transport_result: Dict[str, Any]) -> Dict[str, Any]:
        """
        Unwraps the real API's structured envelope. Success responses are
        {"success":..,"message":..,"data":{...},"error":..,"metadata":{...}}
        directly; FastAPI HTTPException error responses arrive as
        {"detail": {...same shape...}}. Returns whichever shape applies.
        """
        raw = transport_result.get("data") or {}
        detail = raw.get("detail")
        if isinstance(detail, dict) and "success" in detail:
            return detail
        return raw

    def _call_api(self, method: str, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        transport_result = self._transport_call(method, path, payload)
        envelope = self._extract_envelope(transport_result)
        envelope_success = envelope.get("success")
        ok = bool(transport_result.get("ok")) and (envelope_success is not False)
        return {
            "ok": ok,
            "transport_ok": bool(transport_result.get("ok")),
            "transport_status": transport_result.get("status"),
            "envelope": envelope,
            "errors": transport_result.get("errors", []),
        }

    def _call_with_backoff(
        self,
        func: Callable[[], Dict[str, Any]],
        max_attempts: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Exponential backoff, capped at config.max_backoff_seconds. Retries
        only on transport-level unreachability (connection_error /
        request_failed), not on HTTP-level responses (auth/validation
        errors are not "the backend is unreachable" -- they are reported
        immediately without a retry storm).
        """
        attempt = 0
        backoff = 1
        while True:
            attempt += 1
            result = func()
            if result["transport_ok"] or str(result["transport_status"]).startswith("http_"):
                return result

            self._set_state(
                VoiceWorkerState.ERROR,
                f"backend unreachable (attempt {attempt}, status={result['transport_status']})",
            )

            if max_attempts is not None and attempt >= max_attempts:
                return result

            time.sleep(backoff)
            backoff = min(backoff * 2, self.config.max_backoff_seconds)

    # -----------------------------------------------------------------
    # Voice API calls
    # -----------------------------------------------------------------

    def fetch_status(self, max_attempts: Optional[int] = None) -> Dict[str, Any]:
        return self._call_with_backoff(lambda: self._call_api("GET", "/voice/status"), max_attempts=max_attempts)

    def send_heartbeat(self) -> Dict[str, Any]:
        """
        Tells the backend this worker is alive right now, independent of
        wake events -- without this, voice_worker_connected only ever got
        set True on a wake event, so a worker that was up but hadn't heard
        the wake word yet incorrectly showed as "Worker Offline" on the
        dashboard.
        """
        return self._call_with_backoff(lambda: self._call_api("POST", "/voice/worker/heartbeat"), max_attempts=1)

    def send_wake_event(self, confidence: float, activation_type: str = "wake_word") -> Dict[str, Any]:
        payload = {
            "session_id": self.session_id,
            "confidence": confidence,
            "activation_type": activation_type,
        }
        return self._call_with_backoff(lambda: self._call_api("POST", "/voice/wake-event", payload), max_attempts=3)

    def send_command(self, transcript: str, detected_language: str, wake_word: Optional[str]) -> Dict[str, Any]:
        """POSTs to /voice/push-to-talk/text, not /voice/command --
        push-to-talk-text is the route that shares apps/api/routes/
        assistant.py's real SystemAgent/Windows Worker dispatcher (see
        apps/api/routes/voice.py::push_to_talk_text's docstring); /voice/
        command's own standby-mode wake-word-reactivation and speaker-
        profile logic (which `wake_word` fed into) doesn't apply to
        push-to-talk-text, so it's accepted here but no longer sent."""
        del wake_word  # kept in the signature for backward-compat call sites
        payload = {
            "text": transcript,
            "detected_language": detected_language,
            "session_id": self.session_id,
        }
        return self._call_with_backoff(lambda: self._call_api("POST", "/voice/push-to-talk/text", payload), max_attempts=3)

    # -----------------------------------------------------------------
    # Dependency status reporting
    # -----------------------------------------------------------------

    def _report_dependency_status(self, status_result: Dict[str, Any], brief: bool = False) -> None:
        if not status_result.get("ok"):
            envelope = status_result.get("envelope") or {}
            message = envelope.get("message") or "Could not reach /voice/status."
            self._log(f"Dependency status check failed: {message} (transport_status={status_result.get('transport_status')})")
            self._log(
                "Continuing in dependency-check mode: no confirmed audio_input_worker / "
                "stt_provider / tts_provider / speaker_recognition_provider available "
                "(status unknown -- backend unreachable or auth failed)."
            )
            return

        envelope = status_result.get("envelope") or {}
        settings = (envelope.get("data") or {}).get("settings") or {}
        dependency_status = settings.get("dependency_status") or {}
        mode = settings.get("mode", VOICE_MODE_DISABLED)
        wake_word = settings.get("wake_word", DEFAULT_WAKE_WORD)

        self._sync_wake_word(wake_word)

        if brief:
            self._log(f"Status re-check: mode={mode} wake_word={wake_word!r} deps={dependency_status}")
            return

        if mode == VOICE_MODE_DISABLED:
            self._log("Voice disabled for this workspace.")
        elif mode == VOICE_MODE_STANDBY:
            self._log(f"Voice is in standby. Say {wake_word!r} to resume processing commands.")
        else:
            self._log(f"Voice mode for this workspace: {mode}")
        self._log(f"Configured wake word: {wake_word!r}")
        self._log("Dependency status:")
        for key in (
            "wake_word_engine",
            "audio_input_worker",
            "stt_provider",
            "tts_provider",
            "speaker_recognition_provider",
        ):
            entry = dependency_status.get(key, "unknown")
            # entry is {"status": ..., "install_guidance": ...} in the
            # current backend shape; "unknown"/a bare string is still
            # handled so an older/unreachable backend doesn't crash this
            # worker -- it just reports honestly as MISSING.
            value = entry.get("status", "unknown") if isinstance(entry, dict) else entry
            guidance = entry.get("install_guidance") if isinstance(entry, dict) else None
            marker = "OK" if value == "configured" or value == "available" else "MISSING"
            self._log(f"    - {key}: {value}  [{marker}]" + (f" -- {guidance}" if guidance else ""))

        def _dep_status(entry: Any) -> str:
            return entry.get("status", "unknown") if isinstance(entry, dict) else entry

        missing = [
            key
            for key, value in dependency_status.items()
            if _dep_status(value) not in ("configured", "available")
        ]
        if missing:
            self._log(
                "No real audio/STT/TTS libraries are installed in this environment "
                f"({', '.join(missing)}). Starting in dependency-check mode: text-based "
                "wake-word detection and the API control plane still work; real "
                "microphone/speech capture does not."
            )
        else:
            self._log("All voice dependencies report configured/available.")

    # -----------------------------------------------------------------
    # Wake-word detection (local, text-based, real)
    # -----------------------------------------------------------------

    def _detect_wake_word(self, text: str) -> Dict[str, Any]:
        if self._wake_detector is None:
            return {"detected": False, "confidence": 0.0, "trigger": None, "match_metadata": {}}

        result = self._wake_detector.detect_from_text(text=text, context=None, metadata={"source": "voice_worker"})
        data = result.get("data") or {}
        return {
            "detected": bool(data.get("detected")),
            "confidence": float(data.get("confidence", 0.0) or 0.0),
            "trigger": data.get("trigger"),
            "match_metadata": data.get("metadata") or {},
        }

    @staticmethod
    def _strip_wake_word(text: str, match_metadata: Dict[str, Any]) -> str:
        start = match_metadata.get("match_start")
        end = match_metadata.get("match_end")
        if not isinstance(start, int) or not isinstance(end, int):
            return text.strip()

        remainder = (text[:start] + " " + text[end:]).strip()
        remainder = remainder.lstrip(",:;-— \t")
        remainder = " ".join(remainder.split())
        return remainder or text.strip()

    # -----------------------------------------------------------------
    # Core text-input pipeline (used by --simulate-text and the
    # interactive stdin fallback loop)
    # -----------------------------------------------------------------

    def _handle_input_text(self, text: str, status_result: Dict[str, Any]) -> bool:
        """
        Runs one piece of "as-if-transcribed" text through the full local
        gating + API pipeline. Returns True if a command was actually
        sent to /voice/push-to-talk/text.
        """
        if not text or not text.strip():
            self._log("Empty input; nothing to process.")
            return False

        envelope = status_result.get("envelope") or {}
        settings = (envelope.get("data") or {}).get("settings") or {}
        mode = settings.get("mode", VOICE_MODE_DISABLED) if status_result.get("ok") else VOICE_MODE_DISABLED

        if not status_result.get("ok"):
            self._set_state(VoiceWorkerState.ERROR, "voice status unavailable; cannot safely determine mode")
            self._log("Could not confirm the workspace's voice mode from /voice/status; treating as disabled/unsafe to send.")
            return False

        self._set_state(VoiceWorkerState.LISTENING, f"input_length={len(text)} mode={mode}")

        detection = self._detect_wake_word(text)
        detected = detection["detected"]

        if detected:
            self._set_state(
                VoiceWorkerState.WAKE_DETECTED,
                f"trigger={detection['trigger']!r} confidence={detection['confidence']:.2f}",
            )
        else:
            self._log(f"No wake word detected in input text (mode={mode}).")

        if mode == VOICE_MODE_DISABLED:
            if self.config.ignore_mode_for_dev:
                self._log(
                    "Voice mode is disabled for this workspace, but --ignore-mode-for-dev is set: "
                    "sending anyway (dev/test only). Do not use this flag for production listening -- "
                    "it only bypasses this worker's own local gate; it does not change the workspace's "
                    "real voice mode setting."
                )
            else:
                self._log("Voice mode is disabled for this workspace; command not sent.")
                return False

        if mode in WAKE_WORD_GATED_MODES and not detected:
            self._log(
                f"Wake word not detected. Command not sent (mode='{mode}' requires local "
                "wake-word activation before the worker will contact /voice/push-to-talk/text)."
            )
            return False

        wake_word_for_command: Optional[str] = None
        transcript = text.strip()

        if detected:
            wake_word_for_command = detection["trigger"]
            transcript = self._strip_wake_word(text, detection["match_metadata"])

            wake_event_result = self.send_wake_event(confidence=detection["confidence"])
            if not wake_event_result["ok"]:
                self._set_state(VoiceWorkerState.ERROR, "failed to register wake event with backend")
                self._print_api_failure("POST /voice/wake-event", wake_event_result)
                return False

            wake_data = (wake_event_result["envelope"].get("data") or {})
            self._log(
                f"Wake event registered. should_listen={wake_data.get('should_listen')} "
                f"server_mode={wake_data.get('mode')}"
            )

        # No real speaker-recognition provider is configured in this
        # environment (see dependency_status.speaker_recognition_provider)
        # -- honestly report that this step is skipped rather than
        # pretending a verification happened.
        self._set_state(
            VoiceWorkerState.VERIFYING_SPEAKER,
            "no speaker-recognition provider configured; skipping local verification "
            "(server still applies its own admin/owner or profile-based authorization)",
        )

        # No real STT ran -- the "transcript" is the text the caller
        # already gave us (via --simulate-text or the interactive stdin
        # fallback). This state transition is kept honest about that.
        self._set_state(
            VoiceWorkerState.TRANSCRIBING,
            f"no real STT provider installed; using provided text as transcript (length={len(transcript)})",
        )

        detected_language = "en"
        self._set_state(VoiceWorkerState.LANGUAGE_DETECTED, f"detected_language={detected_language} (default; no language-ID provider configured)")

        self._set_state(VoiceWorkerState.SENDING_TO_MASTER, f"session_id={self.session_id}")
        command_result = self.send_command(transcript, detected_language, wake_word_for_command)

        if not command_result["ok"]:
            self._set_state(VoiceWorkerState.ERROR, "voice command request failed")
            self._print_api_failure("POST /voice/push-to-talk/text", command_result)
            return False

        command_envelope = command_result["envelope"]
        command_data = command_envelope.get("data") or {}
        speech_status = command_data.get("speech_output_status", "tts_missing")

        self._set_state(
            VoiceWorkerState.SPEAKING,
            f"speech_output_status={speech_status} (no local speaker/TTS provider attached; "
            "text response only)",
        )

        self._print_command_response(command_data)
        return True

    # -----------------------------------------------------------------
    # Output formatting
    # -----------------------------------------------------------------

    def _print_api_failure(self, call_label: str, result: Dict[str, Any]) -> None:
        envelope = result.get("envelope") or {}
        message = envelope.get("message") or "Request failed."
        error = envelope.get("error")
        print(f"\n[{call_label}] failed: {message}")
        if error:
            print(f"  error: {error}")
        if result.get("errors"):
            print(f"  transport_errors: {result['errors']}")
        print()

    def _print_command_response(self, command_data: Dict[str, Any]) -> None:
        print("\n" + "=" * 60)
        print("Voice command response")
        print("-" * 60)
        if "final_answer" in command_data:
            # Real command, routed through the shared assistant dispatcher
            # (apps/api/routes/assistant.py::process_assistant_message).
            print(f"final_answer         : {command_data.get('final_answer')}")
            print(f"status               : {command_data.get('status')}")
            print(f"route                : {command_data.get('route')}")
            print(f"worker_task_id       : {command_data.get('worker_task_id')}")
            print(f"speech_output_status : {command_data.get('speech_output_status')}")
        else:
            # Control-phrase ("William standby"/"William shutdown voice")
            # or speaker-permission-denial response -- unchanged shape.
            print(f"success              : {command_data.get('success')}")
            print(f"response_text        : {command_data.get('response_text')}")
            print(f"speech_output_status : {command_data.get('speech_output_status')}")
        print("=" * 60 + "\n")

    # -----------------------------------------------------------------
    # Run modes
    # -----------------------------------------------------------------

    def run(self) -> int:
        self._print_banner()

        if not self.config.token and not self.config.device_token:
            self._log(
                "No auth token configured (--token / WILLIAM_VOICE_WORKER_TOKEN, or --device-token / "
                "--config for an installed worker, not set). Starting in dependency-check mode; API "
                "calls will likely fail authentication."
            )

        status_result = self.fetch_status(max_attempts=3 if self.config.simulate_text else None)

        if self._is_auth_failure(status_result):
            # A dead credential can never succeed via retry -- stop cleanly
            # with an honest, actionable message instead of looping forever
            # or dumping a traceback (mirrors windows_worker.py::run_forever's
            # own DeviceAuthError handling).
            self._set_state(VoiceWorkerState.ERROR, "authentication failed (401)")
            print(self._auth_failure_message())
            return 1

        self._report_dependency_status(status_result)

        if self.config.simulate_text is not None:
            sent = self._handle_input_text(self.config.simulate_text, status_result)
            self._set_state(VoiceWorkerState.IDLE, "simulate-text run complete")
            return 0 if (sent or status_result.get("ok")) else 1

        if status_result.get("ok"):
            heartbeat_result = self.send_heartbeat()
            if heartbeat_result["ok"]:
                self._log("Heartbeat sent. Dashboard should show this worker as connected.")
            else:
                self._log("Heartbeat failed; dashboard may show this worker as offline until the next successful check-in.")

        try:
            if sys.stdin.isatty():
                self._run_interactive_loop()
            else:
                self._run_idle_loop()
        except KeyboardInterrupt:
            pass

        self._log("Voice worker stopped.")
        return 0

    def _run_idle_loop(self) -> None:
        self._set_state(
            VoiceWorkerState.IDLE,
            "no --simulate-text given and stdin is not a TTY; entering safe idle loop "
            f"(re-checking /voice/status and sending a heartbeat every "
            f"{self.config.poll_interval_seconds}s, Ctrl+C to stop). This is the real "
            "'ears on' background listening loop: no dashboard tab needs to stay open "
            "for this process to keep reporting connected and, once a real "
            "audio/STT/wake-word provider is configured, to keep listening.",
        )
        while True:
            time.sleep(self.config.poll_interval_seconds)
            status_result = self.fetch_status(max_attempts=1)
            if self._is_auth_failure(status_result):
                self._set_state(VoiceWorkerState.ERROR, "authentication failed (401)")
                print(self._auth_failure_message())
                return
            self._report_dependency_status(status_result, brief=True)
            if status_result.get("ok"):
                heartbeat_result = self.send_heartbeat()
                if self._is_auth_failure(heartbeat_result):
                    self._set_state(VoiceWorkerState.ERROR, "authentication failed (401)")
                    print(self._auth_failure_message())
                    return

    def _run_interactive_loop(self) -> None:
        self._set_state(VoiceWorkerState.IDLE, "interactive fallback mode ready")
        print(
            "Interactive fallback mode: type text as if it were transcribed speech "
            "(no real microphone is attached). Type 'exit' or press Ctrl+D to quit.\n"
        )
        while True:
            try:
                line = input("you> ")
            except EOFError:
                break

            if not line.strip():
                continue
            if line.strip().lower() in {"exit", "quit"}:
                break

            status_result = self.fetch_status(max_attempts=3)
            if self._is_auth_failure(status_result):
                self._set_state(VoiceWorkerState.ERROR, "authentication failed (401)")
                print(self._auth_failure_message())
                return
            if status_result.get("ok"):
                self.send_heartbeat()
            self._handle_input_text(line, status_result)
            self._set_state(VoiceWorkerState.IDLE, "waiting for next input")

    def _print_banner(self) -> None:
        self._log("William / Jarvis Voice Worker starting.")
        self._log(f"API base URL   : {self.config.api_base_url}")
        self._log(f"Session id     : {self.session_id}")
        self._log(f"Wake word seed : {self._effective_wake_word_seed()!r}")
        self._log(f"Auth mode      : {'device_token' if self.config.device_token else ('jwt' if self.config.token else 'none')}")


# ---------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------

def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="voice_worker",
        description="William/Jarvis voice worker: talks to the real /api/v1/voice/* API.",
    )
    parser.add_argument("--token", default=None, help="JWT access token (or set WILLIAM_VOICE_WORKER_TOKEN).")
    parser.add_argument(
        "--device-token",
        default=None,
        help="Installed-worker device token from POST /voice/device/register (overrides WILLIAM_VOICE_WORKER_DEVICE_TOKEN).",
    )
    parser.add_argument(
        "--config",
        default=None,
        help='Path to a JSON config file (scripts/windows/install_voice_worker.ps1 writes one to '
        '%%USERPROFILE%%\\.william\\voice_worker.json) with api_base_url/device_id/device_token/device_name.',
    )
    parser.add_argument("--api-base-url", default=None, help="Backend API base URL (or set WILLIAM_API_BASE_URL).")
    parser.add_argument("--poll-interval", type=int, default=None, help="Idle-loop status re-check interval, seconds.")
    parser.add_argument("--wake-word", default=None, help="Override local wake word (default: server-configured, else 'william').")
    parser.add_argument("--max-backoff", type=int, default=None, help="Reconnect backoff cap, seconds (default 30).")
    parser.add_argument(
        "--simulate-text",
        default=None,
        help="Run this text through wake-word detection and the voice API once, then exit.",
    )
    parser.add_argument(
        "--ignore-mode-for-dev",
        action="store_true",
        help="Bypass this worker's local 'voice mode is disabled' gate for --simulate-text dev/test runs. "
        "Does not change the workspace's real voice mode setting. Do not use this for production listening.",
    )
    return parser.parse_args(argv)


def build_config(args: argparse.Namespace) -> VoiceWorkerConfig:
    config = VoiceWorkerConfig(
        api_base_url=args.api_base_url or os.getenv("WILLIAM_API_BASE_URL", DEFAULT_API_BASE_URL),
        token=args.token or os.getenv("WILLIAM_VOICE_WORKER_TOKEN", ""),
        device_token=args.device_token or os.getenv("WILLIAM_VOICE_WORKER_DEVICE_TOKEN", ""),
        poll_interval_seconds=args.poll_interval or _env_int("WILLIAM_VOICE_WORKER_POLL_INTERVAL", 20),
        wake_word=args.wake_word or os.getenv("WILLIAM_VOICE_WORKER_WAKE_WORD") or None,
        max_backoff_seconds=args.max_backoff or _env_int("WILLIAM_VOICE_WORKER_MAX_BACKOFF", 30),
        simulate_text=args.simulate_text,
        ignore_mode_for_dev=bool(args.ignore_mode_for_dev),
    )

    # Config-file values apply first (lowest priority) -- explicit CLI
    # flags/env vars above always override them, matching windows_worker.py
    # ::main's own --token/--api-base-url/--device-name precedence over a
    # loaded --config file.
    if args.config:
        config.config_path = args.config
        try:
            with open(args.config, "r", encoding="utf-8") as config_file:
                file_config = json.load(config_file)
            if not isinstance(file_config, dict):
                raise ValueError("Config file must contain a JSON object.")
            if not args.api_base_url and file_config.get("api_base_url"):
                config.api_base_url = str(file_config["api_base_url"]).rstrip("/")
            if not args.device_token and file_config.get("device_token"):
                config.device_token = str(file_config["device_token"])
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            print(f"Could not read config file {args.config}: {exc}")
            raise SystemExit(1)

    return config


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)
    config = build_config(args)
    worker = VoiceWorker(config)
    try:
        return worker.run()
    except Exception as exc:  # pragma: no cover - last-resort safety net
        # Never surface a raw traceback to the console for a worker whose
        # whole job is to stay alive; log full detail, print a clear
        # honest one-line summary, and exit non-zero.
        logger.exception("Voice worker crashed unexpectedly.")
        print(f"\nVoice worker error: {exc.__class__.__name__}: {exc}\n")
        return 1


if __name__ == "__main__":
    sys.exit(main())
