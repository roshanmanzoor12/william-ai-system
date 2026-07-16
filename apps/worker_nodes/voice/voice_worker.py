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

    Real microphone capture, real STT, and real TTS are provided by
    apps/worker_nodes/voice/providers/ (audio_input.py/stt.py/tts.py/
    wake_word.py/provider_status.py) -- this file composes those adapters
    rather than reimplementing them. Every one of them degrades honestly
    to dependency_required when its package/env var isn't configured; this
    worker never fabricates a listen/transcribe/speak event. What it
    provides beyond that composition is real, working plumbing:

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

    Hard privacy/safety rule (mirrors the rest of this codebase): raw audio
    is never persisted by default. audio_input.py::record_to_tempfile()
    writes one real WAV file per capture to the OS temp directory; this
    worker deletes it immediately after stt.py::transcribe() consumes it
    (see _dispatch_transcript's finally block), unless
    WILLIAM_VOICE_DEBUG_KEEP_AUDIO=true is explicitly set for local
    debugging. Every real wake/listen/transcribe/speak event is logged
    (metadata only -- duration, confidence, provider name -- never audio
    content) via the existing audit path
    (apps/api/services/voice_service.py::record_voice_event, called
    server-side on every /voice/wake-event and /voice/push-to-talk/text
    call this worker already makes).

Run:
    python -m apps.worker_nodes.voice.voice_worker
    python -m apps.worker_nodes.voice.voice_worker --simulate-text "William create a VEO prompt for ClickRonix"
    python -m apps.worker_nodes.voice.voice_worker --config "%USERPROFILE%\\.william\\voice_worker.json" --list-audio-devices
    python -m apps.worker_nodes.voice.voice_worker --config "%USERPROFILE%\\.william\\voice_worker.json" --test-tts
    python -m apps.worker_nodes.voice.voice_worker --config "%USERPROFILE%\\.william\\voice_worker.json" --test-mic
    python -m apps.worker_nodes.voice.voice_worker --config "%USERPROFILE%\\.william\\voice_worker.json" --test-stt
    python -m apps.worker_nodes.voice.voice_worker --config "%USERPROFILE%\\.william\\voice_worker.json" --test-wake-word

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
    --list-audio-devices                              print real input devices (sounddevice) and exit; no auth needed
    --test-mic                                          record a few real seconds from the mic and report
                                                          duration/path (deletes the file after); no auth needed
    --test-stt                                          record + transcribe with the configured STT provider and
                                                          print the real text; no auth needed
    --test-tts ["<text>"]                               speak a test sentence (the default one, or the given
                                                          text) with the configured TTS provider (or report
                                                          tts_missing); no auth needed
    --test-wake-word                                    listen for the real audio wake word for a few seconds and
                                                          report detected/not detected; no auth needed
    --enroll-voice <role>                               enroll a Trusted Voice Profile (owner/admin/
                                                          trusted_friend/trusted_family/trusted_team_member/
                                                          guest) by speaking 3 short phrases; requires admin
                                                          auth (--token/--device-token)
    --list-voice-profiles                               list this workspace's Trusted Voice Profiles
                                                          (never prints an embedding); requires auth
    --delete-voice-profile <profile_id>                  revoke a Trusted Voice Profile; requires admin auth

Continuous conversation session (wake_word_admin/wake_word_trusted_users
only -- see _run_active_conversation_session): after the wake word is
detected, the worker stays in active_conversation and keeps capturing/
dispatching commands WITHOUT requiring the wake word again, until a local
sleep phrase (SLEEP_PHRASES) is said or the session times out.
    WILLIAM_VOICE_ACTIVE_SESSION_TIMEOUT_SECONDS      inactivity timeout, seconds (default 60)
    WILLIAM_VOICE_COMMAND_RECORD_SECONDS              max seconds per command capture (default 5)
    WILLIAM_VOICE_COMMAND_SILENCE_TIMEOUT             silence-to-stop-recording seconds (default 1.5)
    WILLIAM_VOICE_NO_SPEECH_MAX_RETRIES               consecutive genuine-silence captures before the
                                                          session ends and the worker returns to wake-word
                                                          waiting (default 2) -- never spoken about on every
                                                          single silent capture, only once at the cap
    WILLIAM_VOICE_VERBOSE_ERRORS                       "1"/"true" also speaks "No speech detected; still
                                                          listening." on every silent capture, not just at
                                                          the retry cap (default off -- log-only)
    WILLIAM_VOICE_REPLY_STYLE                          "short" (default) or "full" -- only the SPOKEN
                                                          copy of a reply is ever shortened; the printed/
                                                          logged text is always shown in full
    WILLIAM_VOICE_MAX_SPOKEN_CHARS                     spoken-reply character cap when REPLY_STYLE=short
                                                          (default 240)
    WILLIAM_VOICE_DEBUG                                 "1"/"true" prints extra debug info (selected mic
                                                          device, RMS input level, TTS voice/rate/volume)
                                                          from --test-mic/--test-stt/--test-tts
    WILLIAM_VOICE_SAVE_DEBUG_WAV                        alias for WILLIAM_VOICE_DEBUG_KEEP_AUDIO -- keeps
                                                          the captured WAV instead of deleting it
    WILLIAM_VOICE_MIC_DEVICE                           preferred alias for WILLIAM_AUDIO_DEVICE (device
                                                          index or a substring of its name)

Trusted Voice Profiles (--enroll-voice, see apps/worker_nodes/voice/
providers/speaker_embedding.py):
    WILLIAM_SPEAKER_RECOGNITION_PROVIDER              set to "local_speaker_embedding" to enable real local
                                                          enrollment/verification; unset means honest
                                                          external_dependency_required
    WILLIAM_VOICE_ENROLLMENT_PHRASES                   number of phrases to record during enrollment
                                                          (default 3)
    WILLIAM_VOICE_MATCH_THRESHOLD                      minimum cosine-similarity confidence for a runtime
                                                          verification match (default 0.72; enforced
                                                          server-side)

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
from typing import Any, Callable, Dict, List, Optional


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

try:
    from apps.worker_nodes.voice.providers import (  # type: ignore
        audio_input as audio_input_provider,
        stt as stt_provider,
        tts as tts_provider,
        wake_word as wake_word_provider,
        provider_status as provider_status_module,
        speaker_embedding as speaker_embedding_provider,
    )
except Exception:  # pragma: no cover - import-safe fallback
    audio_input_provider = None  # type: ignore
    stt_provider = None  # type: ignore
    tts_provider = None  # type: ignore
    wake_word_provider = None  # type: ignore
    provider_status_module = None  # type: ignore
    speaker_embedding_provider = None  # type: ignore


LOGGER_NAME = "william.worker_nodes.voice"
logger = logging.getLogger(LOGGER_NAME)

# Guards against double-registration if this module is ever imported under
# two different names in the same process (e.g. once as "__main__" via
# `python -m`, once via a real `import apps.worker_nodes.voice.voice_worker`
# elsewhere) -- logging.getLogger(LOGGER_NAME) always returns the SAME
# logger object either way (the registry is keyed by name, independent of
# Python's module import system), so this check is safe and sufficient:
# it is never possible for this exact handler to be added twice.
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
# Modes that mean "start the real always-listening audio loop if this
# worker's local providers support it" -- distinct from WAKE_WORD_GATED_MODES
# above (which is about server-side/text-path gating semantics that already
# applied before real audio existed). standby is deliberately excluded here:
# it means "connected but not listening" even with providers fully installed.
ALWAYS_LISTENING_MODES = {"wake_word_admin", "wake_word_trusted_users"}

# Local debug-only escape hatch: real captured audio is deleted immediately
# after STT consumes it unless this is explicitly set to keep it on disk
# for troubleshooting a bad transcription. Never enabled by default.
# WILLIAM_VOICE_SAVE_DEBUG_WAV is an honest alias for the exact same
# behavior (matches the naming this feature's spec asks for) -- either one
# set keeps the WAV.
DEBUG_KEEP_AUDIO_ENV_VAR = "WILLIAM_VOICE_DEBUG_KEEP_AUDIO"
SAVE_DEBUG_WAV_ENV_VAR = "WILLIAM_VOICE_SAVE_DEBUG_WAV"
VOICE_DEBUG_ENV_VAR = "WILLIAM_VOICE_DEBUG"
MIC_DEVICE_ENV_VAR = "WILLIAM_VOICE_MIC_DEVICE"


def _voice_debug_enabled() -> bool:
    return os.getenv(VOICE_DEBUG_ENV_VAR, "").strip().lower() in ("1", "true", "yes")


# --enroll-voice: the exact phrases asked for, spoken once each and
# averaged into one enrollment embedding. WILLIAM_VOICE_ENROLLMENT_PHRASES
# lets an operator ask for fewer (never more than these 3 are defined).
ENROLLMENT_PHRASES = [
    "William, this is my voice.",
    "William, verify me.",
    "William, open assistant.",
]
DEFAULT_ENROLLMENT_PHRASES = 3
ENROLLMENT_PHRASES_ENV_VAR = "WILLIAM_VOICE_ENROLLMENT_PHRASES"

# Local, worker-side heuristic ONLY -- deciding whether to hold a command
# back locally pending speaker verification (see _is_sensitive_transcript).
# This is never the real authorization boundary: the server-side
# SecurityAgent/system_worker classify_worker_action gate (apps/api/routes/
# system_worker.py) still independently reviews risky actions regardless of
# what this worker does locally. This list exists only so a workspace
# without a speaker-recognition provider doesn't let ANY voice speaker
# execute a sensitive command hands-free with zero local friction.
SENSITIVE_TRANSCRIPT_KEYWORDS = {
    "delete", "remove all", "wipe", "format", "shutdown", "shut down", "restart",
    "reboot", "uninstall", "factory reset",
    "payment", "pay ", "transfer", "wire ", "invoice", "refund", "charge",
    "purchase", "buy ", "bank account", "credit card", "routing number",
    "password", "credential", "api key", "secret key", "private key",
    "confidential", "unlock", "grant access", "revoke access", "admin access",
}

# Env vars the worker itself reads locally for its real-listening gate --
# printed at startup (requirement: honest, exact effective values, not the
# BACKEND process's view of the same names). See _print_local_provider_env.
LOCAL_PROVIDER_ENV_VARS = (
    "WILLIAM_AUDIO_INPUT_PROVIDER",
    "WILLIAM_STT_PROVIDER",
    "WILLIAM_TTS_PROVIDER",
    "WILLIAM_WAKE_WORD_PROVIDER",
    "WILLIAM_WAKE_WORD_PHRASE",
)

# Continuous conversation session -- local, worker-side control phrases
# ONLY (never sent to the assistant dispatcher/MasterAgent when matched
# during an active_conversation session; see _is_sleep_transcript). This is
# deliberately distinct from the SERVER-side "William standby"/"William
# shutdown voice" control phrases apps/api/routes/voice.py's push-to-talk-
# text dispatcher already recognizes (which fully disable/pause the
# workspace's voice mode) -- these phrases only end THIS worker's local
# active_conversation session and return to wake-word waiting; the
# workspace's server-side voice mode is untouched. "shutdown voice"
# appearing in both lists is intentional: said during an active
# conversation it now means "stop this local session" (per this feature's
# spec), not "disable the workspace" -- an operator who wants the full
# server-side disable can still do it from the dashboard or via
# POST /voice/disable.
SLEEP_PHRASES = (
    "william bye",
    "bye william",
    "go to sleep",
    "stop listening",
    "shutdown voice",
    "sleep now",
    "that's all",
    "thank you william",
)

# Continuous conversation session env vars.
ACTIVE_SESSION_TIMEOUT_ENV_VAR = "WILLIAM_VOICE_ACTIVE_SESSION_TIMEOUT_SECONDS"
DEFAULT_ACTIVE_SESSION_TIMEOUT_SECONDS = 60.0
COMMAND_RECORD_SECONDS_ENV_VAR = "WILLIAM_VOICE_COMMAND_RECORD_SECONDS"
DEFAULT_COMMAND_RECORD_SECONDS = 5.0
COMMAND_SILENCE_TIMEOUT_ENV_VAR = "WILLIAM_VOICE_COMMAND_SILENCE_TIMEOUT"
DEFAULT_COMMAND_SILENCE_TIMEOUT = 1.5

# No-speech handling: a capture where STT reports ok=False (e.g. "no speech
# detected") or returns empty text is genuine SILENCE, not a garbled
# attempt -- distinct from WEAK_TRANSCRIPT_* below (real but low-confidence/
# garbled speech). Silence is common and expected while the user just
# isn't talking yet in an active_conversation session, so it must never be
# spoken about on every single occurrence (that was the reported bug: a
# silent room made the worker repeat "could not understand" every ~5s).
# Only after NO_SPEECH_MAX_RETRIES consecutive silent captures does the
# worker say anything out loud, and then only once, before ending the
# session.
NO_SPEECH_MAX_RETRIES_ENV_VAR = "WILLIAM_VOICE_NO_SPEECH_MAX_RETRIES"
DEFAULT_NO_SPEECH_MAX_RETRIES = 2
VERBOSE_ERRORS_ENV_VAR = "WILLIAM_VOICE_VERBOSE_ERRORS"

# A transcript this short/empty (after stripping trailing periods) is
# never sent to the assistant dispatcher -- honest local rejection instead
# of guessing at a garbled/empty STT result. Not itself an env var (the
# spec only asks for the behavior, not a tunable threshold); a low
# confidence floor is also applied when the STT provider reports one.
WEAK_TRANSCRIPT_MIN_LENGTH = 2
WEAK_TRANSCRIPT_MIN_CONFIDENCE = 0.15

# Reply-shaping env vars (Phase 4: keep spoken replies short by default;
# the full text is always still printed/logged/shown in the dashboard --
# only what gets SPOKEN through TTS is ever shortened).
VOICE_REPLY_STYLE_ENV_VAR = "WILLIAM_VOICE_REPLY_STYLE"
DEFAULT_VOICE_REPLY_STYLE = "short"
VOICE_MAX_SPOKEN_CHARS_ENV_VAR = "WILLIAM_VOICE_MAX_SPOKEN_CHARS"
DEFAULT_VOICE_MAX_SPOKEN_CHARS = 240


class VoiceWorkerState(str, Enum):
    """
    Console lifecycle states, exact names from the Phase 9 spec, extended
    with the continuous-conversation-session states (waiting_for_wake_word/
    active_conversation/capturing_command/dispatching/sleeping) -- added
    alongside the originals, not replacing them, so every existing state
    transition (idle-loop/interactive-loop/wake-word-wait/speaker-
    verification/language-detection stages) keeps working unchanged.
    """

    IDLE = "idle"
    LISTENING = "listening"
    WAITING_FOR_WAKE_WORD = "waiting_for_wake_word"
    WAKE_DETECTED = "wake_detected"
    ACTIVE_CONVERSATION = "active_conversation"
    CAPTURING_COMMAND = "capturing_command"
    VERIFYING_SPEAKER = "verifying_speaker"
    TRANSCRIBING = "transcribing"
    LANGUAGE_DETECTED = "language_detected"
    SENDING_TO_MASTER = "sending_to_master"
    DISPATCHING = "dispatching"
    SPEAKING = "speaking"
    SLEEPING = "sleeping"
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
        # Continuous conversation session state (see _run_active_conversation_
        # session) -- _active_conversation gates the local sleep-phrase check
        # in _capture_transcribe_and_respond (never applied to a single
        # --simulate-text/interactive-loop call); _sleep_requested is set by
        # that same method right before returning False for a detected sleep
        # phrase, so the caller can distinguish "sleep" from "weak/failed
        # capture" without changing _capture_transcribe_and_respond's
        # existing bool return contract.
        self._active_conversation = False
        self._sleep_requested = False
        # Consecutive genuine-silence captures (STT ok=False or empty text)
        # within the current active_conversation session -- reset to 0 by
        # any real (non-silent) capture; once it reaches
        # WILLIAM_VOICE_NO_SPEECH_MAX_RETRIES the session ends (see
        # _capture_transcribe_and_respond).
        self._consecutive_no_speech = 0

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

    @staticmethod
    def _effective_wake_word_phrase_for_display() -> str:
        """Human-readable form of the REAL audio wake phrase the
        openwakeword listener is actually loaded with (WILLIAM_WAKE_WORD_
        PHRASE, resolved to a real bundled model name via wake_word.py::
        resolve_bundled_model_name) -- deliberately reads the same env var
        wake_word.WakeWordListener() itself resolves from, not this
        worker's separate --wake-word/DEFAULT_WAKE_WORD (which only
        configures the always-available TEXT-based detector used by
        --simulate-text/push-to-talk, a different phrase entirely)."""
        if wake_word_provider is not None:
            try:
                resolved = wake_word_provider.resolve_bundled_model_name()
                phrase = resolved["model_name"]
            except Exception:  # pragma: no cover - defensive only
                phrase = os.getenv("WILLIAM_WAKE_WORD_PHRASE", DEFAULT_WAKE_WORD)
        else:
            phrase = os.getenv("WILLIAM_WAKE_WORD_PHRASE", DEFAULT_WAKE_WORD)
        return phrase.strip().replace("_", " ").replace("-", " ").title() or DEFAULT_WAKE_WORD.title()

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

    def verify_speaker(self, embedding: List[float]) -> Dict[str, Any]:
        """Sends a real, locally-computed embedding vector (never raw
        audio) to the backend for comparison against this workspace's own
        trusted profiles (apps/api/routes/voice.py::verify_voice_profile).
        See _verify_speaker for the honest wrapper that also handles a
        transport failure (network down, backend error) as "could not
        verify" rather than crashing the pipeline."""
        return self._call_with_backoff(
            lambda: self._call_api("POST", "/voice/profiles/verify", {"embedding": embedding}), max_attempts=2,
        )

    def _verify_speaker(self, embedding: List[float]) -> Dict[str, Any]:
        """Honest wrapper: a transport failure or malformed response is
        never treated as a match -- fail closed, exactly like "no
        embedding at all" (see _send_transcript_and_respond)."""
        result = self.verify_speaker(embedding)
        if not result.get("ok"):
            self._log(f"Speaker verification request failed: {result.get('transport_status')}")
            return {"matched": False, "profile_id": None, "display_name": None, "role": None, "confidence": 0.0}
        data = (result.get("envelope") or {}).get("data") or {}
        return {
            "matched": bool(data.get("matched")),
            "profile_id": data.get("profile_id"),
            "display_name": data.get("display_name"),
            "role": data.get("role"),
            "confidence": data.get("confidence", 0.0),
        }

    def send_command(
        self,
        transcript: str,
        detected_language: str,
        wake_word: Optional[str],
        timing_ms: Optional[Dict[str, float]] = None,
    ) -> Dict[str, Any]:
        """POSTs to /voice/push-to-talk/text, not /voice/command --
        push-to-talk-text is the route that shares apps/api/routes/
        assistant.py's real SystemAgent/Windows Worker dispatcher (see
        apps/api/routes/voice.py::push_to_talk_text's docstring); /voice/
        command's own standby-mode wake-word-reactivation and speaker-
        profile logic (which `wake_word` fed into) doesn't apply to
        push-to-talk-text, so it's accepted here but no longer sent."""
        del wake_word  # kept in the signature for backward-compat call sites
        payload: Dict[str, Any] = {
            "text": transcript,
            "detected_language": detected_language,
            "session_id": self.session_id,
        }
        if timing_ms:
            payload["timing_ms"] = timing_ms
        return self._call_with_backoff(lambda: self._call_api("POST", "/voice/push-to-talk/text", payload), max_attempts=3)

    # -----------------------------------------------------------------
    # Dependency status reporting
    # -----------------------------------------------------------------

    def _report_dependency_status(self, status_result: Dict[str, Any], brief: bool = False) -> None:
        if not status_result.get("ok"):
            envelope = status_result.get("envelope") or {}
            transport_status = status_result.get("transport_status")
            # A real transport_status like "http_500"/"http_401" is a safe,
            # actionable detail (never leaks response body/stack trace); the
            # envelope message is whatever this codebase's own api_success/
            # raise_api_error helpers put there (also always safe -- no raw
            # tracebacks cross the API boundary), so both are fine to print
            # verbatim. The endpoint name is stated explicitly so "which
            # call failed" is never left for the operator to guess.
            message = envelope.get("message") or "No response body."
            self._log(
                f"GET /voice/status failed: {message} (transport_status={transport_status})"
            )
            self._log(
                "Continuing in dependency-check mode: no confirmed audio_input_worker / "
                "stt_provider / tts_provider / speaker_recognition_provider available "
                "(status unknown -- backend unreachable, auth failed, or a backend error "
                "occurred; text push-to-talk and --simulate-text still work regardless)."
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
        self._log("Dependency status (as reported by the BACKEND process's own env -- see "
                   "'Effective local env' above for what THIS worker process actually uses "
                   "for its own real-listening gate; the two are not guaranteed to match "
                   "unless the backend and this worker share the same environment):")
        for key in (
            "wake_word_engine",
            "audio_input_worker",
            "stt_provider",
            # wake_word_provider (the real *audio* engine, distinct from the
            # always-available text-based wake_word_engine above) was
            # missing from this loop entirely -- an operator could never
            # see its true backend-reported status here, only infer it
            # indirectly from the dependency_required message below.
            "wake_word_provider",
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
        # Only audio_input_worker/stt_provider/wake_word_provider actually
        # block real always-listening audio (see provider_status.py::
        # get_full_status's always_listening_available formula) --
        # tts_provider/speaker_recognition_provider missing must never be
        # reported here as if they stop real listening; they don't.
        blocking = [key for key in missing if key in ("audio_input_worker", "stt_provider", "wake_word_provider")]
        if blocking:
            self._log(
                "Per the backend's own env, real always-listening audio is blocked by: "
                f"{', '.join(blocking)}. Starting in dependency-check mode: text-based "
                "wake-word detection and the API control plane still work regardless. "
                "(This worker's own local providers are what actually decide -- see below.)"
            )
        elif missing:
            self._log(
                f"Non-blocking dependencies missing per the backend's own env: {', '.join(missing)} "
                "-- real always-listening audio can still start; TTS falls back to text-only "
                "responses (speech_output_status=tts_missing) and speaker recognition falls back "
                "to normal typed/voice confirmation for sensitive commands only."
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

    @staticmethod
    def _is_sensitive_transcript(text: str) -> bool:
        """Local, worker-side heuristic only (see SENSITIVE_TRANSCRIPT_
        KEYWORDS) -- never the real authorization boundary. Used solely to
        decide whether a missing speaker-recognition provider should hold
        a command back locally; normal, non-sensitive commands are never
        affected by this check."""
        lowered = f" {text.strip().lower()} "
        return any(keyword in lowered for keyword in SENSITIVE_TRANSCRIPT_KEYWORDS)

    @staticmethod
    def _is_sleep_transcript(text: str) -> bool:
        """Local session-control heuristic only (see SLEEP_PHRASES) --
        only ever consulted while self._active_conversation is True (see
        _capture_transcribe_and_respond), so a plain --simulate-text/
        interactive-loop call is never affected by this check."""
        lowered = " ".join(text.strip().lower().split())
        return any(phrase in lowered for phrase in SLEEP_PHRASES)

    @staticmethod
    def _is_weak_transcript(text: Optional[str], confidence: Optional[float] = None) -> bool:
        """True for an empty/garbled STT result (e.g. "", ".", "..") or a
        result the STT provider itself reports very low confidence for --
        never sent to the assistant dispatcher; the caller instead asks
        the user to repeat themselves. Never applied to typed/simulated
        text (which has no STT confidence to begin with)."""
        if not text:
            return True
        normalized = text.strip().strip(".").strip()
        if len(normalized) < WEAK_TRANSCRIPT_MIN_LENGTH:
            return True
        if confidence is not None and confidence < WEAK_TRANSCRIPT_MIN_CONFIDENCE:
            return True
        return False

    @staticmethod
    def _verbose_errors_enabled() -> bool:
        return os.getenv(VERBOSE_ERRORS_ENV_VAR, "").strip().lower() in ("1", "true", "yes")

    def _handle_no_speech_event(self) -> bool:
        """Called only from within an active_conversation session (see
        _capture_transcribe_and_respond) when a capture produced no real
        speech (STT ok=False or empty text). Counts consecutive no-speech
        events; only speaks out loud once the retry cap is hit (or if
        WILLIAM_VOICE_VERBOSE_ERRORS=1), never on every single silent
        capture -- that repeated chatter was the reported bug. Always
        returns False (nothing was dispatched)."""
        self._consecutive_no_speech += 1
        max_retries = _env_int(NO_SPEECH_MAX_RETRIES_ENV_VAR, DEFAULT_NO_SPEECH_MAX_RETRIES)

        if self._consecutive_no_speech >= max_retries:
            self._consecutive_no_speech = 0
            self._sleep_requested = True
            self._set_state(VoiceWorkerState.SLEEPING, "no-speech retry cap reached")
            self._log(
                f"No speech detected for {max_retries} consecutive attempt(s); "
                "returning to wake-word waiting mode."
            )
            self._speak_and_print("Okay boss, I'll wait for the wake word.")
            return False

        self._log("No speech detected; still listening.")
        if self._verbose_errors_enabled():
            self._speak_and_print("No speech detected; still listening.")
        return False

    def _speak_and_print(self, text: str) -> None:
        """Standalone short spoken/printed message (wake acknowledgement,
        sleep confirmation, weak-transcript reprompt) -- ALWAYS printed
        (visible even without TTS configured -- "speak or print", never
        silent), and additionally spoken via the local TTS provider when
        one is configured. Distinct from _speak_response (which speaks a
        command's final_answer -- that text is already printed separately
        by _print_command_response, so it must never print again here)."""
        if not text:
            return
        print(text)
        self._log(f"[voice] {text}")
        if tts_provider is None:
            return
        status = tts_provider.check_status()
        if not status["configured"]:
            return
        self._set_state(VoiceWorkerState.SPEAKING, "speaking short message with local TTS provider")
        result = tts_provider.speak(text)
        if result["ok"]:
            self._log("Spoken via local TTS provider.")
        else:
            self._log(f"TTS speak failed ({result['error']}); text response only.")

    @staticmethod
    def _prepare_spoken_text(text: str) -> str:
        """The FULL text is always shown in the printed response/dashboard/
        log unchanged -- only what gets SPOKEN through TTS is shortened by
        default (WILLIAM_VOICE_REPLY_STYLE=short, the default; set to
        "full" to speak everything verbatim). WILLIAM_VOICE_MAX_SPOKEN_CHARS
        caps the spoken length (default 240), cut at the last whole word so
        it never trails off mid-word."""
        style = os.getenv(VOICE_REPLY_STYLE_ENV_VAR, DEFAULT_VOICE_REPLY_STYLE).strip().lower()
        if style == "full":
            return text
        max_chars = _env_int(VOICE_MAX_SPOKEN_CHARS_ENV_VAR, DEFAULT_VOICE_MAX_SPOKEN_CHARS)
        if max_chars <= 0 or len(text) <= max_chars:
            return text
        truncated = text[:max_chars].rsplit(" ", 1)[0].rstrip(",;: ")
        return f"{truncated}..." if truncated else text[:max_chars]

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
        timing: Dict[str, float] = {}
        pipeline_started = time.monotonic()

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

        wake_detect_started = time.monotonic()
        detection = self._detect_wake_word(text)
        timing["wake_detect_ms"] = round((time.monotonic() - wake_detect_started) * 1000, 1)
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

        transcript = text.strip()

        if detected:
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

        # No real STT ran on this path -- the "transcript" is the text the
        # caller already gave us (via --simulate-text or the interactive
        # stdin fallback). Kept honest about that in the state detail; the
        # real-audio path (_run_wake_word_admin_loop -> stt_provider.
        # transcribe) logs the real thing instead.
        self._set_state(
            VoiceWorkerState.TRANSCRIBING,
            f"no real STT provider used on this path; using provided text as transcript (length={len(transcript)})",
        )
        timing["stt_ms"] = 0.0  # no real STT ran on this path -- stated honestly, not omitted silently
        return self._send_transcript_and_respond(transcript, timing=timing, pipeline_started=pipeline_started)

    def _send_transcript_and_respond(
        self,
        transcript: str,
        *,
        timing: Optional[Dict[str, float]] = None,
        pipeline_started: Optional[float] = None,
        speaker_embedding: Optional[List[float]] = None,
    ) -> bool:
        """Shared tail of the pipeline: a transcript is already in hand
        (either typed/simulated text, or a real STT transcription from
        _run_wake_word_admin_loop) -- verify speaker for sensitive commands
        only, detect language (honest default), send to the shared
        assistant dispatcher, print the response, and speak it with real
        TTS if configured. Returns True if a command was sent.

        `speaker_embedding` is a real, locally-computed embedding for the
        JUST-CAPTURED audio (see _capture_transcribe_and_respond) --
        None for typed/simulated text (no real audio exists) or when no
        speaker-recognition provider is configured. Only ever consulted
        for a SENSITIVE transcript (see _is_sensitive_transcript); normal
        commands are never gated on it, matching "unknown speaker can use
        low-risk commands." The server-side SecurityAgent/system_worker
        classify_worker_action gate is unaffected either way and still
        independently reviews risky actions regardless of what this
        worker decides locally -- this is defense-in-depth, not a
        replacement for it.

        `timing`/`pipeline_started` carry real, locally-measured wall-clock
        stage durations (see Phase 3 "SPEED / PERFORMANCE" requirements) --
        never estimated, only what this process actually measured. Each
        stage is reported in milliseconds; a stage that didn't run on this
        path (e.g. no real STT for --simulate-text) is set to 0.0 by the
        caller rather than omitted, so the shape is always the same."""
        timing = timing if timing is not None else {}
        pipeline_started = pipeline_started if pipeline_started is not None else time.monotonic()

        if self._is_sensitive_transcript(transcript):
            if speaker_embedding is not None:
                self._set_state(VoiceWorkerState.VERIFYING_SPEAKER, "verifying captured voice against trusted profiles")
                verify_result = self._verify_speaker(speaker_embedding)
                if verify_result["matched"]:
                    self._log(
                        f"Speaker verified: {verify_result['display_name']!r} "
                        f"(role={verify_result['role']}, confidence={verify_result['confidence']}) -- "
                        "sensitive command allowed."
                    )
                else:
                    self._log(
                        f"Command held locally, not sent: {transcript!r} is sensitive/private/risky and "
                        f"the captured voice did not match any trusted profile "
                        f"(confidence={verify_result['confidence']})."
                    )
                    self._speak_and_print("Boss, I cannot verify this voice. Please confirm from dashboard.")
                    return False
            else:
                # No real embedding to check -- either no speaker-
                # recognition provider is configured, or this call has no
                # real audio at all (typed/simulated text). Fail closed:
                # hold the sensitive command back locally rather than
                # execute it hands-free with zero verification.
                self._log("Sensitive voice verification unavailable; normal voice commands still work.")
                self._set_state(
                    VoiceWorkerState.VERIFYING_SPEAKER,
                    "sensitive command held pending speaker verification (none configured)",
                )
                self._log(
                    f"Command held locally, not sent: {transcript!r} looks sensitive/private/risky "
                    "and no speaker-recognition provider is configured to verify who is speaking. "
                    "Use a verified channel (the dashboard, or an admin's typed confirmation) to run "
                    "it, or configure WILLIAM_SPEAKER_RECOGNITION_PROVIDER to allow this hands-free."
                )
                return False
        else:
            self._set_state(
                VoiceWorkerState.VERIFYING_SPEAKER,
                "command is not sensitive -- speaker verification not required",
            )

        detected_language = "en"
        self._set_state(VoiceWorkerState.LANGUAGE_DETECTED, f"detected_language={detected_language} (default; no language-ID provider configured)")

        # Everything measured so far (wake_detect_ms, record_ms/stt_ms if
        # this came from the real-audio path) is sent WITH this same
        # request -- routing_ms/tts_ms/total_ms are only knowable AFTER the
        # request completes, so they cannot be included in this call's own
        # body (sending them would require a second request that could only
        # either re-run the command or add a dedicated timing-report
        # endpoint, neither of which exists yet -- an honest, documented
        # limitation, not silently dropped). Those three are still logged
        # locally below and printed in the command response either way.
        self._set_state(VoiceWorkerState.SENDING_TO_MASTER, f"session_id={self.session_id}")
        routing_started = time.monotonic()
        command_result = self.send_command(transcript, detected_language, None, timing_ms=dict(timing))
        timing["routing_ms"] = round((time.monotonic() - routing_started) * 1000, 1)

        if not command_result["ok"]:
            self._set_state(VoiceWorkerState.ERROR, "voice command request failed")
            self._print_api_failure("POST /voice/push-to-talk/text", command_result)
            return False

        command_envelope = command_result["envelope"]
        command_data = command_envelope.get("data") or {}
        self._print_command_response(command_data)

        tts_started = time.monotonic()
        self._speak_response(command_data)
        timing["tts_ms"] = round((time.monotonic() - tts_started) * 1000, 1)
        timing["total_ms"] = round((time.monotonic() - pipeline_started) * 1000, 1)

        self._log(
            "Timing (ms): " + ", ".join(f"{key}={value}" for key, value in timing.items())
        )
        return True

    def _speak_response(self, command_data: Dict[str, Any]) -> None:
        """Real TTS, spoken client-side (this is the machine with the real
        speaker attached) -- the server's own speech_output_status field
        (based on the BACKEND's WILLIAM_TTS_PROVIDER) is informative only;
        the actual speak-or-not decision is this worker's local provider
        status, since a real distributed deployment's backend and worker
        need not share the same env vars. Never claims spoken=True unless
        tts_provider.speak() really ran the engine. Only the SPOKEN copy is
        shortened (see _prepare_spoken_text) -- _print_command_response
        above already printed the full, untruncated final_answer."""
        text = command_data.get("final_answer") or command_data.get("response_text") or ""
        if not text:
            return
        if tts_provider is None:
            return
        status = tts_provider.check_status()
        if not status["configured"]:
            self._log(f"TTS not configured locally ({status['reason']}); text response only.")
            return
        self._set_state(VoiceWorkerState.SPEAKING, "speaking final_answer with local TTS provider")
        result = tts_provider.speak(self._prepare_spoken_text(text))
        if result["ok"]:
            self._log("Spoken via local TTS provider.")
        else:
            self._log(f"TTS speak failed ({result['error']}); text response only.")

    # -----------------------------------------------------------------
    # Real always-listening audio loop (wake_word_admin / wake_word_trusted_users)
    # -----------------------------------------------------------------

    def _local_provider_readiness(self) -> Dict[str, Any]:
        if provider_status_module is None:
            return {
                "always_listening_available": False,
                "blocking_dependencies": ["audio_input_worker", "stt_provider", "wake_word_provider"],
                "reason": None,
                "full_status": {},
            }
        full_status = provider_status_module.get_full_status()
        # always_listening_blocking_dependencies is the true blocking
        # subset (audio_input_worker/stt_provider/wake_word_provider only
        # -- never tts_provider/speaker_recognition_provider, which don't
        # gate real listening). Falls back to filtering the older, fuller
        # missing_dependencies list for an outdated provider_status module
        # that predates this field, rather than crashing on a KeyError.
        blocking = full_status.get("always_listening_blocking_dependencies")
        if blocking is None:
            blocking = [
                key for key in (full_status.get("missing_dependencies") or [])
                if key in ("audio_input_worker", "stt_provider", "wake_word_provider")
            ]
        return {
            "always_listening_available": bool(full_status.get("always_listening_available")),
            "blocking_dependencies": blocking,
            "reason": None,
            "full_status": full_status,
        }

    def _run_wake_word_admin_loop(self, mode: str) -> None:
        """Real always-listening loop: blocks on real audio wake-word
        detection, then real microphone capture, then real STT, then the
        same dispatcher every other path uses, then real TTS. Falls back
        to the safe heartbeat-only idle loop (never a crash, never a fake
        "listening") if any of audio_input/stt/wake_word isn't actually
        configured on this machine. tts_provider/speaker_recognition_
        provider are deliberately never checked here -- missing TTS means
        text-only responses (speech_output_status=tts_missing, never a
        blocker); missing speaker recognition only holds back sensitive
        commands locally (see _is_sensitive_transcript), never the listen
        loop itself."""
        readiness = self._local_provider_readiness()
        if not readiness["always_listening_available"]:
            blocking = readiness["blocking_dependencies"] or ["audio_input_worker", "stt_provider", "wake_word_provider"]
            self._log(
                f"dependency_required: mode={mode!r} wants real always-listening audio, but "
                f"{', '.join(blocking)} {'is' if len(blocking) == 1 else 'are'} not configured on this "
                "machine. See 'Effective local env' above for what this worker actually read. Keeping "
                "heartbeat alive; text push-to-talk and --simulate-text still work regardless. Run "
                "check_voice_dependencies.ps1 for exact setup guidance."
            )
            self._run_idle_loop()
            return

        display_phrase = self._effective_wake_word_phrase_for_display()
        print(f"Listening for wake word: {display_phrase}")
        self._log(f"Listening for wake word: {display_phrase}")

        self._set_state(
            VoiceWorkerState.WAITING_FOR_WAKE_WORD,
            f"real always-listening audio loop starting (mode={mode}); say the wake word to activate.",
        )
        listener = wake_word_provider.WakeWordListener()  # type: ignore[union-attr]
        try:
            while True:
                self._log(f"Listening for real wake word (poll window {self.config.poll_interval_seconds}s)...")
                self._set_state(VoiceWorkerState.WAITING_FOR_WAKE_WORD, "real audio wake-word detection active")
                wake_detect_started = time.monotonic()
                detection = listener.listen_until_detected(max_seconds=self.config.poll_interval_seconds)
                wake_detect_ms = round((time.monotonic() - wake_detect_started) * 1000, 1)

                heartbeat_result = self.send_heartbeat()
                if self._is_auth_failure(heartbeat_result):
                    self._set_state(VoiceWorkerState.ERROR, "authentication failed (401)")
                    print(self._auth_failure_message())
                    return

                if not detection["detected"]:
                    continue

                self._set_state(
                    VoiceWorkerState.WAKE_DETECTED,
                    f"trigger={detection['trigger']!r} confidence={detection['score']:.2f} (real audio)",
                )
                wake_event_result = self.send_wake_event(confidence=detection["score"])
                if not wake_event_result["ok"]:
                    self._set_state(VoiceWorkerState.ERROR, "failed to register wake event with backend")
                    self._print_api_failure("POST /voice/wake-event", wake_event_result)
                    continue

                self._run_active_conversation_session(wake_detect_ms=wake_detect_ms)
        except KeyboardInterrupt:
            raise
        finally:
            listener.stop()

    def _run_active_conversation_session(self, *, wake_detect_ms: float = 0.0) -> None:
        """The wake word was just detected -- acknowledge it, then stay in
        active_conversation, capturing and dispatching commands WITHOUT
        requiring the wake word again, until a local sleep phrase is
        detected (see _is_sleep_transcript) or
        WILLIAM_VOICE_ACTIVE_SESSION_TIMEOUT_SECONDS of inactivity elapses.
        Always returns control to the caller's outer wake-word loop one way
        or another; only KeyboardInterrupt (a real Ctrl+C) propagates past
        it, for a clean stop."""
        self._active_conversation = True
        self._consecutive_no_speech = 0
        try:
            self._speak_and_print("Yes boss?")
            self._set_state(VoiceWorkerState.ACTIVE_CONVERSATION, "active conversation session started")

            timeout_seconds = _env_float(ACTIVE_SESSION_TIMEOUT_ENV_VAR, DEFAULT_ACTIVE_SESSION_TIMEOUT_SECONDS)
            session_started = time.monotonic()
            first_command = True

            while True:
                if time.monotonic() - session_started >= timeout_seconds:
                    self._log(
                        f"Active conversation session timed out after {timeout_seconds:.0f}s of "
                        "inactivity; returning to wake-word waiting mode."
                    )
                    self._set_state(VoiceWorkerState.SLEEPING, "inactivity timeout")
                    return

                self._set_state(
                    VoiceWorkerState.ACTIVE_CONVERSATION,
                    "listening for the next command (no wake word needed)",
                )
                sent = self._capture_transcribe_and_respond(
                    wake_detect_ms=wake_detect_ms if first_command else 0.0,
                )
                first_command = False

                if self._sleep_requested:
                    return
                if sent:
                    # Real activity resets the inactivity clock; a weak/
                    # failed capture does not -- repeated silence still
                    # counts toward the timeout.
                    session_started = time.monotonic()
        finally:
            self._active_conversation = False

    def _capture_transcribe_and_respond(self, *, wake_detect_ms: float = 0.0) -> bool:
        """Real microphone capture -> real STT -> shared dispatch/response/
        TTS tail. The captured WAV is always deleted immediately after STT
        consumes it unless WILLIAM_VOICE_DEBUG_KEEP_AUDIO/
        WILLIAM_VOICE_SAVE_DEBUG_WAV is set -- "no raw audio stored by
        default" is enforced right here, not just claimed in a comment.
        Returns True only if a command was actually dispatched to the
        assistant dispatcher; see self._sleep_requested (set just before
        returning False) for the caller to distinguish "local sleep phrase"
        from "weak/garbled/failed capture" without changing this method's
        long-standing bool return contract."""
        self._sleep_requested = False
        timing: Dict[str, float] = {"wake_detect_ms": wake_detect_ms}
        pipeline_started = time.monotonic()

        self._set_state(VoiceWorkerState.CAPTURING_COMMAND, "capturing real microphone audio")
        record_started = time.monotonic()
        record_result = audio_input_provider.record_to_tempfile(  # type: ignore[union-attr]
            max_duration_seconds=_env_float(COMMAND_RECORD_SECONDS_ENV_VAR, DEFAULT_COMMAND_RECORD_SECONDS),
            silence_timeout_seconds=_env_float(COMMAND_SILENCE_TIMEOUT_ENV_VAR, DEFAULT_COMMAND_SILENCE_TIMEOUT),
        )
        timing["record_ms"] = round((time.monotonic() - record_started) * 1000, 1)
        if not record_result["ok"]:
            self._set_state(VoiceWorkerState.ERROR, "microphone capture failed")
            self._log(f"Could not capture audio: {record_result['error']}")
            return False

        audio_path = record_result["audio_path"]
        try:
            self._set_state(
                VoiceWorkerState.TRANSCRIBING,
                f"transcribing {record_result['duration_seconds']:.1f}s of real captured audio",
            )
            stt_started = time.monotonic()
            transcribe_result = stt_provider.transcribe(audio_path)  # type: ignore[union-attr]
            timing["stt_ms"] = round((time.monotonic() - stt_started) * 1000, 1)

            # Genuine silence/empty transcript (STT ok=False, e.g. "no
            # speech detected") is common and expected while the user just
            # isn't talking yet -- handled BEFORE the weak-transcript check
            # below, and deliberately never spoken about on every single
            # occurrence (that was the reported bug: a silent room made the
            # worker repeat "could not understand" every ~5s forever).
            if not transcribe_result["ok"] or not (transcribe_result.get("text") or "").strip():
                self._set_state(VoiceWorkerState.TRANSCRIBING, "no speech detected in captured audio")
                if not self._active_conversation:
                    self._log(f"STT could not produce a transcript: {transcribe_result.get('error')}")
                    return False
                return self._handle_no_speech_event()

            self._consecutive_no_speech = 0
            transcript = transcribe_result["text"]
            confidence = transcribe_result.get("confidence")
            self._log(f"Transcript: {transcript!r} (confidence={confidence})")

            if self._is_weak_transcript(transcript, confidence):
                # Real speech was captured (non-empty), just garbled/low-
                # confidence -- distinct from silence above. Always spoken
                # once per occurrence (this is genuinely new information for
                # the user, not repeated noise), no retry cap.
                self._log(f"Weak/garbled transcript rejected locally, not sent: {transcript!r}")
                if self._active_conversation:
                    self._speak_and_print("Boss, I could not understand. Please repeat.")
                return False

            if self._active_conversation and self._is_sleep_transcript(transcript):
                self._sleep_requested = True
                self._set_state(VoiceWorkerState.SLEEPING, f"sleep phrase detected: {transcript!r}")
                self._log(f"Sleep phrase detected ({transcript!r}); not sending to the assistant dispatcher.")
                self._speak_and_print("Okay boss, I'll wait for the wake word.")
                return False

            speaker_embedding = self._compute_speaker_embedding_for_sensitive_command(transcript, audio_path)
            return self._send_transcript_and_respond(
                transcript, timing=timing, pipeline_started=pipeline_started, speaker_embedding=speaker_embedding,
            )
        finally:
            keep_audio = (
                os.getenv(DEBUG_KEEP_AUDIO_ENV_VAR, "").strip().lower() in ("1", "true", "yes")
                or os.getenv(SAVE_DEBUG_WAV_ENV_VAR, "").strip().lower() in ("1", "true", "yes")
            )
            if keep_audio:
                self._log(f"Debug WAV retention is set -- keeping captured audio at {audio_path}")
            else:
                try:
                    os.remove(audio_path)
                except OSError as exc:
                    logger.warning("Could not delete temp audio file %s: %s", audio_path, exc)

    def _compute_speaker_embedding_for_sensitive_command(self, transcript: str, audio_path: str) -> Optional[List[float]]:
        """Only ever computed for a SENSITIVE transcript (never wasted CPU
        on normal commands, which don't need speaker verification) and
        only while the local speaker-embedding provider is genuinely
        configured -- returns None otherwise, which _send_transcript_and_
        respond treats as "no real embedding to check" (fail closed on
        sensitive commands, per its own docstring). Reads `audio_path`
        BEFORE _capture_transcribe_and_respond's own finally block deletes
        it -- this is the only real, uncorrupted copy of what was said."""
        if not self._is_sensitive_transcript(transcript):
            return None
        if speaker_embedding_provider is None:
            return None
        status = speaker_embedding_provider.check_status()
        if not status["configured"]:
            return None

        result = speaker_embedding_provider.compute_embedding(audio_path)
        if not result["ok"]:
            self._log(f"Could not compute a speaker embedding for verification: {result['error']}")
            return None
        return result["embedding"]

    # -----------------------------------------------------------------
    # Local diagnostic commands (--list-audio-devices / --test-mic /
    # --test-stt / --test-tts / --test-wake-word) -- no backend auth
    # required, no fabricated results.
    # -----------------------------------------------------------------

    def list_audio_devices(self) -> int:
        if audio_input_provider is None:
            print("dependency_required: apps.worker_nodes.voice.providers.audio_input is unavailable.")
            return 1
        status = audio_input_provider.check_status()
        devices = status["devices"]
        if not devices:
            print(f"No input devices found. {status.get('install_guidance') or ''}")
            return 1
        print(f"Found {len(devices)} real input device(s):")
        for device in devices:
            marker = " (default)" if device.get("is_default") else ""
            print(f"  [{device['index']}] {device['name']}{marker} -- {device['max_input_channels']}ch @ {device['default_samplerate']}Hz")
        if not status["available"]:
            print(f"\nNote: {status['reason']}. {status.get('install_guidance') or ''}")
        return 0

    def test_mic(self) -> int:
        if audio_input_provider is None:
            print("dependency_required: apps.worker_nodes.voice.providers.audio_input is unavailable.")
            return 1
        debug = _voice_debug_enabled()
        if debug:
            print(f"Selected microphone device: {audio_input_provider.selected_device_label()}")
        print("Recording a few real seconds from the microphone (speak now)...")
        keep_wav = os.getenv(SAVE_DEBUG_WAV_ENV_VAR, "").strip().lower() in ("1", "true", "yes") or os.getenv(
            DEBUG_KEEP_AUDIO_ENV_VAR, ""
        ).strip().lower() in ("1", "true", "yes")
        result = audio_input_provider.record_to_tempfile(max_duration_seconds=6.0)
        if not result["ok"]:
            print(f"Microphone test failed: {result['error']}")
            return 1
        print(f"Captured {result['duration_seconds']:.1f}s of real audio -> {result['audio_path']}")
        if debug:
            print(f"Peak input level (RMS): {result.get('peak_rms', 0.0)}")
        if keep_wav:
            print(f"Debug WAV kept at: {result['audio_path']}")
            return 0
        try:
            os.remove(result["audio_path"])
            print("Temp audio file deleted (no raw audio stored by default).")
        except OSError as exc:
            print(f"Could not delete temp audio file: {exc}")
        return 0

    def test_stt(self) -> int:
        if stt_provider is None or audio_input_provider is None:
            print("dependency_required: STT/audio provider modules are unavailable.")
            return 1
        stt_status = stt_provider.check_status()
        if not stt_status["configured"]:
            print(f"dependency_required: {stt_status['reason']}. {stt_status.get('install_guidance') or ''}")
            return 1
        debug = _voice_debug_enabled()
        if debug:
            print(f"Selected microphone device: {audio_input_provider.selected_device_label()}")
            print(f"WILLIAM_STT_MODEL={os.getenv('WILLIAM_STT_MODEL', 'base')!r} WILLIAM_STT_LANGUAGE={os.getenv('WILLIAM_STT_LANGUAGE', '') or '(auto-detect)'!r}")
        print("Recording a few real seconds from the microphone (speak now)...")
        keep_wav = os.getenv(SAVE_DEBUG_WAV_ENV_VAR, "").strip().lower() in ("1", "true", "yes") or os.getenv(
            DEBUG_KEEP_AUDIO_ENV_VAR, ""
        ).strip().lower() in ("1", "true", "yes")
        record_result = audio_input_provider.record_to_tempfile(max_duration_seconds=8.0)
        if not record_result["ok"]:
            print(f"Microphone capture failed: {record_result['error']}")
            return 1
        if debug:
            print(f"Recording duration: {record_result['duration_seconds']:.1f}s")
            print(f"Peak input level (RMS): {record_result.get('peak_rms', 0.0)}")
        try:
            print("Transcribing real captured audio...")
            transcribe_result = stt_provider.transcribe(record_result["audio_path"])
            if not transcribe_result["ok"]:
                print(f"Transcription failed: {transcribe_result['error']}")
                return 1
            print(f"Real transcript: {transcribe_result['text']!r} (confidence={transcribe_result.get('confidence')})")
            if keep_wav:
                print(f"Debug WAV kept at: {record_result['audio_path']}")
            return 0
        finally:
            if not keep_wav:
                try:
                    os.remove(record_result["audio_path"])
                except OSError:
                    pass

    def test_tts(self, text: Optional[str] = None) -> int:
        spoken_text = text or "This is a test of William's text to speech."
        if tts_provider is None:
            print("dependency_required: apps.worker_nodes.voice.providers.tts is unavailable.")
            return 1
        status = tts_provider.check_status()
        if not status["configured"]:
            print(f"tts_missing: {status['reason']}. {status.get('install_guidance') or ''}")
            print(f"Text response only: {spoken_text}")
            return 0
        if _voice_debug_enabled():
            voice_selector = os.getenv("WILLIAM_TTS_VOICE", "").strip() or "(engine default)"
            print(
                f"TTS provider ready. WILLIAM_TTS_RATE={os.getenv('WILLIAM_TTS_RATE', '175')} "
                f"WILLIAM_TTS_VOLUME={os.getenv('WILLIAM_TTS_VOLUME', '1.0')} WILLIAM_TTS_VOICE={voice_selector!r}"
            )
            try:
                voices = tts_provider.list_voices()
                print(f"Installed voices ({len(voices)}): {[v.get('name') for v in voices]}")
            except Exception as exc:  # pragma: no cover - defensive only
                print(f"Could not list installed voices: {exc}")
        print(f"Speaking through the configured TTS provider: {spoken_text!r}")
        result = tts_provider.speak(spoken_text)
        if result["ok"]:
            print("Spoken successfully via local TTS provider.")
            return 0
        print(f"TTS speak failed: {result['error']}")
        return 1

    def test_wake_word(self) -> int:
        if wake_word_provider is None:
            print("dependency_required: apps.worker_nodes.voice.providers.wake_word is unavailable.")
            return 1
        status = wake_word_provider.check_status()
        if not status["configured"]:
            print(f"dependency_required: {status['reason']}. {status.get('install_guidance') or ''}")
            return 1
        try:
            listener = wake_word_provider.WakeWordListener()
        except RuntimeError as exc:
            print(f"dependency_required: {exc}")
            return 1
        wake_word_phrase = os.getenv("WILLIAM_WAKE_WORD_PHRASE", DEFAULT_WAKE_WORD)
        print(f"Configured wake word: {wake_word_phrase!r} -- real audio model in use: {listener.active_model_name!r}")
        print(f"Listening for real audio wake word ({listener.active_model_name!r}) for 10 seconds -- say it now...")
        result = listener.listen_until_detected(max_seconds=10.0)
        listener.stop()
        if result["detected"]:
            print(f"Wake word detected! trigger={result['trigger']!r} score={result['score']:.2f}")
            return 0
        print("Wake word not detected within 10 seconds.")
        return 1

    # -----------------------------------------------------------------
    # Trusted Voice Profiles -- local enrollment (--enroll-voice /
    # --list-voice-profiles / --delete-voice-profile). Unlike the
    # diagnostics above, these DO require real backend auth (an admin/
    # owner credential via --token/--device-token) since they create/
    # revoke real, workspace-scoped rows.
    # -----------------------------------------------------------------

    def enroll_voice(self, role: str) -> int:
        """Enrollment flow: create the profile, speak
        WILLIAM_VOICE_ENROLLMENT_PHRASES phrases (default 3), compute a
        real local embedding for each, average them into one vector, and
        upload ONLY that vector (never raw audio) to the backend for
        encrypted storage. Every captured WAV is deleted immediately after
        its embedding is computed, unless WILLIAM_VOICE_SAVE_DEBUG_WAV/
        WILLIAM_VOICE_DEBUG_KEEP_AUDIO is set."""
        if not self.config.token and not self.config.device_token:
            print("Enrollment requires --token or --device-token (an admin/owner credential).")
            return 1
        if speaker_embedding_provider is None:
            print("dependency_required: apps.worker_nodes.voice.providers.speaker_embedding is unavailable.")
            return 1
        embedding_status = speaker_embedding_provider.check_status()
        if not embedding_status["configured"]:
            print(f"dependency_required: {embedding_status['reason']}. {embedding_status.get('install_guidance') or ''}")
            return 1
        if audio_input_provider is None:
            print("dependency_required: apps.worker_nodes.voice.providers.audio_input is unavailable.")
            return 1

        display_name = f"{role.replace('_', ' ').title()} ({self.session_id[:8]})"
        create_result = self._call_with_backoff(
            lambda: self._call_api(
                "POST", "/voice/profiles",
                {"display_name": display_name, "role": role, "can_use_voice": True, "can_use_wake_word": True},
            ),
            max_attempts=3,
        )
        if not create_result["ok"]:
            self._print_api_failure("POST /voice/profiles", create_result)
            return 1

        profile = (create_result["envelope"].get("data") or {}).get("profile") or {}
        profile_id = profile.get("id")
        if not profile_id:
            print("Could not create voice profile: no profile id returned.")
            return 1
        print(f"Created voice profile {profile_id!r} (role={role!r}). Starting enrollment...\n")

        phrase_count = max(1, min(_env_int(ENROLLMENT_PHRASES_ENV_VAR, DEFAULT_ENROLLMENT_PHRASES), len(ENROLLMENT_PHRASES)))
        phrases = ENROLLMENT_PHRASES[:phrase_count]
        keep_wav = (
            os.getenv(SAVE_DEBUG_WAV_ENV_VAR, "").strip().lower() in ("1", "true", "yes")
            or os.getenv(DEBUG_KEEP_AUDIO_ENV_VAR, "").strip().lower() in ("1", "true", "yes")
        )

        embeddings: List[List[float]] = []
        for index, phrase in enumerate(phrases, start=1):
            print(f"Phrase {index}/{len(phrases)} -- please say: {phrase!r}")
            print("Recording (speak now)...")
            record_result = audio_input_provider.record_to_tempfile(max_duration_seconds=6.0)
            if not record_result["ok"]:
                print(f"Microphone capture failed: {record_result['error']}")
                return 1
            audio_path = record_result["audio_path"]
            try:
                embed_result = speaker_embedding_provider.compute_embedding(audio_path)
                if not embed_result["ok"]:
                    print(f"Could not compute a voice fingerprint for this phrase: {embed_result['error']}")
                    return 1
                embeddings.append(embed_result["embedding"])
                print(f"Captured {record_result['duration_seconds']:.1f}s -- fingerprint computed.\n")
            finally:
                if keep_wav:
                    print(f"Debug WAV kept at: {audio_path}")
                else:
                    try:
                        os.remove(audio_path)
                    except OSError as exc:
                        logger.warning("Could not delete temp audio file %s: %s", audio_path, exc)

        # Average the per-phrase embeddings into one enrollment vector,
        # re-normalized -- real math over real captured audio, never a
        # fabricated/random vector.
        dims = len(embeddings[0])
        averaged = [sum(vec[i] for vec in embeddings) / len(embeddings) for i in range(dims)]
        norm = sum(v * v for v in averaged) ** 0.5
        if norm > 0:
            averaged = [v / norm for v in averaged]

        upload_result = self._call_with_backoff(
            lambda: self._call_api(
                "POST", f"/voice/profiles/{profile_id}/embedding",
                {"embedding": averaged, "provider": speaker_embedding_provider.LOCAL_PROVIDER_NAME},
            ),
            max_attempts=3,
        )
        if not upload_result["ok"]:
            self._print_api_failure(f"POST /voice/profiles/{profile_id}/embedding", upload_result)
            return 1

        print(f"Voice enrolled successfully for profile {profile_id!r} (role={role!r}).")
        print("Raw audio was never uploaded -- only the local voice fingerprint, encrypted at rest.")
        return 0

    def list_voice_profiles(self) -> int:
        result = self._call_with_backoff(lambda: self._call_api("GET", "/voice/profiles"), max_attempts=3)
        if not result["ok"]:
            self._print_api_failure("GET /voice/profiles", result)
            return 1

        profiles = (result["envelope"].get("data") or {}).get("profiles") or []
        if not profiles:
            print("No voice profiles enrolled yet.")
            return 0

        print(f"Found {len(profiles)} voice profile(s):")
        for profile in profiles:
            embedding_marker = "embedding enrolled" if profile.get("has_voice_embedding") else "no embedding yet"
            print(
                f"  [{profile.get('id')}] {profile.get('display_name')} -- role={profile.get('role')} "
                f"status={profile.get('status')} ({embedding_marker}) "
                f"last_verified_at={profile.get('last_verified_at')}"
            )
        return 0

    def delete_voice_profile(self, profile_id: str) -> int:
        result = self._call_with_backoff(
            lambda: self._call_api("DELETE", f"/voice/profiles/{profile_id}"), max_attempts=3,
        )
        if not result["ok"]:
            self._print_api_failure(f"DELETE /voice/profiles/{profile_id}", result)
            return 1
        print(f"Voice profile {profile_id!r} revoked.")
        return 0

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

        envelope = status_result.get("envelope") or {}
        settings = (envelope.get("data") or {}).get("settings") or {}
        mode = settings.get("mode", VOICE_MODE_DISABLED)

        try:
            if status_result.get("ok") and mode in ALWAYS_LISTENING_MODES:
                # The workspace's real mode is wake_word_admin/
                # wake_word_trusted_users -- start the real audio loop if
                # this machine's providers support it, honestly falling
                # back to heartbeat-only otherwise (see
                # _run_wake_word_admin_loop's own dependency_required
                # check). Takes priority over the TTY check below: a real
                # always-listening mode should listen for real audio, not
                # fall into the typed-text interactive fallback, even when
                # run from an interactive terminal.
                self._run_wake_word_admin_loop(mode)
            elif sys.stdin.isatty():
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
        self._print_local_provider_env()

    @staticmethod
    def _print_local_provider_env() -> None:
        """Debug startup output: the EXACT effective env values THIS
        worker process reads for its own real-listening gate (audio_input/
        stt/tts/wake_word providers + wake word phrase) -- printed as-is
        from os.getenv, never guessed or fabricated. This is deliberately
        distinct from GET /voice/status's dependency report further below,
        which reflects the BACKEND process's own env and may run on a
        different machine with different values; this worker's own
        real-listening decision is always based on what's printed here,
        not on the backend's view."""
        logger.info("Effective local env (this worker process):")
        for name in LOCAL_PROVIDER_ENV_VARS:
            value = os.getenv(name, "")
            logger.info("    %s = %r%s", name, value, "" if value else "  [not set]")


# ---------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------

# argparse sentinel: distinguishes "--test-tts given with no value" (speak
# the default sentence) from "--test-tts never given at all" (None,
# nargs='?' + const so a bare flag doesn't collide with an empty-string
# custom text, which would be falsy and get skipped by the diagnostic-flag
# dispatch below).
_TEST_TTS_FLAG_ONLY_SENTINEL = "\x00__test_tts_default__\x00"


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if not value:
        return default
    try:
        return float(value)
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
    parser.add_argument(
        "--list-audio-devices",
        action="store_true",
        help="Print real input devices (sounddevice) and exit. No backend auth required.",
    )
    parser.add_argument(
        "--test-mic",
        action="store_true",
        help="Record a few real seconds from the microphone, report duration, delete the file, and exit. No backend auth required.",
    )
    parser.add_argument(
        "--test-stt",
        action="store_true",
        help="Record + transcribe with the configured STT provider and print the real text. No backend auth required.",
    )
    parser.add_argument(
        "--test-tts",
        nargs="?",
        const=_TEST_TTS_FLAG_ONLY_SENTINEL,
        default=None,
        metavar="TEXT",
        help="Speak a test sentence (the default one, or TEXT if given) with the configured TTS "
        "provider (or report tts_missing). No backend auth required.",
    )
    parser.add_argument(
        "--test-wake-word",
        action="store_true",
        help="Listen for the real audio wake word for a few seconds and report detected/not detected. No backend auth required.",
    )
    parser.add_argument(
        "--enroll-voice",
        default=None,
        metavar="ROLE",
        help="Enroll a Trusted Voice Profile with the given role (owner/admin/trusted_friend/"
        "trusted_family/trusted_team_member/guest) by speaking a few short phrases. "
        "Requires --token/--device-token (admin/owner credential).",
    )
    parser.add_argument(
        "--list-voice-profiles",
        action="store_true",
        help="List this workspace's Trusted Voice Profiles (never prints an embedding). Requires auth.",
    )
    parser.add_argument(
        "--delete-voice-profile",
        default=None,
        metavar="PROFILE_ID",
        help="Revoke a Trusted Voice Profile by id. Requires --token/--device-token (admin/owner credential).",
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
            # utf-8-sig transparently strips a leading BOM if present (and
            # behaves exactly like utf-8 if not) -- scripts/windows/
            # install_voice_worker.ps1 writes this file via PowerShell's
            # `ConvertTo-Json | Set-Content -Encoding UTF8`, which (Windows
            # PowerShell 5.1) always emits a UTF-8 BOM. Plain "utf-8" here
            # raised "Unexpected UTF-8 BOM" and crashed the worker on every
            # installed-mode startup -- found via a real install+run, not
            # a hypothetical.
            with open(args.config, "r", encoding="utf-8-sig") as config_file:
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


# test_tts is dispatched separately (below) since it now carries an
# optional custom-text value rather than being a plain boolean flag.
_LOCAL_DIAGNOSTIC_FLAGS = ("list_audio_devices", "test_mic", "test_stt", "test_wake_word")


def main(argv: Optional[list] = None) -> int:
    args = parse_args(argv)
    config = build_config(args)
    worker = VoiceWorker(config)
    try:
        # Local diagnostics never touch the backend -- no token/device-token
        # is required to run them, matching the "no auth needed" examples
        # in this module's own docstring. Mutually exclusive by construction
        # (only one can meaningfully run per invocation); the first one set
        # wins if more than one flag is passed.
        if args.test_tts is not None:
            custom_text = None if args.test_tts == _TEST_TTS_FLAG_ONLY_SENTINEL else args.test_tts
            return worker.test_tts(text=custom_text)

        # Trusted Voice Profile commands DO require real backend auth
        # (create/list/revoke real, workspace-scoped rows) -- dispatched
        # before the no-auth diagnostics loop below.
        if args.enroll_voice is not None:
            return worker.enroll_voice(args.enroll_voice)
        if args.list_voice_profiles:
            return worker.list_voice_profiles()
        if args.delete_voice_profile is not None:
            return worker.delete_voice_profile(args.delete_voice_profile)

        for flag_name in _LOCAL_DIAGNOSTIC_FLAGS:
            if getattr(args, flag_name):
                return getattr(worker, flag_name)()

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
