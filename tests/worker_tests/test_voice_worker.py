"""
tests/worker_tests/test_voice_worker.py

Phase 7 coverage (item 5): apps/worker_nodes/voice/voice_worker.py's
--simulate-text pipeline requires neither a real STT nor a real TTS
provider to run -- it uses typed text as the "transcript" and only ever
prints the resulting speech_output_status honestly, never fabricating
spoken output. Also confirms the worker now calls the real, shared-
dispatcher endpoint (/voice/push-to-talk/text), not the old /voice/command
bypass.

No real HTTP/network calls: VoiceWorker._client._request is monkeypatched
directly (the same transport method apps/worker_nodes/common/
worker_client.py::WorkerClient._request would otherwise perform over the
network), matching this worker's own "compose WorkerClient's transport,
don't rebuild it" design -- there is no STT/TTS/microphone code anywhere
in this file to accidentally exercise, by construction.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Tuple

import pytest

from apps.worker_nodes.common.worker_client import WorkerResponse
from apps.worker_nodes.voice import voice_worker as voice_worker_module
from apps.worker_nodes.voice.voice_worker import VoiceWorker, VoiceWorkerConfig


def _envelope(*, success: bool = True, data: Dict[str, Any] | None = None) -> Dict[str, Any]:
    return {
        "success": success,
        "message": "ok",
        "data": data or {},
        "error": None,
        "metadata": {},
    }


class FakeTransport:
    """Records every call and returns a scripted WorkerResponse per path,
    standing in for VoiceWorker._client._request without any real network
    I/O, STT, or TTS involved."""

    def __init__(self, responses: Dict[str, Dict[str, Any]]) -> None:
        self.responses = responses
        self.calls: List[Tuple[str, str, Dict[str, Any]]] = []

    def __call__(self, method: str, path: str, payload: Dict[str, Any] | None = None) -> WorkerResponse:
        self.calls.append((method, path, payload or {}))
        envelope = self.responses.get(path, _envelope(success=False))
        return WorkerResponse(ok=True, status="http_200", message="ok", data=envelope)


def _build_worker(simulate_text: str, *, mode: str = "push_to_talk") -> Tuple[VoiceWorker, FakeTransport]:
    config = VoiceWorkerConfig(
        api_base_url="http://fake-backend.invalid/api/v1",
        token="fake-jwt-token",
        simulate_text=simulate_text,
    )
    worker = VoiceWorker(config)

    transport = FakeTransport(
        {
            "/voice/status": _envelope(
                data={
                    "settings": {
                        "mode": mode,
                        "dependency_status": {
                            "wake_word_engine": "available",
                            "wake_word_provider": "external_dependency_required",
                            "audio_input_worker": "external_dependency_required",
                            "stt_provider": "external_dependency_required",
                            "tts_provider": "external_dependency_required",
                            "speaker_recognition_provider": "external_dependency_required",
                        },
                    }
                }
            ),
            "/voice/wake-event": _envelope(data={"should_listen": True, "mode": mode}),
            "/voice/push-to-talk/text": _envelope(
                data={
                    "final_answer": "Done boss, I sent the command to your Windows device. notepad is opening.",
                    "status": "completed",
                    "route": ["system"],
                    "worker_task_id": "wtask_fake123",
                    "speech_output_status": "tts_missing",
                }
            ),
        }
    )
    worker._client._request = transport  # type: ignore[method-assign]
    return worker, transport


class TestSimulateTextRequiresNoSttOrTts:
    def test_simulate_text_runs_without_stt_or_tts(self) -> None:
        worker, transport = _build_worker("William open Notepad")

        exit_code = worker.run()

        assert exit_code == 0
        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/status" in called_paths
        assert "/voice/push-to-talk/text" in called_paths
        # The old bypass endpoint must never be called.
        assert "/voice/command" not in called_paths

    def test_simulate_text_sends_text_field_not_only_transcript(self) -> None:
        worker, transport = _build_worker("William open Chrome")
        worker.run()

        push_to_talk_calls = [
            payload for method, path, payload in transport.calls if path == "/voice/push-to-talk/text"
        ]
        assert len(push_to_talk_calls) == 1
        # The detected wake word ("William") is stripped locally before
        # sending -- this is existing, correct behavior (_strip_wake_word),
        # not something this refactor changed. What matters here is the
        # payload key is "text" (push-to-talk-text's field), not
        # "transcript" (the old /voice/command field).
        assert "text" in push_to_talk_calls[0]
        assert "transcript" not in push_to_talk_calls[0]
        assert push_to_talk_calls[0]["text"] == "open Chrome"

    def test_simulate_text_prints_final_answer_and_speech_status(self, capsys) -> None:
        worker, _ = _build_worker("William open Notepad")
        worker.run()

        captured = capsys.readouterr()
        assert "Done boss, I sent the command to your Windows device. notepad is opening." in captured.out
        assert "speech_output_status" in captured.out
        assert "tts_missing" in captured.out

    def test_disabled_mode_never_sends_command(self) -> None:
        worker, transport = _build_worker("William open Notepad", mode="disabled")
        worker.run()

        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" not in called_paths


def _build_worker_with_ignore_mode_for_dev(simulate_text: str, *, mode: str = "disabled") -> Tuple[VoiceWorker, FakeTransport]:
    config = VoiceWorkerConfig(
        api_base_url="http://fake-backend.invalid/api/v1",
        token="fake-jwt-token",
        simulate_text=simulate_text,
        ignore_mode_for_dev=True,
    )
    worker = VoiceWorker(config)

    transport = FakeTransport(
        {
            "/voice/status": _envelope(
                data={
                    "settings": {
                        "mode": mode,
                        "dependency_status": {
                            "wake_word_engine": {"status": "available", "install_guidance": None},
                            "stt_provider": {"status": "external_dependency_required", "install_guidance": "pip install faster-whisper"},
                            "tts_provider": {"status": "external_dependency_required", "install_guidance": None},
                        },
                    }
                }
            ),
            "/voice/wake-event": _envelope(data={"should_listen": True, "mode": mode}),
            "/voice/push-to-talk/text": _envelope(
                data={
                    "final_answer": "Done boss, notepad is opening.",
                    "status": "completed",
                    "route": ["system"],
                    "worker_task_id": "wtask_fake456",
                    "speech_output_status": "tts_missing",
                }
            ),
        }
    )
    worker._client._request = transport  # type: ignore[method-assign]
    return worker, transport


class TestIgnoreModeForDev:
    def test_ignore_mode_for_dev_bypasses_local_disabled_gate(self) -> None:
        worker, transport = _build_worker_with_ignore_mode_for_dev("William open Notepad", mode="disabled")
        exit_code = worker.run()

        assert exit_code == 0
        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" in called_paths

    def test_without_flag_disabled_mode_still_refuses(self) -> None:
        # Sanity check that the flag, not some other change, is what makes
        # the difference -- the same disabled-mode workspace with the flag
        # OFF must still refuse, exactly like TestSimulateTextRequiresNoSttOrTts
        # ::test_disabled_mode_never_sends_command already covers.
        config = VoiceWorkerConfig(
            api_base_url="http://fake-backend.invalid/api/v1",
            token="fake-jwt-token",
            simulate_text="William open Notepad",
            ignore_mode_for_dev=False,
        )
        worker = VoiceWorker(config)
        transport = FakeTransport(
            {
                "/voice/status": _envelope(data={"settings": {"mode": "disabled", "dependency_status": {}}}),
            }
        )
        worker._client._request = transport  # type: ignore[method-assign]
        worker.run()

        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" not in called_paths

    def test_ignore_mode_for_dev_does_not_affect_gated_wake_word_modes(self) -> None:
        """--ignore-mode-for-dev only bypasses the DISABLED-mode gate -- a
        wake-word-gated mode (e.g. wake_word_admin) with no wake word
        detected in the input text must still refuse, flag or not."""
        worker, transport = _build_worker_with_ignore_mode_for_dev(
            "open Notepad", mode="wake_word_admin"  # no "William" trigger in the text
        )
        worker.run()

        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" not in called_paths


class Fake401Transport:
    """Simulates a real HTTP 401 response -- WorkerResponse.status is
    "http_401" for any real HTTP response (see apps/worker_nodes/common/
    worker_client.py), which is what voice_worker.py's _is_auth_failure
    checks for. No real network/JWT involved."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, str, Dict[str, Any]]] = []

    def __call__(self, method: str, path: str, payload: Dict[str, Any] | None = None) -> WorkerResponse:
        self.calls.append((method, path, payload or {}))
        return WorkerResponse(
            ok=False,
            status="http_401",
            message="Unauthorized",
            data={
                "detail": {
                    "success": False,
                    "message": "Bearer token required.",
                    "data": {},
                    "error": {"code": "ACCESS_TOKEN_REQUIRED", "details": None},
                    "metadata": {},
                }
            },
        )


class TestAuthFailureCleanStop:
    """Phase 8 coverage (worker side): a real 401 must produce the exact
    credential-specific message and a clean, non-crashing stop -- never a
    raw traceback, never an infinite retry loop against a dead credential."""

    def test_jwt_mode_prints_expired_message_and_stops_cleanly(self, capsys) -> None:
        config = VoiceWorkerConfig(
            api_base_url="http://fake-backend.invalid/api/v1",
            token="expired-jwt-token",
            simulate_text="William open Notepad",
        )
        worker = VoiceWorker(config)
        transport = Fake401Transport()
        worker._client._request = transport  # type: ignore[method-assign]

        exit_code = worker.run()

        captured = capsys.readouterr()
        assert exit_code == 1
        assert "JWT expired. Use installed device-token worker or login again." in captured.out
        assert "Traceback" not in captured.out
        # Exactly one status call -- no retry storm against a dead credential.
        assert len([c for c in transport.calls if c[1] == "/voice/status"]) == 1

    def test_device_token_mode_prints_revoked_message_and_stops_cleanly(self, capsys) -> None:
        config = VoiceWorkerConfig(
            api_base_url="http://fake-backend.invalid/api/v1",
            device_token="revoked-device-token",
            simulate_text="William open Notepad",
        )
        worker = VoiceWorker(config)
        transport = Fake401Transport()
        worker._client._request = transport  # type: ignore[method-assign]

        exit_code = worker.run()

        captured = capsys.readouterr()
        assert exit_code == 1
        assert "Device token revoked. Re-enable worker from dashboard." in captured.out
        assert "Traceback" not in captured.out


class TestLocalDiagnosticsHandleMissingProvidersCleanly:
    """Phase 9 coverage (items 3, 4): --test-tts / --list-audio-devices
    must never crash or fabricate a result when the underlying provider
    module is unavailable -- they print dependency_required and exit 1."""

    def test_test_tts_handles_missing_provider_module_cleanly(self, monkeypatch, capsys) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)
        monkeypatch.setattr(voice_worker_module, "tts_provider", None)

        exit_code = worker.test_tts()

        captured = capsys.readouterr()
        assert exit_code == 1
        assert "dependency_required" in captured.out
        assert "Traceback" not in captured.out

    def test_list_audio_devices_handles_missing_module_cleanly(self, monkeypatch, capsys) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)
        monkeypatch.setattr(voice_worker_module, "audio_input_provider", None)

        exit_code = worker.list_audio_devices()

        captured = capsys.readouterr()
        assert exit_code == 1
        assert "dependency_required" in captured.out
        assert "Traceback" not in captured.out


class TestWakeWordAdminDependencyRequired:
    """Phase 9 coverage (item 5): wake_word_admin mode must fall back to
    the safe heartbeat-only idle loop -- never a fake "listening" state --
    when audio_input/stt/wake_word aren't all configured on this machine."""

    def test_falls_back_to_idle_loop_when_providers_missing(self, monkeypatch, caplog) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)

        class _FakeProviderStatusModule:
            @staticmethod
            def get_full_status() -> Dict[str, Any]:
                return {
                    "always_listening_available": False,
                    "missing_dependencies": ["audio_input_worker", "stt_provider", "wake_word_provider"],
                }

        monkeypatch.setattr(voice_worker_module, "provider_status_module", _FakeProviderStatusModule())

        idle_loop_calls: List[bool] = []
        monkeypatch.setattr(worker, "_run_idle_loop", lambda: idle_loop_calls.append(True))

        import logging

        with caplog.at_level(logging.INFO):
            worker._run_wake_word_admin_loop("wake_word_admin")

        assert idle_loop_calls == [True]
        assert any("dependency_required" in record.message for record in caplog.records)

    def test_missing_speaker_recognition_alone_does_not_block_listening(self, monkeypatch) -> None:
        """Wake-word-approval Phase 4 (item 7): speaker_recognition_provider
        is optional (sensitive commands fall back to typed confirmation/PIN
        without it, per apps/worker_nodes/voice/providers/provider_status.py)
        -- always_listening_available is computed from audio/stt/wake_word
        only, so a missing speaker_recognition_provider alone must never
        keep the worker out of the real listening loop."""
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)

        class _FakeProviderStatusModule:
            @staticmethod
            def get_full_status() -> Dict[str, Any]:
                return {
                    # Real provider_status.py behavior: speaker recognition
                    # missing shows up in missing_dependencies for display,
                    # but never flips always_listening_available to False.
                    "always_listening_available": True,
                    "missing_dependencies": ["speaker_recognition_provider"],
                }

        monkeypatch.setattr(voice_worker_module, "provider_status_module", _FakeProviderStatusModule())

        idle_loop_calls: List[bool] = []
        monkeypatch.setattr(worker, "_run_idle_loop", lambda: idle_loop_calls.append(True))

        class _FakeListener:
            def listen_until_detected(self, max_seconds: float | None = None) -> Dict[str, Any]:
                raise KeyboardInterrupt

            def stop(self) -> None:
                pass

        class _FakeWakeWordProvider:
            @staticmethod
            def WakeWordListener() -> _FakeListener:  # noqa: N802
                return _FakeListener()

        monkeypatch.setattr(voice_worker_module, "wake_word_provider", _FakeWakeWordProvider())

        try:
            worker._run_wake_word_admin_loop("wake_word_admin")
        except KeyboardInterrupt:
            pass

        # Never fell back to the idle/heartbeat-only loop -- it reached the
        # real listen_until_detected call instead (which raised to stop the
        # test cleanly).
        assert idle_loop_calls == []


class TestNoRawAudioStoredByDefault:
    """Phase 9 coverage (item 9): a real captured WAV must be deleted
    immediately after STT consumes it, unless WILLIAM_VOICE_DEBUG_KEEP_AUDIO
    is explicitly set."""

    def test_captured_audio_deleted_after_transcription(self, tmp_path, monkeypatch) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)

        fake_audio_path = tmp_path / "captured.wav"
        fake_audio_path.write_bytes(b"RIFF....WAVEfmt ")
        assert fake_audio_path.exists()

        class _FakeAudioInput:
            @staticmethod
            def record_to_tempfile(**kwargs: Any) -> Dict[str, Any]:
                return {"ok": True, "audio_path": str(fake_audio_path), "duration_seconds": 1.2, "error": None}

        class _FakeStt:
            @staticmethod
            def transcribe(path: str) -> Dict[str, Any]:
                assert path == str(fake_audio_path)
                return {"ok": True, "text": "open notepad", "confidence": 0.9, "error": None}

        monkeypatch.setattr(voice_worker_module, "audio_input_provider", _FakeAudioInput())
        monkeypatch.setattr(voice_worker_module, "stt_provider", _FakeStt())
        monkeypatch.delenv("WILLIAM_VOICE_DEBUG_KEEP_AUDIO", raising=False)
        monkeypatch.setattr(worker, "_send_transcript_and_respond", lambda transcript, **kwargs: True)

        result = worker._capture_transcribe_and_respond()

        assert result is True
        assert not fake_audio_path.exists()

    def test_captured_audio_kept_when_debug_flag_set(self, tmp_path, monkeypatch) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)

        fake_audio_path = tmp_path / "captured_debug.wav"
        fake_audio_path.write_bytes(b"RIFF....WAVEfmt ")

        class _FakeAudioInput:
            @staticmethod
            def record_to_tempfile(**kwargs: Any) -> Dict[str, Any]:
                return {"ok": True, "audio_path": str(fake_audio_path), "duration_seconds": 1.2, "error": None}

        class _FakeStt:
            @staticmethod
            def transcribe(path: str) -> Dict[str, Any]:
                return {"ok": True, "text": "open notepad", "confidence": 0.9, "error": None}

        monkeypatch.setattr(voice_worker_module, "audio_input_provider", _FakeAudioInput())
        monkeypatch.setattr(voice_worker_module, "stt_provider", _FakeStt())
        monkeypatch.setenv("WILLIAM_VOICE_DEBUG_KEEP_AUDIO", "true")
        monkeypatch.setattr(worker, "_send_transcript_and_respond", lambda transcript, **kwargs: True)

        worker._capture_transcribe_and_respond()

        assert fake_audio_path.exists()
        fake_audio_path.unlink()


class TestTtsNotCalledWhenMissing:
    """Phase 9 coverage (item 10): TTS must never be invoked -- not even
    check_status()-then-speak() -- when no provider is configured. Real
    text-based --simulate-text path, real dispatcher mocked at the
    transport layer only (see _build_worker), TTS specifically watched."""

    def test_speak_not_called_when_tts_unconfigured(self, monkeypatch) -> None:
        worker, _transport = _build_worker("William open Notepad", mode="push_to_talk")
        monkeypatch.delenv("WILLIAM_TTS_PROVIDER", raising=False)

        def _fail_if_called(text: str) -> Dict[str, Any]:
            raise AssertionError("tts_provider.speak() must not be called when TTS is not configured")

        monkeypatch.setattr(voice_worker_module.tts_provider, "speak", _fail_if_called)

        worker.run()  # must not raise


class TestSttNotCalledInSimulateText:
    """Phase 9 coverage (item 11): --simulate-text uses the typed/provided
    text directly -- stt_provider.transcribe() must never be invoked on
    this path, real STT or not."""

    def test_transcribe_not_called_for_simulate_text(self, monkeypatch) -> None:
        worker, _transport = _build_worker("William open Notepad", mode="push_to_talk")

        def _fail_if_called(path: str) -> Dict[str, Any]:
            raise AssertionError("stt_provider.transcribe() must not be called on the --simulate-text path")

        monkeypatch.setattr(voice_worker_module.stt_provider, "transcribe", _fail_if_called)

        worker.run()  # must not raise


class TestLoggerDoesNotDuplicate:
    """Regression coverage: this worker's module-level setup code guards
    handler registration with `if not logger.handlers:` -- logging.
    getLogger(LOGGER_NAME) always returns the SAME logger object regardless
    of how many times/under how many names this module gets imported in one
    process, so that guard alone is sufficient to guarantee the handler is
    never attached twice (which would otherwise print every line twice)."""

    def test_handler_registered_exactly_once(self) -> None:
        assert len(voice_worker_module.logger.handlers) == 1

    def test_reimporting_setup_does_not_add_a_second_handler(self) -> None:
        # Simulates the module's own top-level guard running again (as it
        # would on a second import under a different name) -- must be a
        # no-op given a handler is already present.
        if not voice_worker_module.logger.handlers:
            voice_worker_module.logger.addHandler(logging.StreamHandler())
        assert len(voice_worker_module.logger.handlers) == 1



class TestDependencyStatusFailureNamesTheEndpoint:
    """Regression coverage for the exact live bug report: GET /voice/status
    returning HTTP 500 (e.g. from a stale DB schema) must be reported with
    the specific endpoint and transport status -- not a bare, unattributed
    "Internal server error." """

    def test_named_endpoint_and_transport_status_on_failure(self, caplog) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)

        failed_status_result = {
            "ok": False,
            "transport_ok": True,
            "transport_status": "http_500",
            "envelope": {"success": False, "message": "Internal server error.", "data": {}, "error": None},
            "errors": [],
        }

        with caplog.at_level(logging.INFO, logger=voice_worker_module.LOGGER_NAME):
            worker._report_dependency_status(failed_status_result)

        messages = "\n".join(record.message for record in caplog.records)
        assert "GET /voice/status failed" in messages
        assert "http_500" in messages
        assert "Internal server error." in messages
        # Must degrade honestly, not crash or claim providers are ready.
        assert "dependency-check mode" in messages


class TestCleanDependencyRequiredPrinting:
    """Item 4: when /voice/status succeeds but every provider is honestly
    unconfigured, the worker must print clean dependency_required-shaped
    status lines, never a raw exception or "Internal server error." """

    def test_all_providers_missing_prints_missing_markers_not_errors(self, capsys, caplog) -> None:
        worker, _transport = _build_worker("William what is moderation?")

        with caplog.at_level(logging.INFO, logger=voice_worker_module.LOGGER_NAME):
            exit_code = worker.run()

        assert exit_code == 0

        # The command-response block is a raw print() (capsys-visible);
        # dependency-status lines go through the logger (caplog-visible) --
        # both must be checked, neither may ever show a raw crash.
        captured = capsys.readouterr()
        assert "Internal server error" not in captured.out
        assert "Traceback" not in captured.out

        log_messages = "\n".join(record.message for record in caplog.records)
        assert "Internal server error" not in log_messages
        assert "Traceback" not in log_messages
        # wake_word_engine (text-based detection) always reports "available"
        # regardless of provider config -- only the other four are honestly
        # "external_dependency_required" when nothing is configured.
        for key in ("audio_input_worker", "stt_provider", "tts_provider", "speaker_recognition_provider"):
            assert f"{key}: external_dependency_required  [MISSING]" in log_messages
        assert "wake_word_engine: available  [OK]" in log_messages


class TestSpeaksFinalAnswerOnly:
    """Item 5/7: TTS must speak the real final_answer text and nothing
    else -- never the raw response dict/JSON, even though command_data
    (the full /voice/push-to-talk/text response) is what _speak_response
    receives."""

    def test_speaks_final_answer_text_when_tts_configured(self, monkeypatch) -> None:
        worker, _transport = _build_worker("William open Notepad", mode="push_to_talk")

        class _FakeTts:
            def __init__(self) -> None:
                self.spoken_calls: List[str] = []

            def check_status(self) -> Dict[str, Any]:
                return {"configured": True, "reason": None, "install_guidance": None}

            def speak(self, text: str) -> Dict[str, Any]:
                self.spoken_calls.append(text)
                return {"ok": True, "spoken": True, "error": None}

        fake_tts = _FakeTts()
        monkeypatch.setattr(voice_worker_module, "tts_provider", fake_tts)

        worker.run()

        assert len(fake_tts.spoken_calls) == 1
        spoken_text = fake_tts.spoken_calls[0]
        # Must be the plain final_answer string, never the JSON envelope.
        assert spoken_text == "Done boss, I sent the command to your Windows device. notepad is opening."
        assert isinstance(spoken_text, str)
        assert "{" not in spoken_text and "final_answer" not in spoken_text

    def test_never_speaks_raw_json_even_if_response_has_extra_fields(self, monkeypatch) -> None:
        worker, _transport = _build_worker("William what is moderation?", mode="push_to_talk")

        class _FakeTts:
            def __init__(self) -> None:
                self.spoken_calls: List[str] = []

            def check_status(self) -> Dict[str, Any]:
                return {"configured": True, "reason": None, "install_guidance": None}

            def speak(self, text: str) -> Dict[str, Any]:
                self.spoken_calls.append(text)
                return {"ok": True, "spoken": True, "error": None}

        fake_tts = _FakeTts()
        monkeypatch.setattr(voice_worker_module, "tts_provider", fake_tts)

        worker.run()

        assert len(fake_tts.spoken_calls) == 1
        # command_data has route/status/worker_task_id/speech_output_status
        # alongside final_answer -- only the final_answer text may be spoken.
        assert fake_tts.spoken_calls[0] == "Done boss, I sent the command to your Windows device. notepad is opening."


class TestReturnsToListeningAfterCommand:
    """Item 8 (continuous conversation session): after handling one real
    wake-word-triggered command, the worker must stay in active_conversation
    and capture a SECOND command WITHOUT requiring the wake word again --
    the outer wake-word-waiting loop is only re-entered once a local sleep
    phrase is detected (or the inactivity timeout expires), never after
    just one command."""

    def test_active_conversation_captures_second_command_without_wake_word(self, monkeypatch) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)

        class _FakeProviderStatusModule:
            @staticmethod
            def get_full_status() -> Dict[str, Any]:
                return {
                    "always_listening_available": True,
                    "missing_dependencies": [],
                    "always_listening_blocking_dependencies": [],
                }

        monkeypatch.setattr(voice_worker_module, "provider_status_module", _FakeProviderStatusModule())

        listen_call_count = {"n": 0}

        class _FakeListener:
            def __init__(self) -> None:
                pass

            def listen_until_detected(self, max_seconds: float | None = None) -> Dict[str, Any]:
                listen_call_count["n"] += 1
                if listen_call_count["n"] >= 2:
                    # Proves the outer wake-word loop was only re-entered
                    # AFTER the active-conversation session ended (the 2nd
                    # captured command below requests sleep) -- stop the
                    # test cleanly here rather than looping forever.
                    raise KeyboardInterrupt
                return {"detected": True, "score": 0.9, "trigger": "hey_jarvis"}

            def stop(self) -> None:
                pass

        class _FakeWakeWordProvider:
            @staticmethod
            def WakeWordListener() -> _FakeListener:  # noqa: N802
                return _FakeListener()

        monkeypatch.setattr(voice_worker_module, "wake_word_provider", _FakeWakeWordProvider())

        transport = FakeTransport(
            {
                "/voice/wake-event": _envelope(data={"should_listen": True, "mode": "wake_word_admin"}),
                "/voice/worker/heartbeat": _envelope(data={"worker_connected": True}),
            }
        )
        worker._client._request = transport  # type: ignore[method-assign]
        monkeypatch.setattr(worker, "_speak_and_print", lambda text: None)

        respond_calls: List[bool] = []

        def _fake_capture(**kwargs: Any) -> bool:
            respond_calls.append(True)
            if len(respond_calls) >= 2:
                # The second captured command in this session is a local
                # sleep phrase -- ends the active_conversation session.
                worker._sleep_requested = True
                return False
            return True

        monkeypatch.setattr(worker, "_capture_transcribe_and_respond", _fake_capture)

        try:
            worker._run_wake_word_admin_loop("wake_word_admin")
        except KeyboardInterrupt:
            pass

        # Two commands captured in ONE active-conversation session (no
        # second wake-word detection between them); the outer loop only
        # re-entered listen_until_detected once the session ended.
        assert len(respond_calls) == 2
        assert listen_call_count["n"] == 2

    def test_inactivity_timeout_returns_to_wake_word_waiting(self, monkeypatch) -> None:
        """Item 4: a session with no real activity for
        WILLIAM_VOICE_ACTIVE_SESSION_TIMEOUT_SECONDS returns to wake-word
        waiting even though no sleep phrase was ever said."""
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)
        monkeypatch.setenv("WILLIAM_VOICE_ACTIVE_SESSION_TIMEOUT_SECONDS", "0")

        class _FakeProviderStatusModule:
            @staticmethod
            def get_full_status() -> Dict[str, Any]:
                return {
                    "always_listening_available": True,
                    "missing_dependencies": [],
                    "always_listening_blocking_dependencies": [],
                }

        monkeypatch.setattr(voice_worker_module, "provider_status_module", _FakeProviderStatusModule())

        listen_call_count = {"n": 0}

        class _FakeListener:
            def listen_until_detected(self, max_seconds: float | None = None) -> Dict[str, Any]:
                listen_call_count["n"] += 1
                if listen_call_count["n"] >= 2:
                    raise KeyboardInterrupt
                return {"detected": True, "score": 0.9, "trigger": "hey_jarvis"}

            def stop(self) -> None:
                pass

        class _FakeWakeWordProvider:
            @staticmethod
            def WakeWordListener() -> _FakeListener:  # noqa: N802
                return _FakeListener()

        monkeypatch.setattr(voice_worker_module, "wake_word_provider", _FakeWakeWordProvider())

        transport = FakeTransport(
            {
                "/voice/wake-event": _envelope(data={"should_listen": True, "mode": "wake_word_admin"}),
                "/voice/worker/heartbeat": _envelope(data={"worker_connected": True}),
            }
        )
        worker._client._request = transport  # type: ignore[method-assign]
        monkeypatch.setattr(worker, "_speak_and_print", lambda text: None)

        capture_calls: List[bool] = []
        monkeypatch.setattr(
            worker, "_capture_transcribe_and_respond", lambda **kwargs: capture_calls.append(True) or False
        )

        try:
            worker._run_wake_word_admin_loop("wake_word_admin")
        except KeyboardInterrupt:
            pass

        # timeout=0 means the very first inactivity check (before the
        # first capture attempt) already exceeds it -- session ends without
        # ever calling _capture_transcribe_and_respond, and the outer loop
        # re-enters listen_until_detected.
        assert capture_calls == []
        assert listen_call_count["n"] == 2


class TestLocalProviderEnvAliasesMatchBackendGuidance:
    """Regression coverage for the exact live bug report: the backend's own
    install_guidance (agents/voice_agent/provider_capabilities.py's
    provider_value_hint) tells an operator to set
    WILLIAM_STT_PROVIDER=faster_whisper_local /
    WILLIAM_TTS_PROVIDER=pyttsx3_local /
    WILLIAM_WAKE_WORD_PROVIDER=openwakeword_local -- these exact values
    must be accepted by the real provider modules (apps/worker_nodes/
    voice/providers/*.py), not just their un-suffixed canonical forms.
    Uses the REAL provider modules (no fakes) -- this is exactly the check
    that failed live, with faster-whisper/pyttsx3/openwakeword genuinely
    installed but WILLIAM_STT_PROVIDER=faster_whisper_local (etc.) still
    reporting external_dependency_required."""

    def test_stt_accepts_local_suffixed_alias(self, monkeypatch) -> None:
        from apps.worker_nodes.voice.providers import stt as real_stt

        monkeypatch.setenv("WILLIAM_STT_PROVIDER", "faster_whisper_local")
        assert real_stt.check_status()["configured"] is True

    def test_tts_accepts_local_suffixed_alias(self, monkeypatch) -> None:
        from apps.worker_nodes.voice.providers import tts as real_tts

        monkeypatch.setenv("WILLIAM_TTS_PROVIDER", "pyttsx3_local")
        assert real_tts.check_status()["configured"] is True

    def test_wake_word_accepts_local_suffixed_alias(self, monkeypatch) -> None:
        from apps.worker_nodes.voice.providers import wake_word as real_wake_word

        monkeypatch.setenv("WILLIAM_WAKE_WORD_PROVIDER", "openwakeword_local")
        assert real_wake_word.check_status()["configured"] is True

    def test_provider_env_is_read_fresh_from_this_process_every_call(self, monkeypatch) -> None:
        """Item 8: provider env values are read fresh from THIS process's
        os.environ on every check_status() call -- never cached at import
        time -- which is what makes it correct for the worker to use its
        own local env for the real-listening gate rather than trusting the
        backend process's (possibly different-machine) view."""
        from apps.worker_nodes.voice.providers import stt as real_stt

        monkeypatch.delenv("WILLIAM_STT_PROVIDER", raising=False)
        assert real_stt.check_status()["configured"] is False
        monkeypatch.setenv("WILLIAM_STT_PROVIDER", "faster_whisper_local")
        assert real_stt.check_status()["configured"] is True


class TestListeningGateIgnoresTtsAndSpeakerRecognition:
    """Wake-word listening gate fix: only audio_input_worker/stt_provider/
    wake_word_provider actually gate _run_wake_word_admin_loop's real
    always-listening loop -- tts_provider/speaker_recognition_provider
    missing must never keep the worker in the safe idle loop, and the
    dependency_required message (when something IS genuinely missing) must
    never name tts_provider/speaker_recognition_provider as blockers."""

    @staticmethod
    def _fake_listener_stops_immediately() -> Any:
        class _FakeListener:
            def listen_until_detected(self, max_seconds: float | None = None) -> Dict[str, Any]:
                raise KeyboardInterrupt

            def stop(self) -> None:
                pass

        return _FakeListener()

    def test_enters_listening_when_tts_missing(self, monkeypatch) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)

        class _FakeProviderStatusModule:
            @staticmethod
            def get_full_status() -> Dict[str, Any]:
                return {
                    "always_listening_available": True,  # audio/stt/wake_word all configured
                    "missing_dependencies": ["tts_provider"],  # TTS genuinely missing
                    "always_listening_blocking_dependencies": [],  # never a blocker
                }

        monkeypatch.setattr(voice_worker_module, "provider_status_module", _FakeProviderStatusModule())

        listener = self._fake_listener_stops_immediately()

        class _FakeWakeWordProvider:
            @staticmethod
            def WakeWordListener() -> Any:  # noqa: N802
                return listener

        monkeypatch.setattr(voice_worker_module, "wake_word_provider", _FakeWakeWordProvider())

        idle_loop_calls: List[bool] = []
        monkeypatch.setattr(worker, "_run_idle_loop", lambda: idle_loop_calls.append(True))

        try:
            worker._run_wake_word_admin_loop("wake_word_admin")
        except KeyboardInterrupt:
            pass

        assert idle_loop_calls == []  # never fell back to idle just because TTS is missing

    def test_dependency_required_message_lists_only_true_blockers(self, monkeypatch, caplog) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)

        class _FakeProviderStatusModule:
            @staticmethod
            def get_full_status() -> Dict[str, Any]:
                return {
                    "always_listening_available": False,
                    "missing_dependencies": ["stt_provider", "tts_provider", "speaker_recognition_provider"],
                    "always_listening_blocking_dependencies": ["stt_provider"],
                }

        monkeypatch.setattr(voice_worker_module, "provider_status_module", _FakeProviderStatusModule())
        monkeypatch.setattr(worker, "_run_idle_loop", lambda: None)

        with caplog.at_level(logging.INFO, logger=voice_worker_module.LOGGER_NAME):
            worker._run_wake_word_admin_loop("wake_word_admin")

        messages = "\n".join(record.message for record in caplog.records)
        assert "dependency_required" in messages
        assert "stt_provider" in messages
        assert "tts_provider" not in messages
        assert "speaker_recognition_provider" not in messages

    def test_prints_listening_for_wake_word_message(self, monkeypatch, capsys) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)
        monkeypatch.setenv("WILLIAM_WAKE_WORD_PHRASE", "hey_jarvis")

        class _FakeProviderStatusModule:
            @staticmethod
            def get_full_status() -> Dict[str, Any]:
                return {
                    "always_listening_available": True,
                    "missing_dependencies": [],
                    "always_listening_blocking_dependencies": [],
                }

        monkeypatch.setattr(voice_worker_module, "provider_status_module", _FakeProviderStatusModule())

        listener = self._fake_listener_stops_immediately()

        class _FakeWakeWordProvider:
            @staticmethod
            def WakeWordListener() -> Any:  # noqa: N802
                return listener

            @staticmethod
            def resolve_bundled_model_name() -> Dict[str, Any]:
                return {"model_name": "hey_jarvis", "matched_configured_phrase": True, "configured_phrase": "hey_jarvis"}

        monkeypatch.setattr(voice_worker_module, "wake_word_provider", _FakeWakeWordProvider())

        try:
            worker._run_wake_word_admin_loop("wake_word_admin")
        except KeyboardInterrupt:
            pass

        captured = capsys.readouterr()
        assert "Listening for wake word: Hey Jarvis" in captured.out


class TestTtsAndSpeakerRecognitionOptionalForCommandExecution:
    """Wake-word listening gate fix items 2-4: TTS and speaker recognition
    must never block command execution once a transcript is in hand
    (either from real STT or typed text) -- only a locally-recognized
    sensitive/private/risky transcript is held back when no
    speaker-recognition provider is configured, and even then only that
    specific command, never TTS."""

    @staticmethod
    def _build_bare_worker() -> Tuple[VoiceWorker, FakeTransport]:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)
        transport = FakeTransport(
            {
                "/voice/push-to-talk/text": _envelope(
                    data={
                        "final_answer": "Done boss, notepad is opening.",
                        "status": "completed",
                        "route": ["system"],
                        "worker_task_id": "wtask_fake789",
                        "speech_output_status": "tts_missing",
                    }
                ),
            }
        )
        worker._client._request = transport  # type: ignore[method-assign]
        return worker, transport

    def test_missing_tts_does_not_block_command_execution(self, monkeypatch) -> None:
        worker, transport = self._build_bare_worker()
        monkeypatch.delenv("WILLIAM_TTS_PROVIDER", raising=False)
        monkeypatch.setenv("WILLIAM_SPEAKER_RECOGNITION_PROVIDER", "test_provider")

        sent = worker._send_transcript_and_respond("open Notepad")

        assert sent is True
        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" in called_paths

    def test_missing_speaker_recognition_does_not_block_normal_command(self, monkeypatch) -> None:
        worker, transport = self._build_bare_worker()
        monkeypatch.delenv("WILLIAM_SPEAKER_RECOGNITION_PROVIDER", raising=False)

        sent = worker._send_transcript_and_respond("open Notepad")

        assert sent is True
        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" in called_paths

    def test_missing_speaker_recognition_blocks_only_sensitive_command(self, monkeypatch, caplog) -> None:
        worker, transport = self._build_bare_worker()
        monkeypatch.delenv("WILLIAM_SPEAKER_RECOGNITION_PROVIDER", raising=False)

        with caplog.at_level(logging.INFO, logger=voice_worker_module.LOGGER_NAME):
            sent = worker._send_transcript_and_respond("please delete all my files")

        assert sent is False
        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" not in called_paths
        messages = "\n".join(record.message for record in caplog.records)
        assert "Sensitive voice verification unavailable; normal voice commands still work." in messages


class TestWakeWordAdminSimulateTextRoutesToWindowsWorker:
    """Item 9: "Hey Jarvis open Notepad" (typed/simulated) must reach the
    same real dispatcher normal push-to-talk-text commands do -- "jarvis"
    is always one of the local text-detector's default wake words (see
    _build_wake_detector), independent of the workspace's configured
    wake_word phrase."""

    def test_hey_jarvis_open_notepad_routes_through_dispatcher(self) -> None:
        worker, transport = _build_worker("Hey Jarvis open Notepad", mode="wake_word_admin")

        exit_code = worker.run()

        assert exit_code == 0
        push_to_talk_calls = [
            payload for method, path, payload in transport.calls if path == "/voice/push-to-talk/text"
        ]
        assert len(push_to_talk_calls) == 1
        assert "notepad" in push_to_talk_calls[0]["text"].lower()


def _build_capture_worker(*, transcript: str, confidence: float = 0.9) -> Tuple[VoiceWorker, FakeTransport, List[Any]]:
    """A worker wired for _capture_transcribe_and_respond with fake audio
    input + STT (real record/transcribe call shapes, no real hardware) and
    a fake transport for /voice/push-to-talk/text -- used by the
    continuous-conversation-session tests below. Returns
    (worker, transport, tts_spoken_calls)."""
    config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
    worker = VoiceWorker(config)

    class _FakeAudioInput:
        @staticmethod
        def record_to_tempfile(**kwargs: Any) -> Dict[str, Any]:
            return {"ok": True, "audio_path": "C:\\fake\\captured.wav", "duration_seconds": 1.5, "error": None, "peak_rms": 900.0}

    class _FakeStt:
        @staticmethod
        def transcribe(path: str) -> Dict[str, Any]:
            return {"ok": True, "text": transcript, "confidence": confidence, "error": None}

    tts_spoken_calls: List[str] = []

    class _FakeTts:
        @staticmethod
        def check_status() -> Dict[str, Any]:
            return {"configured": True, "reason": None, "install_guidance": None}

        @staticmethod
        def speak(text: str) -> Dict[str, Any]:
            tts_spoken_calls.append(text)
            return {"ok": True, "spoken": True, "error": None}

    orig_audio = voice_worker_module.audio_input_provider
    orig_stt = voice_worker_module.stt_provider
    orig_tts = voice_worker_module.tts_provider
    voice_worker_module.audio_input_provider = _FakeAudioInput()
    voice_worker_module.stt_provider = _FakeStt()
    voice_worker_module.tts_provider = _FakeTts()

    def _restore() -> None:
        voice_worker_module.audio_input_provider = orig_audio
        voice_worker_module.stt_provider = orig_stt
        voice_worker_module.tts_provider = orig_tts

    worker._test_restore_providers = _restore  # type: ignore[attr-defined]

    transport = FakeTransport(
        {
            "/voice/push-to-talk/text": _envelope(
                data={
                    "final_answer": "Done boss.",
                    "status": "completed",
                    "route": ["system"],
                    "worker_task_id": "wtask_fake999",
                    "speech_output_status": "spoken",
                }
            ),
        }
    )
    worker._client._request = transport  # type: ignore[method-assign]
    return worker, transport, tts_spoken_calls


class TestActiveConversationAcknowledgement:
    """Item 1: wake word activates active_conversation mode with a short
    spoken/printed acknowledgement, before any command is captured."""

    def test_wake_word_speaks_acknowledgement_and_enters_active_conversation(self, monkeypatch, capsys) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)

        capture_calls: List[bool] = []

        def _fake_capture(**kwargs: Any) -> bool:
            capture_calls.append(True)
            # Confirm we're already in active_conversation by the time the
            # first command capture happens.
            assert worker._active_conversation is True
            worker._sleep_requested = True
            return False

        monkeypatch.setattr(worker, "_capture_transcribe_and_respond", _fake_capture)
        monkeypatch.setattr(worker, "send_heartbeat", lambda: {"ok": True, "transport_ok": True, "transport_status": "http_200"})

        worker._run_active_conversation_session(wake_detect_ms=12.3)

        captured = capsys.readouterr()
        assert "Yes boss?" in captured.out
        assert len(capture_calls) == 1
        # Session must clean up back to False once it ends.
        assert worker._active_conversation is False


class TestSleepPhrasesEndSession:
    """Items 3 and 5: a local sleep phrase said during active_conversation
    ends the session, is spoken back, and -- critically -- is NEVER sent to
    the assistant dispatcher/MasterAgent."""

    def test_william_bye_returns_to_wake_word_waiting(self, monkeypatch, capsys) -> None:
        worker, transport, _tts_calls = _build_capture_worker(transcript="William bye")
        worker._active_conversation = True
        try:
            sent = worker._capture_transcribe_and_respond()
        finally:
            worker._test_restore_providers()  # type: ignore[attr-defined]

        assert sent is False
        assert worker._sleep_requested is True
        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" not in called_paths
        captured = capsys.readouterr()
        assert "Okay boss, I'll wait for the wake word." in captured.out

    def test_go_to_sleep_is_not_sent_to_assistant_dispatcher(self, monkeypatch) -> None:
        worker, transport, _tts_calls = _build_capture_worker(transcript="okay, go to sleep now")
        worker._active_conversation = True
        try:
            sent = worker._capture_transcribe_and_respond()
        finally:
            worker._test_restore_providers()  # type: ignore[attr-defined]

        assert sent is False
        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" not in called_paths

    def test_sleep_phrases_ignored_outside_active_conversation(self) -> None:
        """A plain --simulate-text/one-shot call (self._active_conversation
        left False) must NOT treat "William bye" as a sleep phrase -- that
        gate only applies during a real continuous-conversation session."""
        worker, transport, _tts_calls = _build_capture_worker(transcript="William bye")
        assert worker._active_conversation is False
        try:
            sent = worker._capture_transcribe_and_respond()
        finally:
            worker._test_restore_providers()  # type: ignore[attr-defined]

        assert sent is True
        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" in called_paths


class TestRiskyCommandNotTreatedAsSleep:
    """Item 6: "shutdown computer" is a real risky command, not a local
    sleep phrase ("shutdown voice" is the sleep phrase) -- it must still
    reach the assistant dispatcher, which routes it to SecurityAgent."""

    def test_shutdown_computer_is_dispatched_not_treated_as_sleep(self, monkeypatch) -> None:
        # Isolates the sleep-vs-risky distinction from speaker-verification
        # mechanics (covered separately by TestSpeakerVerificationGating) --
        # mocks a real, MATCHED speaker verification so the sensitive-
        # command gate passes legitimately, confirming "shutdown computer"
        # reaches the dispatcher rather than being silently treated as a
        # "shutdown voice" sleep phrase.
        monkeypatch.setenv("WILLIAM_SPEAKER_RECOGNITION_PROVIDER", "local_speaker_embedding")
        worker, transport, _tts_calls = _build_capture_worker(transcript="shutdown computer")

        class _FakeSpeakerEmbeddingProvider:
            @staticmethod
            def check_status() -> Dict[str, Any]:
                return {"configured": True, "reason": None, "install_guidance": None}

            @staticmethod
            def compute_embedding(path: str) -> Dict[str, Any]:
                return {"ok": True, "embedding": [0.1, 0.2, 0.3], "error": None}

        monkeypatch.setattr(voice_worker_module, "speaker_embedding_provider", _FakeSpeakerEmbeddingProvider())
        monkeypatch.setattr(
            worker, "_verify_speaker",
            lambda embedding: {
                "matched": True, "profile_id": "voiceprofile_1", "display_name": "Owner",
                "role": "owner", "confidence": 0.95,
            },
        )

        worker._active_conversation = True
        assert worker._is_sleep_transcript("shutdown computer") is False
        try:
            sent = worker._capture_transcribe_and_respond()
        finally:
            worker._test_restore_providers()  # type: ignore[attr-defined]

        assert sent is True
        assert worker._sleep_requested is False
        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" in called_paths


class TestWeakTranscriptRejectedLocally:
    """Item 9: an empty/garbled/low-confidence transcript is never sent to
    the assistant dispatcher -- the worker asks the user to repeat
    instead."""

    def test_dot_transcript_rejected_and_asks_repeat(self, capsys) -> None:
        worker, transport, _tts_calls = _build_capture_worker(transcript=".", confidence=0.9)
        worker._active_conversation = True
        try:
            sent = worker._capture_transcribe_and_respond()
        finally:
            worker._test_restore_providers()  # type: ignore[attr-defined]

        assert sent is False
        assert worker._sleep_requested is False
        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" not in called_paths
        captured = capsys.readouterr()
        assert "Boss, I could not understand. Please repeat." in captured.out

    def test_low_confidence_transcript_rejected(self) -> None:
        worker, transport, _tts_calls = _build_capture_worker(transcript="open notepad", confidence=0.02)
        worker._active_conversation = True
        try:
            sent = worker._capture_transcribe_and_respond()
        finally:
            worker._test_restore_providers()  # type: ignore[attr-defined]

        assert sent is False
        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" not in called_paths

    def test_clear_transcript_not_rejected(self) -> None:
        worker, transport, _tts_calls = _build_capture_worker(transcript="open notepad", confidence=0.9)
        try:
            sent = worker._capture_transcribe_and_respond()
        finally:
            worker._test_restore_providers()  # type: ignore[attr-defined]

        assert sent is True
        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" in called_paths


class TestSpokenReplyShortening:
    """Item 12: WILLIAM_VOICE_MAX_SPOKEN_CHARS caps what gets SPOKEN
    through TTS by default -- never the printed/logged full text."""

    def test_long_reply_is_truncated_for_speech(self, monkeypatch) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)
        monkeypatch.setenv("WILLIAM_VOICE_MAX_SPOKEN_CHARS", "40")
        monkeypatch.delenv("WILLIAM_VOICE_REPLY_STYLE", raising=False)

        long_text = "This is a very long answer that goes on and on well past the configured spoken character limit."
        spoken = worker._prepare_spoken_text(long_text)

        assert len(spoken) <= 44  # 40 + "..." plus a little slack for word-boundary cut
        assert spoken != long_text
        assert long_text.startswith(spoken.rstrip("."))

    def test_reply_style_full_disables_truncation(self, monkeypatch) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)
        monkeypatch.setenv("WILLIAM_VOICE_MAX_SPOKEN_CHARS", "10")
        monkeypatch.setenv("WILLIAM_VOICE_REPLY_STYLE", "full")

        long_text = "This text is much longer than ten characters."
        assert worker._prepare_spoken_text(long_text) == long_text

    def test_short_reply_unaffected(self, monkeypatch) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)
        monkeypatch.delenv("WILLIAM_VOICE_MAX_SPOKEN_CHARS", raising=False)
        monkeypatch.delenv("WILLIAM_VOICE_REPLY_STYLE", raising=False)

        assert worker._prepare_spoken_text("Done boss.") == "Done boss."


class TestCliDiagnosticsWork:
    """Items 13-15: --test-tts / --test-mic / --test-stt each do a real
    (fake-provider-backed) capture/speak cycle and report success."""

    def test_test_tts_speaks_custom_text(self, monkeypatch, capsys) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)

        spoken_calls: List[str] = []

        class _FakeTts:
            @staticmethod
            def check_status() -> Dict[str, Any]:
                return {"configured": True, "reason": None, "install_guidance": None}

            @staticmethod
            def speak(text: str) -> Dict[str, Any]:
                spoken_calls.append(text)
                return {"ok": True, "spoken": True, "error": None}

        monkeypatch.setattr(voice_worker_module, "tts_provider", _FakeTts())

        exit_code = worker.test_tts(text="Boss, William voice output is working.")

        captured = capsys.readouterr()
        assert exit_code == 0
        assert spoken_calls == ["Boss, William voice output is working."]
        assert "Spoken successfully" in captured.out

    def test_test_mic_records_and_reports_duration(self, monkeypatch, capsys) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)

        class _FakeAudioInput:
            @staticmethod
            def record_to_tempfile(**kwargs: Any) -> Dict[str, Any]:
                return {"ok": True, "audio_path": "C:\\fake\\mic_test.wav", "duration_seconds": 3.2, "error": None, "peak_rms": 700.0}

        monkeypatch.setattr(voice_worker_module, "audio_input_provider", _FakeAudioInput())
        monkeypatch.setattr(os, "remove", lambda path: None)

        exit_code = worker.test_mic()

        captured = capsys.readouterr()
        assert exit_code == 0
        assert "3.2s" in captured.out

    def test_test_stt_records_and_transcribes(self, monkeypatch, capsys) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)

        class _FakeAudioInput:
            @staticmethod
            def record_to_tempfile(**kwargs: Any) -> Dict[str, Any]:
                return {"ok": True, "audio_path": "C:\\fake\\stt_test.wav", "duration_seconds": 2.0, "error": None, "peak_rms": 800.0}

        class _FakeStt:
            @staticmethod
            def check_status() -> Dict[str, Any]:
                return {"configured": True, "reason": None, "install_guidance": None}

            @staticmethod
            def transcribe(path: str) -> Dict[str, Any]:
                return {"ok": True, "text": "open notepad", "confidence": 0.93, "error": None}

        monkeypatch.setattr(voice_worker_module, "audio_input_provider", _FakeAudioInput())
        monkeypatch.setattr(voice_worker_module, "stt_provider", _FakeStt())
        monkeypatch.setattr(os, "remove", lambda path: None)

        exit_code = worker.test_stt()

        captured = capsys.readouterr()
        assert exit_code == 0
        assert "open notepad" in captured.out


def _build_silent_capture_worker() -> Tuple[VoiceWorker, List[str]]:
    """A worker wired so every _capture_transcribe_and_respond call reports
    genuine SILENCE (STT ok=False, "no speech detected") -- for the
    no-speech-retry-cap tests below. Returns (worker, tts_spoken_calls)."""
    config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
    worker = VoiceWorker(config)

    class _FakeAudioInput:
        @staticmethod
        def record_to_tempfile(**kwargs: Any) -> Dict[str, Any]:
            return {"ok": True, "audio_path": "C:\\fake\\silent.wav", "duration_seconds": 5.0, "error": None, "peak_rms": 50.0}

    class _FakeStt:
        @staticmethod
        def transcribe(path: str) -> Dict[str, Any]:
            return {"ok": False, "text": None, "confidence": None, "error": "no speech detected"}

    spoken_calls: List[str] = []

    class _FakeTts:
        @staticmethod
        def check_status() -> Dict[str, Any]:
            return {"configured": True, "reason": None, "install_guidance": None}

        @staticmethod
        def speak(text: str) -> Dict[str, Any]:
            spoken_calls.append(text)
            return {"ok": True, "spoken": True, "error": None}

    orig_audio = voice_worker_module.audio_input_provider
    orig_stt = voice_worker_module.stt_provider
    orig_tts = voice_worker_module.tts_provider
    voice_worker_module.audio_input_provider = _FakeAudioInput()
    voice_worker_module.stt_provider = _FakeStt()
    voice_worker_module.tts_provider = _FakeTts()

    def _restore() -> None:
        voice_worker_module.audio_input_provider = orig_audio
        voice_worker_module.stt_provider = orig_stt
        voice_worker_module.tts_provider = orig_tts

    worker._test_restore_providers = _restore  # type: ignore[attr-defined]
    return worker, spoken_calls


class TestNoSpeechRetryCap:
    """Items 1-2 (silence-loop fix): genuine silence (STT ok=False) during
    active_conversation must never be spoken about on every single
    occurrence -- only logged -- and only speaks + ends the session once
    WILLIAM_VOICE_NO_SPEECH_MAX_RETRIES consecutive silent captures have
    happened. This is the exact reported bug: a silent room made the
    worker repeat "could not understand" every ~5s forever."""

    def test_first_no_speech_event_does_not_speak(self, monkeypatch, capsys) -> None:
        worker, spoken_calls = _build_silent_capture_worker()
        monkeypatch.setenv("WILLIAM_VOICE_NO_SPEECH_MAX_RETRIES", "5")
        worker._active_conversation = True

        try:
            sent = worker._capture_transcribe_and_respond()
        finally:
            worker._test_restore_providers()  # type: ignore[attr-defined]

        assert sent is False
        assert worker._sleep_requested is False
        assert spoken_calls == []
        captured = capsys.readouterr()
        assert "Okay boss" not in captured.out
        assert "could not understand" not in captured.out

    def test_repeated_silence_below_cap_never_speaks(self, monkeypatch) -> None:
        worker, spoken_calls = _build_silent_capture_worker()
        monkeypatch.setenv("WILLIAM_VOICE_NO_SPEECH_MAX_RETRIES", "5")
        worker._active_conversation = True

        try:
            for _ in range(4):
                assert worker._capture_transcribe_and_respond() is False
        finally:
            worker._test_restore_providers()  # type: ignore[attr-defined]

        # 4 silent captures, cap is 5 -- never spoken, session not ended.
        assert spoken_calls == []
        assert worker._sleep_requested is False

    def test_consecutive_no_speech_hits_cap_and_returns_to_wake_word_waiting(self, monkeypatch) -> None:
        worker, spoken_calls = _build_silent_capture_worker()
        monkeypatch.setenv("WILLIAM_VOICE_NO_SPEECH_MAX_RETRIES", "2")
        worker._active_conversation = True

        try:
            assert worker._capture_transcribe_and_respond() is False
            assert spoken_calls == []  # first attempt: silent, not spoken

            assert worker._capture_transcribe_and_respond() is False
        finally:
            worker._test_restore_providers()  # type: ignore[attr-defined]

        # Cap reached on the 2nd consecutive silent capture -- spoken
        # exactly once, and the session is flagged to end.
        assert spoken_calls == ["Okay boss, I'll wait for the wake word."]
        assert worker._sleep_requested is True

    def test_verbose_errors_speaks_on_every_silent_capture(self, monkeypatch) -> None:
        worker, spoken_calls = _build_silent_capture_worker()
        monkeypatch.setenv("WILLIAM_VOICE_NO_SPEECH_MAX_RETRIES", "5")
        monkeypatch.setenv("WILLIAM_VOICE_VERBOSE_ERRORS", "1")
        worker._active_conversation = True

        try:
            worker._capture_transcribe_and_respond()
        finally:
            worker._test_restore_providers()  # type: ignore[attr-defined]

        assert spoken_calls == ["No speech detected; still listening."]


class TestLowConfidenceAsksRepeatOnce:
    """Item 3: a real (non-empty) but low-confidence/garbled transcript is
    spoken about exactly once per occurrence -- distinct from silence
    above, which is never spoken about until the retry cap."""

    def test_low_confidence_transcript_speaks_repeat_prompt_once(self, monkeypatch) -> None:
        worker, _transport, tts_calls = _build_capture_worker(transcript="mumble mumble", confidence=0.02)
        worker._active_conversation = True

        try:
            sent = worker._capture_transcribe_and_respond()
        finally:
            worker._test_restore_providers()  # type: ignore[attr-defined]

        assert sent is False
        assert tts_calls == ["Boss, I could not understand. Please repeat."]


class TestSpeakerVerificationGating:
    """Item 10: an unknown/unmatched voice must never execute a sensitive
    command -- the worker holds it back and asks for dashboard
    confirmation, exactly like the "no provider configured" case, but via
    the real verify-speaker round trip this time."""

    def test_unmatched_voice_blocks_sensitive_command(self, monkeypatch, capsys) -> None:
        monkeypatch.setenv("WILLIAM_SPEAKER_RECOGNITION_PROVIDER", "local_speaker_embedding")
        worker, transport, _tts_calls = _build_capture_worker(transcript="please delete all my files")

        class _FakeSpeakerEmbeddingProvider:
            @staticmethod
            def check_status() -> Dict[str, Any]:
                return {"configured": True, "reason": None, "install_guidance": None}

            @staticmethod
            def compute_embedding(path: str) -> Dict[str, Any]:
                return {"ok": True, "embedding": [0.1, 0.2, 0.3], "error": None}

        monkeypatch.setattr(voice_worker_module, "speaker_embedding_provider", _FakeSpeakerEmbeddingProvider())
        monkeypatch.setattr(
            worker, "_verify_speaker",
            lambda embedding: {"matched": False, "profile_id": None, "display_name": None, "role": None, "confidence": 0.1},
        )

        try:
            sent = worker._capture_transcribe_and_respond()
        finally:
            worker._test_restore_providers()  # type: ignore[attr-defined]

        assert sent is False
        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" not in called_paths
        captured = capsys.readouterr()
        assert "Boss, I cannot verify this voice. Please confirm from dashboard." in captured.out

    def test_matched_voice_allows_sensitive_command(self, monkeypatch) -> None:
        monkeypatch.setenv("WILLIAM_SPEAKER_RECOGNITION_PROVIDER", "local_speaker_embedding")
        worker, transport, _tts_calls = _build_capture_worker(transcript="please delete all my files")

        class _FakeSpeakerEmbeddingProvider:
            @staticmethod
            def check_status() -> Dict[str, Any]:
                return {"configured": True, "reason": None, "install_guidance": None}

            @staticmethod
            def compute_embedding(path: str) -> Dict[str, Any]:
                return {"ok": True, "embedding": [0.1, 0.2, 0.3], "error": None}

        monkeypatch.setattr(voice_worker_module, "speaker_embedding_provider", _FakeSpeakerEmbeddingProvider())
        monkeypatch.setattr(
            worker, "_verify_speaker",
            lambda embedding: {
                "matched": True, "profile_id": "voiceprofile_1", "display_name": "Owner",
                "role": "owner", "confidence": 0.9,
            },
        )

        try:
            sent = worker._capture_transcribe_and_respond()
        finally:
            worker._test_restore_providers()  # type: ignore[attr-defined]

        assert sent is True
        called_paths = [path for _, path, _ in transport.calls]
        assert "/voice/push-to-talk/text" in called_paths


class TestEnrollmentDeletesRawAudio:
    """Item 8: --enroll-voice must never keep raw audio by default -- each
    phrase's captured WAV is deleted immediately after its embedding is
    computed, just like the normal command-capture path."""

    def test_enroll_voice_deletes_each_phrase_wav(self, monkeypatch, tmp_path) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)
        monkeypatch.setenv("WILLIAM_SPEAKER_RECOGNITION_PROVIDER", "local_speaker_embedding")
        monkeypatch.setenv("WILLIAM_VOICE_ENROLLMENT_PHRASES", "2")
        monkeypatch.delenv("WILLIAM_VOICE_SAVE_DEBUG_WAV", raising=False)
        monkeypatch.delenv("WILLIAM_VOICE_DEBUG_KEEP_AUDIO", raising=False)

        created_paths: List[Any] = []

        class _FakeAudioInput:
            @staticmethod
            def record_to_tempfile(**kwargs: Any) -> Dict[str, Any]:
                wav_path = tmp_path / f"phrase_{len(created_paths)}.wav"
                wav_path.write_bytes(b"RIFF....WAVEfmt ")
                created_paths.append(wav_path)
                return {"ok": True, "audio_path": str(wav_path), "duration_seconds": 1.5, "error": None, "peak_rms": 900.0}

        class _FakeSpeakerEmbeddingProvider:
            LOCAL_PROVIDER_NAME = "local_speaker_embedding"

            @staticmethod
            def check_status() -> Dict[str, Any]:
                return {"configured": True, "reason": None, "install_guidance": None}

            @staticmethod
            def compute_embedding(path: str) -> Dict[str, Any]:
                return {"ok": True, "embedding": [0.1] * 24, "error": None}

        monkeypatch.setattr(voice_worker_module, "audio_input_provider", _FakeAudioInput())
        monkeypatch.setattr(voice_worker_module, "speaker_embedding_provider", _FakeSpeakerEmbeddingProvider())

        transport = FakeTransport(
            {
                "/voice/profiles": _envelope(data={"profile": {"id": "voiceprofile_owner_1"}}),
                "/voice/profiles/voiceprofile_owner_1/embedding": _envelope(data={"profile": {"id": "voiceprofile_owner_1"}}),
            }
        )
        worker._client._request = transport  # type: ignore[method-assign]

        exit_code = worker.enroll_voice("owner")

        assert exit_code == 0
        assert len(created_paths) == 2
        for wav_path in created_paths:
            assert not wav_path.exists()
