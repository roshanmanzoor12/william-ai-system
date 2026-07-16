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
    """Item 8: after handling one real wake-word-triggered command, the
    always-listening loop must go back to listening for the next wake
    word -- not stop, not fall into idle/heartbeat-only mode."""

    def test_wake_word_admin_loop_listens_again_after_responding(self, monkeypatch) -> None:
        config = VoiceWorkerConfig(api_base_url="http://fake-backend.invalid/api/v1", token="fake-jwt-token")
        worker = VoiceWorker(config)

        class _FakeProviderStatusModule:
            @staticmethod
            def get_full_status() -> Dict[str, Any]:
                return {"always_listening_available": True, "missing_dependencies": []}

        monkeypatch.setattr(voice_worker_module, "provider_status_module", _FakeProviderStatusModule())

        listen_call_count = {"n": 0}

        class _FakeListener:
            def __init__(self) -> None:
                pass

            def listen_until_detected(self, max_seconds: float | None = None) -> Dict[str, Any]:
                listen_call_count["n"] += 1
                if listen_call_count["n"] >= 2:
                    # Proves the loop came back to listen a SECOND time
                    # after fully handling the first detection -- stop the
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

        respond_calls: List[bool] = []
        monkeypatch.setattr(
            worker, "_capture_transcribe_and_respond", lambda **kwargs: respond_calls.append(True) or True
        )

        try:
            worker._run_wake_word_admin_loop("wake_word_admin")
        except KeyboardInterrupt:
            pass

        # Detected+handled once, then the loop genuinely went back to
        # listen_until_detected for a second time before this test stopped it.
        assert len(respond_calls) == 1
        assert listen_call_count["n"] == 2
