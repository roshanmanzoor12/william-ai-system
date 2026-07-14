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

from typing import Any, Dict, List, Tuple

import pytest

from apps.worker_nodes.common.worker_client import WorkerResponse
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
