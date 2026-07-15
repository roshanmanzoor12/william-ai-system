"""
tests/worker_tests/test_voice_providers.py

Phase 9 coverage (items 1, 2): apps/worker_nodes/voice/providers/*.py must
never claim a provider is "configured" just because a package happens to
be importable -- the matching WILLIAM_*_PROVIDER env var must also be set.
Runs against this test environment's REAL package set (no mocking of
imports) -- pyttsx3/sounddevice/numpy are genuinely installed here, while
faster-whisper/openwakeword genuinely are not, so these tests exercise
both branches honestly rather than simulating them.
"""

from __future__ import annotations

import os

import pytest

from apps.worker_nodes.voice.providers import audio_input, stt, tts, wake_word, provider_status


@pytest.fixture(autouse=True)
def _clean_voice_env(monkeypatch):
    """Every test starts with a clean slate for the provider env vars --
    otherwise a real .env loaded elsewhere in the process could leak in
    and make these tests order-dependent."""
    for var in (
        "WILLIAM_AUDIO_INPUT_PROVIDER",
        "WILLIAM_STT_PROVIDER",
        "WILLIAM_TTS_PROVIDER",
        "WILLIAM_WAKE_WORD_PROVIDER",
        "WILLIAM_SPEAKER_RECOGNITION_PROVIDER",
    ):
        monkeypatch.delenv(var, raising=False)


class TestAudioInputStatus:
    def test_dependency_required_without_env_var(self) -> None:
        status = audio_input.check_status()
        assert status["available"] is False
        assert "WILLIAM_AUDIO_INPUT_PROVIDER" in status["reason"]

    def test_configured_when_env_set_and_device_present(self) -> None:
        if not audio_input.is_available():
            pytest.skip("sounddevice/numpy not installed in this environment")
        devices = audio_input.list_devices()
        if not devices:
            pytest.skip("no real input device attached to this test environment")
        os.environ["WILLIAM_AUDIO_INPUT_PROVIDER"] = "local_microphone"
        try:
            status = audio_input.check_status()
            assert status["available"] is True
            assert status["devices"]
        finally:
            del os.environ["WILLIAM_AUDIO_INPUT_PROVIDER"]


class TestSttStatus:
    def test_dependency_required_without_provider_env_var(self) -> None:
        status = stt.check_status()
        assert status["configured"] is False
        assert "faster-whisper" in status["install_guidance"] or "WILLIAM_STT" in status["install_guidance"]

    def test_dependency_required_when_faster_whisper_not_installed(self) -> None:
        if stt.local_package_available():
            pytest.skip("faster-whisper is installed in this environment; this checks the not-installed branch")
        os.environ["WILLIAM_STT_PROVIDER"] = "faster_whisper"
        try:
            status = stt.check_status()
            assert status["configured"] is False
            assert "faster-whisper" in status["install_guidance"]
        finally:
            del os.environ["WILLIAM_STT_PROVIDER"]


class TestTtsStatus:
    def test_dependency_required_without_provider_env_var(self) -> None:
        status = tts.check_status()
        assert status["configured"] is False

    def test_configured_when_pyttsx3_available_and_env_set(self) -> None:
        if not tts.local_package_available():
            pytest.skip("pyttsx3 not installed in this environment")
        os.environ["WILLIAM_TTS_PROVIDER"] = "pyttsx3"
        try:
            status = tts.check_status()
            assert status["configured"] is True
        finally:
            del os.environ["WILLIAM_TTS_PROVIDER"]

    def test_install_guidance_names_pip_install_when_package_missing(self) -> None:
        if tts.local_package_available():
            pytest.skip("pyttsx3 is installed in this environment; this checks the not-installed branch")
        status = tts.check_status()
        assert "pip install" in status["install_guidance"]


class TestWakeWordStatus:
    def test_dependency_required_when_openwakeword_not_installed(self) -> None:
        if wake_word.local_package_available():
            pytest.skip("openwakeword is installed in this environment; this checks the not-installed branch")
        os.environ["WILLIAM_WAKE_WORD_PROVIDER"] = "openwakeword"
        try:
            status = wake_word.check_status()
            assert status["configured"] is False
            assert "openwakeword" in status["install_guidance"]
        finally:
            del os.environ["WILLIAM_WAKE_WORD_PROVIDER"]


class TestProviderStatusAggregate:
    def test_full_status_shape(self) -> None:
        result = provider_status.get_full_status()
        for key in (
            "audio_input_status",
            "stt_status",
            "tts_status",
            "wake_word_status",
            "speaker_recognition_status",
            "real_microphone_available",
            "speech_output_available",
            "always_listening_available",
            "text_command_available",
            "missing_dependencies",
            "setup_commands",
        ):
            assert key in result, f"{key} missing from get_full_status()"
        assert result["text_command_available"] is True

    def test_always_listening_unavailable_when_nothing_configured(self) -> None:
        result = provider_status.get_full_status()
        assert result["always_listening_available"] is False

    def test_missing_dependencies_lists_every_unconfigured_provider(self) -> None:
        result = provider_status.get_full_status()
        for key in ("audio_input_worker", "stt_provider", "tts_provider", "wake_word_provider"):
            assert key in result["missing_dependencies"]

    def test_setup_commands_reference_real_scripts(self) -> None:
        result = provider_status.get_full_status()
        assert "install_voice_dependencies.ps1" in result["setup_commands"]["install_dependencies"]
        assert "check_voice_dependencies.ps1" in result["setup_commands"]["check_dependencies"]
