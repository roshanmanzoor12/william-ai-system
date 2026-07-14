"""
tests/worker_tests/test_windows_worker_auth_messages.py

Phase 8 coverage (Windows Worker side): apps/worker_nodes/windows/
windows_worker.py::WindowsWorker._auth_failure_message() must print the
right one of two exact messages depending on which credential was actually
in use -- a dev-mode JWT simply expiring is not the same situation as an
installed device token being revoked, and the operator needs to know which
one happened to know what to do next.

Pure unit test of the helper -- no real HTTP, no real 401 round trip
(that end-to-end behavior is covered by run_forever()'s existing
DeviceAuthError handling, exercised indirectly by
tests/worker_tests/test_voice_worker.py's TestAuthFailureCleanStop for the
voice worker's equivalent).
"""

from __future__ import annotations

from apps.worker_nodes.windows.windows_worker import WindowsWorker, WorkerConfig


class TestAuthFailureMessage:
    def test_jwt_only_reports_expired(self) -> None:
        config = WorkerConfig(worker_token="some-jwt", device_token="")
        worker = WindowsWorker(config)
        assert worker._auth_failure_message() == "[worker] JWT expired. Use installed device-token worker or login again."

    def test_device_token_reports_revoked(self) -> None:
        config = WorkerConfig(worker_token="", device_token="some-device-token")
        worker = WindowsWorker(config)
        assert worker._auth_failure_message() == "[worker] Device token revoked. Re-enable worker from dashboard."

    def test_both_set_prefers_device_token_message(self) -> None:
        """Matches _headers()'s own effective_token precedence -- if both
        happen to be set, the device token is what's actually sent on the
        wire, so a 401 reflects that credential's state, not the JWT's."""
        config = WorkerConfig(worker_token="some-jwt", device_token="some-device-token")
        worker = WindowsWorker(config)
        assert worker._auth_failure_message() == "[worker] Device token revoked. Re-enable worker from dashboard."

    def test_neither_set_reports_expired_as_the_safe_default(self) -> None:
        config = WorkerConfig(worker_token="", device_token="")
        worker = WindowsWorker(config)
        assert worker._auth_failure_message() == "[worker] JWT expired. Use installed device-token worker or login again."
