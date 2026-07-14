"""
tests/scripts_tests/test_windows_worker_scripts.py

Static-content coverage for scripts/windows/*.ps1 (Phase 8, item 16: "auto-
start scripts exist and include expected commands"). This environment has
no Windows PowerShell execution available for these tests to actually run
the scripts against a live backend -- these are plain string/AST-shape
checks confirming the 3 files exist and reference the right cmdlets,
endpoints, and config path, not an execution/integration test. Real
end-to-end verification of these scripts requires running them on an
actual Windows machine (see the final report's manual verification notes).
"""

from __future__ import annotations

from pathlib import Path

import pytest

SCRIPTS_DIR = Path(__file__).resolve().parents[2] / "scripts" / "windows"


@pytest.fixture(scope="module")
def install_script() -> str:
    return (SCRIPTS_DIR / "install_windows_worker.ps1").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def start_script() -> str:
    return (SCRIPTS_DIR / "start_windows_worker.ps1").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def uninstall_script() -> str:
    return (SCRIPTS_DIR / "uninstall_windows_worker.ps1").read_text(encoding="utf-8")


class TestScriptsExist:
    def test_all_three_scripts_exist(self) -> None:
        for name in ("install_windows_worker.ps1", "start_windows_worker.ps1", "uninstall_windows_worker.ps1"):
            assert (SCRIPTS_DIR / name).exists(), f"{name} is missing from scripts/windows/"


class TestInstallScript:
    def test_registers_device_via_setup_token(self, install_script: str) -> None:
        assert "Invoke-RestMethod" in install_script
        assert "/system/device/register" in install_script
        assert "$SetupToken" in install_script

    def test_saves_device_token_config(self, install_script: str) -> None:
        assert "windows_worker.json" in install_script
        assert "device_token" in install_script
        assert ".william" in install_script

    def test_registers_auto_start_scheduled_task(self, install_script: str) -> None:
        assert "Register-ScheduledTask" in install_script
        assert "AtLogOn" in install_script
        assert "WilliamWindowsWorker" in install_script

    def test_falls_back_to_startup_shortcut(self, install_script: str) -> None:
        assert "Startup" in install_script
        assert "WScript.Shell" in install_script

    def test_starts_worker_after_install(self, install_script: str) -> None:
        assert "start_windows_worker.ps1" in install_script
        assert "installed and connected" in install_script


class TestStartScript:
    def test_invokes_worker_module_with_config(self, start_script: str) -> None:
        assert "python -m apps.worker_nodes.windows.windows_worker" in start_script
        assert "--config" in start_script

    def test_defaults_to_standard_config_path(self, start_script: str) -> None:
        assert "windows_worker.json" in start_script


class TestUninstallScript:
    def test_removes_scheduled_task(self, uninstall_script: str) -> None:
        assert "Unregister-ScheduledTask" in uninstall_script
        assert "WilliamWindowsWorker" in uninstall_script

    def test_can_call_disable_endpoint(self, uninstall_script: str) -> None:
        assert "/system/device/disable" in uninstall_script
        assert "Invoke-RestMethod" in uninstall_script

    def test_config_removal_is_optional(self, uninstall_script: str) -> None:
        assert "RemoveConfig" in uninstall_script
