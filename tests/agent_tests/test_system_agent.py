"""
tests/agent_tests/test_system_agent.py

Tests for SystemAgent.open_app/close_app's honest device-worker gating
(agents/system_agent/system_agent.py). These methods never execute a real
subprocess on the BACKEND SERVER's own host and never claim success
without a connected Windows device worker.

Since the device setup-token/device-token flow (apps/api/routes/
device_setup.py) landed, "no worker" is no longer one flat state: a
workspace that has NEVER completed the Enable Windows Worker flow reads
"not_enabled" (this file's scenario -- a brand-new, never-seen-before
workspace_id), distinct from "disabled" (explicitly revoked from Settings)
and "device_worker_offline" (was set up and working, just hasn't
heartbeated recently). See database/models/system_worker.py::
compute_connection_state for the single source of truth these 3 states
come from.
"""

from __future__ import annotations

import uuid

import pytest

from agents.system_agent.system_agent import SystemAgent, TaskContext


def make_context(workspace_id: str | None = None) -> TaskContext:
    return TaskContext(
        user_id=f"user_{uuid.uuid4().hex[:12]}",
        workspace_id=workspace_id or f"workspace_{uuid.uuid4().hex[:12]}",
        request_id=f"req_{uuid.uuid4().hex[:12]}",
    )


class TestSystemAgentDeviceGating:
    @pytest.mark.asyncio
    async def test_open_microsoft_store_without_worker_returns_not_enabled(
        self,
    ) -> None:
        agent = SystemAgent()
        context = make_context()

        result = await agent.open_app({"app": "Microsoft Store"}, context)

        assert result["success"] is False
        assert result["error"] == "not_enabled"
        assert result["metadata"]["runtime_state"] == "not_enabled"
        assert result["message"] == (
            "I can open Microsoft Store once Windows Worker is enabled. Set it up from Settings > Devices."
        )

    @pytest.mark.asyncio
    async def test_open_other_app_without_worker_returns_not_enabled(
        self,
    ) -> None:
        agent = SystemAgent()
        context = make_context()

        result = await agent.open_app({"app": "Notepad"}, context)

        assert result["success"] is False
        assert result["error"] == "not_enabled"
        assert result["metadata"]["runtime_state"] == "not_enabled"
        assert "Notepad" in result["message"]

    @pytest.mark.asyncio
    async def test_open_app_never_executes_locally(self, monkeypatch) -> None:
        """Regression guard: this method must never shell out on the
        backend's own host, regardless of worker state."""
        agent = SystemAgent()
        context = make_context()

        def _fail_if_called(*args, **kwargs):
            raise AssertionError("open_app must never execute a local subprocess")

        monkeypatch.setattr(
            "agents.system_agent.system_agent.subprocess.Popen",
            _fail_if_called,
            raising=False,
        )
        monkeypatch.setattr(
            "agents.system_agent.system_agent.subprocess.run",
            _fail_if_called,
            raising=False,
        )

        result = await agent.open_app({"app": "Microsoft Store"}, context)
        assert result["success"] is False

    @pytest.mark.asyncio
    async def test_close_app_without_worker_returns_not_enabled(self) -> None:
        agent = SystemAgent()
        context = make_context()

        result = await agent.close_app({"app": "Calculator"}, context)

        assert result["success"] is False
        assert result["metadata"]["runtime_state"] == "not_enabled"

    @pytest.mark.asyncio
    async def test_open_app_missing_app_name_is_a_structured_error(self) -> None:
        agent = SystemAgent()
        context = make_context()

        result = await agent.open_app({}, context)

        assert result["success"] is False
        assert result["error"] == "missing_app"
