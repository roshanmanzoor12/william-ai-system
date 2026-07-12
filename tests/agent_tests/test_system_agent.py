"""
tests/agent_tests/test_system_agent.py

Tests for SystemAgent.open_app/close_app's honest device-worker gating
(agents/system_agent/system_agent.py). Before this session's fix, these
methods either executed a real subprocess command on the BACKEND SERVER's
own host, or returned a vague "dry-run" message -- neither told the caller
the backend cannot open apps on THEIR machine without a connected Windows
device worker. Now they always return device_worker_offline (no worker has
ever checked in for this workspace) or external_dependency_required (a
worker is connected, but the real remote task-dispatch protocol isn't built
yet), and never execute anything locally.
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
    async def test_open_microsoft_store_without_worker_returns_device_worker_offline(
        self,
    ) -> None:
        agent = SystemAgent()
        context = make_context()

        result = await agent.open_app({"app": "Microsoft Store"}, context)

        assert result["success"] is False
        assert result["error"] == "device_worker_offline"
        assert result["metadata"]["runtime_state"] == "device_worker_offline"
        assert result["message"] == (
            "I can open Microsoft Store only when the Windows device worker is connected."
        )

    @pytest.mark.asyncio
    async def test_open_other_app_without_worker_returns_device_worker_offline(
        self,
    ) -> None:
        agent = SystemAgent()
        context = make_context()

        result = await agent.open_app({"app": "Notepad"}, context)

        assert result["success"] is False
        assert result["error"] == "device_worker_offline"
        assert result["metadata"]["runtime_state"] == "device_worker_offline"
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
    async def test_close_app_without_worker_returns_device_worker_offline(self) -> None:
        agent = SystemAgent()
        context = make_context()

        result = await agent.close_app({"app": "Calculator"}, context)

        assert result["success"] is False
        assert result["metadata"]["runtime_state"] == "device_worker_offline"

    @pytest.mark.asyncio
    async def test_open_app_missing_app_name_is_a_structured_error(self) -> None:
        agent = SystemAgent()
        context = make_context()

        result = await agent.open_app({}, context)

        assert result["success"] is False
        assert result["error"] == "missing_app"
