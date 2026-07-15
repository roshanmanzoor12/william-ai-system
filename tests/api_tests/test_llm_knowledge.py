"""
tests/api_tests/test_llm_knowledge.py

Real HTTP tests for the LLM "brain" layer (core/llm_provider.py) wired
into apps/api/routes/assistant.py -- GET /assistant/llm/status and
knowledge-question dispatch through POST /assistant/message. No
WILLIAM_LLM_PROVIDER is set in the test environment, so every knowledge
question here exercises the honest "not configured" path -- a real
configured-provider call is out of reach without a live LLM endpoint,
matching this repo's existing pattern for STT/TTS provider tests.
"""

from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _clear_llm_env(monkeypatch):
    for key in ("WILLIAM_LLM_PROVIDER", "WILLIAM_LLM_BASE_URL", "WILLIAM_LLM_API_KEY", "WILLIAM_LLM_MODEL"):
        monkeypatch.delenv(key, raising=False)


class TestLlmStatusEndpoint:
    def test_requires_auth(self, client) -> None:
        response = client.get("/api/v1/assistant/llm/status")
        assert response.status_code in (401, 403)

    def test_reports_not_configured_by_default(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.get("/api/v1/assistant/llm/status", headers=owner.headers)
        assert response.status_code == 200
        status = response.json()["data"]["llm_provider"]
        assert status["configured"] is False
        assert status["reason"]
        assert status["install_guidance"]

    def test_reports_configured_once_env_set(self, client, make_owner, monkeypatch) -> None:
        monkeypatch.setenv("WILLIAM_LLM_PROVIDER", "ollama")
        monkeypatch.setenv("WILLIAM_LLM_BASE_URL", "http://localhost:11434/v1")
        monkeypatch.setenv("WILLIAM_LLM_MODEL", "llama3.1")
        owner = make_owner()
        response = client.get("/api/v1/assistant/llm/status", headers=owner.headers)
        status = response.json()["data"]["llm_provider"]
        assert status["configured"] is True
        assert status["reason"] is None


class TestKnowledgeQuestionDispatch:
    def test_unconfigured_llm_gives_honest_fallback(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post(
            "/api/v1/assistant/message",
            json={"message": "William what is moderation?"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["final_answer"] == "Boss, AI knowledge provider is not configured yet."
        assert data["status"] == "failed"
        assert data["generated_files"] == []

    def test_weather_question_never_faked(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post(
            "/api/v1/assistant/message",
            json={"message": "William current Lahore weather?"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response.json()["data"]
        assert data["final_answer"] == "Boss, live weather provider is not connected yet."

    def test_weather_fallback_wins_even_if_llm_is_configured(self, client, make_owner, monkeypatch) -> None:
        """A configured LLM must never be allowed to answer a live-data
        question -- the deterministic guard in core/llm_provider.py::
        is_live_data_query runs before any provider call, regardless of
        configuration state."""
        monkeypatch.setenv("WILLIAM_LLM_PROVIDER", "ollama")
        monkeypatch.setenv("WILLIAM_LLM_BASE_URL", "http://localhost:11434/v1")
        monkeypatch.setenv("WILLIAM_LLM_MODEL", "llama3.1")
        owner = make_owner()
        response = client.post(
            "/api/v1/assistant/message",
            json={"message": "What's the weather forecast today?"},
            headers=owner.headers,
        )
        data = response.json()["data"]
        assert data["final_answer"] == "Boss, live weather provider is not connected yet."

    def test_other_live_data_question_never_faked(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post(
            "/api/v1/assistant/message",
            json={"message": "What's today's news?"},
            headers=owner.headers,
        )
        data = response.json()["data"]
        assert "connected live/current data provider" in data["final_answer"]
