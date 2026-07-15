"""
tests/api_tests/test_voice_runtime_extras.py

Real HTTP tests for this phase's additions to the voice runtime layer:
per-workspace assistant_display_name, the honest wake-word-model mapping
(core/llm_provider.py-adjacent -- agents/voice_agent/provider_capabilities.py
::resolve_bundled_wake_word_model), worker-reported command timing, and
voice-command routing accuracy ("open Microsoft Store" must queue
open_microsoft_store, never open_notepad, and back-to-back different
commands must never reuse a stale transcript/action).

Broader cross-workspace isolation (memory, generated files, worker tasks,
voice profiles/push-to-talk/device-setup) is already covered by
tests/api_tests/test_memory.py, tests/api_tests/test_file_generation.py,
tests/api_tests/test_windows_worker_dispatch.py, tests/api_tests/
test_system_worker.py, and tests/api_tests/test_voice.py -- this file adds
only the isolation coverage for the fields introduced in this phase
(assistant_display_name, active_wake_word_model, last_command_timing) plus
the accuracy/no-stale-reuse regression tests.
"""

from __future__ import annotations


def response_json(response):
    return response.json()


class TestAssistantDisplayName:
    def test_defaults_to_william(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.get("/api/v1/voice/status", headers=owner.headers)
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert data["assistant_display_name"] == "William"
        assert data["settings"]["assistant_display_name"] == "William"

    def test_save_updates_display_name(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post(
            "/api/v1/voice/config",
            json={"assistant_display_name": "Jarvis"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        assert response_json(response)["data"]["settings"]["assistant_display_name"] == "Jarvis"

        status_response = client.get("/api/v1/voice/status", headers=owner.headers)
        assert response_json(status_response)["data"]["assistant_display_name"] == "Jarvis"

    def test_assistant_display_name_is_workspace_isolated(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()

        client.post(
            "/api/v1/voice/config",
            json={"assistant_display_name": "Sara"},
            headers=owner_a.headers,
        )

        status_a = client.get("/api/v1/voice/status", headers=owner_a.headers)
        status_b = client.get("/api/v1/voice/status", headers=owner_b.headers)

        assert response_json(status_a)["data"]["assistant_display_name"] == "Sara"
        assert response_json(status_b)["data"]["assistant_display_name"] == "William"


class TestActiveWakeWordModel:
    def test_default_william_reports_honest_custom_model_notice(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.get("/api/v1/voice/status", headers=owner.headers)
        data = response_json(response)["data"]
        assert data["active_wake_word_model"] == "hey_jarvis"
        assert data["wake_word_matches_supported_model"] is False
        assert data["wake_word_custom_model_notice"] == (
            "This wake word requires a custom model. Current active local model is hey_jarvis."
        )

    def test_supported_phrase_has_no_notice(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"wake_word": "hey_jarvis"}, headers=owner.headers)
        response = client.get("/api/v1/voice/status", headers=owner.headers)
        data = response_json(response)["data"]
        assert data["active_wake_word_model"] == "hey_jarvis"
        assert data["wake_word_matches_supported_model"] is True
        assert data["wake_word_custom_model_notice"] is None

    def test_wake_word_settings_are_workspace_isolated(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()

        client.post("/api/v1/voice/config", json={"wake_word": "hey_jarvis"}, headers=owner_a.headers)

        status_a = client.get("/api/v1/voice/status", headers=owner_a.headers)
        status_b = client.get("/api/v1/voice/status", headers=owner_b.headers)

        assert response_json(status_a)["data"]["settings"]["wake_word"] == "hey_jarvis"
        assert response_json(status_b)["data"]["settings"]["wake_word"] == "william"


class TestCommandTiming:
    def test_timing_ms_is_stored_and_workspace_isolated(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()

        response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"text": "William what is moderation?", "timing_ms": {"wake_detect_ms": 12.5, "stt_ms": 0.0}},
            headers=owner_a.headers,
        )
        assert response.status_code == 200
        assert response_json(response)["data"]["timing_ms"] == {"wake_detect_ms": 12.5, "stt_ms": 0.0}

        status_a = client.get("/api/v1/voice/status", headers=owner_a.headers)
        status_b = client.get("/api/v1/voice/status", headers=owner_b.headers)

        assert response_json(status_a)["data"]["last_command_timing"] == {"wake_detect_ms": 12.5, "stt_ms": 0.0}
        assert response_json(status_b)["data"]["last_command_timing"] is None

    def test_omitted_timing_does_not_error(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"text": "William what is moderation?"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        assert "timing_ms" not in response_json(response)["data"]


class TestVoiceCommandRoutingAccuracy:
    """Regression coverage: 'open Microsoft Store' must never open Notepad,
    and consecutive different commands must never reuse a stale transcript
    or replay an old WorkerTask."""

    def _queued_action_types(self, workspace_id: str) -> list:
        from database.db import db_manager
        from database.models.worker_task import WorkerTaskService

        with db_manager.session_scope() as db:
            tasks = WorkerTaskService.list_queued_for_workspace(db, workspace_id=workspace_id)
            return [t.action_type for t in tasks]

    def test_open_microsoft_store_queues_correct_action(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/system/worker/heartbeat", json={"platform": "windows"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"text": "William open Microsoft Store"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert "Microsoft Store" in data["final_answer"]

        action_types = self._queued_action_types(owner.workspace_id)
        assert "open_microsoft_store" in action_types
        assert "open_notepad" not in action_types

    def test_open_notepad_queues_correct_action(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/system/worker/heartbeat", json={"platform": "windows"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"text": "William open Notepad"},
            headers=owner.headers,
        )
        assert response.status_code == 200

        action_types = self._queued_action_types(owner.workspace_id)
        assert "open_notepad" in action_types
        assert "open_microsoft_store" not in action_types

    def test_consecutive_different_commands_do_not_reuse_stale_transcript(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/system/worker/heartbeat", json={"platform": "windows"}, headers=owner.headers)

        first = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"text": "William open Notepad"},
            headers=owner.headers,
        )
        second = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"text": "William open Microsoft Store"},
            headers=owner.headers,
        )

        first_task_id = response_json(first)["data"]["worker_task_id"]
        second_task_id = response_json(second)["data"]["worker_task_id"]

        assert first_task_id
        assert second_task_id
        assert first_task_id != second_task_id

        status_response = client.get("/api/v1/voice/status", headers=owner.headers)
        # The LATEST command's transcript is what /voice/status reflects --
        # never the first command's, proving no stale reuse.
        assert "Microsoft Store" in response_json(status_response)["data"]["last_command"]
