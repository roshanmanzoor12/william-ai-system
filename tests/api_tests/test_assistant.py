"""
tests/api_tests/test_assistant.py

Real HTTP tests for apps/api/routes/assistant.py -- Phase 1's Conversational
Assistant Brain. Uses the real JWT auth fixtures (make_owner/make_member,
tests/api_tests/conftest.py) against the real FastAPI app, matching every
other file in this directory.
"""

from __future__ import annotations


def response_json(response):
    return response.json()


class TestFinalAnswerShape:
    def test_requires_auth(self, client) -> None:
        response = client.post("/api/v1/assistant/message", json={"message": "hello"})
        assert response.status_code in (401, 403)

    def test_flat_envelope_fields_present(self, client, make_owner) -> None:
        owner = make_owner()

        response = client.post(
            "/api/v1/assistant/message",
            json={"message": "What is the capital of France?"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]

        # Every field must be reachable at the top level -- never nested
        # inside data.result.results[...] for the caller to dig through.
        for field in ("final_answer", "follow_up_questions", "status", "route", "generated_files", "error"):
            assert field in data, f"{field} missing from assistant response"

        assert isinstance(data["final_answer"], str)
        assert data["final_answer"].strip() != ""
        assert isinstance(data["follow_up_questions"], list)
        assert isinstance(data["route"], list)
        assert data["generated_files"] == []


class TestVeoPromptFlow:
    def test_veo_prompt_asks_clarification(self, client, make_owner) -> None:
        owner = make_owner()

        response = client.post(
            "/api/v1/assistant/message",
            json={"message": "William create a VEO prompt for ClickRonix"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]

        assert data["status"] == "waiting_for_user"
        assert len(data["follow_up_questions"]) == 4
        assert data["conversation_thread_id"]
        assert data["generated_files"] == []

    def test_follow_up_continues_pending_task(self, client, make_owner) -> None:
        owner = make_owner()

        first = client.post(
            "/api/v1/assistant/message",
            json={"message": "William create a VEO prompt for ClickRonix"},
            headers=owner.headers,
        )
        thread_id = response_json(first)["data"]["conversation_thread_id"]

        second = client.post(
            "/api/v1/assistant/message",
            json={
                "message": "here you go",
                "conversation_thread_id": thread_id,
                "collected_inputs": {
                    "style": "cinematic cybersecurity",
                    "duration": "15s",
                    "main_visual": "shield",
                    "cta": "Get Protected Now",
                },
            },
            headers=owner.headers,
        )
        assert second.status_code == 200
        second_data = response_json(second)["data"]

        # Same thread id proves this was a continuation, not a new thread.
        assert second_data["conversation_thread_id"] == thread_id
        assert second_data["status"] == "completed"

    def test_final_veo_prompt_generated_from_collected_fields(self, client, make_owner) -> None:
        owner = make_owner()

        first = client.post(
            "/api/v1/assistant/message",
            json={"message": "William create a VEO prompt for ClickRonix"},
            headers=owner.headers,
        )
        thread_id = response_json(first)["data"]["conversation_thread_id"]

        second = client.post(
            "/api/v1/assistant/message",
            json={
                "message": "here you go",
                "conversation_thread_id": thread_id,
                "collected_inputs": {
                    "style": "cinematic cybersecurity",
                    "duration": "15s",
                    "main_visual": "shield",
                    "cta": "Get Protected Now",
                },
            },
            headers=owner.headers,
        )
        data = response_json(second)["data"]

        # Proves the template actually used the collected fields (and the
        # brand extracted from the ORIGINAL request), not hardcoded defaults.
        assert "shield" in data["final_answer"]
        assert "cinematic cybersecurity" in data["final_answer"]
        assert "Get Protected Now" in data["final_answer"]
        assert "ClickRonix" in data["final_answer"]
        assert data["route"] == ["creator"]
        assert data["error"] is None

    def test_follow_up_can_be_answered_with_free_text(self, client, make_owner) -> None:
        owner = make_owner()

        first = client.post(
            "/api/v1/assistant/message",
            json={"message": "William create a VEO prompt for ClickRonix"},
            headers=owner.headers,
        )
        thread_id = response_json(first)["data"]["conversation_thread_id"]

        second = client.post(
            "/api/v1/assistant/message",
            json={
                "message": 'cinematic cybersecurity, 15s, shield, CTA: Get Protected Now',
                "conversation_thread_id": thread_id,
            },
            headers=owner.headers,
        )
        data = response_json(second)["data"]
        assert data["status"] == "completed"
        assert "Get Protected Now" in data["final_answer"]


class TestKnowledgeQuestionHonesty:
    def test_knowledge_question_never_crashes_and_is_honest(self, client, make_owner) -> None:
        owner = make_owner()

        response = client.post(
            "/api/v1/assistant/message",
            json={"message": "What is the capital of France?"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]

        # Never fakes success -- if it failed, there must be a real error.
        if data["status"] == "failed":
            assert data["error"] is not None
        assert data["generated_files"] == []


class TestMultiTaskIsolation:
    def test_unrelated_message_does_not_disturb_pending_thread(self, client, make_owner) -> None:
        owner = make_owner()

        pending = client.post(
            "/api/v1/assistant/message",
            json={"message": "William create a VEO prompt for ClickRonix"},
            headers=owner.headers,
        )
        pending_thread_id = response_json(pending)["data"]["conversation_thread_id"]

        # A second, unrelated message with no thread id must start its own
        # brand-new thread, never touching the pending one.
        unrelated = client.post(
            "/api/v1/assistant/message",
            json={"message": "What is the capital of France?"},
            headers=owner.headers,
        )
        unrelated_thread_id = response_json(unrelated)["data"]["conversation_thread_id"]
        assert unrelated_thread_id != pending_thread_id

        # The pending thread must still be exactly as it was.
        reloaded = client.get(f"/api/v1/assistant/threads/{pending_thread_id}", headers=owner.headers)
        assert reloaded.status_code == 200
        reloaded_data = response_json(reloaded)["data"]
        assert reloaded_data["status"] == "waiting_for_user"
        assert reloaded_data["collected_inputs"] == {}

    def test_second_user_cannot_read_or_continue_first_users_thread(
        self, client, make_owner
    ) -> None:
        owner_a = make_owner()
        owner_b = make_owner()

        started = client.post(
            "/api/v1/assistant/message",
            json={"message": "William create a VEO prompt for ClickRonix"},
            headers=owner_a.headers,
        )
        thread_id = response_json(started)["data"]["conversation_thread_id"]

        leaked_read = client.get(f"/api/v1/assistant/threads/{thread_id}", headers=owner_b.headers)
        assert leaked_read.status_code == 404

        leaked_continue = client.post(
            "/api/v1/assistant/message",
            json={
                "message": "here",
                "conversation_thread_id": thread_id,
                "collected_inputs": {"style": "product ad", "duration": "8s", "main_visual": "globe", "cta": "Go"},
            },
            headers=owner_b.headers,
        )
        assert leaked_continue.status_code == 404

    def test_unknown_thread_id_is_404_not_silently_ignored(self, client, make_owner) -> None:
        owner = make_owner()

        response = client.post(
            "/api/v1/assistant/message",
            json={"message": "hi", "conversation_thread_id": "conv_does_not_exist"},
            headers=owner.headers,
        )
        assert response.status_code == 404
        assert response_json(response)["error"]["code"] == "THREAD_NOT_FOUND"
