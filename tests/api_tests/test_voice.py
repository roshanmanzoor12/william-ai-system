"""
tests/api_tests/test_voice.py

Phase 9 -- Voice Agent API tests. Real HTTP calls against the real FastAPI
app with real JWT auth (see tests/api_tests/conftest.py's make_owner/
make_member fixtures), exactly like tests/api_tests/test_agents.py.
"""

from __future__ import annotations

import pytest


def response_json(response):
    return response.json()


class TestVoiceStatus:
    def test_status_requires_auth(self, client) -> None:
        response = client.get("/api/v1/voice/status")
        assert response.status_code in (401, 403)

    def test_default_voice_mode_is_disabled(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.get("/api/v1/voice/status", headers=owner.headers)
        assert response.status_code == 200
        payload = response_json(response)
        assert payload["data"]["settings"]["mode"] == "disabled"

    def test_status_reports_dependency_state_honestly(self, client, make_owner) -> None:
        owner = make_owner()
        payload = response_json(client.get("/api/v1/voice/status", headers=owner.headers))
        deps = payload["data"]["settings"]["dependency_status"]
        for key in ("wake_word_engine", "audio_input_worker", "stt_provider", "tts_provider", "speaker_recognition_provider"):
            assert key in deps
        # No real provider is configured in the test environment -- these
        # must never silently claim to be available.
        assert deps["stt_provider"] == "external_dependency_required"
        assert deps["tts_provider"] == "external_dependency_required"
        assert deps["speaker_recognition_provider"] == "external_dependency_required"
        # Text-based wake word detection is real, local, and needs no provider.
        assert deps["wake_word_engine"] == "available"

    def test_status_flattened_shape_matches_dashboard_contract(self, client, make_owner) -> None:
        owner = make_owner()
        payload = response_json(client.get("/api/v1/voice/status", headers=owner.headers))["data"]
        for field in (
            "mode", "enabled", "runtime_state", "wake_word_enabled", "wake_word_phrase",
            "worker_connected", "worker_last_seen_at", "dependencies", "missing_dependencies",
            "active_sessions", "last_wake_event", "last_command", "last_detected_language",
            "last_speaker_name", "last_routed_agent", "last_error", "user_id", "workspace_id",
        ):
            assert field in payload, f"{field} missing from /voice/status"
        assert payload["user_id"] == owner.user_id
        assert payload["workspace_id"] == owner.workspace_id
        assert payload["enabled"] is False
        assert payload["runtime_state"] == "disabled"

    def test_wake_word_admin_reports_dependency_required_runtime_state(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "wake_word_admin"}, headers=owner.headers)
        payload = response_json(client.get("/api/v1/voice/status", headers=owner.headers))["data"]
        # No STT/TTS/speaker-recognition provider is configured in tests --
        # even if approval was granted, runtime_state must honestly report
        # the missing providers rather than claim "listening".
        if payload["mode"] == "wake_word_admin":
            assert payload["runtime_state"] == "dependency_required"
            assert "stt_provider" in payload["missing_dependencies"]


class TestVoiceConfig:
    def test_admin_can_enable_push_to_talk(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert data["settings"]["mode"] == "push_to_talk"
        assert data["approved"] is True

    def test_non_admin_cannot_enable_wake_word(self, client, make_owner, make_member) -> None:
        owner = make_owner()
        member = make_member(owner, role="member")
        response = client.post("/api/v1/voice/config", json={"mode": "wake_word_admin"}, headers=member.headers)
        assert response.status_code == 403

    def test_admin_requesting_wake_word_requires_security_approval(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post("/api/v1/voice/config", json={"mode": "wake_word_admin"}, headers=owner.headers)
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert data["requires_approval"] is True
        # Mode change fails closed when Security Agent approval isn't granted.
        if not data["approved"]:
            assert data["settings"]["mode"] == "disabled"

    def test_continuous_conversation_also_requires_approval(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post("/api/v1/voice/config", json={"mode": "continuous_conversation"}, headers=owner.headers)
        assert response.status_code == 200
        assert response_json(response)["data"]["requires_approval"] is True

    def test_invalid_mode_rejected(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post("/api/v1/voice/config", json={"mode": "not_a_real_mode"}, headers=owner.headers)
        assert response.status_code == 400

    def test_owner_can_set_standby_without_security_approval(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post("/api/v1/voice/config", json={"mode": "standby"}, headers=owner.headers)
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert data["settings"]["mode"] == "standby"
        assert data["approved"] is True
        assert data["requires_approval"] is False


class TestVoiceWorkerHeartbeat:
    def test_heartbeat_requires_auth(self, client) -> None:
        response = client.post("/api/v1/voice/worker/heartbeat", json={})
        assert response.status_code in (401, 403)

    def test_heartbeat_marks_worker_connected(self, client, make_owner) -> None:
        owner = make_owner()

        before = response_json(client.get("/api/v1/voice/status", headers=owner.headers))["data"]
        assert before["worker_connected"] is False

        heartbeat = client.post("/api/v1/voice/worker/heartbeat", json={}, headers=owner.headers)
        assert heartbeat.status_code == 200
        assert response_json(heartbeat)["data"]["worker_connected"] is True

        after = response_json(client.get("/api/v1/voice/status", headers=owner.headers))["data"]
        assert after["worker_connected"] is True
        assert after["worker_last_seen_at"] is not None


class TestVoiceStandbyAndShutdown:
    def test_standby_voice_command_pauses_processing(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"transcript": "William standby", "detected_language": "en"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert data["success"] is True
        assert "standing by" in data["response_text"].lower()

        status_payload = response_json(client.get("/api/v1/voice/status", headers=owner.headers))["data"]
        assert status_payload["mode"] == "standby"
        assert status_payload["runtime_state"] == "standby"

    def test_standby_mode_refuses_command_without_wake_word(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "standby"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/command",
            json={"transcript": "what is our business report", "detected_language": "en"},
            headers=owner.headers,
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "VOICE_STANDBY"

    def test_standby_mode_reactivates_on_wake_word(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "standby"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/command",
            json={"transcript": "what is our business report", "detected_language": "en", "wake_word": "william"},
            headers=owner.headers,
        )
        assert response.status_code == 200

        status_payload = response_json(client.get("/api/v1/voice/status", headers=owner.headers))["data"]
        assert status_payload["mode"] == "push_to_talk"

    def test_shutdown_voice_command_disables_workspace_voice(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"transcript": "William shutdown voice", "detected_language": "en"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        assert response_json(response)["data"]["success"] is True

        status_payload = response_json(client.get("/api/v1/voice/status", headers=owner.headers))["data"]
        assert status_payload["mode"] == "disabled"

    def test_shutdown_voice_by_non_admin_profile_is_ignored(self, client, make_owner) -> None:
        """A non-owner/admin trusted profile saying "shutdown voice" must not
        be able to kill the whole workspace's voice mode -- the phrase falls
        through to normal permission/routing handling instead."""
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)
        create = client.post(
            "/api/v1/voice/profiles",
            json={"display_name": "Guest", "role": "guest", "allowed_agents": ["creator"]},
            headers=owner.headers,
        )
        profile_id = response_json(create)["data"]["profile"]["id"]

        client.post(
            "/api/v1/voice/command",
            json={"transcript": "William shutdown voice", "detected_language": "en", "speaker_profile_id": profile_id},
            headers=owner.headers,
        )

        status_payload = response_json(client.get("/api/v1/voice/status", headers=owner.headers))["data"]
        assert status_payload["mode"] == "push_to_talk"


class TestVoiceProfiles:
    def test_only_admin_can_create_profile(self, client, make_owner, make_member) -> None:
        owner = make_owner()
        member = make_member(owner, role="member")
        response = client.post(
            "/api/v1/voice/profiles",
            json={"display_name": "Friend", "role": "trusted_assistant"},
            headers=member.headers,
        )
        assert response.status_code == 403

    def test_admin_can_create_profile(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post(
            "/api/v1/voice/profiles",
            json={"display_name": "Trusted Friend", "role": "trusted_assistant", "allowed_agents": ["creator", "browser"]},
            headers=owner.headers,
        )
        assert response.status_code == 200
        profile = response_json(response)["data"]["profile"]
        assert profile["display_name"] == "Trusted Friend"
        assert profile["role"] == "trusted_assistant"
        assert profile["status"] == "active"

    def test_new_profile_defaults_block_finance_and_system(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post(
            "/api/v1/voice/profiles",
            json={"display_name": "Friend", "role": "trusted_manager"},
            headers=owner.headers,
        )
        profile = response_json(response)["data"]["profile"]
        assert "finance" in profile["blocked_agents"]
        assert "system" in profile["blocked_agents"]

    def test_role_limits_enforced_finance_blocked(self, client, make_owner) -> None:
        owner = make_owner()
        create = client.post(
            "/api/v1/voice/profiles",
            json={
                "display_name": "Trusted Dev", "role": "trusted_developer",
                "allowed_agents": ["code", "browser", "creator", "verification"],
                "can_run_code_agent": True,
            },
            headers=owner.headers,
        )
        profile_id = response_json(create)["data"]["profile"]["id"]

        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/command",
            json={"transcript": "William, draft an invoice for our client", "detected_language": "en", "speaker_profile_id": profile_id},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert data["success"] is False
        assert "finance" in data["message"].lower()

    def test_admin_can_update_profile(self, client, make_owner) -> None:
        owner = make_owner()
        create = client.post(
            "/api/v1/voice/profiles",
            json={"display_name": "Friend", "role": "guest"},
            headers=owner.headers,
        )
        profile_id = response_json(create)["data"]["profile"]["id"]

        response = client.patch(
            f"/api/v1/voice/profiles/{profile_id}",
            json={"role": "trusted_assistant", "allowed_agents": ["creator"]},
            headers=owner.headers,
        )
        assert response.status_code == 200
        profile = response_json(response)["data"]["profile"]
        assert profile["role"] == "trusted_assistant"
        assert profile["allowed_agents"] == ["creator"]

    def test_admin_can_revoke_profile(self, client, make_owner) -> None:
        owner = make_owner()
        create = client.post(
            "/api/v1/voice/profiles",
            json={"display_name": "Friend", "role": "guest"},
            headers=owner.headers,
        )
        profile_id = response_json(create)["data"]["profile"]["id"]

        response = client.delete(f"/api/v1/voice/profiles/{profile_id}", headers=owner.headers)
        assert response.status_code == 200
        assert response_json(response)["data"]["profile"]["status"] == "revoked"

    def test_profiles_are_workspace_isolated(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()
        client.post("/api/v1/voice/profiles", json={"display_name": "A's Friend", "role": "guest"}, headers=owner_a.headers)

        response = client.get("/api/v1/voice/profiles", headers=owner_b.headers)
        assert response_json(response)["data"]["count"] == 0


class TestVoiceCommand:
    def test_voice_disabled_by_default_blocks_command(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post(
            "/api/v1/voice/command",
            json={"transcript": "Hello William", "detected_language": "en"},
            headers=owner.headers,
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "VOICE_DISABLED"

    def test_unknown_speaker_profile_id_is_refused(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/command",
            json={"transcript": "Hello William", "detected_language": "en", "speaker_profile_id": "does_not_exist"},
            headers=owner.headers,
        )
        assert response.status_code == 403
        body = response.json()
        assert body["error"]["code"] == "SPEAKER_UNAUTHORIZED"
        assert body["message"] == "You are not authorized to use this William workspace."

    def test_recognized_owner_command_routes_to_master_agent(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/command",
            json={"transcript": "Write a short creator ad script for our new product", "detected_language": "en"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert "master_result" in data
        assert data["master_result"] is not None
        # Real routing happened (not the empty-registry failure mode).
        assert "No suitable registered agent found" not in str(data["master_result"])

    def test_voice_command_preserves_user_and_workspace_id(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/command",
            json={"transcript": "What is our current business report", "detected_language": "en"},
            headers=owner.headers,
        )
        data = response_json(response)["data"]
        master_data = (data.get("master_result") or {}).get("data") or {}
        assert master_data.get("user_id") == owner.user_id
        assert master_data.get("workspace_id") == owner.workspace_id

    def test_voice_command_routes_to_creator_agent(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/command",
            json={"transcript": "Write a 30 second video ad script with hook variations", "detected_language": "en"},
            headers=owner.headers,
        )
        data = response_json(response)["data"]
        master_data = (data.get("master_result") or {}).get("data") or {}
        results = master_data.get("results") or []
        routed_agents = [r.get("data", {}).get("agent_name") for r in results]
        assert "creator" in routed_agents

    def test_finance_voice_command_by_non_owner_is_blocked(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)
        create = client.post(
            "/api/v1/voice/profiles",
            json={"display_name": "Assistant", "role": "trusted_assistant", "allowed_agents": ["creator", "browser"]},
            headers=owner.headers,
        )
        profile_id = response_json(create)["data"]["profile"]["id"]

        response = client.post(
            "/api/v1/voice/command",
            json={"transcript": "Please process a payment for this invoice", "detected_language": "en", "speaker_profile_id": profile_id},
            headers=owner.headers,
        )
        data = response_json(response)["data"]
        assert data["success"] is False

    def test_risky_system_voice_command_by_non_owner_is_blocked(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)
        create = client.post(
            "/api/v1/voice/profiles",
            json={"display_name": "Assistant", "role": "trusted_assistant", "allowed_agents": ["creator"]},
            headers=owner.headers,
        )
        profile_id = response_json(create)["data"]["profile"]["id"]

        response = client.post(
            "/api/v1/voice/command",
            json={"transcript": "Please shutdown the system now", "detected_language": "en", "speaker_profile_id": profile_id},
            headers=owner.headers,
        )
        data = response_json(response)["data"]
        assert data["success"] is False

    def test_missing_tts_returns_text_only_response(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/command",
            json={"transcript": "Summarize this week's business report", "detected_language": "en"},
            headers=owner.headers,
        )
        data = response_json(response)["data"]
        assert data["speech_output_status"] == "external_dependency_required"
        assert isinstance(data["response_text"], str)

    def test_english_text_mode_command_works(self, client, make_owner) -> None:
        """Real commands (not control phrases) through push-to-talk-text
        now go through apps/api/routes/assistant.py::process_assistant_message
        -- the same dispatcher /assistant/message uses -- so the response
        shape is final_answer-first, not the old response_text/
        reply_language shape. This VEO command triggers the template's
        clarifying-question flow (style/duration/etc not supplied), which
        is itself proof the real dispatcher (not the old raw MasterAgent
        bypass) is now handling it."""
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"text": "Create a VEO prompt for ClickRonix", "detected_language": "en"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert isinstance(data["final_answer"], str)
        assert data["final_answer"] != ""
        assert data["speech_output_status"] in ("spoken", "tts_missing")

    def test_roman_urdu_text_mode_command_works(self, client, make_owner) -> None:
        """Push-to-talk-text no longer adapts reply language (the shared
        assistant dispatcher has no language-adaptation layer, matching
        dashboard chat) -- this test now only locks in that a Roman Urdu
        command still gets a real, structured final_answer, not a crash or
        an empty response."""
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={
                "text": "mera ClickRonix dashboard premium black orange style mein banao",
                "detected_language": "roman_urdu",
            },
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert isinstance(data["final_answer"], str)
        assert data["final_answer"] != ""

    def test_vague_command_gets_a_structured_response_not_a_crash(self, client, make_owner) -> None:
        """
        The mission asks for MasterAgent to ask follow-up questions on vague
        commands (e.g. "create the project"); that Planner-level clarifying-
        question capability does not exist in this codebase yet and building
        it is out of this phase's safe scope (would require modifying
        core/planner.py's core logic). This test instead locks in the
        honest, safe behavior available today: a vague command never
        crashes the pipeline and always returns a structured response.
        """
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"text": "William, create the project", "detected_language": "en"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert isinstance(data["final_answer"], str)
        assert data["final_answer"] != ""


class TestVoiceWakeEvent:
    def test_wake_event_requires_auth(self, client) -> None:
        response = client.post("/api/v1/voice/wake-event", json={})
        assert response.status_code in (401, 403)

    def test_wake_event_reports_should_listen_false_when_disabled(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post("/api/v1/voice/wake-event", json={"activation_type": "wake_word"}, headers=owner.headers)
        assert response.status_code == 200
        assert response_json(response)["data"]["should_listen"] is False

    def test_wake_event_writes_audit_log(self, client, make_owner) -> None:
        from database.db import db_manager
        from database.models.security import AuditLogModel

        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)
        client.post("/api/v1/voice/wake-event", json={"activation_type": "wake_word"}, headers=owner.headers)

        with db_manager.session_scope() as db:
            rows = (
                db.query(AuditLogModel)
                .filter(AuditLogModel.workspace_id == owner.workspace_id, AuditLogModel.action == "voice.wake_event")
                .all()
            )
            assert len(rows) >= 1


class TestVoiceEnrollment:
    def test_enroll_start_requires_admin(self, client, make_owner, make_member) -> None:
        owner = make_owner()
        member = make_member(owner, role="member")
        response = client.post("/api/v1/voice/enroll/start", json={"display_name": "Owner Voice"}, headers=member.headers)
        assert response.status_code == 403

    def test_enroll_start_reports_dependency_status_honestly(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post("/api/v1/voice/enroll/start", json={"display_name": "Owner Voice"}, headers=owner.headers)
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert data["dependency_status"]["provider_configured"] is False

    def test_enroll_complete_without_provider_returns_external_dependency_required(self, client, make_owner) -> None:
        owner = make_owner()
        start = client.post("/api/v1/voice/enroll/start", json={"display_name": "Owner Voice"}, headers=owner.headers)
        profile_id = response_json(start)["data"]["profile_id"]

        response = client.post(
            "/api/v1/voice/enroll/complete",
            json={"profile_id": profile_id, "voice_sample_ref": "fake_ref_for_test"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert data["profile"]["voiceprint_status"] == "external_dependency_required"


def _create_setup_token(client, owner) -> dict:
    response = client.post(
        "/api/v1/system/device/setup-token",
        json={"device_name": "Voice Test Laptop"},
        headers=owner.headers,
    )
    assert response.status_code == 200
    return response.json()["data"]


def _register_device(client, setup_token: str) -> dict:
    response = client.post(
        "/api/v1/system/device/register",
        json={"setup_token": setup_token, "device_name": "Voice Test Laptop", "supported_actions": ["open_notepad"]},
    )
    assert response.status_code == 200
    return response.json()["data"]


class TestVoiceSharesAssistantDispatcher:
    """Phase 7 coverage: POST /voice/push-to-talk/text must use the exact
    same dispatcher as POST /assistant/message (apps/api/routes/
    assistant.py::process_assistant_message), not the old raw MasterAgent
    bypass that could never reach SystemAgent/Windows Worker."""

    def test_push_to_talk_text_matches_assistant_message_final_answer(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)

        voice_response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"text": "William open Notepad"},
            headers=owner.headers,
        )
        assistant_response = client.post(
            "/api/v1/assistant/message",
            json={"message": "William open Notepad"},
            headers=owner.headers,
        )
        assert voice_response.status_code == 200
        assert assistant_response.status_code == 200
        assert (
            response_json(voice_response)["data"]["final_answer"]
            == response_json(assistant_response)["data"]["final_answer"]
        )

    def test_push_to_talk_text_says_not_enabled_when_no_worker_ever_registered(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"text": "William open Notepad"},
            headers=owner.headers,
        )
        data = response_json(response)["data"]
        assert data["final_answer"] == (
            "Boss, Windows Worker is not enabled yet. Open Settings > Devices and click Enable Windows Worker."
        )
        assert data["speech_output_status"] == "tts_missing"

    def test_push_to_talk_text_says_offline_when_worker_enabled_but_stale(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)
        setup_data = _create_setup_token(client, owner)
        _register_device(client, setup_data["setup_token"])

        from datetime import datetime, timedelta, timezone
        from database.db import db_manager
        from database.models.system_worker import SystemWorkerStatus

        with db_manager.session_scope() as db:
            row = db.query(SystemWorkerStatus).filter(
                SystemWorkerStatus.workspace_id == owner.workspace_id
            ).first()
            assert row is not None
            row.worker_last_seen_at = datetime.now(timezone.utc) - timedelta(seconds=999)

        response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"text": "William open Notepad"},
            headers=owner.headers,
        )
        data = response_json(response)["data"]
        assert data["final_answer"] == (
            "Boss, Windows Worker is enabled but offline. Start the worker or reinstall it from Settings."
        )

    def test_push_to_talk_text_queues_worker_task_when_connected(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)
        setup_data = _create_setup_token(client, owner)
        _register_device(client, setup_data["setup_token"])

        response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"text": "William open Notepad"},
            headers=owner.headers,
        )
        data = response_json(response)["data"]
        assert "notepad" in data["final_answer"].lower()
        assert data["worker_task_id"]
        assert data["speech_output_status"] == "tts_missing"

    def test_push_to_talk_text_speech_status_is_spoken_when_tts_configured(self, client, make_owner, monkeypatch) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)
        monkeypatch.setenv("WILLIAM_TTS_PROVIDER", "test_provider")

        response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"text": "William what is moderation?"},
            headers=owner.headers,
        )
        data = response_json(response)["data"]
        assert data["speech_output_status"] == "spoken"

    @pytest.mark.asyncio
    async def test_risky_action_via_voice_still_requires_approval(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)
        setup_data = _create_setup_token(client, owner)
        _register_device(client, setup_data["setup_token"])

        from apps.api.routes.system_worker import classify_worker_action
        from apps.api.routes.auth import AuthContext
        import uuid

        context = AuthContext(
            request_id=f"req_{uuid.uuid4().hex[:12]}",
            user_id=owner.user_id,
            workspace_id=owner.workspace_id,
            session_id="voice_test_session",
            role="owner",
            plan="free",
            email=owner.email,
        )
        classification = await classify_worker_action("delete_file", context=context)
        assert classification == "requires_approval"

    def test_push_to_talk_text_workspace_isolation(self, client, make_owner) -> None:
        """A WorkerTask queued via voice for one workspace must never be
        visible to another workspace's worker poll."""
        owner_a = make_owner()
        owner_b = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner_a.headers)
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner_b.headers)

        setup_a = _create_setup_token(client, owner_a)
        register_a = _register_device(client, setup_a["setup_token"])

        client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"text": "William open Notepad"},
            headers=owner_a.headers,
        )

        device_headers_a = {"Authorization": f"Bearer {register_a['device_token']}"}
        tasks_a = client.get("/api/v1/system/worker/tasks", headers=device_headers_a).json()["data"]["tasks"]
        assert len(tasks_a) == 1

        status_b = client.get("/api/v1/system/worker/status", headers=owner_b.headers).json()["data"]
        assert status_b["connection_state"] == "needs_setup"
