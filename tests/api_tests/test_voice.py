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
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={"transcript": "Create a VEO prompt for ClickRonix", "detected_language": "en"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert data["reply_language"] == "en"

    def test_roman_urdu_text_mode_command_works(self, client, make_owner) -> None:
        owner = make_owner()
        client.post("/api/v1/voice/config", json={"mode": "push_to_talk"}, headers=owner.headers)

        response = client.post(
            "/api/v1/voice/push-to-talk/text",
            json={
                "transcript": "mera ClickRonix dashboard premium black orange style mein banao",
                "detected_language": "roman_urdu",
            },
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert data["reply_language"] == "roman_urdu"

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
            json={"transcript": "William, create the project", "detected_language": "en"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert isinstance(data["response_text"], str)
        assert data["response_text"] != ""


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
