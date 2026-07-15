"""
tests/api_tests/test_project_builder.py

Real HTTP tests for natural-language project scaffolding -- POST
/assistant/message routing through core/intent_classifier.py's
PROJECT_BUILD_TEMPLATE clarifying questions to CodeAgent.create_project
(agents/code_agent/code_agent.py), which writes REAL files to disk under
WILLIAM_PROJECTS_ROOT. Never writes anything until target_folder AND
new_or_overwrite are both answered.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest


def response_json(response):
    return response.json()


@pytest.fixture
def _isolated_projects_root(tmp_path, monkeypatch):
    root = tmp_path / "william_workspaces_test"
    monkeypatch.setenv("WILLIAM_PROJECTS_ROOT", str(root))
    yield root
    shutil.rmtree(root, ignore_errors=True)


class TestProjectBuildClarification:
    def test_asks_all_ten_required_fields(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.post(
            "/api/v1/assistant/message",
            json={"message": "William build website builder SaaS"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert data["status"] == "waiting_for_user"
        assert len(data["follow_up_questions"]) == 10
        field_names = {f["name"] for f in data["required_inputs"]}
        assert field_names == {
            "target_user",
            "features",
            "stack",
            "auth_subscription",
            "admin_panel",
            "template_upload",
            "seo",
            "download_zip",
            "target_folder",
            "new_or_overwrite",
        }


class TestProjectBuildStandardShortcut:
    def test_standard_then_folder_name_creates_real_project(
        self, client, make_owner, _isolated_projects_root
    ) -> None:
        owner = make_owner()

        first = client.post(
            "/api/v1/assistant/message",
            json={"message": "William build website builder SaaS"},
            headers=owner.headers,
        )
        thread_id = response_json(first)["data"]["conversation_thread_id"]

        # Round 1: "standard" fills every field EXCEPT target_folder (never
        # auto-picked -- the user must always name the folder explicitly).
        second = client.post(
            "/api/v1/assistant/message",
            json={"message": "use defaults", "conversation_thread_id": thread_id},
            headers=owner.headers,
        )
        second_data = response_json(second)["data"]
        assert second_data["status"] == "waiting_for_user"
        assert [f["name"] for f in second_data["required_inputs"]] == ["target_folder"]

        # Round 2: supply the folder name -> real files get written.
        third = client.post(
            "/api/v1/assistant/message",
            json={"message": "acme_site_builder", "conversation_thread_id": thread_id},
            headers=owner.headers,
        )
        assert third.status_code == 200
        third_data = response_json(third)["data"]
        assert third_data["status"] == "completed"
        assert len(third_data["files_changed"]) == 5
        assert third_data["checks"]["syntax_errors"] == []

        project_root = Path(third_data["project_root"])
        assert (project_root / "README.md").exists()
        assert (project_root / "backend" / "main.py").exists()
        assert "acme_site_builder" in (project_root / "README.md").read_text(encoding="utf-8")


class TestProjectBuildOverwriteProtection:
    def test_second_build_without_overwrite_skips_existing_files(
        self, client, make_owner, _isolated_projects_root
    ) -> None:
        owner = make_owner()

        def _build(folder_answer: str, overwrite_answer: str):
            first = client.post(
                "/api/v1/assistant/message",
                json={"message": "William build website builder SaaS"},
                headers=owner.headers,
            )
            thread_id = response_json(first)["data"]["conversation_thread_id"]
            # A single round with every field supplied via collected_inputs
            # (the form-submission path a dashboard would use) -- resolves
            # the clarification in one shot.
            final = client.post(
                "/api/v1/assistant/message",
                json={
                    "message": "here are the details",
                    "conversation_thread_id": thread_id,
                    "collected_inputs": {
                        "target_user": "small businesses",
                        "features": "landing page builder",
                        "stack": "python fastapi + nextjs",
                        "auth_subscription": "no",
                        "admin_panel": "no",
                        "template_upload": "no",
                        "seo": "no",
                        "download_zip": "no",
                        "target_folder": folder_answer,
                        "new_or_overwrite": overwrite_answer,
                    },
                },
                headers=owner.headers,
            )
            return response_json(final)["data"]

        first_result = _build("shared_project_folder", "new")
        assert len(first_result["files_changed"]) == 5

        second_result = _build("shared_project_folder", "new")
        assert second_result["files_changed"] == []
        assert len(second_result["files_skipped"]) == 5
