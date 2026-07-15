"""
tests/api_tests/test_file_generation.py

Real HTTP tests for PDF/DOCX document generation -- POST /assistant/message
routing to CreatorAgent.generate_document (agents/super_agents/creator_agent/
document_generator.py), workspace-scoped GeneratedFile persistence, and the
real download route (GET /files/generated/{file_id}/download). Every
generated file here is a REAL PDF/DOCX written to disk under
core.config.StorageConfig.generated_files_dir, not a mocked response.
"""

from __future__ import annotations


def response_json(response):
    return response.json()


class TestPdfNdaClarification:
    def test_asks_all_required_fields(self, client, make_owner) -> None:
        """The initial message already says "PDF" and "NDA", so
        core/intent_classifier.py::extract_file_generation_hints
        pre-fills doc_type/format -- only the 4 fields with no reliable
        keyword signal (parties/jurisdiction/duration/confidentiality_scope)
        are actually asked."""
        owner = make_owner()
        response = client.post(
            "/api/v1/assistant/message",
            json={"message": "William make a PDF NDA for Digital Promotix"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert data["status"] == "waiting_for_user"
        assert len(data["follow_up_questions"]) == 4
        assert data["generated_files"] == []
        field_names = {f["name"] for f in data["required_inputs"]}
        assert field_names == {
            "parties",
            "jurisdiction",
            "duration",
            "confidentiality_scope",
        }

    def test_format_not_mentioned_still_asks_pdf_or_docx(self, client, make_owner) -> None:
        """"agreement" is a doc-type signal but not a format signal -- only
        doc_type gets pre-filled, format is still asked (5 of 6 fields)."""
        owner = make_owner()
        response = client.post(
            "/api/v1/assistant/message",
            json={"message": "William create an agreement"},
            headers=owner.headers,
        )
        assert response.status_code == 200
        data = response_json(response)["data"]
        assert data["status"] == "waiting_for_user"
        assert len(data["follow_up_questions"]) == 5
        field_names = {f["name"] for f in data["required_inputs"]}
        assert "format" in field_names
        assert "doc_type" not in field_names


class TestPdfNdaStandardShortcut:
    def test_standard_one_generates_real_pdf_with_download_link(self, client, make_owner) -> None:
        owner = make_owner()

        first = client.post(
            "/api/v1/assistant/message",
            json={"message": "William make a PDF NDA for Digital Promotix"},
            headers=owner.headers,
        )
        thread_id = response_json(first)["data"]["conversation_thread_id"]

        second = client.post(
            "/api/v1/assistant/message",
            json={"message": "standard one", "conversation_thread_id": thread_id},
            headers=owner.headers,
        )
        assert second.status_code == 200
        data = response_json(second)["data"]

        assert data["status"] == "completed"
        assert len(data["generated_files"]) == 1
        generated = data["generated_files"][0]
        assert generated["file_id"]
        assert generated["filename"].endswith(".pdf")
        assert generated["download_url"] == f"/files/generated/{generated['file_id']}/download"

        download = client.get(
            f"/api/v1/files/generated/{generated['file_id']}/download",
            headers=owner.headers,
        )
        assert download.status_code == 200
        assert download.headers["content-type"] == "application/pdf"
        assert download.content[:4] == b"%PDF"

    def test_standard_shortcut_never_uses_the_word_standard_as_a_field_value(self, client, make_owner) -> None:
        """Regression guard: before the standard-shortcut special-case, the
        generic merge_free_text_answer fallback would have dumped the raw
        text "standard one" into whichever single free-form field was left
        -- this must never happen."""
        owner = make_owner()

        first = client.post(
            "/api/v1/assistant/message",
            json={"message": "William make a DOCX proposal"},
            headers=owner.headers,
        )
        thread_id = response_json(first)["data"]["conversation_thread_id"]

        second = client.post(
            "/api/v1/assistant/message",
            json={"message": "standard one", "conversation_thread_id": thread_id},
            headers=owner.headers,
        )
        data = response_json(second)["data"]
        assert data["status"] == "completed"
        generated = data["generated_files"][0]
        assert generated["filename"].endswith(".docx")


class TestGeneratedFileWorkspaceIsolation:
    def test_other_workspace_cannot_download(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()

        first = client.post(
            "/api/v1/assistant/message",
            json={"message": "William make a PDF NDA for Digital Promotix"},
            headers=owner_a.headers,
        )
        thread_id = response_json(first)["data"]["conversation_thread_id"]
        second = client.post(
            "/api/v1/assistant/message",
            json={"message": "standard one", "conversation_thread_id": thread_id},
            headers=owner_a.headers,
        )
        file_id = response_json(second)["data"]["generated_files"][0]["file_id"]

        cross_workspace = client.get(
            f"/api/v1/files/generated/{file_id}/download",
            headers=owner_b.headers,
        )
        assert cross_workspace.status_code == 404

    def test_list_generated_files_scoped_to_workspace(self, client, make_owner) -> None:
        owner_a = make_owner()
        owner_b = make_owner()

        first = client.post(
            "/api/v1/assistant/message",
            json={"message": "William make a PDF NDA for Digital Promotix"},
            headers=owner_a.headers,
        )
        thread_id = response_json(first)["data"]["conversation_thread_id"]
        client.post(
            "/api/v1/assistant/message",
            json={"message": "standard one", "conversation_thread_id": thread_id},
            headers=owner_a.headers,
        )

        list_a = client.get("/api/v1/files/generated", headers=owner_a.headers)
        list_b = client.get("/api/v1/files/generated", headers=owner_b.headers)
        assert list_a.json()["data"]["count"] >= 1
        assert list_b.json()["data"]["count"] == 0


class TestPdfDownloadNotFound:
    def test_unknown_file_id_is_404(self, client, make_owner) -> None:
        owner = make_owner()
        response = client.get(
            "/api/v1/files/generated/genfile_doesnotexist/download",
            headers=owner.headers,
        )
        assert response.status_code == 404
