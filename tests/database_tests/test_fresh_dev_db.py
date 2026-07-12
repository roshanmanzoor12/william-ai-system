"""
tests/database_tests/test_fresh_dev_db.py

Regression tests for "deleting william.db and restarting the backend
produces a clean, usable dev database" (previously: nothing in
apps/api/main.py's boot path ever imported the model modules or called
Base.metadata.create_all(), so a fresh/deleted-and-recreated SQLite file
had zero tables and every route touching the database 500'd with
`sqlite3.OperationalError: no such table: users`).

These tests run apps.api.main.create_app() in a genuinely fresh
**subprocess** against a brand-new temp SQLite file, deliberately NOT
reusing tests/conftest.py's module-level fixture app -- conftest.py builds
its own schema via create_all() before any test runs, which would mask
exactly the bug this file exists to catch (the real app's own startup path
never being exercised in isolation). A subprocess is the only way to prove
`Main.create_app()` builds the schema on its own, with nothing else having
touched Base.metadata first.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap

import pytest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

_SUBPROCESS_SCRIPT = textwrap.dedent(
    """
    import json
    import sys

    sys.path.insert(0, {project_root!r})

    from apps.api.main import create_app
    from fastapi.testclient import TestClient
    from database.db import Base

    report = {{}}

    app = create_app(testing=False)
    client = TestClient(app)

    tables = sorted(Base.metadata.tables.keys())
    report["tables"] = tables
    report["has_users_table"] = "users" in tables
    report["has_audit_logs_table"] = "audit_logs" in tables
    report["has_voice_tables"] = all(
        t in tables for t in ("voice_settings", "voice_identity_profiles", "voice_sessions", "voice_events")
    )
    report["has_workspace_tables"] = all(
        t in tables for t in ("workspaces", "workspace_memberships")
    )

    register = client.post(
        "/api/v1/auth/register",
        json={{
            "email": "fresh_db_owner@example.test",
            "password": "Sup3rSecure!Pass1",
            "full_name": "Fresh DB Owner",
            "workspace_name": "Fresh DB Workspace",
        }},
    )
    report["register_status"] = register.status_code
    register_body = register.json()
    report["register_success"] = register_body.get("success")

    access_token = None
    if register.status_code == 200:
        access_token = register_body["data"]["tokens"]["access_token"]

    login = client.post(
        "/api/v1/auth/login",
        json={{"email": "fresh_db_owner@example.test", "password": "Sup3rSecure!Pass1"}},
    )
    report["login_status"] = login.status_code
    report["login_success"] = login.json().get("success")

    if access_token:
        headers = {{"Authorization": f"Bearer {{access_token}}"}}

        agents = client.get("/api/v1/agents", headers=headers)
        report["agents_status"] = agents.status_code

        voice_status = client.get("/api/v1/voice/status", headers=headers)
        report["voice_status_status"] = voice_status.status_code
        if voice_status.status_code == 200:
            report["voice_mode"] = voice_status.json()["data"]["settings"]["mode"]

    print("REPORT_JSON_START")
    print(json.dumps(report))
    print("REPORT_JSON_END")
    """
)


def _run_fresh_db_subprocess(tmp_path) -> dict:
    db_path = tmp_path / "fresh_dev.db"

    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{db_path}"
    env["ENVIRONMENT"] = "development"
    env["APP_ENV"] = "development"
    env.pop("WILLIAM_ENV", None)
    env.pop("TESTING", None)
    env["JWT_SECRET"] = "fresh-db-test-jwt-secret-not-for-production"
    env["ENCRYPTION_KEY"] = "fresh-db-test-encryption-key-not-for-production"
    env["MASTER_AGENT_ENABLED"] = "false"
    env["EXTERNAL_ACTIONS_ENABLED"] = "false"
    env["BILLING_PROVIDER_ENABLED"] = "false"

    script = _SUBPROCESS_SCRIPT.format(project_root=PROJECT_ROOT)

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=PROJECT_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert "REPORT_JSON_START" in result.stdout, (
        f"Subprocess did not produce a report.\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    payload = result.stdout.split("REPORT_JSON_START", 1)[1].split("REPORT_JSON_END", 1)[0].strip()
    return json.loads(payload)


class TestFreshDevDatabase:
    def test_startup_creates_users_table_on_brand_new_sqlite_file(self, tmp_path) -> None:
        report = _run_fresh_db_subprocess(tmp_path)
        assert report["has_users_table"] is True, report

    def test_startup_creates_audit_logs_table(self, tmp_path) -> None:
        report = _run_fresh_db_subprocess(tmp_path)
        assert report["has_audit_logs_table"] is True, report

    def test_startup_creates_voice_tables(self, tmp_path) -> None:
        report = _run_fresh_db_subprocess(tmp_path)
        assert report["has_voice_tables"] is True, report

    def test_startup_creates_workspace_tables(self, tmp_path) -> None:
        report = _run_fresh_db_subprocess(tmp_path)
        assert report["has_workspace_tables"] is True, report

    def test_register_works_on_fresh_db(self, tmp_path) -> None:
        report = _run_fresh_db_subprocess(tmp_path)
        assert report["register_status"] == 200, report
        assert report["register_success"] is True, report

    def test_login_works_after_register_on_fresh_db(self, tmp_path) -> None:
        report = _run_fresh_db_subprocess(tmp_path)
        assert report["login_status"] == 200, report
        assert report["login_success"] is True, report

    def test_agents_endpoint_works_after_fresh_register(self, tmp_path) -> None:
        report = _run_fresh_db_subprocess(tmp_path)
        assert report["agents_status"] == 200, report

    def test_voice_status_works_on_fresh_db(self, tmp_path) -> None:
        report = _run_fresh_db_subprocess(tmp_path)
        assert report["voice_status_status"] == 200, report
        assert report["voice_mode"] == "disabled", report
