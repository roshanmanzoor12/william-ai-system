"""
tests/api_tests/test_cors.py

Regression tests for CORS preflight handling. Starlette's CORSMiddleware
returns its own 400 "Disallowed CORS ..." response (before the request ever
reaches routing/auth) whenever a preflight's Origin or
Access-Control-Request-Headers isn't covered by apps/api/main.py::Settings'
allowed_origins/allowed_headers -- this previously blocked every real
browser GET to /agents, /tasks, and /dashboard/summary from the dashboard
(ports 3000/3001) with a 400 before the request ever reached auth.
"""

from __future__ import annotations

import pytest

REQUIRED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:3001",
    "http://127.0.0.1:3001",
]

PREFLIGHTED_PATHS = [
    "/api/v1/agents",
    "/api/v1/tasks",
    "/api/v1/dashboard/summary",
]


class TestCorsPreflight:
    @pytest.mark.parametrize("origin", REQUIRED_ORIGINS)
    @pytest.mark.parametrize("path", PREFLIGHTED_PATHS)
    def test_preflight_succeeds_for_required_origin(self, client, origin, path) -> None:
        response = client.options(
            path,
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )

        assert response.status_code in (200, 204), (
            f"OPTIONS {path} from {origin} returned {response.status_code}: {response.text}"
        )
        assert response.headers.get("access-control-allow-origin") == origin
        assert response.headers.get("access-control-allow-credentials") == "true"

    def test_preflight_allows_authorization_header(self, client) -> None:
        response = client.options(
            "/api/v1/agents",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization",
            },
        )
        allowed = response.headers.get("access-control-allow-headers", "")
        assert "authorization" in allowed.lower()

    def test_preflight_allows_dashboards_real_custom_headers(self, client) -> None:
        """
        Regression test for the actual reported root cause: several
        dashboard pages' local apiRequest helpers (dashboard/agents/tasks
        page.tsx) send X-Action/X-Client-App/X-Audit-Enabled/X-Audit-Action/
        X-Sensitive-Action on real requests (confirmed by grepping
        apps/dashboard/src/ directly, not guessed). None of these were ever
        in Settings.allowed_headers, so the browser's real preflight
        Access-Control-Request-Headers always included at least one
        disallowed header and Starlette's CORSMiddleware always returned its
        own 400 "Disallowed CORS headers" -- reproduced live via
        `curl -X OPTIONS ... -H "Access-Control-Request-Headers:
        authorization,content-type,x-action,x-client-app,x-audit-enabled"`
        before this fix.
        """
        response = client.options(
            "/api/v1/agents",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": (
                    "authorization,content-type,x-action,x-client-app,"
                    "x-audit-enabled,x-audit-action,x-sensitive-action"
                ),
            },
        )
        assert response.status_code in (200, 204), (
            f"Real dashboard custom headers were rejected by CORS preflight: "
            f"{response.status_code} {response.text}"
        )
        allowed = response.headers.get("access-control-allow-headers", "").lower()
        for header in (
            "x-action",
            "x-client-app",
            "x-audit-enabled",
            "x-audit-action",
            "x-sensitive-action",
        ):
            assert header in allowed, f"{header} missing from Access-Control-Allow-Headers"

    def test_preflight_allows_all_required_methods(self, client) -> None:
        response = client.options(
            "/api/v1/tasks",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        allowed_methods = {
            method.strip()
            for method in response.headers.get("access-control-allow-methods", "").split(",")
        }
        for required in ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"):
            assert required in allowed_methods, f"{required} missing from Access-Control-Allow-Methods"

    def test_actual_get_request_carries_cors_headers(self, client, make_owner) -> None:
        """The preflight is only half the story -- the real GET response
        itself must also carry Access-Control-Allow-Origin, or the browser
        blocks the response even after a successful preflight."""
        owner = make_owner()
        response = client.get(
            "/api/v1/agents",
            headers={**owner.headers, "Origin": "http://localhost:3000"},
        )
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"
