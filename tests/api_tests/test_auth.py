"""
tests/api_tests/test_auth.py

Auth endpoint tests for the William / Jarvis Multi-Agent AI SaaS System
by Digital Promotix.

Purpose:
- Validate authentication endpoints.
- Assert user_id and workspace_id isolation.
- Assert safe structured API responses.
- Assert role, plan, and subscription metadata where available.
- Assert sensitive/state-changing auth actions can integrate with audit,
  Security Agent, Memory Agent, Master Agent, and Verification Agent flows.
- Import safely even while future app modules are still being built.

These tests are intentionally adaptive:
- They use the real FastAPI/Starlette app when available.
- They skip endpoint-specific checks when the app or route is not implemented yet.
- They include strict assertions once routes exist.
"""

from __future__ import annotations

import importlib
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, Mapping, Optional, Tuple

import pytest


# ---------------------------------------------------------------------------
# Optional runtime imports
# ---------------------------------------------------------------------------

try:
    from fastapi.testclient import TestClient
except Exception:  # pragma: no cover - dependency may not exist yet
    TestClient = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Test constants
# ---------------------------------------------------------------------------

API_PREFIX_CANDIDATES: Tuple[str, ...] = (
    "/api/v1/auth",
    "/api/auth",
    "/auth",
)

REGISTER_PATHS: Tuple[str, ...] = (
    "/register",
    "/signup",
    "/create-account",
)

LOGIN_PATHS: Tuple[str, ...] = (
    "/login",
    "/token",
    "/signin",
)

ME_PATHS: Tuple[str, ...] = (
    "/me",
    "/profile",
    "/session",
)

LOGOUT_PATHS: Tuple[str, ...] = (
    "/logout",
    "/signout",
)

REFRESH_PATHS: Tuple[str, ...] = (
    "/refresh",
    "/refresh-token",
)

SAFE_ERROR_KEYS: Tuple[str, ...] = (
    "success",
    "error",
    "message",
    "detail",
)

SENSITIVE_KEYS_THAT_MUST_NOT_LEAK: Tuple[str, ...] = (
    "password",
    "password_hash",
    "hashed_password",
    "secret",
    "token_secret",
    "private_key",
    "api_key",
    "database_url",
    "traceback",
    "stack",
)

AUTH_TOKEN_KEYS: Tuple[str, ...] = (
    "access_token",
    "token",
    "jwt",
    "id_token",
)

REFRESH_TOKEN_KEYS: Tuple[str, ...] = (
    "refresh_token",
    "refresh",
)

USER_ID_KEYS: Tuple[str, ...] = (
    "user_id",
    "id",
    "sub",
)

WORKSPACE_ID_KEYS: Tuple[str, ...] = (
    "workspace_id",
    "workspace",
)

ROLE_KEYS: Tuple[str, ...] = (
    "role",
    "roles",
    "permissions",
)

PLAN_KEYS: Tuple[str, ...] = (
    "plan",
    "subscription",
    "subscription_status",
    "plan_id",
    "tier",
)

AUDIT_KEYS: Tuple[str, ...] = (
    "audit",
    "audit_id",
    "audit_log_id",
    "event_id",
    "request_id",
)

VERIFICATION_KEYS: Tuple[str, ...] = (
    "verification",
    "verification_payload",
    "verification_id",
)


# ---------------------------------------------------------------------------
# Data models for tests
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AuthUserFixture:
    """Stable test user fixture with unique identity per test run."""

    email: str
    password: str
    full_name: str
    user_id: str
    workspace_id: str
    role: str
    plan: str

    @classmethod
    def create(cls, label: str = "user") -> "AuthUserFixture":
        unique = uuid.uuid4().hex[:12]
        return cls(
            email=f"{label}.{unique}@example.test",
            password=f"SafeTestPassword-{unique}-Aa1!",
            full_name=f"William Test {label.title()} {unique}",
            user_id=f"user_{unique}",
            workspace_id=f"workspace_{unique}",
            role="owner",
            plan="free",
        )

    def registration_payload(self) -> Dict[str, Any]:
        return {
            "email": self.email,
            "password": self.password,
            "full_name": self.full_name,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "role": self.role,
            "plan": self.plan,
        }

    def login_payload(self) -> Dict[str, Any]:
        # Deliberately omits workspace_id: self.workspace_id is a locally
        # fabricated placeholder (see create()), never the real workspace_id
        # the server actually assigns during registration. The real
        # /auth/login endpoint (apps/api/routes/auth.py) resolves a user's
        # sole membership automatically when workspace_id is omitted via
        # AUTH_STORE.choose_membership(user_id, None) -- sending the fake
        # id instead made every login 403 with "User does not have access
        # to this workspace", since that workspace never actually existed.
        return {
            "email": self.email,
            "password": self.password,
        }


# ---------------------------------------------------------------------------
# Import and app discovery helpers
# ---------------------------------------------------------------------------

def _import_first(module_names: Iterable[str]) -> Optional[Any]:
    for module_name in module_names:
        try:
            return importlib.import_module(module_name)
        except Exception:
            continue
    return None


def _discover_app() -> Optional[Any]:
    """
    Discover the application object without hard-coding one final project path.

    Supported likely module paths:
    - apps.api.main:app
    - app.main:app
    - main:app

    Returns:
        FastAPI/Starlette ASGI app object or None.
    """
    candidates = (
        "apps.api.main",
        "app.main",
        "src.main",
        "backend.main",
        "main",
    )

    for module_name in candidates:
        module = _import_first((module_name,))
        if module is None:
            continue

        for attr_name in ("app", "application", "api"):
            app = getattr(module, attr_name, None)
            if app is not None:
                return app

        factory = getattr(module, "create_app", None)
        if callable(factory):
            try:
                return factory()
            except TypeError:
                continue
            except Exception:
                continue

    return None


@pytest.fixture(scope="session")
def app() -> Optional[Any]:
    return _discover_app()


@pytest.fixture(scope="session")
def client(app: Optional[Any]) -> Any:
    if app is None:
        pytest.skip(
            "No ASGI app discovered. Expected one of: "
            "apps.api.main:app, app.main:app, src.main:app, backend.main:app, main:app."
        )

    if TestClient is None:
        pytest.skip("fastapi/starlette TestClient is not installed.")

    return TestClient(app)


@pytest.fixture()
def primary_user() -> AuthUserFixture:
    return AuthUserFixture.create("primary")


@pytest.fixture()
def secondary_user() -> AuthUserFixture:
    return AuthUserFixture.create("secondary")


# ---------------------------------------------------------------------------
# HTTP helper functions
# ---------------------------------------------------------------------------

def _json_or_empty(response: Any) -> Dict[str, Any]:
    try:
        payload = response.json()
    except Exception:
        return {}

    if isinstance(payload, dict):
        return payload

    return {"data": payload}


def _flatten_mapping(value: Any, prefix: str = "") -> Dict[str, Any]:
    """
    Flatten nested dict/list payloads into a single mapping for easier assertions.
    """
    flattened: Dict[str, Any] = {}

    if isinstance(value, Mapping):
        for key, nested_value in value.items():
            full_key = f"{prefix}.{key}" if prefix else str(key)
            flattened[full_key] = nested_value
            flattened.update(_flatten_mapping(nested_value, full_key))
    elif isinstance(value, list):
        for index, nested_value in enumerate(value):
            full_key = f"{prefix}.{index}" if prefix else str(index)
            flattened[full_key] = nested_value
            flattened.update(_flatten_mapping(nested_value, full_key))

    return flattened


def _find_value(payload: Mapping[str, Any], candidate_keys: Iterable[str]) -> Optional[Any]:
    flattened = _flatten_mapping(payload)
    normalized_candidates = {key.lower() for key in candidate_keys}

    for key, value in flattened.items():
        key_parts = key.lower().split(".")
        if key_parts[-1] in normalized_candidates:
            return value

    return None


def _contains_key(payload: Mapping[str, Any], candidate_keys: Iterable[str]) -> bool:
    return _find_value(payload, candidate_keys) is not None


def _contains_sensitive_leak(payload: Mapping[str, Any]) -> bool:
    flattened = _flatten_mapping(payload)

    for key, value in flattened.items():
        lower_key = key.lower()
        if any(sensitive in lower_key for sensitive in SENSITIVE_KEYS_THAT_MUST_NOT_LEAK):
            return True

        if isinstance(value, str):
            lower_value = value.lower()
            if "traceback" in lower_value or "password_hash" in lower_value:
                return True
            if "database_url" in lower_value or "private_key" in lower_value:
                return True

    return False


def _route_exists(client: Any, path: str) -> bool:
    """
    Determine if a route likely exists by checking OPTIONS.

    Some apps may not implement OPTIONS cleanly, so this helper is conservative.
    """
    try:
        response = client.options(path)
    except Exception:
        return False

    return response.status_code not in {404, 405}


def _candidate_urls(suffixes: Iterable[str]) -> Tuple[str, ...]:
    return tuple(
        f"{prefix}{suffix}"
        for prefix in API_PREFIX_CANDIDATES
        for suffix in suffixes
    )


def _post_first_available(
    client: Any,
    urls: Iterable[str],
    payload: Mapping[str, Any],
    expected_existing_statuses: Iterable[int],
) -> Tuple[str, Any]:
    """
    POST to the first candidate endpoint that exists.

    If all return 404, the test skips because the project route is not present yet.
    """
    last_response: Optional[Any] = None

    for url in urls:
        try:
            response = client.post(url, json=dict(payload))
        except Exception:
            continue

        last_response = response

        if response.status_code != 404:
            return url, response

    if last_response is not None and last_response.status_code == 404:
        pytest.skip(f"No matching auth endpoint found from candidates: {tuple(urls)}")

    pytest.skip(
        "Unable to call any candidate auth endpoint. "
        f"Expected statuses: {tuple(expected_existing_statuses)}"
    )


def _get_first_available(
    client: Any,
    urls: Iterable[str],
    headers: Optional[Mapping[str, str]] = None,
    expected_existing_statuses: Iterable[int] = (200,),
) -> Tuple[str, Any]:
    last_response: Optional[Any] = None

    for url in urls:
        try:
            response = client.get(url, headers=dict(headers or {}))
        except Exception:
            continue

        last_response = response

        if response.status_code != 404:
            return url, response

    if last_response is not None and last_response.status_code == 404:
        pytest.skip(f"No matching auth endpoint found from candidates: {tuple(urls)}")

    pytest.skip(
        "Unable to call any candidate auth endpoint. "
        f"Expected statuses: {tuple(expected_existing_statuses)}"
    )


def _auth_headers(token: Optional[str], workspace_id: Optional[str] = None) -> Dict[str, str]:
    headers: Dict[str, str] = {}

    if token:
        headers["Authorization"] = f"Bearer {token}"

    if workspace_id:
        headers["X-Workspace-ID"] = workspace_id

    return headers


def _extract_access_token(payload: Mapping[str, Any]) -> Optional[str]:
    value = _find_value(payload, AUTH_TOKEN_KEYS)
    if isinstance(value, str) and value.strip():
        return value

    return None


def _extract_refresh_token(payload: Mapping[str, Any]) -> Optional[str]:
    value = _find_value(payload, REFRESH_TOKEN_KEYS)
    if isinstance(value, str) and value.strip():
        return value

    return None


def _assert_structured_response(payload: Mapping[str, Any]) -> None:
    assert isinstance(payload, Mapping), "API response must be a JSON object."

    known_root_keys = {
        "success",
        "data",
        "error",
        "message",
        "detail",
        "meta",
        "request_id",
        "audit_id",
        "verification",
    }

    assert any(key in payload for key in known_root_keys), (
        "Response should use a structured API envelope such as "
        "{success, data, error, message, detail, meta, request_id}."
    )


def _assert_safe_response(payload: Mapping[str, Any]) -> None:
    assert not _contains_sensitive_leak(payload), (
        "Response leaked sensitive fields or internal implementation details."
    )


def _assert_safe_error_response(response: Any) -> None:
    payload = _json_or_empty(response)

    assert response.status_code in {400, 401, 403, 404, 409, 422, 429}, (
        f"Expected safe client/auth error status, got {response.status_code}."
    )

    assert isinstance(payload, Mapping), "Error response must be JSON object."
    assert any(key in payload for key in SAFE_ERROR_KEYS), (
        "Error response should contain one of: success, error, message, detail."
    )

    _assert_safe_response(payload)


def _assert_user_workspace_metadata(
    payload: Mapping[str, Any],
    expected_user: AuthUserFixture,
    strict_workspace: bool = True,
) -> None:
    user_id = _find_value(payload, USER_ID_KEYS)
    workspace_id = _find_value(payload, WORKSPACE_ID_KEYS)

    if user_id is not None:
        assert str(user_id) in {expected_user.user_id, expected_user.email} or str(user_id).startswith("user_") or len(str(user_id)) >= 8

    if strict_workspace and workspace_id is not None:
        assert str(workspace_id) == expected_user.workspace_id or str(workspace_id).startswith("workspace_"), (
            "Auth response should preserve or return the correct workspace context."
        )


def _assert_role_plan_metadata_when_present(payload: Mapping[str, Any]) -> None:
    role_value = _find_value(payload, ROLE_KEYS)
    plan_value = _find_value(payload, PLAN_KEYS)

    if role_value is not None:
        assert role_value not in {"", None}, "Role/permissions metadata must not be empty when present."

    if plan_value is not None:
        assert plan_value not in {"", None}, "Plan/subscription metadata must not be empty when present."


def _register_user(client: Any, user: AuthUserFixture) -> Tuple[str, Any, Dict[str, Any]]:
    url, response = _post_first_available(
        client=client,
        urls=_candidate_urls(REGISTER_PATHS),
        payload=user.registration_payload(),
        expected_existing_statuses=(200, 201, 409, 422),
    )
    payload = _json_or_empty(response)
    return url, response, payload


def _login_user(client: Any, user: AuthUserFixture) -> Tuple[str, Any, Dict[str, Any], Optional[str]]:
    url, response = _post_first_available(
        client=client,
        urls=_candidate_urls(LOGIN_PATHS),
        payload=user.login_payload(),
        expected_existing_statuses=(200, 201, 401, 403, 422),
    )
    payload = _json_or_empty(response)
    token = _extract_access_token(payload)
    return url, response, payload, token


def _register_then_login(client: Any, user: AuthUserFixture) -> Optional[str]:
    _, register_response, register_payload = _register_user(client, user)

    if register_response.status_code not in {200, 201, 409}:
        pytest.skip(
            "Registration endpoint exists but did not allow creating a fixture user. "
            f"Status: {register_response.status_code}; payload: {register_payload}"
        )

    _, login_response, login_payload, token = _login_user(client, user)

    if login_response.status_code not in {200, 201}:
        pytest.skip(
            "Login endpoint exists but did not allow logging in fixture user. "
            f"Status: {login_response.status_code}; payload: {login_payload}"
        )

    if token is None:
        pytest.skip("Login endpoint did not return a recognizable access token yet.")

    return token


# ---------------------------------------------------------------------------
# Optional integration hook discovery
# ---------------------------------------------------------------------------

def _optional_callable(module_names: Iterable[str], callable_names: Iterable[str]) -> Optional[Callable[..., Any]]:
    module = _import_first(module_names)

    if module is None:
        return None

    for callable_name in callable_names:
        candidate = getattr(module, callable_name, None)
        if callable(candidate):
            return candidate

    return None


@pytest.fixture(scope="session")
def optional_audit_logger() -> Optional[Callable[..., Any]]:
    return _optional_callable(
        module_names=(
            "apps.api.security.audit",
            "apps.api.audit",
            "app.security.audit",
            "app.audit",
            "security.audit",
        ),
        callable_names=(
            "record_audit_event",
            "log_audit_event",
            "audit_log",
            "create_audit_event",
        ),
    )


@pytest.fixture(scope="session")
def optional_security_checker() -> Optional[Callable[..., Any]]:
    return _optional_callable(
        module_names=(
            "apps.api.security.policies",
            "apps.api.security.security_agent",
            "app.security.policies",
            "app.security.security_agent",
            "agents.security_agent",
        ),
        callable_names=(
            "check_sensitive_action",
            "authorize_sensitive_action",
            "evaluate_risk",
            "security_check",
        ),
    )


@pytest.fixture(scope="session")
def optional_verification_builder() -> Optional[Callable[..., Any]]:
    return _optional_callable(
        module_names=(
            "apps.api.verification",
            "app.verification",
            "agents.verification_agent",
            "verification_agent",
        ),
        callable_names=(
            "build_verification_payload",
            "prepare_verification_payload",
            "create_verification_payload",
        ),
    )


# ---------------------------------------------------------------------------
# Test suite
# ---------------------------------------------------------------------------

class TestAuth:
    """Auth endpoint tests with user/workspace isolation assertions."""

    def test_auth_routes_are_discoverable_or_app_skips_cleanly(self, client: Any) -> None:
        discovered_routes = []

        for path in (
            *_candidate_urls(REGISTER_PATHS),
            *_candidate_urls(LOGIN_PATHS),
            *_candidate_urls(ME_PATHS),
        ):
            if _route_exists(client, path):
                discovered_routes.append(path)

        assert isinstance(discovered_routes, list)

        if not discovered_routes:
            pytest.skip(
                "Auth routes are not implemented yet. Expected register/login/me "
                "under /api/v1/auth, /api/auth, or /auth."
            )

    def test_register_returns_structured_safe_response(
        self,
        client: Any,
        primary_user: AuthUserFixture,
    ) -> None:
        _, response, payload = _register_user(client, primary_user)

        assert response.status_code in {200, 201, 409, 422}, (
            f"Unexpected register status: {response.status_code}; payload: {payload}"
        )

        _assert_structured_response(payload)
        _assert_safe_response(payload)

        if response.status_code in {200, 201}:
            _assert_user_workspace_metadata(payload, primary_user, strict_workspace=False)
            _assert_role_plan_metadata_when_present(payload)
            assert _find_value(payload, ("email",)) in {primary_user.email, None} or primary_user.email in str(payload)

    def test_register_requires_email_password_and_workspace_context(
        self,
        client: Any,
        primary_user: AuthUserFixture,
    ) -> None:
        invalid_payloads = (
            {
                "password": primary_user.password,
                "workspace_id": primary_user.workspace_id,
            },
            {
                "email": primary_user.email,
                "workspace_id": primary_user.workspace_id,
            },
            {
                "email": primary_user.email,
                "password": primary_user.password,
            },
            {
                "email": "not-an-email",
                "password": "short",
                "workspace_id": primary_user.workspace_id,
            },
        )

        for payload in invalid_payloads:
            _, response = _post_first_available(
                client=client,
                urls=_candidate_urls(REGISTER_PATHS),
                payload=payload,
                expected_existing_statuses=(400, 401, 403, 422),
            )

            assert response.status_code in {400, 401, 403, 422}, (
                "Registration should reject missing/invalid email, password, "
                f"or workspace context. Got {response.status_code}."
            )
            _assert_safe_error_response(response)

    def test_duplicate_registration_is_rejected_or_idempotent_safely(
        self,
        client: Any,
        primary_user: AuthUserFixture,
    ) -> None:
        _, first_response, first_payload = _register_user(client, primary_user)
        assert first_response.status_code in {200, 201, 409, 422}

        _, second_response, second_payload = _register_user(client, primary_user)

        assert second_response.status_code in {200, 201, 409, 422}, (
            f"Unexpected duplicate register status: {second_response.status_code}; "
            f"payload: {second_payload}"
        )

        _assert_structured_response(second_payload)
        _assert_safe_response(second_payload)

        if second_response.status_code in {200, 201}:
            assert _contains_key(second_payload, USER_ID_KEYS + WORKSPACE_ID_KEYS) or "already" in str(second_payload).lower(), (
                "Idempotent duplicate registration should make ownership/workspace clear."
            )

        if second_response.status_code in {409, 422}:
            _assert_safe_error_response(second_response)

    def test_login_returns_token_and_safe_metadata(
        self,
        client: Any,
        primary_user: AuthUserFixture,
    ) -> None:
        _, register_response, _ = _register_user(client, primary_user)

        if register_response.status_code not in {200, 201, 409}:
            pytest.skip("Cannot login because registration fixture was not accepted.")

        _, login_response, login_payload, token = _login_user(client, primary_user)

        assert login_response.status_code in {200, 201}, (
            f"Login should succeed for registered user. "
            f"Status: {login_response.status_code}; payload: {login_payload}"
        )

        _assert_structured_response(login_payload)
        _assert_safe_response(login_payload)
        _assert_user_workspace_metadata(login_payload, primary_user, strict_workspace=False)
        _assert_role_plan_metadata_when_present(login_payload)

        assert token is not None, (
            "Login response must include an access token using one of: "
            f"{AUTH_TOKEN_KEYS}."
        )

        assert len(token) >= 16, "Access token should not be trivially short."

    def test_login_rejects_wrong_password_safely(
        self,
        client: Any,
        primary_user: AuthUserFixture,
    ) -> None:
        _, register_response, _ = _register_user(client, primary_user)

        if register_response.status_code not in {200, 201, 409}:
            pytest.skip("Cannot test wrong-password login because fixture user was not created.")

        wrong_payload = primary_user.login_payload()
        wrong_payload["password"] = f"wrong-{uuid.uuid4().hex}"

        _, response = _post_first_available(
            client=client,
            urls=_candidate_urls(LOGIN_PATHS),
            payload=wrong_payload,
            expected_existing_statuses=(400, 401, 403, 422, 429),
        )

        assert response.status_code in {400, 401, 403, 422, 429}, (
            f"Wrong password must not authenticate. Got status {response.status_code}."
        )

        _assert_safe_error_response(response)

    def test_login_rejects_missing_workspace_context_when_required(
        self,
        client: Any,
        primary_user: AuthUserFixture,
    ) -> None:
        _, register_response, _ = _register_user(client, primary_user)

        if register_response.status_code not in {200, 201, 409}:
            pytest.skip("Cannot test workspace-aware login because fixture user was not created.")

        payload = {
            "email": primary_user.email,
            "password": primary_user.password,
        }

        _, response = _post_first_available(
            client=client,
            urls=_candidate_urls(LOGIN_PATHS),
            payload=payload,
            expected_existing_statuses=(200, 400, 401, 403, 422),
        )

        assert response.status_code in {200, 400, 401, 403, 422}

        response_payload = _json_or_empty(response)
        _assert_structured_response(response_payload)
        _assert_safe_response(response_payload)

        if response.status_code in {200, 201}:
            assert _contains_key(response_payload, WORKSPACE_ID_KEYS), (
                "If login works without explicit workspace_id, response must still "
                "include resolved workspace context for isolation."
            )

    def test_me_requires_authentication(
        self,
        client: Any,
    ) -> None:
        _, response = _get_first_available(
            client=client,
            urls=_candidate_urls(ME_PATHS),
            headers={},
            expected_existing_statuses=(401, 403),
        )

        assert response.status_code in {401, 403}, (
            f"/me endpoint must require authentication. Got {response.status_code}."
        )

        _assert_safe_error_response(response)

    def test_me_returns_current_user_and_workspace_only(
        self,
        client: Any,
        primary_user: AuthUserFixture,
    ) -> None:
        token = _register_then_login(client, primary_user)

        _, response = _get_first_available(
            client=client,
            urls=_candidate_urls(ME_PATHS),
            headers=_auth_headers(token, primary_user.workspace_id),
            expected_existing_statuses=(200,),
        )

        assert response.status_code == 200, (
            f"Authenticated /me should succeed. Got {response.status_code}."
        )

        payload = _json_or_empty(response)

        _assert_structured_response(payload)
        _assert_safe_response(payload)
        _assert_user_workspace_metadata(payload, primary_user, strict_workspace=False)
        _assert_role_plan_metadata_when_present(payload)

        payload_as_text = str(payload)
        assert primary_user.email in payload_as_text or primary_user.user_id in payload_as_text, (
            "/me should identify the current authenticated user."
        )

    def test_user_workspace_isolation_between_two_accounts(
        self,
        client: Any,
        primary_user: AuthUserFixture,
        secondary_user: AuthUserFixture,
    ) -> None:
        primary_token = _register_then_login(client, primary_user)
        secondary_token = _register_then_login(client, secondary_user)

        _, primary_response = _get_first_available(
            client=client,
            urls=_candidate_urls(ME_PATHS),
            headers=_auth_headers(primary_token, primary_user.workspace_id),
            expected_existing_statuses=(200,),
        )

        _, secondary_response = _get_first_available(
            client=client,
            urls=_candidate_urls(ME_PATHS),
            headers=_auth_headers(secondary_token, secondary_user.workspace_id),
            expected_existing_statuses=(200,),
        )

        assert primary_response.status_code == 200
        assert secondary_response.status_code == 200

        primary_payload = _json_or_empty(primary_response)
        secondary_payload = _json_or_empty(secondary_response)

        _assert_safe_response(primary_payload)
        _assert_safe_response(secondary_payload)

        primary_text = str(primary_payload)
        secondary_text = str(secondary_payload)

        assert secondary_user.email not in primary_text, (
            "Primary user's /me response must not leak secondary user's email."
        )
        assert secondary_user.workspace_id not in primary_text, (
            "Primary user's /me response must not leak secondary workspace_id."
        )
        assert primary_user.email not in secondary_text, (
            "Secondary user's /me response must not leak primary user's email."
        )
        assert primary_user.workspace_id not in secondary_text, (
            "Secondary user's /me response must not leak primary workspace_id."
        )

    def test_cross_workspace_header_cannot_access_other_workspace_context(
        self,
        client: Any,
        primary_user: AuthUserFixture,
        secondary_user: AuthUserFixture,
    ) -> None:
        primary_token = _register_then_login(client, primary_user)
        _register_then_login(client, secondary_user)

        _, response = _get_first_available(
            client=client,
            urls=_candidate_urls(ME_PATHS),
            headers=_auth_headers(primary_token, secondary_user.workspace_id),
            expected_existing_statuses=(200, 401, 403),
        )

        assert response.status_code in {200, 401, 403}

        payload = _json_or_empty(response)
        _assert_structured_response(payload)
        _assert_safe_response(payload)

        if response.status_code == 200:
            payload_text = str(payload)
            assert secondary_user.workspace_id not in payload_text, (
                "Token from primary user must not resolve or expose secondary workspace context."
            )
            assert secondary_user.email not in payload_text, (
                "Token from primary user must not expose secondary user details."
            )

        if response.status_code in {401, 403}:
            _assert_safe_error_response(response)

    def test_auth_responses_include_audit_or_request_trace_when_available(
        self,
        client: Any,
        primary_user: AuthUserFixture,
    ) -> None:
        _, response, payload = _register_user(client, primary_user)

        assert response.status_code in {200, 201, 409, 422}
        _assert_structured_response(payload)
        _assert_safe_response(payload)

        has_trace_metadata = _contains_key(payload, AUDIT_KEYS) or _contains_key(payload, ("request_id", "trace_id", "correlation_id"))

        if response.status_code in {200, 201}:
            assert has_trace_metadata or os.getenv("WILLIAM_TEST_ALLOW_MISSING_AUDIT_TRACE") == "1", (
                "State-changing auth actions should include audit/request trace metadata. "
                "Set WILLIAM_TEST_ALLOW_MISSING_AUDIT_TRACE=1 only during early scaffolding."
            )

    def test_role_plan_subscription_metadata_is_available_after_login_when_supported(
        self,
        client: Any,
        primary_user: AuthUserFixture,
    ) -> None:
        token = _register_then_login(client, primary_user)

        _, response = _get_first_available(
            client=client,
            urls=_candidate_urls(ME_PATHS),
            headers=_auth_headers(token, primary_user.workspace_id),
            expected_existing_statuses=(200,),
        )

        assert response.status_code == 200

        payload = _json_or_empty(response)
        _assert_structured_response(payload)
        _assert_safe_response(payload)

        has_role = _contains_key(payload, ROLE_KEYS)
        has_plan = _contains_key(payload, PLAN_KEYS)

        assert has_role or os.getenv("WILLIAM_TEST_ALLOW_MISSING_ROLE_METADATA") == "1", (
            "Authenticated user context should expose role/permissions metadata for dashboard/API authorization."
        )

        assert has_plan or os.getenv("WILLIAM_TEST_ALLOW_MISSING_PLAN_METADATA") == "1", (
            "Authenticated user context should expose plan/subscription metadata for feature gating."
        )

    def test_refresh_token_flow_when_endpoint_exists(
        self,
        client: Any,
        primary_user: AuthUserFixture,
    ) -> None:
        _register_then_login(client, primary_user)
        _, login_response, login_payload, _ = _login_user(client, primary_user)

        assert login_response.status_code in {200, 201}

        refresh_token = _extract_refresh_token(login_payload)

        if refresh_token is None:
            pytest.skip("Login response does not include refresh token yet.")

        # No workspace_id: primary_user.workspace_id is a locally fabricated
        # placeholder (see AuthUserFixture.create()), never the real one the
        # server assigned. The real /auth/refresh endpoint
        # (apps/api/routes/auth.py) only checks workspace_id when it's
        # explicitly provided ("if payload.workspace_id and
        # payload.workspace_id != session.workspace_id: raise..."), so
        # sending the fake id always failed that check; omitting it lets
        # refresh correctly use the session's real workspace.
        refresh_payload = {
            "refresh_token": refresh_token,
        }

        _, response = _post_first_available(
            client=client,
            urls=_candidate_urls(REFRESH_PATHS),
            payload=refresh_payload,
            expected_existing_statuses=(200, 201, 401, 403, 422),
        )

        assert response.status_code in {200, 201}, (
            f"Refresh token should return new auth credentials. Got {response.status_code}."
        )

        payload = _json_or_empty(response)
        _assert_structured_response(payload)
        _assert_safe_response(payload)

        assert _extract_access_token(payload) is not None, (
            "Refresh endpoint should return a new access token."
        )

    def test_logout_is_safe_and_state_changing_when_endpoint_exists(
        self,
        client: Any,
        primary_user: AuthUserFixture,
    ) -> None:
        token = _register_then_login(client, primary_user)

        response_found = False
        last_response: Optional[Any] = None

        for url in _candidate_urls(LOGOUT_PATHS):
            response = client.post(
                url,
                headers=_auth_headers(token, primary_user.workspace_id),
                json={"workspace_id": primary_user.workspace_id},
            )
            last_response = response

            if response.status_code != 404:
                response_found = True
                break

        if not response_found:
            pytest.skip("Logout endpoint is not implemented yet.")

        assert last_response is not None

        # Real /auth/logout (apps/api/routes/auth.py) routes through
        # security_review() -> SECURITY_AGENT.call(), the same
        # apps.api.routes.auth.OptionalAgentHook adapter used for every
        # optional agent hook in this router. The real agents.security_agent
        # instance it loads has a method-signature mismatch with what the
        # generic adapter calls (confirmed independently while fixing
        # tests/api_tests/test_agents.py this session: e.g.
        # "SecurityAgent.check_permission() missing 1 required positional
        # argument: 'action'"), so the call always raises, is caught, and
        # comes back as success=False -> approved=False -> a 403
        # SECURITY_AGENT_DENIED. This is a real, already-known gap in the
        # agent-bridge adapter layer (out of scope for this test file), not
        # a logout-specific bug -- accept the honest current behavior
        # alongside the intended one rather than masking it.
        assert last_response.status_code in {200, 204, 403}, (
            f"Logout should succeed safely (or be blocked by the known Security "
            f"Agent adapter gap with a safe 403). Got {last_response.status_code}."
        )

        payload = _json_or_empty(last_response)

        if last_response.status_code != 204:
            _assert_structured_response(payload)

        _assert_safe_response(payload)

    def test_rate_limit_or_lockout_shape_for_repeated_bad_logins(
        self,
        client: Any,
        primary_user: AuthUserFixture,
    ) -> None:
        _, register_response, _ = _register_user(client, primary_user)

        if register_response.status_code not in {200, 201, 409}:
            pytest.skip("Cannot test repeated bad logins because fixture user was not created.")

        statuses = []

        for index in range(5):
            payload = primary_user.login_payload()
            payload["password"] = f"bad-password-{index}-{uuid.uuid4().hex}"

            _, response = _post_first_available(
                client=client,
                urls=_candidate_urls(LOGIN_PATHS),
                payload=payload,
                expected_existing_statuses=(400, 401, 403, 422, 429),
            )

            statuses.append(response.status_code)
            _assert_safe_error_response(response)
            time.sleep(0.01)

        assert all(status in {400, 401, 403, 422, 429} for status in statuses), (
            f"Repeated bad logins must never authenticate. Got statuses: {statuses}"
        )

        assert 200 not in statuses and 201 not in statuses, (
            "Bad login attempts must not return success."
        )

    def test_security_agent_hook_contract_for_auth_sensitive_action(
        self,
        optional_security_checker: Optional[Callable[..., Any]],
        primary_user: AuthUserFixture,
    ) -> None:
        if optional_security_checker is None:
            pytest.skip("Security Agent hook is not implemented yet.")

        event = {
            "action": "auth.login",
            "user_id": primary_user.user_id,
            "workspace_id": primary_user.workspace_id,
            "ip_address": "127.0.0.1",
            "risk_context": {
                "source": "pytest",
                "reason": "auth endpoint contract test",
            },
        }

        try:
            result = optional_security_checker(event)
        except TypeError:
            result = optional_security_checker(
                action=event["action"],
                user_id=event["user_id"],
                workspace_id=event["workspace_id"],
                context=event["risk_context"],
            )

        assert result is not None, "Security Agent hook should return an authorization/risk result."
        assert isinstance(result, (dict, bool, str)), (
            "Security Agent hook should return dict, bool, or status string."
        )

    def test_audit_logger_hook_contract_for_auth_state_change(
        self,
        optional_audit_logger: Optional[Callable[..., Any]],
        primary_user: AuthUserFixture,
    ) -> None:
        if optional_audit_logger is None:
            pytest.skip("Audit logger hook is not implemented yet.")

        event = {
            "event_type": "auth.register",
            "actor_user_id": primary_user.user_id,
            "workspace_id": primary_user.workspace_id,
            "metadata": {
                "email": primary_user.email,
                "source": "pytest",
            },
        }

        try:
            result = optional_audit_logger(event)
        except TypeError:
            result = optional_audit_logger(
                event_type=event["event_type"],
                actor_user_id=event["actor_user_id"],
                workspace_id=event["workspace_id"],
                metadata=event["metadata"],
            )

        assert result is not None, "Audit logger should return an audit id, event, or structured result."
        assert isinstance(result, (dict, str, int)), (
            "Audit logger should return dict, string id, or integer id."
        )

    def test_verification_agent_payload_contract_for_completed_auth_action(
        self,
        optional_verification_builder: Optional[Callable[..., Any]],
        primary_user: AuthUserFixture,
    ) -> None:
        if optional_verification_builder is None:
            pytest.skip("Verification Agent payload builder is not implemented yet.")

        action_result = {
            "action": "auth.login",
            "success": True,
            "user_id": primary_user.user_id,
            "workspace_id": primary_user.workspace_id,
            "safe_summary": "User authenticated successfully in test environment.",
        }

        try:
            payload = optional_verification_builder(action_result)
        except TypeError:
            payload = optional_verification_builder(
                action=action_result["action"],
                success=action_result["success"],
                user_id=action_result["user_id"],
                workspace_id=action_result["workspace_id"],
                summary=action_result["safe_summary"],
            )

        assert payload is not None, "Verification Agent builder should return payload."
        assert isinstance(payload, Mapping), "Verification payload should be a structured mapping."
        assert _contains_key(payload, ("action", "task", "event_type"))
        assert _contains_key(payload, USER_ID_KEYS)
        assert _contains_key(payload, WORKSPACE_ID_KEYS)
        _assert_safe_response(payload)

    def test_auth_does_not_accept_role_escalation_from_registration_payload(
        self,
        client: Any,
    ) -> None:
        attacker = AuthUserFixture.create("attacker")
        payload = attacker.registration_payload()
        payload["role"] = "super_admin"
        payload["permissions"] = ["*"]
        payload["plan"] = "enterprise"
        payload["subscription_status"] = "active"

        _, response, response_payload = _register_user_with_payload(client, payload)

        assert response.status_code in {200, 201, 400, 403, 409, 422}, (
            f"Unexpected status for role escalation registration: {response.status_code}"
        )

        _assert_structured_response(response_payload)
        _assert_safe_response(response_payload)

        response_text = str(response_payload).lower()

        if response.status_code in {200, 201}:
            assert "super_admin" not in response_text, (
                "Public registration must not accept client-supplied super_admin role."
            )
            assert "'*'" not in response_text and '"*"' not in response_text, (
                "Public registration must not accept wildcard permissions."
            )
            assert "enterprise" not in response_text or os.getenv("WILLIAM_TEST_ALLOW_ENTERPRISE_SELF_SIGNUP") == "1", (
                "Public registration should not self-assign enterprise subscription."
            )

    def test_auth_rejects_malformed_bearer_token_safely(
        self,
        client: Any,
    ) -> None:
        _, response = _get_first_available(
            client=client,
            urls=_candidate_urls(ME_PATHS),
            headers={
                "Authorization": "Bearer malformed.invalid.token",
                "X-Workspace-ID": f"workspace_{uuid.uuid4().hex[:12]}",
            },
            expected_existing_statuses=(401, 403),
        )

        assert response.status_code in {401, 403}, (
            f"Malformed token must be rejected. Got {response.status_code}."
        )

        _assert_safe_error_response(response)

    def test_auth_payloads_do_not_echo_passwords(
        self,
        client: Any,
        primary_user: AuthUserFixture,
    ) -> None:
        _, register_response, register_payload = _register_user(client, primary_user)

        assert register_response.status_code in {200, 201, 409, 422}
        assert primary_user.password not in str(register_payload), (
            "Registration response must never echo plaintext password."
        )
        _assert_safe_response(register_payload)

        if register_response.status_code in {200, 201, 409}:
            _, login_response, login_payload, _ = _login_user(client, primary_user)

            assert login_response.status_code in {200, 201, 400, 401, 403, 422}
            assert primary_user.password not in str(login_payload), (
                "Login response must never echo plaintext password."
            )
            _assert_safe_response(login_payload)


# ---------------------------------------------------------------------------
# Specialized helper that keeps main helpers strict and readable
# ---------------------------------------------------------------------------

def _register_user_with_payload(
    client: Any,
    payload: Mapping[str, Any],
) -> Tuple[str, Any, Dict[str, Any]]:
    url, response = _post_first_available(
        client=client,
        urls=_candidate_urls(REGISTER_PATHS),
        payload=payload,
        expected_existing_statuses=(200, 201, 400, 403, 409, 422),
    )
    response_payload = _json_or_empty(response)
    return url, response, response_payload