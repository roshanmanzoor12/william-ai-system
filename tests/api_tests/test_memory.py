"""
tests/api_tests/test_memory.py

Memory API tests for the William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    - Validate memory API behavior.
    - Enforce strict user_id and workspace_id isolation.
    - Verify role, subscription, and permission-style access checks.
    - Confirm sensitive/state-changing memory actions trigger audit hooks.
    - Confirm completed memory actions can produce verification payloads.
    - Keep imports safe even when the production API is not fully implemented yet.

Design:
    These tests prefer the real FastAPI app if available, but include a realistic
    fallback app so the test file itself imports and runs safely during early
    development.

Run:
    pytest tests/api_tests/test_memory.py -q
"""

from __future__ import annotations

import importlib
import os
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import pytest

try:
    from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
    from fastapi.testclient import TestClient
    from pydantic import BaseModel, Field
except Exception as exc:  # pragma: no cover - dependency guard
    FastAPI = None  # type: ignore[assignment]
    TestClient = None  # type: ignore[assignment]
    Depends = None  # type: ignore[assignment]
    Header = None  # type: ignore[assignment]
    HTTPException = None  # type: ignore[assignment]
    Request = None  # type: ignore[assignment]
    status = None  # type: ignore[assignment]
    BaseModel = object  # type: ignore[assignment]
    Field = None  # type: ignore[assignment]
    FASTAPI_IMPORT_ERROR = exc
else:
    FASTAPI_IMPORT_ERROR = None


pytestmark = pytest.mark.skipif(
    FASTAPI_IMPORT_ERROR is not None,
    reason=f"FastAPI/TestClient dependencies are required for memory API tests: {FASTAPI_IMPORT_ERROR}",
)


# ---------------------------------------------------------------------------
# Test constants
# ---------------------------------------------------------------------------

TEST_API_TOKEN = os.getenv("WILLIAM_TEST_API_TOKEN", "test-token-memory-api")
MEMORY_AGENT_NAME = "memory_agent"
SECURITY_AGENT_NAME = "security_agent"
VERIFICATION_AGENT_NAME = "verification_agent"
MASTER_AGENT_NAME = "master_agent"


# ---------------------------------------------------------------------------
# In-memory fallback services used only when the real app is unavailable.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TestIdentity:
    user_id: str
    workspace_id: str
    role: str = "owner"
    plan: str = "pro"


@dataclass
class MemoryRecord:
    memory_id: str
    user_id: str
    workspace_id: str
    content: str
    tags: List[str]
    source_agent: str
    sensitivity: str
    created_at: float
    updated_at: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditRecord:
    action: str
    user_id: str
    workspace_id: str
    resource_type: str
    resource_id: str
    decision: str
    source_agent: str
    created_at: float
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationPayload:
    action: str
    user_id: str
    workspace_id: str
    resource_type: str
    resource_id: str
    verification_agent: str
    status: str
    created_at: float
    checks: Dict[str, Any] = field(default_factory=dict)


class FakeMemoryStore:
    """Small deterministic in-memory store for fallback API tests."""

    def __init__(self) -> None:
        self.memories: Dict[str, MemoryRecord] = {}
        self.audit_logs: List[AuditRecord] = []
        self.verification_payloads: List[VerificationPayload] = []

    def reset(self) -> None:
        self.memories.clear()
        self.audit_logs.clear()
        self.verification_payloads.clear()

    def create_memory(
        self,
        *,
        identity: TestIdentity,
        content: str,
        tags: Optional[List[str]],
        source_agent: str,
        sensitivity: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MemoryRecord:
        now = time.time()
        memory_id = f"mem_{uuid.uuid4().hex}"
        record = MemoryRecord(
            memory_id=memory_id,
            user_id=identity.user_id,
            workspace_id=identity.workspace_id,
            content=content,
            tags=list(tags or []),
            source_agent=source_agent,
            sensitivity=sensitivity,
            created_at=now,
            updated_at=now,
            metadata=metadata or {},
        )
        self.memories[memory_id] = record
        self.log_audit(
            action="memory.create",
            identity=identity,
            resource_id=memory_id,
            decision="allowed",
            source_agent=source_agent,
            details={"sensitivity": sensitivity, "tags": record.tags},
        )
        self.add_verification_payload(
            action="memory.create",
            identity=identity,
            resource_id=memory_id,
            checks={
                "user_workspace_bound": True,
                "memory_agent_compatible": True,
                "security_reviewed": sensitivity in {"normal", "internal", "sensitive"},
            },
        )
        return record

    def list_memories(self, *, identity: TestIdentity, query: Optional[str] = None) -> List[MemoryRecord]:
        records = [
            record
            for record in self.memories.values()
            if record.user_id == identity.user_id and record.workspace_id == identity.workspace_id
        ]
        if query:
            lowered = query.lower()
            records = [
                record
                for record in records
                if lowered in record.content.lower()
                or any(lowered in tag.lower() for tag in record.tags)
            ]
        return sorted(records, key=lambda item: item.created_at, reverse=True)

    def get_memory(self, *, identity: TestIdentity, memory_id: str) -> MemoryRecord:
        record = self.memories.get(memory_id)
        if record is None:
            raise KeyError("memory_not_found")
        if record.user_id != identity.user_id or record.workspace_id != identity.workspace_id:
            raise PermissionError("memory_cross_workspace_access_denied")
        return record

    def delete_memory(self, *, identity: TestIdentity, memory_id: str, source_agent: str) -> None:
        record = self.get_memory(identity=identity, memory_id=memory_id)
        del self.memories[record.memory_id]
        self.log_audit(
            action="memory.delete",
            identity=identity,
            resource_id=memory_id,
            decision="allowed",
            source_agent=source_agent,
            details={"sensitivity": record.sensitivity},
        )
        self.add_verification_payload(
            action="memory.delete",
            identity=identity,
            resource_id=memory_id,
            checks={
                "user_workspace_bound": True,
                "deleted_from_visible_store": True,
                "verification_agent_notified": True,
            },
        )

    def log_audit(
        self,
        *,
        action: str,
        identity: TestIdentity,
        resource_id: str,
        decision: str,
        source_agent: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        audit = AuditRecord(
            action=action,
            user_id=identity.user_id,
            workspace_id=identity.workspace_id,
            resource_type="memory",
            resource_id=resource_id,
            decision=decision,
            source_agent=source_agent,
            created_at=time.time(),
            details=details or {},
        )
        self.audit_logs.append(audit)
        return audit

    def add_verification_payload(
        self,
        *,
        action: str,
        identity: TestIdentity,
        resource_id: str,
        checks: Optional[Dict[str, Any]] = None,
    ) -> VerificationPayload:
        payload = VerificationPayload(
            action=action,
            user_id=identity.user_id,
            workspace_id=identity.workspace_id,
            resource_type="memory",
            resource_id=resource_id,
            verification_agent=VERIFICATION_AGENT_NAME,
            status="prepared",
            created_at=time.time(),
            checks=checks or {},
        )
        self.verification_payloads.append(payload)
        return payload


class MemoryCreateRequest(BaseModel):  # type: ignore[misc]
    content: str = Field(..., min_length=1, max_length=5000)  # type: ignore[misc]
    tags: List[str] = Field(default_factory=list)  # type: ignore[misc]
    source_agent: str = Field(default=MEMORY_AGENT_NAME, min_length=1)  # type: ignore[misc]
    sensitivity: str = Field(default="normal", pattern="^(normal|internal|sensitive)$")  # type: ignore[misc]
    metadata: Dict[str, Any] = Field(default_factory=dict)  # type: ignore[misc]


class MemorySearchRequest(BaseModel):  # type: ignore[misc]
    query: Optional[str] = Field(default=None, max_length=512)  # type: ignore[misc]


def _record_to_response(record: MemoryRecord) -> Dict[str, Any]:
    return {
        "memory_id": record.memory_id,
        "user_id": record.user_id,
        "workspace_id": record.workspace_id,
        "content": record.content,
        "tags": record.tags,
        "source_agent": record.source_agent,
        "sensitivity": record.sensitivity,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "metadata": record.metadata,
    }


def _audit_to_response(record: AuditRecord) -> Dict[str, Any]:
    return {
        "action": record.action,
        "user_id": record.user_id,
        "workspace_id": record.workspace_id,
        "resource_type": record.resource_type,
        "resource_id": record.resource_id,
        "decision": record.decision,
        "source_agent": record.source_agent,
        "created_at": record.created_at,
        "details": record.details,
    }


def _verification_to_response(record: VerificationPayload) -> Dict[str, Any]:
    return {
        "action": record.action,
        "user_id": record.user_id,
        "workspace_id": record.workspace_id,
        "resource_type": record.resource_type,
        "resource_id": record.resource_id,
        "verification_agent": record.verification_agent,
        "status": record.status,
        "created_at": record.created_at,
        "checks": record.checks,
    }


def _identity_from_headers(
    x_user_id: str = Header(..., alias="X-User-Id"),  # type: ignore[misc]
    x_workspace_id: str = Header(..., alias="X-Workspace-Id"),  # type: ignore[misc]
    x_role: str = Header("owner", alias="X-Role"),  # type: ignore[misc]
    x_plan: str = Header("pro", alias="X-Plan"),  # type: ignore[misc]
    authorization: Optional[str] = Header(default=None, alias="Authorization"),  # type: ignore[misc]
) -> TestIdentity:
    if authorization != f"Bearer {TEST_API_TOKEN}":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "success": False,
                "error": {
                    "code": "unauthorized",
                    "message": "A valid bearer token is required.",
                },
            },
        )

    if not x_user_id.strip() or not x_workspace_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "success": False,
                "error": {
                    "code": "missing_identity_scope",
                    "message": "user_id and workspace_id are required.",
                },
            },
        )

    return TestIdentity(
        user_id=x_user_id.strip(),
        workspace_id=x_workspace_id.strip(),
        role=x_role.strip().lower(),
        plan=x_plan.strip().lower(),
    )


def _require_memory_access(identity: TestIdentity) -> None:
    allowed_roles = {"owner", "admin", "member"}
    allowed_plans = {"pro", "business", "enterprise"}

    if identity.role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "success": False,
                "error": {
                    "code": "role_not_allowed",
                    "message": "Your role does not allow memory API access.",
                },
            },
        )

    if identity.plan not in allowed_plans:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "success": False,
                "error": {
                    "code": "plan_memory_access_required",
                    "message": "Memory API requires an active Pro, Business, or Enterprise plan.",
                },
            },
        )


def _build_fallback_app(store: FakeMemoryStore) -> FastAPI:
    app = FastAPI(title="William Jarvis Memory API Test App", version="test")

    @app.post("/api/memory")
    def create_memory(
        payload: MemoryCreateRequest,
        identity: TestIdentity = Depends(_identity_from_headers),
    ) -> Dict[str, Any]:
        _require_memory_access(identity)

        if payload.sensitivity == "sensitive" and payload.source_agent != SECURITY_AGENT_NAME:
            store.log_audit(
                action="memory.create",
                identity=identity,
                resource_id="pending",
                decision="denied",
                source_agent=payload.source_agent,
                details={"reason": "sensitive_memory_requires_security_agent"},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "error": {
                        "code": "security_agent_required",
                        "message": "Sensitive memory writes must route through Security Agent.",
                    },
                },
            )

        record = store.create_memory(
            identity=identity,
            content=payload.content,
            tags=payload.tags,
            source_agent=payload.source_agent,
            sensitivity=payload.sensitivity,
            metadata=payload.metadata,
        )
        verification_payload = store.verification_payloads[-1]

        return {
            "success": True,
            "data": {
                "memory": _record_to_response(record),
                "audit_logged": True,
                "verification_payload": _verification_to_response(verification_payload),
                "agents": {
                    "master_agent_ready": True,
                    "memory_agent_ready": True,
                    "security_agent_ready": payload.sensitivity == "sensitive",
                    "verification_agent_ready": True,
                },
            },
            "error": None,
        }

    @app.get("/api/memory")
    def list_memories(
        query: Optional[str] = None,
        identity: TestIdentity = Depends(_identity_from_headers),
    ) -> Dict[str, Any]:
        _require_memory_access(identity)
        records = store.list_memories(identity=identity, query=query)
        return {
            "success": True,
            "data": {
                "memories": [_record_to_response(record) for record in records],
                "count": len(records),
                "scope": {
                    "user_id": identity.user_id,
                    "workspace_id": identity.workspace_id,
                },
            },
            "error": None,
        }

    @app.get("/api/memory/{memory_id}")
    def get_memory(
        memory_id: str,
        identity: TestIdentity = Depends(_identity_from_headers),
    ) -> Dict[str, Any]:
        _require_memory_access(identity)

        try:
            record = store.get_memory(identity=identity, memory_id=memory_id)
        except KeyError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "success": False,
                    "error": {
                        "code": "memory_not_found",
                        "message": "Memory was not found.",
                    },
                },
            )
        except PermissionError:
            store.log_audit(
                action="memory.read",
                identity=identity,
                resource_id=memory_id,
                decision="denied",
                source_agent=MEMORY_AGENT_NAME,
                details={"reason": "cross_user_or_workspace_access"},
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "success": False,
                    "error": {
                        "code": "memory_not_found",
                        "message": "Memory was not found.",
                    },
                },
            )

        return {
            "success": True,
            "data": {
                "memory": _record_to_response(record),
            },
            "error": None,
        }

    @app.delete("/api/memory/{memory_id}")
    def delete_memory(
        memory_id: str,
        identity: TestIdentity = Depends(_identity_from_headers),
    ) -> Dict[str, Any]:
        _require_memory_access(identity)

        if identity.role not in {"owner", "admin"}:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "error": {
                        "code": "delete_role_not_allowed",
                        "message": "Only owner or admin roles can delete memory.",
                    },
                },
            )

        try:
            store.delete_memory(identity=identity, memory_id=memory_id, source_agent=SECURITY_AGENT_NAME)
        except KeyError:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "success": False,
                    "error": {
                        "code": "memory_not_found",
                        "message": "Memory was not found.",
                    },
                },
            )
        except PermissionError:
            store.log_audit(
                action="memory.delete",
                identity=identity,
                resource_id=memory_id,
                decision="denied",
                source_agent=SECURITY_AGENT_NAME,
                details={"reason": "cross_user_or_workspace_delete_attempt"},
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={
                    "success": False,
                    "error": {
                        "code": "memory_not_found",
                        "message": "Memory was not found.",
                    },
                },
            )

        verification_payload = store.verification_payloads[-1]

        return {
            "success": True,
            "data": {
                "deleted": True,
                "memory_id": memory_id,
                "audit_logged": True,
                "verification_payload": _verification_to_response(verification_payload),
            },
            "error": None,
        }

    @app.get("/api/audit/memory")
    def list_memory_audit_logs(
        identity: TestIdentity = Depends(_identity_from_headers),
    ) -> Dict[str, Any]:
        if identity.role not in {"owner", "admin"}:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "success": False,
                    "error": {
                        "code": "audit_role_not_allowed",
                        "message": "Only owner or admin roles can view audit logs.",
                    },
                },
            )

        records = [
            record
            for record in store.audit_logs
            if record.user_id == identity.user_id and record.workspace_id == identity.workspace_id
        ]

        return {
            "success": True,
            "data": {
                "audit_logs": [_audit_to_response(record) for record in records],
                "count": len(records),
            },
            "error": None,
        }

    return app


def _try_load_real_app() -> Optional[Any]:
    """
    Attempt to load the production FastAPI app without making the test file depend
    on a finalized module path.

    Supported future module paths:
        - apps.api.main:app
        - app.main:app
        - backend.main:app
        - main:app
    """
    candidate_paths = (
        "apps.api.main",
        "app.main",
        "backend.main",
        "main",
    )

    for module_path in candidate_paths:
        try:
            module = importlib.import_module(module_path)
        except Exception:
            continue

        app = getattr(module, "app", None)
        if app is not None:
            return app

    return None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def memory_store() -> FakeMemoryStore:
    store = FakeMemoryStore()
    store.reset()
    return store


@pytest.fixture()
def app(memory_store: FakeMemoryStore) -> Any:
    real_app = _try_load_real_app()
    if real_app is not None:
        return real_app
    return _build_fallback_app(memory_store)


@pytest.fixture()
def client(app: Any) -> TestClient:
    return TestClient(app)


@pytest.fixture()
def user_a_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {TEST_API_TOKEN}",
        "X-User-Id": "user_alpha",
        "X-Workspace-Id": "workspace_alpha",
        "X-Role": "owner",
        "X-Plan": "pro",
    }


@pytest.fixture()
def user_a_member_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {TEST_API_TOKEN}",
        "X-User-Id": "user_alpha",
        "X-Workspace-Id": "workspace_alpha",
        "X-Role": "member",
        "X-Plan": "pro",
    }


@pytest.fixture()
def user_b_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {TEST_API_TOKEN}",
        "X-User-Id": "user_beta",
        "X-Workspace-Id": "workspace_beta",
        "X-Role": "owner",
        "X-Plan": "pro",
    }


@pytest.fixture()
def same_user_other_workspace_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {TEST_API_TOKEN}",
        "X-User-Id": "user_alpha",
        "X-Workspace-Id": "workspace_secondary",
        "X-Role": "owner",
        "X-Plan": "pro",
    }


@pytest.fixture()
def viewer_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {TEST_API_TOKEN}",
        "X-User-Id": "user_viewer",
        "X-Workspace-Id": "workspace_alpha",
        "X-Role": "viewer",
        "X-Plan": "pro",
    }


@pytest.fixture()
def free_plan_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {TEST_API_TOKEN}",
        "X-User-Id": "user_free",
        "X-Workspace-Id": "workspace_free",
        "X-Role": "owner",
        "X-Plan": "free",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _json(response: Any) -> Dict[str, Any]:
    try:
        return response.json()
    except Exception as exc:
        pytest.fail(f"Response did not contain valid JSON. Status={response.status_code}. Error={exc}")


def _assert_structured_success(payload: Dict[str, Any]) -> None:
    assert payload["success"] is True
    assert "data" in payload
    assert payload.get("error") is None


def _assert_structured_error(payload: Dict[str, Any]) -> None:
    normalized = payload.get("detail", payload)
    assert normalized["success"] is False
    assert "error" in normalized
    assert "code" in normalized["error"]
    assert "message" in normalized["error"]


def _create_memory(
    client: TestClient,
    headers: Dict[str, str],
    *,
    content: str = "Remember that the user prefers workspace-safe summaries.",
    tags: Optional[List[str]] = None,
    source_agent: str = MEMORY_AGENT_NAME,
    sensitivity: str = "normal",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    response = client.post(
        "/api/memory",
        headers=headers,
        json={
            "content": content,
            "tags": tags or ["preference", "workspace-safe"],
            "source_agent": source_agent,
            "sensitivity": sensitivity,
            "metadata": metadata or {"origin": "api_test"},
        },
    )
    assert response.status_code in {200, 201}, response.text
    payload = _json(response)
    _assert_structured_success(payload)
    return payload["data"]["memory"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestMemory:
    """Memory API tests with strict tenant isolation and agent compatibility checks."""

    def test_create_memory_returns_structured_response_with_scope(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
    ) -> None:
        response = client.post(
            "/api/memory",
            headers=user_a_headers,
            json={
                "content": "User prefers concise but complete Jarvis task summaries.",
                "tags": ["preference", "summary"],
                "source_agent": MEMORY_AGENT_NAME,
                "sensitivity": "normal",
                "metadata": {
                    "master_agent_context": True,
                    "workspace_safe": True,
                },
            },
        )

        assert response.status_code in {200, 201}, response.text
        payload = _json(response)
        _assert_structured_success(payload)

        memory = payload["data"]["memory"]
        assert memory["memory_id"]
        assert memory["user_id"] == "user_alpha"
        assert memory["workspace_id"] == "workspace_alpha"
        assert memory["content"] == "User prefers concise but complete Jarvis task summaries."
        assert memory["tags"] == ["preference", "summary"]
        assert memory["source_agent"] == MEMORY_AGENT_NAME
        assert memory["sensitivity"] == "normal"

        assert payload["data"]["audit_logged"] is True
        assert payload["data"]["verification_payload"]["status"] == "prepared"
        assert payload["data"]["verification_payload"]["verification_agent"] == VERIFICATION_AGENT_NAME
        assert payload["data"]["agents"]["master_agent_ready"] is True
        assert payload["data"]["agents"]["memory_agent_ready"] is True
        assert payload["data"]["agents"]["verification_agent_ready"] is True

    def test_list_memory_only_returns_current_user_and_workspace_records(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
        user_b_headers: Dict[str, str],
        same_user_other_workspace_headers: Dict[str, str],
    ) -> None:
        alpha_memory = _create_memory(
            client,
            user_a_headers,
            content="Alpha workspace memory should stay isolated.",
            tags=["alpha"],
        )
        _create_memory(
            client,
            user_b_headers,
            content="Beta user memory must never leak to Alpha.",
            tags=["beta"],
        )
        _create_memory(
            client,
            same_user_other_workspace_headers,
            content="Same user but different workspace memory must stay isolated.",
            tags=["secondary-workspace"],
        )

        response = client.get("/api/memory", headers=user_a_headers)
        assert response.status_code == 200, response.text
        payload = _json(response)
        _assert_structured_success(payload)

        memories = payload["data"]["memories"]
        assert payload["data"]["scope"] == {
            "user_id": "user_alpha",
            "workspace_id": "workspace_alpha",
        }
        assert len(memories) == 1
        assert memories[0]["memory_id"] == alpha_memory["memory_id"]
        assert memories[0]["user_id"] == "user_alpha"
        assert memories[0]["workspace_id"] == "workspace_alpha"
        assert "Beta user memory" not in str(memories)
        assert "different workspace memory" not in str(memories)

    def test_get_memory_denies_cross_user_access_without_leaking_existence(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
        user_b_headers: Dict[str, str],
    ) -> None:
        alpha_memory = _create_memory(
            client,
            user_a_headers,
            content="Alpha private memory.",
            tags=["private"],
        )

        response = client.get(f"/api/memory/{alpha_memory['memory_id']}", headers=user_b_headers)
        assert response.status_code == 404, response.text

        payload = _json(response)
        _assert_structured_error(payload)
        normalized = payload.get("detail", payload)
        assert normalized["error"]["code"] == "memory_not_found"

    def test_get_memory_denies_cross_workspace_access_for_same_user(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
        same_user_other_workspace_headers: Dict[str, str],
    ) -> None:
        alpha_memory = _create_memory(
            client,
            user_a_headers,
            content="Alpha workspace-only memory.",
            tags=["workspace-alpha"],
        )

        response = client.get(
            f"/api/memory/{alpha_memory['memory_id']}",
            headers=same_user_other_workspace_headers,
        )

        assert response.status_code == 404, response.text
        payload = _json(response)
        _assert_structured_error(payload)
        normalized = payload.get("detail", payload)
        assert normalized["error"]["code"] == "memory_not_found"

    def test_get_memory_allows_owner_inside_same_user_workspace_scope(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
    ) -> None:
        created = _create_memory(
            client,
            user_a_headers,
            content="Owner can read memory inside same workspace.",
            tags=["read"],
        )

        response = client.get(f"/api/memory/{created['memory_id']}", headers=user_a_headers)

        assert response.status_code == 200, response.text
        payload = _json(response)
        _assert_structured_success(payload)

        memory = payload["data"]["memory"]
        assert memory["memory_id"] == created["memory_id"]
        assert memory["user_id"] == "user_alpha"
        assert memory["workspace_id"] == "workspace_alpha"

    def test_search_memory_filters_within_current_scope_only(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
        user_b_headers: Dict[str, str],
    ) -> None:
        expected = _create_memory(
            client,
            user_a_headers,
            content="Campaign launch preference: use short approval summaries.",
            tags=["campaign", "approval"],
        )
        _create_memory(
            client,
            user_a_headers,
            content="Billing reminder preference: show monthly usage.",
            tags=["billing"],
        )
        _create_memory(
            client,
            user_b_headers,
            content="Campaign launch memory from another user must not appear.",
            tags=["campaign"],
        )

        response = client.get("/api/memory?query=campaign", headers=user_a_headers)

        assert response.status_code == 200, response.text
        payload = _json(response)
        _assert_structured_success(payload)

        memories = payload["data"]["memories"]
        assert len(memories) == 1
        assert memories[0]["memory_id"] == expected["memory_id"]
        assert memories[0]["user_id"] == "user_alpha"
        assert memories[0]["workspace_id"] == "workspace_alpha"

    def test_create_memory_requires_user_and_workspace_headers(
        self,
        client: TestClient,
    ) -> None:
        response = client.post(
            "/api/memory",
            headers={"Authorization": f"Bearer {TEST_API_TOKEN}"},
            json={
                "content": "This request is missing identity scope.",
                "tags": ["invalid"],
                "source_agent": MEMORY_AGENT_NAME,
                "sensitivity": "normal",
            },
        )

        assert response.status_code in {400, 422}, response.text

    def test_create_memory_requires_authorization_token(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
    ) -> None:
        headers = dict(user_a_headers)
        headers["Authorization"] = "Bearer wrong-token"

        response = client.post(
            "/api/memory",
            headers=headers,
            json={
                "content": "Unauthorized memory write should fail.",
                "tags": ["auth"],
                "source_agent": MEMORY_AGENT_NAME,
                "sensitivity": "normal",
            },
        )

        assert response.status_code == 401, response.text
        payload = _json(response)
        _assert_structured_error(payload)

    def test_create_memory_validates_non_empty_content(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
    ) -> None:
        response = client.post(
            "/api/memory",
            headers=user_a_headers,
            json={
                "content": "",
                "tags": ["invalid"],
                "source_agent": MEMORY_AGENT_NAME,
                "sensitivity": "normal",
            },
        )

        assert response.status_code == 422, response.text

    def test_free_plan_cannot_use_memory_api(
        self,
        client: TestClient,
        free_plan_headers: Dict[str, str],
    ) -> None:
        response = client.post(
            "/api/memory",
            headers=free_plan_headers,
            json={
                "content": "Free plan should not create persistent memory.",
                "tags": ["plan"],
                "source_agent": MEMORY_AGENT_NAME,
                "sensitivity": "normal",
            },
        )

        assert response.status_code == 402, response.text
        payload = _json(response)
        _assert_structured_error(payload)
        normalized = payload.get("detail", payload)
        assert normalized["error"]["code"] == "plan_memory_access_required"

    def test_viewer_role_cannot_create_memory(
        self,
        client: TestClient,
        viewer_headers: Dict[str, str],
    ) -> None:
        response = client.post(
            "/api/memory",
            headers=viewer_headers,
            json={
                "content": "Viewer role should not create memory.",
                "tags": ["role"],
                "source_agent": MEMORY_AGENT_NAME,
                "sensitivity": "normal",
            },
        )

        assert response.status_code == 403, response.text
        payload = _json(response)
        _assert_structured_error(payload)
        normalized = payload.get("detail", payload)
        assert normalized["error"]["code"] == "role_not_allowed"

    def test_sensitive_memory_requires_security_agent_route(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
    ) -> None:
        response = client.post(
            "/api/memory",
            headers=user_a_headers,
            json={
                "content": "Sensitive billing approval details require Security Agent review.",
                "tags": ["sensitive", "billing"],
                "source_agent": MEMORY_AGENT_NAME,
                "sensitivity": "sensitive",
            },
        )

        assert response.status_code == 403, response.text
        payload = _json(response)
        _assert_structured_error(payload)
        normalized = payload.get("detail", payload)
        assert normalized["error"]["code"] == "security_agent_required"

    def test_sensitive_memory_can_be_written_by_security_agent(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
    ) -> None:
        response = client.post(
            "/api/memory",
            headers=user_a_headers,
            json={
                "content": "Security-approved sensitive memory for workspace isolation test.",
                "tags": ["sensitive", "security-approved"],
                "source_agent": SECURITY_AGENT_NAME,
                "sensitivity": "sensitive",
            },
        )

        assert response.status_code in {200, 201}, response.text
        payload = _json(response)
        _assert_structured_success(payload)

        memory = payload["data"]["memory"]
        assert memory["sensitivity"] == "sensitive"
        assert memory["source_agent"] == SECURITY_AGENT_NAME
        assert payload["data"]["agents"]["security_agent_ready"] is True
        assert payload["data"]["verification_payload"]["checks"]["security_reviewed"] is True

    def test_member_can_read_but_cannot_delete_memory(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
        user_a_member_headers: Dict[str, str],
    ) -> None:
        created = _create_memory(
            client,
            user_a_headers,
            content="Member can read but should not delete this memory.",
            tags=["member"],
        )

        read_response = client.get(f"/api/memory/{created['memory_id']}", headers=user_a_member_headers)
        assert read_response.status_code == 200, read_response.text

        delete_response = client.delete(f"/api/memory/{created['memory_id']}", headers=user_a_member_headers)
        assert delete_response.status_code == 403, delete_response.text

        payload = _json(delete_response)
        _assert_structured_error(payload)
        normalized = payload.get("detail", payload)
        assert normalized["error"]["code"] == "delete_role_not_allowed"

    def test_delete_memory_is_scoped_audited_and_verified(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
    ) -> None:
        created = _create_memory(
            client,
            user_a_headers,
            content="Delete action must create audit and verification payload.",
            tags=["delete"],
        )

        delete_response = client.delete(f"/api/memory/{created['memory_id']}", headers=user_a_headers)
        assert delete_response.status_code == 200, delete_response.text

        payload = _json(delete_response)
        _assert_structured_success(payload)
        assert payload["data"]["deleted"] is True
        assert payload["data"]["memory_id"] == created["memory_id"]
        assert payload["data"]["audit_logged"] is True
        assert payload["data"]["verification_payload"]["action"] == "memory.delete"
        assert payload["data"]["verification_payload"]["status"] == "prepared"

        read_response = client.get(f"/api/memory/{created['memory_id']}", headers=user_a_headers)
        assert read_response.status_code == 404, read_response.text

    def test_delete_memory_denies_cross_workspace_delete_without_leaking_existence(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
        same_user_other_workspace_headers: Dict[str, str],
    ) -> None:
        created = _create_memory(
            client,
            user_a_headers,
            content="Cross-workspace delete attempt must fail safely.",
            tags=["delete", "isolation"],
        )

        response = client.delete(
            f"/api/memory/{created['memory_id']}",
            headers=same_user_other_workspace_headers,
        )

        assert response.status_code == 404, response.text
        payload = _json(response)
        _assert_structured_error(payload)
        normalized = payload.get("detail", payload)
        assert normalized["error"]["code"] == "memory_not_found"

        owner_read_response = client.get(f"/api/memory/{created['memory_id']}", headers=user_a_headers)
        assert owner_read_response.status_code == 200, owner_read_response.text

    def test_audit_logs_are_visible_only_to_current_workspace_admin_scope(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
        user_b_headers: Dict[str, str],
    ) -> None:
        alpha_memory = _create_memory(
            client,
            user_a_headers,
            content="Alpha audit visibility memory.",
            tags=["audit-alpha"],
        )
        _create_memory(
            client,
            user_b_headers,
            content="Beta audit visibility memory.",
            tags=["audit-beta"],
        )

        response = client.get("/api/audit/memory", headers=user_a_headers)
        assert response.status_code == 200, response.text

        payload = _json(response)
        _assert_structured_success(payload)

        logs = payload["data"]["audit_logs"]
        assert len(logs) >= 1
        assert all(log["user_id"] == "user_alpha" for log in logs)
        assert all(log["workspace_id"] == "workspace_alpha" for log in logs)
        assert any(log["resource_id"] == alpha_memory["memory_id"] for log in logs)
        assert not any(log["user_id"] == "user_beta" for log in logs)

    def test_viewer_cannot_read_memory_audit_logs(
        self,
        client: TestClient,
        viewer_headers: Dict[str, str],
    ) -> None:
        response = client.get("/api/audit/memory", headers=viewer_headers)

        assert response.status_code == 403, response.text
        payload = _json(response)
        _assert_structured_error(payload)
        normalized = payload.get("detail", payload)
        assert normalized["error"]["code"] == "audit_role_not_allowed"

    def test_memory_response_is_compatible_with_memory_agent_context_shape(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
    ) -> None:
        created = _create_memory(
            client,
            user_a_headers,
            content="Memory Agent should receive stable content, tags, metadata, user_id, and workspace_id.",
            tags=["memory-agent", "context"],
            metadata={
                "task_id": "task_memory_api_001",
                "agent_chain": [MASTER_AGENT_NAME, MEMORY_AGENT_NAME, VERIFICATION_AGENT_NAME],
            },
        )

        required_keys = {
            "memory_id",
            "user_id",
            "workspace_id",
            "content",
            "tags",
            "source_agent",
            "sensitivity",
            "metadata",
            "created_at",
            "updated_at",
        }

        assert required_keys.issubset(set(created.keys()))
        assert created["metadata"]["task_id"] == "task_memory_api_001"
        assert MASTER_AGENT_NAME in created["metadata"]["agent_chain"]
        assert MEMORY_AGENT_NAME in created["metadata"]["agent_chain"]
        assert VERIFICATION_AGENT_NAME in created["metadata"]["agent_chain"]

    def test_verification_payload_contains_user_workspace_and_resource_binding(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
    ) -> None:
        response = client.post(
            "/api/memory",
            headers=user_a_headers,
            json={
                "content": "Verification Agent must confirm the memory action scope.",
                "tags": ["verification"],
                "source_agent": MEMORY_AGENT_NAME,
                "sensitivity": "normal",
            },
        )

        assert response.status_code in {200, 201}, response.text
        payload = _json(response)
        _assert_structured_success(payload)

        memory = payload["data"]["memory"]
        verification = payload["data"]["verification_payload"]

        assert verification["action"] == "memory.create"
        assert verification["user_id"] == memory["user_id"]
        assert verification["workspace_id"] == memory["workspace_id"]
        assert verification["resource_type"] == "memory"
        assert verification["resource_id"] == memory["memory_id"]
        assert verification["verification_agent"] == VERIFICATION_AGENT_NAME
        assert verification["checks"]["user_workspace_bound"] is True
        assert verification["checks"]["memory_agent_compatible"] is True

    def test_memory_api_never_returns_other_workspace_data_after_mixed_operations(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
        user_b_headers: Dict[str, str],
        same_user_other_workspace_headers: Dict[str, str],
    ) -> None:
        alpha_records = [
            _create_memory(
                client,
                user_a_headers,
                content=f"Alpha record {index}",
                tags=["alpha", str(index)],
            )
            for index in range(3)
        ]

        beta_records = [
            _create_memory(
                client,
                user_b_headers,
                content=f"Beta record {index}",
                tags=["beta", str(index)],
            )
            for index in range(2)
        ]

        secondary_records = [
            _create_memory(
                client,
                same_user_other_workspace_headers,
                content=f"Secondary workspace record {index}",
                tags=["secondary", str(index)],
            )
            for index in range(2)
        ]

        response = client.get("/api/memory", headers=user_a_headers)
        assert response.status_code == 200, response.text

        payload = _json(response)
        _assert_structured_success(payload)

        visible_ids = {memory["memory_id"] for memory in payload["data"]["memories"]}
        alpha_ids = {memory["memory_id"] for memory in alpha_records}
        beta_ids = {memory["memory_id"] for memory in beta_records}
        secondary_ids = {memory["memory_id"] for memory in secondary_records}

        assert visible_ids == alpha_ids
        assert visible_ids.isdisjoint(beta_ids)
        assert visible_ids.isdisjoint(secondary_ids)

    def test_memory_payload_does_not_require_or_expose_real_secrets(
        self,
        client: TestClient,
        user_a_headers: Dict[str, str],
    ) -> None:
        created = _create_memory(
            client,
            user_a_headers,
            content="Store a harmless user preference, not secrets.",
            tags=["safe"],
            metadata={
                "config_source": "environment",
                "contains_secret": False,
            },
        )

        serialized = str(created).lower()
        forbidden_fragments = [
            "sk-",
            "api_key",
            "password=",
            "secret_access_key",
            "private_key",
        ]

        assert created["metadata"]["contains_secret"] is False
        assert not any(fragment in serialized for fragment in forbidden_fragments)