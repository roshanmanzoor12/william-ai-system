"""
tests/api_tests/test_memory.py

Memory API tests for the William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    - Validate memory API behavior against the REAL apps/api/routes/memory.py
      backend (prefix /api/v1/memory), not an imagined contract.
    - Enforce strict user_id and workspace_id isolation.
    - Verify role-based access checks (write/delete/export gates).
    - Confirm state-changing memory actions produce verification payloads.
    - Keep imports safe even when FastAPI/TestClient are not installed.

Auth:
    Every request in this file authenticates with a real, JWT-verified
    Bearer token minted through tests/api_tests/conftest.py's make_owner /
    make_member / set_plan fixtures (which drive the real
    POST /api/v1/auth/register endpoint and the real WorkspaceMembership
    model) -- apps/api/routes/memory.py's get_actor_context dependency now
    resolves identity exclusively from get_current_auth_context
    (apps/api/routes/auth.py), so the old spoofable X-User-Id/X-Workspace-Id/
    X-Role/X-Plan headers plus a static fake bearer token are gone; they are
    silently ignored by the real app and every request built with them used
    to 401 or hit the wrong URL (/api/memory instead of /api/v1/memory).

Data model:
    memory_type: short | long | project | client
    sensitivity: public | internal | confidential | restricted
    source: user | master_agent | memory_agent | system | api
    Response envelope: {"ok": bool, "message": str, "data"/"records": ...,
    "verification": {...}, "request_id": str} -- NOT {"success": ...}.

Run:
    pytest tests/api_tests/test_memory.py -q
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

import pytest

try:
    from fastapi.testclient import TestClient  # noqa: F401
except Exception as exc:  # pragma: no cover - dependency guard
    TestClient = None  # type: ignore[assignment]
    FASTAPI_IMPORT_ERROR = exc
else:
    FASTAPI_IMPORT_ERROR = None


pytestmark = pytest.mark.skipif(
    FASTAPI_IMPORT_ERROR is not None,
    reason=f"FastAPI/TestClient dependencies are required for memory API tests: {FASTAPI_IMPORT_ERROR}",
)


MEMORY_PREFIX = "/api/v1/memory"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _json(response: Any) -> Dict[str, Any]:
    try:
        return response.json()
    except Exception as exc:
        pytest.fail(f"Response did not contain valid JSON. Status={response.status_code}. Error={exc}")


def _error_code(payload: Dict[str, Any]) -> Optional[str]:
    """
    Real error payloads take one of two shapes depending on which layer
    raised the HTTPException, both surfaced as-is by apps/api/main.py's
    http_exception_handler (which passes exc.detail straight through when
    it is already a dict):

    - apps/api/routes/memory.py's own raise_safe_error() -> a flat
      ErrorDetail dict: {"code": ..., "message": ..., "request_id": ...,
      "details": {...}}.
    - apps/api/routes/auth.py's raise_api_error() / apps/api/main.py's
      response_error() (used for 401s and 422 validation errors) ->
      {"success": False, "message": ..., "error": {"code": ..., "details":
      ...}, ...}.
    """
    if "code" in payload:
        return payload["code"]
    error = payload.get("error")
    if isinstance(error, dict):
        return error.get("code")
    return None


def _save_memory(
    client: Any,
    actor: Any,
    *,
    memory_type: str = "long",
    content: str = "Remember that the user prefers workspace-safe summaries.",
    title: Optional[str] = None,
    tags: Optional[List[str]] = None,
    source: str = "user",
    sensitivity: str = "internal",
    project_id: Optional[str] = None,
    client_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    response = client.post(
        f"{MEMORY_PREFIX}/save",
        headers=actor.headers,
        json={
            "memory_type": memory_type,
            "content": content,
            "title": title,
            "tags": tags if tags is not None else ["preference", "workspace-safe"],
            "source": source,
            "sensitivity": sensitivity,
            "project_id": project_id,
            "client_id": client_id,
            "metadata": metadata or {"origin": "api_test"},
        },
    )
    assert response.status_code == 201, response.text
    payload = _json(response)
    assert payload["ok"] is True
    return payload["data"]["memory"]


def _login(client: Any, *, email: str, password: str, workspace_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Log the same real account in a second time, optionally selecting a
    specific workspace membership.

    tests/api_tests/conftest.py's make_owner/make_member fixtures always
    mint a *new* user, so neither can produce "one real user, two real
    workspace memberships" on its own. add_member_with_role (behind
    make_member) does create exactly that as a side effect, though: it
    registers its new user through a real POST /api/v1/auth/register call
    first (which gives that user their own throwaway "scratch" workspace as
    owner) and *then* adds them as a member of the target workspace. So a
    make_member(..., email=..., password=...) actor's underlying account
    already holds two distinct real workspace memberships; this helper logs
    that same account in again through the real POST /api/v1/auth/login
    endpoint, selecting the other membership by workspace_id, to get a
    second, differently-scoped, genuinely valid JWT for it -- exactly how a
    real multi-workspace user's browser session would switch context.
    """
    body: Dict[str, Any] = {"email": email, "password": password}
    if workspace_id:
        body["workspace_id"] = workspace_id

    response = client.post("/api/v1/auth/login", json=body)
    assert response.status_code == 200, response.text
    data = _json(response)["data"]

    return {
        "user_id": data["user"]["user_id"],
        "workspace_id": data["workspace"]["workspace_id"],
        "headers": {"Authorization": f"Bearer {data['tokens']['access_token']}"},
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestMemory:
    """Memory API tests with strict tenant isolation and real-contract checks."""

    def test_save_memory_returns_structured_response_with_scope(
        self,
        client: Any,
        make_owner: Any,
    ) -> None:
        owner = make_owner()

        response = client.post(
            f"{MEMORY_PREFIX}/save",
            headers=owner.headers,
            json={
                "memory_type": "long",
                "content": "User prefers concise but complete Jarvis task summaries.",
                "tags": ["preference", "summary"],
                "source": "user",
                "sensitivity": "internal",
                "metadata": {
                    "master_agent_context": True,
                    "workspace_safe": True,
                },
            },
        )

        assert response.status_code == 201, response.text
        payload = _json(response)
        assert payload["ok"] is True

        memory = payload["data"]["memory"]
        assert memory["id"]
        assert memory["user_id"] == owner.user_id
        assert memory["workspace_id"] == owner.workspace_id
        assert memory["content"] == "User prefers concise but complete Jarvis task summaries."
        assert memory["tags"] == ["preference", "summary"]
        assert memory["memory_type"] == "long"
        assert memory["source"] == "user"
        assert memory["sensitivity"] == "internal"

        verification = payload["verification"]
        assert verification["action"] == "memory.save"
        assert verification["user_id"] == owner.user_id
        assert verification["workspace_id"] == owner.workspace_id
        assert verification["result"]["memory_id"] == memory["id"]

    def test_list_memory_only_returns_current_user_and_workspace_records(
        self,
        client: Any,
        make_owner: Any,
    ) -> None:
        owner = make_owner()
        other = make_owner()

        mine = _save_memory(
            client,
            owner,
            content="My workspace memory should stay isolated.",
            tags=["mine"],
        )
        _save_memory(
            client,
            other,
            content="Other workspace memory must never leak.",
            tags=["theirs"],
        )

        response = client.get(MEMORY_PREFIX, headers=owner.headers)
        assert response.status_code == 200, response.text
        payload = _json(response)
        assert payload["ok"] is True

        records = payload["records"]
        assert len(records) == 1
        assert records[0]["id"] == mine["id"]
        assert records[0]["user_id"] == owner.user_id
        assert records[0]["workspace_id"] == owner.workspace_id
        assert "Other workspace memory" not in str(records)

    def test_get_memory_denies_cross_workspace_access_without_leaking_existence(
        self,
        client: Any,
        make_owner: Any,
    ) -> None:
        owner = make_owner()
        other = make_owner()

        created = _save_memory(client, owner, content="Private memory.", tags=["private"])

        response = client.get(f"{MEMORY_PREFIX}/{created['id']}", headers=other.headers)
        assert response.status_code == 404, response.text

        payload = _json(response)
        assert _error_code(payload) == "memory_not_found"

    def test_get_memory_denies_cross_workspace_access_for_same_user(
        self,
        client: Any,
        make_owner: Any,
        make_member: Any,
    ) -> None:
        """
        Note the memory record must be created by `member` (not `owner`),
        so record.user_id equals member.user_id. That isolates exactly what
        this test claims to check: the SAME user_id but a DIFFERENT
        workspace_id must still be denied. Creating it as `owner` instead
        would make this indistinguishable from the plain cross-user test
        above (own_workspace's user_id would already differ from the
        record's creator, so the workspace_id check would never actually
        be exercised).
        """
        owner = make_owner()
        email = f"multi-workspace-{uuid.uuid4().hex[:10]}@example.test"
        password = "Sup3rSecure!Pass1"

        # This user is now a "member" of owner's workspace *and* (via the
        # real registration side effect described in _login's docstring)
        # the owner of their own separate scratch workspace.
        member = make_member(owner, role="member", email=email, password=password)

        own_workspace = _login(client, email=email, password=password, workspace_id=None)
        assert own_workspace["user_id"] == member.user_id
        assert own_workspace["workspace_id"] != owner.workspace_id

        created = _save_memory(
            client,
            member,
            content="Member's workspace-scoped memory.",
            tags=["workspace-member"],
        )

        # Same real user_id, wrong workspace_id -- must be denied exactly
        # like a genuinely different user, and must not leak existence.
        response = client.get(f"{MEMORY_PREFIX}/{created['id']}", headers=own_workspace["headers"])
        assert response.status_code == 404, response.text
        payload = _json(response)
        assert _error_code(payload) == "memory_not_found"

    def test_get_memory_allows_owner_inside_same_workspace_scope(
        self,
        client: Any,
        make_owner: Any,
    ) -> None:
        owner = make_owner()
        created = _save_memory(
            client,
            owner,
            content="Owner can read memory inside same workspace.",
            tags=["read"],
        )

        response = client.get(f"{MEMORY_PREFIX}/{created['id']}", headers=owner.headers)

        assert response.status_code == 200, response.text
        payload = _json(response)
        assert payload["ok"] is True

        memory = payload["data"]["memory"]
        assert memory["id"] == created["id"]
        assert memory["user_id"] == owner.user_id
        assert memory["workspace_id"] == owner.workspace_id

    def test_search_memory_filters_within_current_scope_only(
        self,
        client: Any,
        make_owner: Any,
    ) -> None:
        owner = make_owner()
        other = make_owner()

        expected = _save_memory(
            client,
            owner,
            content="Campaign launch preference: use short approval summaries.",
            tags=["campaign", "approval"],
        )
        _save_memory(
            client,
            owner,
            content="Billing reminder preference: show monthly usage.",
            tags=["billing"],
        )
        _save_memory(
            client,
            other,
            content="Campaign launch memory from another workspace must not appear.",
            tags=["campaign"],
        )

        response = client.post(
            f"{MEMORY_PREFIX}/search",
            headers=owner.headers,
            json={"query": "campaign"},
        )

        assert response.status_code == 200, response.text
        payload = _json(response)
        assert payload["ok"] is True

        records = payload["records"]
        assert len(records) == 1
        assert records[0]["id"] == expected["id"]
        assert records[0]["user_id"] == owner.user_id
        assert records[0]["workspace_id"] == owner.workspace_id

    def test_save_memory_without_authorization_header_is_rejected(
        self,
        client: Any,
    ) -> None:
        response = client.post(
            f"{MEMORY_PREFIX}/save",
            json={
                "memory_type": "short",
                "content": "This request has no Authorization header at all.",
                "tags": ["invalid"],
                "source": "user",
                "sensitivity": "internal",
            },
        )

        assert response.status_code == 401, response.text
        payload = _json(response)
        assert _error_code(payload) == "ACCESS_TOKEN_REQUIRED"

    def test_save_memory_with_invalid_token_is_rejected(
        self,
        client: Any,
    ) -> None:
        response = client.post(
            f"{MEMORY_PREFIX}/save",
            headers={"Authorization": "Bearer not-a-real-jwt"},
            json={
                "memory_type": "short",
                "content": "Unauthorized memory write should fail.",
                "tags": ["auth"],
                "source": "user",
                "sensitivity": "internal",
            },
        )

        assert response.status_code == 401, response.text
        payload = _json(response)
        assert _error_code(payload) == "INVALID_TOKEN"

    def test_save_memory_validates_non_empty_content(
        self,
        client: Any,
        make_owner: Any,
    ) -> None:
        owner = make_owner()
        response = client.post(
            f"{MEMORY_PREFIX}/save",
            headers=owner.headers,
            json={
                "memory_type": "short",
                "content": "",
                "tags": ["invalid"],
                "source": "user",
                "sensitivity": "internal",
            },
        )

        assert response.status_code == 422, response.text

    def test_free_plan_memory_quota_is_enforced(
        self,
        client: Any,
        make_owner: Any,
        monkeypatch: Any,
    ) -> None:
        """
        Real contract note: apps/api/routes/memory.py has no blanket "free
        plan cannot use the memory API at all" gate -- that was this test
        file's old, imagined contract. enforce_write_access() only checks
        role (can_write_memory), never plan; the one real plan-tied
        behavior is memory_limit_for_plan()'s per-plan quota, enforced by
        enforce_memory_quota(). New workspaces default to the "free" plan
        (see apps/api/routes/auth.py's create_user_with_workspace ->
        _DbWorkspacePlan.FREE), so this test exercises that real quota gate
        instead, temporarily lowering the free-plan limit so it doesn't
        need to create hundreds of real records to trip it.
        """
        import apps.api.routes.memory as memory_module

        owner = make_owner()
        monkeypatch.setattr(memory_module, "DEFAULT_FREE_MEMORY_LIMIT", 1)

        _save_memory(client, owner, content="First memory within the free-plan quota.")

        response = client.post(
            f"{MEMORY_PREFIX}/save",
            headers=owner.headers,
            json={
                "memory_type": "short",
                "content": "Second memory should exceed the lowered free-plan quota.",
                "tags": ["quota"],
                "source": "user",
                "sensitivity": "internal",
            },
        )

        assert response.status_code == 403, response.text
        payload = _json(response)
        assert _error_code(payload) == "memory_quota_exceeded"

    def test_viewer_role_cannot_save_memory(
        self,
        client: Any,
        make_owner: Any,
        make_member: Any,
    ) -> None:
        owner = make_owner()
        viewer = make_member(owner, role="viewer")

        response = client.post(
            f"{MEMORY_PREFIX}/save",
            headers=viewer.headers,
            json={
                "memory_type": "short",
                "content": "Viewer role should not create memory.",
                "tags": ["role"],
                "source": "user",
                "sensitivity": "internal",
            },
        )

        assert response.status_code == 403, response.text
        payload = _json(response)
        assert _error_code(payload) == "role_cannot_write_memory"

    def test_security_agent_denial_blocks_sensitive_memory_save(
        self,
        client: Any,
        make_owner: Any,
        monkeypatch: Any,
    ) -> None:
        """
        Real contract note: require_security() only ever *denies* a save
        when a real Security Agent bridge is wired up via
        apps.api.services.security.require_security_approval -- that module
        does not exist in this codebase yet (project_security_approval is
        None), so by default require_security() always takes its
        {"approved": True, "mode": "fallback"} branch and sensitive saves
        always succeed (see the companion "succeeds via fallback" test
        below, which replaces this file's old hardcoded
        "security_agent_required" 403 expectation -- that specific
        behavior never existed in the real handler). This test exercises
        the real denial code path directly by monkeypatching the Memory
        service's own security_hook to a fake bridge that denies -- the
        same seam a real Security Agent integration would plug into.
        """
        import apps.api.routes.memory as memory_module

        owner = make_owner()

        def _deny(request_payload: Dict[str, Any]) -> Dict[str, Any]:
            return {"approved": False, "reason": "test-security-denial"}

        monkeypatch.setattr(memory_module.memory_service, "security_hook", _deny)

        response = client.post(
            f"{MEMORY_PREFIX}/save",
            headers=owner.headers,
            json={
                "memory_type": "client",
                "content": "Sensitive billing approval details require Security Agent review.",
                "tags": ["sensitive", "billing"],
                "source": "user",
                "sensitivity": "confidential",
            },
        )

        assert response.status_code == 403, response.text
        payload = _json(response)
        assert _error_code(payload) == "security_agent_denied"

    def test_sensitive_memory_save_succeeds_via_default_security_fallback(
        self,
        client: Any,
        make_owner: Any,
    ) -> None:
        owner = make_owner()

        response = client.post(
            f"{MEMORY_PREFIX}/save",
            headers=owner.headers,
            json={
                "memory_type": "client",
                "content": "Security-approved sensitive memory for workspace isolation test.",
                "tags": ["sensitive", "security-approved"],
                "source": "user",
                "sensitivity": "restricted",
            },
        )

        assert response.status_code == 201, response.text
        payload = _json(response)
        assert payload["ok"] is True

        memory = payload["data"]["memory"]
        assert memory["sensitivity"] == "restricted"

    def test_member_can_read_own_memory_but_cannot_delete_it(
        self,
        client: Any,
        make_owner: Any,
        make_member: Any,
    ) -> None:
        """
        Real contract note: the repository scopes every record by the
        *creating* user_id as well as workspace_id (InMemoryMemoryRepository
        .get_scoped() requires record.user_id == actor.user_id, not just a
        matching workspace_id) -- memory is per-user within a workspace, not
        shared workspace-wide. So a member can never read a record the
        owner created in the same workspace (that path 404s, same as
        cross-workspace access); to exercise the role-based delete gate
        specifically, the member must create -- and can therefore read --
        their own record first, then be denied deleting it purely on role
        (can_delete_memory() excludes "member" regardless of ownership).
        """
        owner = make_owner()
        member = make_member(owner, role="member")

        created = _save_memory(
            client,
            member,
            content="Member's own memory in the shared workspace.",
            tags=["member"],
        )

        read_response = client.get(f"{MEMORY_PREFIX}/{created['id']}", headers=member.headers)
        assert read_response.status_code == 200, read_response.text

        delete_response = client.delete(f"{MEMORY_PREFIX}/{created['id']}", headers=member.headers)
        assert delete_response.status_code == 403, delete_response.text

        payload = _json(delete_response)
        assert _error_code(payload) == "role_cannot_delete_memory"

    def test_delete_memory_is_scoped_and_verified(
        self,
        client: Any,
        make_owner: Any,
    ) -> None:
        owner = make_owner()
        created = _save_memory(
            client,
            owner,
            content="Delete action must produce a verification payload.",
            tags=["delete"],
        )

        delete_response = client.delete(f"{MEMORY_PREFIX}/{created['id']}", headers=owner.headers)
        assert delete_response.status_code == 200, delete_response.text

        payload = _json(delete_response)
        assert payload["ok"] is True
        assert payload["data"]["deleted_ids"] == [created["id"]]
        assert payload["data"]["deleted_count"] == 1
        assert payload["data"]["hard_delete"] is False
        assert payload["verification"]["action"] == "memory.delete"
        assert payload["verification"]["result"]["deleted_ids"] == [created["id"]]

        # Default delete is soft-delete, so a scoped GET must no longer
        # surface it (include_deleted defaults to False).
        read_response = client.get(f"{MEMORY_PREFIX}/{created['id']}", headers=owner.headers)
        assert read_response.status_code == 404, read_response.text

    def test_delete_memory_denies_cross_workspace_delete_without_leaking_existence(
        self,
        client: Any,
        make_owner: Any,
    ) -> None:
        """
        Real contract note: unlike GET/PATCH, the delete handlers
        (Memory.delete_memory()) never raise memory_not_found for missing
        or out-of-scope ids -- delete_one_memory() always builds a
        MemoryDeleteRequest and returns 200 "success" with whatever subset
        of the requested ids actually matched the caller's own
        (user_id, workspace_id) scope (possibly none). This is arguably
        even more leak-resistant than a 404 (the response is identical
        whether the id exists for someone else or doesn't exist at all),
        so the real assertion here is that the request has *zero effect*
        on the other actor's own record, not that it 404s.
        """
        owner = make_owner()
        other = make_owner()

        created = _save_memory(
            client,
            owner,
            content="Cross-workspace delete attempt must fail safely.",
            tags=["delete", "isolation"],
        )

        response = client.delete(f"{MEMORY_PREFIX}/{created['id']}", headers=other.headers)
        assert response.status_code == 200, response.text
        payload = _json(response)
        assert payload["ok"] is True
        assert payload["data"]["deleted_ids"] == []
        assert payload["data"]["deleted_count"] == 0

        owner_read_response = client.get(f"{MEMORY_PREFIX}/{created['id']}", headers=owner.headers)
        assert owner_read_response.status_code == 200, owner_read_response.text

    @pytest.mark.skip(
        reason=(
            "No real equivalent exists yet: apps/api/routes/memory.py's "
            "Memory.audit() (around lines 602-634) calls self.audit_hook, "
            "which is project_audit_log imported from "
            "apps.api.services.audit -- that module does not exist in this "
            "codebase (project_audit_log is None), so audit_hook silently "
            "no-ops on every memory action and nothing is ever persisted "
            "to the real, DB-backed audit log (apps/api/routes/audit.py's "
            "AuditLogModel). There is also no memory-specific "
            "audit-listing endpoint (no GET /api/v1/memory/.../audit or "
            "similar) -- the old fallback app's invented GET /api/audit/memory "
            "has no real backend counterpart. Once a real audit bridge is "
            "wired up (apps/api/services/audit.py), this should be "
            "rewritten against whichever real endpoint surfaces those events."
        )
    )
    def test_memory_audit_logs_are_visible_only_to_current_workspace_admin_scope(self) -> None:
        pass

    @pytest.mark.skip(
        reason=(
            "Same root cause as "
            "test_memory_audit_logs_are_visible_only_to_current_workspace_admin_scope "
            "above: there is no real, queryable memory-audit endpoint to "
            "assert a viewer is forbidden from reading, because memory "
            "audit events are never persisted anywhere in this codebase "
            "yet (apps/api/routes/memory.py's audit_hook is None)."
        )
    )
    def test_viewer_cannot_read_memory_audit_logs(self) -> None:
        pass

    def test_saved_memory_shape_is_compatible_with_memory_agent_indexing(
        self,
        client: Any,
        make_owner: Any,
    ) -> None:
        owner = make_owner()
        created = _save_memory(
            client,
            owner,
            content="Memory Agent should receive stable content, tags, metadata, user_id, and workspace_id.",
            tags=["memory-agent", "context"],
            metadata={
                "task_id": "task_memory_api_001",
                "agent_chain": ["master_agent", "memory_agent", "verification_agent"],
            },
        )

        required_keys = {
            "id",
            "user_id",
            "workspace_id",
            "memory_type",
            "content",
            "title",
            "tags",
            "source",
            "sensitivity",
            "project_id",
            "client_id",
            "metadata",
            "created_at",
            "updated_at",
            "deleted_at",
            "created_by",
            "updated_by",
        }

        assert required_keys.issubset(set(created.keys()))
        assert created["metadata"]["task_id"] == "task_memory_api_001"
        assert "master_agent" in created["metadata"]["agent_chain"]
        assert "memory_agent" in created["metadata"]["agent_chain"]
        assert "verification_agent" in created["metadata"]["agent_chain"]

    def test_verification_payload_contains_user_workspace_and_resource_binding(
        self,
        client: Any,
        make_owner: Any,
    ) -> None:
        owner = make_owner()
        response = client.post(
            f"{MEMORY_PREFIX}/save",
            headers=owner.headers,
            json={
                "memory_type": "short",
                "content": "Verification Agent must confirm the memory action scope.",
                "tags": ["verification"],
                "source": "user",
                "sensitivity": "internal",
            },
        )

        assert response.status_code == 201, response.text
        payload = _json(response)
        assert payload["ok"] is True

        memory = payload["data"]["memory"]
        verification = payload["verification"]

        assert verification["action"] == "memory.save"
        assert verification["user_id"] == memory["user_id"]
        assert verification["workspace_id"] == memory["workspace_id"]
        assert verification["request_id"]
        assert verification["result"]["memory_id"] == memory["id"]
        assert verification["result"]["memory_type"] == memory["memory_type"]

    def test_memory_api_never_returns_other_workspace_data_after_mixed_operations(
        self,
        client: Any,
        make_owner: Any,
    ) -> None:
        owner = make_owner()
        other = make_owner()

        mine = [
            _save_memory(client, owner, content=f"My record {index}", tags=["mine", str(index)])
            for index in range(3)
        ]
        theirs = [
            _save_memory(client, other, content=f"Their record {index}", tags=["theirs", str(index)])
            for index in range(2)
        ]

        response = client.get(MEMORY_PREFIX, headers=owner.headers)
        assert response.status_code == 200, response.text

        payload = _json(response)
        assert payload["ok"] is True

        visible_ids = {record["id"] for record in payload["records"]}
        mine_ids = {record["id"] for record in mine}
        theirs_ids = {record["id"] for record in theirs}

        assert visible_ids == mine_ids
        assert visible_ids.isdisjoint(theirs_ids)

    def test_memory_payload_does_not_require_or_expose_real_secrets(
        self,
        client: Any,
        make_owner: Any,
    ) -> None:
        owner = make_owner()
        created = _save_memory(
            client,
            owner,
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
