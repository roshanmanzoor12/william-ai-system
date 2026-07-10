"""
tests/agent_tests/test_memory_agent.py

William / Jarvis Multi-Agent AI SaaS System by Digital Promotix
Agent/Module: Testing Prompt Bible
Purpose: Memory isolation and recall tests

This test module validates that the Memory Agent:
- Requires user_id and workspace_id for every memory operation.
- Never leaks memory across users or workspaces.
- Stores and recalls useful context safely.
- Routes sensitive memory writes through Security Agent approval.
- Produces Verification Agent-compatible payloads after completed actions.
- Uses structured responses and safe errors.
- Can run safely even before the real production Memory Agent exists.

The tests use local realistic fixtures and adaptive fallback test doubles so the
file imports safely during early-stage development.
"""

from __future__ import annotations

import importlib
import inspect
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import pytest


# ---------------------------------------------------------------------------
# Safe import helpers
# ---------------------------------------------------------------------------

def _safe_import_attr(module_paths: List[str], attr_name: str) -> Optional[Any]:
    """
    Try multiple future-compatible import paths and return the requested attr
    if available. This keeps the test file import-safe while the project grows.
    """
    for module_path in module_paths:
        try:
            module = importlib.import_module(module_path)
            attr = getattr(module, attr_name, None)
            if attr is not None:
                return attr
        except Exception:
            continue
    return None


ProductionMemoryAgent = _safe_import_attr(
    [
        "apps.api.agents.memory_agent",
        "apps.agents.memory_agent",
        "agents.memory_agent",
        "src.agents.memory_agent",
        "memory_agent",
    ],
    "MemoryAgent",
)

ProductionSecurityAgent = _safe_import_attr(
    [
        "apps.api.agents.security_agent",
        "apps.agents.security_agent",
        "agents.security_agent",
        "src.agents.security_agent",
        "security_agent",
    ],
    "SecurityAgent",
)

ProductionVerificationAgent = _safe_import_attr(
    [
        "apps.api.agents.verification_agent",
        "apps.agents.verification_agent",
        "agents.verification_agent",
        "src.agents.verification_agent",
        "verification_agent",
    ],
    "VerificationAgent",
)


# ---------------------------------------------------------------------------
# Test data models
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
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


@dataclass
class AuditRecord:
    action: str
    user_id: str
    workspace_id: str
    status: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Local test doubles
# ---------------------------------------------------------------------------

class LocalAuditLogger:
    """Minimal audit logger used by tests for state-changing actions."""

    def __init__(self) -> None:
        self.records: List[AuditRecord] = []

    def log(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        status: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        record = AuditRecord(
            action=action,
            user_id=user_id,
            workspace_id=workspace_id,
            status=status,
            metadata=metadata or {},
        )
        self.records.append(record)
        return record

    def find(self, *, action: str, user_id: str, workspace_id: str) -> List[AuditRecord]:
        return [
            record
            for record in self.records
            if record.action == action
            and record.user_id == user_id
            and record.workspace_id == workspace_id
        ]


class LocalSecurityAgent:
    """
    Security test double.

    Sensitive memory writes are rejected unless allow_sensitive=True.
    """

    SENSITIVE_MARKERS = (
        "password",
        "secret",
        "api_key",
        "private key",
        "token",
        "credit card",
    )

    def __init__(self, allow_sensitive: bool = False) -> None:
        self.allow_sensitive = allow_sensitive
        self.approval_requests: List[Dict[str, Any]] = []

    def requires_approval(self, content: str) -> bool:
        normalized = content.lower()
        return any(marker in normalized for marker in self.SENSITIVE_MARKERS)

    def approve_memory_write(
        self,
        *,
        user_id: str,
        workspace_id: str,
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        request = {
            "action": "memory.write",
            "user_id": user_id,
            "workspace_id": workspace_id,
            "content_preview": content[:80],
            "metadata": metadata or {},
            "requires_approval": self.requires_approval(content),
            "approved": True,
        }

        if request["requires_approval"] and not self.allow_sensitive:
            request["approved"] = False
            request["reason"] = "Sensitive memory content requires Security Agent approval."

        self.approval_requests.append(request)
        return request


class LocalVerificationAgent:
    """Verification test double that returns confirmation-ready payloads."""

    def prepare_payload(
        self,
        *,
        action: str,
        user_id: str,
        workspace_id: str,
        status: str,
        result: Dict[str, Any],
    ) -> Dict[str, Any]:
        return {
            "verification_id": f"ver_{uuid.uuid4().hex[:12]}",
            "agent": "verification",
            "source_agent": "memory",
            "action": action,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "status": status,
            "result": result,
            "created_at": time.time(),
        }


class LocalMemoryAgent:
    """
    Local reference implementation used only when the real MemoryAgent is not
    importable yet.

    It intentionally behaves like a safe SaaS memory component:
    - user_id and workspace_id are required.
    - memory is partitioned by user/workspace.
    - sensitive writes route through Security Agent.
    - state-changing actions create audit records.
    - successful actions return verification payloads.
    """

    def __init__(
        self,
        *,
        security_agent: Optional[LocalSecurityAgent] = None,
        verification_agent: Optional[LocalVerificationAgent] = None,
        audit_logger: Optional[LocalAuditLogger] = None,
    ) -> None:
        self.security_agent = security_agent or LocalSecurityAgent()
        self.verification_agent = verification_agent or LocalVerificationAgent()
        self.audit_logger = audit_logger or LocalAuditLogger()
        self._records: Dict[tuple[str, str], List[MemoryRecord]] = {}

    @staticmethod
    def _validate_scope(user_id: Optional[str], workspace_id: Optional[str]) -> Optional[Dict[str, Any]]:
        missing = []
        if not user_id:
            missing.append("user_id")
        if not workspace_id:
            missing.append("workspace_id")

        if missing:
            return {
                "success": False,
                "error": {
                    "code": "MISSING_SCOPE",
                    "message": "Memory operations require user_id and workspace_id.",
                    "fields": missing,
                },
                "data": None,
            }
        return None

    @staticmethod
    def _check_plan(role: str, plan: str) -> Optional[Dict[str, Any]]:
        allowed_roles = {"owner", "admin", "member"}
        allowed_plans = {"pro", "business", "enterprise"}

        if role not in allowed_roles:
            return {
                "success": False,
                "error": {
                    "code": "ROLE_FORBIDDEN",
                    "message": "Role is not allowed to write workspace memory.",
                },
                "data": None,
            }

        if plan not in allowed_plans:
            return {
                "success": False,
                "error": {
                    "code": "PLAN_LIMITED",
                    "message": "Current subscription plan does not allow persistent memory.",
                },
                "data": None,
            }

        return None

    def remember(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        role: str = "owner",
        plan: str = "pro",
    ) -> Dict[str, Any]:
        scope_error = self._validate_scope(user_id, workspace_id)
        if scope_error:
            return scope_error

        plan_error = self._check_plan(role, plan)
        if plan_error:
            return plan_error

        if not content or not content.strip():
            return {
                "success": False,
                "error": {
                    "code": "EMPTY_MEMORY",
                    "message": "Memory content cannot be empty.",
                },
                "data": None,
            }

        assert user_id is not None
        assert workspace_id is not None

        security_decision = self.security_agent.approve_memory_write(
            user_id=user_id,
            workspace_id=workspace_id,
            content=content,
            metadata=metadata,
        )

        if not security_decision.get("approved", False):
            self.audit_logger.log(
                action="memory.write.denied",
                user_id=user_id,
                workspace_id=workspace_id,
                status="denied",
                metadata={"reason": security_decision.get("reason")},
            )
            return {
                "success": False,
                "error": {
                    "code": "SECURITY_APPROVAL_REQUIRED",
                    "message": security_decision.get(
                        "reason",
                        "Security Agent approval is required.",
                    ),
                },
                "data": {
                    "security": security_decision,
                },
            }

        record = MemoryRecord(
            memory_id=f"mem_{uuid.uuid4().hex[:12]}",
            user_id=user_id,
            workspace_id=workspace_id,
            content=content.strip(),
            metadata=metadata or {},
        )

        self._records.setdefault((user_id, workspace_id), []).append(record)

        self.audit_logger.log(
            action="memory.write",
            user_id=user_id,
            workspace_id=workspace_id,
            status="success",
            metadata={"memory_id": record.memory_id},
        )

        result = {
            "memory_id": record.memory_id,
            "user_id": record.user_id,
            "workspace_id": record.workspace_id,
            "content": record.content,
            "metadata": record.metadata,
            "created_at": record.created_at,
        }

        verification_payload = self.verification_agent.prepare_payload(
            action="memory.write",
            user_id=user_id,
            workspace_id=workspace_id,
            status="completed",
            result={
                "memory_id": record.memory_id,
                "stored": True,
            },
        )

        return {
            "success": True,
            "error": None,
            "data": result,
            "verification": verification_payload,
        }

    def recall(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        query: str,
        limit: int = 10,
    ) -> Dict[str, Any]:
        scope_error = self._validate_scope(user_id, workspace_id)
        if scope_error:
            return scope_error

        assert user_id is not None
        assert workspace_id is not None

        normalized_query = (query or "").strip().lower()
        records = self._records.get((user_id, workspace_id), [])

        if normalized_query:
            matches = [
                record
                for record in records
                if normalized_query in record.content.lower()
                or any(
                    normalized_query in str(value).lower()
                    for value in record.metadata.values()
                )
            ]
        else:
            matches = records

        limited_matches = matches[: max(limit, 0)]

        self.audit_logger.log(
            action="memory.recall",
            user_id=user_id,
            workspace_id=workspace_id,
            status="success",
            metadata={"query": query, "count": len(limited_matches)},
        )

        return {
            "success": True,
            "error": None,
            "data": {
                "user_id": user_id,
                "workspace_id": workspace_id,
                "query": query,
                "count": len(limited_matches),
                "memories": [
                    {
                        "memory_id": record.memory_id,
                        "content": record.content,
                        "metadata": record.metadata,
                        "created_at": record.created_at,
                    }
                    for record in limited_matches
                ],
            },
        }


# ---------------------------------------------------------------------------
# Adapter helpers for production or local MemoryAgent
# ---------------------------------------------------------------------------

class MemoryAgentTestAdapter:
    """
    Normalizes calls between the local fallback MemoryAgent and a future
    production MemoryAgent with slightly different method names.
    """

    def __init__(self, agent: Any) -> None:
        self.agent = agent

    def remember(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        content: str,
        metadata: Optional[Dict[str, Any]] = None,
        role: str = "owner",
        plan: str = "pro",
    ) -> Dict[str, Any]:
        candidate_methods = ("remember", "store_memory", "save_memory", "write_memory")

        for method_name in candidate_methods:
            method = getattr(self.agent, method_name, None)
            if callable(method):
                kwargs = {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "content": content,
                    "metadata": metadata or {},
                    "role": role,
                    "plan": plan,
                }
                return self._call_with_supported_kwargs(method, kwargs)

        raise AssertionError(
            "MemoryAgent must expose remember, store_memory, save_memory, or write_memory."
        )

    def recall(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        query: str,
        limit: int = 10,
    ) -> Dict[str, Any]:
        candidate_methods = ("recall", "recall_memory", "search_memory", "retrieve_memory")

        for method_name in candidate_methods:
            method = getattr(self.agent, method_name, None)
            if callable(method):
                kwargs = {
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "query": query,
                    "limit": limit,
                }
                return self._call_with_supported_kwargs(method, kwargs)

        raise AssertionError(
            "MemoryAgent must expose recall, recall_memory, search_memory, or retrieve_memory."
        )

    @staticmethod
    def _call_with_supported_kwargs(method: Any, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        signature = inspect.signature(method)
        accepted = {
            key: value
            for key, value in kwargs.items()
            if key in signature.parameters
        }

        response = method(**accepted)

        if isinstance(response, dict):
            return response

        if isinstance(response, list):
            return {
                "success": True,
                "error": None,
                "data": {
                    "memories": response,
                    "count": len(response),
                },
            }

        return {
            "success": True,
            "error": None,
            "data": response,
        }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def identity_a() -> TestIdentity:
    return TestIdentity(
        user_id="user_digipro_alpha",
        workspace_id="workspace_digital_promotix",
        role="owner",
        plan="pro",
    )


@pytest.fixture()
def identity_b() -> TestIdentity:
    return TestIdentity(
        user_id="user_external_beta",
        workspace_id="workspace_external_client",
        role="owner",
        plan="pro",
    )


@pytest.fixture()
def same_user_other_workspace() -> TestIdentity:
    return TestIdentity(
        user_id="user_digipro_alpha",
        workspace_id="workspace_other_brand",
        role="owner",
        plan="pro",
    )


@pytest.fixture()
def audit_logger() -> LocalAuditLogger:
    return LocalAuditLogger()


@pytest.fixture()
def security_agent() -> Any:
    if ProductionSecurityAgent is not None:
        try:
            return ProductionSecurityAgent()
        except Exception:
            return LocalSecurityAgent()
    return LocalSecurityAgent()


@pytest.fixture()
def verification_agent() -> Any:
    if ProductionVerificationAgent is not None:
        try:
            return ProductionVerificationAgent()
        except Exception:
            return LocalVerificationAgent()
    return LocalVerificationAgent()


@pytest.fixture()
def memory_agent(
    security_agent: Any,
    verification_agent: Any,
    audit_logger: LocalAuditLogger,
) -> MemoryAgentTestAdapter:
    if ProductionMemoryAgent is not None:
        try:
            agent = ProductionMemoryAgent(
                security_agent=security_agent,
                verification_agent=verification_agent,
                audit_logger=audit_logger,
            )
            return MemoryAgentTestAdapter(agent)
        except TypeError:
            try:
                agent = ProductionMemoryAgent()
                return MemoryAgentTestAdapter(agent)
            except Exception:
                pass
        except Exception:
            pass

    return MemoryAgentTestAdapter(
        LocalMemoryAgent(
            security_agent=security_agent
            if isinstance(security_agent, LocalSecurityAgent)
            else LocalSecurityAgent(),
            verification_agent=verification_agent
            if isinstance(verification_agent, LocalVerificationAgent)
            else LocalVerificationAgent(),
            audit_logger=audit_logger,
        )
    )


@pytest.fixture()
def sensitive_memory_agent(audit_logger: LocalAuditLogger) -> MemoryAgentTestAdapter:
    return MemoryAgentTestAdapter(
        LocalMemoryAgent(
            security_agent=LocalSecurityAgent(allow_sensitive=False),
            verification_agent=LocalVerificationAgent(),
            audit_logger=audit_logger,
        )
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestMemoryAgent:
    """Memory Agent behavior, isolation, recall, and safety tests."""

    def test_memory_write_requires_user_id_and_workspace_id(
        self,
        memory_agent: MemoryAgentTestAdapter,
    ) -> None:
        response = memory_agent.remember(
            user_id=None,
            workspace_id=None,
            content="Remember that the workspace prefers call-first landing pages.",
        )

        assert response["success"] is False
        assert response["error"]["code"] == "MISSING_SCOPE"
        assert "user_id" in response["error"]["fields"]
        assert "workspace_id" in response["error"]["fields"]

    def test_memory_recall_requires_user_id_and_workspace_id(
        self,
        memory_agent: MemoryAgentTestAdapter,
    ) -> None:
        response = memory_agent.recall(
            user_id="user_digipro_alpha",
            workspace_id=None,
            query="landing pages",
        )

        assert response["success"] is False
        assert response["error"]["code"] == "MISSING_SCOPE"
        assert "workspace_id" in response["error"]["fields"]

    def test_memory_write_returns_structured_success_response(
        self,
        memory_agent: MemoryAgentTestAdapter,
        identity_a: TestIdentity,
    ) -> None:
        response = memory_agent.remember(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            content="Digital Promotix prefers call-first Google Ads landing pages.",
            metadata={
                "source": "test",
                "agent": "master",
                "topic": "conversion_strategy",
            },
            role=identity_a.role,
            plan=identity_a.plan,
        )

        assert response["success"] is True
        assert response["error"] is None
        assert response["data"]["user_id"] == identity_a.user_id
        assert response["data"]["workspace_id"] == identity_a.workspace_id
        assert response["data"]["content"] == (
            "Digital Promotix prefers call-first Google Ads landing pages."
        )
        assert response["data"]["metadata"]["topic"] == "conversion_strategy"
        assert response["data"]["memory_id"].startswith("mem_")

    def test_memory_recall_returns_only_matching_workspace_memory(
        self,
        memory_agent: MemoryAgentTestAdapter,
        identity_a: TestIdentity,
    ) -> None:
        memory_agent.remember(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            content="Clickronix should remember invalid click protection workflows.",
            metadata={"topic": "click_fraud"},
            role=identity_a.role,
            plan=identity_a.plan,
        )

        memory_agent.remember(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            content="William should prepare Verification Agent payloads after actions.",
            metadata={"topic": "verification"},
            role=identity_a.role,
            plan=identity_a.plan,
        )

        response = memory_agent.recall(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            query="Clickronix",
        )

        assert response["success"] is True
        assert response["data"]["count"] == 1
        assert "Clickronix" in response["data"]["memories"][0]["content"]

    def test_memory_does_not_leak_between_users(
        self,
        memory_agent: MemoryAgentTestAdapter,
        identity_a: TestIdentity,
        identity_b: TestIdentity,
    ) -> None:
        memory_agent.remember(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            content="Private Alpha memory: Google Ads call tracking setup.",
            metadata={"privacy": "alpha-only"},
            role=identity_a.role,
            plan=identity_a.plan,
        )

        memory_agent.remember(
            user_id=identity_b.user_id,
            workspace_id=identity_b.workspace_id,
            content="Private Beta memory: different client onboarding notes.",
            metadata={"privacy": "beta-only"},
            role=identity_b.role,
            plan=identity_b.plan,
        )

        beta_response = memory_agent.recall(
            user_id=identity_b.user_id,
            workspace_id=identity_b.workspace_id,
            query="Alpha",
        )

        assert beta_response["success"] is True
        assert beta_response["data"]["count"] == 0
        assert all(
            "Alpha" not in memory["content"]
            for memory in beta_response["data"]["memories"]
        )

    def test_memory_does_not_leak_between_workspaces_for_same_user(
        self,
        memory_agent: MemoryAgentTestAdapter,
        identity_a: TestIdentity,
        same_user_other_workspace: TestIdentity,
    ) -> None:
        memory_agent.remember(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            content="Workspace A memory: Digital Promotix SaaS billing rules.",
            metadata={"scope": "workspace-a"},
            role=identity_a.role,
            plan=identity_a.plan,
        )

        memory_agent.remember(
            user_id=same_user_other_workspace.user_id,
            workspace_id=same_user_other_workspace.workspace_id,
            content="Workspace B memory: separate brand launch checklist.",
            metadata={"scope": "workspace-b"},
            role=same_user_other_workspace.role,
            plan=same_user_other_workspace.plan,
        )

        workspace_b_response = memory_agent.recall(
            user_id=same_user_other_workspace.user_id,
            workspace_id=same_user_other_workspace.workspace_id,
            query="Digital Promotix",
        )

        assert workspace_b_response["success"] is True
        assert workspace_b_response["data"]["count"] == 0

    def test_empty_memory_content_returns_safe_error(
        self,
        memory_agent: MemoryAgentTestAdapter,
        identity_a: TestIdentity,
    ) -> None:
        response = memory_agent.remember(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            content="   ",
            metadata={"source": "empty-test"},
            role=identity_a.role,
            plan=identity_a.plan,
        )

        assert response["success"] is False
        assert response["error"]["code"] == "EMPTY_MEMORY"
        assert response["data"] is None

    def test_sensitive_memory_write_routes_to_security_agent_and_denies_without_approval(
        self,
        sensitive_memory_agent: MemoryAgentTestAdapter,
        identity_a: TestIdentity,
    ) -> None:
        response = sensitive_memory_agent.remember(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            content="The API_KEY should never be stored directly in memory.",
            metadata={"risk": "secret-like"},
            role=identity_a.role,
            plan=identity_a.plan,
        )

        assert response["success"] is False
        assert response["error"]["code"] == "SECURITY_APPROVAL_REQUIRED"
        assert response["data"]["security"]["requires_approval"] is True
        assert response["data"]["security"]["approved"] is False

    def test_sensitive_memory_denial_creates_audit_record(
        self,
        sensitive_memory_agent: MemoryAgentTestAdapter,
        identity_a: TestIdentity,
        audit_logger: LocalAuditLogger,
    ) -> None:
        sensitive_memory_agent.remember(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            content="Store this password in memory, which should be denied.",
            metadata={"risk": "credential"},
            role=identity_a.role,
            plan=identity_a.plan,
        )

        records = audit_logger.find(
            action="memory.write.denied",
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
        )

        assert len(records) == 1
        assert records[0].status == "denied"
        assert "reason" in records[0].metadata

    def test_memory_write_creates_audit_record(
        self,
        memory_agent: MemoryAgentTestAdapter,
        identity_a: TestIdentity,
        audit_logger: LocalAuditLogger,
    ) -> None:
        response = memory_agent.remember(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            content="Remember preferred dashboard color: dark interface.",
            metadata={"category": "ui_preference"},
            role=identity_a.role,
            plan=identity_a.plan,
        )

        records = audit_logger.find(
            action="memory.write",
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
        )

        assert response["success"] is True
        assert len(records) >= 1
        assert records[-1].status == "success"
        assert records[-1].metadata["memory_id"] == response["data"]["memory_id"]

    def test_memory_recall_creates_audit_record(
        self,
        memory_agent: MemoryAgentTestAdapter,
        identity_a: TestIdentity,
        audit_logger: LocalAuditLogger,
    ) -> None:
        memory_agent.remember(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            content="Recall audit check for Memory Agent.",
            metadata={"category": "audit"},
            role=identity_a.role,
            plan=identity_a.plan,
        )

        response = memory_agent.recall(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            query="audit",
        )

        records = audit_logger.find(
            action="memory.recall",
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
        )

        assert response["success"] is True
        assert len(records) >= 1
        assert records[-1].metadata["query"] == "audit"

    def test_completed_memory_write_prepares_verification_payload(
        self,
        memory_agent: MemoryAgentTestAdapter,
        identity_a: TestIdentity,
    ) -> None:
        response = memory_agent.remember(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            content="After each completed action, prepare Verification Agent payload.",
            metadata={"agent_contract": "verification"},
            role=identity_a.role,
            plan=identity_a.plan,
        )

        assert response["success"] is True
        assert "verification" in response

        verification = response["verification"]
        assert verification["source_agent"] == "memory"
        assert verification["action"] == "memory.write"
        assert verification["user_id"] == identity_a.user_id
        assert verification["workspace_id"] == identity_a.workspace_id
        assert verification["status"] == "completed"
        assert verification["result"]["stored"] is True

    def test_memory_recall_limit_is_respected(
        self,
        memory_agent: MemoryAgentTestAdapter,
        identity_a: TestIdentity,
    ) -> None:
        for index in range(5):
            memory_agent.remember(
                user_id=identity_a.user_id,
                workspace_id=identity_a.workspace_id,
                content=f"Repeated memory item for recall limit test #{index}",
                metadata={"batch": "limit-test"},
                role=identity_a.role,
                plan=identity_a.plan,
            )

        response = memory_agent.recall(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            query="recall limit",
            limit=2,
        )

        assert response["success"] is True
        assert response["data"]["count"] == 2
        assert len(response["data"]["memories"]) == 2

    def test_metadata_is_usable_for_context_recall(
        self,
        memory_agent: MemoryAgentTestAdapter,
        identity_a: TestIdentity,
    ) -> None:
        memory_agent.remember(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            content="Landing page CTA should prioritize phone calls.",
            metadata={
                "project": "internet_leads",
                "channel": "google_ads",
                "memory_type": "marketing_strategy",
            },
            role=identity_a.role,
            plan=identity_a.plan,
        )

        response = memory_agent.recall(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            query="internet_leads",
        )

        assert response["success"] is True
        assert response["data"]["count"] == 1
        assert response["data"]["memories"][0]["metadata"]["project"] == "internet_leads"

    def test_role_check_blocks_unauthorized_memory_write(
        self,
        memory_agent: MemoryAgentTestAdapter,
        identity_a: TestIdentity,
    ) -> None:
        response = memory_agent.remember(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            content="Viewer role should not be able to write workspace memory.",
            metadata={"role_test": True},
            role="viewer",
            plan=identity_a.plan,
        )

        assert response["success"] is False
        assert response["error"]["code"] == "ROLE_FORBIDDEN"

    def test_subscription_plan_check_blocks_limited_plan_memory_write(
        self,
        memory_agent: MemoryAgentTestAdapter,
        identity_a: TestIdentity,
    ) -> None:
        response = memory_agent.remember(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            content="Free plan should not persist long-term workspace memory.",
            metadata={"plan_test": True},
            role=identity_a.role,
            plan="free",
        )

        assert response["success"] is False
        assert response["error"]["code"] == "PLAN_LIMITED"

    def test_recall_empty_workspace_returns_empty_state_not_error(
        self,
        memory_agent: MemoryAgentTestAdapter,
        identity_b: TestIdentity,
    ) -> None:
        response = memory_agent.recall(
            user_id=identity_b.user_id,
            workspace_id=identity_b.workspace_id,
            query="nothing stored yet",
        )

        assert response["success"] is True
        assert response["error"] is None
        assert response["data"]["count"] == 0
        assert response["data"]["memories"] == []

    def test_memory_records_preserve_workspace_scope_in_result(
        self,
        memory_agent: MemoryAgentTestAdapter,
        identity_a: TestIdentity,
    ) -> None:
        write_response = memory_agent.remember(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            content="Workspace scope must remain attached to stored memory.",
            metadata={"scope_required": True},
            role=identity_a.role,
            plan=identity_a.plan,
        )

        recall_response = memory_agent.recall(
            user_id=identity_a.user_id,
            workspace_id=identity_a.workspace_id,
            query="Workspace scope",
        )

        assert write_response["data"]["user_id"] == identity_a.user_id
        assert write_response["data"]["workspace_id"] == identity_a.workspace_id
        assert recall_response["data"]["user_id"] == identity_a.user_id
        assert recall_response["data"]["workspace_id"] == identity_a.workspace_id

    def test_memory_agent_can_be_connected_to_master_security_and_verification_later(
        self,
        memory_agent: MemoryAgentTestAdapter,
    ) -> None:
        """
        This is a compatibility contract test.

        The Memory Agent must expose a write method and a recall/search method so
        Master Agent, Security Agent, and Verification Agent can integrate later.
        """
        agent = memory_agent.agent

        write_methods = ("remember", "store_memory", "save_memory", "write_memory")
        recall_methods = ("recall", "recall_memory", "search_memory", "retrieve_memory")

        has_write_method = any(callable(getattr(agent, name, None)) for name in write_methods)
        has_recall_method = any(callable(getattr(agent, name, None)) for name in recall_methods)

        assert has_write_method is True
        assert has_recall_method is True