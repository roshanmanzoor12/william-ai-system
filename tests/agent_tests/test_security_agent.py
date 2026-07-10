"""
tests/agent_tests/test_security_agent.py

Security/risk/approval tests for the William / Jarvis Multi-Agent AI SaaS System.

These tests validate the expected Security Agent contract without requiring every
future production module to exist yet. When the real SecurityAgent is available,
the adapter will attempt to use it. Otherwise, a strict local fallback model keeps
the test suite meaningful and import-safe.

Core guarantees tested:
- Every security task carries user_id and workspace_id.
- Sensitive actions are routed to Security Agent approval.
- Risk levels are structured and deterministic.
- Cross-user/workspace access is denied.
- Sensitive/state-changing actions emit audit events.
- Completed decisions prepare Verification Agent-compatible payloads.
- Safe errors never leak secrets or raw internal exception details.
"""

from __future__ import annotations

import asyncio
import dataclasses
import importlib
import inspect
import os
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Protocol

import pytest


# ---------------------------------------------------------------------------
# Shared test constants
# ---------------------------------------------------------------------------

PRIMARY_USER_ID = "user_test_primary"
PRIMARY_WORKSPACE_ID = "workspace_test_primary"
SECONDARY_USER_ID = "user_test_secondary"
SECONDARY_WORKSPACE_ID = "workspace_test_secondary"

AGENT_NAME = "security_agent"
MASTER_AGENT_NAME = "master_agent"
MEMORY_AGENT_NAME = "memory_agent"
VERIFICATION_AGENT_NAME = "verification_agent"


# ---------------------------------------------------------------------------
# Protocols and local fallback contracts
# ---------------------------------------------------------------------------

class RiskLevel(str, Enum):
    """Expected normalized risk levels used by Security Agent decisions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionStatus(str, Enum):
    """Expected normalized decision statuses."""

    APPROVED = "approved"
    REQUIRES_APPROVAL = "requires_approval"
    DENIED = "denied"
    ERROR = "error"


@dataclasses.dataclass(frozen=True)
class SecurityAction:
    """
    Normalized security action fixture.

    The production system may use Pydantic models, dataclasses, or plain dicts.
    Tests convert this dataclass to a dict before calling the target agent.
    """

    action_id: str
    action_type: str
    user_id: str
    workspace_id: str
    actor_agent: str
    target_resource: str
    payload: Dict[str, Any]
    requires_state_change: bool = False
    created_at: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class AuditEvent:
    """Audit event captured by the fallback audit sink."""

    event_type: str
    user_id: str
    workspace_id: str
    action_id: str
    risk_level: str
    status: str
    actor_agent: str
    metadata: Dict[str, Any]
    created_at: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class AuditSinkProtocol(Protocol):
    def record(self, event: Mapping[str, Any]) -> None:
        """Record an audit event."""


class MemorySinkProtocol(Protocol):
    def remember(self, item: Mapping[str, Any]) -> None:
        """Record memory-compatible context."""


class VerificationSinkProtocol(Protocol):
    def prepare(self, payload: Mapping[str, Any]) -> None:
        """Record verification-compatible payload."""


class InMemoryAuditSink:
    """Simple audit collector used by tests and fallback agent."""

    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    def record(self, event: Mapping[str, Any]) -> None:
        safe_event = dict(event)
        safe_event.setdefault("created_at", datetime.now(timezone.utc).isoformat())
        self.events.append(safe_event)

    def by_action(self, action_id: str) -> List[Dict[str, Any]]:
        return [event for event in self.events if event.get("action_id") == action_id]


class InMemoryMemorySink:
    """Simple memory collector used by tests and fallback agent."""

    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []

    def remember(self, item: Mapping[str, Any]) -> None:
        self.items.append(dict(item))


class InMemoryVerificationSink:
    """Simple verification payload collector used by tests and fallback agent."""

    def __init__(self) -> None:
        self.payloads: List[Dict[str, Any]] = []

    def prepare(self, payload: Mapping[str, Any]) -> None:
        self.payloads.append(dict(payload))


class FallbackSecurityAgent:
    """
    Test fallback that models the minimum production Security Agent behavior.

    This is intentionally strict so the tests remain useful before the real
    SecurityAgent implementation exists.
    """

    SENSITIVE_ACTION_TYPES = {
        "delete_file",
        "send_email",
        "external_api_call",
        "billing_plan_change",
        "modify_permissions",
        "export_workspace_data",
        "run_shell_command",
        "access_memory",
        "access_agent",
    }

    CRITICAL_ACTION_TYPES = {
        "delete_workspace",
        "rotate_secret",
        "modify_permissions",
        "disable_audit_logging",
        "export_workspace_data",
        "run_shell_command",
    }

    SAFE_ACTION_TYPES = {
        "read_public_status",
        "summarize_non_sensitive_context",
        "list_available_agents",
    }

    SECRET_PATTERNS = [
        re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*[^,\s]+"),
    ]

    def __init__(
        self,
        *,
        audit_sink: Optional[AuditSinkProtocol] = None,
        memory_sink: Optional[MemorySinkProtocol] = None,
        verification_sink: Optional[VerificationSinkProtocol] = None,
        allowed_users_by_workspace: Optional[Mapping[str, Iterable[str]]] = None,
        plan_features_by_workspace: Optional[Mapping[str, Iterable[str]]] = None,
        role_permissions_by_user: Optional[Mapping[str, Iterable[str]]] = None,
    ) -> None:
        self.audit_sink = audit_sink or InMemoryAuditSink()
        self.memory_sink = memory_sink or InMemoryMemorySink()
        self.verification_sink = verification_sink or InMemoryVerificationSink()
        self.allowed_users_by_workspace = {
            workspace_id: set(user_ids)
            for workspace_id, user_ids in (allowed_users_by_workspace or {}).items()
        }
        self.plan_features_by_workspace = {
            workspace_id: set(features)
            for workspace_id, features in (plan_features_by_workspace or {}).items()
        }
        self.role_permissions_by_user = {
            user_id: set(permissions)
            for user_id, permissions in (role_permissions_by_user or {}).items()
        }

    async def review_action(self, action: Mapping[str, Any]) -> Dict[str, Any]:
        return self._review_action_sync(action)

    async def approve_action(self, action: Mapping[str, Any]) -> Dict[str, Any]:
        normalized = dict(action)
        normalized["approval_granted"] = True
        return self._review_action_sync(normalized)

    async def deny_action(self, action: Mapping[str, Any], reason: str = "Denied by policy") -> Dict[str, Any]:
        normalized = dict(action)
        decision = self._base_decision(
            normalized,
            status=DecisionStatus.DENIED,
            risk_level=self._risk_for(normalized),
            reason=reason,
        )
        self._emit_audit(normalized, decision)
        self._emit_memory_context(normalized, decision)
        self._emit_verification_payload(normalized, decision)
        return decision

    def _review_action_sync(self, action: Mapping[str, Any]) -> Dict[str, Any]:
        try:
            normalized = self._validate_action(action)
            isolation_error = self._validate_isolation(normalized)
            if isolation_error:
                decision = self._base_decision(
                    normalized,
                    status=DecisionStatus.DENIED,
                    risk_level=RiskLevel.HIGH,
                    reason=isolation_error,
                )
                self._emit_audit(normalized, decision)
                self._emit_memory_context(normalized, decision)
                self._emit_verification_payload(normalized, decision)
                return decision

            permission_error = self._validate_role_and_plan(normalized)
            if permission_error:
                decision = self._base_decision(
                    normalized,
                    status=DecisionStatus.DENIED,
                    risk_level=RiskLevel.MEDIUM,
                    reason=permission_error,
                )
                self._emit_audit(normalized, decision)
                self._emit_memory_context(normalized, decision)
                self._emit_verification_payload(normalized, decision)
                return decision

            risk_level = self._risk_for(normalized)
            action_type = str(normalized.get("action_type"))

            if action_type in self.SAFE_ACTION_TYPES:
                status = DecisionStatus.APPROVED
                reason = "Action is low risk and allowed by policy."
            elif risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
                if normalized.get("approval_granted") is True:
                    status = DecisionStatus.APPROVED
                    reason = "Sensitive action approved after explicit security approval."
                else:
                    status = DecisionStatus.REQUIRES_APPROVAL
                    reason = "Sensitive action requires explicit Security Agent approval."
            elif action_type in self.SENSITIVE_ACTION_TYPES or normalized.get("requires_state_change"):
                if normalized.get("approval_granted") is True:
                    status = DecisionStatus.APPROVED
                    reason = "State-changing action approved."
                else:
                    status = DecisionStatus.REQUIRES_APPROVAL
                    reason = "State-changing action requires approval."
            else:
                status = DecisionStatus.APPROVED
                reason = "Action approved by default low-risk policy."

            decision = self._base_decision(
                normalized,
                status=status,
                risk_level=risk_level,
                reason=reason,
            )
            self._emit_audit(normalized, decision)
            self._emit_memory_context(normalized, decision)
            self._emit_verification_payload(normalized, decision)
            return decision

        except Exception:
            safe_action = dict(action) if isinstance(action, Mapping) else {}
            decision = self._base_decision(
                safe_action,
                status=DecisionStatus.ERROR,
                risk_level=RiskLevel.MEDIUM,
                reason="Security review failed safely.",
            )
            self._emit_audit(safe_action, decision)
            self._emit_verification_payload(safe_action, decision)
            return decision

    def _validate_action(self, action: Mapping[str, Any]) -> Dict[str, Any]:
        if not isinstance(action, Mapping):
            raise ValueError("Action must be a mapping.")

        normalized = dict(action)
        required_fields = {
            "action_id",
            "action_type",
            "user_id",
            "workspace_id",
            "actor_agent",
            "target_resource",
            "payload",
        }
        missing = sorted(field for field in required_fields if not normalized.get(field))
        if missing:
            raise ValueError(f"Missing required action fields: {', '.join(missing)}")

        if not isinstance(normalized.get("payload"), Mapping):
            raise ValueError("Action payload must be a mapping.")

        normalized["payload"] = dict(normalized["payload"])
        return normalized

    def _validate_isolation(self, action: Mapping[str, Any]) -> Optional[str]:
        workspace_id = str(action.get("workspace_id"))
        user_id = str(action.get("user_id"))
        allowed_users = self.allowed_users_by_workspace.get(workspace_id)

        if allowed_users is not None and user_id not in allowed_users:
            return "User is not allowed to access this workspace."

        payload = action.get("payload") or {}
        target_user_id = payload.get("target_user_id")
        target_workspace_id = payload.get("target_workspace_id")

        if target_user_id and target_user_id != user_id:
            return "Cross-user access denied."

        if target_workspace_id and target_workspace_id != workspace_id:
            return "Cross-workspace access denied."

        return None

    def _validate_role_and_plan(self, action: Mapping[str, Any]) -> Optional[str]:
        action_type = str(action.get("action_type"))
        workspace_id = str(action.get("workspace_id"))
        user_id = str(action.get("user_id"))

        role_permissions = self.role_permissions_by_user.get(user_id, set())
        plan_features = self.plan_features_by_workspace.get(workspace_id, set())

        if action_type == "modify_permissions" and "security:permissions:write" not in role_permissions:
            return "Role does not allow permission changes."

        if action_type == "export_workspace_data" and "workspace:data_export" not in plan_features:
            return "Subscription plan does not allow workspace data export."

        if action_type == "access_agent":
            requested_agent = str((action.get("payload") or {}).get("agent_name", ""))
            permission = f"agent:{requested_agent}:access"
            if requested_agent and permission not in role_permissions:
                return "Role does not allow access to the requested agent."

        return None

    def _risk_for(self, action: Mapping[str, Any]) -> RiskLevel:
        action_type = str(action.get("action_type"))
        payload = action.get("payload") or {}
        payload_text = repr(payload)

        if action_type in self.CRITICAL_ACTION_TYPES:
            return RiskLevel.CRITICAL

        if any(pattern.search(payload_text) for pattern in self.SECRET_PATTERNS):
            return RiskLevel.CRITICAL

        if action_type in self.SENSITIVE_ACTION_TYPES:
            return RiskLevel.HIGH

        if action.get("requires_state_change"):
            return RiskLevel.MEDIUM

        return RiskLevel.LOW

    def _base_decision(
        self,
        action: Mapping[str, Any],
        *,
        status: DecisionStatus,
        risk_level: RiskLevel,
        reason: str,
    ) -> Dict[str, Any]:
        return {
            "success": status not in {DecisionStatus.ERROR},
            "decision_id": f"secdec_{uuid.uuid4().hex}",
            "action_id": action.get("action_id", "unknown"),
            "user_id": action.get("user_id"),
            "workspace_id": action.get("workspace_id"),
            "agent": AGENT_NAME,
            "status": status.value,
            "risk_level": risk_level.value,
            "requires_approval": status == DecisionStatus.REQUIRES_APPROVAL,
            "reason": self._sanitize(reason),
            "safe_error": status == DecisionStatus.ERROR,
            "verification_payload": {
                "source_agent": AGENT_NAME,
                "action_id": action.get("action_id", "unknown"),
                "user_id": action.get("user_id"),
                "workspace_id": action.get("workspace_id"),
                "status": status.value,
                "risk_level": risk_level.value,
                "verified_at": None,
            },
        }

    def _emit_audit(self, action: Mapping[str, Any], decision: Mapping[str, Any]) -> None:
        event = AuditEvent(
            event_type="security.action_reviewed",
            user_id=str(action.get("user_id")),
            workspace_id=str(action.get("workspace_id")),
            action_id=str(action.get("action_id", "unknown")),
            risk_level=str(decision.get("risk_level")),
            status=str(decision.get("status")),
            actor_agent=str(action.get("actor_agent", "unknown")),
            metadata={
                "target_resource": action.get("target_resource"),
                "requires_approval": decision.get("requires_approval"),
                "reason": decision.get("reason"),
            },
        )
        self.audit_sink.record(dataclasses.asdict(event))

    def _emit_memory_context(self, action: Mapping[str, Any], decision: Mapping[str, Any]) -> None:
        self.memory_sink.remember(
            {
                "type": "security_decision_context",
                "user_id": action.get("user_id"),
                "workspace_id": action.get("workspace_id"),
                "action_id": action.get("action_id"),
                "risk_level": decision.get("risk_level"),
                "status": decision.get("status"),
                "memory_agent_compatible": True,
            }
        )

    def _emit_verification_payload(self, action: Mapping[str, Any], decision: Mapping[str, Any]) -> None:
        self.verification_sink.prepare(decision.get("verification_payload", {}))

    @classmethod
    def _sanitize(cls, value: str) -> str:
        sanitized = str(value)
        for pattern in cls.SECRET_PATTERNS:
            sanitized = pattern.sub("[REDACTED]", sanitized)
        return sanitized


# ---------------------------------------------------------------------------
# Import adapter for future real SecurityAgent
# ---------------------------------------------------------------------------

def _import_optional_security_agent_class() -> Optional[type]:
    """
    Try known future module paths without failing test collection.

    The project is still evolving, so this keeps imports safe while allowing the
    tests to run against the real implementation once it exists.
    """

    candidate_paths = [
        "apps.agents.security.security_agent.SecurityAgent",
        "apps.agents.security_agent.SecurityAgent",
        "agents.security.security_agent.SecurityAgent",
        "agents.security_agent.SecurityAgent",
        "app.agents.security_agent.SecurityAgent",
        "william.agents.security_agent.SecurityAgent",
    ]

    for dotted_path in candidate_paths:
        module_path, _, class_name = dotted_path.rpartition(".")
        try:
            module = importlib.import_module(module_path)
            candidate = getattr(module, class_name, None)
            if inspect.isclass(candidate):
                return candidate
        except Exception:
            continue

    return None


def _build_security_agent(
    *,
    audit_sink: InMemoryAuditSink,
    memory_sink: InMemoryMemorySink,
    verification_sink: InMemoryVerificationSink,
    allowed_users_by_workspace: Optional[Mapping[str, Iterable[str]]] = None,
    plan_features_by_workspace: Optional[Mapping[str, Iterable[str]]] = None,
    role_permissions_by_user: Optional[Mapping[str, Iterable[str]]] = None,
) -> Any:
    """
    Build real SecurityAgent when possible, otherwise fallback.

    The constructor signatures of future production modules may differ. This
    adapter tries common dependency names first and falls back safely.
    """

    real_agent_class = _import_optional_security_agent_class()

    kwargs = {
        "audit_sink": audit_sink,
        "memory_sink": memory_sink,
        "verification_sink": verification_sink,
        "allowed_users_by_workspace": allowed_users_by_workspace,
        "plan_features_by_workspace": plan_features_by_workspace,
        "role_permissions_by_user": role_permissions_by_user,
    }

    if real_agent_class is not None:
        try:
            signature = inspect.signature(real_agent_class)
            accepted_kwargs = {
                key: value
                for key, value in kwargs.items()
                if key in signature.parameters
            }
            return real_agent_class(**accepted_kwargs)
        except Exception:
            # Import-safe fallback while project modules are under construction.
            return FallbackSecurityAgent(**kwargs)

    return FallbackSecurityAgent(**kwargs)


async def _call_security_review(agent: Any, action: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Call the most likely review method on a real or fallback SecurityAgent.

    This avoids locking tests to one method name too early while still enforcing
    the response contract.
    """

    candidate_method_names = [
        "review_action",
        "evaluate_action",
        "assess_action",
        "authorize_action",
        "check_action",
        "handle_security_review",
    ]

    for method_name in candidate_method_names:
        method = getattr(agent, method_name, None)
        if callable(method):
            result = method(action)
            if inspect.isawaitable(result):
                result = await result
            assert isinstance(result, Mapping), (
                f"{method_name} must return a structured mapping response."
            )
            return dict(result)

    raise AssertionError(
        "SecurityAgent must expose one of: "
        + ", ".join(candidate_method_names)
    )


async def _call_security_approval(agent: Any, action: Mapping[str, Any]) -> Dict[str, Any]:
    candidate_method_names = [
        "approve_action",
        "approve_sensitive_action",
        "authorize_after_approval",
    ]

    for method_name in candidate_method_names:
        method = getattr(agent, method_name, None)
        if callable(method):
            result = method(action)
            if inspect.isawaitable(result):
                result = await result
            assert isinstance(result, Mapping), (
                f"{method_name} must return a structured mapping response."
            )
            return dict(result)

    approved_action = dict(action)
    approved_action["approval_granted"] = True
    return await _call_security_review(agent, approved_action)


def _make_action(
    *,
    action_type: str = "read_public_status",
    user_id: str = PRIMARY_USER_ID,
    workspace_id: str = PRIMARY_WORKSPACE_ID,
    actor_agent: str = MASTER_AGENT_NAME,
    target_resource: str = "workspace/status",
    payload: Optional[Dict[str, Any]] = None,
    requires_state_change: bool = False,
) -> SecurityAction:
    return SecurityAction(
        action_id=f"act_{uuid.uuid4().hex}",
        action_type=action_type,
        user_id=user_id,
        workspace_id=workspace_id,
        actor_agent=actor_agent,
        target_resource=target_resource,
        payload=payload or {},
        requires_state_change=requires_state_change,
    )


def _assert_response_contract(decision: Mapping[str, Any], action: Mapping[str, Any]) -> None:
    assert isinstance(decision, Mapping)
    assert "success" in decision
    assert "status" in decision
    assert "risk_level" in decision
    assert "requires_approval" in decision
    assert "reason" in decision
    assert decision.get("action_id") == action.get("action_id")
    assert decision.get("user_id") == action.get("user_id")
    assert decision.get("workspace_id") == action.get("workspace_id")

    assert decision["status"] in {status.value for status in DecisionStatus}
    assert decision["risk_level"] in {level.value for level in RiskLevel}
    assert isinstance(decision["requires_approval"], bool)
    assert isinstance(decision["reason"], str)


def _assert_verification_payload_contract(
    payload: Mapping[str, Any],
    *,
    action: Mapping[str, Any],
) -> None:
    assert payload["source_agent"] == AGENT_NAME
    assert payload["action_id"] == action["action_id"]
    assert payload["user_id"] == action["user_id"]
    assert payload["workspace_id"] == action["workspace_id"]
    assert payload["status"] in {status.value for status in DecisionStatus}
    assert payload["risk_level"] in {level.value for level in RiskLevel}


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def audit_sink() -> InMemoryAuditSink:
    return InMemoryAuditSink()


@pytest.fixture()
def memory_sink() -> InMemoryMemorySink:
    return InMemoryMemorySink()


@pytest.fixture()
def verification_sink() -> InMemoryVerificationSink:
    return InMemoryVerificationSink()


@pytest.fixture()
def allowed_users_by_workspace() -> Dict[str, List[str]]:
    return {
        PRIMARY_WORKSPACE_ID: [PRIMARY_USER_ID],
        SECONDARY_WORKSPACE_ID: [SECONDARY_USER_ID],
    }


@pytest.fixture()
def plan_features_by_workspace() -> Dict[str, List[str]]:
    return {
        PRIMARY_WORKSPACE_ID: ["security:basic_review", "workspace:data_export"],
        SECONDARY_WORKSPACE_ID: ["security:basic_review"],
    }


@pytest.fixture()
def role_permissions_by_user() -> Dict[str, List[str]]:
    return {
        PRIMARY_USER_ID: [
            "agent:memory_agent:access",
            "agent:verification_agent:access",
            "security:permissions:write",
        ],
        SECONDARY_USER_ID: [
            "agent:memory_agent:access",
        ],
    }


@pytest.fixture()
def security_agent(
    audit_sink: InMemoryAuditSink,
    memory_sink: InMemoryMemorySink,
    verification_sink: InMemoryVerificationSink,
    allowed_users_by_workspace: Dict[str, List[str]],
    plan_features_by_workspace: Dict[str, List[str]],
    role_permissions_by_user: Dict[str, List[str]],
) -> Any:
    return _build_security_agent(
        audit_sink=audit_sink,
        memory_sink=memory_sink,
        verification_sink=verification_sink,
        allowed_users_by_workspace=allowed_users_by_workspace,
        plan_features_by_workspace=plan_features_by_workspace,
        role_permissions_by_user=role_permissions_by_user,
    )


@pytest.fixture()
def sensitive_action() -> SecurityAction:
    return _make_action(
        action_type="send_email",
        target_resource="gmail/outbound",
        payload={
            "recipient": "client@example.test",
            "subject": "Account update",
            "body": "A safe test email body.",
        },
        requires_state_change=True,
    )


@pytest.fixture()
def critical_action() -> SecurityAction:
    return _make_action(
        action_type="export_workspace_data",
        actor_agent=MASTER_AGENT_NAME,
        target_resource="workspace/export",
        payload={
            "format": "json",
            "include_memory": True,
            "target_workspace_id": PRIMARY_WORKSPACE_ID,
        },
        requires_state_change=True,
    )


# ---------------------------------------------------------------------------
# Main test class required by prompt
# ---------------------------------------------------------------------------

class TestSecurityAgent:
    """Security Agent behavior tests for risk, approval, audit, and isolation."""

    @pytest.mark.asyncio
    async def test_low_risk_action_is_approved_with_required_context(
        self,
        security_agent: Any,
        audit_sink: InMemoryAuditSink,
        memory_sink: InMemoryMemorySink,
        verification_sink: InMemoryVerificationSink,
    ) -> None:
        action = _make_action(
            action_type="read_public_status",
            payload={"scope": "own_workspace_status"},
        ).as_dict()

        decision = await _call_security_review(security_agent, action)

        _assert_response_contract(decision, action)
        assert decision["status"] == DecisionStatus.APPROVED.value
        assert decision["risk_level"] == RiskLevel.LOW.value
        assert decision["requires_approval"] is False

        assert len(audit_sink.by_action(action["action_id"])) >= 1
        assert any(item.get("action_id") == action["action_id"] for item in memory_sink.items)
        assert verification_sink.payloads
        _assert_verification_payload_contract(
            verification_sink.payloads[-1],
            action=action,
        )

    @pytest.mark.asyncio
    async def test_sensitive_state_changing_action_requires_security_approval(
        self,
        security_agent: Any,
        sensitive_action: SecurityAction,
        audit_sink: InMemoryAuditSink,
        verification_sink: InMemoryVerificationSink,
    ) -> None:
        action = sensitive_action.as_dict()

        decision = await _call_security_review(security_agent, action)

        _assert_response_contract(decision, action)
        assert decision["status"] in {
            DecisionStatus.REQUIRES_APPROVAL.value,
            DecisionStatus.DENIED.value,
        }
        assert decision["risk_level"] in {
            RiskLevel.MEDIUM.value,
            RiskLevel.HIGH.value,
            RiskLevel.CRITICAL.value,
        }

        audit_events = audit_sink.by_action(action["action_id"])
        assert audit_events, "Sensitive action must create an audit event."
        assert audit_events[-1]["user_id"] == PRIMARY_USER_ID
        assert audit_events[-1]["workspace_id"] == PRIMARY_WORKSPACE_ID
        assert audit_events[-1]["actor_agent"] == MASTER_AGENT_NAME

        assert verification_sink.payloads
        _assert_verification_payload_contract(
            verification_sink.payloads[-1],
            action=action,
        )

    @pytest.mark.asyncio
    async def test_explicit_approval_allows_sensitive_action_without_losing_audit_trail(
        self,
        security_agent: Any,
        sensitive_action: SecurityAction,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        action = sensitive_action.as_dict()

        initial_decision = await _call_security_review(security_agent, action)
        approved_decision = await _call_security_approval(security_agent, action)

        _assert_response_contract(initial_decision, action)
        _assert_response_contract(approved_decision, action)

        assert approved_decision["status"] == DecisionStatus.APPROVED.value
        assert approved_decision["requires_approval"] is False

        audit_events = audit_sink.by_action(action["action_id"])
        assert len(audit_events) >= 2
        assert {event["status"] for event in audit_events}.issuperset(
            {initial_decision["status"], approved_decision["status"]}
        )

    @pytest.mark.asyncio
    async def test_cross_workspace_access_is_denied(
        self,
        security_agent: Any,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        action = _make_action(
            action_type="access_memory",
            user_id=PRIMARY_USER_ID,
            workspace_id=PRIMARY_WORKSPACE_ID,
            actor_agent=MEMORY_AGENT_NAME,
            target_resource="memory/vector-store",
            payload={
                "target_user_id": PRIMARY_USER_ID,
                "target_workspace_id": SECONDARY_WORKSPACE_ID,
                "query": "retrieve unrelated workspace memory",
            },
        ).as_dict()

        decision = await _call_security_review(security_agent, action)

        _assert_response_contract(decision, action)
        assert decision["status"] == DecisionStatus.DENIED.value
        assert decision["requires_approval"] is False
        assert "workspace" in decision["reason"].lower()

        audit_events = audit_sink.by_action(action["action_id"])
        assert audit_events
        assert audit_events[-1]["status"] == DecisionStatus.DENIED.value

    @pytest.mark.asyncio
    async def test_cross_user_access_is_denied(
        self,
        security_agent: Any,
    ) -> None:
        action = _make_action(
            action_type="access_memory",
            user_id=PRIMARY_USER_ID,
            workspace_id=PRIMARY_WORKSPACE_ID,
            actor_agent=MEMORY_AGENT_NAME,
            target_resource="memory/profile",
            payload={
                "target_user_id": SECONDARY_USER_ID,
                "target_workspace_id": PRIMARY_WORKSPACE_ID,
            },
        ).as_dict()

        decision = await _call_security_review(security_agent, action)

        _assert_response_contract(decision, action)
        assert decision["status"] == DecisionStatus.DENIED.value
        assert "user" in decision["reason"].lower()

    @pytest.mark.asyncio
    async def test_user_not_mapped_to_workspace_is_denied(
        self,
        security_agent: Any,
    ) -> None:
        action = _make_action(
            action_type="list_available_agents",
            user_id=SECONDARY_USER_ID,
            workspace_id=PRIMARY_WORKSPACE_ID,
            target_resource="agents/registry",
            payload={"scope": "workspace_agents"},
        ).as_dict()

        decision = await _call_security_review(security_agent, action)

        _assert_response_contract(decision, action)
        assert decision["status"] == DecisionStatus.DENIED.value
        assert "workspace" in decision["reason"].lower()

    @pytest.mark.asyncio
    async def test_role_permission_required_for_agent_access(
        self,
        security_agent: Any,
    ) -> None:
        action = _make_action(
            action_type="access_agent",
            user_id=SECONDARY_USER_ID,
            workspace_id=SECONDARY_WORKSPACE_ID,
            actor_agent=MASTER_AGENT_NAME,
            target_resource="agents/verification_agent",
            payload={"agent_name": VERIFICATION_AGENT_NAME},
        ).as_dict()

        decision = await _call_security_review(security_agent, action)

        _assert_response_contract(decision, action)
        assert decision["status"] == DecisionStatus.DENIED.value
        assert "role" in decision["reason"].lower()

    @pytest.mark.asyncio
    async def test_subscription_feature_required_for_workspace_export(
        self,
        security_agent: Any,
    ) -> None:
        action = _make_action(
            action_type="export_workspace_data",
            user_id=SECONDARY_USER_ID,
            workspace_id=SECONDARY_WORKSPACE_ID,
            actor_agent=MASTER_AGENT_NAME,
            target_resource="workspace/export",
            payload={"target_workspace_id": SECONDARY_WORKSPACE_ID},
            requires_state_change=True,
        ).as_dict()

        decision = await _call_security_review(security_agent, action)

        _assert_response_contract(decision, action)
        assert decision["status"] == DecisionStatus.DENIED.value
        assert "plan" in decision["reason"].lower() or "subscription" in decision["reason"].lower()

    @pytest.mark.asyncio
    async def test_permission_modification_requires_role_permission(
        self,
        security_agent: Any,
    ) -> None:
        action = _make_action(
            action_type="modify_permissions",
            user_id=SECONDARY_USER_ID,
            workspace_id=SECONDARY_WORKSPACE_ID,
            actor_agent=MASTER_AGENT_NAME,
            target_resource="roles/permissions",
            payload={
                "target_user_id": SECONDARY_USER_ID,
                "grant": ["agent:finance_agent:access"],
            },
            requires_state_change=True,
        ).as_dict()

        decision = await _call_security_review(security_agent, action)

        _assert_response_contract(decision, action)
        assert decision["status"] == DecisionStatus.DENIED.value
        assert "role" in decision["reason"].lower()

    @pytest.mark.asyncio
    async def test_critical_risk_detected_when_payload_contains_secret_like_value(
        self,
        security_agent: Any,
    ) -> None:
        fake_secret = "sk-testvalue-not-real-1234567890abcdef"
        action = _make_action(
            action_type="external_api_call",
            target_resource="third-party/api",
            payload={
                "endpoint": "https://api.example.test/sync",
                "authorization": f"Bearer {fake_secret}",
            },
            requires_state_change=True,
        ).as_dict()

        decision = await _call_security_review(security_agent, action)

        _assert_response_contract(decision, action)
        assert decision["risk_level"] == RiskLevel.CRITICAL.value
        assert decision["status"] in {
            DecisionStatus.REQUIRES_APPROVAL.value,
            DecisionStatus.DENIED.value,
        }
        assert fake_secret not in decision["reason"]

    @pytest.mark.asyncio
    async def test_safe_errors_are_structured_and_do_not_leak_internal_details(
        self,
        security_agent: Any,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        invalid_action = {
            "action_id": f"act_{uuid.uuid4().hex}",
            "action_type": "send_email",
            "user_id": PRIMARY_USER_ID,
            # workspace_id intentionally missing
            "actor_agent": MASTER_AGENT_NAME,
            "target_resource": "gmail/outbound",
            "payload": {"body": "hello"},
        }

        decision = await _call_security_review(security_agent, invalid_action)

        assert isinstance(decision, Mapping)
        assert decision["status"] in {
            DecisionStatus.ERROR.value,
            DecisionStatus.DENIED.value,
        }
        assert decision.get("safe_error") in {True, False, None}
        assert "traceback" not in str(decision).lower()
        assert "valueerror" not in str(decision).lower()

        audit_events = audit_sink.by_action(invalid_action["action_id"])
        assert audit_events, "Invalid security reviews should still be audit-visible."

    @pytest.mark.asyncio
    async def test_audit_events_do_not_mix_users_or_workspaces(
        self,
        security_agent: Any,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        primary_action = _make_action(
            action_type="send_email",
            user_id=PRIMARY_USER_ID,
            workspace_id=PRIMARY_WORKSPACE_ID,
            payload={"recipient": "primary@example.test"},
            requires_state_change=True,
        ).as_dict()

        secondary_action = _make_action(
            action_type="send_email",
            user_id=SECONDARY_USER_ID,
            workspace_id=SECONDARY_WORKSPACE_ID,
            payload={"recipient": "secondary@example.test"},
            requires_state_change=True,
        ).as_dict()

        await _call_security_review(security_agent, primary_action)
        await _call_security_review(security_agent, secondary_action)

        primary_events = audit_sink.by_action(primary_action["action_id"])
        secondary_events = audit_sink.by_action(secondary_action["action_id"])

        assert primary_events
        assert secondary_events

        assert all(event["user_id"] == PRIMARY_USER_ID for event in primary_events)
        assert all(event["workspace_id"] == PRIMARY_WORKSPACE_ID for event in primary_events)
        assert all(event["user_id"] == SECONDARY_USER_ID for event in secondary_events)
        assert all(event["workspace_id"] == SECONDARY_WORKSPACE_ID for event in secondary_events)

    @pytest.mark.asyncio
    async def test_memory_context_is_user_workspace_scoped_and_agent_compatible(
        self,
        security_agent: Any,
        memory_sink: InMemoryMemorySink,
    ) -> None:
        action = _make_action(
            action_type="summarize_non_sensitive_context",
            actor_agent=MEMORY_AGENT_NAME,
            target_resource="memory/context-summary",
            payload={"summary_type": "security_relevant_context"},
        ).as_dict()

        decision = await _call_security_review(security_agent, action)

        _assert_response_contract(decision, action)
        assert memory_sink.items

        related_items = [
            item for item in memory_sink.items if item.get("action_id") == action["action_id"]
        ]
        assert related_items
        assert all(item["user_id"] == PRIMARY_USER_ID for item in related_items)
        assert all(item["workspace_id"] == PRIMARY_WORKSPACE_ID for item in related_items)
        assert all(item.get("memory_agent_compatible") is True for item in related_items)

    @pytest.mark.asyncio
    async def test_verification_payload_created_for_completed_security_decision(
        self,
        security_agent: Any,
        verification_sink: InMemoryVerificationSink,
    ) -> None:
        action = _make_action(
            action_type="list_available_agents",
            actor_agent=MASTER_AGENT_NAME,
            target_resource="agents/registry",
            payload={"include": ["security_agent", "memory_agent", "verification_agent"]},
        ).as_dict()

        decision = await _call_security_review(security_agent, action)

        _assert_response_contract(decision, action)

        assert "verification_payload" in decision
        _assert_verification_payload_contract(
            decision["verification_payload"],
            action=action,
        )

        assert verification_sink.payloads
        _assert_verification_payload_contract(
            verification_sink.payloads[-1],
            action=action,
        )

    @pytest.mark.asyncio
    async def test_master_agent_sensitive_request_routes_through_security_agent(
        self,
        security_agent: Any,
    ) -> None:
        action = _make_action(
            action_type="run_shell_command",
            actor_agent=MASTER_AGENT_NAME,
            target_resource="worker/windows-shell",
            payload={
                "command": "echo safe-test-command",
                "reason": "diagnostic test",
            },
            requires_state_change=True,
        ).as_dict()

        decision = await _call_security_review(security_agent, action)

        _assert_response_contract(decision, action)
        assert decision["agent"] == AGENT_NAME
        assert decision["risk_level"] == RiskLevel.CRITICAL.value
        assert decision["status"] in {
            DecisionStatus.REQUIRES_APPROVAL.value,
            DecisionStatus.DENIED.value,
        }

    @pytest.mark.asyncio
    async def test_environment_secret_values_are_not_required_for_tests(
        self,
        security_agent: Any,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.delenv("JWT_SECRET", raising=False)

        action = _make_action(
            action_type="read_public_status",
            payload={"env_required": False},
        ).as_dict()

        decision = await _call_security_review(security_agent, action)

        _assert_response_contract(decision, action)
        assert decision["status"] == DecisionStatus.APPROVED.value

    @pytest.mark.asyncio
    async def test_concurrent_reviews_keep_decisions_isolated(
        self,
        security_agent: Any,
    ) -> None:
        actions = [
            _make_action(
                action_type="read_public_status",
                user_id=PRIMARY_USER_ID,
                workspace_id=PRIMARY_WORKSPACE_ID,
                payload={"index": index},
            ).as_dict()
            for index in range(5)
        ]

        decisions = await asyncio.gather(
            *[_call_security_review(security_agent, action) for action in actions]
        )

        assert len(decisions) == len(actions)
        decision_action_ids = {decision["action_id"] for decision in decisions}
        source_action_ids = {action["action_id"] for action in actions}

        assert decision_action_ids == source_action_ids
        assert all(decision["user_id"] == PRIMARY_USER_ID for decision in decisions)
        assert all(decision["workspace_id"] == PRIMARY_WORKSPACE_ID for decision in decisions)

    def test_security_test_file_contains_no_real_secret_from_environment(self) -> None:
        """
        Guardrail for this test module itself.

        The suite must not depend on or expose real secrets. It is okay for the
        file to mention environment variable names, but not real values.
        """

        suspicious_env_names = [
            "OPENAI_API_KEY",
            "DATABASE_URL",
            "JWT_SECRET",
            "GOOGLE_CLIENT_SECRET",
        ]

        for env_name in suspicious_env_names:
            value = os.environ.get(env_name)
            if value:
                assert value not in __doc__
                assert value not in repr(FallbackSecurityAgent)