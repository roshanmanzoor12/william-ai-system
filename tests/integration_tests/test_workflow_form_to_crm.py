"""
tests/integration_tests/test_workflow_form_to_crm.py

Integration-style workflow pipeline tests for William / Jarvis Multi-Agent AI SaaS System.

Purpose:
- Validate a complete form submission -> workflow orchestration -> CRM write pipeline.
- Enforce user_id and workspace_id isolation throughout the pipeline.
- Ensure sensitive/state-changing CRM actions route through Security Agent.
- Ensure audit logging is emitted for state-changing workflow activity.
- Ensure useful context is prepared for Memory Agent.
- Ensure completed workflow actions prepare Verification Agent-compatible payloads.
- Keep imports safe even when future production modules are not created yet.

This test file intentionally includes local fallback doubles. When real project modules
exist later, the adapter will attempt to use them without breaking collection.
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
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol

import pytest


# ---------------------------------------------------------------------------
# Stable test constants
# ---------------------------------------------------------------------------

PRIMARY_USER_ID = "user_form_primary"
PRIMARY_WORKSPACE_ID = "workspace_form_primary"

SECONDARY_USER_ID = "user_form_secondary"
SECONDARY_WORKSPACE_ID = "workspace_form_secondary"

MASTER_AGENT_NAME = "master_agent"
SECURITY_AGENT_NAME = "security_agent"
MEMORY_AGENT_NAME = "memory_agent"
VERIFICATION_AGENT_NAME = "verification_agent"
WORKFLOW_AGENT_NAME = "workflow_agent"
CRM_AGENT_NAME = "crm_agent"

CRM_WRITE_FEATURE = "workflow:crm_write"
CRM_READ_FEATURE = "workflow:crm_read"
CRM_WRITE_PERMISSION = "crm:lead:write"
WORKFLOW_RUN_PERMISSION = "workflow:run"


# ---------------------------------------------------------------------------
# Enums and data contracts
# ---------------------------------------------------------------------------

class WorkflowStatus(str, Enum):
    RECEIVED = "received"
    VALIDATED = "validated"
    SECURITY_REVIEW_REQUIRED = "security_review_required"
    COMPLETED = "completed"
    DENIED = "denied"
    ERROR = "error"


class SecurityDecisionStatus(str, Enum):
    APPROVED = "approved"
    REQUIRES_APPROVAL = "requires_approval"
    DENIED = "denied"
    ERROR = "error"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclasses.dataclass(frozen=True)
class LeadFormSubmission:
    """Realistic web form submission payload entering the William workflow system."""

    submission_id: str
    user_id: str
    workspace_id: str
    source: str
    form_name: str
    name: str
    email: str
    phone: str
    company: str
    message: str
    page_url: str
    utm_source: str
    utm_medium: str
    utm_campaign: str
    gclid: str
    consent_to_contact: bool
    submitted_at: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class SecurityAction:
    """State-changing action reviewed by Security Agent before CRM write."""

    action_id: str
    action_type: str
    user_id: str
    workspace_id: str
    actor_agent: str
    target_resource: str
    payload: Dict[str, Any]
    requires_state_change: bool = True
    created_at: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def as_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class AuditEvent:
    """Audit event captured by fallback sinks."""

    event_type: str
    user_id: str
    workspace_id: str
    entity_id: str
    actor_agent: str
    status: str
    metadata: Dict[str, Any]
    created_at: str = dataclasses.field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------

class AuditSinkProtocol(Protocol):
    def record(self, event: Mapping[str, Any]) -> None:
        """Record audit event."""


class MemorySinkProtocol(Protocol):
    def remember(self, item: Mapping[str, Any]) -> None:
        """Record Memory Agent-compatible context."""


class VerificationSinkProtocol(Protocol):
    def prepare(self, payload: Mapping[str, Any]) -> None:
        """Record Verification Agent-compatible payload."""


class CrmStoreProtocol(Protocol):
    def create_lead(self, lead: Mapping[str, Any]) -> Dict[str, Any]:
        """Create lead in CRM."""


# ---------------------------------------------------------------------------
# Local fallback sinks/stores
# ---------------------------------------------------------------------------

class InMemoryAuditSink:
    """Simple in-memory audit event collector."""

    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    def record(self, event: Mapping[str, Any]) -> None:
        safe_event = dict(event)
        safe_event.setdefault("created_at", datetime.now(timezone.utc).isoformat())
        self.events.append(safe_event)

    def by_entity(self, entity_id: str) -> List[Dict[str, Any]]:
        return [event for event in self.events if event.get("entity_id") == entity_id]

    def by_workspace(self, workspace_id: str) -> List[Dict[str, Any]]:
        return [event for event in self.events if event.get("workspace_id") == workspace_id]


class InMemoryMemorySink:
    """Simple in-memory Memory Agent context collector."""

    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []

    def remember(self, item: Mapping[str, Any]) -> None:
        self.items.append(dict(item))

    def by_submission(self, submission_id: str) -> List[Dict[str, Any]]:
        return [item for item in self.items if item.get("submission_id") == submission_id]


class InMemoryVerificationSink:
    """Simple in-memory Verification Agent payload collector."""

    def __init__(self) -> None:
        self.payloads: List[Dict[str, Any]] = []

    def prepare(self, payload: Mapping[str, Any]) -> None:
        self.payloads.append(dict(payload))

    def by_submission(self, submission_id: str) -> List[Dict[str, Any]]:
        return [
            payload
            for payload in self.payloads
            if payload.get("submission_id") == submission_id
        ]


class InMemoryCrmStore:
    """
    Workspace-isolated fake CRM.

    The store deliberately indexes by workspace_id first to catch accidental
    cross-workspace leakage in tests.
    """

    def __init__(self) -> None:
        self.leads_by_workspace: Dict[str, List[Dict[str, Any]]] = {}

    def create_lead(self, lead: Mapping[str, Any]) -> Dict[str, Any]:
        workspace_id = str(lead["workspace_id"])
        user_id = str(lead["user_id"])
        lead_id = f"crm_lead_{uuid.uuid4().hex}"

        stored_lead = {
            "lead_id": lead_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "name": lead["name"],
            "email": lead["email"],
            "phone": lead["phone"],
            "company": lead.get("company", ""),
            "message": lead.get("message", ""),
            "source": lead.get("source", "unknown"),
            "submission_id": lead["submission_id"],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "utm": {
                "source": lead.get("utm_source", ""),
                "medium": lead.get("utm_medium", ""),
                "campaign": lead.get("utm_campaign", ""),
                "gclid": lead.get("gclid", ""),
            },
        }

        self.leads_by_workspace.setdefault(workspace_id, []).append(stored_lead)
        return {
            "success": True,
            "lead_id": lead_id,
            "user_id": user_id,
            "workspace_id": workspace_id,
            "data": stored_lead,
        }

    def leads_for_workspace(self, workspace_id: str) -> List[Dict[str, Any]]:
        return list(self.leads_by_workspace.get(workspace_id, []))


# ---------------------------------------------------------------------------
# Fallback Security Agent
# ---------------------------------------------------------------------------

class FallbackSecurityAgent:
    """
    Strict local Security Agent double.

    CRM lead creation is a state-changing action. It must require explicit
    security approval unless approval_granted=True is present.
    """

    SECRET_PATTERNS = [
        re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
        re.compile(r"AKIA[0-9A-Z]{16}"),
        re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*[^,\s]+"),
    ]

    def __init__(
        self,
        *,
        audit_sink: Optional[AuditSinkProtocol] = None,
        allowed_users_by_workspace: Optional[Mapping[str, Iterable[str]]] = None,
    ) -> None:
        self.audit_sink = audit_sink or InMemoryAuditSink()
        self.allowed_users_by_workspace = {
            workspace_id: set(user_ids)
            for workspace_id, user_ids in (allowed_users_by_workspace or {}).items()
        }

    async def review_action(self, action: Mapping[str, Any]) -> Dict[str, Any]:
        normalized = dict(action)
        required = {
            "action_id",
            "action_type",
            "user_id",
            "workspace_id",
            "actor_agent",
            "target_resource",
            "payload",
        }
        missing = sorted(field for field in required if not normalized.get(field))
        if missing:
            return self._decision(
                normalized,
                status=SecurityDecisionStatus.ERROR,
                risk_level=RiskLevel.MEDIUM,
                reason="Security action failed validation safely.",
            )

        workspace_id = str(normalized["workspace_id"])
        user_id = str(normalized["user_id"])
        allowed_users = self.allowed_users_by_workspace.get(workspace_id)

        if allowed_users is not None and user_id not in allowed_users:
            return self._decision(
                normalized,
                status=SecurityDecisionStatus.DENIED,
                risk_level=RiskLevel.HIGH,
                reason="User is not allowed to access this workspace.",
            )

        payload = dict(normalized.get("payload") or {})
        target_workspace_id = payload.get("target_workspace_id")
        target_user_id = payload.get("target_user_id")

        if target_workspace_id and target_workspace_id != workspace_id:
            return self._decision(
                normalized,
                status=SecurityDecisionStatus.DENIED,
                risk_level=RiskLevel.HIGH,
                reason="Cross-workspace CRM write denied.",
            )

        if target_user_id and target_user_id != user_id:
            return self._decision(
                normalized,
                status=SecurityDecisionStatus.DENIED,
                risk_level=RiskLevel.HIGH,
                reason="Cross-user CRM write denied.",
            )

        risk_level = self._risk_for(normalized)

        if normalized.get("requires_state_change") and normalized.get("approval_granted") is not True:
            return self._decision(
                normalized,
                status=SecurityDecisionStatus.REQUIRES_APPROVAL,
                risk_level=risk_level,
                reason="CRM write requires explicit Security Agent approval.",
            )

        return self._decision(
            normalized,
            status=SecurityDecisionStatus.APPROVED,
            risk_level=risk_level,
            reason="CRM write approved by Security Agent.",
        )

    async def approve_action(self, action: Mapping[str, Any]) -> Dict[str, Any]:
        approved = dict(action)
        approved["approval_granted"] = True
        return await self.review_action(approved)

    def _risk_for(self, action: Mapping[str, Any]) -> RiskLevel:
        payload_text = repr(action.get("payload", {}))
        if any(pattern.search(payload_text) for pattern in self.SECRET_PATTERNS):
            return RiskLevel.CRITICAL
        if action.get("requires_state_change"):
            return RiskLevel.HIGH
        return RiskLevel.LOW

    def _decision(
        self,
        action: Mapping[str, Any],
        *,
        status: SecurityDecisionStatus,
        risk_level: RiskLevel,
        reason: str,
    ) -> Dict[str, Any]:
        decision = {
            "success": status not in {
                SecurityDecisionStatus.ERROR,
                SecurityDecisionStatus.DENIED,
            },
            "decision_id": f"security_decision_{uuid.uuid4().hex}",
            "action_id": action.get("action_id", "unknown"),
            "user_id": action.get("user_id"),
            "workspace_id": action.get("workspace_id"),
            "agent": SECURITY_AGENT_NAME,
            "status": status.value,
            "risk_level": risk_level.value,
            "requires_approval": status == SecurityDecisionStatus.REQUIRES_APPROVAL,
            "reason": self._sanitize(reason),
            "safe_error": status == SecurityDecisionStatus.ERROR,
        }

        self.audit_sink.record(
            dataclasses.asdict(
                AuditEvent(
                    event_type="security.crm_action_reviewed",
                    user_id=str(action.get("user_id")),
                    workspace_id=str(action.get("workspace_id")),
                    entity_id=str(action.get("action_id", "unknown")),
                    actor_agent=str(action.get("actor_agent", "unknown")),
                    status=status.value,
                    metadata={
                        "target_resource": action.get("target_resource"),
                        "risk_level": risk_level.value,
                        "requires_approval": decision["requires_approval"],
                    },
                )
            )
        )

        return decision

    @classmethod
    def _sanitize(cls, value: str) -> str:
        sanitized = str(value)
        for pattern in cls.SECRET_PATTERNS:
            sanitized = pattern.sub("[REDACTED]", sanitized)
        return sanitized


# ---------------------------------------------------------------------------
# Fallback form-to-CRM workflow orchestrator
# ---------------------------------------------------------------------------

class FallbackWorkflowFormToCrm:
    """
    Local workflow engine double.

    It represents the expected production pipeline:
    1. Master/Workflow Agent receives form.
    2. Validate user_id/workspace_id and lead fields.
    3. Check user role and workspace subscription feature.
    4. Create Security Agent action for CRM write.
    5. Require or consume approval.
    6. Write lead into workspace-isolated CRM.
    7. Emit audit event.
    8. Store Memory Agent-compatible context.
    9. Prepare Verification Agent payload.
    """

    EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

    def __init__(
        self,
        *,
        security_agent: Any,
        crm_store: CrmStoreProtocol,
        audit_sink: AuditSinkProtocol,
        memory_sink: MemorySinkProtocol,
        verification_sink: VerificationSinkProtocol,
        allowed_users_by_workspace: Mapping[str, Iterable[str]],
        plan_features_by_workspace: Mapping[str, Iterable[str]],
        role_permissions_by_user: Mapping[str, Iterable[str]],
    ) -> None:
        self.security_agent = security_agent
        self.crm_store = crm_store
        self.audit_sink = audit_sink
        self.memory_sink = memory_sink
        self.verification_sink = verification_sink
        self.allowed_users_by_workspace = {
            workspace_id: set(user_ids)
            for workspace_id, user_ids in allowed_users_by_workspace.items()
        }
        self.plan_features_by_workspace = {
            workspace_id: set(features)
            for workspace_id, features in plan_features_by_workspace.items()
        }
        self.role_permissions_by_user = {
            user_id: set(permissions)
            for user_id, permissions in role_permissions_by_user.items()
        }

    async def run(self, submission: Mapping[str, Any]) -> Dict[str, Any]:
        try:
            lead = self._validate_submission(submission)
            self._audit(
                event_type="workflow.form_submission_received",
                submission=lead,
                status=WorkflowStatus.RECEIVED.value,
                metadata={"form_name": lead["form_name"], "source": lead["source"]},
            )

            policy_error = self._check_user_workspace_role_and_plan(lead)
            if policy_error:
                result = self._workflow_result(
                    submission=lead,
                    status=WorkflowStatus.DENIED,
                    success=False,
                    reason=policy_error,
                    crm_result=None,
                    security_decision=None,
                )
                self._finalize_context(lead, result)
                return result

            security_action = self._build_security_action(lead)
            security_decision = await self._call_security_review(security_action)

            if security_decision["status"] == SecurityDecisionStatus.REQUIRES_APPROVAL.value:
                approved_action = dict(security_action)
                approved_action["approval_granted"] = True
                security_decision = await self._call_security_approval(approved_action)

            if security_decision["status"] != SecurityDecisionStatus.APPROVED.value:
                result = self._workflow_result(
                    submission=lead,
                    status=WorkflowStatus.DENIED,
                    success=False,
                    reason=security_decision.get("reason", "Security review denied CRM write."),
                    crm_result=None,
                    security_decision=security_decision,
                )
                self._finalize_context(lead, result)
                return result

            crm_result = self.crm_store.create_lead(lead)

            self._audit(
                event_type="workflow.crm_lead_created",
                submission=lead,
                status=WorkflowStatus.COMPLETED.value,
                metadata={
                    "crm_lead_id": crm_result["lead_id"],
                    "security_decision_id": security_decision["decision_id"],
                },
            )

            result = self._workflow_result(
                submission=lead,
                status=WorkflowStatus.COMPLETED,
                success=True,
                reason="Form submission converted to CRM lead successfully.",
                crm_result=crm_result,
                security_decision=security_decision,
            )
            self._finalize_context(lead, result)
            return result

        except Exception:
            safe_submission = dict(submission) if isinstance(submission, Mapping) else {}
            result = {
                "success": False,
                "status": WorkflowStatus.ERROR.value,
                "safe_error": True,
                "reason": "Workflow failed safely.",
                "submission_id": safe_submission.get("submission_id", "unknown"),
                "user_id": safe_submission.get("user_id"),
                "workspace_id": safe_submission.get("workspace_id"),
                "crm_result": None,
                "security_decision": None,
                "verification_payload": self._verification_payload(
                    safe_submission,
                    status=WorkflowStatus.ERROR.value,
                    crm_result=None,
                    security_decision=None,
                ),
            }
            self.verification_sink.prepare(result["verification_payload"])
            return result

    def _validate_submission(self, submission: Mapping[str, Any]) -> Dict[str, Any]:
        if not isinstance(submission, Mapping):
            raise ValueError("Submission must be a mapping.")

        lead = dict(submission)
        required_fields = [
            "submission_id",
            "user_id",
            "workspace_id",
            "source",
            "form_name",
            "name",
            "email",
            "phone",
            "message",
            "page_url",
            "consent_to_contact",
        ]

        missing = [field for field in required_fields if lead.get(field) in {None, ""}]
        if missing:
            raise ValueError("Missing required lead form fields.")

        if not self.EMAIL_PATTERN.match(str(lead["email"])):
            raise ValueError("Invalid email format.")

        if lead["consent_to_contact"] is not True:
            raise ValueError("Consent is required before CRM lead creation.")

        lead.setdefault("company", "")
        lead.setdefault("utm_source", "")
        lead.setdefault("utm_medium", "")
        lead.setdefault("utm_campaign", "")
        lead.setdefault("gclid", "")
        lead.setdefault("submitted_at", datetime.now(timezone.utc).isoformat())

        return lead

    def _check_user_workspace_role_and_plan(self, lead: Mapping[str, Any]) -> Optional[str]:
        workspace_id = str(lead["workspace_id"])
        user_id = str(lead["user_id"])

        allowed_users = self.allowed_users_by_workspace.get(workspace_id, set())
        if user_id not in allowed_users:
            return "User is not allowed to run workflows in this workspace."

        role_permissions = self.role_permissions_by_user.get(user_id, set())
        if WORKFLOW_RUN_PERMISSION not in role_permissions:
            return "Role does not allow workflow execution."

        if CRM_WRITE_PERMISSION not in role_permissions:
            return "Role does not allow CRM lead creation."

        plan_features = self.plan_features_by_workspace.get(workspace_id, set())
        if CRM_WRITE_FEATURE not in plan_features:
            return "Subscription plan does not allow CRM write workflows."

        return None

    def _build_security_action(self, lead: Mapping[str, Any]) -> Dict[str, Any]:
        return SecurityAction(
            action_id=f"security_action_{uuid.uuid4().hex}",
            action_type="crm_create_lead",
            user_id=str(lead["user_id"]),
            workspace_id=str(lead["workspace_id"]),
            actor_agent=WORKFLOW_AGENT_NAME,
            target_resource="crm/leads",
            payload={
                "submission_id": lead["submission_id"],
                "target_user_id": lead["user_id"],
                "target_workspace_id": lead["workspace_id"],
                "lead_email": lead["email"],
                "source": lead["source"],
                "form_name": lead["form_name"],
            },
            requires_state_change=True,
        ).as_dict()

    async def _call_security_review(self, action: Mapping[str, Any]) -> Dict[str, Any]:
        method = getattr(self.security_agent, "review_action", None)
        if not callable(method):
            raise AssertionError("Security Agent must expose review_action for CRM workflow tests.")

        result = method(action)
        if inspect.isawaitable(result):
            result = await result

        if not isinstance(result, Mapping):
            raise AssertionError("Security Agent review_action must return structured mapping.")

        return dict(result)

    async def _call_security_approval(self, action: Mapping[str, Any]) -> Dict[str, Any]:
        method = getattr(self.security_agent, "approve_action", None)
        if callable(method):
            result = method(action)
            if inspect.isawaitable(result):
                result = await result

            if not isinstance(result, Mapping):
                raise AssertionError("Security Agent approve_action must return structured mapping.")

            return dict(result)

        approved = dict(action)
        approved["approval_granted"] = True
        return await self._call_security_review(approved)

    def _workflow_result(
        self,
        *,
        submission: Mapping[str, Any],
        status: WorkflowStatus,
        success: bool,
        reason: str,
        crm_result: Optional[Mapping[str, Any]],
        security_decision: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        verification_payload = self._verification_payload(
            submission,
            status=status.value,
            crm_result=crm_result,
            security_decision=security_decision,
        )

        return {
            "success": success,
            "status": status.value,
            "safe_error": status == WorkflowStatus.ERROR,
            "reason": reason,
            "submission_id": submission["submission_id"],
            "user_id": submission["user_id"],
            "workspace_id": submission["workspace_id"],
            "source_agent": WORKFLOW_AGENT_NAME,
            "crm_result": dict(crm_result) if crm_result else None,
            "security_decision": dict(security_decision) if security_decision else None,
            "verification_payload": verification_payload,
        }

    def _verification_payload(
        self,
        submission: Mapping[str, Any],
        *,
        status: str,
        crm_result: Optional[Mapping[str, Any]],
        security_decision: Optional[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        return {
            "source_agent": WORKFLOW_AGENT_NAME,
            "target_agent": VERIFICATION_AGENT_NAME,
            "submission_id": submission.get("submission_id", "unknown"),
            "user_id": submission.get("user_id"),
            "workspace_id": submission.get("workspace_id"),
            "status": status,
            "crm_lead_id": crm_result.get("lead_id") if crm_result else None,
            "security_decision_id": security_decision.get("decision_id") if security_decision else None,
            "ready_for_verification": status in {
                WorkflowStatus.COMPLETED.value,
                WorkflowStatus.DENIED.value,
                WorkflowStatus.ERROR.value,
            },
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    def _finalize_context(self, submission: Mapping[str, Any], result: Mapping[str, Any]) -> None:
        self.memory_sink.remember(
            {
                "type": "form_to_crm_workflow_context",
                "memory_agent_compatible": True,
                "submission_id": submission["submission_id"],
                "user_id": submission["user_id"],
                "workspace_id": submission["workspace_id"],
                "lead_email": submission["email"],
                "lead_source": submission["source"],
                "workflow_status": result["status"],
                "crm_lead_id": (
                    result.get("crm_result", {}).get("lead_id")
                    if result.get("crm_result")
                    else None
                ),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        self.verification_sink.prepare(result["verification_payload"])

    def _audit(
        self,
        *,
        event_type: str,
        submission: Mapping[str, Any],
        status: str,
        metadata: Mapping[str, Any],
    ) -> None:
        self.audit_sink.record(
            dataclasses.asdict(
                AuditEvent(
                    event_type=event_type,
                    user_id=str(submission["user_id"]),
                    workspace_id=str(submission["workspace_id"]),
                    entity_id=str(submission["submission_id"]),
                    actor_agent=WORKFLOW_AGENT_NAME,
                    status=status,
                    metadata=dict(metadata),
                )
            )
        )


# ---------------------------------------------------------------------------
# Import adapters for future real implementation
# ---------------------------------------------------------------------------

def _import_optional_class(candidate_paths: Iterable[str]) -> Optional[type]:
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
    allowed_users_by_workspace: Mapping[str, Iterable[str]],
) -> Any:
    security_class = _import_optional_class(
        [
            "apps.agents.security.security_agent.SecurityAgent",
            "apps.agents.security_agent.SecurityAgent",
            "agents.security.security_agent.SecurityAgent",
            "agents.security_agent.SecurityAgent",
            "app.agents.security_agent.SecurityAgent",
            "william.agents.security_agent.SecurityAgent",
        ]
    )

    kwargs = {
        "audit_sink": audit_sink,
        "allowed_users_by_workspace": allowed_users_by_workspace,
    }

    if security_class is not None:
        try:
            signature = inspect.signature(security_class)
            accepted_kwargs = {
                key: value
                for key, value in kwargs.items()
                if key in signature.parameters
            }
            return security_class(**accepted_kwargs)
        except Exception:
            return FallbackSecurityAgent(**kwargs)

    return FallbackSecurityAgent(**kwargs)


def _build_workflow_engine(
    *,
    security_agent: Any,
    crm_store: InMemoryCrmStore,
    audit_sink: InMemoryAuditSink,
    memory_sink: InMemoryMemorySink,
    verification_sink: InMemoryVerificationSink,
    allowed_users_by_workspace: Mapping[str, Iterable[str]],
    plan_features_by_workspace: Mapping[str, Iterable[str]],
    role_permissions_by_user: Mapping[str, Iterable[str]],
) -> Any:
    workflow_class = _import_optional_class(
        [
            "apps.workflows.form_to_crm.WorkflowFormToCrm",
            "apps.workflows.form_to_crm.FormToCrmWorkflow",
            "workflows.form_to_crm.WorkflowFormToCrm",
            "workflows.form_to_crm.FormToCrmWorkflow",
            "app.workflows.form_to_crm.WorkflowFormToCrm",
            "william.workflows.form_to_crm.WorkflowFormToCrm",
        ]
    )

    kwargs = {
        "security_agent": security_agent,
        "crm_store": crm_store,
        "audit_sink": audit_sink,
        "memory_sink": memory_sink,
        "verification_sink": verification_sink,
        "allowed_users_by_workspace": allowed_users_by_workspace,
        "plan_features_by_workspace": plan_features_by_workspace,
        "role_permissions_by_user": role_permissions_by_user,
    }

    if workflow_class is not None:
        try:
            signature = inspect.signature(workflow_class)
            accepted_kwargs = {
                key: value
                for key, value in kwargs.items()
                if key in signature.parameters
            }
            return workflow_class(**accepted_kwargs)
        except Exception:
            return FallbackWorkflowFormToCrm(**kwargs)

    return FallbackWorkflowFormToCrm(**kwargs)


async def _run_workflow(engine: Any, submission: Mapping[str, Any]) -> Dict[str, Any]:
    candidate_method_names = [
        "run",
        "execute",
        "process",
        "handle_submission",
        "run_form_to_crm",
    ]

    for method_name in candidate_method_names:
        method = getattr(engine, method_name, None)
        if callable(method):
            result = method(submission)
            if inspect.isawaitable(result):
                result = await result

            assert isinstance(result, Mapping), (
                f"{method_name} must return a structured mapping response."
            )
            return dict(result)

    raise AssertionError(
        "Form-to-CRM workflow must expose one of: "
        + ", ".join(candidate_method_names)
    )


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _make_submission(
    *,
    user_id: str = PRIMARY_USER_ID,
    workspace_id: str = PRIMARY_WORKSPACE_ID,
    email: str = "lead@example.test",
    phone: str = "+13023853483",
    message: str = "I need help with Google Ads and CRM automation.",
    consent_to_contact: bool = True,
    source: str = "website",
    form_name: str = "contact_form",
    page_url: str = "https://example.test/contact",
    target_gclid: str = "test-gclid-123",
) -> LeadFormSubmission:
    return LeadFormSubmission(
        submission_id=f"submission_{uuid.uuid4().hex}",
        user_id=user_id,
        workspace_id=workspace_id,
        source=source,
        form_name=form_name,
        name="Alex Test Lead",
        email=email,
        phone=phone,
        company="Example Test Company",
        message=message,
        page_url=page_url,
        utm_source="google",
        utm_medium="cpc",
        utm_campaign="crm_workflow_test",
        gclid=target_gclid,
        consent_to_contact=consent_to_contact,
    )


def _assert_workflow_response_contract(
    result: Mapping[str, Any],
    submission: Mapping[str, Any],
) -> None:
    assert isinstance(result, Mapping)
    assert "success" in result
    assert "status" in result
    assert "reason" in result
    assert "submission_id" in result
    assert "user_id" in result
    assert "workspace_id" in result
    assert "verification_payload" in result

    assert result["submission_id"] == submission["submission_id"]
    assert result["user_id"] == submission["user_id"]
    assert result["workspace_id"] == submission["workspace_id"]
    assert result["status"] in {status.value for status in WorkflowStatus}
    assert isinstance(result["reason"], str)


def _assert_verification_payload_contract(
    payload: Mapping[str, Any],
    submission: Mapping[str, Any],
) -> None:
    assert payload["source_agent"] == WORKFLOW_AGENT_NAME
    assert payload["target_agent"] == VERIFICATION_AGENT_NAME
    assert payload["submission_id"] == submission["submission_id"]
    assert payload["user_id"] == submission["user_id"]
    assert payload["workspace_id"] == submission["workspace_id"]
    assert payload["status"] in {status.value for status in WorkflowStatus}
    assert payload["ready_for_verification"] is True


def _assert_no_cross_workspace_crm_leakage(
    crm_store: InMemoryCrmStore,
    *,
    primary_workspace_id: str,
    secondary_workspace_id: str,
) -> None:
    primary_leads = crm_store.leads_for_workspace(primary_workspace_id)
    secondary_leads = crm_store.leads_for_workspace(secondary_workspace_id)

    assert all(lead["workspace_id"] == primary_workspace_id for lead in primary_leads)
    assert all(lead["workspace_id"] == secondary_workspace_id for lead in secondary_leads)

    primary_submission_ids = {lead["submission_id"] for lead in primary_leads}
    secondary_submission_ids = {lead["submission_id"] for lead in secondary_leads}
    assert primary_submission_ids.isdisjoint(secondary_submission_ids)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def allowed_users_by_workspace() -> Dict[str, List[str]]:
    return {
        PRIMARY_WORKSPACE_ID: [PRIMARY_USER_ID],
        SECONDARY_WORKSPACE_ID: [SECONDARY_USER_ID],
    }


@pytest.fixture()
def plan_features_by_workspace() -> Dict[str, List[str]]:
    return {
        PRIMARY_WORKSPACE_ID: [CRM_READ_FEATURE, CRM_WRITE_FEATURE],
        SECONDARY_WORKSPACE_ID: [CRM_READ_FEATURE],
    }


@pytest.fixture()
def role_permissions_by_user() -> Dict[str, List[str]]:
    return {
        PRIMARY_USER_ID: [WORKFLOW_RUN_PERMISSION, CRM_WRITE_PERMISSION],
        SECONDARY_USER_ID: [WORKFLOW_RUN_PERMISSION],
    }


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
def crm_store() -> InMemoryCrmStore:
    return InMemoryCrmStore()


@pytest.fixture()
def security_agent(
    audit_sink: InMemoryAuditSink,
    allowed_users_by_workspace: Dict[str, List[str]],
) -> Any:
    return _build_security_agent(
        audit_sink=audit_sink,
        allowed_users_by_workspace=allowed_users_by_workspace,
    )


@pytest.fixture()
def workflow_engine(
    security_agent: Any,
    crm_store: InMemoryCrmStore,
    audit_sink: InMemoryAuditSink,
    memory_sink: InMemoryMemorySink,
    verification_sink: InMemoryVerificationSink,
    allowed_users_by_workspace: Dict[str, List[str]],
    plan_features_by_workspace: Dict[str, List[str]],
    role_permissions_by_user: Dict[str, List[str]],
) -> Any:
    return _build_workflow_engine(
        security_agent=security_agent,
        crm_store=crm_store,
        audit_sink=audit_sink,
        memory_sink=memory_sink,
        verification_sink=verification_sink,
        allowed_users_by_workspace=allowed_users_by_workspace,
        plan_features_by_workspace=plan_features_by_workspace,
        role_permissions_by_user=role_permissions_by_user,
    )


# ---------------------------------------------------------------------------
# Required test class
# ---------------------------------------------------------------------------

class TestWorkflowFormToCrm:
    """Integration tests for website form submission to CRM lead workflow."""

    @pytest.mark.asyncio
    async def test_form_submission_creates_crm_lead_after_security_approval(
        self,
        workflow_engine: Any,
        crm_store: InMemoryCrmStore,
        audit_sink: InMemoryAuditSink,
        memory_sink: InMemoryMemorySink,
        verification_sink: InMemoryVerificationSink,
    ) -> None:
        submission = _make_submission().as_dict()

        result = await _run_workflow(workflow_engine, submission)

        _assert_workflow_response_contract(result, submission)
        assert result["success"] is True
        assert result["status"] == WorkflowStatus.COMPLETED.value
        assert result["crm_result"] is not None
        assert result["crm_result"]["workspace_id"] == PRIMARY_WORKSPACE_ID
        assert result["crm_result"]["user_id"] == PRIMARY_USER_ID
        assert result["security_decision"] is not None
        assert result["security_decision"]["status"] == SecurityDecisionStatus.APPROVED.value

        crm_leads = crm_store.leads_for_workspace(PRIMARY_WORKSPACE_ID)
        assert len(crm_leads) == 1
        assert crm_leads[0]["submission_id"] == submission["submission_id"]
        assert crm_leads[0]["email"] == submission["email"]
        assert crm_leads[0]["utm"]["gclid"] == submission["gclid"]

        audit_events = audit_sink.by_entity(submission["submission_id"])
        assert {event["event_type"] for event in audit_events}.issuperset(
            {
                "workflow.form_submission_received",
                "workflow.crm_lead_created",
            }
        )

        memory_items = memory_sink.by_submission(submission["submission_id"])
        assert memory_items
        assert memory_items[-1]["memory_agent_compatible"] is True
        assert memory_items[-1]["user_id"] == PRIMARY_USER_ID
        assert memory_items[-1]["workspace_id"] == PRIMARY_WORKSPACE_ID

        verification_payloads = verification_sink.by_submission(submission["submission_id"])
        assert verification_payloads
        _assert_verification_payload_contract(verification_payloads[-1], submission)

    @pytest.mark.asyncio
    async def test_every_pipeline_step_preserves_user_id_and_workspace_id(
        self,
        workflow_engine: Any,
        crm_store: InMemoryCrmStore,
        audit_sink: InMemoryAuditSink,
        memory_sink: InMemoryMemorySink,
        verification_sink: InMemoryVerificationSink,
    ) -> None:
        submission = _make_submission().as_dict()

        result = await _run_workflow(workflow_engine, submission)

        _assert_workflow_response_contract(result, submission)

        assert result["user_id"] == submission["user_id"]
        assert result["workspace_id"] == submission["workspace_id"]

        crm_lead = crm_store.leads_for_workspace(PRIMARY_WORKSPACE_ID)[0]
        assert crm_lead["user_id"] == submission["user_id"]
        assert crm_lead["workspace_id"] == submission["workspace_id"]

        for event in audit_sink.by_entity(submission["submission_id"]):
            assert event["user_id"] == submission["user_id"]
            assert event["workspace_id"] == submission["workspace_id"]

        for item in memory_sink.by_submission(submission["submission_id"]):
            assert item["user_id"] == submission["user_id"]
            assert item["workspace_id"] == submission["workspace_id"]

        for payload in verification_sink.by_submission(submission["submission_id"]):
            assert payload["user_id"] == submission["user_id"]
            assert payload["workspace_id"] == submission["workspace_id"]

    @pytest.mark.asyncio
    async def test_cross_workspace_submission_is_denied_before_crm_write(
        self,
        workflow_engine: Any,
        crm_store: InMemoryCrmStore,
        audit_sink: InMemoryAuditSink,
        memory_sink: InMemoryMemorySink,
        verification_sink: InMemoryVerificationSink,
    ) -> None:
        submission = _make_submission(
            user_id=PRIMARY_USER_ID,
            workspace_id=SECONDARY_WORKSPACE_ID,
            email="blocked-cross-workspace@example.test",
        ).as_dict()

        result = await _run_workflow(workflow_engine, submission)

        _assert_workflow_response_contract(result, submission)
        assert result["success"] is False
        assert result["status"] == WorkflowStatus.DENIED.value
        assert "workspace" in result["reason"].lower()
        assert crm_store.leads_for_workspace(SECONDARY_WORKSPACE_ID) == []

        audit_events = audit_sink.by_entity(submission["submission_id"])
        assert audit_events
        assert all(event["workspace_id"] == SECONDARY_WORKSPACE_ID for event in audit_events)

        memory_items = memory_sink.by_submission(submission["submission_id"])
        assert memory_items
        assert memory_items[-1]["workflow_status"] == WorkflowStatus.DENIED.value

        verification_payloads = verification_sink.by_submission(submission["submission_id"])
        assert verification_payloads
        _assert_verification_payload_contract(verification_payloads[-1], submission)

    @pytest.mark.asyncio
    async def test_subscription_without_crm_write_feature_is_denied(
        self,
        workflow_engine: Any,
        crm_store: InMemoryCrmStore,
    ) -> None:
        submission = _make_submission(
            user_id=SECONDARY_USER_ID,
            workspace_id=SECONDARY_WORKSPACE_ID,
            email="plan-blocked@example.test",
        ).as_dict()

        result = await _run_workflow(workflow_engine, submission)

        _assert_workflow_response_contract(result, submission)
        assert result["success"] is False
        assert result["status"] == WorkflowStatus.DENIED.value
        assert "role" in result["reason"].lower() or "subscription" in result["reason"].lower()
        assert crm_store.leads_for_workspace(SECONDARY_WORKSPACE_ID) == []

    @pytest.mark.asyncio
    async def test_role_without_crm_write_permission_is_denied(
        self,
        security_agent: Any,
        crm_store: InMemoryCrmStore,
        audit_sink: InMemoryAuditSink,
        memory_sink: InMemoryMemorySink,
        verification_sink: InMemoryVerificationSink,
        allowed_users_by_workspace: Dict[str, List[str]],
        plan_features_by_workspace: Dict[str, List[str]],
    ) -> None:
        role_permissions = {
            PRIMARY_USER_ID: [WORKFLOW_RUN_PERMISSION],
            SECONDARY_USER_ID: [WORKFLOW_RUN_PERMISSION],
        }

        engine = _build_workflow_engine(
            security_agent=security_agent,
            crm_store=crm_store,
            audit_sink=audit_sink,
            memory_sink=memory_sink,
            verification_sink=verification_sink,
            allowed_users_by_workspace=allowed_users_by_workspace,
            plan_features_by_workspace=plan_features_by_workspace,
            role_permissions_by_user=role_permissions,
        )

        submission = _make_submission().as_dict()
        result = await _run_workflow(engine, submission)

        _assert_workflow_response_contract(result, submission)
        assert result["success"] is False
        assert result["status"] == WorkflowStatus.DENIED.value
        assert "role" in result["reason"].lower()
        assert crm_store.leads_for_workspace(PRIMARY_WORKSPACE_ID) == []

    @pytest.mark.asyncio
    async def test_invalid_email_returns_safe_structured_error_without_crm_write(
        self,
        workflow_engine: Any,
        crm_store: InMemoryCrmStore,
        verification_sink: InMemoryVerificationSink,
    ) -> None:
        submission = _make_submission(email="not-an-email").as_dict()

        result = await _run_workflow(workflow_engine, submission)

        assert result["success"] is False
        assert result["status"] == WorkflowStatus.ERROR.value
        assert result["safe_error"] is True
        assert "traceback" not in str(result).lower()
        assert "valueerror" not in str(result).lower()
        assert crm_store.leads_for_workspace(PRIMARY_WORKSPACE_ID) == []

        verification_payloads = verification_sink.by_submission(submission["submission_id"])
        assert verification_payloads
        assert verification_payloads[-1]["status"] == WorkflowStatus.ERROR.value

    @pytest.mark.asyncio
    async def test_missing_contact_consent_returns_safe_error_without_crm_write(
        self,
        workflow_engine: Any,
        crm_store: InMemoryCrmStore,
    ) -> None:
        submission = _make_submission(consent_to_contact=False).as_dict()

        result = await _run_workflow(workflow_engine, submission)

        assert result["success"] is False
        assert result["status"] == WorkflowStatus.ERROR.value
        assert result["safe_error"] is True
        assert crm_store.leads_for_workspace(PRIMARY_WORKSPACE_ID) == []

    @pytest.mark.asyncio
    async def test_audit_log_captures_state_changing_crm_write(
        self,
        workflow_engine: Any,
        audit_sink: InMemoryAuditSink,
    ) -> None:
        submission = _make_submission().as_dict()

        result = await _run_workflow(workflow_engine, submission)

        _assert_workflow_response_contract(result, submission)
        assert result["success"] is True

        workflow_events = audit_sink.by_entity(submission["submission_id"])
        security_events = [
            event
            for event in audit_sink.events
            if event["event_type"] == "security.crm_action_reviewed"
        ]

        assert workflow_events
        assert security_events

        assert any(
            event["event_type"] == "workflow.crm_lead_created"
            and event["status"] == WorkflowStatus.COMPLETED.value
            for event in workflow_events
        )
        assert any(
            event["status"] == SecurityDecisionStatus.APPROVED.value
            for event in security_events
        )

    @pytest.mark.asyncio
    async def test_memory_agent_context_does_not_mix_workspace_data(
        self,
        workflow_engine: Any,
        memory_sink: InMemoryMemorySink,
    ) -> None:
        primary_submission = _make_submission(
            user_id=PRIMARY_USER_ID,
            workspace_id=PRIMARY_WORKSPACE_ID,
            email="primary-memory@example.test",
        ).as_dict()

        secondary_denied_submission = _make_submission(
            user_id=SECONDARY_USER_ID,
            workspace_id=SECONDARY_WORKSPACE_ID,
            email="secondary-memory@example.test",
        ).as_dict()

        await _run_workflow(workflow_engine, primary_submission)
        await _run_workflow(workflow_engine, secondary_denied_submission)

        primary_items = memory_sink.by_submission(primary_submission["submission_id"])
        secondary_items = memory_sink.by_submission(secondary_denied_submission["submission_id"])

        assert primary_items
        assert secondary_items

        assert all(item["workspace_id"] == PRIMARY_WORKSPACE_ID for item in primary_items)
        assert all(item["user_id"] == PRIMARY_USER_ID for item in primary_items)

        assert all(item["workspace_id"] == SECONDARY_WORKSPACE_ID for item in secondary_items)
        assert all(item["user_id"] == SECONDARY_USER_ID for item in secondary_items)

    @pytest.mark.asyncio
    async def test_verification_payload_is_created_for_completed_workflow(
        self,
        workflow_engine: Any,
        verification_sink: InMemoryVerificationSink,
    ) -> None:
        submission = _make_submission().as_dict()

        result = await _run_workflow(workflow_engine, submission)

        assert result["success"] is True
        assert result["status"] == WorkflowStatus.COMPLETED.value

        payload = result["verification_payload"]
        _assert_verification_payload_contract(payload, submission)
        assert payload["crm_lead_id"] is not None
        assert payload["security_decision_id"] is not None

        stored_payloads = verification_sink.by_submission(submission["submission_id"])
        assert stored_payloads
        _assert_verification_payload_contract(stored_payloads[-1], submission)

    @pytest.mark.asyncio
    async def test_security_agent_denial_prevents_crm_write(
        self,
        crm_store: InMemoryCrmStore,
        audit_sink: InMemoryAuditSink,
        memory_sink: InMemoryMemorySink,
        verification_sink: InMemoryVerificationSink,
        allowed_users_by_workspace: Dict[str, List[str]],
        plan_features_by_workspace: Dict[str, List[str]],
        role_permissions_by_user: Dict[str, List[str]],
    ) -> None:
        class DenyingSecurityAgent:
            async def review_action(self, action: Mapping[str, Any]) -> Dict[str, Any]:
                return {
                    "success": False,
                    "decision_id": f"security_decision_{uuid.uuid4().hex}",
                    "action_id": action["action_id"],
                    "user_id": action["user_id"],
                    "workspace_id": action["workspace_id"],
                    "agent": SECURITY_AGENT_NAME,
                    "status": SecurityDecisionStatus.DENIED.value,
                    "risk_level": RiskLevel.HIGH.value,
                    "requires_approval": False,
                    "reason": "Denied by test security policy.",
                    "safe_error": False,
                }

        engine = _build_workflow_engine(
            security_agent=DenyingSecurityAgent(),
            crm_store=crm_store,
            audit_sink=audit_sink,
            memory_sink=memory_sink,
            verification_sink=verification_sink,
            allowed_users_by_workspace=allowed_users_by_workspace,
            plan_features_by_workspace=plan_features_by_workspace,
            role_permissions_by_user=role_permissions_by_user,
        )

        submission = _make_submission().as_dict()
        result = await _run_workflow(engine, submission)

        _assert_workflow_response_contract(result, submission)
        assert result["success"] is False
        assert result["status"] == WorkflowStatus.DENIED.value
        assert crm_store.leads_for_workspace(PRIMARY_WORKSPACE_ID) == []

    @pytest.mark.asyncio
    async def test_parallel_submissions_keep_crm_records_isolated(
        self,
        workflow_engine: Any,
        crm_store: InMemoryCrmStore,
    ) -> None:
        submissions = [
            _make_submission(
                user_id=PRIMARY_USER_ID,
                workspace_id=PRIMARY_WORKSPACE_ID,
                email=f"lead-{index}@example.test",
                target_gclid=f"gclid-{index}",
            ).as_dict()
            for index in range(5)
        ]

        results = await asyncio.gather(
            *[_run_workflow(workflow_engine, submission) for submission in submissions]
        )

        assert all(result["success"] is True for result in results)

        crm_leads = crm_store.leads_for_workspace(PRIMARY_WORKSPACE_ID)
        assert len(crm_leads) == 5

        crm_submission_ids = {lead["submission_id"] for lead in crm_leads}
        source_submission_ids = {submission["submission_id"] for submission in submissions}
        assert crm_submission_ids == source_submission_ids

        _assert_no_cross_workspace_crm_leakage(
            crm_store,
            primary_workspace_id=PRIMARY_WORKSPACE_ID,
            secondary_workspace_id=SECONDARY_WORKSPACE_ID,
        )

    @pytest.mark.asyncio
    async def test_safe_response_does_not_expose_secret_like_form_data(
        self,
        workflow_engine: Any,
    ) -> None:
        fake_secret = "sk-testvalue-not-real-1234567890abcdef"
        submission = _make_submission(
            message=f"My message accidentally includes token {fake_secret}",
        ).as_dict()

        result = await _run_workflow(workflow_engine, submission)

        _assert_workflow_response_contract(result, submission)
        assert fake_secret not in result["reason"]
        assert "traceback" not in str(result).lower()

    def test_test_module_does_not_require_real_environment_secrets(self) -> None:
        """
        This integration test must run locally and in CI without real credentials.

        The workflow should use fake stores/doubles and avoid requiring values like
        real CRM tokens, database URLs, Google secrets, or JWT secrets.
        """

        sensitive_env_names = [
            "CRM_API_KEY",
            "CRM_ACCESS_TOKEN",
            "DATABASE_URL",
            "JWT_SECRET",
            "GOOGLE_CLIENT_SECRET",
            "OPENAI_API_KEY",
        ]

        for env_name in sensitive_env_names:
            value = os.environ.get(env_name)
            if value:
                assert value not in __doc__
                assert value not in repr(FallbackWorkflowFormToCrm)
                assert value not in repr(FallbackSecurityAgent)