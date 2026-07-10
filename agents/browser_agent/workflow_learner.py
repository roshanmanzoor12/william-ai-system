"""
agents/browser_agent/workflow_learner.py

William / Jarvis Multi-Agent AI SaaS System
Digital Promotix

BrowserWorkflowLearner learns website signup, checkout, onboarding, login,
and dashboard flows step-by-step.

This module is intentionally SAFE:
- It does NOT execute real browser actions.
- It does NOT submit forms.
- It does NOT complete checkout/payment flows.
- It does NOT create accounts.
- It does NOT bypass security, CAPTCHA, paywalls, authentication, or permissions.
- It records, analyzes, validates, and prepares reusable workflow knowledge only.

Designed for:
- Master Agent routing
- Browser Agent planning
- Workflow Agent handoff
- Security Agent approval
- Verification Agent payloads
- Memory Agent safe storage
- Dashboard/API analytics
- SaaS user/workspace isolation
"""

from __future__ import annotations

import copy
import hashlib
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Optional William/Jarvis imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover

    class BaseAgent:  # type: ignore
        """
        Import-safe fallback BaseAgent.

        The real William/Jarvis BaseAgent may not exist yet while this module
        is being generated. This fallback prevents import crashes.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", "browser_workflow_learner")


try:
    from agents.registry import AgentRegistry  # type: ignore
except Exception:  # pragma: no cover
    AgentRegistry = None  # type: ignore


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WORKFLOW_LEARNER_SCHEMA_VERSION = "1.0.0"

DEFAULT_MAX_WORKFLOWS = 100
DEFAULT_MAX_STEPS_PER_WORKFLOW = 250
DEFAULT_MAX_EVENTS = 500
DEFAULT_MAX_OBSERVATIONS = 1000

SENSITIVE_FIELD_KEYWORDS = {
    "password",
    "passcode",
    "token",
    "secret",
    "api_key",
    "apikey",
    "card",
    "cc",
    "cvv",
    "cvc",
    "ssn",
    "otp",
    "pin",
    "auth",
    "session",
    "cookie",
    "private",
}

HIGH_RISK_ACTION_KEYWORDS = {
    "submit_payment",
    "confirm_purchase",
    "place_order",
    "delete",
    "cancel_subscription",
    "transfer",
    "send_message",
    "call",
    "login",
    "signup",
    "register",
    "create_account",
    "checkout",
    "pay",
    "subscribe",
}

SAFE_DEFAULT_PERMISSIONS = {
    "can_learn_workflow": True,
    "can_record_observations": True,
    "can_prepare_memory_payload": True,
    "can_prepare_verification_payload": True,
    "can_export_workflow": True,
    "can_clear_workflow": False,
    "can_mark_workflow_production_ready": False,
}


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class WorkflowType(str, Enum):
    UNKNOWN = "unknown"
    SIGNUP = "signup"
    LOGIN = "login"
    CHECKOUT = "checkout"
    DASHBOARD = "dashboard"
    ONBOARDING = "onboarding"
    CONTACT_FORM = "contact_form"
    LEAD_FORM = "lead_form"
    BOOKING = "booking"
    SUBSCRIPTION = "subscription"
    SETTINGS = "settings"
    SUPPORT = "support"


class WorkflowStatus(str, Enum):
    DRAFT = "draft"
    LEARNING = "learning"
    REVIEW_REQUIRED = "review_required"
    SECURITY_REVIEW_REQUIRED = "security_review_required"
    VERIFIED = "verified"
    PRODUCTION_READY = "production_ready"
    ARCHIVED = "archived"
    FAILED = "failed"


class StepType(str, Enum):
    OBSERVE_PAGE = "observe_page"
    CLICK = "click"
    TYPE = "type"
    SELECT = "select"
    CHECKBOX = "checkbox"
    RADIO = "radio"
    UPLOAD = "upload"
    WAIT = "wait"
    NAVIGATE = "navigate"
    ASSERT = "assert"
    CAPTCHA_DETECTED = "captcha_detected"
    LOGIN_REQUIRED = "login_required"
    PAYMENT_REQUIRED = "payment_required"
    HUMAN_REVIEW = "human_review"
    UNKNOWN = "unknown"


class StepRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKED = "blocked"


class LearnerEventType(str, Enum):
    LEARNER_CREATED = "learner_created"
    WORKFLOW_CREATED = "workflow_created"
    WORKFLOW_UPDATED = "workflow_updated"
    WORKFLOW_ARCHIVED = "workflow_archived"
    STEP_ADDED = "step_added"
    STEP_UPDATED = "step_updated"
    OBSERVATION_RECORDED = "observation_recorded"
    PATTERNS_ANALYZED = "patterns_analyzed"
    RISK_ANALYZED = "risk_analyzed"
    SECURITY_APPROVAL_REQUESTED = "security_approval_requested"
    VERIFICATION_PAYLOAD_PREPARED = "verification_payload_prepared"
    MEMORY_PAYLOAD_PREPARED = "memory_payload_prepared"
    AUDIT_EVENT = "audit_event"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

@dataclass
class WorkflowStepElement:
    """
    Safe UI element descriptor.

    This stores selectors and visible labels only.
    It must not store sensitive values entered by the user.
    """

    element_id: str
    tag: Optional[str] = None
    selector: Optional[str] = None
    xpath: Optional[str] = None
    role: Optional[str] = None
    label: Optional[str] = None
    placeholder: Optional[str] = None
    text_hint: Optional[str] = None
    field_name_hash: Optional[str] = None
    is_sensitive_field: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowStep:
    """
    One learned workflow step.

    This is a plan/observation step, not an execution instruction.
    """

    step_id: str
    workflow_id: str
    step_index: int
    user_id: str
    workspace_id: str
    task_id: Optional[str]
    step_type: str
    description: str
    url: Optional[str] = None
    domain: Optional[str] = None
    page_title: Optional[str] = None
    element: Optional[WorkflowStepElement] = None
    input_value_hint: Optional[str] = None
    expected_result: Optional[str] = None
    risk_level: str = StepRiskLevel.LOW.value
    requires_security_review: bool = False
    requires_human_review: bool = False
    blocked_reason: Optional[str] = None
    confidence: float = 0.0
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowObservation:
    """
    Raw safe observation from a page state.

    Can be produced by Browser Agent, Page Analyzer, Scraper, Visual Agent, or
    future dashboard instrumentation.
    """

    observation_id: str
    workflow_id: str
    user_id: str
    workspace_id: str
    task_id: Optional[str]
    url: Optional[str]
    domain: Optional[str]
    page_title: Optional[str]
    visible_text_summary: Optional[str]
    detected_elements: List[Dict[str, Any]] = field(default_factory=list)
    detected_forms: List[Dict[str, Any]] = field(default_factory=list)
    detected_buttons: List[Dict[str, Any]] = field(default_factory=list)
    detected_links: List[Dict[str, Any]] = field(default_factory=list)
    detected_warnings: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: utc_now_iso())
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class LearnedWorkflow:
    """
    Main learned workflow model.

    Stored per user/workspace to prevent cross-user knowledge leakage.
    """

    workflow_id: str
    user_id: str
    workspace_id: str
    task_id: Optional[str]
    name: str
    workflow_type: str = WorkflowType.UNKNOWN.value
    status: str = WorkflowStatus.DRAFT.value
    source_domain: Optional[str] = None
    start_url: Optional[str] = None
    goal: Optional[str] = None
    steps: List[WorkflowStep] = field(default_factory=list)
    observations: List[WorkflowObservation] = field(default_factory=list)
    confidence: float = 0.0
    risk_level: str = StepRiskLevel.LOW.value
    requires_security_review: bool = False
    requires_human_review: bool = False
    created_at: str = field(default_factory=lambda: utc_now_iso())
    updated_at: str = field(default_factory=lambda: utc_now_iso())
    verified_at: Optional[str] = None
    archived_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowLearnerEvent:
    """Internal event for audit/dashboard/Master Agent visibility."""

    event_id: str
    event_type: str
    user_id: str
    workspace_id: str
    task_id: Optional[str]
    workflow_id: Optional[str]
    timestamp: str
    message: str
    data: Dict[str, Any] = field(default_factory=dict)
    risk_level: str = StepRiskLevel.LOW.value


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return timezone-aware UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def generate_id(prefix: str) -> str:
    """Generate readable unique ID."""
    return f"{prefix}_{uuid.uuid4().hex}"


def safe_hash(value: str) -> str:
    """Hash values that should not be stored raw."""
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()


def safe_copy(data: Any) -> Any:
    """Safely deep-copy JSON-like data."""
    try:
        return copy.deepcopy(data)
    except Exception:
        return data


def normalize_url(url: Optional[str]) -> Optional[str]:
    """Normalize URL without making network requests."""
    if url is None:
        return None

    clean = str(url).strip()
    if not clean:
        return None

    parsed = urlparse(clean)

    if not parsed.scheme:
        clean = f"https://{clean}"
        parsed = urlparse(clean)

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"

    if path != "/":
        path = path.rstrip("/")

    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{netloc}{path}{query}"


def extract_domain(url: Optional[str]) -> Optional[str]:
    """Extract domain from URL."""
    if not url:
        return None

    parsed = urlparse(normalize_url(url) or "")
    domain = parsed.netloc.lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain or None


def clean_text(value: Optional[str], max_length: int = 500) -> Optional[str]:
    """Normalize text for safe storage."""
    if value is None:
        return None

    text = re.sub(r"\s+", " ", str(value)).strip()
    if len(text) > max_length:
        return text[: max_length - 3] + "..."

    return text


def clamp_confidence(value: Any) -> float:
    """Clamp confidence score to 0..1."""
    try:
        score = float(value)
    except Exception:
        score = 0.0

    return max(0.0, min(1.0, score))


def detect_sensitive_name(name: Optional[str]) -> bool:
    """Detect sensitive field names/labels."""
    text = str(name or "").lower()
    return any(keyword in text for keyword in SENSITIVE_FIELD_KEYWORDS)


def redact_input_value(value: Optional[str]) -> Optional[str]:
    """Return a safe hint for an input value without storing full value."""
    if value is None:
        return None

    raw = str(value)

    if not raw:
        return "empty"

    if len(raw) <= 2:
        return "***"

    return f"{raw[:1]}***{raw[-1:]}"


# ---------------------------------------------------------------------------
# BrowserWorkflowLearner
# ---------------------------------------------------------------------------

class BrowserWorkflowLearner:
    """
    Learns website flows step-by-step.

    It stores safe workflow observations and step definitions for later review,
    verification, memory storage, dashboard display, and supervised execution
    by approved Browser Agent tools.

    This class does not execute browser automation.
    """

    module_name = "browser_agent"
    component_name = "workflow_learner"
    schema_version = WORKFLOW_LEARNER_SCHEMA_VERSION

    def __init__(
        self,
        user_id: str,
        workspace_id: str,
        task_id: Optional[str] = None,
        permissions: Optional[Dict[str, bool]] = None,
        max_workflows: int = DEFAULT_MAX_WORKFLOWS,
        max_steps_per_workflow: int = DEFAULT_MAX_STEPS_PER_WORKFLOW,
        max_observations: int = DEFAULT_MAX_OBSERVATIONS,
        max_events: int = DEFAULT_MAX_EVENTS,
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize Workflow Learner.

        Args:
            user_id: SaaS user ID.
            workspace_id: SaaS workspace ID.
            task_id: Optional active task ID.
            permissions: Optional local permission map.
            max_workflows: Max workflows stored in memory.
            max_steps_per_workflow: Max steps per workflow.
            max_observations: Max observations across workflows.
            max_events: Max internal events retained.
            event_callback: Optional dashboard/API/Master Agent event sink.
            audit_callback: Optional audit log sink.
            security_callback: Optional Security Agent approval bridge.
            metadata: Optional safe metadata.
        """
        self.user_id = str(user_id or "").strip()
        self.workspace_id = str(workspace_id or "").strip()
        self.task_id = str(task_id).strip() if task_id else None

        self.permissions = dict(SAFE_DEFAULT_PERMISSIONS)
        if permissions:
            self.permissions.update({str(k): bool(v) for k, v in permissions.items()})

        self.max_workflows = max(1, int(max_workflows))
        self.max_steps_per_workflow = max(1, int(max_steps_per_workflow))
        self.max_observations = max(1, int(max_observations))
        self.max_events = max(1, int(max_events))

        self.event_callback = event_callback
        self.audit_callback = audit_callback
        self.security_callback = security_callback

        self.metadata: Dict[str, Any] = metadata.copy() if isinstance(metadata, dict) else {}

        self.learner_id = generate_id("workflow_learner")
        self.created_at = utc_now_iso()
        self.updated_at = self.created_at

        self.workflows: Dict[str, LearnedWorkflow] = {}
        self.active_workflow_id: Optional[str] = None
        self.events: List[WorkflowLearnerEvent] = []

        validation = self._validate_task_context()
        if not validation["success"]:
            raise ValueError(validation["error"]["message"])

        self._emit_agent_event(
            LearnerEventType.LEARNER_CREATED.value,
            "Browser workflow learner created.",
            data={
                "learner_id": self.learner_id,
                "schema_version": self.schema_version,
            },
        )

    # -----------------------------------------------------------------------
    # Workflow lifecycle
    # -----------------------------------------------------------------------

    def create_workflow(
        self,
        name: str,
        workflow_type: str = WorkflowType.UNKNOWN.value,
        start_url: Optional[str] = None,
        goal: Optional[str] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        make_active: bool = True,
    ) -> Dict[str, Any]:
        """
        Create a new learned workflow.

        Example use:
        - Learn signup flow for a SaaS website
        - Learn checkout flow step-by-step for review
        - Learn dashboard navigation flow
        """
        try:
            validation = self._validate_task_context(task_id=task_id)
            if not validation["success"]:
                return validation

            permission = self._check_permission("can_learn_workflow")
            if not permission["success"]:
                return permission

            if len(self.workflows) >= self.max_workflows:
                return self._error_result(
                    "Maximum workflow limit reached.",
                    error_code="MAX_WORKFLOWS_REACHED",
                    metadata={"max_workflows": self.max_workflows},
                )

            clean_name = clean_text(name, max_length=160)
            if not clean_name:
                return self._error_result(
                    "Workflow name is required.",
                    error_code="INVALID_WORKFLOW_NAME",
                )

            clean_type = self._validate_workflow_type(workflow_type)
            normalized_url = normalize_url(start_url)
            domain = extract_domain(normalized_url)

            workflow = LearnedWorkflow(
                workflow_id=generate_id("workflow"),
                user_id=self.user_id,
                workspace_id=self.workspace_id,
                task_id=task_id or self.task_id,
                name=clean_name,
                workflow_type=clean_type,
                status=WorkflowStatus.LEARNING.value,
                source_domain=domain,
                start_url=normalized_url,
                goal=clean_text(goal, max_length=500),
                metadata=metadata.copy() if isinstance(metadata, dict) else {},
            )

            initial_risk = self._analyze_workflow_risk(workflow)
            workflow.risk_level = initial_risk["risk_level"]
            workflow.requires_security_review = initial_risk["requires_security_review"]
            workflow.requires_human_review = initial_risk["requires_human_review"]

            if workflow.requires_security_review:
                workflow.status = WorkflowStatus.SECURITY_REVIEW_REQUIRED.value

            self.workflows[workflow.workflow_id] = workflow

            if make_active:
                self.active_workflow_id = workflow.workflow_id

            self.updated_at = utc_now_iso()

            self._emit_agent_event(
                LearnerEventType.WORKFLOW_CREATED.value,
                "Workflow created for learning.",
                workflow_id=workflow.workflow_id,
                task_id=task_id or self.task_id,
                data={"workflow": self._workflow_to_safe_dict(workflow, include_observations=False)},
                risk_level=workflow.risk_level,
            )

            self._log_audit_event(
                action="create_workflow",
                status="success",
                workflow_id=workflow.workflow_id,
                task_id=task_id or self.task_id,
                details={
                    "workflow_type": workflow.workflow_type,
                    "source_domain": workflow.source_domain,
                    "risk_level": workflow.risk_level,
                },
                risk_level=workflow.risk_level,
            )

            return self._safe_result(
                "Workflow created successfully.",
                data={
                    "workflow": self._workflow_to_safe_dict(workflow),
                    "active_workflow_id": self.active_workflow_id,
                },
            )

        except Exception as exc:
            return self._handle_exception("Failed to create workflow.", exc)

    def set_active_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Set the active workflow by ID."""
        workflow = self.workflows.get(workflow_id)
        if not workflow:
            return self._error_result(
                "Workflow not found.",
                error_code="WORKFLOW_NOT_FOUND",
                metadata={"workflow_id": workflow_id},
            )

        ownership = self._validate_record_scope(workflow.user_id, workflow.workspace_id)
        if not ownership["success"]:
            return ownership

        self.active_workflow_id = workflow_id
        self.updated_at = utc_now_iso()

        return self._safe_result(
            "Active workflow updated successfully.",
            data={"active_workflow_id": self.active_workflow_id},
        )

    def update_workflow(
        self,
        workflow_id: str,
        name: Optional[str] = None,
        workflow_type: Optional[str] = None,
        goal: Optional[str] = None,
        status: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update workflow metadata safely."""
        try:
            workflow = self._get_workflow_or_active(workflow_id)
            if not workflow:
                return self._error_result(
                    "Workflow not found.",
                    error_code="WORKFLOW_NOT_FOUND",
                    metadata={"workflow_id": workflow_id},
                )

            validation = self._validate_task_context(task_id=task_id or workflow.task_id)
            if not validation["success"]:
                return validation

            if name is not None:
                clean_name = clean_text(name, max_length=160)
                if not clean_name:
                    return self._error_result(
                        "Workflow name cannot be blank.",
                        error_code="INVALID_WORKFLOW_NAME",
                    )
                workflow.name = clean_name

            if workflow_type is not None:
                workflow.workflow_type = self._validate_workflow_type(workflow_type)

            if goal is not None:
                workflow.goal = clean_text(goal, max_length=500)

            if status is not None:
                clean_status = self._validate_workflow_status(status)

                if clean_status == WorkflowStatus.PRODUCTION_READY.value:
                    permission = self._check_permission("can_mark_workflow_production_ready")
                    if not permission["success"]:
                        return permission

                    if self._requires_security_check("mark_workflow_production_ready"):
                        approval = self._request_security_approval(
                            action="mark_workflow_production_ready",
                            risk_level=workflow.risk_level,
                            workflow_id=workflow.workflow_id,
                            task_id=task_id or workflow.task_id,
                            payload=self._workflow_to_safe_dict(workflow),
                        )
                        if not approval["success"]:
                            return approval

                workflow.status = clean_status

                if clean_status == WorkflowStatus.VERIFIED.value:
                    workflow.verified_at = utc_now_iso()

                if clean_status == WorkflowStatus.ARCHIVED.value:
                    workflow.archived_at = utc_now_iso()

            if isinstance(metadata, dict):
                workflow.metadata.update(safe_copy(metadata))

            risk = self._analyze_workflow_risk(workflow)
            workflow.risk_level = risk["risk_level"]
            workflow.requires_security_review = risk["requires_security_review"]
            workflow.requires_human_review = risk["requires_human_review"]
            workflow.confidence = self._calculate_workflow_confidence(workflow)
            workflow.updated_at = utc_now_iso()
            self.updated_at = workflow.updated_at

            self._emit_agent_event(
                LearnerEventType.WORKFLOW_UPDATED.value,
                "Workflow updated.",
                workflow_id=workflow.workflow_id,
                task_id=task_id or workflow.task_id,
                data={"workflow": self._workflow_to_safe_dict(workflow, include_observations=False)},
                risk_level=workflow.risk_level,
            )

            self._log_audit_event(
                action="update_workflow",
                status="success",
                workflow_id=workflow.workflow_id,
                task_id=task_id or workflow.task_id,
                details={
                    "workflow_status": workflow.status,
                    "risk_level": workflow.risk_level,
                    "confidence": workflow.confidence,
                },
                risk_level=workflow.risk_level,
            )

            return self._safe_result(
                "Workflow updated successfully.",
                data={"workflow": self._workflow_to_safe_dict(workflow)},
            )

        except Exception as exc:
            return self._handle_exception("Failed to update workflow.", exc)

    def archive_workflow(
        self,
        workflow_id: str,
        reason: str = "manual_archive",
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Archive a workflow without deleting it."""
        try:
            workflow = self._get_workflow_or_active(workflow_id)
            if not workflow:
                return self._error_result(
                    "Workflow not found.",
                    error_code="WORKFLOW_NOT_FOUND",
                    metadata={"workflow_id": workflow_id},
                )

            workflow.status = WorkflowStatus.ARCHIVED.value
            workflow.archived_at = utc_now_iso()
            workflow.updated_at = workflow.archived_at
            workflow.metadata["archive_reason"] = clean_text(reason, max_length=300)

            if self.active_workflow_id == workflow.workflow_id:
                self.active_workflow_id = None

            self._emit_agent_event(
                LearnerEventType.WORKFLOW_ARCHIVED.value,
                "Workflow archived.",
                workflow_id=workflow.workflow_id,
                task_id=task_id or workflow.task_id,
                data={"reason": reason},
                risk_level=workflow.risk_level,
            )

            self._log_audit_event(
                action="archive_workflow",
                status="success",
                workflow_id=workflow.workflow_id,
                task_id=task_id or workflow.task_id,
                details={"reason": reason},
                risk_level=workflow.risk_level,
            )

            return self._safe_result(
                "Workflow archived successfully.",
                data={"workflow": self._workflow_to_safe_dict(workflow)},
            )

        except Exception as exc:
            return self._handle_exception("Failed to archive workflow.", exc)

    # -----------------------------------------------------------------------
    # Step learning
    # -----------------------------------------------------------------------

    def add_step(
        self,
        workflow_id: Optional[str],
        step_type: str,
        description: str,
        url: Optional[str] = None,
        page_title: Optional[str] = None,
        element: Optional[Dict[str, Any]] = None,
        input_value: Optional[str] = None,
        expected_result: Optional[str] = None,
        confidence: float = 0.5,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Add a learned step to a workflow.

        Sensitive input values are redacted. The raw value is never stored.
        """
        try:
            workflow = self._get_workflow_or_active(workflow_id)
            if not workflow:
                return self._error_result(
                    "Workflow not found.",
                    error_code="WORKFLOW_NOT_FOUND",
                    metadata={"workflow_id": workflow_id},
                )

            validation = self._validate_task_context(task_id=task_id or workflow.task_id)
            if not validation["success"]:
                return validation

            permission = self._check_permission("can_learn_workflow")
            if not permission["success"]:
                return permission

            if len(workflow.steps) >= self.max_steps_per_workflow:
                return self._error_result(
                    "Maximum steps per workflow reached.",
                    error_code="MAX_STEPS_REACHED",
                    metadata={"max_steps_per_workflow": self.max_steps_per_workflow},
                )

            clean_step_type = self._validate_step_type(step_type)
            clean_description = clean_text(description, max_length=600)

            if not clean_description:
                return self._error_result(
                    "Step description is required.",
                    error_code="INVALID_STEP_DESCRIPTION",
                )

            normalized_url = normalize_url(url)
            domain = extract_domain(normalized_url) or workflow.source_domain

            safe_element = self._build_safe_element(element)
            input_value_hint = redact_input_value(input_value)

            risk = self._analyze_step_risk(
                step_type=clean_step_type,
                description=clean_description,
                element=safe_element,
                input_value=input_value,
                url=normalized_url,
            )

            step = WorkflowStep(
                step_id=generate_id("workflow_step"),
                workflow_id=workflow.workflow_id,
                step_index=len(workflow.steps) + 1,
                user_id=self.user_id,
                workspace_id=self.workspace_id,
                task_id=task_id or workflow.task_id or self.task_id,
                step_type=clean_step_type,
                description=clean_description,
                url=normalized_url,
                domain=domain,
                page_title=clean_text(page_title, max_length=200),
                element=safe_element,
                input_value_hint=input_value_hint,
                expected_result=clean_text(expected_result, max_length=600),
                risk_level=risk["risk_level"],
                requires_security_review=risk["requires_security_review"],
                requires_human_review=risk["requires_human_review"],
                blocked_reason=risk.get("blocked_reason"),
                confidence=clamp_confidence(confidence),
                metadata=metadata.copy() if isinstance(metadata, dict) else {},
            )

            workflow.steps.append(step)
            workflow.confidence = self._calculate_workflow_confidence(workflow)

            workflow_risk = self._analyze_workflow_risk(workflow)
            workflow.risk_level = workflow_risk["risk_level"]
            workflow.requires_security_review = workflow_risk["requires_security_review"]
            workflow.requires_human_review = workflow_risk["requires_human_review"]

            if workflow.requires_security_review:
                workflow.status = WorkflowStatus.SECURITY_REVIEW_REQUIRED.value
            elif workflow.requires_human_review and workflow.status == WorkflowStatus.LEARNING.value:
                workflow.status = WorkflowStatus.REVIEW_REQUIRED.value

            workflow.updated_at = utc_now_iso()
            self.updated_at = workflow.updated_at

            self._emit_agent_event(
                LearnerEventType.STEP_ADDED.value,
                "Workflow step added.",
                workflow_id=workflow.workflow_id,
                task_id=task_id or workflow.task_id,
                data={"step": self._step_to_safe_dict(step)},
                risk_level=step.risk_level,
            )

            self._log_audit_event(
                action="add_workflow_step",
                status="success",
                workflow_id=workflow.workflow_id,
                task_id=task_id or workflow.task_id,
                details={
                    "step_id": step.step_id,
                    "step_type": step.step_type,
                    "risk_level": step.risk_level,
                },
                risk_level=step.risk_level,
            )

            return self._safe_result(
                "Workflow step added successfully.",
                data={
                    "step": self._step_to_safe_dict(step),
                    "workflow": self._workflow_to_safe_dict(workflow, include_observations=False),
                },
            )

        except Exception as exc:
            return self._handle_exception("Failed to add workflow step.", exc)

    def update_step(
        self,
        workflow_id: str,
        step_id: str,
        description: Optional[str] = None,
        expected_result: Optional[str] = None,
        confidence: Optional[float] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Update a learned workflow step."""
        try:
            workflow = self._get_workflow_or_active(workflow_id)
            if not workflow:
                return self._error_result(
                    "Workflow not found.",
                    error_code="WORKFLOW_NOT_FOUND",
                    metadata={"workflow_id": workflow_id},
                )

            step = self._find_step(workflow, step_id)
            if not step:
                return self._error_result(
                    "Workflow step not found.",
                    error_code="STEP_NOT_FOUND",
                    metadata={"step_id": step_id},
                )

            if description is not None:
                clean_description = clean_text(description, max_length=600)
                if not clean_description:
                    return self._error_result(
                        "Step description cannot be blank.",
                        error_code="INVALID_STEP_DESCRIPTION",
                    )
                step.description = clean_description

            if expected_result is not None:
                step.expected_result = clean_text(expected_result, max_length=600)

            if confidence is not None:
                step.confidence = clamp_confidence(confidence)

            if isinstance(metadata, dict):
                step.metadata.update(safe_copy(metadata))

            risk = self._analyze_step_risk(
                step_type=step.step_type,
                description=step.description,
                element=step.element,
                input_value=None,
                url=step.url,
            )
            step.risk_level = risk["risk_level"]
            step.requires_security_review = risk["requires_security_review"]
            step.requires_human_review = risk["requires_human_review"]
            step.blocked_reason = risk.get("blocked_reason")
            step.updated_at = utc_now_iso()

            workflow.confidence = self._calculate_workflow_confidence(workflow)
            workflow_risk = self._analyze_workflow_risk(workflow)
            workflow.risk_level = workflow_risk["risk_level"]
            workflow.requires_security_review = workflow_risk["requires_security_review"]
            workflow.requires_human_review = workflow_risk["requires_human_review"]
            workflow.updated_at = utc_now_iso()

            self._emit_agent_event(
                LearnerEventType.STEP_UPDATED.value,
                "Workflow step updated.",
                workflow_id=workflow.workflow_id,
                task_id=step.task_id,
                data={"step": self._step_to_safe_dict(step)},
                risk_level=step.risk_level,
            )

            return self._safe_result(
                "Workflow step updated successfully.",
                data={"step": self._step_to_safe_dict(step)},
            )

        except Exception as exc:
            return self._handle_exception("Failed to update workflow step.", exc)

    # -----------------------------------------------------------------------
    # Observation learning
    # -----------------------------------------------------------------------

    def record_observation(
        self,
        workflow_id: Optional[str],
        url: Optional[str] = None,
        page_title: Optional[str] = None,
        visible_text_summary: Optional[str] = None,
        detected_elements: Optional[List[Dict[str, Any]]] = None,
        detected_forms: Optional[List[Dict[str, Any]]] = None,
        detected_buttons: Optional[List[Dict[str, Any]]] = None,
        detected_links: Optional[List[Dict[str, Any]]] = None,
        detected_warnings: Optional[List[str]] = None,
        task_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record a safe page observation.

        Observations can come from Page Analyzer, Scraper, Visual Agent, or
        browser instrumentation. Sensitive field data is sanitized.
        """
        try:
            workflow = self._get_workflow_or_active(workflow_id)
            if not workflow:
                return self._error_result(
                    "Workflow not found.",
                    error_code="WORKFLOW_NOT_FOUND",
                    metadata={"workflow_id": workflow_id},
                )

            validation = self._validate_task_context(task_id=task_id or workflow.task_id)
            if not validation["success"]:
                return validation

            permission = self._check_permission("can_record_observations")
            if not permission["success"]:
                return permission

            normalized_url = normalize_url(url)
            domain = extract_domain(normalized_url) or workflow.source_domain

            observation = WorkflowObservation(
                observation_id=generate_id("workflow_observation"),
                workflow_id=workflow.workflow_id,
                user_id=self.user_id,
                workspace_id=self.workspace_id,
                task_id=task_id or workflow.task_id or self.task_id,
                url=normalized_url,
                domain=domain,
                page_title=clean_text(page_title, max_length=200),
                visible_text_summary=clean_text(visible_text_summary, max_length=1200),
                detected_elements=self._sanitize_detected_items(detected_elements),
                detected_forms=self._sanitize_detected_items(detected_forms),
                detected_buttons=self._sanitize_detected_items(detected_buttons),
                detected_links=self._sanitize_detected_items(detected_links),
                detected_warnings=[
                    clean_text(warning, max_length=300) or ""
                    for warning in (detected_warnings or [])
                ],
                metadata=metadata.copy() if isinstance(metadata, dict) else {},
            )

            workflow.observations.append(observation)
            self._trim_observations(workflow)

            if not workflow.source_domain and domain:
                workflow.source_domain = domain

            if not workflow.start_url and normalized_url:
                workflow.start_url = normalized_url

            workflow.updated_at = utc_now_iso()
            self.updated_at = workflow.updated_at

            self._emit_agent_event(
                LearnerEventType.OBSERVATION_RECORDED.value,
                "Workflow observation recorded.",
                workflow_id=workflow.workflow_id,
                task_id=task_id or workflow.task_id,
                data={"observation": self._observation_to_safe_dict(observation)},
            )

            return self._safe_result(
                "Workflow observation recorded successfully.",
                data={"observation": self._observation_to_safe_dict(observation)},
            )

        except Exception as exc:
            return self._handle_exception("Failed to record workflow observation.", exc)

    def analyze_observations(
        self,
        workflow_id: Optional[str],
        task_id: Optional[str] = None,
        auto_add_safe_steps: bool = False,
    ) -> Dict[str, Any]:
        """
        Analyze observations and suggest likely workflow steps.

        If auto_add_safe_steps=True, only LOW-risk observe/assert/wait style
        steps may be added automatically. Risky actions remain suggestions.
        """
        try:
            workflow = self._get_workflow_or_active(workflow_id)
            if not workflow:
                return self._error_result(
                    "Workflow not found.",
                    error_code="WORKFLOW_NOT_FOUND",
                    metadata={"workflow_id": workflow_id},
                )

            suggestions: List[Dict[str, Any]] = []

            for observation in workflow.observations:
                suggestions.extend(self._suggest_steps_from_observation(workflow, observation))

            safe_added_steps = []

            if auto_add_safe_steps:
                for suggestion in suggestions:
                    if suggestion.get("risk_level") != StepRiskLevel.LOW.value:
                        continue

                    if suggestion.get("step_type") not in {
                        StepType.OBSERVE_PAGE.value,
                        StepType.ASSERT.value,
                        StepType.WAIT.value,
                    }:
                        continue

                    add_result = self.add_step(
                        workflow_id=workflow.workflow_id,
                        step_type=suggestion["step_type"],
                        description=suggestion["description"],
                        url=suggestion.get("url"),
                        page_title=suggestion.get("page_title"),
                        element=suggestion.get("element"),
                        expected_result=suggestion.get("expected_result"),
                        confidence=suggestion.get("confidence", 0.5),
                        task_id=task_id or workflow.task_id,
                        metadata={"source": "analyze_observations"},
                    )
                    if add_result["success"]:
                        safe_added_steps.append(add_result["data"]["step"])

            workflow.confidence = self._calculate_workflow_confidence(workflow)
            workflow.updated_at = utc_now_iso()

            self._emit_agent_event(
                LearnerEventType.PATTERNS_ANALYZED.value,
                "Workflow observations analyzed.",
                workflow_id=workflow.workflow_id,
                task_id=task_id or workflow.task_id,
                data={
                    "suggestions_count": len(suggestions),
                    "auto_added_count": len(safe_added_steps),
                },
            )

            return self._safe_result(
                "Workflow observations analyzed successfully.",
                data={
                    "workflow_id": workflow.workflow_id,
                    "suggestions": suggestions,
                    "auto_added_steps": safe_added_steps,
                    "confidence": workflow.confidence,
                },
            )

        except Exception as exc:
            return self._handle_exception("Failed to analyze workflow observations.", exc)

    # -----------------------------------------------------------------------
    # Risk and review
    # -----------------------------------------------------------------------

    def analyze_workflow_risk(
        self,
        workflow_id: Optional[str],
    ) -> Dict[str, Any]:
        """Public workflow risk analysis."""
        try:
            workflow = self._get_workflow_or_active(workflow_id)
            if not workflow:
                return self._error_result(
                    "Workflow not found.",
                    error_code="WORKFLOW_NOT_FOUND",
                    metadata={"workflow_id": workflow_id},
                )

            risk = self._analyze_workflow_risk(workflow)
            workflow.risk_level = risk["risk_level"]
            workflow.requires_security_review = risk["requires_security_review"]
            workflow.requires_human_review = risk["requires_human_review"]
            workflow.updated_at = utc_now_iso()

            self._emit_agent_event(
                LearnerEventType.RISK_ANALYZED.value,
                "Workflow risk analyzed.",
                workflow_id=workflow.workflow_id,
                task_id=workflow.task_id,
                data=risk,
                risk_level=risk["risk_level"],
            )

            return self._safe_result(
                "Workflow risk analyzed successfully.",
                data={"risk": risk, "workflow": self._workflow_to_safe_dict(workflow)},
            )

        except Exception as exc:
            return self._handle_exception("Failed to analyze workflow risk.", exc)

    # -----------------------------------------------------------------------
    # Export helpers
    # -----------------------------------------------------------------------

    def get_workflow(
        self,
        workflow_id: Optional[str] = None,
        include_observations: bool = True,
    ) -> Dict[str, Any]:
        """Return one workflow."""
        workflow = self._get_workflow_or_active(workflow_id)
        if not workflow:
            return self._error_result(
                "Workflow not found.",
                error_code="WORKFLOW_NOT_FOUND",
                metadata={"workflow_id": workflow_id},
            )

        return self._safe_result(
            "Workflow returned successfully.",
            data={"workflow": self._workflow_to_safe_dict(workflow, include_observations=include_observations)},
        )

    def list_workflows(
        self,
        workflow_type: Optional[str] = None,
        status: Optional[str] = None,
        domain: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List workflows for current user/workspace."""
        try:
            workflows = list(self.workflows.values())

            if workflow_type:
                clean_type = self._validate_workflow_type(workflow_type)
                workflows = [item for item in workflows if item.workflow_type == clean_type]

            if status:
                clean_status = self._validate_workflow_status(status)
                workflows = [item for item in workflows if item.status == clean_status]

            if domain:
                clean_domain = str(domain).strip().lower().replace("www.", "")
                workflows = [item for item in workflows if item.source_domain == clean_domain]

            workflows.sort(key=lambda item: item.updated_at, reverse=True)

            return self._safe_result(
                "Workflows returned successfully.",
                data={
                    "workflows": [
                        self._workflow_to_safe_dict(item, include_observations=False)
                        for item in workflows
                    ],
                    "count": len(workflows),
                    "active_workflow_id": self.active_workflow_id,
                },
            )

        except Exception as exc:
            return self._handle_exception("Failed to list workflows.", exc)

    def export_workflow_plan(
        self,
        workflow_id: Optional[str] = None,
        include_risky_steps: bool = True,
    ) -> Dict[str, Any]:
        """
        Export learned workflow as a safe plan.

        This can be reviewed by Master Agent, Workflow Agent, Verification Agent,
        or a human before any execution tool is allowed.
        """
        try:
            permission = self._check_permission("can_export_workflow")
            if not permission["success"]:
                return permission

            workflow = self._get_workflow_or_active(workflow_id)
            if not workflow:
                return self._error_result(
                    "Workflow not found.",
                    error_code="WORKFLOW_NOT_FOUND",
                    metadata={"workflow_id": workflow_id},
                )

            steps = workflow.steps
            if not include_risky_steps:
                steps = [
                    step for step in steps
                    if step.risk_level == StepRiskLevel.LOW.value
                    and not step.requires_security_review
                    and not step.requires_human_review
                ]

            plan = {
                "plan_id": generate_id("workflow_plan"),
                "workflow_id": workflow.workflow_id,
                "name": workflow.name,
                "workflow_type": workflow.workflow_type,
                "source_domain": workflow.source_domain,
                "start_url": workflow.start_url,
                "goal": workflow.goal,
                "status": workflow.status,
                "confidence": workflow.confidence,
                "risk_level": workflow.risk_level,
                "requires_security_review": workflow.requires_security_review,
                "requires_human_review": workflow.requires_human_review,
                "execution_allowed": False,
                "execution_note": (
                    "This is a learned workflow plan only. "
                    "Execution must be handled by approved Browser Agent tools "
                    "after Security Agent and human review where required."
                ),
                "steps": [self._step_to_safe_dict(step) for step in steps],
                "created_at": utc_now_iso(),
            }

            return self._safe_result(
                "Workflow plan exported successfully.",
                data={"workflow_plan": plan},
            )

        except Exception as exc:
            return self._handle_exception("Failed to export workflow plan.", exc)

    def snapshot(self, include_events: bool = True) -> Dict[str, Any]:
        """Export full safe learner snapshot."""
        try:
            data = {
                "schema_version": self.schema_version,
                "learner_id": self.learner_id,
                "module_name": self.module_name,
                "component_name": self.component_name,
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "task_id": self.task_id,
                "active_workflow_id": self.active_workflow_id,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "permissions": self.permissions.copy(),
                "metadata": safe_copy(self.metadata),
                "workflows": [
                    self._workflow_to_safe_dict(workflow)
                    for workflow in self.workflows.values()
                ],
            }

            if include_events:
                data["events"] = [self._event_to_safe_dict(event) for event in self.events]

            return self._safe_result(
                "Workflow learner snapshot prepared successfully.",
                data=data,
            )

        except Exception as exc:
            return self._handle_exception("Failed to prepare workflow learner snapshot.", exc)

    @classmethod
    def restore_from_snapshot(
        cls,
        snapshot_data: Dict[str, Any],
        event_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        security_callback: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    ) -> "BrowserWorkflowLearner":
        """
        Restore learner from safe snapshot.

        This method does not execute workflows.
        """
        if not isinstance(snapshot_data, dict):
            raise ValueError("snapshot_data must be a dictionary")

        user_id = str(snapshot_data.get("user_id") or "").strip()
        workspace_id = str(snapshot_data.get("workspace_id") or "").strip()

        if not user_id or not workspace_id:
            raise ValueError("snapshot_data requires user_id and workspace_id")

        learner = cls(
            user_id=user_id,
            workspace_id=workspace_id,
            task_id=snapshot_data.get("task_id"),
            permissions=snapshot_data.get("permissions"),
            event_callback=event_callback,
            audit_callback=audit_callback,
            security_callback=security_callback,
            metadata=snapshot_data.get("metadata") or {},
        )

        learner.learner_id = snapshot_data.get("learner_id") or generate_id("workflow_learner")
        learner.created_at = snapshot_data.get("created_at") or utc_now_iso()
        learner.updated_at = snapshot_data.get("updated_at") or utc_now_iso()
        learner.active_workflow_id = snapshot_data.get("active_workflow_id")

        learner.workflows = {}
        for raw_workflow in snapshot_data.get("workflows", []) or []:
            workflow = learner._workflow_from_dict(raw_workflow)
            learner.workflows[workflow.workflow_id] = workflow

        learner.events = []
        for raw_event in snapshot_data.get("events", []) or []:
            learner.events.append(
                WorkflowLearnerEvent(
                    event_id=raw_event.get("event_id") or generate_id("event"),
                    event_type=raw_event.get("event_type") or LearnerEventType.AUDIT_EVENT.value,
                    user_id=raw_event.get("user_id") or user_id,
                    workspace_id=raw_event.get("workspace_id") or workspace_id,
                    task_id=raw_event.get("task_id"),
                    workflow_id=raw_event.get("workflow_id"),
                    timestamp=raw_event.get("timestamp") or utc_now_iso(),
                    message=raw_event.get("message") or "",
                    data=raw_event.get("data") or {},
                    risk_level=raw_event.get("risk_level") or StepRiskLevel.LOW.value,
                )
            )

        learner._emit_agent_event(
            LearnerEventType.WORKFLOW_UPDATED.value,
            "Workflow learner restored from snapshot.",
            data={"learner_id": learner.learner_id},
        )

        return learner

    # -----------------------------------------------------------------------
    # Compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        user_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate SaaS user/workspace/task isolation."""
        actual_user_id = str(user_id or self.user_id or "").strip()
        actual_workspace_id = str(workspace_id or self.workspace_id or "").strip()

        if not actual_user_id:
            return self._error_result(
                "user_id is required.",
                error_code="MISSING_USER_ID",
            )

        if not actual_workspace_id:
            return self._error_result(
                "workspace_id is required.",
                error_code="MISSING_WORKSPACE_ID",
            )

        if actual_user_id != self.user_id:
            return self._error_result(
                "Cross-user workflow access denied.",
                error_code="CROSS_USER_ACCESS_DENIED",
                metadata={"requested_user_id": actual_user_id},
            )

        if actual_workspace_id != self.workspace_id:
            return self._error_result(
                "Cross-workspace workflow access denied.",
                error_code="CROSS_WORKSPACE_ACCESS_DENIED",
                metadata={"requested_workspace_id": actual_workspace_id},
            )

        if task_id is not None and not str(task_id).strip():
            return self._error_result(
                "task_id cannot be blank when provided.",
                error_code="INVALID_TASK_ID",
            )

        return self._safe_result(
            "Task context validated.",
            data={
                "user_id": self.user_id,
                "workspace_id": self.workspace_id,
                "task_id": task_id or self.task_id,
            },
        )

    def _requires_security_check(self, action: str) -> bool:
        """Return True when action requires Security Agent review."""
        protected_actions = {
            "mark_workflow_production_ready",
            "clear_workflow",
            "export_high_risk_workflow",
            "approve_high_risk_step",
        }

        return action in protected_actions

    def _request_security_approval(
        self,
        action: str,
        risk_level: str = StepRiskLevel.MEDIUM.value,
        workflow_id: Optional[str] = None,
        task_id: Optional[str] = None,
        reason: Optional[str] = None,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Request approval from Security Agent callback or local permission."""
        approval_payload = {
            "action": action,
            "risk_level": risk_level,
            "reason": reason,
            "module_name": self.module_name,
            "component_name": self.component_name,
            "learner_id": self.learner_id,
            "workflow_id": workflow_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": task_id or self.task_id,
            "payload": payload or {},
            "timestamp": utc_now_iso(),
        }

        self._emit_agent_event(
            LearnerEventType.SECURITY_APPROVAL_REQUESTED.value,
            "Security approval requested.",
            workflow_id=workflow_id,
            task_id=task_id or self.task_id,
            data=approval_payload,
            risk_level=risk_level,
        )

        if self.security_callback:
            try:
                approval = self.security_callback(approval_payload)
                if isinstance(approval, dict) and approval.get("success") is True:
                    return self._safe_result(
                        "Security approval granted.",
                        data={"approval": approval},
                    )

                return self._error_result(
                    "Security approval denied.",
                    error_code="SECURITY_APPROVAL_DENIED",
                    metadata={"approval": approval},
                )
            except Exception as exc:
                return self._handle_exception("Security callback failed.", exc)

        permission_key = f"can_{action}"
        if self.permissions.get(permission_key) is True:
            return self._safe_result(
                "Security approval granted by local permission.",
                data={"permission_key": permission_key},
            )

        return self._error_result(
            "Security approval required.",
            error_code="SECURITY_APPROVAL_REQUIRED",
            metadata={
                "action": action,
                "permission_key": permission_key,
                "risk_level": risk_level,
            },
        )

    def _prepare_verification_payload(
        self,
        workflow_id: Optional[str] = None,
        action: str = "workflow_learning_review",
        result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Prepare payload for Verification Agent."""
        workflow = self._get_workflow_or_active(workflow_id)

        payload = {
            "verification_type": "browser_workflow_learning",
            "action": action,
            "module_name": self.module_name,
            "component_name": self.component_name,
            "learner_id": self.learner_id,
            "workflow_id": workflow.workflow_id if workflow else workflow_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": workflow.task_id if workflow else self.task_id,
            "workflow": self._workflow_to_safe_dict(workflow) if workflow else None,
            "result": safe_copy(result) if result else None,
            "timestamp": utc_now_iso(),
        }

        self._emit_agent_event(
            LearnerEventType.VERIFICATION_PAYLOAD_PREPARED.value,
            "Verification payload prepared.",
            workflow_id=workflow.workflow_id if workflow else workflow_id,
            data={"action": action},
        )

        return payload

    def _prepare_memory_payload(
        self,
        workflow_id: Optional[str] = None,
        memory_type: str = "learned_browser_workflow",
    ) -> Dict[str, Any]:
        """Prepare safe payload for Memory Agent."""
        workflow = self._get_workflow_or_active(workflow_id)

        payload = {
            "memory_type": memory_type,
            "module_name": self.module_name,
            "component_name": self.component_name,
            "learner_id": self.learner_id,
            "workflow_id": workflow.workflow_id if workflow else workflow_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": workflow.task_id if workflow else self.task_id,
            "summary": self._workflow_memory_summary(workflow) if workflow else None,
            "timestamp": utc_now_iso(),
        }

        self._emit_agent_event(
            LearnerEventType.MEMORY_PAYLOAD_PREPARED.value,
            "Memory payload prepared.",
            workflow_id=workflow.workflow_id if workflow else workflow_id,
            data={"memory_type": memory_type},
        )

        return payload

    def _emit_agent_event(
        self,
        event_type: str,
        message: str,
        workflow_id: Optional[str] = None,
        task_id: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
        risk_level: str = StepRiskLevel.LOW.value,
    ) -> Dict[str, Any]:
        """Emit internal learner event for dashboard/Master Agent."""
        event = WorkflowLearnerEvent(
            event_id=generate_id("event"),
            event_type=event_type,
            user_id=self.user_id,
            workspace_id=self.workspace_id,
            task_id=task_id or self.task_id,
            workflow_id=workflow_id,
            timestamp=utc_now_iso(),
            message=message,
            data=data.copy() if isinstance(data, dict) else {},
            risk_level=risk_level,
        )

        self.events.append(event)
        self._trim_events()

        payload = self._event_to_safe_dict(event)

        if self.event_callback:
            try:
                self.event_callback(payload)
            except Exception:
                logger.exception("BrowserWorkflowLearner event_callback failed.")

        return self._safe_result(
            "Agent event emitted.",
            data={"event": payload},
        )

    def _log_audit_event(
        self,
        action: str,
        status: str,
        workflow_id: Optional[str] = None,
        task_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        risk_level: str = StepRiskLevel.LOW.value,
    ) -> Dict[str, Any]:
        """Log safe audit event."""
        audit_payload = {
            "audit_id": generate_id("audit"),
            "module_name": self.module_name,
            "component_name": self.component_name,
            "learner_id": self.learner_id,
            "workflow_id": workflow_id,
            "user_id": self.user_id,
            "workspace_id": self.workspace_id,
            "task_id": task_id or self.task_id,
            "action": action,
            "status": status,
            "risk_level": risk_level,
            "details": safe_copy(details) if details else {},
            "timestamp": utc_now_iso(),
        }

        self._emit_agent_event(
            LearnerEventType.AUDIT_EVENT.value,
            f"Audit event recorded for action: {action}",
            workflow_id=workflow_id,
            task_id=task_id,
            data=audit_payload,
            risk_level=risk_level,
        )

        if self.audit_callback:
            try:
                self.audit_callback(audit_payload)
            except Exception:
                logger.exception("BrowserWorkflowLearner audit_callback failed.")

        return self._safe_result(
            "Audit event logged.",
            data={"audit": audit_payload},
        )

    def _safe_result(
        self,
        message: str,
        data: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis success response."""
        return {
            "success": True,
            "message": message,
            "data": data or {},
            "error": None,
            "metadata": {
                "module_name": self.module_name,
                "component_name": self.component_name,
                "learner_id": getattr(self, "learner_id", None),
                "schema_version": self.schema_version,
                "timestamp": utc_now_iso(),
                **(metadata or {}),
            },
        }

    def _error_result(
        self,
        message: str,
        error_code: str = "WORKFLOW_LEARNER_ERROR",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Standard William/Jarvis error response."""
        return {
            "success": False,
            "message": message,
            "data": {},
            "error": {
                "code": error_code,
                "message": message,
            },
            "metadata": {
                "module_name": self.module_name,
                "component_name": self.component_name,
                "learner_id": getattr(self, "learner_id", None),
                "schema_version": self.schema_version,
                "timestamp": utc_now_iso(),
                **(metadata or {}),
            },
        }

    # -----------------------------------------------------------------------
    # Public compatibility exports
    # -----------------------------------------------------------------------

    def export_for_memory_agent(self, workflow_id: Optional[str] = None) -> Dict[str, Any]:
        """Public Memory Agent export wrapper."""
        permission = self._check_permission("can_prepare_memory_payload")
        if not permission["success"]:
            return permission

        payload = self._prepare_memory_payload(workflow_id=workflow_id)
        return self._safe_result(
            "Memory Agent payload prepared successfully.",
            data={"memory_payload": payload},
        )

    def export_for_verification_agent(
        self,
        workflow_id: Optional[str] = None,
        action: str = "workflow_learning_review",
        result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Public Verification Agent export wrapper."""
        permission = self._check_permission("can_prepare_verification_payload")
        if not permission["success"]:
            return permission

        payload = self._prepare_verification_payload(
            workflow_id=workflow_id,
            action=action,
            result=result,
        )
        return self._safe_result(
            "Verification Agent payload prepared successfully.",
            data={"verification_payload": payload},
        )

    def prepare_dashboard_payload(self) -> Dict[str, Any]:
        """Prepare compact Dashboard/API payload."""
        workflow_summaries = []

        for workflow in self.workflows.values():
            workflow_summaries.append(
                {
                    "workflow_id": workflow.workflow_id,
                    "name": workflow.name,
                    "workflow_type": workflow.workflow_type,
                    "status": workflow.status,
                    "source_domain": workflow.source_domain,
                    "steps_count": len(workflow.steps),
                    "observations_count": len(workflow.observations),
                    "confidence": workflow.confidence,
                    "risk_level": workflow.risk_level,
                    "requires_security_review": workflow.requires_security_review,
                    "requires_human_review": workflow.requires_human_review,
                    "updated_at": workflow.updated_at,
                }
            )

        workflow_summaries.sort(key=lambda item: item["updated_at"], reverse=True)

        return self._safe_result(
            "Dashboard payload prepared successfully.",
            data={
                "dashboard": {
                    "learner_id": self.learner_id,
                    "user_id": self.user_id,
                    "workspace_id": self.workspace_id,
                    "task_id": self.task_id,
                    "active_workflow_id": self.active_workflow_id,
                    "workflows_count": len(self.workflows),
                    "workflows": workflow_summaries,
                    "events_count": len(self.events),
                    "updated_at": self.updated_at,
                }
            },
        )

    # -----------------------------------------------------------------------
    # Internal analysis helpers
    # -----------------------------------------------------------------------

    def _check_permission(self, permission_key: str) -> Dict[str, Any]:
        """Check local permission map."""
        if self.permissions.get(permission_key) is True:
            return self._safe_result(
                "Permission granted.",
                data={"permission": permission_key},
            )

        return self._error_result(
            f"Permission denied: {permission_key}",
            error_code="PERMISSION_DENIED",
            metadata={"permission": permission_key},
        )

    def _validate_record_scope(self, user_id: str, workspace_id: str) -> Dict[str, Any]:
        """Validate stored record belongs to this user/workspace."""
        if user_id != self.user_id:
            return self._error_result(
                "Stored workflow record user scope mismatch.",
                error_code="RECORD_USER_SCOPE_MISMATCH",
            )

        if workspace_id != self.workspace_id:
            return self._error_result(
                "Stored workflow record workspace scope mismatch.",
                error_code="RECORD_WORKSPACE_SCOPE_MISMATCH",
            )

        return self._safe_result("Record scope validated.")

    def _get_workflow_or_active(self, workflow_id: Optional[str]) -> Optional[LearnedWorkflow]:
        """Return workflow by ID or active workflow."""
        actual_id = workflow_id or self.active_workflow_id
        if not actual_id:
            return None

        workflow = self.workflows.get(actual_id)
        if not workflow:
            return None

        if workflow.user_id != self.user_id or workflow.workspace_id != self.workspace_id:
            return None

        return workflow

    def _find_step(self, workflow: LearnedWorkflow, step_id: str) -> Optional[WorkflowStep]:
        """Find step by ID."""
        for step in workflow.steps:
            if step.step_id == step_id:
                return step
        return None

    def _validate_workflow_type(self, workflow_type: str) -> str:
        """Validate workflow type enum."""
        clean = str(workflow_type or WorkflowType.UNKNOWN.value).strip().lower()
        allowed = {item.value for item in WorkflowType}

        if clean not in allowed:
            return WorkflowType.UNKNOWN.value

        return clean

    def _validate_workflow_status(self, status: str) -> str:
        """Validate workflow status enum."""
        clean = str(status).strip().lower()
        allowed = {item.value for item in WorkflowStatus}

        if clean not in allowed:
            raise ValueError(f"Invalid workflow status: {status}")

        return clean

    def _validate_step_type(self, step_type: str) -> str:
        """Validate step type enum."""
        clean = str(step_type or StepType.UNKNOWN.value).strip().lower()
        allowed = {item.value for item in StepType}

        if clean not in allowed:
            return StepType.UNKNOWN.value

        return clean

    def _build_safe_element(self, element: Optional[Dict[str, Any]]) -> Optional[WorkflowStepElement]:
        """Build sanitized UI element descriptor."""
        if not isinstance(element, dict):
            return None

        raw_field_name = (
            element.get("field_name")
            or element.get("name")
            or element.get("label")
            or element.get("placeholder")
            or element.get("selector")
            or ""
        )

        is_sensitive = detect_sensitive_name(str(raw_field_name))

        return WorkflowStepElement(
            element_id=element.get("element_id") or generate_id("element"),
            tag=clean_text(element.get("tag"), max_length=60),
            selector=clean_text(element.get("selector"), max_length=300),
            xpath=clean_text(element.get("xpath"), max_length=500),
            role=clean_text(element.get("role"), max_length=80),
            label=clean_text(element.get("label"), max_length=160),
            placeholder=clean_text(element.get("placeholder"), max_length=160),
            text_hint=clean_text(element.get("text_hint") or element.get("text"), max_length=200),
            field_name_hash=safe_hash(str(raw_field_name)) if raw_field_name else None,
            is_sensitive_field=is_sensitive,
            metadata=self._sanitize_metadata(element.get("metadata") or {}),
        )

    def _sanitize_detected_items(
        self,
        items: Optional[List[Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """Sanitize detected DOM/page items."""
        if not isinstance(items, list):
            return []

        clean_items: List[Dict[str, Any]] = []

        for item in items:
            if not isinstance(item, dict):
                continue

            safe_item: Dict[str, Any] = {}

            for key, value in item.items():
                key_str = str(key)

                if key_str.lower() in {"value", "input_value", "password", "token", "cookie"}:
                    safe_item[f"{key_str}_hint"] = redact_input_value(str(value))
                    continue

                if detect_sensitive_name(key_str):
                    safe_item[f"{key_str}_hash"] = safe_hash(str(value))
                    continue

                if isinstance(value, str):
                    safe_item[key_str] = clean_text(value, max_length=300)
                elif isinstance(value, (int, float, bool)) or value is None:
                    safe_item[key_str] = value
                else:
                    safe_item[key_str] = clean_text(str(value), max_length=300)

            clean_items.append(safe_item)

        return clean_items[:200]

    def _sanitize_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize metadata dictionary."""
        if not isinstance(metadata, dict):
            return {}

        safe: Dict[str, Any] = {}

        for key, value in metadata.items():
            key_str = str(key)

            if detect_sensitive_name(key_str):
                safe[f"{key_str}_hash"] = safe_hash(str(value))
                continue

            if isinstance(value, str):
                safe[key_str] = clean_text(value, max_length=500)
            elif isinstance(value, (int, float, bool)) or value is None:
                safe[key_str] = value
            elif isinstance(value, list):
                safe[key_str] = [
                    clean_text(str(item), max_length=200)
                    for item in value[:50]
                ]
            elif isinstance(value, dict):
                safe[key_str] = {
                    str(inner_key): clean_text(str(inner_value), max_length=200)
                    for inner_key, inner_value in list(value.items())[:50]
                }
            else:
                safe[key_str] = clean_text(str(value), max_length=500)

        return safe

    def _analyze_step_risk(
        self,
        step_type: str,
        description: Optional[str],
        element: Optional[WorkflowStepElement],
        input_value: Optional[str],
        url: Optional[str],
    ) -> Dict[str, Any]:
        """Analyze risk for a workflow step."""
        text_blob = " ".join(
            [
                step_type or "",
                description or "",
                element.label if element else "",
                element.placeholder if element else "",
                element.text_hint if element else "",
                url or "",
            ]
        ).lower()

        risk_level = StepRiskLevel.LOW.value
        requires_security_review = False
        requires_human_review = False
        blocked_reason = None

        if any(keyword in text_blob for keyword in HIGH_RISK_ACTION_KEYWORDS):
            risk_level = StepRiskLevel.HIGH.value
            requires_security_review = True
            requires_human_review = True

        if step_type in {
            StepType.TYPE.value,
            StepType.UPLOAD.value,
            StepType.CLICK.value,
            StepType.SELECT.value,
        }:
            if risk_level == StepRiskLevel.LOW.value:
                risk_level = StepRiskLevel.MEDIUM.value
            requires_human_review = True

        if element and element.is_sensitive_field:
            risk_level = StepRiskLevel.HIGH.value
            requires_security_review = True
            requires_human_review = True

        if input_value and detect_sensitive_name(text_blob):
            risk_level = StepRiskLevel.HIGH.value
            requires_security_review = True
            requires_human_review = True

        if "captcha" in text_blob or "recaptcha" in text_blob or "hcaptcha" in text_blob:
            risk_level = StepRiskLevel.BLOCKED.value
            requires_security_review = True
            requires_human_review = True
            blocked_reason = "CAPTCHA or anti-bot challenge detected. Human handling required."

        if "payment" in text_blob or "card" in text_blob or "checkout" in text_blob:
            risk_level = StepRiskLevel.HIGH.value
            requires_security_review = True
            requires_human_review = True

        return {
            "risk_level": risk_level,
            "requires_security_review": requires_security_review,
            "requires_human_review": requires_human_review,
            "blocked_reason": blocked_reason,
        }

    def _analyze_workflow_risk(self, workflow: LearnedWorkflow) -> Dict[str, Any]:
        """Analyze overall workflow risk."""
        risk_order = {
            StepRiskLevel.LOW.value: 1,
            StepRiskLevel.MEDIUM.value: 2,
            StepRiskLevel.HIGH.value: 3,
            StepRiskLevel.BLOCKED.value: 4,
        }

        workflow_text = " ".join(
            [
                workflow.name or "",
                workflow.workflow_type or "",
                workflow.goal or "",
                workflow.start_url or "",
            ]
        ).lower()

        risk_level = StepRiskLevel.LOW.value
        requires_security_review = False
        requires_human_review = False
        blocked_reasons: List[str] = []

        if workflow.workflow_type in {
            WorkflowType.LOGIN.value,
            WorkflowType.SIGNUP.value,
            WorkflowType.CHECKOUT.value,
            WorkflowType.SUBSCRIPTION.value,
        }:
            risk_level = StepRiskLevel.HIGH.value
            requires_security_review = True
            requires_human_review = True

        if any(keyword in workflow_text for keyword in HIGH_RISK_ACTION_KEYWORDS):
            risk_level = StepRiskLevel.HIGH.value
            requires_security_review = True
            requires_human_review = True

        for step in workflow.steps:
            if risk_order.get(step.risk_level, 1) > risk_order.get(risk_level, 1):
                risk_level = step.risk_level

            if step.requires_security_review:
                requires_security_review = True

            if step.requires_human_review:
                requires_human_review = True

            if step.blocked_reason:
                blocked_reasons.append(step.blocked_reason)

        if risk_level == StepRiskLevel.BLOCKED.value:
            requires_security_review = True
            requires_human_review = True

        return {
            "workflow_id": workflow.workflow_id,
            "risk_level": risk_level,
            "requires_security_review": requires_security_review,
            "requires_human_review": requires_human_review,
            "blocked_reasons": blocked_reasons,
            "steps_count": len(workflow.steps),
            "high_risk_steps": [
                step.step_id
                for step in workflow.steps
                if step.risk_level in {StepRiskLevel.HIGH.value, StepRiskLevel.BLOCKED.value}
            ],
        }

    def _calculate_workflow_confidence(self, workflow: LearnedWorkflow) -> float:
        """Calculate workflow confidence based on step coverage."""
        if not workflow.steps:
            return 0.0

        step_scores = [clamp_confidence(step.confidence) for step in workflow.steps]
        average_score = sum(step_scores) / len(step_scores)

        observation_bonus = min(0.15, len(workflow.observations) * 0.01)
        length_bonus = min(0.10, len(workflow.steps) * 0.01)

        penalty = 0.0
        if workflow.requires_security_review:
            penalty += 0.10
        if workflow.requires_human_review:
            penalty += 0.05

        return max(0.0, min(1.0, average_score + observation_bonus + length_bonus - penalty))

    def _suggest_steps_from_observation(
        self,
        workflow: LearnedWorkflow,
        observation: WorkflowObservation,
    ) -> List[Dict[str, Any]]:
        """Generate safe suggested steps from page observation."""
        suggestions: List[Dict[str, Any]] = []

        suggestions.append(
            {
                "step_type": StepType.OBSERVE_PAGE.value,
                "description": f"Observe page state for {observation.page_title or observation.domain or 'current page'}.",
                "url": observation.url,
                "page_title": observation.page_title,
                "expected_result": "Page loads and expected content is visible.",
                "risk_level": StepRiskLevel.LOW.value,
                "confidence": 0.65,
            }
        )

        for form in observation.detected_forms[:10]:
            form_text = " ".join(str(value) for value in form.values()).lower()
            is_sensitive = detect_sensitive_name(form_text)

            suggestions.append(
                {
                    "step_type": StepType.HUMAN_REVIEW.value if is_sensitive else StepType.ASSERT.value,
                    "description": (
                        "Review sensitive form fields before any automation."
                        if is_sensitive
                        else "Verify detected form exists on page."
                    ),
                    "url": observation.url,
                    "page_title": observation.page_title,
                    "element": form,
                    "expected_result": "Form is visible and ready for human-approved handling.",
                    "risk_level": StepRiskLevel.HIGH.value if is_sensitive else StepRiskLevel.LOW.value,
                    "confidence": 0.60,
                }
            )

        for button in observation.detected_buttons[:20]:
            text = str(button.get("text") or button.get("label") or button).lower()
            risk = StepRiskLevel.HIGH.value if any(k in text for k in HIGH_RISK_ACTION_KEYWORDS) else StepRiskLevel.MEDIUM.value

            suggestions.append(
                {
                    "step_type": StepType.HUMAN_REVIEW.value if risk == StepRiskLevel.HIGH.value else StepType.ASSERT.value,
                    "description": (
                        f"Review button before interaction: {clean_text(text, 120)}"
                        if risk == StepRiskLevel.HIGH.value
                        else f"Verify button exists: {clean_text(text, 120)}"
                    ),
                    "url": observation.url,
                    "page_title": observation.page_title,
                    "element": button,
                    "expected_result": "Button is present and reviewed before interaction.",
                    "risk_level": risk,
                    "confidence": 0.55,
                }
            )

        warnings_text = " ".join(observation.detected_warnings).lower()
        if "captcha" in warnings_text or "recaptcha" in warnings_text or "hcaptcha" in warnings_text:
            suggestions.append(
                {
                    "step_type": StepType.CAPTCHA_DETECTED.value,
                    "description": "CAPTCHA detected. Stop automation and require human review.",
                    "url": observation.url,
                    "page_title": observation.page_title,
                    "expected_result": "Human handles CAPTCHA manually.",
                    "risk_level": StepRiskLevel.BLOCKED.value,
                    "confidence": 0.90,
                }
            )

        return suggestions

    # -----------------------------------------------------------------------
    # Serialization helpers
    # -----------------------------------------------------------------------

    def _workflow_to_safe_dict(
        self,
        workflow: Optional[LearnedWorkflow],
        include_observations: bool = True,
    ) -> Optional[Dict[str, Any]]:
        """Convert workflow to safe dictionary."""
        if workflow is None:
            return None

        data = asdict(workflow)
        data["steps"] = [self._step_to_safe_dict(step) for step in workflow.steps]

        if include_observations:
            data["observations"] = [
                self._observation_to_safe_dict(observation)
                for observation in workflow.observations
            ]
        else:
            data["observations"] = []

        return data

    def _step_to_safe_dict(self, step: WorkflowStep) -> Dict[str, Any]:
        """Convert step to safe dictionary."""
        data = asdict(step)

        if step.element:
            data["element"] = asdict(step.element)

        return data

    def _observation_to_safe_dict(self, observation: WorkflowObservation) -> Dict[str, Any]:
        """Convert observation to safe dictionary."""
        return asdict(observation)

    def _event_to_safe_dict(self, event: WorkflowLearnerEvent) -> Dict[str, Any]:
        """Convert event to safe dictionary."""
        return asdict(event)

    def _workflow_memory_summary(self, workflow: Optional[LearnedWorkflow]) -> Optional[Dict[str, Any]]:
        """Create compact memory summary."""
        if not workflow:
            return None

        return {
            "workflow_id": workflow.workflow_id,
            "name": workflow.name,
            "workflow_type": workflow.workflow_type,
            "source_domain": workflow.source_domain,
            "goal": workflow.goal,
            "status": workflow.status,
            "steps_count": len(workflow.steps),
            "observations_count": len(workflow.observations),
            "confidence": workflow.confidence,
            "risk_level": workflow.risk_level,
            "requires_security_review": workflow.requires_security_review,
            "requires_human_review": workflow.requires_human_review,
            "step_summaries": [
                {
                    "step_index": step.step_index,
                    "step_type": step.step_type,
                    "description": step.description,
                    "risk_level": step.risk_level,
                    "confidence": step.confidence,
                }
                for step in workflow.steps[:50]
            ],
            "updated_at": workflow.updated_at,
        }

    def _workflow_from_dict(self, raw: Dict[str, Any]) -> LearnedWorkflow:
        """Restore workflow from dictionary."""
        steps = []
        for raw_step in raw.get("steps", []) or []:
            raw_element = raw_step.get("element")
            element = None

            if isinstance(raw_element, dict):
                element = WorkflowStepElement(
                    element_id=raw_element.get("element_id") or generate_id("element"),
                    tag=raw_element.get("tag"),
                    selector=raw_element.get("selector"),
                    xpath=raw_element.get("xpath"),
                    role=raw_element.get("role"),
                    label=raw_element.get("label"),
                    placeholder=raw_element.get("placeholder"),
                    text_hint=raw_element.get("text_hint"),
                    field_name_hash=raw_element.get("field_name_hash"),
                    is_sensitive_field=bool(raw_element.get("is_sensitive_field")),
                    metadata=raw_element.get("metadata") or {},
                )

            steps.append(
                WorkflowStep(
                    step_id=raw_step.get("step_id") or generate_id("workflow_step"),
                    workflow_id=raw_step.get("workflow_id") or raw.get("workflow_id"),
                    step_index=int(raw_step.get("step_index") or len(steps) + 1),
                    user_id=raw_step.get("user_id") or self.user_id,
                    workspace_id=raw_step.get("workspace_id") or self.workspace_id,
                    task_id=raw_step.get("task_id"),
                    step_type=raw_step.get("step_type") or StepType.UNKNOWN.value,
                    description=raw_step.get("description") or "",
                    url=raw_step.get("url"),
                    domain=raw_step.get("domain"),
                    page_title=raw_step.get("page_title"),
                    element=element,
                    input_value_hint=raw_step.get("input_value_hint"),
                    expected_result=raw_step.get("expected_result"),
                    risk_level=raw_step.get("risk_level") or StepRiskLevel.LOW.value,
                    requires_security_review=bool(raw_step.get("requires_security_review")),
                    requires_human_review=bool(raw_step.get("requires_human_review")),
                    blocked_reason=raw_step.get("blocked_reason"),
                    confidence=float(raw_step.get("confidence") or 0.0),
                    created_at=raw_step.get("created_at") or utc_now_iso(),
                    updated_at=raw_step.get("updated_at") or utc_now_iso(),
                    metadata=raw_step.get("metadata") or {},
                )
            )

        observations: List[WorkflowObservation] = []
        for raw_observation in raw.get("observations", []) or []:
            if not isinstance(raw_observation, dict):
                continue

            observations.append(
                WorkflowObservation(
                    observation_id=raw_observation.get("observation_id") or generate_id("workflow_observation"),
                    workflow_id=raw_observation.get("workflow_id") or raw.get("workflow_id") or generate_id("workflow"),
                    user_id=raw_observation.get("user_id") or self.user_id,
                    workspace_id=raw_observation.get("workspace_id") or self.workspace_id,
                    task_id=raw_observation.get("task_id"),
                    url=raw_observation.get("url"),
                    domain=raw_observation.get("domain"),
                    page_title=raw_observation.get("page_title"),
                    visible_text_summary=raw_observation.get("visible_text_summary"),
                    detected_elements=raw_observation.get("detected_elements") or [],
                    detected_forms=raw_observation.get("detected_forms") or [],
                    detected_buttons=raw_observation.get("detected_buttons") or [],
                    detected_links=raw_observation.get("detected_links") or [],
                    detected_warnings=raw_observation.get("detected_warnings") or [],
                    timestamp=raw_observation.get("timestamp") or utc_now_iso(),
                    metadata=raw_observation.get("metadata") or {},
                )
            )

        workflow_id = raw.get("workflow_id") or generate_id("workflow")
        for step in steps:
            if not step.workflow_id:
                step.workflow_id = workflow_id
        for observation in observations:
            if not observation.workflow_id:
                observation.workflow_id = workflow_id

        return LearnedWorkflow(
            workflow_id=workflow_id,
            user_id=raw.get("user_id") or self.user_id,
            workspace_id=raw.get("workspace_id") or self.workspace_id,
            task_id=raw.get("task_id"),
            name=raw.get("name") or "Restored Workflow",
            workflow_type=raw.get("workflow_type") or WorkflowType.UNKNOWN.value,
            status=raw.get("status") or WorkflowStatus.DRAFT.value,
            source_domain=raw.get("source_domain"),
            start_url=raw.get("start_url"),
            goal=raw.get("goal"),
            steps=steps,
            observations=observations,
            confidence=float(raw.get("confidence") or 0.0),
            risk_level=raw.get("risk_level") or StepRiskLevel.LOW.value,
            requires_security_review=bool(raw.get("requires_security_review")),
            requires_human_review=bool(raw.get("requires_human_review")),
            created_at=raw.get("created_at") or utc_now_iso(),
            updated_at=raw.get("updated_at") or utc_now_iso(),
            verified_at=raw.get("verified_at"),
            archived_at=raw.get("archived_at"),
            metadata=raw.get("metadata") or {},
        )

    def _trim_events(self) -> None:
        """Keep retained events within configured limit."""
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]

    def _trim_observations(self, workflow: LearnedWorkflow) -> None:
        """Keep observations within configured per-workflow/global safety limits."""
        if len(workflow.observations) > self.max_observations:
            workflow.observations = workflow.observations[-self.max_observations:]

    def _handle_exception(self, message: str, exc: Exception) -> Dict[str, Any]:
        """Convert unexpected exceptions to William/Jarvis structured errors."""
        logger.exception("%s %s", message, exc)
        self._emit_agent_event(
            LearnerEventType.ERROR.value,
            message,
            data={"exception": exc.__class__.__name__, "error": str(exc)},
            risk_level=StepRiskLevel.MEDIUM.value,
        )
        return self._error_result(
            message,
            error_code="WORKFLOW_LEARNER_EXCEPTION",
            metadata={
                "exception": exc.__class__.__name__,
                "details": str(exc),
            },
        )


__all__ = [
    "BrowserWorkflowLearner",
    "WorkflowType",
    "WorkflowStatus",
    "StepType",
    "StepRiskLevel",
    "LearnerEventType",
    "WorkflowStepElement",
    "WorkflowStep",
    "WorkflowObservation",
    "LearnedWorkflow",
    "WorkflowLearnerEvent",
    "utc_now_iso",
    "generate_id",
    "safe_hash",
    "normalize_url",
    "extract_domain",
]
