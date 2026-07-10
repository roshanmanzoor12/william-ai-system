"""
William / Jarvis All-File Prompt Bible - Digital Promotix
Use one prompt per file. Safety > SaaS isolation > BaseAgent compatibility > MasterAgent routing > file-specific features.

File: agents/workflow_agent/workflow_agent.py
Agent/Module: Workflow Agent
Purpose:
    Automation pipeline brain for n8n, triggers, webhooks, Form->Sheet->WhatsApp->CRM,
    conditions, monitoring, approvals, retry-safe planning, and workflow orchestration.

What this file does:
    - Provides the main WorkflowAgent class for William/Jarvis.
    - Accepts workflow tasks from Master Agent / API / dashboard.
    - Validates user_id and workspace_id for SaaS isolation.
    - Detects sensitive workflow actions and routes them through security approval hooks.
    - Builds safe workflow plans for form pipelines, webhooks, n8n workflows, CRM/sheet/WhatsApp/email flows.
    - Supports dry-run execution by default.
    - Exposes monitoring, trigger handling, webhook handling, workflow template listing, and workflow status APIs.
    - Prepares Verification Agent payloads after each workflow action.
    - Prepares Memory Agent payloads for useful workflow context.
    - Emits audit/event records using safe fallback methods.
    - Is import-safe even if future William/Jarvis modules are not created yet.

Where to place it:
    agents/workflow_agent/workflow_agent.py

Required dependencies:
    Python 3.10+
    Standard library only for this file.

Optional future dependencies:
    httpx or aiohttp for real n8n/API calls.
    pydantic for strict request schemas.
    celery/rq/arq for async workflow execution.
    redis/postgres for persistent workflow state.
    FastAPI for dashboard/API integration.

How to test it:
    python -m py_compile agents/workflow_agent/workflow_agent.py

    Example quick test:
        from agents.workflow_agent.workflow_agent import WorkflowAgent

        agent = WorkflowAgent()
        result = agent.run({
            "user_id": "user_123",
            "workspace_id": "workspace_123",
            "task_type": "build_form_pipeline",
            "payload": {
                "form_name": "Lead Form",
                "source": "website",
                "fields": ["full_name", "phone", "email", "service"],
                "destinations": ["sheet", "whatsapp", "crm"],
                "dry_run": True
            }
        })
        print(result)

Agent/module completion percentage after this file:
    4.8%

Next file to generate:
    agents/workflow_agent/n8n_connector.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple, Union


# =============================================================================
# Safe optional imports / fallback stubs
# =============================================================================

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent stub.

        This keeps workflow_agent.py import-safe while the wider William/Jarvis
        project is still being generated. In production, the real BaseAgent
        should provide shared logging, registry, permissions, event bus, memory,
        verification, and router compatibility.
        """

        agent_name: str = "base_agent"
        agent_type: str = "generic"

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.logger = logging.getLogger(self.__class__.__name__)

        def run(self, task: Mapping[str, Any], **kwargs: Any) -> Dict[str, Any]:
            raise NotImplementedError("Fallback BaseAgent.run is not implemented.")


try:
    from agents.security_agent.security_agent import SecurityAgent  # type: ignore
except Exception:  # pragma: no cover
    class SecurityAgent:  # type: ignore
        """
        Fallback SecurityAgent stub.

        Production Security Agent should perform:
        - permission checks
        - policy checks
        - sensitive action approval
        - data exfiltration protection
        - destructive action protection
        """

        def check_permission(self, request: Mapping[str, Any]) -> Dict[str, Any]:
            return {
                "success": True,
                "approved": True,
                "message": "Fallback security approval granted for dry-run/import-safe mode.",
                "data": {"fallback": True},
                "error": None,
                "metadata": {},
            }


try:
    from agents.verification_agent.verification_agent import VerificationAgent  # type: ignore
except Exception:  # pragma: no cover
    class VerificationAgent:  # type: ignore
        """
        Fallback VerificationAgent stub.

        Production Verification Agent should validate completed workflow actions,
        screenshots, external side effects, API responses, and dashboard state.
        """

        def prepare_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
            return dict(payload)


try:
    from agents.memory_agent.memory_agent import MemoryAgent  # type: ignore
except Exception:  # pragma: no cover
    class MemoryAgent:  # type: ignore
        """
        Fallback MemoryAgent stub.

        Production Memory Agent should persist useful per-user/per-workspace
        workflow preferences, safe reusable patterns, connector settings, and
        task outcomes without mixing workspace/user data.
        """

        def prepare_payload(self, payload: Mapping[str, Any]) -> Dict[str, Any]:
            return dict(payload)


# =============================================================================
# Logging
# =============================================================================

LOGGER = logging.getLogger("William.WorkflowAgent")
if not LOGGER.handlers:
    logging.basicConfig(level=logging.INFO)


# =============================================================================
# Enums and constants
# =============================================================================

class WorkflowTaskType(str, Enum):
    """Supported public task types for WorkflowAgent."""

    BUILD_WORKFLOW = "build_workflow"
    BUILD_N8N_WORKFLOW = "build_n8n_workflow"
    BUILD_FORM_PIPELINE = "build_form_pipeline"
    HANDLE_TRIGGER = "handle_trigger"
    HANDLE_WEBHOOK = "handle_webhook"
    RUN_WORKFLOW = "run_workflow"
    DRY_RUN_WORKFLOW = "dry_run_workflow"
    VALIDATE_WORKFLOW = "validate_workflow"
    MONITOR_WORKFLOW = "monitor_workflow"
    GET_WORKFLOW_STATUS = "get_workflow_status"
    LIST_TEMPLATES = "list_templates"
    APPLY_TEMPLATE = "apply_template"
    PAUSE_WORKFLOW = "pause_workflow"
    RESUME_WORKFLOW = "resume_workflow"
    DISABLE_WORKFLOW = "disable_workflow"


class WorkflowStatus(str, Enum):
    """Workflow lifecycle states."""

    DRAFT = "draft"
    READY = "ready"
    WAITING_APPROVAL = "waiting_approval"
    ACTIVE = "active"
    PAUSED = "paused"
    DISABLED = "disabled"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class WorkflowStepType(str, Enum):
    """Supported workflow step categories."""

    TRIGGER = "trigger"
    CONDITION = "condition"
    ACTION = "action"
    TRANSFORM = "transform"
    ROUTER = "router"
    APPROVAL = "approval"
    MONITOR = "monitor"
    RETRY = "retry"


class ConnectorName(str, Enum):
    """Known connector names for workflow planning."""

    N8N = "n8n"
    WEBHOOK = "webhook"
    FORM = "form"
    SHEET = "sheet"
    WHATSAPP = "whatsapp"
    CRM = "crm"
    EMAIL = "email"
    NOTIFICATION = "notification"
    SCHEDULER = "scheduler"
    INTERNAL = "internal"


class RiskLevel(str, Enum):
    """Risk score categories for workflow tasks/actions."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SENSITIVE_ACTION_KEYWORDS = {
    "send_whatsapp",
    "send_sms",
    "send_email",
    "send_message",
    "call",
    "delete",
    "archive",
    "charge",
    "payment",
    "refund",
    "browser_action",
    "external_post",
    "webhook_outbound",
    "crm_write",
    "sheet_write",
    "publish",
    "public_post",
    "financial_action",
    "destructive_action",
}

DEFAULT_ALLOWED_TASK_TYPES = {item.value for item in WorkflowTaskType}

DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_MAX_RETRIES = 3
DEFAULT_RETRY_BACKOFF_SECONDS = 2.0
DEFAULT_MONITOR_WINDOW_SECONDS = 300


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class WorkflowContext:
    """
    SaaS isolation context.

    Every user-specific workflow operation must include user_id and workspace_id.
    Never mix workflow state, logs, memory, events, or audit records between
    users/workspaces.
    """

    user_id: str
    workspace_id: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    actor_id: Optional[str] = None
    role: Optional[str] = None
    source: str = "workflow_agent"
    session_id: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowStep:
    """One workflow step in a safe execution plan."""

    step_id: str
    name: str
    step_type: str
    connector: str
    operation: str
    input_map: Dict[str, Any] = field(default_factory=dict)
    output_map: Dict[str, Any] = field(default_factory=dict)
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    requires_approval: bool = False
    risk_level: str = RiskLevel.LOW.value
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    max_retries: int = DEFAULT_MAX_RETRIES
    retry_backoff_seconds: float = DEFAULT_RETRY_BACKOFF_SECONDS
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowPlan:
    """Structured workflow plan generated by WorkflowAgent."""

    workflow_id: str
    name: str
    description: str
    status: str
    steps: List[WorkflowStep]
    triggers: List[Dict[str, Any]] = field(default_factory=list)
    conditions: List[Dict[str, Any]] = field(default_factory=list)
    connectors: List[str] = field(default_factory=list)
    requires_approval: bool = False
    risk_level: str = RiskLevel.LOW.value
    dry_run: bool = True
    version: str = "1.0.0"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["steps"] = [step.to_dict() for step in self.steps]
        return data


@dataclass
class WorkflowExecutionRecord:
    """Execution/monitoring record for a workflow run."""

    execution_id: str
    workflow_id: str
    status: str
    started_at: str
    finished_at: Optional[str] = None
    step_results: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# =============================================================================
# Utility helpers
# =============================================================================

def _utc_now() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()


def _safe_json_dumps(value: Any) -> str:
    """Safely JSON serialize any value for hashing/logging."""
    try:
        return json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    except Exception:
        return str(value)


def _hash_payload(value: Any) -> str:
    """Create stable hash for workflow/task payloads."""
    raw = _safe_json_dumps(value)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _coerce_dict(value: Any) -> Dict[str, Any]:
    """Convert mapping-like values to dict safely."""
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, Mapping):
        return dict(value)
    return {"value": value}


def _as_list(value: Any) -> List[Any]:
    """Safely convert value to list."""
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, set):
        return list(value)
    return [value]


def _normalize_string(value: Any, default: str = "") -> str:
    """Normalize value to stripped string."""
    if value is None:
        return default
    return str(value).strip()


def _make_id(prefix: str) -> str:
    """Create readable unique IDs."""
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


# =============================================================================
# WorkflowAgent
# =============================================================================

class WorkflowAgent(BaseAgent):
    """
    Automation pipeline brain for William/Jarvis.

    Responsibilities:
        - Build workflow plans for automation pipelines.
        - Coordinate n8n/webhook/form/sheet/WhatsApp/CRM/email style flows.
        - Handle triggers and webhooks safely.
        - Detect sensitive actions and route approval through Security Agent.
        - Prepare verification payloads for completed tasks.
        - Prepare memory payloads for reusable workflow context.
        - Emit structured events and audit logs.
        - Stay compatible with Master Agent, Agent Registry, Agent Router,
          dashboard/API, and future module files.

    This file does not perform real external actions by default.
    Real connector behavior should be implemented in future files:
        - n8n_connector.py
        - workflow_builder.py
        - trigger_engine.py
        - action_router.py
        - app_connector.py
        - webhook_manager.py
        - form_pipeline.py
        - crm_connector.py
        - sheet_connector.py
        - whatsapp_connector.py
        - email_connector.py
        - notification_engine.py
        - condition_engine.py
        - scheduler.py
        - workflow_monitor.py
        - retry_handler.py
        - workflow_templates.py
        - workflow_memory.py
        - approval_gate.py
        - config.py
    """

    agent_name = "workflow_agent"
    agent_type = "workflow"
    public_methods = [
        "run",
        "build_workflow",
        "build_n8n_workflow",
        "build_form_pipeline",
        "handle_trigger",
        "handle_webhook",
        "run_workflow",
        "validate_workflow",
        "monitor_workflow",
        "get_workflow_status",
        "list_templates",
        "apply_template",
        "pause_workflow",
        "resume_workflow",
        "disable_workflow",
    ]

    def __init__(
        self,
        security_agent: Optional[Any] = None,
        verification_agent: Optional[Any] = None,
        memory_agent: Optional[Any] = None,
        event_emitter: Optional[Callable[[Dict[str, Any]], None]] = None,
        audit_logger: Optional[Callable[[Dict[str, Any]], None]] = None,
        config: Optional[Mapping[str, Any]] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize WorkflowAgent.

        Args:
            security_agent:
                Optional Security Agent instance.
            verification_agent:
                Optional Verification Agent instance.
            memory_agent:
                Optional Memory Agent instance.
            event_emitter:
                Optional callable used by dashboard/API/event bus.
            audit_logger:
                Optional callable used by central audit log system.
            config:
                Optional configuration mapping.
            **kwargs:
                Additional args for BaseAgent compatibility.
        """
        try:
            super().__init__(**kwargs)
        except TypeError:
            super().__init__()

        self.logger = getattr(self, "logger", LOGGER)
        self.security_agent = security_agent or SecurityAgent()
        self.verification_agent = verification_agent or VerificationAgent()
        self.memory_agent = memory_agent or MemoryAgent()
        self.event_emitter = event_emitter
        self.audit_logger = audit_logger
        self.config = self._load_default_config(config)

        self._workflow_store: Dict[str, Dict[str, Any]] = {}
        self._execution_store: Dict[str, Dict[str, Any]] = {}
        self._template_store: Dict[str, Dict[str, Any]] = self._load_builtin_templates()

    # -------------------------------------------------------------------------
    # Main router
    # -------------------------------------------------------------------------

    def run(self, task: Mapping[str, Any], **kwargs: Any) -> Dict[str, Any]:
        """
        Master Agent / Router entrypoint.

        Expected task format:
            {
                "user_id": "user_123",
                "workspace_id": "workspace_123",
                "task_type": "build_form_pipeline",
                "payload": {...},
                "metadata": {...}
            }

        Returns:
            Structured result dict:
            {
                "success": bool,
                "message": str,
                "data": dict,
                "error": dict | None,
                "metadata": dict
            }
        """
        started_at = _utc_now()
        task_dict = _coerce_dict(task)

        context_result = self._validate_task_context(task_dict)
        if not context_result["success"]:
            return context_result

        context = context_result["data"]["context"]
        task_type = _normalize_string(task_dict.get("task_type") or task_dict.get("type"))
        payload = _coerce_dict(task_dict.get("payload"))

        if not task_type:
            return self._error_result(
                message="Missing task_type for WorkflowAgent.",
                code="missing_task_type",
                context=context,
                metadata={"started_at": started_at},
            )

        if task_type not in DEFAULT_ALLOWED_TASK_TYPES:
            return self._error_result(
                message=f"Unsupported WorkflowAgent task_type: {task_type}",
                code="unsupported_task_type",
                context=context,
                metadata={
                    "supported_task_types": sorted(DEFAULT_ALLOWED_TASK_TYPES),
                    "started_at": started_at,
                },
            )

        self._emit_agent_event(
            event_type="workflow.task.received",
            context=context,
            data={
                "task_type": task_type,
                "payload_hash": _hash_payload(payload),
            },
        )

        self._log_audit_event(
            action="workflow_task_received",
            context=context,
            data={
                "task_type": task_type,
                "payload_hash": _hash_payload(payload),
            },
        )

        try:
            if task_type == WorkflowTaskType.BUILD_WORKFLOW.value:
                result = self.build_workflow(context=context, payload=payload)
            elif task_type == WorkflowTaskType.BUILD_N8N_WORKFLOW.value:
                result = self.build_n8n_workflow(context=context, payload=payload)
            elif task_type == WorkflowTaskType.BUILD_FORM_PIPELINE.value:
                result = self.build_form_pipeline(context=context, payload=payload)
            elif task_type == WorkflowTaskType.HANDLE_TRIGGER.value:
                result = self.handle_trigger(context=context, payload=payload)
            elif task_type == WorkflowTaskType.HANDLE_WEBHOOK.value:
                result = self.handle_webhook(context=context, payload=payload)
            elif task_type == WorkflowTaskType.RUN_WORKFLOW.value:
                result = self.run_workflow(context=context, payload=payload, dry_run=False)
            elif task_type == WorkflowTaskType.DRY_RUN_WORKFLOW.value:
                result = self.run_workflow(context=context, payload=payload, dry_run=True)
            elif task_type == WorkflowTaskType.VALIDATE_WORKFLOW.value:
                result = self.validate_workflow(context=context, payload=payload)
            elif task_type == WorkflowTaskType.MONITOR_WORKFLOW.value:
                result = self.monitor_workflow(context=context, payload=payload)
            elif task_type == WorkflowTaskType.GET_WORKFLOW_STATUS.value:
                result = self.get_workflow_status(context=context, payload=payload)
            elif task_type == WorkflowTaskType.LIST_TEMPLATES.value:
                result = self.list_templates(context=context, payload=payload)
            elif task_type == WorkflowTaskType.APPLY_TEMPLATE.value:
                result = self.apply_template(context=context, payload=payload)
            elif task_type == WorkflowTaskType.PAUSE_WORKFLOW.value:
                result = self.pause_workflow(context=context, payload=payload)
            elif task_type == WorkflowTaskType.RESUME_WORKFLOW.value:
                result = self.resume_workflow(context=context, payload=payload)
            elif task_type == WorkflowTaskType.DISABLE_WORKFLOW.value:
                result = self.disable_workflow(context=context, payload=payload)
            else:
                result = self._error_result(
                    message=f"Task type routed but not implemented: {task_type}",
                    code="task_not_implemented",
                    context=context,
                )

            result.setdefault("metadata", {})
            result["metadata"].update(
                {
                    "agent": self.agent_name,
                    "task_type": task_type,
                    "request_id": context.request_id,
                    "started_at": started_at,
                    "finished_at": _utc_now(),
                }
            )

            self._emit_agent_event(
                event_type="workflow.task.completed" if result.get("success") else "workflow.task.failed",
                context=context,
                data={
                    "task_type": task_type,
                    "success": result.get("success"),
                    "message": result.get("message"),
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("WorkflowAgent task failed unexpectedly.")
            return self._error_result(
                message="WorkflowAgent encountered an unexpected error.",
                code="workflow_agent_exception",
                context=context,
                error_details={"exception": str(exc), "type": exc.__class__.__name__},
                metadata={"started_at": started_at, "finished_at": _utc_now()},
            )

    # -------------------------------------------------------------------------
    # Public workflow methods
    # -------------------------------------------------------------------------

    def build_workflow(self, context: WorkflowContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Build a generic workflow plan.

        This is the central planner used by Master Agent and API routes.
        """
        payload_dict = _coerce_dict(payload)
        name = _normalize_string(payload_dict.get("name"), default="Untitled Workflow")
        description = _normalize_string(
            payload_dict.get("description"),
            default="Automation workflow generated by WorkflowAgent.",
        )
        requested_steps = _as_list(payload_dict.get("steps"))
        requested_triggers = _as_list(payload_dict.get("triggers"))
        dry_run = bool(payload_dict.get("dry_run", True))

        if not requested_steps:
            requested_steps = self._infer_steps_from_payload(payload_dict)

        steps = [self._normalize_step(step, index=i) for i, step in enumerate(requested_steps)]
        connectors = sorted({step.connector for step in steps if step.connector})
        risk_level = self._calculate_workflow_risk(steps=steps, payload=payload_dict)
        requires_approval = any(step.requires_approval for step in steps) or self._requires_security_check(
            action="build_workflow",
            payload=payload_dict,
            risk_level=risk_level,
        )

        plan = WorkflowPlan(
            workflow_id=_make_id("wf"),
            name=name,
            description=description,
            status=WorkflowStatus.WAITING_APPROVAL.value if requires_approval and not dry_run else WorkflowStatus.DRAFT.value,
            steps=steps,
            triggers=[_coerce_dict(item) for item in requested_triggers],
            conditions=_as_list(payload_dict.get("conditions")),
            connectors=connectors,
            requires_approval=requires_approval,
            risk_level=risk_level,
            dry_run=dry_run,
            metadata={
                "created_at": _utc_now(),
                "created_by": context.user_id,
                "workspace_id": context.workspace_id,
                "source": payload_dict.get("source", "workflow_agent"),
                "payload_hash": _hash_payload(payload_dict),
            },
        )

        validation = self._validate_plan(plan)
        if not validation["success"]:
            return validation

        if requires_approval and not dry_run:
            approval = self._request_security_approval(
                context=context,
                action="build_workflow",
                payload=plan.to_dict(),
                risk_level=risk_level,
            )
            if not approval.get("success") or not approval.get("data", {}).get("approved", False):
                plan.status = WorkflowStatus.WAITING_APPROVAL.value
                self._store_workflow(context, plan)
                return self._safe_result(
                    success=True,
                    message="Workflow plan created and is waiting for security approval.",
                    data={
                        "workflow": plan.to_dict(),
                        "approval": approval,
                        "verification_payload": self._prepare_verification_payload(
                            context=context,
                            action="build_workflow",
                            result_data=plan.to_dict(),
                        ),
                        "memory_payload": self._prepare_memory_payload(
                            context=context,
                            action="build_workflow",
                            result_data=plan.to_dict(),
                        ),
                    },
                    context=context,
                )

        self._store_workflow(context, plan)

        return self._safe_result(
            success=True,
            message="Workflow plan created successfully.",
            data={
                "workflow": plan.to_dict(),
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="build_workflow",
                    result_data=plan.to_dict(),
                ),
                "memory_payload": self._prepare_memory_payload(
                    context=context,
                    action="build_workflow",
                    result_data=plan.to_dict(),
                ),
            },
            context=context,
        )

    def build_n8n_workflow(self, context: WorkflowContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Build an n8n-ready workflow plan.

        This does not call n8n directly. The future n8n_connector.py file should
        convert this plan into real n8n nodes/credentials/workflow API calls.
        """
        payload_dict = _coerce_dict(payload)
        workflow_name = _normalize_string(payload_dict.get("name"), "n8n Automation Workflow")

        base_plan_payload = {
            "name": workflow_name,
            "description": payload_dict.get(
                "description",
                "n8n-compatible automation workflow generated by WorkflowAgent.",
            ),
            "source": "n8n",
            "dry_run": payload_dict.get("dry_run", True),
            "triggers": payload_dict.get("triggers", [{"type": "webhook", "method": "POST"}]),
            "steps": payload_dict.get("steps") or self._build_n8n_default_steps(payload_dict),
            "conditions": payload_dict.get("conditions", []),
        }

        result = self.build_workflow(context=context, payload=base_plan_payload)
        if not result.get("success"):
            return result

        workflow = result["data"]["workflow"]
        n8n_export = self._to_n8n_blueprint(workflow)

        workflow["metadata"]["n8n_ready"] = True
        workflow["metadata"]["n8n_blueprint_hash"] = _hash_payload(n8n_export)

        self._workflow_store[self._store_key(context, workflow["workflow_id"])] = workflow

        return self._safe_result(
            success=True,
            message="n8n workflow blueprint created successfully.",
            data={
                "workflow": workflow,
                "n8n_blueprint": n8n_export,
                "notes": [
                    "This blueprint is safe and does not execute external actions.",
                    "Use n8n_connector.py later to create/update the real n8n workflow.",
                    "Credentials/secrets must be configured outside this file.",
                ],
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="build_n8n_workflow",
                    result_data={"workflow": workflow, "n8n_blueprint": n8n_export},
                ),
                "memory_payload": self._prepare_memory_payload(
                    context=context,
                    action="build_n8n_workflow",
                    result_data=workflow,
                ),
            },
            context=context,
        )

    def build_form_pipeline(self, context: WorkflowContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Build Form -> Sheet -> WhatsApp -> CRM pipeline plan.

        This is designed for Digital Promotix lead-generation flows:
            Website form submission
            Save to Google Sheet
            Send WhatsApp/internal notification
            Create/update CRM lead
            Optional email confirmation
            Monitor delivery
        """
        payload_dict = _coerce_dict(payload)
        form_name = _normalize_string(payload_dict.get("form_name"), "Lead Capture Form")
        source = _normalize_string(payload_dict.get("source"), "website")
        fields = [_normalize_string(item) for item in _as_list(payload_dict.get("fields")) if _normalize_string(item)]
        destinations = [
            _normalize_string(item).lower()
            for item in _as_list(payload_dict.get("destinations") or ["sheet", "whatsapp", "crm"])
            if _normalize_string(item)
        ]
        dry_run = bool(payload_dict.get("dry_run", True))

        if not fields:
            fields = ["full_name", "phone", "email", "service", "message"]

        steps: List[Dict[str, Any]] = [
            {
                "name": "Receive form submission",
                "step_type": WorkflowStepType.TRIGGER.value,
                "connector": ConnectorName.FORM.value,
                "operation": "receive_submission",
                "input_map": {
                    "form_name": form_name,
                    "source": source,
                    "fields": fields,
                },
                "risk_level": RiskLevel.LOW.value,
            },
            {
                "name": "Validate form data",
                "step_type": WorkflowStepType.CONDITION.value,
                "connector": ConnectorName.INTERNAL.value,
                "operation": "validate_required_fields",
                "input_map": {
                    "required_fields": self._required_form_fields(fields),
                    "allowed_fields": fields,
                },
                "risk_level": RiskLevel.LOW.value,
            },
            {
                "name": "Normalize lead data",
                "step_type": WorkflowStepType.TRANSFORM.value,
                "connector": ConnectorName.INTERNAL.value,
                "operation": "normalize_lead_payload",
                "input_map": {
                    "trim_strings": True,
                    "normalize_phone": True,
                    "dedupe_key_fields": ["phone", "email"],
                },
                "risk_level": RiskLevel.LOW.value,
            },
        ]

        if "sheet" in destinations or "google_sheet" in destinations:
            steps.append(
                {
                    "name": "Save lead to sheet",
                    "step_type": WorkflowStepType.ACTION.value,
                    "connector": ConnectorName.SHEET.value,
                    "operation": "append_row",
                    "input_map": {
                        "sheet_id_ref": "configured_sheet_id",
                        "columns": ["timestamp"] + fields,
                    },
                    "requires_approval": True,
                    "risk_level": RiskLevel.MEDIUM.value,
                }
            )

        if "whatsapp" in destinations:
            steps.append(
                {
                    "name": "Send WhatsApp lead notification",
                    "step_type": WorkflowStepType.ACTION.value,
                    "connector": ConnectorName.WHATSAPP.value,
                    "operation": "send_whatsapp",
                    "input_map": {
                        "recipient_ref": "configured_sales_number",
                        "message_template": (
                            "New lead from {source}: {full_name}, {phone}, "
                            "{email}, service: {service}"
                        ),
                    },
                    "requires_approval": True,
                    "risk_level": RiskLevel.HIGH.value,
                }
            )

        if "crm" in destinations:
            steps.append(
                {
                    "name": "Create or update CRM lead",
                    "step_type": WorkflowStepType.ACTION.value,
                    "connector": ConnectorName.CRM.value,
                    "operation": "upsert_lead",
                    "input_map": {
                        "dedupe_fields": ["phone", "email"],
                        "lead_stage": payload_dict.get("lead_stage", "new"),
                        "source": source,
                    },
                    "requires_approval": True,
                    "risk_level": RiskLevel.MEDIUM.value,
                }
            )

        if "email" in destinations:
            steps.append(
                {
                    "name": "Send confirmation email",
                    "step_type": WorkflowStepType.ACTION.value,
                    "connector": ConnectorName.EMAIL.value,
                    "operation": "send_email",
                    "input_map": {
                        "to_field": "email",
                        "subject": payload_dict.get("email_subject", "We received your request"),
                        "template_ref": "lead_confirmation_template",
                    },
                    "requires_approval": True,
                    "risk_level": RiskLevel.HIGH.value,
                }
            )

        steps.extend(
            [
                {
                    "name": "Monitor pipeline delivery",
                    "step_type": WorkflowStepType.MONITOR.value,
                    "connector": ConnectorName.INTERNAL.value,
                    "operation": "monitor_delivery",
                    "input_map": {
                        "monitor_window_seconds": DEFAULT_MONITOR_WINDOW_SECONDS,
                        "alert_on_failure": True,
                    },
                    "risk_level": RiskLevel.LOW.value,
                },
                {
                    "name": "Prepare retry plan",
                    "step_type": WorkflowStepType.RETRY.value,
                    "connector": ConnectorName.INTERNAL.value,
                    "operation": "prepare_retry_policy",
                    "input_map": {
                        "max_retries": DEFAULT_MAX_RETRIES,
                        "backoff_seconds": DEFAULT_RETRY_BACKOFF_SECONDS,
                    },
                    "risk_level": RiskLevel.LOW.value,
                },
            ]
        )

        return self.build_workflow(
            context=context,
            payload={
                "name": f"{form_name} Pipeline",
                "description": "Form -> Sheet -> WhatsApp -> CRM automation pipeline.",
                "source": source,
                "dry_run": dry_run,
                "triggers": [
                    {
                        "type": "form_submission",
                        "source": source,
                        "form_name": form_name,
                    }
                ],
                "steps": steps,
                "conditions": [
                    {
                        "name": "Only continue when required fields are valid.",
                        "expression": "required_fields_present == true",
                    }
                ],
                "metadata": {
                    "form_name": form_name,
                    "fields": fields,
                    "destinations": destinations,
                },
            },
        )

    def handle_trigger(self, context: WorkflowContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Handle a workflow trigger event.

        This safely evaluates the trigger and returns a planned next action.
        It does not execute real external actions unless routed through run_workflow.
        """
        payload_dict = _coerce_dict(payload)
        workflow_id = _normalize_string(payload_dict.get("workflow_id"))
        trigger_type = _normalize_string(payload_dict.get("trigger_type") or payload_dict.get("type"), "manual")
        trigger_data = _coerce_dict(payload_dict.get("data"))

        workflow = self._get_workflow(context, workflow_id) if workflow_id else None

        if workflow_id and not workflow:
            return self._error_result(
                message="Workflow not found for trigger.",
                code="workflow_not_found",
                context=context,
                metadata={"workflow_id": workflow_id},
            )

        trigger_record = {
            "trigger_id": _make_id("trg"),
            "workflow_id": workflow_id,
            "trigger_type": trigger_type,
            "received_at": _utc_now(),
            "data_hash": _hash_payload(trigger_data),
            "matched": bool(workflow),
            "next_action": "run_workflow" if workflow else "no_workflow_matched",
        }

        self._emit_agent_event(
            event_type="workflow.trigger.received",
            context=context,
            data=trigger_record,
        )

        self._log_audit_event(
            action="workflow_trigger_received",
            context=context,
            data=trigger_record,
        )

        return self._safe_result(
            success=True,
            message="Trigger handled safely.",
            data={
                "trigger": trigger_record,
                "workflow": workflow,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="handle_trigger",
                    result_data=trigger_record,
                ),
            },
            context=context,
        )

    def handle_webhook(self, context: WorkflowContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Handle an inbound webhook safely.

        This method validates the webhook shape, sanitizes metadata, and routes
        the event to a workflow if workflow_id is included.
        """
        payload_dict = _coerce_dict(payload)
        method = _normalize_string(payload_dict.get("method"), "POST").upper()
        headers = self._sanitize_headers(_coerce_dict(payload_dict.get("headers")))
        body = _coerce_dict(payload_dict.get("body") or payload_dict.get("data"))
        workflow_id = _normalize_string(payload_dict.get("workflow_id"))

        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
            return self._error_result(
                message="Unsupported webhook method.",
                code="unsupported_webhook_method",
                context=context,
                metadata={"method": method},
            )

        webhook_event = {
            "webhook_event_id": _make_id("wh"),
            "workflow_id": workflow_id,
            "method": method,
            "headers": headers,
            "body_hash": _hash_payload(body),
            "received_at": _utc_now(),
            "safe_body_preview": self._safe_preview(body),
        }

        trigger_result = self.handle_trigger(
            context=context,
            payload={
                "workflow_id": workflow_id,
                "trigger_type": "webhook",
                "data": {
                    "method": method,
                    "headers": headers,
                    "body": body,
                },
            },
        )

        return self._safe_result(
            success=trigger_result.get("success", False),
            message="Webhook received and routed safely.",
            data={
                "webhook_event": webhook_event,
                "trigger_result": trigger_result,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="handle_webhook",
                    result_data=webhook_event,
                ),
            },
            context=context,
        )

    def run_workflow(
        self,
        context: WorkflowContext,
        payload: Mapping[str, Any],
        dry_run: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Run or dry-run a stored workflow.

        Safety:
            - Dry-run is the default.
            - Real external actions require Security Agent approval.
            - This file simulates execution only. Future action_router.py and
              connector files should perform real external side effects.
        """
        payload_dict = _coerce_dict(payload)
        workflow_id = _normalize_string(payload_dict.get("workflow_id"))
        input_data = _coerce_dict(payload_dict.get("input_data") or payload_dict.get("data"))
        dry_run_value = bool(payload_dict.get("dry_run", True) if dry_run is None else dry_run)

        workflow = self._get_workflow(context, workflow_id)
        if not workflow:
            return self._error_result(
                message="Workflow not found.",
                code="workflow_not_found",
                context=context,
                metadata={"workflow_id": workflow_id},
            )

        steps = [_coerce_dict(step) for step in workflow.get("steps", [])]
        risk_level = _normalize_string(workflow.get("risk_level"), RiskLevel.LOW.value)
        requires_approval = bool(workflow.get("requires_approval", False))

        if requires_approval and not dry_run_value:
            approval = self._request_security_approval(
                context=context,
                action="run_workflow",
                payload={
                    "workflow_id": workflow_id,
                    "workflow_hash": _hash_payload(workflow),
                    "input_hash": _hash_payload(input_data),
                },
                risk_level=risk_level,
            )
            if not approval.get("success") or not approval.get("data", {}).get("approved", False):
                return self._safe_result(
                    success=False,
                    message="Workflow execution blocked pending security approval.",
                    data={
                        "workflow_id": workflow_id,
                        "approval": approval,
                    },
                    context=context,
                    error={
                        "code": "security_approval_required",
                        "details": "Sensitive workflow execution requires approval.",
                    },
                )

        execution = WorkflowExecutionRecord(
            execution_id=_make_id("exec"),
            workflow_id=workflow_id,
            status=WorkflowStatus.RUNNING.value,
            started_at=_utc_now(),
            metadata={
                "dry_run": dry_run_value,
                "input_hash": _hash_payload(input_data),
                "workspace_id": context.workspace_id,
                "user_id": context.user_id,
            },
        )

        step_results = []
        for index, step in enumerate(steps):
            step_result = self._simulate_step_execution(
                context=context,
                workflow=workflow,
                step=step,
                input_data=input_data,
                dry_run=dry_run_value,
                index=index,
            )
            step_results.append(step_result)

            if not step_result.get("success", False):
                execution.status = WorkflowStatus.FAILED.value
                execution.error = {
                    "code": step_result.get("error", {}).get("code", "step_failed"),
                    "message": step_result.get("message", "Workflow step failed."),
                    "step_id": step.get("step_id"),
                }
                break

        if execution.status != WorkflowStatus.FAILED.value:
            execution.status = WorkflowStatus.COMPLETED.value

        execution.finished_at = _utc_now()
        execution.step_results = step_results

        self._execution_store[self._store_key(context, execution.execution_id)] = execution.to_dict()

        workflow["status"] = WorkflowStatus.COMPLETED.value if dry_run_value else WorkflowStatus.ACTIVE.value
        workflow["metadata"]["last_execution_id"] = execution.execution_id
        workflow["metadata"]["last_run_at"] = execution.finished_at
        self._workflow_store[self._store_key(context, workflow_id)] = workflow

        self._emit_agent_event(
            event_type="workflow.execution.completed",
            context=context,
            data=execution.to_dict(),
        )

        self._log_audit_event(
            action="workflow_execution_completed",
            context=context,
            data={
                "workflow_id": workflow_id,
                "execution_id": execution.execution_id,
                "status": execution.status,
                "dry_run": dry_run_value,
            },
        )

        return self._safe_result(
            success=execution.status == WorkflowStatus.COMPLETED.value,
            message="Workflow dry-run completed successfully." if dry_run_value else "Workflow execution completed safely.",
            data={
                "execution": execution.to_dict(),
                "workflow": workflow,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="run_workflow",
                    result_data=execution.to_dict(),
                ),
                "memory_payload": self._prepare_memory_payload(
                    context=context,
                    action="run_workflow",
                    result_data={
                        "workflow_id": workflow_id,
                        "execution_status": execution.status,
                        "dry_run": dry_run_value,
                    },
                ),
            },
            context=context,
            error=execution.error,
        )

    def validate_workflow(self, context: WorkflowContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate a stored workflow or raw workflow object.
        """
        payload_dict = _coerce_dict(payload)
        workflow_id = _normalize_string(payload_dict.get("workflow_id"))
        workflow = self._get_workflow(context, workflow_id) if workflow_id else _coerce_dict(payload_dict.get("workflow"))

        if not workflow:
            return self._error_result(
                message="No workflow found to validate.",
                code="missing_workflow",
                context=context,
            )

        steps = workflow.get("steps", [])
        issues: List[Dict[str, Any]] = []
        warnings: List[Dict[str, Any]] = []

        if not workflow.get("workflow_id"):
            issues.append({"code": "missing_workflow_id", "message": "workflow_id is required."})

        if not workflow.get("name"):
            issues.append({"code": "missing_name", "message": "Workflow name is required."})

        if not isinstance(steps, list) or not steps:
            issues.append({"code": "missing_steps", "message": "Workflow must include at least one step."})

        for index, step in enumerate(steps if isinstance(steps, list) else []):
            step_dict = _coerce_dict(step)
            if not step_dict.get("step_id"):
                warnings.append({"code": "missing_step_id", "index": index, "message": "Step should include step_id."})
            if not step_dict.get("connector"):
                issues.append({"code": "missing_connector", "index": index, "message": "Step connector is required."})
            if not step_dict.get("operation"):
                issues.append({"code": "missing_operation", "index": index, "message": "Step operation is required."})
            if step_dict.get("requires_approval") and not step_dict.get("risk_level"):
                warnings.append({"code": "missing_risk_level", "index": index, "message": "Approval step should include risk_level."})

        valid = len(issues) == 0

        return self._safe_result(
            success=valid,
            message="Workflow validation passed." if valid else "Workflow validation failed.",
            data={
                "valid": valid,
                "issues": issues,
                "warnings": warnings,
                "workflow_id": workflow.get("workflow_id"),
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="validate_workflow",
                    result_data={
                        "valid": valid,
                        "issues": issues,
                        "warnings": warnings,
                    },
                ),
            },
            context=context,
            error=None if valid else {"code": "workflow_validation_failed", "issues": issues},
        )

    def monitor_workflow(self, context: WorkflowContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Return safe monitoring summary for workflow/executions.

        Future workflow_monitor.py should expand this with real health checks.
        """
        payload_dict = _coerce_dict(payload)
        workflow_id = _normalize_string(payload_dict.get("workflow_id"))
        workflow = self._get_workflow(context, workflow_id) if workflow_id else None

        matching_executions = []
        for key, execution in self._execution_store.items():
            if not key.startswith(f"{context.user_id}:{context.workspace_id}:"):
                continue
            if workflow_id and execution.get("workflow_id") != workflow_id:
                continue
            matching_executions.append(execution)

        matching_executions.sort(key=lambda item: item.get("started_at", ""), reverse=True)

        total = len(matching_executions)
        failures = len([item for item in matching_executions if item.get("status") == WorkflowStatus.FAILED.value])
        completed = len([item for item in matching_executions if item.get("status") == WorkflowStatus.COMPLETED.value])

        health = "unknown"
        if total == 0:
            health = "no_runs"
        elif failures == 0:
            health = "healthy"
        elif completed > failures:
            health = "degraded"
        else:
            health = "unhealthy"

        summary = {
            "workflow_id": workflow_id,
            "workflow_exists": bool(workflow) if workflow_id else None,
            "health": health,
            "total_executions": total,
            "completed_executions": completed,
            "failed_executions": failures,
            "recent_executions": matching_executions[:10],
            "checked_at": _utc_now(),
        }

        return self._safe_result(
            success=True,
            message="Workflow monitoring summary prepared.",
            data={
                "monitoring": summary,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action="monitor_workflow",
                    result_data=summary,
                ),
            },
            context=context,
        )

    def get_workflow_status(self, context: WorkflowContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Get status for a workflow.
        """
        payload_dict = _coerce_dict(payload)
        workflow_id = _normalize_string(payload_dict.get("workflow_id"))

        if not workflow_id:
            return self._error_result(
                message="workflow_id is required.",
                code="missing_workflow_id",
                context=context,
            )

        workflow = self._get_workflow(context, workflow_id)
        if not workflow:
            return self._error_result(
                message="Workflow not found.",
                code="workflow_not_found",
                context=context,
                metadata={"workflow_id": workflow_id},
            )

        return self._safe_result(
            success=True,
            message="Workflow status loaded.",
            data={
                "workflow_id": workflow_id,
                "status": workflow.get("status"),
                "risk_level": workflow.get("risk_level"),
                "requires_approval": workflow.get("requires_approval"),
                "metadata": workflow.get("metadata", {}),
                "workflow": workflow,
            },
            context=context,
        )

    def list_templates(self, context: WorkflowContext, payload: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """
        List built-in workflow templates.
        """
        payload_dict = _coerce_dict(payload)
        category = _normalize_string(payload_dict.get("category")).lower()

        templates = []
        for template in self._template_store.values():
            if category and _normalize_string(template.get("category")).lower() != category:
                continue
            templates.append(copy.deepcopy(template))

        return self._safe_result(
            success=True,
            message="Workflow templates loaded.",
            data={
                "templates": templates,
                "count": len(templates),
            },
            context=context,
        )

    def apply_template(self, context: WorkflowContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Apply a built-in template and create a workflow draft.
        """
        payload_dict = _coerce_dict(payload)
        template_id = _normalize_string(payload_dict.get("template_id"))

        if not template_id:
            return self._error_result(
                message="template_id is required.",
                code="missing_template_id",
                context=context,
            )

        template = self._template_store.get(template_id)
        if not template:
            return self._error_result(
                message="Workflow template not found.",
                code="template_not_found",
                context=context,
                metadata={"template_id": template_id},
            )

        overrides = _coerce_dict(payload_dict.get("overrides"))
        workflow_payload = copy.deepcopy(template.get("workflow_payload", {}))
        workflow_payload.update(overrides)
        workflow_payload.setdefault("name", template.get("name", "Workflow From Template"))
        workflow_payload.setdefault("description", template.get("description", "Generated from WorkflowAgent template."))
        workflow_payload["dry_run"] = payload_dict.get("dry_run", workflow_payload.get("dry_run", True))

        return self.build_workflow(context=context, payload=workflow_payload)

    def pause_workflow(self, context: WorkflowContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Pause a workflow safely."""
        return self._set_workflow_status(
            context=context,
            payload=payload,
            status=WorkflowStatus.PAUSED.value,
            action="pause_workflow",
            message="Workflow paused.",
        )

    def resume_workflow(self, context: WorkflowContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Resume a workflow safely."""
        return self._set_workflow_status(
            context=context,
            payload=payload,
            status=WorkflowStatus.ACTIVE.value,
            action="resume_workflow",
            message="Workflow resumed.",
        )

    def disable_workflow(self, context: WorkflowContext, payload: Mapping[str, Any]) -> Dict[str, Any]:
        """Disable a workflow safely."""
        payload_dict = _coerce_dict(payload)
        workflow_id = _normalize_string(payload_dict.get("workflow_id"))

        if not workflow_id:
            return self._error_result(
                message="workflow_id is required.",
                code="missing_workflow_id",
                context=context,
            )

        approval = self._request_security_approval(
            context=context,
            action="disable_workflow",
            payload={"workflow_id": workflow_id},
            risk_level=RiskLevel.MEDIUM.value,
        )
        if not approval.get("success") or not approval.get("data", {}).get("approved", False):
            return self._safe_result(
                success=False,
                message="Workflow disable action blocked pending security approval.",
                data={"approval": approval, "workflow_id": workflow_id},
                context=context,
                error={"code": "security_approval_required"},
            )

        return self._set_workflow_status(
            context=context,
            payload=payload,
            status=WorkflowStatus.DISABLED.value,
            action="disable_workflow",
            message="Workflow disabled.",
        )

    # -------------------------------------------------------------------------
    # Required compatibility hooks
    # -------------------------------------------------------------------------

    def _validate_task_context(self, task: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Validate SaaS user/workspace isolation context.

        Required by William/Jarvis architecture.
        """
        task_dict = _coerce_dict(task)
        user_id = _normalize_string(task_dict.get("user_id"))
        workspace_id = _normalize_string(task_dict.get("workspace_id"))

        payload = _coerce_dict(task_dict.get("payload"))
        if not user_id:
            user_id = _normalize_string(payload.get("user_id"))
        if not workspace_id:
            workspace_id = _normalize_string(payload.get("workspace_id"))

        if not user_id:
            return self._error_result(
                message="user_id is required for WorkflowAgent task isolation.",
                code="missing_user_id",
            )

        if not workspace_id:
            return self._error_result(
                message="workspace_id is required for WorkflowAgent task isolation.",
                code="missing_workspace_id",
            )

        context = WorkflowContext(
            user_id=user_id,
            workspace_id=workspace_id,
            request_id=_normalize_string(task_dict.get("request_id"), default=str(uuid.uuid4())),
            actor_id=_normalize_string(task_dict.get("actor_id")) or None,
            role=_normalize_string(task_dict.get("role")) or None,
            source=_normalize_string(task_dict.get("source"), default="workflow_agent"),
            session_id=_normalize_string(task_dict.get("session_id")) or None,
            permissions=[_normalize_string(item) for item in _as_list(task_dict.get("permissions"))],
            metadata=_coerce_dict(task_dict.get("metadata")),
        )

        return self._safe_result(
            success=True,
            message="Workflow task context validated.",
            data={"context": context},
            context=context,
        )

    def _requires_security_check(
        self,
        action: str,
        payload: Optional[Mapping[str, Any]] = None,
        risk_level: str = RiskLevel.LOW.value,
    ) -> bool:
        """
        Decide whether a task/action needs Security Agent approval.

        Required by William/Jarvis architecture.
        """
        action_norm = _normalize_string(action).lower()
        payload_dict = _coerce_dict(payload)
        payload_text = _safe_json_dumps(payload_dict).lower()

        if risk_level in {RiskLevel.HIGH.value, RiskLevel.CRITICAL.value}:
            return True

        if action_norm in SENSITIVE_ACTION_KEYWORDS:
            return True

        for keyword in SENSITIVE_ACTION_KEYWORDS:
            if keyword in payload_text:
                return True

        return False

    def _request_security_approval(
        self,
        context: WorkflowContext,
        action: str,
        payload: Mapping[str, Any],
        risk_level: str = RiskLevel.LOW.value,
    ) -> Dict[str, Any]:
        """
        Request Security Agent approval.

        Required by William/Jarvis architecture.
        """
        request = {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "agent": self.agent_name,
            "action": action,
            "risk_level": risk_level,
            "payload_hash": _hash_payload(payload),
            "payload_preview": self._safe_preview(payload),
            "timestamp": _utc_now(),
        }

        try:
            if hasattr(self.security_agent, "check_permission"):
                raw = self.security_agent.check_permission(request)
            elif hasattr(self.security_agent, "run"):
                raw = self.security_agent.run(
                    {
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                        "task_type": "check_permission",
                        "payload": request,
                    }
                )
            else:
                raw = {
                    "success": False,
                    "approved": False,
                    "message": "Security agent has no compatible approval method.",
                }

            raw_dict = _coerce_dict(raw)
            approved = bool(raw_dict.get("approved", raw_dict.get("success", False)))

            result = self._safe_result(
                success=bool(raw_dict.get("success", approved)),
                message=_normalize_string(raw_dict.get("message"), "Security approval processed."),
                data={
                    "approved": approved,
                    "security_result": raw_dict,
                    "request": request,
                },
                context=context,
                error=raw_dict.get("error"),
            )

            self._log_audit_event(
                action="security_approval_requested",
                context=context,
                data={
                    "workflow_action": action,
                    "risk_level": risk_level,
                    "approved": approved,
                    "payload_hash": request["payload_hash"],
                },
            )

            return result

        except Exception as exc:
            self.logger.exception("Security approval request failed.")
            return self._error_result(
                message="Security approval request failed.",
                code="security_approval_error",
                context=context,
                error_details={"exception": str(exc), "type": exc.__class__.__name__},
            )

    def _prepare_verification_payload(
        self,
        context: WorkflowContext,
        action: str,
        result_data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Required by William/Jarvis architecture.
        """
        payload = {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "agent": self.agent_name,
            "action": action,
            "result_hash": _hash_payload(result_data),
            "result_preview": self._safe_preview(result_data),
            "verification_type": "workflow_action",
            "timestamp": _utc_now(),
            "checks": [
                "context_isolation",
                "structured_result",
                "security_gate_checked_when_required",
                "workflow_state_consistency",
            ],
        }

        try:
            if hasattr(self.verification_agent, "prepare_payload"):
                prepared = self.verification_agent.prepare_payload(payload)
                return _coerce_dict(prepared)
        except Exception:
            self.logger.debug("VerificationAgent fallback payload used.", exc_info=True)

        return payload

    def _prepare_memory_payload(
        self,
        context: WorkflowContext,
        action: str,
        result_data: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Required by William/Jarvis architecture.
        """
        payload = {
            "user_id": context.user_id,
            "workspace_id": context.workspace_id,
            "request_id": context.request_id,
            "agent": self.agent_name,
            "action": action,
            "memory_type": "workflow_context",
            "timestamp": _utc_now(),
            "content": {
                "summary": f"WorkflowAgent completed action: {action}",
                "result_hash": _hash_payload(result_data),
                "safe_preview": self._safe_preview(result_data),
            },
            "isolation": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
            },
        }

        try:
            if hasattr(self.memory_agent, "prepare_payload"):
                prepared = self.memory_agent.prepare_payload(payload)
                return _coerce_dict(prepared)
        except Exception:
            self.logger.debug("MemoryAgent fallback payload used.", exc_info=True)

        return payload

    def _emit_agent_event(
        self,
        event_type: str,
        context: Optional[WorkflowContext] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Emit agent event.

        Required by William/Jarvis architecture.
        Dashboard/API/event bus can subscribe to this later.
        """
        event = {
            "event_id": _make_id("evt"),
            "event_type": event_type,
            "agent": self.agent_name,
            "timestamp": _utc_now(),
            "context": context.to_dict() if context else {},
            "data": _coerce_dict(data),
        }

        try:
            if self.event_emitter:
                self.event_emitter(event)
            else:
                self.logger.debug("Agent event: %s", _safe_json_dumps(event))
        except Exception:
            self.logger.exception("Failed to emit agent event.")

    def _log_audit_event(
        self,
        action: str,
        context: Optional[WorkflowContext] = None,
        data: Optional[Mapping[str, Any]] = None,
    ) -> None:
        """
        Log audit event.

        Required by William/Jarvis architecture.
        """
        event = {
            "audit_id": _make_id("audit"),
            "action": action,
            "agent": self.agent_name,
            "timestamp": _utc_now(),
            "context": context.to_dict() if context else {},
            "data": _coerce_dict(data),
        }

        try:
            if self.audit_logger:
                self.audit_logger(event)
            else:
                self.logger.debug("Audit event: %s", _safe_json_dumps(event))
        except Exception:
            self.logger.exception("Failed to log audit event.")

    def _safe_result(
        self,
        success: bool,
        message: str,
        data: Optional[Mapping[str, Any]] = None,
        context: Optional[WorkflowContext] = None,
        error: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build standard structured result.

        Required by William/Jarvis architecture.
        """
        final_metadata = _coerce_dict(metadata)
        final_metadata.setdefault("agent", self.agent_name)
        final_metadata.setdefault("timestamp", _utc_now())

        if context:
            final_metadata.setdefault("user_id", context.user_id)
            final_metadata.setdefault("workspace_id", context.workspace_id)
            final_metadata.setdefault("request_id", context.request_id)

        return {
            "success": bool(success),
            "message": message,
            "data": _coerce_dict(data),
            "error": _coerce_dict(error) if error else None,
            "metadata": final_metadata,
        }

    def _error_result(
        self,
        message: str,
        code: str,
        context: Optional[WorkflowContext] = None,
        error_details: Optional[Mapping[str, Any]] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build standard structured error result.

        Required by William/Jarvis architecture.
        """
        error = {
            "code": code,
            "message": message,
            "details": _coerce_dict(error_details),
        }
        return self._safe_result(
            success=False,
            message=message,
            data={},
            context=context,
            error=error,
            metadata=metadata,
        )

    # -------------------------------------------------------------------------
    # Internal planning helpers
    # -------------------------------------------------------------------------

    def _load_default_config(self, config: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
        """Load safe default configuration."""
        defaults = {
            "default_dry_run": True,
            "max_steps_per_workflow": 100,
            "max_retries": DEFAULT_MAX_RETRIES,
            "retry_backoff_seconds": DEFAULT_RETRY_BACKOFF_SECONDS,
            "default_timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
            "monitor_window_seconds": DEFAULT_MONITOR_WINDOW_SECONDS,
            "allow_real_external_actions": False,
            "allowed_connectors": [item.value for item in ConnectorName],
            "sensitive_actions": sorted(SENSITIVE_ACTION_KEYWORDS),
        }
        if config:
            defaults.update(_coerce_dict(config))
        return defaults

    def _load_builtin_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load built-in workflow templates."""
        templates = [
            {
                "template_id": "form_sheet_whatsapp_crm",
                "name": "Form to Sheet, WhatsApp, CRM",
                "category": "lead_generation",
                "description": "Capture website leads, save to sheet, notify WhatsApp, and create/update CRM record.",
                "workflow_payload": {
                    "name": "Lead Capture Pipeline",
                    "description": "Website form lead automation pipeline.",
                    "dry_run": True,
                    "steps": [
                        {
                            "name": "Receive form submission",
                            "step_type": WorkflowStepType.TRIGGER.value,
                            "connector": ConnectorName.FORM.value,
                            "operation": "receive_submission",
                        },
                        {
                            "name": "Save lead to sheet",
                            "step_type": WorkflowStepType.ACTION.value,
                            "connector": ConnectorName.SHEET.value,
                            "operation": "append_row",
                            "requires_approval": True,
                            "risk_level": RiskLevel.MEDIUM.value,
                        },
                        {
                            "name": "Send WhatsApp notification",
                            "step_type": WorkflowStepType.ACTION.value,
                            "connector": ConnectorName.WHATSAPP.value,
                            "operation": "send_whatsapp",
                            "requires_approval": True,
                            "risk_level": RiskLevel.HIGH.value,
                        },
                        {
                            "name": "Upsert CRM lead",
                            "step_type": WorkflowStepType.ACTION.value,
                            "connector": ConnectorName.CRM.value,
                            "operation": "upsert_lead",
                            "requires_approval": True,
                            "risk_level": RiskLevel.MEDIUM.value,
                        },
                    ],
                },
            },
            {
                "template_id": "webhook_to_n8n_router",
                "name": "Webhook to n8n Router",
                "category": "integration",
                "description": "Receive webhook and route payload to n8n workflow blueprint.",
                "workflow_payload": {
                    "name": "Webhook n8n Router",
                    "description": "Webhook-triggered n8n automation.",
                    "dry_run": True,
                    "steps": [
                        {
                            "name": "Receive webhook",
                            "step_type": WorkflowStepType.TRIGGER.value,
                            "connector": ConnectorName.WEBHOOK.value,
                            "operation": "receive_webhook",
                        },
                        {
                            "name": "Validate webhook body",
                            "step_type": WorkflowStepType.CONDITION.value,
                            "connector": ConnectorName.INTERNAL.value,
                            "operation": "validate_payload",
                        },
                        {
                            "name": "Route to n8n",
                            "step_type": WorkflowStepType.ACTION.value,
                            "connector": ConnectorName.N8N.value,
                            "operation": "route_to_workflow",
                            "requires_approval": True,
                            "risk_level": RiskLevel.MEDIUM.value,
                        },
                    ],
                },
            },
            {
                "template_id": "scheduled_crm_followup",
                "name": "Scheduled CRM Follow-Up",
                "category": "sales",
                "description": "Check CRM leads and schedule follow-up notification tasks.",
                "workflow_payload": {
                    "name": "CRM Follow-Up Scheduler",
                    "description": "Scheduled follow-up automation for CRM leads.",
                    "dry_run": True,
                    "steps": [
                        {
                            "name": "Scheduled trigger",
                            "step_type": WorkflowStepType.TRIGGER.value,
                            "connector": ConnectorName.SCHEDULER.value,
                            "operation": "scheduled_run",
                        },
                        {
                            "name": "Find leads needing follow-up",
                            "step_type": WorkflowStepType.ACTION.value,
                            "connector": ConnectorName.CRM.value,
                            "operation": "query_leads",
                            "requires_approval": True,
                            "risk_level": RiskLevel.MEDIUM.value,
                        },
                        {
                            "name": "Send internal notification",
                            "step_type": WorkflowStepType.ACTION.value,
                            "connector": ConnectorName.NOTIFICATION.value,
                            "operation": "send_notification",
                            "requires_approval": True,
                            "risk_level": RiskLevel.MEDIUM.value,
                        },
                    ],
                },
            },
        ]

        return {template["template_id"]: template for template in templates}

    def _infer_steps_from_payload(self, payload: Mapping[str, Any]) -> List[Dict[str, Any]]:
        """
        Infer workflow steps from a high-level payload.

        This helps Master Agent create workflows from natural-language-like
        structured tasks.
        """
        payload_dict = _coerce_dict(payload)
        pipeline = _normalize_string(payload_dict.get("pipeline") or payload_dict.get("intent")).lower()

        if "form" in pipeline or "lead" in pipeline:
            return [
                {
                    "name": "Receive form submission",
                    "step_type": WorkflowStepType.TRIGGER.value,
                    "connector": ConnectorName.FORM.value,
                    "operation": "receive_submission",
                },
                {
                    "name": "Validate lead data",
                    "step_type": WorkflowStepType.CONDITION.value,
                    "connector": ConnectorName.INTERNAL.value,
                    "operation": "validate_required_fields",
                },
                {
                    "name": "Save lead to sheet",
                    "step_type": WorkflowStepType.ACTION.value,
                    "connector": ConnectorName.SHEET.value,
                    "operation": "append_row",
                    "requires_approval": True,
                    "risk_level": RiskLevel.MEDIUM.value,
                },
                {
                    "name": "Notify sales on WhatsApp",
                    "step_type": WorkflowStepType.ACTION.value,
                    "connector": ConnectorName.WHATSAPP.value,
                    "operation": "send_whatsapp",
                    "requires_approval": True,
                    "risk_level": RiskLevel.HIGH.value,
                },
                {
                    "name": "Create CRM lead",
                    "step_type": WorkflowStepType.ACTION.value,
                    "connector": ConnectorName.CRM.value,
                    "operation": "upsert_lead",
                    "requires_approval": True,
                    "risk_level": RiskLevel.MEDIUM.value,
                },
            ]

        if "webhook" in pipeline:
            return [
                {
                    "name": "Receive webhook",
                    "step_type": WorkflowStepType.TRIGGER.value,
                    "connector": ConnectorName.WEBHOOK.value,
                    "operation": "receive_webhook",
                },
                {
                    "name": "Validate webhook payload",
                    "step_type": WorkflowStepType.CONDITION.value,
                    "connector": ConnectorName.INTERNAL.value,
                    "operation": "validate_payload",
                },
                {
                    "name": "Route webhook action",
                    "step_type": WorkflowStepType.ROUTER.value,
                    "connector": ConnectorName.INTERNAL.value,
                    "operation": "route_action",
                },
            ]

        return [
            {
                "name": "Manual trigger",
                "step_type": WorkflowStepType.TRIGGER.value,
                "connector": ConnectorName.INTERNAL.value,
                "operation": "manual_trigger",
            },
            {
                "name": "No-op safe action",
                "step_type": WorkflowStepType.ACTION.value,
                "connector": ConnectorName.INTERNAL.value,
                "operation": "noop",
            },
        ]

    def _normalize_step(self, raw_step: Any, index: int) -> WorkflowStep:
        """Normalize raw step mapping into WorkflowStep dataclass."""
        step = _coerce_dict(raw_step)
        operation = _normalize_string(step.get("operation"), default="noop")
        connector = _normalize_string(step.get("connector"), default=ConnectorName.INTERNAL.value)
        step_type = _normalize_string(step.get("step_type") or step.get("type"), default=WorkflowStepType.ACTION.value)
        risk_level = _normalize_string(step.get("risk_level"), default=RiskLevel.LOW.value)

        requires_approval = bool(step.get("requires_approval", False))
        if self._requires_security_check(action=operation, payload=step, risk_level=risk_level):
            requires_approval = True

        return WorkflowStep(
            step_id=_normalize_string(step.get("step_id"), default=f"step_{index + 1}_{uuid.uuid4().hex[:8]}"),
            name=_normalize_string(step.get("name"), default=f"Step {index + 1}"),
            step_type=step_type,
            connector=connector,
            operation=operation,
            input_map=_coerce_dict(step.get("input_map")),
            output_map=_coerce_dict(step.get("output_map")),
            conditions=[_coerce_dict(item) for item in _as_list(step.get("conditions"))],
            requires_approval=requires_approval,
            risk_level=risk_level,
            timeout_seconds=int(step.get("timeout_seconds", self.config["default_timeout_seconds"])),
            max_retries=int(step.get("max_retries", self.config["max_retries"])),
            retry_backoff_seconds=float(step.get("retry_backoff_seconds", self.config["retry_backoff_seconds"])),
            enabled=bool(step.get("enabled", True)),
            metadata=_coerce_dict(step.get("metadata")),
        )

    def _calculate_workflow_risk(self, steps: Iterable[WorkflowStep], payload: Mapping[str, Any]) -> str:
        """Calculate overall workflow risk level."""
        levels = []
        for step in steps:
            levels.append(step.risk_level)
            if step.requires_approval:
                levels.append(RiskLevel.MEDIUM.value)
            if self._requires_security_check(step.operation, step.to_dict(), step.risk_level):
                levels.append(RiskLevel.HIGH.value)

        payload_text = _safe_json_dumps(payload).lower()
        if any(keyword in payload_text for keyword in ["payment", "charge", "refund", "delete", "call"]):
            levels.append(RiskLevel.CRITICAL.value)

        priority = {
            RiskLevel.LOW.value: 1,
            RiskLevel.MEDIUM.value: 2,
            RiskLevel.HIGH.value: 3,
            RiskLevel.CRITICAL.value: 4,
        }

        max_level = RiskLevel.LOW.value
        for level in levels:
            if priority.get(level, 1) > priority.get(max_level, 1):
                max_level = level
        return max_level

    def _validate_plan(self, plan: WorkflowPlan) -> Dict[str, Any]:
        """Validate generated WorkflowPlan before storing."""
        if not plan.workflow_id:
            return self._error_result(
                message="Generated workflow plan is missing workflow_id.",
                code="invalid_workflow_plan",
            )

        if not plan.name:
            return self._error_result(
                message="Generated workflow plan is missing name.",
                code="invalid_workflow_plan",
            )

        if len(plan.steps) > int(self.config.get("max_steps_per_workflow", 100)):
            return self._error_result(
                message="Workflow has too many steps.",
                code="workflow_step_limit_exceeded",
                metadata={
                    "max_steps": self.config.get("max_steps_per_workflow"),
                    "actual_steps": len(plan.steps),
                },
            )

        allowed_connectors = set(self.config.get("allowed_connectors", []))
        for step in plan.steps:
            if step.connector not in allowed_connectors:
                return self._error_result(
                    message=f"Connector is not allowed: {step.connector}",
                    code="connector_not_allowed",
                    metadata={"connector": step.connector},
                )

        return self._safe_result(
            success=True,
            message="Workflow plan is valid.",
            data={"workflow_id": plan.workflow_id},
        )

    def _build_n8n_default_steps(self, payload: Mapping[str, Any]) -> List[Dict[str, Any]]:
        """Build default n8n-compatible steps from payload."""
        payload_dict = _coerce_dict(payload)
        include_form = bool(payload_dict.get("include_form", True))
        include_sheet = bool(payload_dict.get("include_sheet", True))
        include_whatsapp = bool(payload_dict.get("include_whatsapp", False))
        include_crm = bool(payload_dict.get("include_crm", True))

        steps: List[Dict[str, Any]] = [
            {
                "name": "n8n Webhook Trigger",
                "step_type": WorkflowStepType.TRIGGER.value,
                "connector": ConnectorName.N8N.value,
                "operation": "webhook_trigger",
                "input_map": {
                    "method": "POST",
                    "path": payload_dict.get("webhook_path", "william-workflow"),
                },
                "risk_level": RiskLevel.LOW.value,
            }
        ]

        if include_form:
            steps.append(
                {
                    "name": "Parse Form Payload",
                    "step_type": WorkflowStepType.TRANSFORM.value,
                    "connector": ConnectorName.INTERNAL.value,
                    "operation": "parse_form_payload",
                    "risk_level": RiskLevel.LOW.value,
                }
            )

        steps.append(
            {
                "name": "Validate Required Fields",
                "step_type": WorkflowStepType.CONDITION.value,
                "connector": ConnectorName.INTERNAL.value,
                "operation": "validate_required_fields",
                "risk_level": RiskLevel.LOW.value,
            }
        )

        if include_sheet:
            steps.append(
                {
                    "name": "Google Sheets Append Row",
                    "step_type": WorkflowStepType.ACTION.value,
                    "connector": ConnectorName.SHEET.value,
                    "operation": "append_row",
                    "requires_approval": True,
                    "risk_level": RiskLevel.MEDIUM.value,
                }
            )

        if include_whatsapp:
            steps.append(
                {
                    "name": "WhatsApp Notification",
                    "step_type": WorkflowStepType.ACTION.value,
                    "connector": ConnectorName.WHATSAPP.value,
                    "operation": "send_whatsapp",
                    "requires_approval": True,
                    "risk_level": RiskLevel.HIGH.value,
                }
            )

        if include_crm:
            steps.append(
                {
                    "name": "CRM Upsert Lead",
                    "step_type": WorkflowStepType.ACTION.value,
                    "connector": ConnectorName.CRM.value,
                    "operation": "upsert_lead",
                    "requires_approval": True,
                    "risk_level": RiskLevel.MEDIUM.value,
                }
            )

        return steps

    def _to_n8n_blueprint(self, workflow: Mapping[str, Any]) -> Dict[str, Any]:
        """
        Convert internal workflow into safe n8n-style blueprint.

        This is a blueprint only. It does not contain credentials/secrets.
        """
        workflow_dict = _coerce_dict(workflow)
        nodes = []
        connections: Dict[str, Dict[str, List[List[Dict[str, Any]]]]] = {}

        steps = [_coerce_dict(step) for step in workflow_dict.get("steps", [])]

        for index, step in enumerate(steps):
            node_name = step.get("name") or f"Step {index + 1}"
            node_type = self._map_step_to_n8n_node_type(step)
            node = {
                "id": step.get("step_id") or f"node_{index + 1}",
                "name": node_name,
                "type": node_type,
                "typeVersion": 1,
                "position": [index * 260, 200],
                "parameters": {
                    "operation": step.get("operation"),
                    "connector": step.get("connector"),
                    "input_map": step.get("input_map", {}),
                    "safeGenerated": True,
                    "requiresApproval": bool(step.get("requires_approval", False)),
                },
                "credentials": {},
                "notes": f"Generated by William WorkflowAgent. Risk: {step.get('risk_level', 'low')}",
            }
            nodes.append(node)

            if index > 0:
                previous_name = steps[index - 1].get("name") or f"Step {index}"
                connections.setdefault(previous_name, {"main": [[]]})
                connections[previous_name]["main"][0].append(
                    {
                        "node": node_name,
                        "type": "main",
                        "index": 0,
                    }
                )

        return {
            "name": workflow_dict.get("name", "William Workflow"),
            "active": False,
            "nodes": nodes,
            "connections": connections,
            "settings": {
                "executionOrder": "v1",
                "saveManualExecutions": True,
                "callerPolicy": "workflowsFromSameOwner",
            },
            "staticData": {},
            "tags": ["william", "jarvis", "workflow-agent", "generated"],
            "meta": {
                "generatedBy": self.agent_name,
                "generatedAt": _utc_now(),
                "workflowId": workflow_dict.get("workflow_id"),
                "dryRun": workflow_dict.get("dry_run", True),
                "containsSecrets": False,
            },
        }

    def _map_step_to_n8n_node_type(self, step: Mapping[str, Any]) -> str:
        """Map internal step/connector to n8n node type."""
        connector = _normalize_string(step.get("connector")).lower()
        operation = _normalize_string(step.get("operation")).lower()

        if connector == ConnectorName.WEBHOOK.value or "webhook" in operation:
            return "n8n-nodes-base.webhook"
        if connector == ConnectorName.SHEET.value:
            return "n8n-nodes-base.googleSheets"
        if connector == ConnectorName.EMAIL.value:
            return "n8n-nodes-base.emailSend"
        if connector == ConnectorName.CRM.value:
            return "n8n-nodes-base.httpRequest"
        if connector == ConnectorName.WHATSAPP.value:
            return "n8n-nodes-base.httpRequest"
        if step.get("step_type") == WorkflowStepType.CONDITION.value:
            return "n8n-nodes-base.if"
        if step.get("step_type") == WorkflowStepType.TRANSFORM.value:
            return "n8n-nodes-base.set"
        return "n8n-nodes-base.noOp"

    def _simulate_step_execution(
        self,
        context: WorkflowContext,
        workflow: Mapping[str, Any],
        step: Mapping[str, Any],
        input_data: Mapping[str, Any],
        dry_run: bool,
        index: int,
    ) -> Dict[str, Any]:
        """
        Simulate a workflow step.

        Future action_router.py should perform actual routed execution.
        """
        step_dict = _coerce_dict(step)

        if not step_dict.get("enabled", True):
            return {
                "success": True,
                "message": "Step skipped because it is disabled.",
                "step_id": step_dict.get("step_id"),
                "index": index,
                "status": "skipped",
                "data": {},
                "error": None,
                "metadata": {"dry_run": dry_run, "timestamp": _utc_now()},
            }

        operation = _normalize_string(step_dict.get("operation"), "noop")
        connector = _normalize_string(step_dict.get("connector"), ConnectorName.INTERNAL.value)
        risk_level = _normalize_string(step_dict.get("risk_level"), RiskLevel.LOW.value)

        if self._requires_security_check(operation, step_dict, risk_level) and not dry_run:
            if not bool(self.config.get("allow_real_external_actions", False)):
                return {
                    "success": False,
                    "message": "Real external action blocked by WorkflowAgent safe default.",
                    "step_id": step_dict.get("step_id"),
                    "index": index,
                    "status": "blocked",
                    "data": {},
                    "error": {
                        "code": "external_action_blocked",
                        "details": "Enable real connector execution only through secured connector modules.",
                    },
                    "metadata": {"dry_run": dry_run, "timestamp": _utc_now()},
                }

        simulated_output = {
            "connector": connector,
            "operation": operation,
            "input_hash": _hash_payload(input_data),
            "step_hash": _hash_payload(step_dict),
            "dry_run": dry_run,
            "side_effect_executed": False,
        }

        return {
            "success": True,
            "message": "Step simulated successfully." if dry_run else "Step routed safely.",
            "step_id": step_dict.get("step_id"),
            "index": index,
            "status": "completed",
            "data": simulated_output,
            "error": None,
            "metadata": {"dry_run": dry_run, "timestamp": _utc_now()},
        }

    # -------------------------------------------------------------------------
    # Store/status helpers
    # -------------------------------------------------------------------------

    def _store_key(self, context: WorkflowContext, object_id: str) -> str:
        """Build isolated in-memory store key."""
        return f"{context.user_id}:{context.workspace_id}:{object_id}"

    def _store_workflow(self, context: WorkflowContext, plan: WorkflowPlan) -> None:
        """Store workflow in isolated in-memory store."""
        key = self._store_key(context, plan.workflow_id)
        self._workflow_store[key] = plan.to_dict()

    def _get_workflow(self, context: WorkflowContext, workflow_id: str) -> Optional[Dict[str, Any]]:
        """Load workflow from isolated in-memory store."""
        if not workflow_id:
            return None
        workflow = self._workflow_store.get(self._store_key(context, workflow_id))
        return copy.deepcopy(workflow) if workflow else None

    def _set_workflow_status(
        self,
        context: WorkflowContext,
        payload: Mapping[str, Any],
        status: str,
        action: str,
        message: str,
    ) -> Dict[str, Any]:
        """Set workflow status safely."""
        payload_dict = _coerce_dict(payload)
        workflow_id = _normalize_string(payload_dict.get("workflow_id"))

        if not workflow_id:
            return self._error_result(
                message="workflow_id is required.",
                code="missing_workflow_id",
                context=context,
            )

        workflow = self._get_workflow(context, workflow_id)
        if not workflow:
            return self._error_result(
                message="Workflow not found.",
                code="workflow_not_found",
                context=context,
                metadata={"workflow_id": workflow_id},
            )

        old_status = workflow.get("status")
        workflow["status"] = status
        workflow.setdefault("metadata", {})
        workflow["metadata"]["updated_at"] = _utc_now()
        workflow["metadata"]["updated_by"] = context.user_id
        workflow["metadata"]["last_status_change"] = {
            "from": old_status,
            "to": status,
            "action": action,
            "at": _utc_now(),
        }

        self._workflow_store[self._store_key(context, workflow_id)] = workflow

        self._emit_agent_event(
            event_type=f"workflow.status.{status}",
            context=context,
            data={"workflow_id": workflow_id, "old_status": old_status, "new_status": status},
        )

        self._log_audit_event(
            action=action,
            context=context,
            data={"workflow_id": workflow_id, "old_status": old_status, "new_status": status},
        )

        return self._safe_result(
            success=True,
            message=message,
            data={
                "workflow_id": workflow_id,
                "old_status": old_status,
                "new_status": status,
                "workflow": workflow,
                "verification_payload": self._prepare_verification_payload(
                    context=context,
                    action=action,
                    result_data=workflow,
                ),
            },
            context=context,
        )

    # -------------------------------------------------------------------------
    # Data safety helpers
    # -------------------------------------------------------------------------

    def _sanitize_headers(self, headers: Mapping[str, Any]) -> Dict[str, Any]:
        """Remove secret-like values from headers."""
        sanitized: Dict[str, Any] = {}
        sensitive_names = {"authorization", "cookie", "x-api-key", "api-key", "token", "secret"}

        for key, value in _coerce_dict(headers).items():
            key_str = str(key)
            if key_str.lower() in sensitive_names or any(name in key_str.lower() for name in sensitive_names):
                sanitized[key_str] = "***REDACTED***"
            else:
                sanitized[key_str] = value

        return sanitized

    def _safe_preview(self, data: Any, max_chars: int = 1200) -> Dict[str, Any]:
        """
        Create safe preview of data without exposing obvious secrets.

        This is used for logs, audit, memory, and verification payload previews.
        """
        redacted = self._redact_sensitive_values(data)
        text = _safe_json_dumps(redacted)
        if len(text) > max_chars:
            text = text[:max_chars] + "...[truncated]"
        return {
            "preview": text,
            "hash": _hash_payload(data),
            "truncated": len(_safe_json_dumps(redacted)) > max_chars,
        }

    def _redact_sensitive_values(self, data: Any) -> Any:
        """Recursively redact secret-like fields."""
        sensitive_fragments = {
            "password",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "cookie",
            "credential",
            "private_key",
            "access_key",
            "refresh_token",
        }

        if isinstance(data, Mapping):
            clean = {}
            for key, value in data.items():
                key_str = str(key).lower()
                if any(fragment in key_str for fragment in sensitive_fragments):
                    clean[key] = "***REDACTED***"
                else:
                    clean[key] = self._redact_sensitive_values(value)
            return clean

        if isinstance(data, list):
            return [self._redact_sensitive_values(item) for item in data]

        if isinstance(data, tuple):
            return tuple(self._redact_sensitive_values(item) for item in data)

        return data

    def _required_form_fields(self, fields: List[str]) -> List[str]:
        """Select required lead form fields safely."""
        normalized = {field.lower() for field in fields}
        required = []

        for candidate in ["full_name", "name"]:
            if candidate in normalized:
                required.append(candidate)
                break

        for candidate in ["phone", "mobile", "phone_number"]:
            if candidate in normalized:
                required.append(candidate)
                break

        if "email" in normalized:
            required.append("email")

        if not required:
            required = fields[:2]

        return required


# =============================================================================
# Module metadata for Agent Registry / Agent Loader
# =============================================================================

AGENT_CLASS = WorkflowAgent
AGENT_NAME = WorkflowAgent.agent_name
AGENT_TYPE = WorkflowAgent.agent_type
AGENT_MODULE = "agents.workflow_agent.workflow_agent"
AGENT_DESCRIPTION = (
    "Automation pipeline brain for n8n, triggers, webhooks, "
    "Form->Sheet->WhatsApp->CRM, conditions, and monitoring."
)

MODULE_COMPLETION = {
    "Agent/Module": "Workflow Agent",
    "File Completed": "workflow_agent.py",
    "Completion": "4.8%",
    "Completed Files": ["workflow_agent.py"],
    "Remaining Files": [
        "n8n_connector.py",
        "workflow_builder.py",
        "trigger_engine.py",
        "action_router.py",
        "app_connector.py",
        "webhook_manager.py",
        "form_pipeline.py",
        "crm_connector.py",
        "sheet_connector.py",
        "whatsapp_connector.py",
        "email_connector.py",
        "notification_engine.py",
        "condition_engine.py",
        "scheduler.py",
        "workflow_monitor.py",
        "retry_handler.py",
        "workflow_templates.py",
        "workflow_memory.py",
        "approval_gate.py",
        "config.py",
    ],
    "Next Recommended File": "agents/workflow_agent/n8n_connector.py",
}


__all__ = [
    "WorkflowAgent",
    "WorkflowContext",
    "WorkflowStep",
    "WorkflowPlan",
    "WorkflowExecutionRecord",
    "WorkflowTaskType",
    "WorkflowStatus",
    "WorkflowStepType",
    "ConnectorName",
    "RiskLevel",
    "AGENT_CLASS",
    "AGENT_NAME",
    "AGENT_TYPE",
    "AGENT_MODULE",
    "AGENT_DESCRIPTION",
    "MODULE_COMPLETION",
]


# =============================================================================
# Completion tracking
# =============================================================================

# Agent/Module: Workflow Agent
# File Completed: workflow_agent.py
# Completion: 4.8%
# Completed Files: ['workflow_agent.py']
# Remaining Files: ['n8n_connector.py', 'workflow_builder.py', 'trigger_engine.py', 'action_router.py', 'app_connector.py', 'webhook_manager.py', 'form_pipeline.py', 'crm_connector.py', 'sheet_connector.py', 'whatsapp_connector.py', 'email_connector.py', 'notification_engine.py', 'condition_engine.py', 'scheduler.py', 'workflow_monitor.py', 'retry_handler.py', 'workflow_templates.py', 'workflow_memory.py', 'approval_gate.py', 'config.py']
# Next Recommended File: agents/workflow_agent/n8n_connector.py
# FILE COMPLETE