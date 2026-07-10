"""
agents/workflow_agent/workflow_builder.py

Workflow Builder for William / Jarvis Multi-Agent AI SaaS System.

Purpose:
    Builds trigger-action-condition-output pipelines and workflow JSON/configs.

This module is intentionally import-safe:
    - It does not require the rest of the William/Jarvis codebase to exist yet.
    - It provides fallback BaseAgent behavior when core agent modules are missing.
    - It does not execute real actions, send messages, call browsers, move money,
      modify systems, or perform destructive operations.
    - It only builds, validates, normalizes, and exports workflow definitions.

Architecture Connections:
    Master Agent:
        Can route workflow-build requests to WorkflowBuilder using public methods
        such as build_workflow(), build_from_template(), validate_pipeline(),
        export_workflow_config(), and describe_capabilities().

    Security Agent:
        Sensitive workflow definitions are detected using _requires_security_check().
        When required, _request_security_approval() creates a structured approval
        request payload. This file does not auto-approve sensitive workflows.

    Memory Agent:
        _prepare_memory_payload() produces safe workflow memory context that can
        be stored per user/workspace without mixing tenant data.

    Verification Agent:
        _prepare_verification_payload() produces a structured verification object
        describing what was built, validation results, risk level, and expected
        pipeline structure.

    Dashboard/API:
        All public methods return structured dicts with:
            success, message, data, error, metadata

    Agent Registry / Agent Loader / Agent Router:
        The class includes metadata, capabilities, public method names, and safe
        fallback inheritance for compatibility with future registry systems.

SaaS Isolation:
    Every workflow build operation requires user_id and workspace_id unless the
    caller is only requesting static capabilities. No pipeline data is shared
    across users or workspaces.

Author:
    Digital Promotix / William-Jarvis System
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union


# ---------------------------------------------------------------------------
# Safe optional imports
# ---------------------------------------------------------------------------

try:
    from agents.base_agent import BaseAgent  # type: ignore
except Exception:  # pragma: no cover - fallback for standalone import safety
    class BaseAgent:  # type: ignore
        """
        Fallback BaseAgent used when the real William/Jarvis BaseAgent
        has not been created yet.

        This keeps the file import-safe and compatible with staged generation.
        """

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.agent_name = kwargs.get("agent_name", self.__class__.__name__)
            self.agent_id = kwargs.get("agent_id", self.agent_name.lower())
            self.logger = logging.getLogger(self.agent_name)

        def emit_event(self, event_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "success": True,
                "message": "Fallback event emitted locally.",
                "data": {
                    "event_name": event_name,
                    "payload": payload,
                },
                "error": None,
                "metadata": {
                    "fallback": True,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            }


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOGGER = logging.getLogger("William.WorkflowAgent.WorkflowBuilder")
if not LOGGER.handlers:
    LOGGER.addHandler(logging.NullHandler())


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MODULE_NAME = "workflow_builder"
AGENT_MODULE = "Workflow Agent"
DEFAULT_WORKFLOW_VERSION = "1.0.0"

MAX_WORKFLOW_NAME_LENGTH = 140
MAX_STEP_NAME_LENGTH = 140
MAX_DESCRIPTION_LENGTH = 2_000
MAX_TAGS = 30
MAX_STEPS = 250
MAX_BRANCH_DEPTH = 12

SAFE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:.]{1,160}$")
SAFE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-:. /()[\]{}@+#,&|]{1,160}$")

SENSITIVE_ACTION_TYPES = {
    "send_email",
    "send_sms",
    "send_whatsapp",
    "make_call",
    "browser_submit",
    "browser_click",
    "browser_purchase",
    "payment_charge",
    "payment_refund",
    "financial_transfer",
    "delete_record",
    "delete_file",
    "archive_email",
    "delete_email",
    "crm_update",
    "crm_delete",
    "sheet_write",
    "sheet_delete",
    "webhook_post",
    "api_mutation",
    "system_command",
    "deploy_code",
    "publish_content",
    "social_post",
    "calendar_create",
    "calendar_update",
    "calendar_delete",
}

DESTRUCTIVE_ACTION_TYPES = {
    "delete_record",
    "delete_file",
    "delete_email",
    "sheet_delete",
    "crm_delete",
    "calendar_delete",
    "financial_transfer",
    "payment_charge",
    "payment_refund",
    "system_command",
    "deploy_code",
}

EXTERNAL_OUTPUT_TYPES = {
    "webhook",
    "email",
    "sms",
    "whatsapp",
    "crm",
    "sheet",
    "api",
    "notification",
    "dashboard",
}

ALLOWED_STEP_TYPES = {
    "trigger",
    "condition",
    "action",
    "output",
    "transform",
    "delay",
    "approval",
    "router",
    "merge",
}

ALLOWED_TRIGGER_TYPES = {
    "manual",
    "webhook",
    "schedule",
    "form_submission",
    "sheet_row_created",
    "sheet_row_updated",
    "crm_event",
    "email_received",
    "whatsapp_received",
    "api_event",
    "agent_event",
    "dashboard_event",
}

ALLOWED_CONDITION_OPERATORS = {
    "equals",
    "not_equals",
    "contains",
    "not_contains",
    "starts_with",
    "ends_with",
    "greater_than",
    "greater_than_or_equal",
    "less_than",
    "less_than_or_equal",
    "exists",
    "not_exists",
    "is_empty",
    "is_not_empty",
    "in",
    "not_in",
    "regex",
    "and",
    "or",
}

DEFAULT_RETRY_POLICY = {
    "enabled": True,
    "max_attempts": 3,
    "backoff_seconds": 30,
    "strategy": "exponential",
}

DEFAULT_TIMEOUT_POLICY = {
    "enabled": True,
    "timeout_seconds": 120,
}

DEFAULT_ERROR_POLICY = {
    "on_error": "stop",
    "notify": True,
    "capture_context": True,
}


# ---------------------------------------------------------------------------
# Enums and data structures
# ---------------------------------------------------------------------------

class WorkflowRiskLevel(str, Enum):
    """Workflow risk level used by security, audit, and verification layers."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class WorkflowStatus(str, Enum):
    """Internal workflow build status."""

    DRAFT = "draft"
    VALIDATED = "validated"
    SECURITY_REVIEW_REQUIRED = "security_review_required"
    READY_FOR_EXPORT = "ready_for_export"
    FAILED_VALIDATION = "failed_validation"


@dataclass
class WorkflowContext:
    """
    SaaS execution context.

    user_id and workspace_id are mandatory for all user-specific workflow builds.
    request_id and correlation_id help connect Dashboard/API logs, Master Agent
    routing, Security Agent approvals, and Verification Agent checks.
    """

    user_id: str
    workspace_id: str
    role: Optional[str] = None
    subscription_tier: Optional[str] = None
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    source: str = "workflow_builder"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ValidationIssue:
    """Validation warning/error record."""

    code: str
    message: str
    severity: str = "error"
    step_id: Optional[str] = None
    field: Optional[str] = None
    hint: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WorkflowBuildStats:
    """Summarized build statistics for verification, dashboard, and analytics."""

    total_steps: int = 0
    triggers: int = 0
    conditions: int = 0
    actions: int = 0
    outputs: int = 0
    transforms: int = 0
    approvals: int = 0
    delays: int = 0
    routers: int = 0
    merges: int = 0
    sensitive_actions: int = 0
    destructive_actions: int = 0
    external_outputs: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def utc_now_iso() -> str:
    """Return timezone-aware UTC timestamp."""

    return datetime.now(timezone.utc).isoformat()


def deep_copy_jsonable(value: Any) -> Any:
    """
    Safely deep-copy common JSON-like values.

    Falls back to json serialization to avoid accidental object reference leaks.
    """

    try:
        return copy.deepcopy(value)
    except Exception:
        try:
            return json.loads(json.dumps(value, default=str))
        except Exception:
            return str(value)


def stable_hash(value: Any) -> str:
    """Return stable SHA256 hash for a JSON-like object."""

    serialized = json.dumps(value, sort_keys=True, default=str, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def slugify(value: str, default: str = "workflow") -> str:
    """Create a safe lowercase slug."""

    cleaned = re.sub(r"[^a-zA-Z0-9_\-]+", "-", value.strip().lower())
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-_")
    return cleaned or default


def is_non_empty_string(value: Any) -> bool:
    """Return True when value is a non-empty string."""

    return isinstance(value, str) and bool(value.strip())


def safe_str(value: Any, max_length: int = 2_000) -> str:
    """Convert value to safe bounded string."""

    text = "" if value is None else str(value)
    text = text.strip()
    if len(text) > max_length:
        return text[: max_length - 3] + "..."
    return text


def sanitize_metadata(metadata: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """
    Sanitize arbitrary metadata into JSON-safe dictionary.

    This does not redact secrets by itself; secrets should never be sent here.
    Common secret-like keys are replaced defensively.
    """

    if not metadata:
        return {}

    secret_key_fragments = (
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "private_key",
        "access_key",
        "auth",
        "credential",
    )

    sanitized: Dict[str, Any] = {}
    for key, value in metadata.items():
        key_str = safe_str(key, max_length=120)
        if any(fragment in key_str.lower() for fragment in secret_key_fragments):
            sanitized[key_str] = "[REDACTED]"
        else:
            sanitized[key_str] = deep_copy_jsonable(value)
    return sanitized


# ---------------------------------------------------------------------------
# WorkflowBuilder
# ---------------------------------------------------------------------------

class WorkflowBuilder(BaseAgent):
    """
    Builds trigger-action-condition-output pipelines and workflow JSON/configs.

    Public methods:
        - describe_capabilities()
        - build_workflow()
        - build_from_template()
        - validate_pipeline()
        - export_workflow_config()
        - compile_for_n8n_like_config()
        - normalize_workflow_definition()
        - create_step()
        - create_trigger_step()
        - create_condition_step()
        - create_action_step()
        - create_output_step()

    Important:
        This class does not execute workflows. It only builds definitions.
    """

    agent_name = "WorkflowBuilder"
    agent_module = AGENT_MODULE
    file_name = "workflow_builder.py"
    version = DEFAULT_WORKFLOW_VERSION

    def __init__(
        self,
        agent_id: str = "workflow_builder",
        logger: Optional[logging.Logger] = None,
        strict_validation: bool = True,
        default_retry_policy: Optional[Dict[str, Any]] = None,
        default_timeout_policy: Optional[Dict[str, Any]] = None,
        default_error_policy: Optional[Dict[str, Any]] = None,
        enable_local_events: bool = True,
        **kwargs: Any,
    ) -> None:
        """
        Initialize WorkflowBuilder.

        Args:
            agent_id:
                Registry-friendly agent identifier.
            logger:
                Optional logger.
            strict_validation:
                When True, validation errors block successful workflow build.
            default_retry_policy:
                Default retry policy added to action/output steps.
            default_timeout_policy:
                Default timeout policy added to executable steps.
            default_error_policy:
                Default error policy added to workflow config.
            enable_local_events:
                When True, local event payloads are returned through fallback event flow.
            **kwargs:
                Forward-compatible options for future BaseAgent implementations.
        """

        try:
            super().__init__(agent_name=self.agent_name, agent_id=agent_id, **kwargs)
        except TypeError:
            super().__init__()

        self.agent_id = agent_id
        self.logger = logger or LOGGER
        self.strict_validation = strict_validation
        self.default_retry_policy = deep_copy_jsonable(default_retry_policy or DEFAULT_RETRY_POLICY)
        self.default_timeout_policy = deep_copy_jsonable(default_timeout_policy or DEFAULT_TIMEOUT_POLICY)
        self.default_error_policy = deep_copy_jsonable(default_error_policy or DEFAULT_ERROR_POLICY)
        self.enable_local_events = enable_local_events

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def describe_capabilities(self) -> Dict[str, Any]:
        """
        Return registry/dashboard-readable capabilities.

        This method does not require user_id/workspace_id because it exposes
        only static module capability information.
        """

        return self._safe_result(
            message="WorkflowBuilder capabilities loaded.",
            data={
                "agent": self.agent_name,
                "module": self.agent_module,
                "file": self.file_name,
                "version": self.version,
                "responsibilities": [
                    "Build workflow pipeline definitions",
                    "Normalize trigger/action/condition/output steps",
                    "Validate SaaS user/workspace-safe workflow configs",
                    "Detect sensitive and destructive workflow operations",
                    "Prepare Security Agent approval payloads",
                    "Prepare Verification Agent payloads",
                    "Prepare Memory Agent payloads",
                    "Export dashboard/API/n8n-like workflow JSON configs",
                ],
                "public_methods": [
                    "describe_capabilities",
                    "build_workflow",
                    "build_from_template",
                    "validate_pipeline",
                    "export_workflow_config",
                    "compile_for_n8n_like_config",
                    "normalize_workflow_definition",
                    "create_step",
                    "create_trigger_step",
                    "create_condition_step",
                    "create_action_step",
                    "create_output_step",
                ],
                "allowed_step_types": sorted(ALLOWED_STEP_TYPES),
                "allowed_trigger_types": sorted(ALLOWED_TRIGGER_TYPES),
                "security_sensitive_actions": sorted(SENSITIVE_ACTION_TYPES),
            },
            metadata={
                "import_safe": True,
                "executes_workflows": False,
                "requires_context_for_build": True,
            },
        )

    def build_workflow(
        self,
        *,
        user_id: str,
        workspace_id: str,
        name: str,
        description: str = "",
        trigger: Optional[Mapping[str, Any]] = None,
        actions: Optional[Sequence[Mapping[str, Any]]] = None,
        conditions: Optional[Sequence[Mapping[str, Any]]] = None,
        outputs: Optional[Sequence[Mapping[str, Any]]] = None,
        steps: Optional[Sequence[Mapping[str, Any]]] = None,
        edges: Optional[Sequence[Mapping[str, Any]]] = None,
        tags: Optional[Sequence[str]] = None,
        enabled: bool = False,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        workflow_id: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
        require_security_approval: Optional[bool] = None,
        requested_by_agent: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Build a full workflow definition.

        Args:
            user_id:
                SaaS user id. Required.
            workspace_id:
                SaaS workspace id. Required.
            name:
                Human-readable workflow name.
            description:
                Optional workflow description.
            trigger:
                Single trigger definition.
            actions:
                Action step definitions.
            conditions:
                Condition step definitions.
            outputs:
                Output step definitions.
            steps:
                Fully custom ordered steps. If provided, it is merged with
                trigger/actions/conditions/outputs.
            edges:
                Optional explicit graph edges.
            tags:
                Search/dashboard tags.
            enabled:
                Workflows are built disabled by default for safety.
            role:
                User role from dashboard/auth layer.
            subscription_tier:
                SaaS subscription tier.
            workflow_id:
                Optional caller-provided id. If omitted, generated safely.
            metadata:
                Extra sanitized metadata.
            require_security_approval:
                Force security review behavior. If None, auto-detected.
            requested_by_agent:
                Name/id of calling agent, usually Master Agent or Workflow Agent.

        Returns:
            Structured result with built workflow config.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        context = WorkflowContext(
            user_id=user_id.strip(),
            workspace_id=workspace_id.strip(),
            role=role,
            subscription_tier=subscription_tier,
            source=requested_by_agent or self.agent_name,
            metadata=sanitize_metadata(metadata),
        )

        try:
            workflow = {
                "workflow_id": self._normalize_workflow_id(workflow_id, name),
                "name": self._normalize_name(name, "Workflow"),
                "description": safe_str(description, MAX_DESCRIPTION_LENGTH),
                "version": self.version,
                "status": WorkflowStatus.DRAFT.value,
                "enabled": bool(enabled) and False,
                "tenant": {
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                },
                "ownership": {
                    "created_by_user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "requested_by_agent": requested_by_agent or self.agent_name,
                },
                "tags": self._normalize_tags(tags),
                "steps": [],
                "edges": [],
                "policies": {
                    "retry": deep_copy_jsonable(self.default_retry_policy),
                    "timeout": deep_copy_jsonable(self.default_timeout_policy),
                    "error": deep_copy_jsonable(self.default_error_policy),
                    "security": {
                        "requires_approval": False,
                        "approval_status": "not_required",
                        "approval_id": None,
                    },
                },
                "metadata": sanitize_metadata(metadata),
                "created_at": utc_now_iso(),
                "updated_at": utc_now_iso(),
            }

            normalized_steps = self._assemble_steps(
                trigger=trigger,
                conditions=conditions,
                actions=actions,
                outputs=outputs,
                steps=steps,
            )
            workflow["steps"] = normalized_steps
            workflow["edges"] = self._assemble_edges(normalized_steps, edges)

            stats = self._calculate_stats(workflow["steps"])
            risk_level = self._calculate_risk_level(stats, workflow["steps"])

            validation_result = self._validate_workflow_object(workflow)
            validation_issues = validation_result["data"]["issues"]

            security_required = (
                bool(require_security_approval)
                if require_security_approval is not None
                else self._requires_security_check(workflow=workflow, stats=stats, risk_level=risk_level)
            )

            if security_required:
                workflow["status"] = WorkflowStatus.SECURITY_REVIEW_REQUIRED.value
                workflow["enabled"] = False
                approval_payload = self._request_security_approval(
                    context=context,
                    workflow=workflow,
                    stats=stats,
                    risk_level=risk_level,
                    validation_issues=validation_issues,
                )
                workflow["policies"]["security"] = {
                    "requires_approval": True,
                    "approval_status": "pending",
                    "approval_id": approval_payload["data"]["approval_id"],
                }
            else:
                approval_payload = None
                workflow["status"] = (
                    WorkflowStatus.VALIDATED.value
                    if validation_result["success"]
                    else WorkflowStatus.FAILED_VALIDATION.value
                )
                workflow["policies"]["security"] = {
                    "requires_approval": False,
                    "approval_status": "not_required",
                    "approval_id": None,
                }

            workflow["integrity"] = {
                "config_hash": stable_hash(
                    {
                        "workflow_id": workflow["workflow_id"],
                        "tenant": workflow["tenant"],
                        "steps": workflow["steps"],
                        "edges": workflow["edges"],
                        "policies": workflow["policies"],
                    }
                ),
                "builder": self.agent_name,
                "builder_version": self.version,
            }

            verification_payload = self._prepare_verification_payload(
                context=context,
                workflow=workflow,
                validation_result=validation_result,
                stats=stats,
                risk_level=risk_level,
            )
            memory_payload = self._prepare_memory_payload(
                context=context,
                workflow=workflow,
                stats=stats,
                risk_level=risk_level,
            )

            audit_event = self._log_audit_event(
                context=context,
                event_type="workflow_built",
                workflow=workflow,
                risk_level=risk_level,
                stats=stats,
                success=validation_result["success"],
            )

            agent_event = self._emit_agent_event(
                event_name="workflow.builder.workflow_built",
                context=context,
                payload={
                    "workflow_id": workflow["workflow_id"],
                    "name": workflow["name"],
                    "status": workflow["status"],
                    "risk_level": risk_level.value,
                    "requires_security_approval": security_required,
                    "stats": stats.to_dict(),
                },
            )

            has_errors = any(issue.get("severity") == "error" for issue in validation_issues)
            if self.strict_validation and has_errors:
                return self._error_result(
                    message="Workflow build failed validation.",
                    error={
                        "code": "workflow_validation_failed",
                        "issues": validation_issues,
                    },
                    data={
                        "workflow": workflow,
                        "validation": validation_result["data"],
                        "security_approval": approval_payload["data"] if approval_payload else None,
                        "verification_payload": verification_payload,
                        "memory_payload": memory_payload,
                        "audit_event": audit_event,
                        "agent_event": agent_event,
                    },
                    metadata={
                        "user_id": context.user_id,
                        "workspace_id": context.workspace_id,
                        "risk_level": risk_level.value,
                        "status": workflow["status"],
                    },
                )

            return self._safe_result(
                message="Workflow built successfully."
                if not security_required
                else "Workflow built successfully and requires Security Agent approval before activation.",
                data={
                    "workflow": workflow,
                    "validation": validation_result["data"],
                    "security_approval": approval_payload["data"] if approval_payload else None,
                    "verification_payload": verification_payload,
                    "memory_payload": memory_payload,
                    "audit_event": audit_event,
                    "agent_event": agent_event,
                },
                metadata={
                    "user_id": context.user_id,
                    "workspace_id": context.workspace_id,
                    "risk_level": risk_level.value,
                    "status": workflow["status"],
                    "step_count": len(workflow["steps"]),
                    "edge_count": len(workflow["edges"]),
                },
            )

        except Exception as exc:
            self.logger.exception("Workflow build failed.")
            return self._error_result(
                message="Unexpected error while building workflow.",
                error={
                    "code": "workflow_build_exception",
                    "detail": str(exc),
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "module": MODULE_NAME,
                },
            )

    def build_from_template(
        self,
        *,
        user_id: str,
        workspace_id: str,
        template_name: str,
        variables: Optional[Mapping[str, Any]] = None,
        name: Optional[str] = None,
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build workflow from a built-in safe template.

        Supported templates:
            - form_to_sheet_notification
            - form_to_crm_whatsapp
            - scheduled_report_email
            - webhook_to_agent_event
        """

        variables_safe = sanitize_metadata(variables)
        template_key = slugify(template_name, default="template").replace("-", "_")

        templates = self._builtin_templates()
        if template_key not in templates:
            return self._error_result(
                message="Unknown workflow template.",
                error={
                    "code": "unknown_template",
                    "template_name": template_name,
                    "available_templates": sorted(templates.keys()),
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        template = deep_copy_jsonable(templates[template_key])
        rendered = self._render_template(template, variables_safe)

        return self.build_workflow(
            user_id=user_id,
            workspace_id=workspace_id,
            name=name or rendered.get("name") or template_name,
            description=rendered.get("description", ""),
            trigger=rendered.get("trigger"),
            conditions=rendered.get("conditions"),
            actions=rendered.get("actions"),
            outputs=rendered.get("outputs"),
            tags=rendered.get("tags", []),
            enabled=False,
            role=role,
            subscription_tier=subscription_tier,
            metadata={
                **sanitize_metadata(metadata),
                "template_name": template_key,
                "template_variables_hash": stable_hash(variables_safe),
            },
            requested_by_agent="workflow_template",
        )

    def validate_pipeline(
        self,
        *,
        user_id: str,
        workspace_id: str,
        workflow: Mapping[str, Any],
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate a workflow config without rebuilding it.

        Useful for Dashboard/API preflight checks and Workflow Agent edits.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        try:
            workflow_copy = deep_copy_jsonable(dict(workflow))
            tenant = workflow_copy.get("tenant", {})
            issues: List[ValidationIssue] = []

            if tenant.get("user_id") and tenant.get("user_id") != user_id:
                issues.append(
                    ValidationIssue(
                        code="tenant_user_mismatch",
                        message="Workflow user_id does not match validation context.",
                        severity="error",
                        field="tenant.user_id",
                    )
                )

            if tenant.get("workspace_id") and tenant.get("workspace_id") != workspace_id:
                issues.append(
                    ValidationIssue(
                        code="tenant_workspace_mismatch",
                        message="Workflow workspace_id does not match validation context.",
                        severity="error",
                        field="tenant.workspace_id",
                    )
                )

            validation = self._validate_workflow_object(workflow_copy)
            workflow_issues = [
                ValidationIssue(
                    code=item.get("code", "validation_issue"),
                    message=item.get("message", "Validation issue."),
                    severity=item.get("severity", "error"),
                    step_id=item.get("step_id"),
                    field=item.get("field"),
                    hint=item.get("hint"),
                )
                for item in validation["data"].get("issues", [])
            ]
            issues.extend(workflow_issues)

            stats = self._calculate_stats(workflow_copy.get("steps", []))
            risk_level = self._calculate_risk_level(stats, workflow_copy.get("steps", []))
            security_required = self._requires_security_check(
                workflow=workflow_copy,
                stats=stats,
                risk_level=risk_level,
            )

            has_errors = any(issue.severity == "error" for issue in issues)

            return self._safe_result(
                message="Pipeline validation completed."
                if not has_errors
                else "Pipeline validation completed with errors.",
                data={
                    "valid": not has_errors,
                    "issues": [issue.to_dict() for issue in issues],
                    "stats": stats.to_dict(),
                    "risk_level": risk_level.value,
                    "requires_security_approval": security_required,
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "issue_count": len(issues),
                },
            )

        except Exception as exc:
            self.logger.exception("Pipeline validation failed.")
            return self._error_result(
                message="Unexpected error while validating pipeline.",
                error={
                    "code": "pipeline_validation_exception",
                    "detail": str(exc),
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

    def export_workflow_config(
        self,
        *,
        user_id: str,
        workspace_id: str,
        workflow: Mapping[str, Any],
        export_format: str = "william_json",
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Export workflow config for dashboard/API/connector usage.

        Supported export formats:
            - william_json
            - dashboard_json
            - n8n_like_json

        This method does not activate or execute the workflow.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        validation = self.validate_pipeline(
            user_id=user_id,
            workspace_id=workspace_id,
            workflow=workflow,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not validation["success"]:
            return validation

        export_format_normalized = slugify(export_format, default="william_json").replace("-", "_")
        workflow_copy = deep_copy_jsonable(dict(workflow))

        if export_format_normalized == "william_json":
            exported = workflow_copy
        elif export_format_normalized == "dashboard_json":
            exported = self._compile_dashboard_config(workflow_copy)
        elif export_format_normalized == "n8n_like_json":
            compiled = self.compile_for_n8n_like_config(
                user_id=user_id,
                workspace_id=workspace_id,
                workflow=workflow_copy,
                role=role,
                subscription_tier=subscription_tier,
                metadata=metadata,
            )
            if not compiled["success"]:
                return compiled
            exported = compiled["data"]["n8n_like_config"]
        else:
            return self._error_result(
                message="Unsupported workflow export format.",
                error={
                    "code": "unsupported_export_format",
                    "export_format": export_format,
                    "supported_formats": [
                        "william_json",
                        "dashboard_json",
                        "n8n_like_json",
                    ],
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                },
            )

        return self._safe_result(
            message="Workflow config exported successfully.",
            data={
                "export_format": export_format_normalized,
                "config": exported,
                "config_hash": stable_hash(exported),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "workflow_id": workflow_copy.get("workflow_id"),
                "executes_workflow": False,
            },
        )

    def compile_for_n8n_like_config(
        self,
        *,
        user_id: str,
        workspace_id: str,
        workflow: Mapping[str, Any],
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Compile William workflow object into n8n-like JSON structure.

        This is connector-ready but does not call n8n or activate anything.
        The future n8n_connector.py can consume this config safely.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        workflow_copy = deep_copy_jsonable(dict(workflow))
        steps = workflow_copy.get("steps", [])
        edges = workflow_copy.get("edges", [])

        nodes: List[Dict[str, Any]] = []
        connections: Dict[str, Dict[str, List[List[Dict[str, Any]]]]] = {}

        for index, step in enumerate(steps):
            step_id = step.get("step_id", f"step_{index + 1}")
            node_name = step.get("name", step_id)
            node_type = self._map_step_to_n8n_like_type(step)
            nodes.append(
                {
                    "id": step_id,
                    "name": node_name,
                    "type": node_type,
                    "typeVersion": 1,
                    "position": [
                        280 + (index * 260),
                        280 + ((index % 3) * 120),
                    ],
                    "parameters": deep_copy_jsonable(step.get("config", {})),
                    "credentials": {},
                    "disabled": bool(step.get("disabled", False)),
                    "notes": safe_str(step.get("description", ""), 500),
                    "william": {
                        "step_type": step.get("step_type"),
                        "operation": step.get("operation"),
                        "risk_level": step.get("risk_level", WorkflowRiskLevel.LOW.value),
                        "requires_security_approval": bool(step.get("requires_security_approval", False)),
                    },
                }
            )

        for edge in edges:
            from_id = edge.get("from")
            to_id = edge.get("to")
            if not from_id or not to_id:
                continue

            connections.setdefault(from_id, {"main": [[]]})
            connections[from_id]["main"][0].append(
                {
                    "node": to_id,
                    "type": "main",
                    "index": 0,
                }
            )

        n8n_like_config = {
            "name": workflow_copy.get("name", "William Workflow"),
            "active": False,
            "nodes": nodes,
            "connections": connections,
            "settings": {
                "executionOrder": "v1",
                "saveManualExecutions": True,
                "callerPolicy": "workflowsFromSameOwner",
            },
            "staticData": {
                "william": {
                    "workflow_id": workflow_copy.get("workflow_id"),
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "source": MODULE_NAME,
                    "compiled_at": utc_now_iso(),
                    "config_hash": stable_hash(workflow_copy),
                }
            },
            "tags": workflow_copy.get("tags", []),
            "versionId": str(uuid.uuid4()),
            "meta": {
                "templateCredsSetupCompleted": False,
                "william_builder_version": self.version,
            },
        }

        return self._safe_result(
            message="Workflow compiled into n8n-like JSON config.",
            data={
                "n8n_like_config": n8n_like_config,
                "node_count": len(nodes),
                "connection_count": sum(
                    len(outputs)
                    for connection in connections.values()
                    for output_groups in connection.values()
                    for outputs in output_groups
                ),
            },
            metadata={
                "user_id": user_id,
                "workspace_id": workspace_id,
                "workflow_id": workflow_copy.get("workflow_id"),
                "active": False,
                "executes_workflow": False,
            },
        )

    def normalize_workflow_definition(
        self,
        *,
        user_id: str,
        workspace_id: str,
        workflow: Mapping[str, Any],
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Normalize a raw workflow-like dictionary into William format.

        Useful for dashboard edits, imported configs, and future API requests.
        """

        context_result = self._validate_task_context(
            user_id=user_id,
            workspace_id=workspace_id,
            role=role,
            subscription_tier=subscription_tier,
            metadata=metadata,
        )
        if not context_result["success"]:
            return context_result

        raw = deep_copy_jsonable(dict(workflow))

        return self.build_workflow(
            user_id=user_id,
            workspace_id=workspace_id,
            workflow_id=raw.get("workflow_id") or raw.get("id"),
            name=raw.get("name", "Imported Workflow"),
            description=raw.get("description", ""),
            steps=raw.get("steps", []),
            edges=raw.get("edges", []),
            tags=raw.get("tags", []),
            enabled=False,
            role=role,
            subscription_tier=subscription_tier,
            metadata={
                **sanitize_metadata(metadata),
                "normalized_from": raw.get("source", "raw_workflow_definition"),
            },
            requested_by_agent="workflow_normalizer",
        )

    def create_step(
        self,
        *,
        step_type: str,
        operation: str,
        name: Optional[str] = None,
        config: Optional[Mapping[str, Any]] = None,
        step_id: Optional[str] = None,
        description: str = "",
        depends_on: Optional[Sequence[str]] = None,
        next_steps: Optional[Sequence[str]] = None,
        disabled: bool = False,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Create a normalized workflow step object.

        This helper is safe to use by other Workflow Agent files such as
        trigger_engine.py, action_router.py, condition_engine.py, scheduler.py,
        workflow_templates.py, and dashboard/API layers.
        """

        try:
            step = self._normalize_step(
                raw_step={
                    "step_id": step_id,
                    "step_type": step_type,
                    "operation": operation,
                    "name": name or operation,
                    "description": description,
                    "config": config or {},
                    "depends_on": list(depends_on or []),
                    "next_steps": list(next_steps or []),
                    "disabled": disabled,
                    "metadata": sanitize_metadata(metadata),
                },
                index=0,
            )
            return self._safe_result(
                message="Workflow step created.",
                data={"step": step},
                metadata={
                    "step_id": step["step_id"],
                    "step_type": step["step_type"],
                    "operation": step["operation"],
                },
            )
        except Exception as exc:
            return self._error_result(
                message="Failed to create workflow step.",
                error={
                    "code": "create_step_failed",
                    "detail": str(exc),
                },
            )

    def create_trigger_step(
        self,
        *,
        trigger_type: str,
        name: Optional[str] = None,
        config: Optional[Mapping[str, Any]] = None,
        step_id: Optional[str] = None,
        description: str = "",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a trigger step."""

        return self.create_step(
            step_type="trigger",
            operation=trigger_type,
            name=name or f"{trigger_type} trigger",
            config=config,
            step_id=step_id,
            description=description,
            metadata=metadata,
        )

    def create_condition_step(
        self,
        *,
        operator: str,
        left: Optional[Any] = None,
        right: Optional[Any] = None,
        name: Optional[str] = None,
        config: Optional[Mapping[str, Any]] = None,
        step_id: Optional[str] = None,
        description: str = "",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create a condition step."""

        condition_config = {
            "operator": operator,
            "left": left,
            "right": right,
        }
        if config:
            condition_config.update(sanitize_metadata(config))

        return self.create_step(
            step_type="condition",
            operation=operator,
            name=name or f"{operator} condition",
            config=condition_config,
            step_id=step_id,
            description=description,
            metadata=metadata,
        )

    def create_action_step(
        self,
        *,
        action_type: str,
        name: Optional[str] = None,
        config: Optional[Mapping[str, Any]] = None,
        step_id: Optional[str] = None,
        description: str = "",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create an action step."""

        return self.create_step(
            step_type="action",
            operation=action_type,
            name=name or f"{action_type} action",
            config=config,
            step_id=step_id,
            description=description,
            metadata=metadata,
        )

    def create_output_step(
        self,
        *,
        output_type: str,
        name: Optional[str] = None,
        config: Optional[Mapping[str, Any]] = None,
        step_id: Optional[str] = None,
        description: str = "",
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Create an output step."""

        return self.create_step(
            step_type="output",
            operation=output_type,
            name=name or f"{output_type} output",
            config=config,
            step_id=step_id,
            description=description,
            metadata=metadata,
        )

    # -----------------------------------------------------------------------
    # Required compatibility hooks
    # -----------------------------------------------------------------------

    def _validate_task_context(
        self,
        *,
        user_id: Optional[str],
        workspace_id: Optional[str],
        role: Optional[str] = None,
        subscription_tier: Optional[str] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Validate SaaS task context.

        Required by William/Jarvis architecture.
        """

        issues: List[ValidationIssue] = []

        if not is_non_empty_string(user_id):
            issues.append(
                ValidationIssue(
                    code="missing_user_id",
                    message="user_id is required for workflow build operations.",
                    severity="error",
                    field="user_id",
                )
            )
        elif not SAFE_ID_PATTERN.match(str(user_id).strip()):
            issues.append(
                ValidationIssue(
                    code="invalid_user_id",
                    message="user_id contains unsupported characters.",
                    severity="error",
                    field="user_id",
                )
            )

        if not is_non_empty_string(workspace_id):
            issues.append(
                ValidationIssue(
                    code="missing_workspace_id",
                    message="workspace_id is required for workflow build operations.",
                    severity="error",
                    field="workspace_id",
                )
            )
        elif not SAFE_ID_PATTERN.match(str(workspace_id).strip()):
            issues.append(
                ValidationIssue(
                    code="invalid_workspace_id",
                    message="workspace_id contains unsupported characters.",
                    severity="error",
                    field="workspace_id",
                )
            )

        if role is not None and not is_non_empty_string(role):
            issues.append(
                ValidationIssue(
                    code="invalid_role",
                    message="role must be a non-empty string when provided.",
                    severity="warning",
                    field="role",
                )
            )

        if subscription_tier is not None and not is_non_empty_string(subscription_tier):
            issues.append(
                ValidationIssue(
                    code="invalid_subscription_tier",
                    message="subscription_tier must be a non-empty string when provided.",
                    severity="warning",
                    field="subscription_tier",
                )
            )

        sanitized = sanitize_metadata(metadata)
        has_errors = any(issue.severity == "error" for issue in issues)

        if has_errors:
            return self._error_result(
                message="Invalid workflow task context.",
                error={
                    "code": "invalid_task_context",
                    "issues": [issue.to_dict() for issue in issues],
                },
                metadata={
                    "user_id": user_id,
                    "workspace_id": workspace_id,
                    "metadata": sanitized,
                },
            )

        return self._safe_result(
            message="Workflow task context validated.",
            data={
                "user_id": str(user_id).strip(),
                "workspace_id": str(workspace_id).strip(),
                "role": role,
                "subscription_tier": subscription_tier,
                "issues": [issue.to_dict() for issue in issues],
            },
            metadata=sanitized,
        )

    def _requires_security_check(
        self,
        *,
        workflow: Mapping[str, Any],
        stats: Optional[WorkflowBuildStats] = None,
        risk_level: Optional[WorkflowRiskLevel] = None,
    ) -> bool:
        """
        Return True when Security Agent approval is required.

        Required by William/Jarvis architecture.
        """

        if risk_level in {WorkflowRiskLevel.HIGH, WorkflowRiskLevel.CRITICAL}:
            return True

        computed_stats = stats or self._calculate_stats(workflow.get("steps", []))
        if computed_stats.sensitive_actions > 0:
            return True
        if computed_stats.destructive_actions > 0:
            return True
        if computed_stats.external_outputs > 2:
            return True

        for step in workflow.get("steps", []):
            if step.get("requires_security_approval") is True:
                return True
            if step.get("operation") in SENSITIVE_ACTION_TYPES:
                return True
            if step.get("operation") in DESTRUCTIVE_ACTION_TYPES:
                return True

        return False

    def _request_security_approval(
        self,
        *,
        context: WorkflowContext,
        workflow: Mapping[str, Any],
        stats: WorkflowBuildStats,
        risk_level: WorkflowRiskLevel,
        validation_issues: Sequence[Mapping[str, Any]],
    ) -> Dict[str, Any]:
        """
        Prepare Security Agent approval payload.

        This file does not call or bypass Security Agent. The returned payload
        can be forwarded by Master Agent or Workflow Agent.
        """

        approval_id = f"sec_approval_{uuid.uuid4().hex}"
        sensitive_steps = [
            {
                "step_id": step.get("step_id"),
                "name": step.get("name"),
                "step_type": step.get("step_type"),
                "operation": step.get("operation"),
                "risk_level": step.get("risk_level"),
            }
            for step in workflow.get("steps", [])
            if step.get("requires_security_approval") is True
            or step.get("operation") in SENSITIVE_ACTION_TYPES
            or step.get("operation") in DESTRUCTIVE_ACTION_TYPES
        ]

        payload = {
            "approval_id": approval_id,
            "approval_type": "workflow_build_security_review",
            "status": "pending",
            "requested_at": utc_now_iso(),
            "requested_by": self.agent_name,
            "target_agent": "SecurityAgent",
            "context": asdict(context),
            "workflow": {
                "workflow_id": workflow.get("workflow_id"),
                "name": workflow.get("name"),
                "description": workflow.get("description"),
                "enabled": False,
                "status": WorkflowStatus.SECURITY_REVIEW_REQUIRED.value,
            },
            "risk": {
                "risk_level": risk_level.value,
                "stats": stats.to_dict(),
                "sensitive_steps": sensitive_steps,
            },
            "validation": {
                "issues": deep_copy_jsonable(validation_issues),
                "has_errors": any(issue.get("severity") == "error" for issue in validation_issues),
            },
            "required_decision": {
                "allowed_decisions": ["approve", "reject", "request_changes"],
                "activation_allowed_without_approval": False,
            },
        }

        return self._safe_result(
            message="Security approval payload prepared.",
            data=payload,
            metadata={
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
                "approval_id": approval_id,
            },
        )

    def _prepare_verification_payload(
        self,
        *,
        context: WorkflowContext,
        workflow: Mapping[str, Any],
        validation_result: Mapping[str, Any],
        stats: WorkflowBuildStats,
        risk_level: WorkflowRiskLevel,
    ) -> Dict[str, Any]:
        """
        Prepare Verification Agent payload.

        Required by William/Jarvis architecture.
        """

        return {
            "verification_type": "workflow_build_verification",
            "target_agent": "VerificationAgent",
            "prepared_by": self.agent_name,
            "prepared_at": utc_now_iso(),
            "context": asdict(context),
            "workflow_id": workflow.get("workflow_id"),
            "workflow_name": workflow.get("name"),
            "workflow_status": workflow.get("status"),
            "enabled": workflow.get("enabled", False),
            "risk_level": risk_level.value,
            "stats": stats.to_dict(),
            "validation": deep_copy_jsonable(validation_result.get("data", {})),
            "expected_structure": {
                "has_trigger": stats.triggers > 0,
                "has_action_or_output": stats.actions > 0 or stats.outputs > 0,
                "step_count": stats.total_steps,
                "edge_count": len(workflow.get("edges", [])),
            },
            "integrity": workflow.get("integrity", {}),
            "checks_requested": [
                "tenant_isolation",
                "step_schema",
                "edge_integrity",
                "security_policy",
                "sensitive_action_review",
                "activation_safety",
            ],
        }

    def _prepare_memory_payload(
        self,
        *,
        context: WorkflowContext,
        workflow: Mapping[str, Any],
        stats: WorkflowBuildStats,
        risk_level: WorkflowRiskLevel,
    ) -> Dict[str, Any]:
        """
        Prepare Memory Agent payload.

        Stores only safe workflow summary/context, never secrets.
        """

        return {
            "memory_type": "workflow_definition_summary",
            "target_agent": "MemoryAgent",
            "prepared_by": self.agent_name,
            "prepared_at": utc_now_iso(),
            "tenant": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
            },
            "workflow": {
                "workflow_id": workflow.get("workflow_id"),
                "name": workflow.get("name"),
                "description": workflow.get("description"),
                "status": workflow.get("status"),
                "enabled": workflow.get("enabled", False),
                "tags": workflow.get("tags", []),
                "risk_level": risk_level.value,
                "stats": stats.to_dict(),
            },
            "summary": self._summarize_workflow(workflow),
            "retention_hint": "workspace_scoped_workflow_context",
            "safe_to_store": True,
        }

    def _emit_agent_event(
        self,
        *,
        event_name: str,
        context: WorkflowContext,
        payload: Mapping[str, Any],
    ) -> Dict[str, Any]:
        """
        Emit or prepare an agent event.

        Required by William/Jarvis architecture.
        """

        event = {
            "event_id": f"evt_{uuid.uuid4().hex}",
            "event_name": event_name,
            "emitted_by": self.agent_name,
            "emitted_at": utc_now_iso(),
            "context": asdict(context),
            "payload": deep_copy_jsonable(payload),
        }

        if not self.enable_local_events:
            return {
                "success": True,
                "message": "Agent event prepared but local event emission is disabled.",
                "data": event,
                "error": None,
                "metadata": {
                    "local_emit": False,
                },
            }

        try:
            if hasattr(super(), "emit_event"):
                emitted = super().emit_event(event_name, event)  # type: ignore[misc]
                if isinstance(emitted, dict):
                    return emitted
        except Exception:
            self.logger.debug("BaseAgent emit_event unavailable; returning local event payload.")

        return {
            "success": True,
            "message": "Agent event prepared locally.",
            "data": event,
            "error": None,
            "metadata": {
                "local_emit": True,
            },
        }

    def _log_audit_event(
        self,
        *,
        context: WorkflowContext,
        event_type: str,
        workflow: Mapping[str, Any],
        risk_level: WorkflowRiskLevel,
        stats: WorkflowBuildStats,
        success: bool,
    ) -> Dict[str, Any]:
        """
        Prepare audit event.

        Required by William/Jarvis architecture.
        """

        audit_event = {
            "audit_id": f"audit_{uuid.uuid4().hex}",
            "event_type": event_type,
            "agent": self.agent_name,
            "module": MODULE_NAME,
            "timestamp": utc_now_iso(),
            "success": bool(success),
            "tenant": {
                "user_id": context.user_id,
                "workspace_id": context.workspace_id,
            },
            "request": {
                "request_id": context.request_id,
                "correlation_id": context.correlation_id,
                "source": context.source,
            },
            "workflow": {
                "workflow_id": workflow.get("workflow_id"),
                "name": workflow.get("name"),
                "status": workflow.get("status"),
                "enabled": workflow.get("enabled", False),
                "config_hash": workflow.get("integrity", {}).get("config_hash"),
            },
            "risk": {
                "risk_level": risk_level.value,
                "stats": stats.to_dict(),
                "requires_security_approval": workflow.get("policies", {})
                .get("security", {})
                .get("requires_approval", False),
            },
        }

        self.logger.info(
            "WorkflowBuilder audit event prepared: %s",
            json.dumps(
                {
                    "audit_id": audit_event["audit_id"],
                    "event_type": event_type,
                    "workflow_id": workflow.get("workflow_id"),
                    "success": success,
                    "risk_level": risk_level.value,
                },
                default=str,
            ),
        )

        return audit_event

    def _safe_result(
        self,
        *,
        message: str,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard success response.

        Required by William/Jarvis architecture.
        """

        return {
            "success": True,
            "message": message,
            "data": data if data is not None else {},
            "error": None,
            "metadata": {
                "agent": self.agent_name,
                "module": MODULE_NAME,
                "timestamp": utc_now_iso(),
                **sanitize_metadata(metadata),
            },
        }

    def _error_result(
        self,
        *,
        message: str,
        error: Optional[Any] = None,
        data: Optional[Any] = None,
        metadata: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Return standard error response.

        Required by William/Jarvis architecture.
        """

        return {
            "success": False,
            "message": message,
            "data": data if data is not None else {},
            "error": error if error is not None else {"code": "unknown_error"},
            "metadata": {
                "agent": self.agent_name,
                "module": MODULE_NAME,
                "timestamp": utc_now_iso(),
                **sanitize_metadata(metadata),
            },
        }

    # -----------------------------------------------------------------------
    # Internal normalization
    # -----------------------------------------------------------------------

    def _normalize_workflow_id(self, workflow_id: Optional[str], name: str) -> str:
        """Normalize or generate workflow id."""

        if workflow_id and SAFE_ID_PATTERN.match(workflow_id):
            return workflow_id

        name_slug = slugify(name, default="workflow")
        return f"wf_{name_slug}_{uuid.uuid4().hex[:12]}"

    def _normalize_name(self, name: Any, default: str) -> str:
        """Normalize display name."""

        if not is_non_empty_string(name):
            return default
        normalized = safe_str(name, MAX_WORKFLOW_NAME_LENGTH)
        if not SAFE_NAME_PATTERN.match(normalized):
            normalized = re.sub(r"[^a-zA-Z0-9_\-:. /()[\]{}@+#,&|]", "", normalized)
            normalized = normalized.strip()
        return normalized[:MAX_WORKFLOW_NAME_LENGTH] or default

    def _normalize_tags(self, tags: Optional[Sequence[str]]) -> List[str]:
        """Normalize tags."""

        result: List[str] = []
        for tag in tags or []:
            if not is_non_empty_string(tag):
                continue
            clean = slugify(str(tag), default="tag")
            if clean not in result:
                result.append(clean)
            if len(result) >= MAX_TAGS:
                break
        return result

    def _assemble_steps(
        self,
        *,
        trigger: Optional[Mapping[str, Any]],
        conditions: Optional[Sequence[Mapping[str, Any]]],
        actions: Optional[Sequence[Mapping[str, Any]]],
        outputs: Optional[Sequence[Mapping[str, Any]]],
        steps: Optional[Sequence[Mapping[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """Assemble ordered steps from separate sections and custom steps."""

        raw_steps: List[Mapping[str, Any]] = []

        if trigger:
            trigger_step = dict(trigger)
            trigger_step.setdefault("step_type", "trigger")
            raw_steps.append(trigger_step)

        for condition in conditions or []:
            condition_step = dict(condition)
            condition_step.setdefault("step_type", "condition")
            raw_steps.append(condition_step)

        for action in actions or []:
            action_step = dict(action)
            action_step.setdefault("step_type", "action")
            raw_steps.append(action_step)

        for output in outputs or []:
            output_step = dict(output)
            output_step.setdefault("step_type", "output")
            raw_steps.append(output_step)

        for custom_step in steps or []:
            raw_steps.append(dict(custom_step))

        normalized: List[Dict[str, Any]] = []
        seen_ids: set[str] = set()

        for index, raw_step in enumerate(raw_steps):
            step = self._normalize_step(raw_step=raw_step, index=index)
            original_id = step["step_id"]
            deduped_id = original_id
            counter = 2
            while deduped_id in seen_ids:
                deduped_id = f"{original_id}_{counter}"
                counter += 1
            step["step_id"] = deduped_id
            seen_ids.add(deduped_id)
            normalized.append(step)

        return normalized

    def _normalize_step(self, *, raw_step: Mapping[str, Any], index: int) -> Dict[str, Any]:
        """Normalize a raw step."""

        step_type = safe_str(raw_step.get("step_type") or raw_step.get("type") or "action", 80).lower()
        operation = safe_str(
            raw_step.get("operation")
            or raw_step.get("action_type")
            or raw_step.get("trigger_type")
            or raw_step.get("output_type")
            or raw_step.get("operator")
            or raw_step.get("name")
            or step_type,
            120,
        )
        operation_slug = slugify(operation, default=step_type).replace("-", "_")

        step_id_raw = raw_step.get("step_id") or raw_step.get("id")
        if step_id_raw and SAFE_ID_PATTERN.match(str(step_id_raw)):
            step_id = str(step_id_raw)
        else:
            step_id = f"{step_type}_{operation_slug}_{index + 1}"

        name = self._normalize_name(raw_step.get("name") or operation_slug, f"{step_type.title()} {index + 1}")
        description = safe_str(raw_step.get("description", ""), MAX_DESCRIPTION_LENGTH)
        config = sanitize_metadata(raw_step.get("config", {}))
        metadata = sanitize_metadata(raw_step.get("metadata", {}))

        retry_policy = deep_copy_jsonable(raw_step.get("retry_policy", self.default_retry_policy))
        timeout_policy = deep_copy_jsonable(raw_step.get("timeout_policy", self.default_timeout_policy))

        requires_security = (
            bool(raw_step.get("requires_security_approval", False))
            or operation_slug in SENSITIVE_ACTION_TYPES
            or operation_slug in DESTRUCTIVE_ACTION_TYPES
        )

        risk_level = self._step_risk_level(
            step_type=step_type,
            operation=operation_slug,
            config=config,
            requires_security=requires_security,
        )

        step = {
            "step_id": step_id,
            "step_type": step_type,
            "operation": operation_slug,
            "name": name,
            "description": description,
            "config": config,
            "depends_on": self._normalize_id_list(raw_step.get("depends_on", [])),
            "next_steps": self._normalize_id_list(raw_step.get("next_steps", [])),
            "disabled": bool(raw_step.get("disabled", False)),
            "requires_security_approval": requires_security,
            "risk_level": risk_level.value,
            "retry_policy": retry_policy,
            "timeout_policy": timeout_policy,
            "metadata": metadata,
            "created_at": utc_now_iso(),
        }

        if step_type == "condition":
            step["condition"] = self._normalize_condition(step)

        if step_type == "trigger":
            step["trigger"] = {
                "trigger_type": operation_slug,
                "allowed": operation_slug in ALLOWED_TRIGGER_TYPES,
            }

        return step

    def _normalize_condition(self, step: Mapping[str, Any]) -> Dict[str, Any]:
        """Normalize condition config."""

        config = dict(step.get("config", {}))
        operator = safe_str(config.get("operator") or step.get("operation") or "equals", 80)
        operator = slugify(operator, default="equals").replace("-", "_")

        return {
            "operator": operator,
            "left": deep_copy_jsonable(config.get("left")),
            "right": deep_copy_jsonable(config.get("right")),
            "valid_operator": operator in ALLOWED_CONDITION_OPERATORS,
        }

    def _normalize_id_list(self, values: Any) -> List[str]:
        """Normalize list of IDs."""

        if values is None:
            return []
        if isinstance(values, str):
            values = [values]
        if not isinstance(values, Iterable):
            return []

        result: List[str] = []
        for value in values:
            value_str = safe_str(value, 160)
            if value_str and SAFE_ID_PATTERN.match(value_str):
                result.append(value_str)
        return result

    def _assemble_edges(
        self,
        steps: Sequence[Mapping[str, Any]],
        edges: Optional[Sequence[Mapping[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """
        Assemble graph edges.

        If explicit edges are provided, they are normalized.
        Otherwise sequential edges are generated from ordered steps.
        """

        step_ids = [step["step_id"] for step in steps if step.get("step_id")]
        valid_ids = set(step_ids)
        normalized_edges: List[Dict[str, Any]] = []

        if edges:
            for index, edge in enumerate(edges):
                from_id = safe_str(edge.get("from") or edge.get("source"), 160)
                to_id = safe_str(edge.get("to") or edge.get("target"), 160)
                if not from_id or not to_id:
                    continue
                normalized_edges.append(
                    {
                        "edge_id": safe_str(edge.get("edge_id") or f"edge_{index + 1}", 160),
                        "from": from_id,
                        "to": to_id,
                        "condition": sanitize_metadata(edge.get("condition", {})),
                        "label": safe_str(edge.get("label", ""), 160),
                        "valid": from_id in valid_ids and to_id in valid_ids,
                    }
                )
            return normalized_edges

        for index in range(max(0, len(step_ids) - 1)):
            normalized_edges.append(
                {
                    "edge_id": f"edge_{index + 1}",
                    "from": step_ids[index],
                    "to": step_ids[index + 1],
                    "condition": {},
                    "label": "next",
                    "valid": True,
                }
            )

        return normalized_edges

    # -----------------------------------------------------------------------
    # Validation
    # -----------------------------------------------------------------------

    def _validate_workflow_object(self, workflow: Mapping[str, Any]) -> Dict[str, Any]:
        """Validate a normalized workflow object."""

        issues: List[ValidationIssue] = []

        workflow_id = workflow.get("workflow_id")
        name = workflow.get("name")
        tenant = workflow.get("tenant", {})
        steps = workflow.get("steps", [])
        edges = workflow.get("edges", [])

        if not is_non_empty_string(workflow_id):
            issues.append(
                ValidationIssue(
                    code="missing_workflow_id",
                    message="workflow_id is required.",
                    severity="error",
                    field="workflow_id",
                )
            )
        elif not SAFE_ID_PATTERN.match(str(workflow_id)):
            issues.append(
                ValidationIssue(
                    code="invalid_workflow_id",
                    message="workflow_id contains unsupported characters.",
                    severity="error",
                    field="workflow_id",
                )
            )

        if not is_non_empty_string(name):
            issues.append(
                ValidationIssue(
                    code="missing_workflow_name",
                    message="Workflow name is required.",
                    severity="error",
                    field="name",
                )
            )

        if not tenant.get("user_id"):
            issues.append(
                ValidationIssue(
                    code="missing_tenant_user_id",
                    message="Workflow tenant.user_id is required.",
                    severity="error",
                    field="tenant.user_id",
                )
            )

        if not tenant.get("workspace_id"):
            issues.append(
                ValidationIssue(
                    code="missing_tenant_workspace_id",
                    message="Workflow tenant.workspace_id is required.",
                    severity="error",
                    field="tenant.workspace_id",
                )
            )

        if not isinstance(steps, list):
            issues.append(
                ValidationIssue(
                    code="invalid_steps",
                    message="Workflow steps must be a list.",
                    severity="error",
                    field="steps",
                )
            )
            steps = []

        if len(steps) == 0:
            issues.append(
                ValidationIssue(
                    code="no_steps",
                    message="Workflow must include at least one step.",
                    severity="error",
                    field="steps",
                )
            )

        if len(steps) > MAX_STEPS:
            issues.append(
                ValidationIssue(
                    code="too_many_steps",
                    message=f"Workflow cannot exceed {MAX_STEPS} steps.",
                    severity="error",
                    field="steps",
                )
            )

        step_ids: set[str] = set()
        trigger_count = 0

        for index, step in enumerate(steps):
            step_issues = self._validate_step(step, index=index)
            issues.extend(step_issues)

            step_id = step.get("step_id")
            if step_id:
                if step_id in step_ids:
                    issues.append(
                        ValidationIssue(
                            code="duplicate_step_id",
                            message="Duplicate step_id found.",
                            severity="error",
                            step_id=step_id,
                            field="steps.step_id",
                        )
                    )
                step_ids.add(step_id)

            if step.get("step_type") == "trigger":
                trigger_count += 1

        if trigger_count == 0:
            issues.append(
                ValidationIssue(
                    code="missing_trigger",
                    message="Workflow should include at least one trigger step.",
                    severity="warning",
                    field="steps",
                    hint="Add a manual, webhook, schedule, form_submission, or agent_event trigger.",
                )
            )

        edge_issues = self._validate_edges(edges=edges, step_ids=step_ids)
        issues.extend(edge_issues)

        has_errors = any(issue.severity == "error" for issue in issues)

        return self._safe_result(
            message="Workflow object validation completed.",
            data={
                "valid": not has_errors,
                "issues": [issue.to_dict() for issue in issues],
                "issue_count": len(issues),
                "error_count": sum(1 for issue in issues if issue.severity == "error"),
                "warning_count": sum(1 for issue in issues if issue.severity == "warning"),
            },
            metadata={
                "workflow_id": workflow_id,
            },
        )

    def _validate_step(self, step: Mapping[str, Any], *, index: int) -> List[ValidationIssue]:
        """Validate one step."""

        issues: List[ValidationIssue] = []
        step_id = step.get("step_id")
        step_type = step.get("step_type")
        operation = step.get("operation")
        config = step.get("config", {})

        if not is_non_empty_string(step_id):
            issues.append(
                ValidationIssue(
                    code="missing_step_id",
                    message="Step is missing step_id.",
                    severity="error",
                    field=f"steps[{index}].step_id",
                )
            )
        elif not SAFE_ID_PATTERN.match(str(step_id)):
            issues.append(
                ValidationIssue(
                    code="invalid_step_id",
                    message="Step id contains unsupported characters.",
                    severity="error",
                    step_id=str(step_id),
                    field=f"steps[{index}].step_id",
                )
            )

        if step_type not in ALLOWED_STEP_TYPES:
            issues.append(
                ValidationIssue(
                    code="invalid_step_type",
                    message=f"Unsupported step_type '{step_type}'.",
                    severity="error",
                    step_id=str(step_id) if step_id else None,
                    field=f"steps[{index}].step_type",
                    hint=f"Allowed step types: {sorted(ALLOWED_STEP_TYPES)}",
                )
            )

        if not is_non_empty_string(operation):
            issues.append(
                ValidationIssue(
                    code="missing_operation",
                    message="Step operation is required.",
                    severity="error",
                    step_id=str(step_id) if step_id else None,
                    field=f"steps[{index}].operation",
                )
            )

        if step_type == "trigger" and operation not in ALLOWED_TRIGGER_TYPES:
            issues.append(
                ValidationIssue(
                    code="unsupported_trigger_type",
                    message=f"Unsupported trigger operation '{operation}'.",
                    severity="warning",
                    step_id=str(step_id) if step_id else None,
                    field=f"steps[{index}].operation",
                    hint="Future trigger engines may support this, but it is not in the current known trigger list.",
                )
            )

        if step_type == "condition":
            condition = step.get("condition") or {}
            operator = condition.get("operator") or config.get("operator") or operation
            if operator not in ALLOWED_CONDITION_OPERATORS:
                issues.append(
                    ValidationIssue(
                        code="unsupported_condition_operator",
                        message=f"Unsupported condition operator '{operator}'.",
                        severity="error",
                        step_id=str(step_id) if step_id else None,
                        field=f"steps[{index}].condition.operator",
                        hint=f"Allowed operators: {sorted(ALLOWED_CONDITION_OPERATORS)}",
                    )
                )

        if not isinstance(config, dict):
            issues.append(
                ValidationIssue(
                    code="invalid_step_config",
                    message="Step config must be a dictionary.",
                    severity="error",
                    step_id=str(step_id) if step_id else None,
                    field=f"steps[{index}].config",
                )
            )

        if step.get("requires_security_approval") is True and step.get("disabled") is False:
            issues.append(
                ValidationIssue(
                    code="sensitive_step_requires_approval",
                    message="Sensitive step requires Security Agent approval before activation.",
                    severity="warning",
                    step_id=str(step_id) if step_id else None,
                    field=f"steps[{index}].requires_security_approval",
                )
            )

        return issues

    def _validate_edges(
        self,
        *,
        edges: Any,
        step_ids: set[str],
    ) -> List[ValidationIssue]:
        """Validate workflow edges."""

        issues: List[ValidationIssue] = []

        if edges is None:
            return issues

        if not isinstance(edges, list):
            return [
                ValidationIssue(
                    code="invalid_edges",
                    message="Workflow edges must be a list.",
                    severity="error",
                    field="edges",
                )
            ]

        for index, edge in enumerate(edges):
            from_id = edge.get("from")
            to_id = edge.get("to")

            if not from_id or not to_id:
                issues.append(
                    ValidationIssue(
                        code="invalid_edge",
                        message="Edge must contain from and to step ids.",
                        severity="error",
                        field=f"edges[{index}]",
                    )
                )
                continue

            if from_id not in step_ids:
                issues.append(
                    ValidationIssue(
                        code="edge_from_missing_step",
                        message="Edge source step does not exist.",
                        severity="error",
                        step_id=str(from_id),
                        field=f"edges[{index}].from",
                    )
                )

            if to_id not in step_ids:
                issues.append(
                    ValidationIssue(
                        code="edge_to_missing_step",
                        message="Edge target step does not exist.",
                        severity="error",
                        step_id=str(to_id),
                        field=f"edges[{index}].to",
                    )
                )

        issues.extend(self._detect_graph_cycles(edges=edges))

        return issues

    def _detect_graph_cycles(self, *, edges: Sequence[Mapping[str, Any]]) -> List[ValidationIssue]:
        """Detect basic directed graph cycles."""

        graph: Dict[str, List[str]] = {}
        for edge in edges:
            from_id = edge.get("from")
            to_id = edge.get("to")
            if not from_id or not to_id:
                continue
            graph.setdefault(str(from_id), []).append(str(to_id))

        visited: set[str] = set()
        active: set[str] = set()
        issues: List[ValidationIssue] = []

        def visit(node: str, depth: int = 0) -> None:
            if depth > MAX_BRANCH_DEPTH * 10:
                issues.append(
                    ValidationIssue(
                        code="graph_depth_exceeded",
                        message="Workflow graph depth is unusually high.",
                        severity="warning",
                        step_id=node,
                        field="edges",
                    )
                )
                return

            if node in active:
                issues.append(
                    ValidationIssue(
                        code="workflow_cycle_detected",
                        message="Workflow graph contains a cycle.",
                        severity="warning",
                        step_id=node,
                        field="edges",
                        hint="Cycles may be allowed by future engines, but should be reviewed.",
                    )
                )
                return

            if node in visited:
                return

            active.add(node)
            for target in graph.get(node, []):
                visit(target, depth + 1)
            active.remove(node)
            visited.add(node)

        for node_id in graph:
            visit(node_id)

        deduped: Dict[Tuple[str, Optional[str]], ValidationIssue] = {}
        for issue in issues:
            deduped[(issue.code, issue.step_id)] = issue
        return list(deduped.values())

    # -----------------------------------------------------------------------
    # Risk and stats
    # -----------------------------------------------------------------------

    def _calculate_stats(self, steps: Sequence[Mapping[str, Any]]) -> WorkflowBuildStats:
        """Calculate workflow build stats."""

        stats = WorkflowBuildStats(total_steps=len(steps))

        for step in steps:
            step_type = step.get("step_type")
            operation = step.get("operation")

            if step_type == "trigger":
                stats.triggers += 1
            elif step_type == "condition":
                stats.conditions += 1
            elif step_type == "action":
                stats.actions += 1
            elif step_type == "output":
                stats.outputs += 1
            elif step_type == "transform":
                stats.transforms += 1
            elif step_type == "approval":
                stats.approvals += 1
            elif step_type == "delay":
                stats.delays += 1
            elif step_type == "router":
                stats.routers += 1
            elif step_type == "merge":
                stats.merges += 1

            if operation in SENSITIVE_ACTION_TYPES or step.get("requires_security_approval") is True:
                stats.sensitive_actions += 1

            if operation in DESTRUCTIVE_ACTION_TYPES:
                stats.destructive_actions += 1

            if step_type == "output" and operation in EXTERNAL_OUTPUT_TYPES:
                stats.external_outputs += 1

        return stats

    def _calculate_risk_level(
        self,
        stats: WorkflowBuildStats,
        steps: Sequence[Mapping[str, Any]],
    ) -> WorkflowRiskLevel:
        """Calculate workflow risk level."""

        if stats.destructive_actions > 0:
            return WorkflowRiskLevel.CRITICAL

        if any(step.get("operation") in {"payment_charge", "financial_transfer", "system_command"} for step in steps):
            return WorkflowRiskLevel.CRITICAL

        if stats.sensitive_actions >= 3:
            return WorkflowRiskLevel.HIGH

        if stats.sensitive_actions > 0:
            return WorkflowRiskLevel.HIGH

        if stats.external_outputs > 1:
            return WorkflowRiskLevel.MEDIUM

        if stats.total_steps > 25:
            return WorkflowRiskLevel.MEDIUM

        return WorkflowRiskLevel.LOW

    def _step_risk_level(
        self,
        *,
        step_type: str,
        operation: str,
        config: Mapping[str, Any],
        requires_security: bool,
    ) -> WorkflowRiskLevel:
        """Calculate step risk level."""

        if operation in DESTRUCTIVE_ACTION_TYPES:
            return WorkflowRiskLevel.CRITICAL

        if operation in {"payment_charge", "financial_transfer", "system_command", "deploy_code"}:
            return WorkflowRiskLevel.CRITICAL

        if requires_security or operation in SENSITIVE_ACTION_TYPES:
            return WorkflowRiskLevel.HIGH

        if step_type == "output" and operation in EXTERNAL_OUTPUT_TYPES:
            return WorkflowRiskLevel.MEDIUM

        if config.get("external_url") or config.get("webhook_url"):
            return WorkflowRiskLevel.MEDIUM

        return WorkflowRiskLevel.LOW

    # -----------------------------------------------------------------------
    # Export helpers
    # -----------------------------------------------------------------------

    def _compile_dashboard_config(self, workflow: Mapping[str, Any]) -> Dict[str, Any]:
        """Compile workflow into dashboard-friendly JSON."""

        steps = workflow.get("steps", [])
        edges = workflow.get("edges", [])

        return {
            "workflow_id": workflow.get("workflow_id"),
            "name": workflow.get("name"),
            "description": workflow.get("description"),
            "status": workflow.get("status"),
            "enabled": workflow.get("enabled", False),
            "tenant": workflow.get("tenant", {}),
            "tags": workflow.get("tags", []),
            "summary": self._summarize_workflow(workflow),
            "stats": self._calculate_stats(steps).to_dict(),
            "nodes": [
                {
                    "id": step.get("step_id"),
                    "label": step.get("name"),
                    "type": step.get("step_type"),
                    "operation": step.get("operation"),
                    "risk_level": step.get("risk_level"),
                    "requires_security_approval": step.get("requires_security_approval", False),
                    "disabled": step.get("disabled", False),
                }
                for step in steps
            ],
            "edges": deep_copy_jsonable(edges),
            "policies": workflow.get("policies", {}),
            "integrity": workflow.get("integrity", {}),
            "updated_at": workflow.get("updated_at"),
        }

    def _map_step_to_n8n_like_type(self, step: Mapping[str, Any]) -> str:
        """Map William step to n8n-like node type string."""

        step_type = step.get("step_type")
        operation = step.get("operation")

        if step_type == "trigger":
            if operation == "webhook":
                return "n8n-nodes-base.webhook"
            if operation == "schedule":
                return "n8n-nodes-base.scheduleTrigger"
            if operation == "manual":
                return "n8n-nodes-base.manualTrigger"
            return "william-nodes-base.trigger"

        if step_type == "condition":
            return "n8n-nodes-base.if"

        if step_type == "delay":
            return "n8n-nodes-base.wait"

        if step_type == "transform":
            return "n8n-nodes-base.set"

        if step_type == "output":
            if operation == "webhook":
                return "n8n-nodes-base.httpRequest"
            if operation == "email":
                return "n8n-nodes-base.emailSend"
            if operation == "sheet":
                return "n8n-nodes-base.googleSheets"
            return "william-nodes-base.output"

        if step_type == "approval":
            return "william-nodes-base.approvalGate"

        return "william-nodes-base.action"

    # -----------------------------------------------------------------------
    # Templates
    # -----------------------------------------------------------------------

    def _builtin_templates(self) -> Dict[str, Dict[str, Any]]:
        """Built-in templates for common Digital Promotix workflow use cases."""

        return {
            "form_to_sheet_notification": {
                "name": "{{workflow_name|Form to Sheet Notification}}",
                "description": "Capture a form submission, save it to a sheet, and notify the team.",
                "tags": ["form", "sheet", "notification"],
                "trigger": {
                    "step_type": "trigger",
                    "operation": "form_submission",
                    "name": "New form submission",
                    "config": {
                        "form_id": "{{form_id|default_form}}",
                        "source": "website",
                    },
                },
                "actions": [
                    {
                        "step_type": "action",
                        "operation": "sheet_write",
                        "name": "Save lead to sheet",
                        "config": {
                            "sheet_id": "{{sheet_id|configured_in_connector}}",
                            "worksheet": "{{worksheet|Leads}}",
                            "mode": "append_row",
                        },
                    }
                ],
                "outputs": [
                    {
                        "step_type": "output",
                        "operation": "notification",
                        "name": "Notify dashboard",
                        "config": {
                            "channel": "dashboard",
                            "message": "New form lead received.",
                        },
                    }
                ],
            },
            "form_to_crm_whatsapp": {
                "name": "{{workflow_name|Form to CRM WhatsApp Follow Up}}",
                "description": "Capture form lead, qualify it, create CRM record, and prepare WhatsApp follow-up.",
                "tags": ["form", "crm", "whatsapp", "lead"],
                "trigger": {
                    "step_type": "trigger",
                    "operation": "form_submission",
                    "name": "Website service inquiry",
                    "config": {
                        "form_id": "{{form_id|service_inquiry}}",
                    },
                },
                "conditions": [
                    {
                        "step_type": "condition",
                        "operation": "is_not_empty",
                        "name": "Phone exists",
                        "config": {
                            "operator": "is_not_empty",
                            "left": "{{lead.phone}}",
                            "right": None,
                        },
                    }
                ],
                "actions": [
                    {
                        "step_type": "action",
                        "operation": "crm_update",
                        "name": "Create or update CRM lead",
                        "config": {
                            "crm": "{{crm|default_crm}}",
                            "mode": "upsert",
                        },
                    },
                    {
                        "step_type": "action",
                        "operation": "send_whatsapp",
                        "name": "Prepare WhatsApp follow up",
                        "config": {
                            "template": "{{whatsapp_template|lead_follow_up}}",
                            "send_mode": "approval_required",
                        },
                    },
                ],
                "outputs": [
                    {
                        "step_type": "output",
                        "operation": "dashboard",
                        "name": "Show lead in dashboard",
                        "config": {
                            "widget": "lead_activity",
                        },
                    }
                ],
            },
            "scheduled_report_email": {
                "name": "{{workflow_name|Scheduled Report Email}}",
                "description": "Generate scheduled report and prepare email delivery.",
                "tags": ["schedule", "report", "email"],
                "trigger": {
                    "step_type": "trigger",
                    "operation": "schedule",
                    "name": "Scheduled report trigger",
                    "config": {
                        "cron": "{{cron|0 9 * * 1}}",
                        "timezone": "{{timezone|UTC}}",
                    },
                },
                "actions": [
                    {
                        "step_type": "action",
                        "operation": "api_event",
                        "name": "Generate report data",
                        "config": {
                            "event": "report.generate",
                            "report_type": "{{report_type|weekly_summary}}",
                        },
                    }
                ],
                "outputs": [
                    {
                        "step_type": "output",
                        "operation": "email",
                        "name": "Prepare report email",
                        "config": {
                            "to": "{{email_to|configured_recipient}}",
                            "subject": "{{email_subject|Weekly Report}}",
                            "send_mode": "approval_required",
                        },
                    }
                ],
            },
            "webhook_to_agent_event": {
                "name": "{{workflow_name|Webhook to Agent Event}}",
                "description": "Receive webhook and create internal agent event.",
                "tags": ["webhook", "agent", "event"],
                "trigger": {
                    "step_type": "trigger",
                    "operation": "webhook",
                    "name": "Incoming webhook",
                    "config": {
                        "path": "{{webhook_path|incoming-event}}",
                        "method": "POST",
                    },
                },
                "actions": [
                    {
                        "step_type": "action",
                        "operation": "api_event",
                        "name": "Create internal agent event",
                        "config": {
                            "event_name": "{{event_name|workflow.webhook.received}}",
                            "target_agent": "{{target_agent|MasterAgent}}",
                        },
                    }
                ],
                "outputs": [
                    {
                        "step_type": "output",
                        "operation": "dashboard",
                        "name": "Log webhook event",
                        "config": {
                            "widget": "workflow_events",
                        },
                    }
                ],
            },
        }

    def _render_template(self, template: Any, variables: Mapping[str, Any]) -> Any:
        """
        Render simple {{key|default}} template variables safely.

        This deliberately avoids eval or executable template engines.
        """

        if isinstance(template, dict):
            return {key: self._render_template(value, variables) for key, value in template.items()}

        if isinstance(template, list):
            return [self._render_template(item, variables) for item in template]

        if not isinstance(template, str):
            return template

        pattern = re.compile(r"\{\{\s*([a-zA-Z0-9_.\-]+)(?:\|([^}]*))?\s*\}\}")

        def replace(match: re.Match[str]) -> str:
            key = match.group(1)
            default = match.group(2) if match.group(2) is not None else ""
            value = variables.get(key, default)
            return safe_str(value, 500)

        return pattern.sub(replace, template)

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    def _summarize_workflow(self, workflow: Mapping[str, Any]) -> str:
        """Create a readable workflow summary."""

        steps = workflow.get("steps", [])
        if not steps:
            return "Workflow has no steps."

        parts: List[str] = []
        for step in steps[:12]:
            step_type = step.get("step_type", "step")
            operation = step.get("operation", "operation")
            name = step.get("name", operation)
            parts.append(f"{step_type}:{name}({operation})")

        suffix = ""
        if len(steps) > 12:
            suffix = f" + {len(steps) - 12} more steps"

        return " → ".join(parts) + suffix


# ---------------------------------------------------------------------------
# Standalone smoke test helper
# ---------------------------------------------------------------------------

def _smoke_test() -> Dict[str, Any]:
    """
    Minimal import-safe smoke test.

    This function is intentionally not executed on import.
    """

    builder = WorkflowBuilder()
    return builder.build_workflow(
        user_id="user_demo",
        workspace_id="workspace_demo",
        name="Demo Form Pipeline",
        description="Demo workflow for local smoke testing.",
        trigger={
            "operation": "form_submission",
            "name": "Lead form submitted",
            "config": {
                "form_id": "contact_form",
            },
        },
        actions=[
            {
                "operation": "sheet_write",
                "name": "Save lead",
                "config": {
                    "sheet_id": "configured_in_connector",
                    "worksheet": "Leads",
                },
            }
        ],
        outputs=[
            {
                "operation": "dashboard",
                "name": "Show dashboard notification",
                "config": {
                    "widget": "lead_activity",
                },
            }
        ],
        tags=["demo", "form", "lead"],
    )


__all__ = [
    "WorkflowBuilder",
    "WorkflowContext",
    "WorkflowBuildStats",
    "WorkflowRiskLevel",
    "WorkflowStatus",
    "ValidationIssue",
]